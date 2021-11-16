// Commons for HTTP handling
package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/net/netutil"

	"github.com/rs/cors"
	"github.com/tendermint/tendermint/libs/log"
	rpctypes "github.com/tendermint/tendermint/rpc/jsonrpc/types"
)

// Config is a RPC server configuration.
type Config struct {
	// see netutil.LimitListener
	MaxOpenConnections int
	// mirrors http.Server#ReadTimeout
	ReadTimeout time.Duration
	// mirrors http.Server#WriteTimeout
	WriteTimeout time.Duration
	// MaxBodyBytes controls the maximum number of bytes the
	// server will read parsing the request body.
	MaxBodyBytes int64
	// mirrors http.Server#MaxHeaderBytes
	MaxHeaderBytes int
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		MaxOpenConnections: 0, // unlimited
		ReadTimeout:        10 * time.Second,
		WriteTimeout:       10 * time.Second,
		MaxBodyBytes:       int64(1000000), // 1MB
		MaxHeaderBytes:     1 << 20,        // same as the net/http default
	}
}

type AuthorizationChecker interface {
	IsAuthorized(address string, data []byte, signature []byte) (bool, error)
}

var (
	// set by Node
	authChecker AuthorizationChecker
)

func SetAuthorizationChecker(checker AuthorizationChecker) {
	authChecker = checker
}

// Serve creates a http.Server and calls Serve with the given listener. It
// wraps handler with RecoverAndLogHandler and a handler, which limits the max
// body size to config.MaxBodyBytes.
//
// NOTE: This function blocks - you may want to call it in a go-routine.
func Serve(listener net.Listener, handler http.Handler, logger log.Logger, config *Config) error {
	logger.Info(fmt.Sprintf("Starting RPC HTTP server on %s", listener.Addr()))
	s := &http.Server{
		Handler:        RecoverAndLogHandler(wrapHandler(maxBytesHandler{h: handler, n: config.MaxBodyBytes}), logger),
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		MaxHeaderBytes: config.MaxHeaderBytes,
	}
	err := s.Serve(listener)
	logger.Info("RPC HTTP server stopped", "err", err)
	return err
}

// Serve creates a http.Server and calls ServeTLS with the given listener,
// certFile and keyFile. It wraps handler with RecoverAndLogHandler and a
// handler, which limits the max body size to config.MaxBodyBytes.
//
// NOTE: This function blocks - you may want to call it in a go-routine.
func ServeTLS(
	listener net.Listener,
	handler http.Handler,
	certFile, keyFile string,
	logger log.Logger,
	config *Config,
) error {
	logger.Info(fmt.Sprintf("Starting RPC HTTPS server on %s (cert: %q, key: %q)",
		listener.Addr(), certFile, keyFile))
	s := &http.Server{
		Handler:        RecoverAndLogHandler(wrapHandler(maxBytesHandler{h: handler, n: config.MaxBodyBytes}), logger),
		ReadTimeout:    config.ReadTimeout,
		WriteTimeout:   config.WriteTimeout,
		MaxHeaderBytes: config.MaxHeaderBytes,
	}
	err := s.ServeTLS(listener, certFile, keyFile)

	logger.Error("RPC HTTPS server stopped", "err", err)
	return err
}

// WriteRPCResponseHTTPError marshals res as JSON (with indent) and writes it
// to w.
//
// Maps JSON RPC error codes to HTTP Status codes as follows:
//
// HTTP Status	code	message
// 500	-32700	Parse error.
// 400	-32600	Invalid Request.
// 404	-32601	Method not found.
// 500	-32602	Invalid params.
// 500	-32603	Internal error.
// 500	-32099..-32000	Server error.
//
// source: https://www.jsonrpc.org/historical/json-rpc-over-http.html
func WriteRPCResponseHTTPError(
	w http.ResponseWriter,
	res rpctypes.RPCResponse,
) error {
	if res.Error == nil {
		panic("tried to write http error response without RPC error")
	}

	jsonBytes, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}

	var httpCode int
	switch res.Error.Code {
	case -32600:
		httpCode = http.StatusBadRequest
	case -32601:
		httpCode = http.StatusNotFound
	default:
		httpCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	_, err = w.Write(jsonBytes)
	return err
}

// WriteRPCResponseHTTP marshals res as JSON (with indent) and writes it to w.
// If the rpc response can be cached, add cache-control to the response header.
func WriteRPCResponseHTTP(w http.ResponseWriter, c bool, res ...rpctypes.RPCResponse) error {
	var v interface{}
	if len(res) == 1 {
		v = res[0]
	} else {
		v = res
	}

	jsonBytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("json marshal: %w", err)
	}
	w.Header().Set("Content-Type", "application/json")
	if c {
		w.Header().Set("Cache-Control", "max-age=31536000") // expired after one year
	}
	w.WriteHeader(200)
	_, err = w.Write(jsonBytes)
	return err
}

//-----------------------------------------------------------------------------

// RecoverAndLogHandler wraps an HTTP handler, adding error logging.
// If the inner function panics, the outer function recovers, logs, sends an
// HTTP 500 error response.
func RecoverAndLogHandler(handler http.Handler, logger log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap the ResponseWriter to remember the status
		rww := &responseWriterWrapper{-1, w}
		begin := time.Now()

		rww.Header().Set("X-Server-Time", fmt.Sprintf("%v", begin.Unix()))

		defer func() {
			// Handle any panics in the panic handler below. Does not use the logger, since we want
			// to avoid any further panics. However, we try to return a 500, since it otherwise
			// defaults to 200 and there is no other way to terminate the connection. If that
			// should panic for whatever reason then the Go HTTP server will handle it and
			// terminate the connection - panicing is the de-facto and only way to get the Go HTTP
			// server to terminate the request and close the connection/stream:
			// https://github.com/golang/go/issues/17790#issuecomment-258481416
			if e := recover(); e != nil {
				fmt.Fprintf(os.Stderr, "Panic during RPC panic recovery: %v\n%v\n", e, string(debug.Stack()))
				w.WriteHeader(500)
			}
		}()

		defer func() {
			// Send a 500 error if a panic happens during a handler.
			// Without this, Chrome & Firefox were retrying aborted ajax requests,
			// at least to my localhost.
			if e := recover(); e != nil {

				// If RPCResponse
				if res, ok := e.(rpctypes.RPCResponse); ok {
					if wErr := WriteRPCResponseHTTP(rww, false, res); wErr != nil {
						logger.Error("failed to write response", "res", res, "err", wErr)
					}
				} else {
					// Panics can contain anything, attempt to normalize it as an error.
					var err error
					switch e := e.(type) {
					case error:
						err = e
					case string:
						err = errors.New(e)
					case fmt.Stringer:
						err = errors.New(e.String())
					default:
					}

					logger.Error("panic in RPC HTTP handler", "err", e, "stack", string(debug.Stack()))

					res := rpctypes.RPCInternalError(rpctypes.JSONRPCIntID(-1), err)
					if wErr := WriteRPCResponseHTTPError(rww, res); wErr != nil {
						logger.Error("failed to write response", "res", res, "err", wErr)
					}
				}
			}

			// Finally, log.
			durationMS := time.Since(begin).Nanoseconds() / 1000000
			if rww.Status == -1 {
				rww.Status = 200
			}
			logger.Debug("served RPC HTTP response",
				"method", r.Method,
				"url", r.URL,
				"status", rww.Status,
				"duration", durationMS,
				"remoteAddr", r.RemoteAddr,
			)
		}()

		handler.ServeHTTP(rww, r)
	})
}

// Remember the status for logging
type responseWriterWrapper struct {
	Status int
	http.ResponseWriter
}

func (w *responseWriterWrapper) WriteHeader(status int) {
	w.Status = status
	w.ResponseWriter.WriteHeader(status)
}

// implements http.Hijacker
func (w *responseWriterWrapper) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.ResponseWriter.(http.Hijacker).Hijack()
}

func wrapHandler(handler http.Handler) http.Handler {
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins: []string{},
		AllowedMethods: []string{http.MethodHead, http.MethodGet, http.MethodPost},
		AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "X-Server-Time", "Meraki-Signer", "Meraki-Sign"},
	})

	return corsMiddleware.Handler(authorizationHandler{h: handler})
}

func getSignature(r *http.Request) string {
	queryMap, _ := url.ParseQuery(r.URL.RawQuery)
	sign := queryMap.Get("meraki-sign")

	if sign != "" {
		return sign
	}

	return r.Header.Get("Meraki-Sign")
}

type authorizationHandler struct {
	h http.Handler
}

func isRequestAuthorized(r *http.Request) bool {
	if authChecker == nil {
		return false
	}

	ok, _ := authChecker.IsAuthorized("", []byte{}, []byte{})
	if !ok {
		return false
	}

	sign := getSignature(r)

	return sign == "SIGNATURE"
}

func (h authorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !isRequestAuthorized(r) {
		w.Header().Set("Content-Type", "application/json")
		res := types.RPCInvalidRequestError(nil, fmt.Errorf("Error unauthorized"))
		WriteRPCResponseHTTPError(w, http.StatusUnauthorized, res)
		return
	}

	h.h.ServeHTTP(w, r)
}

type maxBytesHandler struct {
	h http.Handler
	n int64
}

func (h maxBytesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, h.n)
	h.h.ServeHTTP(w, r)
}

// Listen starts a new net.Listener on the given address.
// It returns an error if the address is invalid or the call to Listen() fails.
func Listen(addr string, maxOpenConnections int) (listener net.Listener, err error) {
	parts := strings.SplitN(addr, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf(
			"invalid listening address %s (use fully formed addresses, including the tcp:// or unix:// prefix)",
			addr,
		)
	}
	proto, addr := parts[0], parts[1]
	listener, err = net.Listen(proto, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %v: %v", addr, err)
	}
	if maxOpenConnections > 0 {
		listener = netutil.LimitListener(listener, maxOpenConnections)
	}

	return listener, nil
}
