package metrics

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/go-chi/chi/v5"
)

var (
	// sessionsPathRe matches specific session IDs in the URL to prevent metric
	// cardinality explosion when grpc-gateway catch-all routing is used.
	sessionsPathRe = regexp.MustCompile(`^/v1/auth/sessions/[^/]+$`)
)

// responseWriter is a thin wrapper around http.ResponseWriter that captures
// the status code written by the handler. The default ResponseWriter does not
// expose the written status code after WriteHeader has been called.
//
// We embed the interface to automatically forward all other methods
// (Flush, Hijack, etc.) without manual delegation.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	// Implicit 200 if Write is called before WriteHeader.
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Middleware returns a chi-compatible middleware that records HTTP RED metrics.
//
// It uses chi.RouteContext to obtain the matched route pattern (e.g.,
// "/v1/auth/sessions/{id}") rather than the raw request URI. This prevents
// cardinality explosion from path parameters containing UUIDs or user IDs.
//
// Usage in main.go:
//
//	server.Use(metrics.Middleware)
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		// Resolve the route pattern after the handler has run.
		// chi populates RouteContext during routing; it is available here
		// because the middleware is placed on the router, not before it.
		path := r.URL.Path
		if chiCtx := chi.RouteContext(r.Context()); chiCtx != nil {
			if p := chiCtx.RoutePattern(); p != "" {
				path = p
			}
		}

		// Fallback for grpc-gateway: minato mounts the gateway Mux at "/*".
		// Chi correctly reports that it matched "/*", but we lose the endpoint granularity.
		// So if the pattern is "/*", fallback to the raw URL path.
		if path == "/*" {
			path = r.URL.Path
			// Cardinality protection: mask dynamic path parameters since we lost
			// the original template from grpc-gateway.
			path = sessionsPathRe.ReplaceAllString(path, "/v1/auth/sessions/{id}")
		}

		status := fmt.Sprintf("%d", rw.statusCode)
		method := r.Method

		HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
		HTTPRequestDurationSeconds.WithLabelValues(method, path).Observe(time.Since(start).Seconds())
	})
}
