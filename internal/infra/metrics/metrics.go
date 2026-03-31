// Package metrics provides a single, isolated Prometheus registry for
// core-auth and exposes pre-registered metric handles for use by HTTP
// middleware and domain instrumentation.
//
// Design principles:
//   - Non-global registry: no collision risk with library-registered metrics.
//   - All metric definitions are co-located here for easy discovery.
//   - Metric handles are exported vars — no sync overhead on the hot path.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Registry is the application-scoped Prometheus registry.
// All metrics in this package are registered here at init time.
// Pass this to promhttp.HandlerFor to build the /metrics handler.
// ---------------------------------------------------------------------------
// HTTP RED Metrics
// Used by the HTTP middleware in internal/infra/metrics/middleware.go.
// ---------------------------------------------------------------------------

// HTTPRequestsTotal counts every HTTP request, partitioned by method, path
// template, and response status code. Use this for rate and error-rate signals.
//
// Label cardinality note: "path" is the chi route pattern (e.g., "/v1/auth/login"),
// NOT the raw request URI. Using raw URIs with UUIDs would create unbounded
// cardinality and blow up the TSDB.
var HTTPRequestsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total number of HTTP requests received, partitioned by method, path template, and status code.",
	},
	[]string{"method", "path", "status"},
)

// HTTPRequestDurationSeconds measures the distribution of handler latencies.
//
// Bucket rationale for an auth service:
//   - ≤5ms:   Redis hits (token validation, blacklist check)
//   - ≤25ms:  Simple DB reads (user lookup)
//   - ≤100ms: Password hashing (Argon2id is intentionally slow, ~50–150ms)
//   - ≤250ms: Full login with MFA or OAuth round-trips
//   - ≤500ms: Tail latency / DB under load
//   - >500ms: Outliers — SLO breach territory
var HTTPRequestDurationSeconds = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, partitioned by method and path template.",
		Buckets: []float64{0.005, 0.025, 0.1, 0.25, 0.5, 1.0},
	},
	[]string{"method", "path"},
)

// ---------------------------------------------------------------------------
// Business Metrics
// Incremented directly at domain instrumentation points in use cases.
// ---------------------------------------------------------------------------

// TokensIssuedTotal counts every token pair issued, by grant_type.
//
// grant_type values: "password" (login), "refresh", "mfa", "oauth", "magic_link"
// This metric gives product-level visibility into the authentication mix:
// what fraction of sessions are initiated via each flow.
var TokensIssuedTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "tokens_issued_total",
		Help: "Total number of token pairs issued, partitioned by grant type.",
	},
	[]string{"grant_type"},
)

// LoginAttemptsTotal counts every login attempt that reaches the credential
// validation stage (i.e., after IP rate-limiting has passed), by client_id.
var LoginAttemptsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "login_attempts_total",
		Help: "Total number of login attempts reaching credential validation, by client_id.",
	},
	[]string{"client_id"},
)

// LoginFailuresTotal counts every login that fails after reaching credential
// validation, labelled by the rejection reason.
//
// reason values: "invalid_credentials", "account_locked", "account_suspended",
//
//	"account_not_verified", "ip_not_allowed"
var LoginFailuresTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "login_failures_total",
		Help: "Total number of failed login attempts, partitioned by failure reason.",
	},
	[]string{"reason"},
)

func init() {
	// Register application metrics with the global registry.
	prometheus.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDurationSeconds,
		TokensIssuedTotal,
		LoginAttemptsTotal,
		LoginFailuresTotal,
	)

	// Note: The global prometheus.DefaultRegisterer (which promhttp.Handler() uses)
	// automatically includes Go runtime metrics (memory, GC) and Process metrics (CPU, FD).
	// We don't need to manually register collectors.NewGoCollector() here!
}
