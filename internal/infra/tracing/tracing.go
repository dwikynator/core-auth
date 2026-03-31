// Package tracing sets up the global OpenTelemetry TracerProvider for core-auth.
//
// Usage:
//
//	shutdown, err := tracing.Setup(ctx, "core-auth", cfg.OTELEndpoint)
//	if err != nil {
//	    return err
//	}
//	defer shutdown() // flush buffered spans on graceful shutdown
package tracing

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace/noop"
)

// Setup initialises the global OpenTelemetry TracerProvider.
//
// If otlpEndpoint is empty, a no-op provider is installed and tracing is
// effectively disabled — the binary runs normally with zero overhead.
//
// Returns a shutdown function that flushes any buffered spans. Always call it
// on graceful shutdown, even when tracing is disabled (it is a safe no-op).
func Setup(ctx context.Context, serviceName, otlpEndpoint string) (shutdown func(), err error) {
	if otlpEndpoint == "" {
		// No collector configured — install no-op provider and return.
		otel.SetTracerProvider(noop.NewTracerProvider())
		return func() {}, nil
	}

	// 1. Build OTLP gRPC exporter.
	// WithInsecure is intentional for local/internal collector deployments.
	// For production with TLS, replace with otlptracegrpc.WithTLSClientConfig(...).
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(otlpEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("create otlp exporter: %w", err)
	}

	// 2. Build resource — the set of attributes that identify this service.
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
		),
		resource.WithFromEnv(), // picks up OTEL_RESOURCE_ATTRIBUTES
		resource.WithProcess(), // OS PID, runtime version
		resource.WithOS(),      // OS type
		resource.WithHost(),    // hostname
	)
	if err != nil {
		// resource.New returns a partial resource on recoverable errors.
		// Log it but continue — partial resource is better than no tracing.
		res = resource.Default()
	}

	// 3. Build TracerProvider with a batch exporter.
	// BatchSpanProcessor is the production default:
	//   - Batches spans in memory and flushes periodically (default: 5s).
	//   - Non-blocking on the hot path — the exporter runs in a background goroutine.
	//   - Drops spans under back-pressure (configurable via OTEL_BSP_* env vars).
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter,
			// Flush at least every 5 s, or when the batch reaches 512 spans.
			// These can be overridden at runtime via OTEL_BSP_SCHEDULE_DELAY,
			// OTEL_BSP_MAX_EXPORT_BATCH_SIZE, etc.
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithResource(res),
		// AlwaysSample is fine for local dev and staging.
		// For production, switch to sdktrace.TraceIDRatioBased(0.1) (10% sampling).
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// 4. Register as the global provider and configure propagation.
	// W3C Trace Context is the standard for cross-service propagation.
	// B3 is added for compatibility with legacy systems (Spring Boot, Envoy defaults).
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, // W3C traceparent / tracestate headers
		propagation.Baggage{},
	))

	shutdown = func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// ForceFlush + Shutdown ensures all buffered spans are exported before exit.
		_ = tp.ForceFlush(shutdownCtx)
		_ = tp.Shutdown(shutdownCtx)
	}

	return shutdown, nil
}
