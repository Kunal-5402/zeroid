// Package telemetry provides OpenTelemetry instrumentation for ZeroID.
// Initialises a shared TracerProvider and MeterProvider that export to an OTEL
// Collector via gRPC. When telemetry is disabled, all instruments are no-ops.
package telemetry

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	otelmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Config mirrors the telemetry section of the service config.
type Config struct {
	Enabled      bool
	Endpoint     string
	Insecure     bool
	ServiceName  string
	SamplingRate float64
}

// Package-level instruments — initialised as no-ops, replaced by Init().
var (
	Tracer trace.Tracer
	Meter  metric.Meter

	// Metrics
	TokenIssuances     metric.Int64Counter
	TokenLatency       metric.Float64Histogram
	IdentityOps        metric.Int64Counter
	PolicyEnforcements metric.Int64Counter
	AuthErrors         metric.Int64Counter
)

func init() {
	initNoOpMetrics()
}

func initNoOpMetrics() {
	Tracer = otel.Tracer("zeroid")
	Meter = otel.Meter("zeroid")

	TokenIssuances, _ = Meter.Int64Counter("zeroid.token.issuances",
		metric.WithDescription("Total token issuances"),
	)
	TokenLatency, _ = Meter.Float64Histogram("zeroid.token.latency_ms",
		metric.WithDescription("Token issuance latency in milliseconds"),
	)
	IdentityOps, _ = Meter.Int64Counter("zeroid.identity.operations",
		metric.WithDescription("Identity CRUD operations"),
	)
	PolicyEnforcements, _ = Meter.Int64Counter("zeroid.policy.enforcements",
		metric.WithDescription("Credential policy enforcement decisions"),
	)
	AuthErrors, _ = Meter.Int64Counter("zeroid.errors",
		metric.WithDescription("Authentication errors"),
	)
}

// providers holds references for graceful shutdown.
var (
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *otelmetric.MeterProvider
)

// Init sets up the OTEL TracerProvider and MeterProvider. If disabled, returns
// immediately and all instruments remain no-ops.
func Init(cfg Config) error {
	if !cfg.Enabled {
		return nil
	}

	ctx := context.Background()

	// Shared gRPC connection to the OTEL Collector.
	var dialOpts []grpc.DialOption
	if cfg.Insecure {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	conn, err := grpc.NewClient(cfg.Endpoint, dialOpts...)
	if err != nil {
		return fmt.Errorf("otel grpc dial: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ServiceName),
		),
		resource.WithProcessRuntimeDescription(),
	)
	if err != nil {
		return fmt.Errorf("otel resource: %w", err)
	}

	// Traces
	traceExporter, err := otlptracegrpc.New(ctx, otlptracegrpc.WithGRPCConn(conn))
	if err != nil {
		return fmt.Errorf("otel trace exporter: %w", err)
	}

	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SamplingRate))
	tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
		sdktrace.WithBatcher(traceExporter,
			sdktrace.WithMaxQueueSize(4096),
			sdktrace.WithBatchTimeout(time.Second),
			sdktrace.WithMaxExportBatchSize(512),
		),
	)
	otel.SetTracerProvider(tracerProvider)

	// Metrics
	metricExporter, err := otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithGRPCConn(conn))
	if err != nil {
		return fmt.Errorf("otel metric exporter: %w", err)
	}

	meterProvider = otelmetric.NewMeterProvider(
		otelmetric.WithResource(res),
		otelmetric.WithReader(otelmetric.NewPeriodicReader(metricExporter,
			otelmetric.WithInterval(30*time.Second),
		)),
	)
	otel.SetMeterProvider(meterProvider)

	// Re-initialise instruments with real providers.
	Tracer = tracerProvider.Tracer("zeroid")
	Meter = meterProvider.Meter("zeroid")

	TokenIssuances, _ = Meter.Int64Counter("zeroid.token.issuances",
		metric.WithDescription("Total token issuances"),
	)
	TokenLatency, _ = Meter.Float64Histogram("zeroid.token.latency_ms",
		metric.WithDescription("Token issuance latency in milliseconds"),
	)
	IdentityOps, _ = Meter.Int64Counter("zeroid.identity.operations",
		metric.WithDescription("Identity CRUD operations"),
	)
	PolicyEnforcements, _ = Meter.Int64Counter("zeroid.policy.enforcements",
		metric.WithDescription("Credential policy enforcement decisions"),
	)
	AuthErrors, _ = Meter.Int64Counter("zeroid.errors",
		metric.WithDescription("Authentication errors"),
	)

	return nil
}

// Shutdown flushes and shuts down the OTEL providers. Call during graceful shutdown.
func Shutdown(ctx context.Context) error {
	var firstErr error
	if tracerProvider != nil {
		if err := tracerProvider.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if meterProvider != nil {
		if err := meterProvider.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
