// Package metrics instruments the issuer (signer and JWKS aggregator) with
// OpenTelemetry metrics, exported to Prometheus or to an OpenTelemetry
// Collector (see .specs/openstack-spire-issuer-metrics.md).
//
// Every instrument is created here, behind a typed API, so that names,
// units and attribute sets are defined in one place and the components never
// touch the OpenTelemetry API. A nil *Metrics, like a disabled one, records
// nothing and costs a nil check.
//
// The configuration comes from the file only: every exporter option is set
// explicitly, so that the OTEL_* environment variables cannot redirect the
// metrics, add credentials or change the transport. The SDK still merges
// OTEL_RESOURCE_ATTRIBUTES and OTEL_SERVICE_NAME into the resource, under
// the attributes set here, which take precedence.
package metrics

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
	"go.opentelemetry.io/otel/sdk/resource"
)

// scope is the instrumentation scope of every instrument.
const scope = "github.com/dihedron/openstack-spiffe/internal/issuer"

// cardinalityLimit bounds the series of each instrument, as a last resort:
// the attribute sets are closed by design (D-10).
const cardinalityLimit = 2000

// durationBuckets are the bucket boundaries, in seconds, of the request and
// dependency durations: 5ms to 10s.
var durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Resource identifies the process the metrics come from.
type Resource struct {
	// Component is "signer" or "aggregator".
	Component string
	// InstanceID is the replica_id of a signer, the host name of an
	// aggregator.
	InstanceID string
	// Version is the software version.
	Version string
}

// Metrics holds the meter provider and every instrument.
type Metrics struct {
	provider *sdkmetric.MeterProvider // nil when disabled
	handler  http.Handler             // the Prometheus endpoint, if any

	httpDuration metric.Float64Histogram
	issuance     *issuance
	state        *state
}

type options struct {
	reader sdkmetric.Reader
}

// Option tunes New.
type Option func(*options)

// WithReader replaces the configured exporter with a reader, for tests
// (e.g. sdkmetric.NewManualReader); it applies even if the configuration
// disables metrics.
func WithReader(r sdkmetric.Reader) Option { return func(o *options) { o.reader = r } }

// New builds the metrics of a process from a checked configuration;
// minTLSVersion applies to the connection to the collector. Disabled
// metrics cost nothing: the instruments are no-ops.
func New(ctx context.Context, cfg Config, res Resource, minTLSVersion uint16, opts ...Option) (*Metrics, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	m := &Metrics{}
	var reader sdkmetric.Reader
	switch {
	case o.reader != nil:
		reader = o.reader
	case !cfg.Enabled:
		return m, nil // every recording method returns at once
	case cfg.Exporter == ExporterPrometheus:
		registry := prometheus.NewRegistry()
		exporter, err := otelprometheus.New(otelprometheus.WithRegisterer(registry))
		if err != nil {
			return nil, fmt.Errorf("creating the Prometheus exporter: %w", err)
		}
		reader = exporter
		m.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{ErrorHandling: promhttp.ContinueOnError})
	case cfg.Exporter == ExporterOTLP:
		exporter, err := newOTLPExporter(ctx, cfg.OTLP, minTLSVersion)
		if err != nil {
			return nil, err
		}
		reader = sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(cfg.OTLP.Interval),
			sdkmetric.WithTimeout(cfg.OTLP.Timeout))
	default:
		return nil, fmt.Errorf("unknown metrics exporter %q", cfg.Exporter)
	}

	// the SDK reports export and collection errors through the global
	// handler; failing exports are logged by the exporter wrapper instead
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		slog.Debug("OpenTelemetry error", "error", err)
	}))
	m.provider = sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(resource.NewSchemaless(
			attribute.String("service.name", "openstack-spire-issuer"),
			attribute.String("service.version", res.Version),
			attribute.String("service.instance.id", res.InstanceID),
			attribute.String("openstack_spire.component", res.Component),
		)),
		sdkmetric.WithReader(reader),
		sdkmetric.WithExemplarFilter(exemplar.AlwaysOffFilter),
		sdkmetric.WithCardinalityLimit(cardinalityLimit),
	)
	m.state = &state{}
	m.issuance = &issuance{
		projectAttribute: cfg.ProjectAttribute,
		maxProjects:      max(cfg.MaxProjects, 1),
		projects:         map[string]struct{}{},
	}
	if err := m.instrument(m.provider.Meter(scope)); err != nil {
		return nil, errors.Join(err, m.provider.Shutdown(ctx))
	}
	if cfg.Runtime {
		if err := runtime.Start(runtime.WithMeterProvider(m.provider)); err != nil {
			return nil, errors.Join(fmt.Errorf("starting the runtime metrics: %w", err), m.provider.Shutdown(ctx))
		}
	}
	return m, nil
}

// instrument creates every instrument on the meter.
func (m *Metrics) instrument(meter metric.Meter) error {
	var err error
	m.httpDuration, err = meter.Float64Histogram("http.server.request.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Duration of the HTTP requests served, by route, method and status."),
		metric.WithExplicitBucketBoundaries(durationBuckets...))
	if err != nil {
		return fmt.Errorf("creating the metrics instruments: %w", err)
	}
	if err := m.issuance.instrument(meter); err != nil {
		return err
	}
	return m.state.instrument(meter)
}

// Handler returns the Prometheus endpoint, or nil when the metrics are not
// exported to Prometheus.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return nil
	}
	return m.handler
}

// Shutdown flushes the metrics (OTLP sends a last export) and stops the
// provider; bounded by the context.
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m == nil || m.provider == nil {
		return nil
	}
	if err := m.provider.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutting down the metrics: %w", err)
	}
	return nil
}

// recordHTTP records one served request.
func (m *Metrics) recordHTTP(ctx context.Context, route, method string, status int, elapsed time.Duration) {
	if m == nil || m.httpDuration == nil {
		return
	}
	m.httpDuration.Record(ctx, elapsed.Seconds(), metric.WithAttributes(
		attribute.String("http.route", route),
		attribute.String("http.request.method", method),
		attribute.Int("http.response.status_code", status),
	))
}
