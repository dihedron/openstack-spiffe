package metrics

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc/credentials"
)

// otlpHTTPPath is the standard path of OTLP/HTTP metrics, used when the
// configured endpoint has none.
const otlpHTTPPath = "/v1/metrics"

// newOTLPExporter builds the OTLP exporter, over verified TLS, with every
// option set explicitly so that no OTEL_* variable applies.
func newOTLPExporter(ctx context.Context, cfg OTLPConfig, minTLSVersion uint16) (sdkmetric.Exporter, error) {
	tlsConfig, err := otlpTLSConfig(cfg, minTLSVersion)
	if err != nil {
		return nil, err
	}
	headers, err := otlpHeaders(cfg.HeadersEnv)
	if err != nil {
		return nil, err
	}
	endpoint, err := url.Parse(cfg.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" {
		return nil, fmt.Errorf("metrics.otlp.endpoint %q: an https URL with a host is required", cfg.Endpoint)
	}

	var exporter sdkmetric.Exporter
	switch cfg.Protocol {
	case ProtocolHTTP:
		if endpoint.Path == "" || endpoint.Path == "/" {
			endpoint.Path = otlpHTTPPath
		}
		exporter, err = otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpointURL(endpoint.String()),
			otlpmetrichttp.WithTLSClientConfig(tlsConfig),
			otlpmetrichttp.WithHeaders(headers),
			otlpmetrichttp.WithTimeout(cfg.Timeout),
			otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression),
			otlpmetrichttp.WithTemporalitySelector(sdkmetric.DefaultTemporalitySelector),
			otlpmetrichttp.WithAggregationSelector(sdkmetric.DefaultAggregationSelector))
	case ProtocolGRPC:
		exporter, err = otlpmetricgrpc.New(ctx,
			otlpmetricgrpc.WithEndpoint(endpoint.Host),
			otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)),
			otlpmetricgrpc.WithHeaders(headers),
			otlpmetricgrpc.WithTimeout(cfg.Timeout),
			otlpmetricgrpc.WithCompressor("gzip"),
			otlpmetricgrpc.WithTemporalitySelector(sdkmetric.DefaultTemporalitySelector),
			otlpmetricgrpc.WithAggregationSelector(sdkmetric.DefaultAggregationSelector))
	default:
		return nil, fmt.Errorf("unknown OTLP protocol %q", cfg.Protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("creating the OTLP exporter: %w", err)
	}
	return &loggingExporter{Exporter: exporter, endpoint: endpoint.Host}, nil
}

// otlpTLSConfig verifies the collector against ca_cert_path (default: the
// system roots) and presents the client certificate, if configured.
func otlpTLSConfig(cfg OTLPConfig, minTLSVersion uint16) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: minTLSVersion}
	if cfg.CACertPath != "" {
		data, err := os.ReadFile(filepath.Clean(cfg.CACertPath))
		if err != nil {
			return nil, fmt.Errorf("reading metrics.otlp.ca_cert_path: %w", err)
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		if !tlsConfig.RootCAs.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("metrics.otlp.ca_cert_path %s: no PEM certificates", cfg.CACertPath)
		}
	}
	if cfg.ClientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading the metrics.otlp client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

// otlpHeaders reads the headers sent to the collector from the environment
// variable named by headers_env: "key=value,..." with percent-encoded values,
// as in OTEL_EXPORTER_OTLP_HEADERS. No variable means no headers; a named
// variable that is unset or malformed is an error.
func otlpHeaders(name string) (map[string]string, error) {
	headers := map[string]string{}
	if name == "" {
		return headers, nil
	}
	value, ok := os.LookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, fmt.Errorf("metrics.otlp.headers_env: the environment variable %s is not set", name)
	}
	for _, pair := range strings.Split(value, ",") {
		key, raw, ok := strings.Cut(pair, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			return nil, fmt.Errorf("metrics.otlp.headers_env: %s is not a list of key=value pairs", name)
		}
		decoded, err := url.PathUnescape(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("metrics.otlp.headers_env: %s: the value of %q is not percent-encoded", name, key)
		}
		headers[key] = decoded
	}
	return headers, nil
}

// loggingExporter logs failing exports when they start failing and when they
// recover, never once per attempt.
type loggingExporter struct {
	sdkmetric.Exporter
	endpoint string

	mu      sync.Mutex
	failing bool
}

func (e *loggingExporter) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	err := e.Exporter.Export(ctx, rm)
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case err != nil && !e.failing && !errors.Is(err, context.Canceled):
		e.failing = true
		slog.WarnContext(ctx, "metrics export failing", "collector", e.endpoint, "error", err)
	case err == nil && e.failing:
		e.failing = false
		slog.InfoContext(ctx, "metrics export recovered", "collector", e.endpoint)
	}
	return err
}
