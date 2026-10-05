package metrics

import "time"

// Metrics exporters and OTLP protocols.
const (
	// ExporterPrometheus serves the metrics for scraping, on their own
	// listener.
	ExporterPrometheus = "prometheus"
	// ExporterOTLP pushes the metrics to an OpenTelemetry Collector.
	ExporterOTLP = "otlp"
	// ProtocolHTTP is OTLP over HTTP with protobuf payloads.
	ProtocolHTTP = "http/protobuf"
	// ProtocolGRPC is OTLP over gRPC.
	ProtocolGRPC = "grpc"
)

// Config is what New needs of the metrics configuration, which the
// configuration package defines and validates (see its Metrics type). The
// scrape listener's settings belong to the server, not here.
type Config struct {
	// Enabled turns the metrics on.
	Enabled bool
	// Exporter is ExporterPrometheus or ExporterOTLP.
	Exporter string
	// Runtime adds the Go runtime metrics.
	Runtime bool
	// ProjectAttribute adds project_id to the issued tokens counter.
	ProjectAttribute bool
	// MaxProjects caps the distinct project_id values; further projects
	// are counted under OtherProject.
	MaxProjects int
	// OTLP configures the push to an OpenTelemetry Collector.
	OTLP OTLPConfig
}

// OTLPConfig configures the push to an OpenTelemetry Collector.
type OTLPConfig struct {
	// Endpoint is the collector's https URL.
	Endpoint string
	// Protocol is ProtocolHTTP or ProtocolGRPC.
	Protocol string
	// Interval is the time between exports; Timeout bounds each.
	Interval, Timeout time.Duration
	// CACertPath verifies the collector (default: the system roots).
	CACertPath string
	// ClientCertPath and ClientKeyPath are the client certificate, if any.
	ClientCertPath, ClientKeyPath string
	// HeadersEnv names the environment variable holding the headers.
	HeadersEnv string
}
