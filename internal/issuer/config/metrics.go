package config

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"time"
)

// Metrics exporters and OTLP protocols (see openstack-spire-issuer-metrics.md).
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

const minOTLPInterval = 5 * time.Second

var (
	metricsExporters = []string{ExporterPrometheus, ExporterOTLP}
	otlpProtocols    = []string{ProtocolHTTP, ProtocolGRPC}
	envVarName       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Metrics configures the metrics of a signer or an aggregator (I-8, D-10).
// The settings are validated even while metrics are disabled.
type Metrics struct {
	// Enabled turns the metrics on.
	Enabled bool `yaml:"enabled"`
	// Exporter is ExporterPrometheus or ExporterOTLP.
	Exporter string `yaml:"exporter"`
	// Runtime adds the Go runtime metrics.
	Runtime bool `yaml:"runtime"`
	// ProjectAttribute adds project_id to the issued tokens counter (signer
	// only): it discloses per-tenant activity.
	ProjectAttribute bool `yaml:"project_attribute"`
	// MaxProjects caps the distinct project_id values reported per process;
	// tokens of further projects are counted under "other".
	MaxProjects int `yaml:"max_projects"`
	// Prometheus configures the scrape endpoint.
	Prometheus MetricsPrometheus `yaml:"prometheus"`
	// OTLP configures the push to an OpenTelemetry Collector.
	OTLP MetricsOTLP `yaml:"otlp"`
}

// MetricsPrometheus configures the scrape endpoint, which has its own
// listener: never the service's.
type MetricsPrometheus struct {
	// ListenAddr is the address of the metrics listener; beyond loopback it
	// requires TLS and client certificates.
	ListenAddr string `yaml:"listen_addr"`
	// TLSCertPath is the listener's certificate (PEM).
	TLSCertPath string `yaml:"tls_cert_path"`
	// TLSKeyPath is the listener's private key (PEM).
	TLSKeyPath string `yaml:"tls_key_path"`
	// ClientCAPath is a PEM CA bundle: when set, scrapers must present a
	// certificate chaining to it.
	ClientCAPath string `yaml:"client_ca_path"`
	// RateLimitPerSource limits scrapes per source IP (D-10).
	RateLimitPerSource Rate `yaml:"rate_limit_per_source"`
}

// MetricsOTLP configures the push to an OpenTelemetry Collector, always over
// verified TLS.
type MetricsOTLP struct {
	// Endpoint is the collector's https URL.
	Endpoint string `yaml:"endpoint"`
	// Protocol is ProtocolHTTP or ProtocolGRPC.
	Protocol string `yaml:"protocol"`
	// Interval is the time between exports.
	Interval time.Duration `yaml:"interval"`
	// Timeout bounds each export; shorter than Interval.
	Timeout time.Duration `yaml:"timeout"`
	// CACertPath is a PEM CA bundle verifying the collector; default: the
	// system roots.
	CACertPath string `yaml:"ca_cert_path"`
	// ClientCertPath is the certificate presented to the collector (PEM).
	ClientCertPath string `yaml:"client_cert_path"`
	// ClientKeyPath is the key of ClientCertPath (PEM).
	ClientKeyPath string `yaml:"client_key_path"`
	// HeadersEnv names the environment variable holding the headers sent
	// to the collector ("key=value,..."), e.g. credentials, which never
	// belong in the file.
	HeadersEnv string `yaml:"headers_env"`
}

func defaultMetrics() Metrics {
	return Metrics{
		Exporter:    ExporterPrometheus,
		Runtime:     true,
		MaxProjects: 500,
		Prometheus: MetricsPrometheus{
			ListenAddr:         "127.0.0.1:9464",
			RateLimitPerSource: Rate{Events: 10, Per: time.Second},
		},
		OTLP: MetricsOTLP{
			Protocol: ProtocolHTTP,
			Interval: 30 * time.Second,
			Timeout:  10 * time.Second,
		},
	}
}

// IsLoopback reports whether a listen address only accepts connections from
// the host itself: a loopback IP address, or localhost. An empty host means
// every interface.
func IsLoopback(listenAddr string) bool {
	host, _, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// checkMetrics validates a metrics block; serviceAddr is the service's own
// listen address, which the metrics listener must not take.
func checkMetrics[T any](r *Result[T], m Metrics, serviceAddr string) {
	if !slices.Contains(metricsExporters, m.Exporter) {
		r.errorf(KindRuleViolation, "metrics.exporter", "%q is not one of %v", m.Exporter, metricsExporters)
	}
	if m.MaxProjects < 1 {
		r.errorf(KindRuleViolation, "metrics.max_projects", "%d must be at least 1", m.MaxProjects)
	}

	p := m.Prometheus
	if _, _, err := net.SplitHostPort(p.ListenAddr); err != nil {
		r.errorf(KindInvalidValue, "metrics.prometheus.listen_addr", "%q is not a host:port address: %v", p.ListenAddr, err)
	} else {
		if sameListener(p.ListenAddr, serviceAddr) {
			r.errorf(KindRuleViolation, "metrics.prometheus.listen_addr", "%q overlaps the service's listen_addr %q: metrics are never served on the service's listener", p.ListenAddr, serviceAddr)
		}
		checkPair(r, "metrics.prometheus.tls_cert_path", p.TLSCertPath, "metrics.prometheus.tls_key_path", p.TLSKeyPath)
		tls := p.TLSCertPath != "" && p.TLSKeyPath != ""
		if p.ClientCAPath != "" && !tls {
			r.errorf(KindRuleViolation, "metrics.prometheus.client_ca_path", "requires tls_cert_path and tls_key_path")
		}
		if m.Exporter == ExporterPrometheus && !IsLoopback(p.ListenAddr) {
			if !tls {
				r.errorf(KindRuleViolation, "metrics.prometheus.listen_addr", "%q is not a loopback address: it requires tls_cert_path, tls_key_path and client_ca_path (I-8)", p.ListenAddr)
			} else if p.ClientCAPath == "" {
				r.errorf(KindRuleViolation, "metrics.prometheus.client_ca_path", "is required: %q is not a loopback address, so scrapers must present a certificate (I-8)", p.ListenAddr)
			}
		}
	}

	o := m.OTLP
	if !slices.Contains(otlpProtocols, o.Protocol) {
		r.errorf(KindRuleViolation, "metrics.otlp.protocol", "%q is not one of %v", o.Protocol, otlpProtocols)
	}
	if o.Endpoint == "" {
		if m.Exporter == ExporterOTLP {
			r.errorf(KindRuleViolation, "metrics.otlp.endpoint", "is required with exporter %q", ExporterOTLP)
		}
	} else if u, err := url.Parse(o.Endpoint); err != nil || u.Scheme != "https" || u.Host == "" {
		r.errorf(KindRuleViolation, "metrics.otlp.endpoint", "%q must be an https URL with a host: metrics never travel in clear text", o.Endpoint)
	}
	if o.Interval < minOTLPInterval {
		r.errorf(KindRuleViolation, "metrics.otlp.interval", "%v must be at least %v", o.Interval, minOTLPInterval)
	}
	if o.Timeout <= 0 || o.Timeout >= o.Interval {
		r.errorf(KindRuleViolation, "metrics.otlp.timeout", "%v must be positive and shorter than metrics.otlp.interval (%v)", o.Timeout, o.Interval)
	}
	checkPair(r, "metrics.otlp.client_cert_path", o.ClientCertPath, "metrics.otlp.client_key_path", o.ClientKeyPath)
	if o.HeadersEnv != "" && !envVarName.MatchString(o.HeadersEnv) {
		r.errorf(KindRuleViolation, "metrics.otlp.headers_env", "%q is not an environment variable name", o.HeadersEnv)
	}
}

// warnMetrics flags risky metrics settings; projects tells whether the
// service has a project attribute to report (the signer).
func warnMetrics[T any](r *Result[T], m Metrics, projects bool) {
	if m.ProjectAttribute {
		if projects {
			r.warnf("metrics.project_attribute", "enabled: the metrics disclose per-tenant activity to whoever can read them (I-8)")
		} else {
			r.warnf("metrics.project_attribute", "ignored: the aggregator issues no tokens")
		}
	}
	if m.Exporter == ExporterOTLP && m.OTLP.CACertPath == "" {
		r.warnf("metrics.otlp.ca_cert_path", "not set: every public CA is trusted for the collector")
	}
}

// checkMetricsFiles checks the files a metrics block references.
func checkMetricsFiles[T any](r *Result[T], m Metrics, now time.Time) {
	checkKeyPair(r, "metrics.prometheus.tls_cert_path", m.Prometheus.TLSCertPath, "metrics.prometheus.tls_key_path", m.Prometheus.TLSKeyPath, now)
	checkCABundle(r, "metrics.prometheus.client_ca_path", m.Prometheus.ClientCAPath)
	checkCABundle(r, "metrics.otlp.ca_cert_path", m.OTLP.CACertPath)
	checkKeyPair(r, "metrics.otlp.client_cert_path", m.OTLP.ClientCertPath, "metrics.otlp.client_key_path", m.OTLP.ClientKeyPath, now)
}

// checkPair flags a certificate without its key, or a key without its
// certificate.
func checkPair[T any](r *Result[T], certKey, certPath, keyKey, keyPath string) {
	switch {
	case certPath != "" && keyPath == "":
		r.errorf(KindRuleViolation, keyKey, "is required with %s", certKey)
	case certPath == "" && keyPath != "":
		r.errorf(KindRuleViolation, certKey, "is required with %s", keyKey)
	}
}

// sameListener reports whether two listen addresses can collide: the same
// port, and the same host or a host listening on every interface. Port 0
// (any free port) never collides.
func sameListener(a, b string) bool {
	hostA, portA, errA := net.SplitHostPort(a)
	hostB, portB, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil || portA != portB || portA == "0" {
		return false
	}
	wildcard := func(host string) bool { return host == "" || host == "0.0.0.0" || host == "::" }
	return hostA == hostB || wildcard(hostA) || wildcard(hostB)
}
