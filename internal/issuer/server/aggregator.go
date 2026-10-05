package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/dihedron/openstack-spiffe/internal/issuer/aggregator"
	"github.com/dihedron/openstack-spiffe/internal/issuer/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"github.com/dihedron/openstack-spiffe/internal/issuer/health"
	"github.com/dihedron/openstack-spiffe/internal/issuer/jwks"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/ratelimit"
	"github.com/dihedron/openstack-spiffe/internal/issuer/requestid"
	"github.com/dihedron/openstack-spiffe/pkg/metadata"
)

// aggregatorRoutes are the paths an aggregator serves, as recorded in the
// metrics.
var aggregatorRoutes = []string{"/.well-known/jwks.json", "/liveness", "/readiness"}

// Aggregator is an assembled JWKS aggregator.
type Aggregator struct {
	cfg       *config.Aggregator
	merged    *aggregator.Aggregator
	readiness *health.Readiness
	handler   http.Handler
	metrics   *metrics.Metrics
}

// NewAggregator builds a JWKS aggregator from a checked configuration.
//
// Routes: GET /.well-known/jwks.json (the merged set, with Cache-Control
// max-age = cache_max_age), /liveness and /readiness (ready while at least
// one replica has been fetched within stale_key_retention), all
// unauthenticated and behind a per-source rate limit (D-5). The client
// address is resolved, and a request ID assigned, before anything else.
func NewAggregator(cfg *config.Aggregator) (*Aggregator, error) {
	if cfg == nil {
		return nil, errors.New("creating aggregator: missing configuration")
	}
	client, err := aggregator.NewHTTPClient(cfg.ReplicaCACertPath, cfg.MinTLSVersion())
	if err != nil {
		return nil, fmt.Errorf("creating aggregator: %w", err)
	}
	merged, err := aggregator.New(cfg.Replicas, client,
		aggregator.WithPollInterval(cfg.PollInterval),
		aggregator.WithFetchTimeout(cfg.FetchTimeout),
		aggregator.WithStaleKeyRetention(cfg.StaleKeyRetention))
	if err != nil {
		return nil, fmt.Errorf("creating aggregator: %w", err)
	}
	jwksHandler, err := jwks.NewHandler(merged, jwks.WithMaxAge(cfg.CacheMaxAge))
	if err != nil {
		return nil, fmt.Errorf("creating aggregator: %w", err)
	}
	readiness, err := health.NewReadiness([]health.Check{{Name: "replicas", Run: merged.Check}})
	if err != nil {
		return nil, fmt.Errorf("creating aggregator: %w", err)
	}

	limiter, err := ratelimit.NewLimiter(cfg.RateLimitPerSource.Events, cfg.RateLimitPerSource.Per)
	if err != nil {
		return nil, fmt.Errorf("creating aggregator: per-source limit: %w", err)
	}
	resolver, err := clientaddr.NewResolver(cfg.ClientAddress.TrustedProxies, cfg.ClientAddress.Header)
	if err != nil {
		return nil, fmt.Errorf("creating aggregator: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", jwksHandler)
	mux.Handle("/liveness", health.Liveness())
	mux.Handle("/readiness", readiness)
	limited, err := ratelimit.LimitSources(limiter, mux)
	if err != nil {
		return nil, fmt.Errorf("creating aggregator: %w", err)
	}
	// aggregators have no replica ID: the host name identifies them
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	m, err := metrics.New(context.Background(), cfg.Metrics.Settings(),
		metrics.Resource{Component: "aggregator", InstanceID: host, Version: metadata.Version},
		cfg.MinTLSVersion())
	if err != nil {
		return nil, fmt.Errorf("creating aggregator: %w", err)
	}
	if err := errors.Join(
		observeFetches(m, merged),
		observeLimiter(m, metrics.LimiterSource, limiter),
		observeReadiness(m, readiness),
	); err != nil {
		return nil, fmt.Errorf("creating aggregator: %w", errors.Join(err, m.Shutdown(context.Background())))
	}
	return &Aggregator{cfg: cfg, merged: merged, readiness: readiness, metrics: m,
		handler: m.Middleware(aggregatorRoutes, requestid.Middleware(resolver.Middleware(limited)))}, nil
}

// Run listens on the configured address, and on the metrics address when
// the metrics are served for scraping, and serves until the context ends.
func (a *Aggregator) Run(ctx context.Context) error {
	return runWithMetrics(ctx, a.cfg.ListenAddr, a.metrics, a.cfg.Metrics.Prometheus.ListenAddr, a.ServeWithMetrics)
}

// Serve serves HTTPS on the listener (see serve) and runs the replica polling
// and readiness loops, until the context ends.
func (a *Aggregator) Serve(ctx context.Context, ln net.Listener) error {
	return a.ServeWithMetrics(ctx, ln, nil)
}

// ServeWithMetrics is Serve, also serving the Prometheus endpoint on
// metricsLn if it is not nil and the metrics are exported to Prometheus.
// The metrics are flushed when it returns.
func (a *Aggregator) ServeWithMetrics(ctx context.Context, ln, metricsLn net.Listener) error {
	defer shutdownMetrics(ctx, a.metrics)
	loops := []func(context.Context) error{a.merged.Run, a.readiness.Run}
	if metricsLn != nil && a.metrics.Handler() != nil {
		loop, err := metricsLoop(a.cfg.Metrics.Prometheus, a.metrics, a.cfg.MinTLSVersion(), metricsLn)
		if err != nil {
			_ = ln.Close()
			_ = metricsLn.Close()
			return err
		}
		loops = append(loops, loop)
	}
	return serve(ctx, ln, a.handler, a.cfg.TLSCertPath, a.cfg.TLSKeyPath, a.cfg.MinTLSVersion(), false,
		[]any{"component", "jwks-aggregator"},
		loops...)
}
