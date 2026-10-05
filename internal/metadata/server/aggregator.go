package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/dihedron/openstack-spiffe/internal/metadata/aggregator"
	"github.com/dihedron/openstack-spiffe/internal/metadata/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/metadata/config"
	"github.com/dihedron/openstack-spiffe/internal/metadata/health"
	"github.com/dihedron/openstack-spiffe/internal/metadata/jwks"
	"github.com/dihedron/openstack-spiffe/internal/metadata/ratelimit"
	"github.com/dihedron/openstack-spiffe/internal/metadata/requestid"
)

// Aggregator is an assembled JWKS aggregator.
type Aggregator struct {
	cfg       *config.Aggregator
	merged    *aggregator.Aggregator
	readiness *health.Readiness
	handler   http.Handler
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
	return &Aggregator{cfg: cfg, merged: merged, readiness: readiness, handler: requestid.Middleware(resolver.Middleware(limited))}, nil
}

// Run listens on the configured address and serves until the context ends.
func (a *Aggregator) Run(ctx context.Context) error {
	return run(ctx, a.cfg.ListenAddr, a.Serve)
}

// Serve serves HTTPS on the listener (see serve) and runs the replica polling
// and readiness loops, until the context ends.
func (a *Aggregator) Serve(ctx context.Context, ln net.Listener) error {
	return serve(ctx, ln, a.handler, a.cfg.TLSCertPath, a.cfg.TLSKeyPath, a.cfg.MinTLSVersion(), false,
		[]any{"component", "jwks-aggregator"},
		a.merged.Run, a.readiness.Run)
}
