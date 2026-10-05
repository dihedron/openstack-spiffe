// Package server assembles a signer replica from its configuration: it
// builds every component, mounts the routes behind their middleware, runs
// the background loops and serves HTTPS until its context ends.
package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/dihedron/openstack-spiffe/internal/issuer/aggregator"
	"github.com/dihedron/openstack-spiffe/internal/issuer/attest"
	"github.com/dihedron/openstack-spiffe/internal/issuer/auth"
	"github.com/dihedron/openstack-spiffe/internal/issuer/claims"
	"github.com/dihedron/openstack-spiffe/internal/issuer/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"github.com/dihedron/openstack-spiffe/internal/issuer/health"
	"github.com/dihedron/openstack-spiffe/internal/issuer/jwks"
	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/novalookup"
	"github.com/dihedron/openstack-spiffe/internal/issuer/osclient"
	"github.com/dihedron/openstack-spiffe/internal/issuer/ratelimit"
	"github.com/dihedron/openstack-spiffe/internal/issuer/requestid"
	"github.com/dihedron/openstack-spiffe/internal/issuer/restrict"
	"github.com/dihedron/openstack-spiffe/internal/issuer/token"
	"github.com/dihedron/openstack-spiffe/pkg/metadata"
	"github.com/gophercloud/gophercloud/v2"
)

// signerRoutes are the paths a signer serves, as recorded in the metrics.
var signerRoutes = []string{"/attest", "/jwks/local.json", "/.well-known/jwks.json", "/liveness", "/readiness"}

// Signer is an assembled signer replica.
type Signer struct {
	cfg       *config.Signer
	keys      *keystore.Ephemeral
	peers     *aggregator.Aggregator // nil without peers
	readiness *health.Readiness
	handler   http.Handler
	metrics   *metrics.Metrics
	// requestClientCert asks TLS clients for a certificate, which the
	// /attest guard verifies (attest.client_ca_path)
	requestClientCert bool
}

// NewSigner builds a signer replica from a checked configuration and the
// service's authenticated OpenStack client, and generates its first key.
//
// Routes: POST /attest behind the source allowlist and client certificate
// check (attest), the per-source limit and body cap and the Keystone
// authentication; GET /jwks/local.json (the replica's own keys),
// /.well-known/jwks.json (the own keys merged with the peers', or the own keys
// alone without peers), /liveness and /readiness unauthenticated, behind
// their own per-source limit. The client
// address is resolved, and a request ID assigned, before anything else.
func NewSigner(ctx context.Context, cfg *config.Signer, client *osclient.Client) (_ *Signer, err error) {
	if cfg == nil || client == nil {
		return nil, errors.New("creating signer: missing configuration or OpenStack client")
	}
	m, err := metrics.New(ctx, cfg.Metrics.Settings(),
		metrics.Resource{Component: "signer", InstanceID: cfg.ReplicaID, Version: metadata.Version},
		cfg.MinTLSVersion())
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	defer func() {
		if err != nil {
			_ = m.Shutdown(ctx) // the construction error is the one worth reporting
		}
	}()
	identity, err := client.Identity()
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	keys, err := keystore.NewEphemeral(ctx, cfg.ReplicaID, cfg.KeyStore.Algorithm,
		keystore.WithRotationInterval(cfg.KeyStore.RotationInterval),
		keystore.WithPublishAhead(cfg.KeyStore.PublishAhead))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	builder, err := claims.NewBuilder(
		claims.WithTTL(cfg.TokenTTL()),
		claims.WithAllowlist(cfg.Tags.Allowlist),
		claims.WithCustomClaims(cfg.CustomClaims),
		claims.WithMetrics(m))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	minter, err := token.NewMinter(keys, builder, token.WithMetrics(m))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	checks := []health.Check{
		{Name: "key_store", Run: keys.Check},
		{Name: "keystone", Run: client.CheckIdentity},
	}
	var compute *gophercloud.ServiceClient // only needed for instance verification
	if cfg.NovaLookup.Enabled {
		if compute, err = client.Compute(); err != nil {
			return nil, fmt.Errorf("creating signer: %w", err)
		}
		checks = append(checks, health.Check{Name: "nova", Run: client.CheckCompute})
	}
	backend, err := novalookup.NewOpenStack(compute, identity)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	verifier, err := novalookup.NewVerifier(backend,
		novalookup.WithInstanceVerification(cfg.NovaLookup.Enabled),
		novalookup.WithAllowedStatuses(cfg.NovaLookup.AllowedStatuses),
		novalookup.WithEnrichment(cfg.Enrich),
		novalookup.WithServerCacheTTL(cfg.NovaLookup.CacheTTL),
		novalookup.WithProjectCacheTTL(cfg.Keystone.ProjectCacheTTL),
		novalookup.WithMetrics(m))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	instanceLimiter, err := ratelimit.NewLimiter(cfg.RateLimitPerInstance.Events, cfg.RateLimitPerInstance.Per)
	if err != nil {
		return nil, fmt.Errorf("creating signer: per-instance limit: %w", err)
	}
	sourceLimiter, err := ratelimit.NewLimiter(cfg.RateLimitPerSource.Events, cfg.RateLimitPerSource.Per)
	if err != nil {
		return nil, fmt.Errorf("creating signer: per-source limit: %w", err)
	}
	validator, err := auth.NewKeystoneValidator(identity)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	authenticator, err := auth.NewAuthenticator(validator, cfg.Keystone.AllowedUsers, cfg.Keystone.RequiredRole,
		auth.WithCacheTTL(cfg.Keystone.ValidationCacheTTL),
		auth.WithMaxConcurrentValidations(cfg.Keystone.MaxConcurrentValidations),
		auth.WithMetrics(m))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	attestHandler, err := attest.NewHandler(instanceLimiter, verifier, minter, cfg.MaxBodyBytes, attest.WithMetrics(m))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	rateLimited, err := ratelimit.SourceMiddleware(sourceLimiter, cfg.MaxBodyBytes, authenticator.Middleware(attestHandler))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	// the source allowlist and the client certificate come first: a refused
	// request costs neither a rate-limit slot, nor a body read, nor a
	// Keystone call (S-3, D-2)
	guard, err := restrict.New(cfg.Attest.AllowedSources, cfg.Attest.ClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	protected := guard.Middleware(rateLimited)
	localHandler, err := jwks.NewHandler(keys)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	peers, mergedHandler, err := newPeerAggregation(cfg, keys, localHandler)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	readiness, err := health.NewReadiness(checks)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	resolver, err := clientaddr.NewResolver(cfg.ClientAddress.TrustedProxies, cfg.ClientAddress.Header)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	// the unauthenticated endpoints get their own bucket per source, so
	// that a flood against them never starves Nova's calls (D-5)
	publicLimiter, err := ratelimit.NewLimiter(cfg.RateLimitPerSourcePublic.Events, cfg.RateLimitPerSourcePublic.Per)
	if err != nil {
		return nil, fmt.Errorf("creating signer: public per-source limit: %w", err)
	}
	public := http.NewServeMux()
	public.Handle("/jwks/local.json", localHandler)
	public.Handle("/.well-known/jwks.json", mergedHandler)
	public.Handle("/liveness", health.Liveness())
	public.Handle("/readiness", readiness)
	limitedPublic, err := ratelimit.LimitSources(publicLimiter, public)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}

	mux := http.NewServeMux()
	// outermost: every call is recorded, with the reason named by the layer
	// that answered it
	mux.Handle("/attest", m.AttestMiddleware(protected))
	mux.Handle("/", limitedPublic)

	return &Signer{
		cfg:               cfg,
		keys:              keys,
		peers:             peers,
		readiness:         readiness,
		metrics:           m,
		requestClientCert: guard.RequestsClientCertificates(),
		handler:           m.Middleware(signerRoutes, requestid.Middleware(resolver.Middleware(mux))),
	}, nil
}

// Run listens on the configured address, and on the metrics address when
// the metrics are served for scraping, and serves until the context ends.
func (s *Signer) Run(ctx context.Context) error {
	return runWithMetrics(ctx, s.cfg.ListenAddr, s.metrics, s.cfg.Metrics.Prometheus.ListenAddr, s.ServeWithMetrics)
}

// Serve serves HTTPS on the listener (see serve) and runs the key rotation,
// readiness and (with peers) peer polling loops, until the context ends.
func (s *Signer) Serve(ctx context.Context, ln net.Listener) error {
	return s.ServeWithMetrics(ctx, ln, nil)
}

// ServeWithMetrics is Serve, also serving the Prometheus endpoint on
// metricsLn if it is not nil and the metrics are exported to Prometheus.
// The metrics are flushed when it returns.
func (s *Signer) ServeWithMetrics(ctx context.Context, ln, metricsLn net.Listener) error {
	defer shutdownMetrics(ctx, s.metrics)
	loops := []func(context.Context) error{s.keys.Run, s.readiness.Run}
	if s.peers != nil {
		loops = append(loops, s.peers.Run)
	}
	if metricsLn != nil && s.metrics.Handler() != nil {
		loop, err := metricsLoop(s.cfg.Metrics.Prometheus, s.metrics.Handler(), s.cfg.MinTLSVersion(), metricsLn)
		if err != nil {
			_ = ln.Close()
			_ = metricsLn.Close()
			return err
		}
		loops = append(loops, loop)
	}
	return serve(ctx, ln, s.handler, s.cfg.TLSCertPath, s.cfg.TLSKeyPath, s.cfg.MinTLSVersion(), s.requestClientCert,
		[]any{"component", "signer", "replica_id", s.cfg.ReplicaID},
		loops...)
}

// newPeerAggregation returns the peer aggregator and the handler of the
// merged JWK Set. Without peers, there is no aggregator and the merged set is
// the local one, served by the same handler. Peers are deliberately not a
// readiness check: the merged set always holds the replica's own keys, and a
// peer outage must not take the replica out of Nova's load balancer.
func newPeerAggregation(cfg *config.Signer, keys jwks.KeySource, local http.Handler) (*aggregator.Aggregator, http.Handler, error) {
	if !cfg.Peers.Enabled() {
		return nil, local, nil
	}
	client, err := aggregator.NewHTTPClient(cfg.Peers.CACertPath, cfg.MinTLSVersion())
	if err != nil {
		return nil, nil, fmt.Errorf("peers: %w", err)
	}
	peers, err := aggregator.New(cfg.Peers.URLs, client,
		aggregator.WithPollInterval(cfg.Peers.PollInterval),
		aggregator.WithFetchTimeout(cfg.Peers.FetchTimeout),
		aggregator.WithStaleKeyRetention(cfg.Peers.StaleKeyRetention),
		aggregator.WithLocal(keys))
	if err != nil {
		return nil, nil, fmt.Errorf("peers: %w", err)
	}
	merged, err := jwks.NewHandler(peers, jwks.WithMaxAge(cfg.Peers.CacheMaxAge))
	if err != nil {
		return nil, nil, fmt.Errorf("peers: %w", err)
	}
	return peers, merged, nil
}
