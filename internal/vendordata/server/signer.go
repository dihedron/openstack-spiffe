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

	"github.com/dihedron/openstack-spiffe/internal/vendordata/attest"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/auth"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/claims"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/config"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/health"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/jwks"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/keystore"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/novalookup"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/osclient"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/ratelimit"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/requestid"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/token"
	"github.com/gophercloud/gophercloud/v2"
)

// Signer is an assembled signer replica.
type Signer struct {
	cfg       *config.Signer
	keys      *keystore.Ephemeral
	readiness *health.Readiness
	handler   http.Handler
}

// NewSigner builds a signer replica from a checked configuration and the
// service's authenticated OpenStack client, and generates its first key.
//
// Routes: POST /attest behind the per-source limit and body cap and the
// Keystone authentication; GET /.well-known/jwks.json, /liveness and
// /readiness unauthenticated. The client address is resolved, and a request
// ID assigned, before anything else.
func NewSigner(ctx context.Context, cfg *config.Signer, client *osclient.Client) (*Signer, error) {
	if cfg == nil || client == nil {
		return nil, errors.New("creating signer: missing configuration or OpenStack client")
	}
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
		claims.WithCustomClaims(cfg.CustomClaims))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	minter, err := token.NewMinter(keys, builder)
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
		novalookup.WithProjectCacheTTL(cfg.Keystone.ProjectCacheTTL))
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
		auth.WithCacheTTL(cfg.Keystone.ValidationCacheTTL))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	attestHandler, err := attest.NewHandler(instanceLimiter, verifier, minter, cfg.MaxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	protected, err := ratelimit.SourceMiddleware(sourceLimiter, cfg.MaxBodyBytes, authenticator.Middleware(attestHandler))
	if err != nil {
		return nil, fmt.Errorf("creating signer: %w", err)
	}
	jwksHandler, err := jwks.NewHandler(keys)
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

	mux := http.NewServeMux()
	mux.Handle("/attest", protected)
	mux.Handle("/.well-known/jwks.json", jwksHandler)
	mux.Handle("/liveness", health.Liveness())
	mux.Handle("/readiness", readiness)

	return &Signer{
		cfg:       cfg,
		keys:      keys,
		readiness: readiness,
		handler:   requestid.Middleware(resolver.Middleware(mux)),
	}, nil
}

// Run listens on the configured address and serves until the context ends.
func (s *Signer) Run(ctx context.Context) error {
	return run(ctx, s.cfg.ListenAddr, s.Serve)
}

// Serve serves HTTPS on the listener (see serve) and runs the key rotation
// and readiness loops, until the context ends.
func (s *Signer) Serve(ctx context.Context, ln net.Listener) error {
	return serve(ctx, ln, s.handler, s.cfg.TLSCertPath, s.cfg.TLSKeyPath, s.cfg.MinTLSVersion(),
		[]any{"component", "signer", "replica_id", s.cfg.ReplicaID},
		s.keys.Run, s.readiness.Run)
}
