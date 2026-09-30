// Package server assembles a signer replica from its configuration: it
// builds every component, mounts the routes behind their middleware, runs
// the background loops and serves HTTPS until its context ends.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

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

// shutdownTimeout bounds the graceful shutdown: in-flight requests get this
// long to complete once the context ends.
const shutdownTimeout = 15 * time.Second

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
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.cfg.ListenAddr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves HTTPS on the listener, with the configured certificate and
// TLS 1.3 or later, and runs the key rotation and readiness loops. When the
// context ends, it stops accepting connections, lets in-flight requests
// complete (up to shutdownTimeout) and returns nil.
func (s *Signer) Serve(ctx context.Context, ln net.Listener) error {
	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertPath, s.cfg.TLSKeyPath)
	if err != nil {
		ln.Close()
		return fmt.Errorf("loading TLS certificate: %w", err)
	}
	srv := &http.Server{
		Handler:           s.handler,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// TLS handshake failures from scanners are not worth more than debug
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}

	background, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	wg.Go(func() { s.keys.Run(background) })
	wg.Go(func() { s.readiness.Run(background) })

	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()
	slog.InfoContext(ctx, "signer serving", "address", ln.Addr().String(), "replica_id", s.cfg.ReplicaID)

	var result error
	select {
	case err := <-served:
		result = fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
		slog.InfoContext(ctx, "signer shutting down", "replica_id", s.cfg.ReplicaID)
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			result = fmt.Errorf("shutting down: %w", err)
		}
		<-served // http.ErrServerClosed
	}
	stop()
	wg.Wait()
	return result
}
