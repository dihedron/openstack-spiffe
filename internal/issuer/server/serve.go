package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/ratelimit"
)

// shutdownTimeout bounds the graceful shutdown: in-flight requests get this
// long to complete once the context ends.
const shutdownTimeout = 15 * time.Second

// serve serves HTTPS on the listener with the given certificate, TLS
// minTLSVersion or later and bounded timeouts, asking clients for a
// certificate if requestClientCert is set, while running the background loops. When the
// context ends, it stops accepting connections, lets in-flight requests
// complete (up to shutdownTimeout), stops the loops and returns nil.
func serve(ctx context.Context, ln net.Listener, handler http.Handler, certPath, keyPath string, minTLSVersion uint16, requestClientCert bool, logAttrs []any, loops ...func(context.Context) error) error {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		_ = ln.Close() // the certificate error is the one worth reporting
		return fmt.Errorf("loading TLS certificate: %w", err)
	}
	// asked of every client, never verified here: the /attest guard
	// verifies it, so that an invalid certificate gets a 403 from /attest
	// rather than a failed handshake on every endpoint
	clientAuth := tls.NoClientCert
	if requestClientCert {
		clientAuth = tls.RequestClientCert
	}
	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         &tls.Config{MinVersion: minTLSVersion, Certificates: []tls.Certificate{cert}, ClientAuth: clientAuth},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		// TLS handshake failures from scanners are not worth more than debug
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	log := slog.With(logAttrs...)

	background, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	for _, loop := range loops {
		wg.Go(func() {
			if err := loop(background); err != nil {
				log.ErrorContext(ctx, "background loop failed", "error", err)
			}
		})
	}

	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()
	log.InfoContext(ctx, "serving", "address", ln.Addr().String())

	var result error
	select {
	case err := <-served:
		result = fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
		log.InfoContext(ctx, "shutting down")
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

// metricsShutdownTimeout bounds the metrics' last export at shutdown.
const metricsShutdownTimeout = 5 * time.Second

// metricsLoop returns a background loop serving the Prometheus endpoint on
// its own listener (I-8, D-10): GET /metrics only, plain HTTP on loopback,
// TLS (with client certificates when client_ca_path is set) otherwise,
// behind its own per-source limit and the service's server timeouts.
func metricsLoop(cfg config.MetricsPrometheus, metricsHandler http.Handler, minTLSVersion uint16, ln net.Listener) (func(context.Context) error, error) {
	limiter, err := ratelimit.NewLimiter(cfg.RateLimitPerSource.Events, cfg.RateLimitPerSource.Per)
	if err != nil {
		return nil, fmt.Errorf("metrics per-source limit: %w", err)
	}
	resolver, err := clientaddr.NewResolver(nil, "")
	if err != nil {
		return nil, fmt.Errorf("metrics client address: %w", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		metricsHandler.ServeHTTP(w, r)
	}))
	limited, err := ratelimit.LimitSources(limiter, mux)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           resolver.Middleware(limited),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	useTLS := cfg.TLSCertPath != ""
	if useTLS {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading the metrics TLS certificate: %w", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: minTLSVersion, Certificates: []tls.Certificate{cert}}
		if cfg.ClientCAPath != "" {
			data, err := os.ReadFile(filepath.Clean(cfg.ClientCAPath))
			if err != nil {
				return nil, fmt.Errorf("reading metrics.prometheus.client_ca_path: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("metrics.prometheus.client_ca_path %s: no PEM certificates", cfg.ClientCAPath)
			}
			srv.TLSConfig.ClientCAs = pool
			srv.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	return func(ctx context.Context) error {
		served := make(chan error, 1)
		go func() {
			if useTLS {
				served <- srv.ServeTLS(ln, "", "")
			} else {
				served <- srv.Serve(ln)
			}
		}()
		slog.InfoContext(ctx, "serving metrics", "address", ln.Addr().String(), "tls", useTLS)
		select {
		case err := <-served:
			return fmt.Errorf("serving metrics: %w", err)
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
			defer cancel()
			err := srv.Shutdown(shutdownCtx)
			<-served
			if err != nil {
				return fmt.Errorf("shutting down the metrics server: %w", err)
			}
			return nil
		}
	}, nil
}

// runWithMetrics listens on addr and, when the metrics are served for
// scraping, on the metrics address, then calls serveFn until the context
// ends.
func runWithMetrics(ctx context.Context, addr string, m *metrics.Metrics, metricsAddr string, serveFn func(context.Context, net.Listener, net.Listener) error) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	var metricsLn net.Listener
	if m.Handler() != nil {
		if metricsLn, err = lc.Listen(ctx, "tcp", metricsAddr); err != nil {
			_ = ln.Close() // the metrics listener's error is the one worth reporting
			return fmt.Errorf("listening on %s for metrics: %w", metricsAddr, err)
		}
	}
	return serveFn(ctx, ln, metricsLn)
}

// shutdownMetrics flushes the metrics once the service has stopped.
func shutdownMetrics(ctx context.Context, m *metrics.Metrics) {
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), metricsShutdownTimeout)
	defer cancel()
	if err := m.Shutdown(shutdownCtx); err != nil {
		slog.WarnContext(ctx, "flushing the metrics", "error", err)
	}
}
