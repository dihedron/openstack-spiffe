package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"
)

// shutdownTimeout bounds the graceful shutdown: in-flight requests get this
// long to complete once the context ends.
const shutdownTimeout = 15 * time.Second

// run listens on addr and calls serveFn until the context ends.
func run(ctx context.Context, addr string, serveFn func(context.Context, net.Listener) error) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", addr, err)
	}
	return serveFn(ctx, ln)
}

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
