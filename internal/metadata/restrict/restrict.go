// Package restrict confines /attest to the hosts Nova calls it from (S-3,
// D-2): a source allowlist on the client address, and a client certificate
// chaining to a configured CA bundle. Either one confines stolen vendordata
// credentials to the nova-api-metadata hosts. Refusals happen before the
// per-source rate limit, before the body is read and before any Keystone
// call.
package restrict

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/dihedron/openstack-spiffe/internal/metadata/clientaddr"
)

// Guard enforces the restrictions; the zero restriction lets every request
// through.
type Guard struct {
	sources []netip.Prefix
	roots   *x509.CertPool
}

// New returns a Guard accepting requests from the given sources (IP
// addresses or CIDR ranges; none means any) and, if caPath is not empty,
// only with a client certificate chaining to the PEM bundle at caPath.
func New(sources []string, caPath string) (*Guard, error) {
	g := &Guard{}
	for _, s := range sources {
		p, err := clientaddr.ParseTrustedProxy(s)
		if err != nil {
			return nil, fmt.Errorf("allowed source %q: %w", s, err)
		}
		g.sources = append(g.sources, p)
	}
	if caPath != "" {
		data, err := os.ReadFile(filepath.Clean(caPath))
		if err != nil {
			return nil, fmt.Errorf("reading client CA bundle: %w", err)
		}
		g.roots = x509.NewCertPool()
		if !g.roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("no PEM certificates found in client CA bundle %s", caPath)
		}
	}
	return g, nil
}

// RequestsClientCertificates reports whether the TLS listener must ask
// clients for a certificate. It asks every client (tls.RequestClientCert):
// the path is unknown during the handshake. It does not verify them there,
// so that an invalid certificate gets a 403 from /attest, rather than a
// failed handshake that would also lock its holder out of the other
// endpoints; the Guard verifies it.
func (g *Guard) RequestsClientCertificates() bool { return g.roots != nil }

// Middleware refuses, with 403, the requests that do not satisfy the
// restrictions, and passes the others to next. Refusals are logged with the
// client address, never with anything the client sent beyond it.
func (g *Guard) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := g.check(r); err != nil {
			slog.WarnContext(r.Context(), "rejecting /attest request", "client_address", clientaddr.String(r), "reason", err)
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (g *Guard) check(r *http.Request) error {
	if len(g.sources) > 0 {
		addr, ok := clientaddr.From(r)
		if !ok || !slices.ContainsFunc(g.sources, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			return errors.New("source not in attest.allowed_sources")
		}
	}
	if g.roots == nil {
		return nil
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return errors.New("no client certificate")
	}
	chain := r.TLS.PeerCertificates
	if chain[0].IsCA {
		// Go accepts a root as its own leaf: a CA identifies no client
		return errors.New("invalid client certificate: a CA certificate")
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         g.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("invalid client certificate: %w", err)
	}
	return nil
}
