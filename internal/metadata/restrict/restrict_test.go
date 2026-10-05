package restrict

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// issuer is a test CA.
type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string) issuer {
	t.Helper()
	return issue(t, nil, name, true, nil, time.Now().Add(time.Hour))
}

// issue creates a certificate signed by parent (self-signed if nil).
func issue(t *testing.T, parent *issuer, name string, ca bool, usages []x509.ExtKeyUsage, notAfter time.Time) issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  ca,
		BasicConstraintsValid: true,
		ExtKeyUsage:           usages,
	}
	if ca {
		template.KeyUsage = x509.KeyUsageCertSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
	}
	signer, signerKey := template, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return issuer{cert: cert, key: key}
}

func writeBundle(t *testing.T, certs ...*x509.Certificate) string {
	t.Helper()
	var pemData []byte
	for _, c := range certs {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// guarded returns the guard's middleware around a handler that records
// whether it ran.
func guarded(t *testing.T, sources []string, caPath string) (http.Handler, *bool) {
	t.Helper()
	g, err := New(sources, caPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	reached := false
	return g.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})), &reached
}

// unreadable fails the test if the request body is read: refused requests
// must never cost a body read.
type unreadable struct{ t *testing.T }

func (u unreadable) Read([]byte) (int, error) {
	u.t.Error("the body of a refused request was read")
	return 0, io.EOF
}

func request(t *testing.T, remote string, chain ...*x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/attest", unreadable{t})
	r.RemoteAddr = remote
	if chain != nil {
		r.TLS = &tls.ConnectionState{PeerCertificates: chain}
	}
	return r
}

func serve(h http.Handler, r *http.Request) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestNoRestriction(t *testing.T) {
	g, err := New(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if g.RequestsClientCertificates() {
		t.Error("client certificates requested without a CA bundle")
	}
	h, reached := guarded(t, nil, "")
	if code := serve(h, request(t, "198.51.100.7:1234")); code != http.StatusOK || !*reached {
		t.Fatalf("status %d, reached %v; want any source accepted", code, *reached)
	}
}

func TestAllowedSources(t *testing.T) {
	h, reached := guarded(t, []string{"10.0.20.0/24", "192.0.2.10", "2001:db8::/64"}, "")
	for remote, want := range map[string]int{
		"10.0.20.7:40000":          http.StatusOK,
		"192.0.2.10:40000":         http.StatusOK,
		"[2001:db8::1]:40000":      http.StatusOK,
		"[::ffff:10.0.20.8]:40000": http.StatusOK, // IPv4-mapped
		"10.0.21.7:40000":          http.StatusForbidden,
		"192.0.2.11:40000":         http.StatusForbidden,
		"[2001:db8:0:1::1]:40000":  http.StatusForbidden,
		"not-an-address":           http.StatusForbidden,
	} {
		*reached = false
		if code := serve(h, request(t, remote)); code != want || *reached != (want == http.StatusOK) {
			t.Errorf("%s: status %d, reached %v; want %d", remote, code, *reached, want)
		}
	}
}

func TestClientCertificate(t *testing.T) {
	ca := newCA(t, "nova client CA")
	other := newCA(t, "another CA")
	intermediate := issue(t, &ca, "intermediate", true, nil, time.Now().Add(time.Hour))
	clientAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	valid := issue(t, &ca, "nova-vendordata", false, clientAuth, time.Now().Add(time.Hour))
	viaIntermediate := issue(t, &intermediate, "nova-vendordata", false, clientAuth, time.Now().Add(time.Hour))
	foreign := issue(t, &other, "nova-vendordata", false, clientAuth, time.Now().Add(time.Hour))
	expired := issue(t, &ca, "nova-vendordata", false, clientAuth, time.Now().Add(-time.Minute))
	serverOnly := issue(t, &ca, "nova-vendordata", false, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, time.Now().Add(time.Hour))

	g, err := New(nil, writeBundle(t, ca.cert))
	if err != nil {
		t.Fatal(err)
	}
	if !g.RequestsClientCertificates() {
		t.Error("client certificates not requested with a CA bundle")
	}
	h, reached := guarded(t, nil, writeBundle(t, ca.cert))
	tests := []struct {
		name  string
		chain []*x509.Certificate
		want  int
	}{
		{"valid", []*x509.Certificate{valid.cert}, http.StatusOK},
		{"valid through an intermediate", []*x509.Certificate{viaIntermediate.cert, intermediate.cert}, http.StatusOK},
		{"none", nil, http.StatusForbidden},
		{"from another CA", []*x509.Certificate{foreign.cert}, http.StatusForbidden},
		{"expired", []*x509.Certificate{expired.cert}, http.StatusForbidden},
		{"not for client authentication", []*x509.Certificate{serverOnly.cert}, http.StatusForbidden},
		{"the CA itself", []*x509.Certificate{ca.cert}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			*reached = false
			if code := serve(h, request(t, "10.0.20.7:40000", tt.chain...)); code != tt.want || *reached != (tt.want == http.StatusOK) {
				t.Errorf("status %d, reached %v; want %d", code, *reached, tt.want)
			}
		})
	}
}

func TestBothRestrictions(t *testing.T) {
	ca := newCA(t, "nova client CA")
	valid := issue(t, &ca, "nova-vendordata", false, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, time.Now().Add(time.Hour))
	h, reached := guarded(t, []string{"10.0.20.0/24"}, writeBundle(t, ca.cert))
	if code := serve(h, request(t, "10.0.21.7:40000", valid.cert)); code != http.StatusForbidden || *reached {
		t.Errorf("a valid certificate from an unlisted source: status %d, reached %v; want 403", code, *reached)
	}
	if code := serve(h, request(t, "10.0.20.7:40000")); code != http.StatusForbidden || *reached {
		t.Errorf("a listed source without a certificate: status %d, reached %v; want 403", code, *reached)
	}
	if code := serve(h, request(t, "10.0.20.7:40000", valid.cert)); code != http.StatusOK || !*reached {
		t.Errorf("both satisfied: status %d, reached %v; want 200", code, *reached)
	}
}

func TestRefusalsAreBareAndUncacheable(t *testing.T) {
	h, _ := guarded(t, []string{"10.0.20.0/24"}, "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(t, "10.0.21.7:40000"))
	if w.Header().Get("Cache-Control") != "no-store" || strings.TrimSpace(w.Body.String()) != http.StatusText(http.StatusForbidden) {
		t.Errorf("refusal: Cache-Control %q, body %q", w.Header().Get("Cache-Control"), w.Body.String())
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	if _, err := New([]string{"metadata.internal"}, ""); err == nil {
		t.Error("a host name accepted as a source")
	}
	if _, err := New(nil, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("a missing CA bundle accepted")
	}
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(nil, garbage); err == nil {
		t.Error("a CA bundle without certificates accepted")
	}
}
