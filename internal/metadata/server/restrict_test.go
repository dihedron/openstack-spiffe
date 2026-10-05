package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// clientPKI writes a client CA bundle and returns its path, with a client
// certificate it signed and one signed by another CA.
func clientPKI(t *testing.T) (caPath string, valid, foreign tls.Certificate) {
	t.Helper()
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	ca := func(name string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key := newKey()
		template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert, key
	}
	client := func(parent *x509.Certificate, parentKey *ecdsa.PrivateKey) tls.Certificate {
		key := newKey()
		template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "nova-vendordata"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	caCert, caKey := ca("nova client CA")
	otherCert, otherKey := ca("another CA")
	caPath = filepath.Join(t.TempDir(), "nova-client-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return caPath, client(caCert, caKey), client(otherCert, otherKey)
}

// withCertificate returns a client of the signer presenting cert.
func (h *harness) withCertificate(cert tls.Certificate) *harness {
	c := *h
	c.client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.pool, Certificates: []tls.Certificate{cert}}},
		Timeout:   10 * time.Second,
	}
	return &c
}

// TestAttestSourceAllowlist: a request with a valid Nova token from a source
// outside attest.allowed_sources is refused with 403, without a Keystone
// call (S-3); the other endpoints are not restricted.
func TestAttestSourceAllowlist(t *testing.T) {
	h := start(t, "attest:\n  allowed_sources: [192.0.2.0/24]\n")
	token := h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))
	resp := h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("/attest from 127.0.0.1: status %d, want 403", resp.StatusCode)
	}
	if n := h.cloud.Validations.Load(); n != 0 {
		t.Errorf("Keystone validated %d tokens for a refused source", n)
	}
	if resp := h.request(t, http.MethodGet, "/.well-known/jwks.json", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("JWKS from the same source: status %d, want 200", resp.StatusCode)
	}

	h = start(t, "attest:\n  allowed_sources: [127.0.0.1]\n")
	token = h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))
	waitReady(t, h)
	if resp := h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID)); resp.StatusCode != http.StatusOK {
		t.Errorf("/attest from a listed source: status %d, want 200", resp.StatusCode)
	}
}

// TestAttestClientCertificate: with attest.client_ca_path set, /attest needs
// a client certificate from that CA (S-3): none, or one from another CA,
// gets 403 without a Keystone call; a valid one gets a token; the JWK Set
// still answers clients without a certificate.
func TestAttestClientCertificate(t *testing.T) {
	caPath, valid, foreign := clientPKI(t)
	h := start(t, "attest:\n  client_ca_path: "+caPath+"\n")
	waitReady(t, h)
	token := h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))

	if resp := h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID)); resp.StatusCode != http.StatusForbidden {
		t.Errorf("/attest without a certificate: status %d, want 403", resp.StatusCode)
	}
	if resp := h.withCertificate(foreign).request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID)); resp.StatusCode != http.StatusForbidden {
		t.Errorf("/attest with a certificate from another CA: status %d, want 403", resp.StatusCode)
	}
	if n := h.cloud.Validations.Load(); n != 0 {
		t.Errorf("Keystone validated %d tokens for refused requests", n)
	}
	if resp := h.request(t, http.MethodGet, "/.well-known/jwks.json", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("JWKS without a certificate: status %d, want 200", resp.StatusCode)
	}
	if resp := h.withCertificate(foreign).request(t, http.MethodGet, "/readiness", "", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("readiness with a foreign certificate: status %d, want 200 (only /attest checks it)", resp.StatusCode)
	}
	resp := h.withCertificate(valid).request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/attest with a valid certificate: status %d, want 200", resp.StatusCode)
	}
	if jwt := attestToken(t, resp); strings.Count(jwt, ".") != 2 {
		t.Errorf("no token: %q", jwt)
	}
}

// waitReady waits until the signer can sign (its first key is active).
func waitReady(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if resp := h.request(t, http.MethodGet, "/readiness", "", ""); resp.StatusCode == http.StatusOK {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("signer never ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
