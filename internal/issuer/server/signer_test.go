package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"github.com/dihedron/openstack-spiffe/internal/issuer/jwks"
	"github.com/dihedron/openstack-spiffe/internal/issuer/openstacktest"
	"github.com/dihedron/openstack-spiffe/internal/issuer/osclient"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	projectID      = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	otherProjectID = "0123456789abcdef0123456789abcdef"
	instanceID     = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"
	otherInstance  = "11111111-1111-4111-8111-111111111111"
	publishAhead   = 300 * time.Millisecond
)

var novaUser = openstacktest.User{
	ID: "0123456789abcdef0123456789abcdef", Name: "nova", DomainID: "default", DomainName: "Default",
	Roles: []string{"service"},
}

// writeTLS writes a self-signed certificate for 127.0.0.1 and its key, and
// returns their paths and a pool trusting the certificate.
func writeTLS(t *testing.T) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "signer-a"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certPath, keyPath, pool
}

type harness struct {
	cloud  *openstacktest.Server
	client *http.Client
	// pool trusts the signer's certificate
	pool   *x509.CertPool
	url    string
	cancel context.CancelFunc
	done   chan error
}

// start runs a signer with the given extra configuration against a fake
// OpenStack cloud.
func start(t *testing.T, extra string) *harness {
	t.Helper()
	return startWith(t, extra, publishAhead)
}

// startWith is start with a given key_store.publish_ahead.
func startWith(t *testing.T, extra string, publishAhead time.Duration) *harness {
	t.Helper()
	cloud := openstacktest.New(t)
	cloud.AddInstance(openstacktest.Instance{
		ID: instanceID, ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az-1", FlavorName: "m1.small",
	})
	cloud.AddInstance(openstacktest.Instance{ID: otherInstance, ProjectID: otherProjectID, Status: "ACTIVE", AvailabilityZone: "az-2"})
	cloud.AddProject(openstacktest.Project{ID: projectID, Name: "web", DomainID: "default"})

	certPath, keyPath, pool := writeTLS(t)
	doc := fmt.Sprintf(`listen_addr: 127.0.0.1:0
tls_cert_path: %s
tls_key_path: %s
replica_id: signer-a
key_store:
  algorithm: ES256
  rotation_interval: 5m
  publish_ahead: %s
tags:
  allowlist: [role]
keystone:
  allowed_users: [nova@Default]
  ca_cert_path: %s
`, certPath, keyPath, publishAhead, cloud.CAFile(t)) + extra
	result := config.CheckSigner("signer.yaml", []byte(doc), config.CheckOptions{})
	if err := result.Err(); err != nil {
		t.Fatalf("configuration: %v", err)
	}
	cfg := result.Config

	env := cloud.Env()
	creds, err := osclient.CredentialsFromEnv(func(name string) string { return env[name] })
	if err != nil {
		t.Fatalf("CredentialsFromEnv: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	client, err := osclient.New(ctx, creds, cfg.Keystone.CACertPath)
	if err != nil {
		t.Fatalf("osclient.New: %v", err)
	}
	signer, err := NewSigner(ctx, cfg, client)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{
		cloud:  cloud,
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 10 * time.Second},
		pool:   pool,
		url:    "https://" + ln.Addr().String(),
		cancel: cancel,
		done:   make(chan error, 1),
	}
	go func() { h.done <- signer.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(20 * time.Second):
			t.Error("signer did not shut down")
		}
	})
	return h
}

func (h *harness) request(t *testing.T, method, path, token, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, h.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("X-Auth-Token", token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func novaBody(project, instance string) string {
	return `{"project-id":"` + project + `","instance-id":"` + instance + `","image-id":"img","hostname":"vm-01",` +
		`"metadata":{"role":"web","secret":"s3cr3t"},"user-data":"I2Nsb3VkLWNvbmZpZw==","boot-roles":"member"}`
}

// verify checks the token's signature against the signer's own JWKS, selecting
// the key by kid, and returns its claims.
func (h *harness) verify(t *testing.T, jwt string) (iid.Header, iid.Claims) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", jwt)
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("decoding %q: %v", s, err)
		}
		return b
	}
	var header iid.Header
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	var set jwks.Set
	resp := h.request(t, http.MethodGet, "/.well-known/jwks.json", "", "")
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("decoding JWKS %s: %v", body, err)
	}
	for _, k := range set.Keys {
		if k.KeyID != header.KeyID {
			continue
		}
		pub, err := k.PublicKey()
		if err != nil {
			t.Fatalf("JWKS key: %v", err)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		sig := decode(parts[2])
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub.Key.(*ecdsa.PublicKey), digest[:], r, s) {
			t.Fatal("token signature does not verify against the served JWKS")
		}
		var c iid.Claims
		if err := json.Unmarshal(decode(parts[1]), &c); err != nil {
			t.Fatal(err)
		}
		return header, c
	}
	t.Fatalf("kid %q not in the served JWKS", header.KeyID)
	return iid.Header{}, iid.Claims{}
}

func attestToken(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, _ := io.ReadAll(resp.Body)
	// as an instance finds it: Nova nests the response under the target name
	vendorData := fmt.Appendf(nil, `{%q:%s}`, iid.TargetName, body)
	var vd iid.VendorDataResponse
	if err := json.Unmarshal(vendorData, &vd); err != nil {
		t.Fatalf("decoding vendor_data2.json %s: %v", vendorData, err)
	}
	if vd.Target.JWT == "" {
		t.Fatalf("no token at %s.jwt in vendor_data2.json %s", iid.TargetName, vendorData)
	}
	return vd.Target.JWT
}

func TestSignerEndToEnd(t *testing.T) {
	h := start(t, "enrich: [availability_zone, project_name]\n")
	token := h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))

	resp := h.request(t, http.MethodGet, "/liveness", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("liveness: %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Fatal("no X-Request-Id")
	}

	// the required negative test, through the whole stack
	if resp := h.request(t, http.MethodPost, "/attest", "", novaBody(projectID, instanceID)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: status %d, want 401", resp.StatusCode)
	}

	time.Sleep(publishAhead) // the first key becomes active
	resp = h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("attest: status %d: %s", resp.StatusCode, body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control %q", resp.Header.Get("Cache-Control"))
	}
	header, c := h.verify(t, attestToken(t, resp))
	if !strings.HasPrefix(header.KeyID, time.Now().UTC().Format(time.DateOnly)+"-signer-a-key-") || header.Algorithm != "ES256" {
		t.Fatalf("header %+v", header)
	}
	if c.Subject != instanceID || c.ProjectID != projectID || c.AvailabilityZone != "az-1" || c.ProjectName != "web" ||
		c.Tags["role"] != "web" || c.Tags["secret"] != "" || c.Expiry-c.IssuedAt != 300 {
		t.Fatalf("claims %+v", c)
	}

	if resp := h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID)); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request within 5s: status %d, want 429", resp.StatusCode)
	}
	if resp := h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, otherInstance)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("instance of another project: status %d, want 403", resp.StatusCode)
	}
	arbitrary := h.cloud.IssueToken(openstacktest.User{ID: "fedcba9876543210fedcba9876543210", Name: "alice", DomainID: "default", DomainName: "Default", Roles: []string{"member"}}, time.Now().Add(time.Hour))
	if resp := h.request(t, http.MethodPost, "/attest", arbitrary, novaBody(projectID, instanceID)); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("arbitrary user: status %d, want 403", resp.StatusCode)
	}

	// readiness: the first run (at startup) saw no active key; the next one,
	// within the 5s interval, sees every dependency healthy
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp := h.request(t, http.MethodGet, "/readiness", "", "")
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			if !strings.Contains(string(body), `"nova":"ok"`) || !strings.Contains(string(body), `"keystone":"ok"`) {
				t.Fatalf("readiness body %s", body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never ready: %s", body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestTLS13Minimum(t *testing.T) {
	h := start(t, "")
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    h.client.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		MaxVersion: tls.VersionTLS12,
	}}}
	if resp, err := old.Get(h.url + "/liveness"); err == nil {
		resp.Body.Close()
		t.Fatal("TLS 1.2 client accepted")
	}
	resp := h.request(t, http.MethodGet, "/liveness", "", "")
	if resp.TLS == nil || resp.TLS.Version != tls.VersionTLS13 {
		t.Fatalf("negotiated %v, want TLS 1.3", resp.TLS)
	}
}

func TestTLS12AllowedWhenConfigured(t *testing.T) {
	h := start(t, `tls_min_version: "1.2"`+"\n")
	legacy := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    h.client.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		MaxVersion: tls.VersionTLS12,
	}}}
	resp, err := legacy.Get(h.url + "/liveness")
	if err != nil {
		t.Fatalf("TLS 1.2 client refused with tls_min_version 1.2: %v", err)
	}
	resp.Body.Close()
	if resp.TLS.Version != tls.VersionTLS12 {
		t.Fatalf("negotiated %#x, want TLS 1.2", resp.TLS.Version)
	}
}

func TestWithoutInstanceVerification(t *testing.T) {
	h := start(t, "nova_lookup:\n  enabled: false\nenrich: [domain_id]\n")
	token := h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))
	time.Sleep(publishAhead)
	// the instance is unknown to Nova, which is not consulted
	resp := h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, "22222222-2222-4222-8222-222222222222"))
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if _, c := h.verify(t, attestToken(t, resp)); c.DomainID != "default" || c.AvailabilityZone != "" {
		t.Fatalf("claims %+v", c)
	}
	if h.cloud.ServerLookups.Load() != 0 {
		t.Fatal("Nova consulted with instance verification disabled")
	}
}

func TestGracefulShutdown(t *testing.T) {
	h := start(t, "")
	h.request(t, http.MethodGet, "/liveness", "", "")
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
		h.done <- nil // for the cleanup
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
}
