package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/config"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/jwks"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/keystore"
)

// fakeReplica serves a fixed JWK Set over TLS (httptest's certificate).
type fakeReplica struct {
	*httptest.Server
	mu   sync.Mutex
	body []byte
}

func newFakeReplica(t *testing.T, kids ...string) *fakeReplica {
	t.Helper()
	set := jwks.Set{Keys: []jwks.Key{}}
	for _, kid := range kids {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		jwk, err := jwks.FromPublicKey(keystore.PublicKey{ID: kid, Algorithm: "ES256", Key: k.Public()})
		if err != nil {
			t.Fatal(err)
		}
		set.Keys = append(set.Keys, jwk)
	}
	body, _ := json.Marshal(set)
	r := &fakeReplica{body: body}
	r.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		defer r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write(r.body)
	}))
	t.Cleanup(r.Close)
	return r
}

type aggregatorHarness struct {
	client *http.Client
	url    string
	cancel context.CancelFunc
	done   chan error
}

func startAggregator(t *testing.T, extra string, replicas ...*fakeReplica) *aggregatorHarness {
	t.Helper()
	certPath, keyPath, pool := writeTLS(t)
	ca := filepath.Join(t.TempDir(), "replicas-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: replicas[0].Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := fmt.Sprintf("listen_addr: 127.0.0.1:0\ntls_cert_path: %s\ntls_key_path: %s\nreplica_ca_cert_path: %s\npoll_interval: 1s\nfetch_timeout: 500ms\nreplicas:\n", certPath, keyPath, ca)
	for _, r := range replicas {
		doc += "  - " + r.URL + "/.well-known/jwks.json\n"
	}
	doc += extra
	result := config.CheckAggregator("aggregator.yaml", []byte(doc), config.CheckOptions{})
	if err := result.Err(); err != nil {
		t.Fatalf("configuration: %v", err)
	}
	agg, err := NewAggregator(result.Config)
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &aggregatorHarness{
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 10 * time.Second},
		url:    "https://" + ln.Addr().String(),
		cancel: cancel,
		done:   make(chan error, 1),
	}
	go func() { h.done <- agg.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(20 * time.Second):
			t.Error("aggregator did not shut down")
		}
	})
	return h
}

func (h *aggregatorHarness) get(t *testing.T, method, path string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, h.url+path, nil)
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func TestAggregatorEndToEnd(t *testing.T) {
	h := startAggregator(t, "", newFakeReplica(t, "2026-09-29-signer-a-key-1"), newFakeReplica(t, "2026-09-29-signer-b-key-1"))

	// the first poll runs at startup; wait for the merged set
	var set jwks.Set
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, body := h.get(t, http.MethodGet, "/.well-known/jwks.json")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=30" {
			t.Fatalf("Cache-Control %q, want the cache_max_age default", cc)
		}
		if err := json.Unmarshal(body, &set); err != nil {
			t.Fatalf("decoding %s: %v", body, err)
		}
		if len(set.Keys) == 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KeyID)
		if _, err := k.PublicKey(); err != nil {
			t.Fatalf("served key %s: %v", k.KeyID, err)
		}
	}
	if !slices.Equal(kids, []string{"2026-09-29-signer-a-key-1", "2026-09-29-signer-b-key-1"}) {
		t.Fatalf("merged kids %v", kids)
	}

	if resp, _ := h.get(t, http.MethodPost, "/.well-known/jwks.json"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status %d, want 405", resp.StatusCode)
	}
	if resp, _ := h.get(t, http.MethodGet, "/liveness"); resp.StatusCode != http.StatusOK || resp.Header.Get("X-Request-Id") == "" {
		t.Fatalf("liveness: status %d, request ID %q", resp.StatusCode, resp.Header.Get("X-Request-Id"))
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		resp, body := h.get(t, http.MethodGet, "/readiness")
		if resp.StatusCode == http.StatusOK {
			if !strings.Contains(string(body), `"replicas":"ok"`) {
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

func TestAggregatorTLS13Minimum(t *testing.T) {
	h := startAggregator(t, "", newFakeReplica(t, "k"))
	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    h.client.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		MaxVersion: tls.VersionTLS12,
	}}}
	if resp, err := old.Get(h.url + "/liveness"); err == nil {
		resp.Body.Close()
		t.Fatal("TLS 1.2 client accepted")
	}
}

func TestAggregatorTLS12AllowedWhenConfigured(t *testing.T) {
	h := startAggregator(t, `tls_min_version: "1.2"`+"\n", newFakeReplica(t, "k"))
	legacy := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    h.client.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		MaxVersion: tls.VersionTLS12,
	}}}
	resp, err := legacy.Get(h.url + "/liveness")
	if err != nil {
		t.Fatalf("TLS 1.2 client refused with tls_min_version 1.2: %v", err)
	}
	resp.Body.Close()
}

func TestAggregatorGracefulShutdown(t *testing.T) {
	h := startAggregator(t, "", newFakeReplica(t, "k"))
	h.get(t, http.MethodGet, "/liveness")
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
		h.done <- nil
	case <-time.After(20 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}
}
