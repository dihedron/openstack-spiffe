package server

import (
	"encoding/json/v2"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/metadata/jwks"
)

// servedKids fetches a JWK Set from the signer and returns its kids and
// Cache-Control header.
func (h *harness) servedKids(t *testing.T, path string) ([]string, string) {
	t.Helper()
	resp := h.request(t, http.MethodGet, path, "", "")
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, body)
	}
	var set jwks.Set
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("decoding %s: %v", body, err)
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KeyID)
	}
	return kids, resp.Header.Get("Cache-Control")
}

// peersConfig returns the peers section for the given peer base URLs, with
// the CA of httptest's TLS servers.
func peersConfig(t *testing.T, ca *httptest.Server, settings string, peers ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peers-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	doc := "peers:\n  ca_cert_path: " + path + "\n" + settings + "  urls:\n"
	for _, p := range peers {
		doc += "    - " + p + "/jwks/local.json\n"
	}
	return doc
}

func TestSignerWithoutPeersServesOwnKeysOnBothEndpoints(t *testing.T) {
	h := start(t, "")
	local, localCC := h.servedKids(t, "/jwks/local.json")
	merged, mergedCC := h.servedKids(t, "/.well-known/jwks.json")
	if len(local) != 1 || !strings.Contains(local[0], "-signer-a-key-") {
		t.Fatalf("local kids %v, want the signer's first key", local)
	}
	if !slices.Equal(local, merged) || localCC != "no-cache" || mergedCC != "no-cache" {
		t.Fatalf("local %v (%q), well-known %v (%q): want the same set, not cacheable", local, localCC, merged, mergedCC)
	}
}

func TestSignerWithPeersServesMergedSet(t *testing.T) {
	const peerKid = "2026-09-29-signer-b-key-1"
	peer := newFakeReplica(t, peerKid)
	// publish_ahead (2s) > poll_interval + fetch_timeout + cache_max_age (1.3s)
	h := startWith(t, peersConfig(t, peer.Server, "  poll_interval: 200ms\n  fetch_timeout: 100ms\n  cache_max_age: 1s\n", peer.URL), 2*time.Second)

	local, localCC := h.servedKids(t, "/jwks/local.json")
	if len(local) != 1 || !strings.Contains(local[0], "-signer-a-key-") || localCC != "no-cache" {
		t.Fatalf("local: kids %v (%q), want only the own key, not cacheable", local, localCC)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		merged, cc := h.servedKids(t, "/.well-known/jwks.json")
		if cc != "public, max-age=1" {
			t.Fatalf("well-known Cache-Control %q, want peers.cache_max_age", cc)
		}
		if slices.Equal(merged, []string{peerKid, local[0]}) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("well-known kids %v, want the own and the peer's keys", merged)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// the peer's keys never leak into the local set
	if again, _ := h.servedKids(t, "/jwks/local.json"); !slices.Equal(again, local) {
		t.Fatalf("local kids %v after polling, want %v", again, local)
	}
}

func TestSignerReadyWithEveryPeerDown(t *testing.T) {
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	dead.Close()
	h := start(t, peersConfig(t, dead, "  poll_interval: 200ms\n  fetch_timeout: 50ms\n  cache_max_age: 0s\n", dead.URL))

	merged, cc := h.servedKids(t, "/.well-known/jwks.json")
	if len(merged) != 1 || cc != "no-cache" {
		t.Fatalf("well-known kids %v (%q), want the own key, not cacheable with cache_max_age 0", merged, cc)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp := h.request(t, http.MethodGet, "/readiness", "", "")
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusOK {
			if strings.Contains(string(body), "peer") {
				t.Fatalf("readiness body %s mentions peers", body)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never ready with the peer down: %s", body)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
