package server

import (
	"net/http"
	"testing"
	"time"
)

// TestPublicEndpointLimit: a burst over rate_limit_per_source_public on the
// JWK Set gets 429, while /attest from the same source, which has its own
// bucket, is unaffected (D-5).
func TestPublicEndpointLimit(t *testing.T) {
	h := start(t, "rate_limit_per_source_public: \"3/1m\"\n")
	waitReadyWithin(t, h, 3) // readiness polls count too
	for _, path := range []string{"/.well-known/jwks.json", "/jwks/local.json", "/liveness"} {
		resp := h.request(t, http.MethodGet, path, "", "")
		if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
			t.Errorf("%s over the public limit: status %d, Retry-After %q; want 429", path, resp.StatusCode, resp.Header.Get("Retry-After"))
		}
	}
	token := h.cloud.IssueToken(novaUser, time.Now().Add(time.Hour))
	if resp := h.request(t, http.MethodPost, "/attest", token, novaBody(projectID, instanceID)); resp.StatusCode != http.StatusOK {
		t.Errorf("/attest from the same source: status %d, want 200", resp.StatusCode)
	}
}

// waitReadyWithin waits for the signer's readiness with at most n requests
// to the public endpoints, so that the test knows how many it has spent.
func waitReadyWithin(t *testing.T, h *harness, n int) {
	t.Helper()
	// readiness needs the first key active (publish_ahead) and a check run
	time.Sleep(6 * time.Second)
	for range n {
		if resp := h.request(t, http.MethodGet, "/readiness", "", ""); resp.StatusCode == http.StatusOK {
			// spend the rest of the bucket
			for range n - 1 {
				h.request(t, http.MethodGet, "/liveness", "", "")
			}
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("signer not ready within %d readiness requests", n)
}

// TestAggregatorLimit: the aggregator limits its endpoints per source too.
func TestAggregatorLimit(t *testing.T) {
	replica := newFakeReplica(t, "2026-09-29-signer-a-key-1")
	h := startAggregator(t, "rate_limit_per_source: \"2/1m\"\n", replica)
	for i := range 2 {
		if resp, _ := h.get(t, http.MethodGet, "/liveness"); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status %d", i, resp.StatusCode)
		}
	}
	if resp, _ := h.get(t, http.MethodGet, "/.well-known/jwks.json"); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("over the aggregator's limit: status %d, want 429", resp.StatusCode)
	}
}
