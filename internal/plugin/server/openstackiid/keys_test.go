package openstackiid

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/jwks"
	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// jwksServer serves a JWK Set over TLS; what it serves can change while it
// runs.
type jwksServer struct {
	*httptest.Server
	mu      sync.Mutex
	status  int
	body    []byte
	fetches atomic.Int32
}

func newJWKSServer(t *testing.T, keys ...keystore.PublicKey) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	s.publish(t, keys...)
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.fetches.Add(1)
		s.mu.Lock()
		status, body := s.status, s.body
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) publish(t *testing.T, keys ...keystore.PublicKey) {
	t.Helper()
	set := jwks.Set{Keys: []jwks.Key{}}
	for _, k := range keys {
		jwk, err := jwks.FromPublicKey(k)
		if err != nil {
			t.Fatal(err)
		}
		set.Keys = append(set.Keys, jwk)
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	s.serve(http.StatusOK, body)
}

func (s *jwksServer) serve(status int, body []byte) {
	s.mu.Lock()
	s.status, s.body = status, body
	s.mu.Unlock()
}

func (s *jwksServer) url() string { return s.URL + "/.well-known/jwks.json" }

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newTestKeySource(t *testing.T, s *jwksServer, clock *fakeClock) *keySource {
	t.Helper()
	ks, err := newKeySource(keySourceConfig{
		url:            s.url(),
		client:         s.Client(),
		refresh:        time.Hour, // polled by hand
		fetchTimeout:   2 * time.Second,
		retention:      5 * time.Minute,
		minRefetch:     5 * time.Second,
		now:            clock.Now,
		skipBackground: true,
	})
	if err != nil {
		t.Fatalf("newKeySource: %v", err)
	}
	t.Cleanup(ks.close)
	return ks
}

func kidsOf(t *testing.T, ks *keySource) []string {
	t.Helper()
	keys, err := ks.keys(context.Background())
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	var ids []string
	for id := range keys {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func TestKeySourceUnknownKIDRefetch(t *testing.T) {
	_, es, other := testKeys(t)
	s := newJWKSServer(t, es.public())
	clock := &fakeClock{now: testNow}
	ks := newTestKeySource(t, s, clock)
	ctx := context.Background()

	// nothing fetched yet: the first miss triggers a fetch
	if !ks.refetch(ctx) {
		t.Fatal("first re-fetch refused")
	}
	if got := kidsOf(t, ks); !slices.Equal(got, []string{es.kid}) {
		t.Fatalf("kids %v, want [%s]", got, es.kid)
	}

	// a key published since: picked up by a re-fetch, but not more often
	// than the minimum interval
	s.publish(t, es.public(), other.public())
	if ks.refetch(ctx) {
		t.Fatal("re-fetch allowed within the minimum interval")
	}
	if got := kidsOf(t, ks); slices.Contains(got, other.kid) {
		t.Fatal("new key appeared without a fetch")
	}
	clock.Advance(5 * time.Second)
	if !ks.refetch(ctx) {
		t.Fatal("re-fetch refused after the minimum interval")
	}
	if got := kidsOf(t, ks); !slices.Contains(got, other.kid) {
		t.Fatalf("kids %v after re-fetch, want %s included", got, other.kid)
	}
	if n := s.fetches.Load(); n != 2 {
		t.Fatalf("%d fetches, want 2", n)
	}
}

func TestKeySourceConcurrentRefetchesMerged(t *testing.T) {
	_, es, _ := testKeys(t)
	s := newJWKSServer(t, es.public())
	ks := newTestKeySource(t, s, &fakeClock{now: testNow})
	var wg sync.WaitGroup
	var allowed atomic.Int32
	for range 20 {
		wg.Go(func() {
			if ks.refetch(context.Background()) {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if n := s.fetches.Load(); n != 1 {
		t.Fatalf("%d fetches for 20 concurrent misses, want 1", n)
	}
	if n := allowed.Load(); n != 1 {
		t.Fatalf("%d re-fetches allowed, want 1", n)
	}
}

func TestKeySourceLastKnownGood(t *testing.T) {
	_, es, _ := testKeys(t)
	s := newJWKSServer(t, es.public())
	clock := &fakeClock{now: testNow}
	ks := newTestKeySource(t, s, clock)
	ctx := context.Background()
	ks.agg.Refresh(ctx)

	s.serve(http.StatusInternalServerError, []byte("oops"))
	clock.Advance(4 * time.Minute)
	ks.agg.Refresh(ctx)
	if got := kidsOf(t, ks); !slices.Equal(got, []string{es.kid}) {
		t.Fatalf("kids %v during an outage within retention, want the last known good", got)
	}
	clock.Advance(time.Minute)
	if got := kidsOf(t, ks); len(got) != 0 {
		t.Fatalf("kids %v past retention, want none", got)
	}
}

func TestKeySourceTooManyKeys(t *testing.T) {
	_, es, _ := testKeys(t)
	s := newJWKSServer(t, es.public())
	ks := newTestKeySource(t, s, &fakeClock{now: testNow})
	ctx := context.Background()
	ks.agg.Refresh(ctx)

	body := `{"keys":[`
	for i := range iid.MaxJWKSKeys + 1 {
		if i > 0 {
			body += ","
		}
		body += fmt.Sprintf(`{"kid":"k%d"}`, i)
	}
	s.serve(http.StatusOK, []byte(body+"]}"))
	ks.agg.Refresh(ctx)
	if got := kidsOf(t, ks); !slices.Equal(got, []string{es.kid}) {
		t.Fatalf("kids %v after an oversized set, want the last known good", got)
	}
}

func TestKeySourceBackgroundPolling(t *testing.T) {
	_, es, _ := testKeys(t)
	s := newJWKSServer(t, es.public())
	ks, err := newKeySource(keySourceConfig{
		url: s.url(), client: s.Client(),
		refresh: 50 * time.Millisecond, fetchTimeout: time.Second, retention: 5 * time.Minute, minRefetch: time.Second,
		now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.fetches.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("%d fetches in 5s with a 50ms refresh interval", s.fetches.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	ks.close()
	after := s.fetches.Load()
	time.Sleep(200 * time.Millisecond)
	if n := s.fetches.Load(); n > after+1 {
		t.Fatalf("polling continued after close: %d fetches, then %d", after, n)
	}
}
