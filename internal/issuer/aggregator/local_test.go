package aggregator

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/jwks"
	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
)

// localSource stands for the replica's own key store.
type localSource struct {
	mu   sync.Mutex
	keys []keystore.PublicKey
	err  error
}

func (l *localSource) PublicKeys(ctx context.Context) ([]keystore.PublicKey, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.keys), l.err
}

func (l *localSource) set(keys ...keystore.PublicKey) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.keys = keys
}

func newPeered(t *testing.T, clock *testClock, local jwks.KeySource, replicas ...*replica) *Aggregator {
	t.Helper()
	client, err := NewHTTPClient(caFile(t, replicas[0]), tls.VersionTLS13)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	var urls []string
	for _, r := range replicas {
		urls = append(urls, r.url())
	}
	a, err := New(urls, client, WithClock(clock.Now), WithStaleKeyRetention(5*time.Minute), WithFetchTimeout(2*time.Second), WithLocal(local))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestLocalKeysMergedWithPeers(t *testing.T) {
	own, peer := ecKey(t, "2026-09-29-signer-a-key-1"), ecKey(t, "2026-09-29-signer-b-key-1")
	local := &localSource{keys: []keystore.PublicKey{own}}
	rb := newReplica(t)
	rb.publish(t, peer)
	a := newPeered(t, &testClock{now: testNow}, local, rb)

	// the own keys are served before any poll
	if got := kids(t, a); !slices.Equal(got, []string{own.ID}) {
		t.Fatalf("before polling: kids %v, want the own key", got)
	}
	a.poll(context.Background())
	if got := kids(t, a); !slices.Equal(got, []string{own.ID, peer.ID}) {
		t.Fatalf("kids %v, want own and peer keys", got)
	}
}

func TestLocalKeysAreReadLive(t *testing.T) {
	first, second := ecKey(t, "a-1"), ecKey(t, "a-2")
	local := &localSource{keys: []keystore.PublicKey{first}}
	a := newPeered(t, &testClock{now: testNow}, local, newReplica(t))
	a.poll(context.Background())
	local.set(first, second)
	if got := kids(t, a); !slices.Equal(got, []string{"a-1", "a-2"}) {
		t.Fatalf("kids %v, want the new own key without polling", got)
	}
}

func TestLocalKeysServedWithEveryPeerDown(t *testing.T) {
	clock := &testClock{now: testNow}
	local := &localSource{keys: []keystore.PublicKey{ecKey(t, "own")}}
	rb := newReplica(t)
	rb.serve(http.StatusServiceUnavailable, []byte("down"))
	a := newPeered(t, clock, local, rb)
	a.poll(context.Background())
	if got := kids(t, a); !slices.Equal(got, []string{"own"}) {
		t.Fatalf("kids %v, want the own key", got)
	}
	clock.Advance(time.Hour)
	if got := kids(t, a); !slices.Equal(got, []string{"own"}) {
		t.Fatalf("long after: kids %v, want the own key", got)
	}
}

func TestPeerConflictingWithLocalKidIsExcluded(t *testing.T) {
	logs := captureLogs(t)
	local := &localSource{keys: []keystore.PublicKey{ecKey(t, "clash"), ecKey(t, "own")}}
	rb := newReplica(t)
	rb.publish(t, ecKey(t, "clash"), ecKey(t, "peer"))
	a := newPeered(t, &testClock{now: testNow}, local, rb)
	a.poll(context.Background())
	if got := kids(t, a); !slices.Equal(got, []string{"own", "peer"}) {
		t.Fatalf("kids %v, want the conflicting kid excluded", got)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "clash") || !strings.Contains(logs.String(), localSourceName) {
		t.Fatalf("conflict with the own key not logged as an error:\n%s", logs)
	}
}

func TestOwnURLAmongPeersIsServedOnce(t *testing.T) {
	own := ecKey(t, "own")
	local := &localSource{keys: []keystore.PublicKey{own}}
	self := newReplica(t)
	self.publish(t, own) // the replica's own /jwks/local.json
	a := newPeered(t, &testClock{now: testNow}, local, self)
	a.poll(context.Background())
	if got := kids(t, a); !slices.Equal(got, []string{"own"}) {
		t.Fatalf("kids %v, want [own]", got)
	}
}

func TestLocalSourceFailureFailsTheWholeSet(t *testing.T) {
	local := &localSource{err: errors.New("key store down")}
	rb := newReplica(t)
	rb.publish(t, ecKey(t, "peer"))
	a := newPeered(t, &testClock{now: testNow}, local, rb)
	a.poll(context.Background())
	if keys, err := a.PublicKeys(context.Background()); err == nil {
		t.Fatalf("PublicKeys = %v, want an error rather than a partial set", keys)
	}
}

// signerReplica is a replica with peer aggregation, as the signer serves it:
// its own keys on /jwks/local.json and the merged set on
// /.well-known/jwks.json.
type signerReplica struct {
	server *httptest.Server
	local  *localSource
	merged *Aggregator
}

// TestPeersDoNotCirculateKeys runs two peered replicas polling each other's
// local endpoint: a key one of them retires disappears from both merged
// sets, instead of being imported back from the other's merged set.
func TestPeersDoNotCirculateKeys(t *testing.T) {
	clock := &testClock{now: testNow}
	replicas := map[string]*signerReplica{}
	for _, id := range []string{"a", "b"} {
		r := &signerReplica{local: &localSource{keys: []keystore.PublicKey{ecKey(t, id+"-old"), ecKey(t, id+"-new")}}}
		mux := http.NewServeMux()
		localHandler, _ := jwks.NewHandler(r.local)
		mux.Handle("/jwks/local.json", localHandler)
		mux.Handle("/.well-known/jwks.json", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			h, _ := jwks.NewHandler(r.merged)
			h.ServeHTTP(w, req)
		}))
		r.server = httptest.NewTLSServer(mux)
		t.Cleanup(r.server.Close)
		replicas[id] = r
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: replicas["a"].server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPClient(ca, tls.VersionTLS13)
	if err != nil {
		t.Fatal(err)
	}
	for id, peer := range map[string]string{"a": "b", "b": "a"} {
		r := replicas[id]
		r.merged, err = New([]string{replicas[peer].server.URL + "/jwks/local.json"}, client, WithClock(clock.Now), WithLocal(r.local))
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	pollAll := func() {
		replicas["a"].merged.poll(ctx)
		replicas["b"].merged.poll(ctx)
	}
	pollAll()
	for id, r := range replicas {
		if got := kids(t, r.merged); !slices.Equal(got, []string{"a-new", "a-old", "b-new", "b-old"}) {
			t.Fatalf("%s: kids %v, want every key", id, got)
		}
	}

	// a retires a-old: gone from b's merged set after b's next poll, and
	// never imported back by a
	replicas["a"].local.set(replicas["a"].local.keys[1])
	for range 3 {
		pollAll()
	}
	for id, r := range replicas {
		if got := kids(t, r.merged); !slices.Equal(got, []string{"a-new", "b-new", "b-old"}) {
			t.Fatalf("%s: kids %v, want a-old dropped everywhere", id, got)
		}
	}
}
