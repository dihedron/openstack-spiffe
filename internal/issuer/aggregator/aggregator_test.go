package aggregator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/jwks"
	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

var testNow = time.Date(2026, 9, 29, 14, 32, 11, 0, time.UTC)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// replica is a fake signer replica serving a JWKS body set by the test.
type replica struct {
	*httptest.Server
	mu     sync.Mutex
	body   []byte
	status int
	hits   atomic.Int32
	// hook, if set, runs before each response.
	hook func()
}

func newReplica(t *testing.T) *replica {
	t.Helper()
	r := &replica{status: http.StatusOK, body: []byte(`{"keys":[]}`)}
	r.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits.Add(1)
		if r.hook != nil {
			r.hook()
		}
		r.mu.Lock()
		status, body := r.status, r.body
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *replica) url() string { return r.URL + "/.well-known/jwks.json" }

// publish serves the given keys as a JWK Set.
func (r *replica) publish(t *testing.T, keys ...keystore.PublicKey) {
	t.Helper()
	set := jwks.Set{Keys: []jwks.Key{}}
	for _, k := range keys {
		jwk, err := jwks.FromPublicKey(k)
		if err != nil {
			t.Fatalf("FromPublicKey: %v", err)
		}
		set.Keys = append(set.Keys, jwk)
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	r.serve(http.StatusOK, body)
}

func (r *replica) serve(status int, body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status, r.body = status, body
}

func ecKey(t *testing.T, kid string) keystore.PublicKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keystore.PublicKey{ID: kid, Algorithm: "ES256", Key: k.Public()}
}

// caFile writes the certificate shared by httptest TLS servers.
func caFile(t *testing.T, r *replica) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "replicas-ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newAggregator(t *testing.T, clock *testClock, replicas ...*replica) *Aggregator {
	t.Helper()
	client, err := NewHTTPClient(caFile(t, replicas[0]), tls.VersionTLS13)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	var urls []string
	for _, r := range replicas {
		urls = append(urls, r.url())
	}
	a, err := New(urls, client, WithClock(clock.Now), WithStaleKeyRetention(5*time.Minute), WithFetchTimeout(2*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func kids(t *testing.T, a *Aggregator) []string {
	t.Helper()
	keys, err := a.PublicKeys(context.Background())
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	var ids []string
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestMergesReplicas(t *testing.T) {
	a1, b1, b2 := ecKey(t, "2026-09-29-signer-a-key-100"), ecKey(t, "2026-09-29-signer-b-key-100"), ecKey(t, "2026-09-29-signer-b-key-200")
	ra, rb := newReplica(t), newReplica(t)
	ra.publish(t, a1)
	rb.publish(t, b2, b1)
	a := newAggregator(t, &testClock{now: testNow}, ra, rb)
	a.poll(context.Background())

	if got, want := kids(t, a), []string{a1.ID, b1.ID, b2.ID}; !slices.Equal(got, want) {
		t.Fatalf("merged kids %v, want %v (sorted)", got, want)
	}
	keys, _ := a.PublicKeys(context.Background())
	if !keys[0].Key.(*ecdsa.PublicKey).Equal(a1.Key) {
		t.Fatal("merged key material differs from the replica's")
	}
}

func TestIdenticalKidsAreDeduplicated(t *testing.T) {
	shared := ecKey(t, "shared")
	ra, rb := newReplica(t), newReplica(t)
	ra.publish(t, shared)
	rb.publish(t, shared)
	a := newAggregator(t, &testClock{now: testNow}, ra, rb)
	a.poll(context.Background())
	if got := kids(t, a); !slices.Equal(got, []string{"shared"}) {
		t.Fatalf("kids %v, want [shared]", got)
	}
}

func TestConflictingKidIsExcluded(t *testing.T) {
	logs := captureLogs(t)
	ra, rb := newReplica(t), newReplica(t)
	ra.publish(t, ecKey(t, "clash"), ecKey(t, "a-only"))
	rb.publish(t, ecKey(t, "clash"), ecKey(t, "b-only"))
	a := newAggregator(t, &testClock{now: testNow}, ra, rb)
	a.poll(context.Background())

	if got := kids(t, a); !slices.Equal(got, []string{"a-only", "b-only"}) {
		t.Fatalf("kids %v, want the conflicting kid excluded", got)
	}
	if !strings.Contains(logs.String(), "level=ERROR") || !strings.Contains(logs.String(), "clash") {
		t.Fatalf("conflict not logged as an error:\n%s", logs)
	}
}

func TestConflictWithinOneReplica(t *testing.T) {
	ra := newReplica(t)
	ra.publish(t, ecKey(t, "dup"), ecKey(t, "dup"), ecKey(t, "ok"))
	a := newAggregator(t, &testClock{now: testNow}, ra)
	a.poll(context.Background())
	if got := kids(t, a); !slices.Equal(got, []string{"ok"}) {
		t.Fatalf("kids %v, want [ok]", got)
	}
}

func TestUnreachableReplicaKeysRetainedThenDropped(t *testing.T) {
	clock := &testClock{now: testNow}
	ra, rb := newReplica(t), newReplica(t)
	ra.publish(t, ecKey(t, "a"))
	rb.publish(t, ecKey(t, "b"))
	a := newAggregator(t, clock, ra, rb)
	ctx := context.Background()
	a.poll(ctx)

	rb.serve(http.StatusServiceUnavailable, []byte("down"))
	clock.Advance(5*time.Minute - time.Second)
	a.poll(ctx)
	if got := kids(t, a); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("within stale_key_retention: kids %v, want [a b]", got)
	}
	clock.Advance(time.Second)
	a.poll(ctx)
	if got := kids(t, a); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("after stale_key_retention: kids %v, want [a]", got)
	}
	// dropped by time alone too, without waiting for the next poll
	clock.Advance(5 * time.Minute)
	if got := kids(t, a); len(got) != 0 {
		t.Fatalf("kids %v after every replica went stale, want none", got)
	}
}

func TestKeysDroppedWhenAReplicaStopsPublishingThem(t *testing.T) {
	ra := newReplica(t)
	old, current := ecKey(t, "old"), ecKey(t, "current")
	ra.publish(t, old, current)
	a := newAggregator(t, &testClock{now: testNow}, ra)
	ctx := context.Background()
	a.poll(ctx)
	ra.publish(t, current)
	a.poll(ctx)
	if got := kids(t, a); !slices.Equal(got, []string{"current"}) {
		t.Fatalf("kids %v, want [current]", got)
	}
}

func TestRejectedKeys(t *testing.T) {
	logs := captureLogs(t)
	ok := ecKey(t, "ok")
	okJWK, _ := jwks.FromPublicKey(ok)
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	withPrivate, _ := jwks.FromPublicKey(keystore.PublicKey{ID: "leaked", Algorithm: "ES256", Key: priv.Public()})
	small, _ := rsa.GenerateKey(rand.Reader, 1024)

	okJSON, _ := json.Marshal(okJWK)
	leakedJSON, _ := json.Marshal(withPrivate)
	leakedJSON = append(leakedJSON[:len(leakedJSON)-1], []byte(`,"d":"c2VjcmV0"}`)...)
	body := `{"keys":[` + string(okJSON) + `,` + string(leakedJSON) + `,` +
		`{"kid":"enc","kty":"EC","alg":"ES256","use":"enc","crv":"P-256","x":"` + okJWK.X + `","y":"` + okJWK.Y + `"},` +
		`{"kid":"weak","kty":"RSA","alg":"RS256","use":"sig","n":"` + base64.RawURLEncoding.EncodeToString(small.N.Bytes()) + `","e":"AQAB"},` +
		`{"kid":"hmac","kty":"oct","alg":"HS256","use":"sig","k":"c2VjcmV0"},` +
		`"not an object"]}`
	ra := newReplica(t)
	ra.serve(http.StatusOK, []byte(body))
	a := newAggregator(t, &testClock{now: testNow}, ra)
	a.poll(context.Background())

	if got := kids(t, a); !slices.Equal(got, []string{"ok"}) {
		t.Fatalf("kids %v, want only the valid public signing key", got)
	}
	out := logs.String()
	if !strings.Contains(out, "leaked") || !strings.Contains(out, "private") {
		t.Fatalf("private key material not reported:\n%s", out)
	}
	if strings.Contains(out, "c2VjcmV0") {
		t.Fatalf("private key material logged:\n%s", out)
	}
}

func TestFetchFailuresKeepPreviousKeys(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		body   string
	}{
		{"server error", http.StatusInternalServerError, "oops"},
		{"not found", http.StatusNotFound, ""},
		{"malformed JSON", http.StatusOK, `{"keys":[`},
		{"not a key set", http.StatusOK, `[]`},
		{"oversized", http.StatusOK, `{"keys":[],"pad":"` + strings.Repeat("x", maxResponseBytes) + `"}`},
		{"too many keys", http.StatusOK, `{"keys":[` + strings.Repeat(`{},`, iid.MaxJWKSKeys) + `{}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ra := newReplica(t)
			ra.publish(t, ecKey(t, "k"))
			a := newAggregator(t, &testClock{now: testNow}, ra)
			a.poll(context.Background())
			ra.serve(tt.status, []byte(tt.body))
			a.poll(context.Background())
			if got := kids(t, a); !slices.Equal(got, []string{"k"}) {
				t.Fatalf("kids %v, want the previous [k]", got)
			}
			a.mu.RLock()
			failing := a.replicas[0].failing
			a.mu.RUnlock()
			if !failing {
				t.Fatal("failure not recorded")
			}
		})
	}
}

func TestKeyCountLimit(t *testing.T) {
	keys := make([]keystore.PublicKey, iid.MaxJWKSKeys)
	for i := range keys {
		keys[i] = ecKey(t, fmt.Sprintf("k%03d", i))
	}
	ra := newReplica(t)
	ra.publish(t, keys...)
	a := newAggregator(t, &testClock{now: testNow}, ra)
	a.poll(context.Background())
	if got := kids(t, a); len(got) != iid.MaxJWKSKeys {
		t.Fatalf("%d keys served, want all %d", len(got), iid.MaxJWKSKeys)
	}

	// one key more fails the whole fetch: never truncated to an arbitrary
	// subset, and the previous keys are kept
	ra.publish(t, append(keys, ecKey(t, "k-extra"))...)
	a.poll(context.Background())
	got := kids(t, a)
	if len(got) != iid.MaxJWKSKeys || slices.Contains(got, "k-extra") {
		t.Fatalf("after an oversized set: %d keys served (extra included: %v), want the previous %d", len(got), slices.Contains(got, "k-extra"), iid.MaxJWKSKeys)
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	target := newReplica(t)
	target.publish(t, ecKey(t, "elsewhere"))
	redirecting := httptest.NewTLSServer(http.RedirectHandler(target.url(), http.StatusFound))
	t.Cleanup(redirecting.Close)
	client, err := NewHTTPClient(caFile(t, target), tls.VersionTLS13)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New([]string{redirecting.URL + "/.well-known/jwks.json"}, client)
	if err != nil {
		t.Fatal(err)
	}
	a.poll(context.Background())
	if target.hits.Load() != 0 {
		t.Fatal("the redirect target was contacted")
	}
	if got := kids(t, a); len(got) != 0 {
		t.Fatalf("kids %v: a redirect was followed", got)
	}
}

func TestFetchesRunConcurrently(t *testing.T) {
	ra, rb := newReplica(t), newReplica(t)
	ra.publish(t, ecKey(t, "a"))
	rb.publish(t, ecKey(t, "b"))
	aHit, bHit := make(chan struct{}), make(chan struct{})
	await := func(other <-chan struct{}) {
		select {
		case <-other:
		case <-time.After(time.Second): // sequential fetches: the other never comes
		}
	}
	var onceA, onceB sync.Once
	ra.hook = func() { onceA.Do(func() { close(aHit) }); await(bHit) }
	rb.hook = func() { onceB.Do(func() { close(bHit) }); await(aHit) }
	a := newAggregator(t, &testClock{now: testNow}, ra, rb)
	start := time.Now()
	a.poll(context.Background())
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Fatalf("poll took %v: replicas fetched one after the other", elapsed)
	}
	if got := kids(t, a); len(got) != 2 {
		t.Fatalf("kids %v", got)
	}
}

func TestFetchTimeout(t *testing.T) {
	ra := newReplica(t)
	release := make(chan struct{})
	ra.hook = func() { <-release }
	t.Cleanup(func() { close(release) })
	client, _ := NewHTTPClient(caFile(t, ra), tls.VersionTLS13)
	a, err := New([]string{ra.url()}, client, WithFetchTimeout(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	a.poll(context.Background())
	if time.Since(start) > time.Second {
		t.Fatal("fetch not bounded by fetch_timeout")
	}
}

func TestReadiness(t *testing.T) {
	clock := &testClock{now: testNow}
	ra, rb := newReplica(t), newReplica(t)
	ra.serve(http.StatusServiceUnavailable, nil)
	rb.serve(http.StatusServiceUnavailable, nil)
	a := newAggregator(t, clock, ra, rb)
	ctx := context.Background()

	if err := a.Check(ctx); err == nil {
		t.Fatal("ready before any fetch")
	}
	a.poll(ctx)
	if err := a.Check(ctx); err == nil {
		t.Fatal("ready with every replica failing")
	}
	rb.publish(t, ecKey(t, "b"))
	a.poll(ctx)
	if err := a.Check(ctx); err != nil {
		t.Fatalf("not ready with one replica fetched: %v", err)
	}
	rb.serve(http.StatusServiceUnavailable, nil)
	clock.Advance(5 * time.Minute)
	a.poll(ctx)
	if err := a.Check(ctx); err == nil {
		t.Fatal("ready with every replica stale beyond stale_key_retention")
	}
}

func TestReplicaStatusTransitionsLogged(t *testing.T) {
	logs := captureLogs(t)
	ra := newReplica(t)
	ra.serve(http.StatusServiceUnavailable, nil)
	a := newAggregator(t, &testClock{now: testNow}, ra)
	ctx := context.Background()
	for range 3 {
		a.poll(ctx)
	}
	ra.publish(t, ecKey(t, "a"))
	for range 3 {
		a.poll(ctx)
	}
	out := logs.String()
	if n := strings.Count(out, "replica fetch failing"); n != 1 {
		t.Fatalf("%d failure logs, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "replica fetch recovered"); n != 1 {
		t.Fatalf("%d recovery logs, want 1:\n%s", n, out)
	}
}

func TestRefresh(t *testing.T) {
	ra := newReplica(t)
	ra.publish(t, ecKey(t, "a"))
	a := newAggregator(t, &testClock{now: testNow}, ra)
	if got := kids(t, a); len(got) != 0 {
		t.Fatalf("kids %v before any fetch", got)
	}
	a.Refresh(context.Background())
	if got := kids(t, a); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("kids %v after Refresh, want [a]", got)
	}
	ra.publish(t, ecKey(t, "a"), ecKey(t, "b"))
	a.Refresh(context.Background())
	if got := kids(t, a); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("kids %v after a second Refresh, want [a b]", got)
	}
}

func TestRun(t *testing.T) {
	ra := newReplica(t)
	ra.publish(t, ecKey(t, "a"))
	client, _ := NewHTTPClient(caFile(t, ra), tls.VersionTLS13)
	a, err := New([]string{ra.url()}, client, WithPollInterval(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for ra.hits.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ra.hits.Load() < 3 {
		t.Fatalf("%d polls, want repeated polling", ra.hits.Load())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestHTTPClientRequiresTLS13(t *testing.T) {
	legacy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"keys":[]}`))
	}))
	legacy.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	legacy.StartTLS()
	t.Cleanup(legacy.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: legacy.Certificate().Raw}), 0o600)
	client, err := NewHTTPClient(path, tls.VersionTLS13)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(legacy.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("connected to a TLS 1.2-only replica")
	}
}

func TestHTTPClientWithTLS12Minimum(t *testing.T) {
	legacy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	legacy.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	legacy.StartTLS()
	t.Cleanup(legacy.Close)
	path := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: legacy.Certificate().Raw}), 0o600)
	client, err := NewHTTPClient(path, tls.VersionTLS12)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(legacy.URL)
	if err != nil {
		t.Fatalf("tls_min_version 1.2: could not reach a TLS 1.2-only replica: %v", err)
	}
	resp.Body.Close()
	if _, err := NewHTTPClient(path, tls.VersionTLS11); err == nil {
		t.Fatal("accepted TLS 1.1 as minimum")
	}
}

func TestNewHTTPClientRejectsBadBundles(t *testing.T) {
	if _, err := NewHTTPClient(filepath.Join(t.TempDir(), "missing.pem"), tls.VersionTLS13); err == nil {
		t.Fatal("accepted a missing CA bundle")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	os.WriteFile(empty, []byte("nothing"), 0o600)
	if _, err := NewHTTPClient(empty, tls.VersionTLS13); err == nil {
		t.Fatal("accepted a CA bundle without certificates")
	}
	if _, err := NewHTTPClient("", tls.VersionTLS13); err != nil {
		t.Fatalf("system roots: %v", err)
	}
}

func TestNewValidation(t *testing.T) {
	client := http.DefaultClient
	for _, tt := range []struct {
		name     string
		replicas []string
		client   *http.Client
		options  []Option
	}{
		{"no replicas", nil, client, nil},
		{"plain http replica", []string{"http://signer-a/.well-known/jwks.json"}, client, nil},
		{"duplicate replica", []string{"https://a/j", "https://a/j"}, client, nil},
		{"nil client", []string{"https://a/j"}, nil, nil},
		{"zero poll interval", []string{"https://a/j"}, client, []Option{WithPollInterval(0)}},
		{"zero fetch timeout", []string{"https://a/j"}, client, []Option{WithFetchTimeout(0)}},
		{"zero retention", []string{"https://a/j"}, client, []Option{WithStaleKeyRetention(0)}},
	} {
		if _, err := New(tt.replicas, tt.client, tt.options...); err == nil {
			t.Fatalf("%s: accepted", tt.name)
		}
	}
}
