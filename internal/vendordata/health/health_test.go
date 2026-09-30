package health

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/keystore"
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

// switchable is a check whose outcome the test sets.
type switchable struct {
	mu  sync.Mutex
	err error
}

func (s *switchable) set(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *switchable) check(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func get(h http.Handler, method string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, "/readiness", nil))
	return w
}

type report struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
}

func decode(t *testing.T, w *httptest.ResponseRecorder) report {
	t.Helper()
	var r report
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatalf("decoding %s: %v", w.Body, err)
	}
	return r
}

func TestLiveness(t *testing.T) {
	h := Liveness()
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		if w := get(h, method); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status %d, Cache-Control %q", method, w.Code, w.Header().Get("Cache-Control"))
		}
	}
	if w := get(h, http.MethodPost); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST: status %d, Allow %q", w.Code, w.Header().Get("Allow"))
	}
}

func newReadiness(t *testing.T, clock *testClock, checks []Check, options ...Option) *Readiness {
	t.Helper()
	r, err := NewReadiness(checks, append([]Option{WithClock(clock.Now)}, options...)...)
	if err != nil {
		t.Fatalf("NewReadiness: %v", err)
	}
	return r
}

func TestNotReadyBeforeTheFirstRun(t *testing.T) {
	r := newReadiness(t, &testClock{now: testNow}, []Check{{Name: "key_store", Run: func(context.Context) error { return nil }}})
	w := get(r, http.MethodGet)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 before any check ran", w.Code)
	}
	if got := decode(t, w); got.Status != "not ready" {
		t.Fatalf("report %+v", got)
	}
}

func TestReadyWhenEveryCheckPasses(t *testing.T) {
	ok := func(context.Context) error { return nil }
	r := newReadiness(t, &testClock{now: testNow}, []Check{{Name: "key_store", Run: ok}, {Name: "keystone", Run: ok}})
	r.runChecks(context.Background())
	w := get(r, http.MethodGet)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", w.Code)
	}
	if w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", w.Header())
	}
	got := decode(t, w)
	if got.Status != "ready" || got.Checks["key_store"] != "ok" || got.Checks["keystone"] != "ok" {
		t.Fatalf("report %+v", got)
	}
	if w := get(r, http.MethodHead); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD: status %d, %d body bytes", w.Code, w.Body.Len())
	}
	if w := get(r, http.MethodPost); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status %d, want 405", w.Code)
	}
}

func TestFailingCheckWithoutDetails(t *testing.T) {
	keystone := &switchable{err: errors.New("dial tcp 10.0.0.5:5000: connection refused")}
	r := newReadiness(t, &testClock{now: testNow}, []Check{
		{Name: "key_store", Run: func(context.Context) error { return nil }},
		{Name: "keystone", Run: keystone.check},
	})
	r.runChecks(context.Background())
	w := get(r, http.MethodGet)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
	got := decode(t, w)
	if got.Status != "not ready" || got.Checks["keystone"] != "failing" || got.Checks["key_store"] != "ok" {
		t.Fatalf("report %+v", got)
	}
	if strings.Contains(w.Body.String(), "10.0.0.5") {
		t.Fatalf("error details exposed: %s", w.Body)
	}

	keystone.set(nil)
	r.runChecks(context.Background())
	if w := get(r, http.MethodGet); w.Code != http.StatusOK {
		t.Fatalf("after recovery: status %d, want 200", w.Code)
	}
}

func TestCheckTimeout(t *testing.T) {
	r := newReadiness(t, &testClock{now: testNow}, []Check{{Name: "nova", Run: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}}, WithTimeout(20*time.Millisecond))
	start := time.Now()
	r.runChecks(context.Background())
	if time.Since(start) > time.Second {
		t.Fatal("check not bounded by the timeout")
	}
	if w := get(r, http.MethodGet); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}

func TestChecksRunConcurrently(t *testing.T) {
	aStarted, bStarted := make(chan struct{}), make(chan struct{})
	await := func(ctx context.Context, other <-chan struct{}) error {
		select {
		case <-other:
			return nil
		case <-ctx.Done():
			return errors.New("the other check never started: checks run sequentially")
		}
	}
	r := newReadiness(t, &testClock{now: testNow}, []Check{
		{Name: "a", Run: func(ctx context.Context) error { close(aStarted); return await(ctx, bStarted) }},
		{Name: "b", Run: func(ctx context.Context) error { close(bStarted); return await(ctx, aStarted) }},
	}, WithTimeout(2*time.Second))
	r.runChecks(context.Background())
	if w := get(r, http.MethodGet); w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
}

func TestStaleResultsAreNotReady(t *testing.T) {
	clock := &testClock{now: testNow}
	r := newReadiness(t, clock, []Check{{Name: "key_store", Run: func(context.Context) error { return nil }}}, WithInterval(5*time.Second))
	r.runChecks(context.Background())
	clock.Advance(15*time.Second - time.Nanosecond)
	if w := get(r, http.MethodGet); w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 within three intervals", w.Code)
	}
	clock.Advance(time.Nanosecond)
	if w := get(r, http.MethodGet); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 with results three intervals old", w.Code)
	}
}

func TestOnlyTransitionsAreLogged(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	keystone := &switchable{err: errors.New("connection refused")}
	r := newReadiness(t, &testClock{now: testNow}, []Check{{Name: "keystone", Run: keystone.check}})
	for range 3 {
		r.runChecks(context.Background())
	}
	keystone.set(nil)
	for range 3 {
		r.runChecks(context.Background())
	}
	out := logs.String()
	if n := strings.Count(out, "readiness check failing"); n != 1 {
		t.Fatalf("%d failure logs, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "readiness check recovered"); n != 1 {
		t.Fatalf("%d recovery logs, want 1:\n%s", n, out)
	}
}

func TestRunLoop(t *testing.T) {
	var calls atomic.Int32
	r, err := NewReadiness([]Check{{Name: "key_store", Run: func(context.Context) error {
		if calls.Add(1) < 3 {
			return errors.New("not yet")
		}
		return nil
	}}}, WithInterval(10*time.Millisecond))
	if err != nil {
		t.Fatalf("NewReadiness: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for get(r, http.MethodGet).Code != http.StatusOK && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if get(r, http.MethodGet).Code != http.StatusOK {
		t.Fatal("never became ready")
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

// TestKeyStorePublishAheadGate wires the ephemeral key store: the replica is
// not ready until its first key has been published for publish_ahead.
func TestKeyStorePublishAheadGate(t *testing.T) {
	clock := &testClock{now: testNow}
	ks, err := keystore.NewEphemeral(context.Background(), "signer-a", "ES256", keystore.WithClock(clock.Now))
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	r := newReadiness(t, clock, []Check{{Name: "key_store", Run: ks.Check}})
	r.runChecks(context.Background())
	if w := get(r, http.MethodGet); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d before publish_ahead, want 503", w.Code)
	}
	clock.Advance(2 * time.Minute)
	r.runChecks(context.Background())
	if w := get(r, http.MethodGet); w.Code != http.StatusOK {
		t.Fatalf("status %d after publish_ahead, want 200", w.Code)
	}
}

func TestNewReadinessValidation(t *testing.T) {
	ok := func(context.Context) error { return nil }
	for _, tt := range []struct {
		name    string
		checks  []Check
		options []Option
	}{
		{"no checks", nil, nil},
		{"unnamed check", []Check{{Run: ok}}, nil},
		{"nil check", []Check{{Name: "a"}}, nil},
		{"duplicate name", []Check{{Name: "a", Run: ok}, {Name: "a", Run: ok}}, nil},
		{"zero interval", []Check{{Name: "a", Run: ok}}, []Option{WithInterval(0)}},
		{"zero timeout", []Check{{Name: "a", Run: ok}}, []Option{WithTimeout(0)}},
	} {
		if _, err := NewReadiness(tt.checks, tt.options...); err == nil {
			t.Fatalf("%s: accepted", tt.name)
		}
	}
}
