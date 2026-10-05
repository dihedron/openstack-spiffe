package ttlcache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func newCache(t *testing.T, clock *testClock, cfg Config) *Cache[string, string] {
	t.Helper()
	cfg.Now = clock.Now
	c, err := New[string, string](cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// loader returns value, valid for ttl, counting its calls.
func loader(clock *testClock, calls *atomic.Int32, value string, ttl time.Duration) Loader[string] {
	return func(context.Context) (string, time.Time, error) {
		calls.Add(1)
		return value, clock.Now().Add(ttl), nil
	}
}

func TestHitWithinExpiry(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{})
	var calls atomic.Int32
	ctx := context.Background()

	for range 3 {
		v, err := c.Get(ctx, "k", loader(clock, &calls, "v", time.Minute))
		if err != nil || v != "v" {
			t.Fatalf("Get = %q, %v", v, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("%d loads, want 1", calls.Load())
	}
	clock.Advance(time.Minute)
	_, _ = c.Get(ctx, "k", loader(clock, &calls, "v2", time.Minute))
	if calls.Load() != 2 {
		t.Fatalf("expired entry served: %d loads, want 2", calls.Load())
	}
}

func TestErrorsAreNotCached(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{})
	boom := errors.New("boom")
	var calls atomic.Int32
	failing := func(context.Context) (string, time.Time, error) {
		calls.Add(1)
		return "", clock.Now().Add(time.Minute), boom
	}
	for range 2 {
		if _, err := c.Get(context.Background(), "k", failing); !errors.Is(err, boom) {
			t.Fatalf("Get error %v, want boom", err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("%d loads, want 2 (errors not cached)", calls.Load())
	}
}

func TestAlreadyExpiredValuesAreNotCached(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{})
	var calls atomic.Int32
	for range 2 {
		if v, err := c.Get(context.Background(), "k", loader(clock, &calls, "v", 0)); err != nil || v != "v" {
			t.Fatalf("Get = %q, %v", v, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("%d loads, want 2", calls.Load())
	}
}

func TestBounded(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{MaxEntries: 5})
	var calls atomic.Int32
	for i := range 50 {
		_, _ = c.Get(context.Background(), fmt.Sprint(i), loader(clock, &calls, "v", time.Hour))
		if n := c.Len(); n > 5 {
			t.Fatalf("%d entries, want at most 5", n)
		}
	}
}

func TestExpiredEntriesPurgedFirst(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{MaxEntries: 3})
	var calls atomic.Int32
	ctx := context.Background()
	_, _ = c.Get(ctx, "short", loader(clock, &calls, "v", time.Second))
	_, _ = c.Get(ctx, "long-1", loader(clock, &calls, "v", time.Hour))
	_, _ = c.Get(ctx, "long-2", loader(clock, &calls, "v", time.Hour))
	clock.Advance(2 * time.Second)
	_, _ = c.Get(ctx, "new", loader(clock, &calls, "v", time.Hour))
	before := calls.Load()
	_, _ = c.Get(ctx, "long-1", loader(clock, &calls, "v", time.Hour))
	_, _ = c.Get(ctx, "long-2", loader(clock, &calls, "v", time.Hour))
	if calls.Load() != before {
		t.Fatal("a live entry was evicted while an expired one could be purged")
	}
}

func TestConcurrentLoadsAreMerged(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{})
	gate := make(chan struct{})
	var calls atomic.Int32
	slow := func(context.Context) (string, time.Time, error) {
		calls.Add(1)
		<-gate
		return "v", clock.Now().Add(time.Minute), nil
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if v, err := c.Get(context.Background(), "k", slow); err != nil || v != "v" {
				t.Errorf("Get = %q, %v", v, err)
			}
		})
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("%d loads for 20 concurrent callers, want 1", calls.Load())
	}
}

func TestCallerCancellation(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{})
	gate := make(chan struct{})
	defer close(gate)
	slow := func(ctx context.Context) (string, time.Time, error) {
		<-gate
		return "v", clock.Now().Add(time.Minute), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, "k", slow); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get error %v, want context.DeadlineExceeded", err)
	}
}

func TestLoadTimeout(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{LoadTimeout: 20 * time.Millisecond})
	blocking := func(ctx context.Context) (string, time.Time, error) {
		<-ctx.Done()
		return "", time.Time{}, ctx.Err()
	}
	if _, err := c.Get(context.Background(), "k", blocking); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get error %v, want context.DeadlineExceeded", err)
	}
}

func TestLoadSurvivesCallerCancellation(t *testing.T) {
	clock := &testClock{now: testNow}
	c := newCache(t, clock, Config{})
	gate := make(chan struct{})
	var calls atomic.Int32
	slow := func(ctx context.Context) (string, time.Time, error) {
		calls.Add(1)
		select {
		case <-gate:
		case <-ctx.Done():
			return "", time.Time{}, ctx.Err()
		}
		return "v", clock.Now().Add(time.Minute), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = c.Get(ctx, "k", slow)
		close(done)
	}()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	close(gate) // the load completes after its first caller left
	deadline := time.Now().Add(5 * time.Second)
	for c.Len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if v, err := c.Get(context.Background(), "k", slow); err != nil || v != "v" || calls.Load() != 1 {
		t.Fatalf("Get = %q, %v after %d loads; want the value cached by the first load", v, err, calls.Load())
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New[string, string](Config{MaxEntries: -1}); err == nil {
		t.Fatal("accepted a negative size")
	}
	if _, err := New[string, string](Config{LoadTimeout: -time.Second}); err == nil {
		t.Fatal("accepted a negative timeout")
	}
}
