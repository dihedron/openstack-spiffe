package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"regexp"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// fakeClock is a manually advanced clock, safe for concurrent use.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

const (
	testRotation     = 24 * time.Hour
	testPublishAhead = 2 * time.Minute
)

// testStart is 2026-09-29 14:32:11 UTC, i.e. 52331 seconds after midnight.
var testStart = time.Date(2026, 9, 29, 14, 32, 11, 0, time.UTC)

func newTestStore(t *testing.T, clock *fakeClock, replicaID, algorithm string) *Ephemeral {
	t.Helper()
	s, err := NewEphemeral(context.Background(), replicaID, algorithm,
		WithClock(clock.Now),
		WithRotationInterval(testRotation),
		WithPublishAhead(testPublishAhead),
	)
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	return s
}

func publishedIDs(t *testing.T, s KeyStore) []string {
	t.Helper()
	keys, err := s.PublicKeys(context.Background())
	if err != nil {
		t.Fatalf("PublicKeys: %v", err)
	}
	var ids []string
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids
}

func activeID(t *testing.T, s KeyStore) string {
	t.Helper()
	info, err := s.Active(context.Background())
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	return info.ID
}

// rotate advances the clock to the point where the next key is due, runs
// maintenance so that it gets generated, and returns its kid.
func rotate(t *testing.T, s *Ephemeral, clock *fakeClock) string {
	t.Helper()
	before := publishedIDs(t, s)
	clock.Advance(testRotation - testPublishAhead)
	if _, err := s.maintain(context.Background()); err != nil {
		t.Fatalf("maintain: %v", err)
	}
	after := publishedIDs(t, s)
	for _, id := range after {
		if !slices.Contains(before, id) {
			return id
		}
	}
	t.Fatalf("no new key published: before %v, after %v", before, after)
	return ""
}

func TestKeyIDFormat(t *testing.T) {
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "RS256")

	ids := publishedIDs(t, s)
	if len(ids) != 1 {
		t.Fatalf("expected exactly the first key, got %v", ids)
	}
	if want := "2026-09-29-signer-a-key-52331"; ids[0] != want {
		t.Fatalf("kid = %q, want %q", ids[0], want)
	}
	pattern := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}-[a-z0-9]([a-z0-9-]*[a-z0-9])?-key-\d+$`)
	if !pattern.MatchString(ids[0]) {
		t.Fatalf("kid %q does not match <YYYY-MM-DD>-<replica-id>-key-<n>", ids[0])
	}
}

func TestKeyIDUsesUTCDate(t *testing.T) {
	// 01:00 in UTC+2 is still the previous day (23:00) in UTC.
	local := time.Date(2026, 9, 30, 1, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	s := newTestStore(t, newFakeClock(local), "signer-a", "RS256")
	if got, want := publishedIDs(t, s)[0], "2026-09-29-signer-a-key-82800"; got != want {
		t.Fatalf("kid = %q, want %q", got, want)
	}
}

func TestKeyIDsUniqueAcrossReplicas(t *testing.T) {
	clock := newFakeClock(testStart)
	a := newTestStore(t, clock, "signer-a", "RS256")
	b := newTestStore(t, clock, "signer-b", "RS256")
	if ida, idb := activeOrPending(t, a), activeOrPending(t, b); ida == idb {
		t.Fatalf("replicas share kid %q", ida)
	}
}

func TestKeyIDsUniqueAcrossRestarts(t *testing.T) {
	clock := newFakeClock(testStart)
	first := activeOrPending(t, newTestStore(t, clock, "signer-a", "RS256"))
	clock.Advance(time.Second)
	second := activeOrPending(t, newTestStore(t, clock, "signer-a", "RS256"))
	if first == second {
		t.Fatalf("restarted replica reused kid %q", first)
	}
}

func TestKeyIDsStrictlyIncreaseWithinTheSameSecond(t *testing.T) {
	s := newTestStore(t, newFakeClock(testStart), "signer-a", "RS256")
	// the first key already took second 52331
	if got, want := s.newKeyID(testStart), "2026-09-29-signer-a-key-52332"; got != want {
		t.Fatalf("kid = %q, want %q", got, want)
	}
	if got, want := s.newKeyID(testStart.Add(500*time.Millisecond)), "2026-09-29-signer-a-key-52333"; got != want {
		t.Fatalf("kid = %q, want %q", got, want)
	}
	// a new day starts over from the seconds of that day
	if got, want := s.newKeyID(testStart.Add(24*time.Hour)), "2026-09-30-signer-a-key-52331"; got != want {
		t.Fatalf("kid = %q, want %q", got, want)
	}
}

func activeOrPending(t *testing.T, s KeyStore) string {
	t.Helper()
	ids := publishedIDs(t, s)
	if len(ids) != 1 {
		t.Fatalf("expected one key, got %v", ids)
	}
	return ids[0]
}

func TestFirstKeyPublishedBeforeUse(t *testing.T) {
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "RS256")
	ctx := context.Background()

	pending := activeOrPending(t, s)
	if _, err := s.Active(ctx); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("Active before publish_ahead: got %v, want ErrNoActiveKey", err)
	}
	if err := s.Check(ctx); !errors.Is(err, ErrNoActiveKey) {
		t.Fatalf("Check before publish_ahead: got %v, want ErrNoActiveKey", err)
	}
	if _, err := s.Sign(ctx, pending, make([]byte, sha256.Size)); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("Sign with a pending key: got %v, want ErrKeyNotActive", err)
	}

	clock.Advance(testPublishAhead - time.Nanosecond)
	if err := s.Check(ctx); err == nil {
		t.Fatal("Check succeeded before publish_ahead elapsed")
	}

	clock.Advance(time.Nanosecond)
	if err := s.Check(ctx); err != nil {
		t.Fatalf("Check after publish_ahead: %v", err)
	}
	info, err := s.Active(ctx)
	if err != nil {
		t.Fatalf("Active after publish_ahead: %v", err)
	}
	if info.ID != pending || info.Algorithm != "RS256" {
		t.Fatalf("Active = %+v, want kid %q, alg RS256", info, pending)
	}
}

func TestRotationPublishesNextKeyAheadThenSwitches(t *testing.T) {
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "RS256")
	ctx := context.Background()
	clock.Advance(testPublishAhead)
	first := activeID(t, s)

	// not due yet: nothing happens
	clock.Advance(testRotation - testPublishAhead - time.Second)
	if _, err := s.maintain(ctx); err != nil {
		t.Fatalf("maintain: %v", err)
	}
	if ids := publishedIDs(t, s); len(ids) != 1 {
		t.Fatalf("next key generated too early: %v", ids)
	}
	clock.Advance(-(testRotation - testPublishAhead - time.Second))

	next := rotate(t, s, clock)
	if next == first {
		t.Fatal("rotation reused the active kid")
	}
	if got := activeID(t, s); got != first {
		t.Fatalf("next key activated as soon as published: active %q", got)
	}
	if ids := publishedIDs(t, s); !slices.Equal(ids, []string{first, next}) {
		t.Fatalf("published %v, want [%s %s]", ids, first, next)
	}

	// a second maintenance run must not generate yet another key
	if _, err := s.maintain(ctx); err != nil {
		t.Fatalf("maintain: %v", err)
	}
	if ids := publishedIDs(t, s); len(ids) != 2 {
		t.Fatalf("duplicate pending key: %v", ids)
	}

	clock.Advance(testPublishAhead)
	if got := activeID(t, s); got != next {
		t.Fatalf("active after publish_ahead = %q, want %q", got, next)
	}
	if err := s.Check(ctx); err != nil {
		t.Fatalf("Check after rotation: %v", err)
	}
}

func TestRetiredKeyRetainedForRetentionWindow(t *testing.T) {
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "RS256")
	ctx := context.Background()
	clock.Advance(testPublishAhead)
	first := activeID(t, s)
	next := rotate(t, s, clock)
	clock.Advance(testPublishAhead) // first is retired now

	if _, err := s.Sign(ctx, first, make([]byte, sha256.Size)); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("Sign with a retired key: got %v, want ErrKeyNotActive", err)
	}

	clock.Advance(iid.TTL - time.Nanosecond)
	if ids := publishedIDs(t, s); !slices.Equal(ids, []string{first, next}) {
		t.Fatalf("within retention: published %v, want [%s %s]", ids, first, next)
	}

	clock.Advance(time.Nanosecond)
	if ids := publishedIDs(t, s); !slices.Equal(ids, []string{next}) {
		t.Fatalf("after retention: published %v, want [%s]", ids, next)
	}
	// maintenance purges it from memory as well
	if _, err := s.maintain(ctx); err != nil {
		t.Fatalf("maintain: %v", err)
	}
	s.mu.RLock()
	count := len(s.keys)
	s.mu.RUnlock()
	if count != 1 {
		t.Fatalf("expired key not purged: %d keys held", count)
	}
}

func TestCustomRetention(t *testing.T) {
	clock := newFakeClock(testStart)
	s, err := NewEphemeral(context.Background(), "signer-a", "RS256",
		WithClock(clock.Now), WithRotationInterval(testRotation), WithPublishAhead(testPublishAhead),
		WithRetention(10*time.Minute))
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	clock.Advance(testPublishAhead)
	rotate(t, s, clock)
	clock.Advance(testPublishAhead + 9*time.Minute)
	if ids := publishedIDs(t, s); len(ids) != 2 {
		t.Fatalf("retired key dropped before custom retention: %v", ids)
	}
	clock.Advance(time.Minute)
	if ids := publishedIDs(t, s); len(ids) != 1 {
		t.Fatalf("retired key kept past custom retention: %v", ids)
	}
}

func TestLateGenerationStillPublishesAhead(t *testing.T) {
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "RS256")
	clock.Advance(testPublishAhead)
	first := activeID(t, s)

	// maintenance runs an hour after the next key was due
	clock.Advance(testRotation + time.Hour)
	if _, err := s.maintain(context.Background()); err != nil {
		t.Fatalf("maintain: %v", err)
	}
	if got := activeID(t, s); got != first {
		t.Fatalf("late key activated immediately: active %q", got)
	}
	clock.Advance(testPublishAhead)
	if got := activeID(t, s); got == first {
		t.Fatal("late key never activated")
	}
}

func TestMaintainReportsNextDeadline(t *testing.T) {
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "RS256")
	ctx := context.Background()

	next, err := s.maintain(ctx)
	if err != nil {
		t.Fatalf("maintain: %v", err)
	}
	if want := testStart.Add(testPublishAhead); !next.Equal(want) {
		t.Fatalf("deadline with a pending first key = %v, want its activation %v", next, want)
	}

	clock.Advance(testPublishAhead)
	next, _ = s.maintain(ctx)
	if want := testStart.Add(testRotation); !next.Equal(want) {
		t.Fatalf("deadline with an active key = %v, want next generation %v", next, want)
	}

	rotate(t, s, clock)
	clock.Advance(testPublishAhead)
	next, _ = s.maintain(ctx)
	if want := clock.Now().Add(iid.TTL); !next.Equal(want) {
		t.Fatalf("deadline with a retired key = %v, want its purge %v", next, want)
	}
}

func TestSignaturesVerify(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		t.Run(alg, func(t *testing.T) {
			clock := newFakeClock(testStart)
			s := newTestStore(t, clock, "signer-a", alg)
			ctx := context.Background()
			clock.Advance(testPublishAhead)

			info, err := s.Active(ctx)
			if err != nil {
				t.Fatalf("Active: %v", err)
			}
			if info.Algorithm != alg {
				t.Fatalf("algorithm = %q, want %q", info.Algorithm, alg)
			}
			digest := sha256.Sum256([]byte("header.payload"))
			sig, err := s.Sign(ctx, info.ID, digest[:])
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			keys, err := s.PublicKeys(ctx)
			if err != nil {
				t.Fatalf("PublicKeys: %v", err)
			}
			if len(keys) != 1 || keys[0].ID != info.ID || keys[0].Algorithm != alg {
				t.Fatalf("PublicKeys = %+v", keys)
			}
			switch pub := keys[0].Key.(type) {
			case *rsa.PublicKey:
				if pub.N.BitLen() != 2048 {
					t.Fatalf("RSA key size %d, want 2048", pub.N.BitLen())
				}
				if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
					t.Fatalf("RS256 signature does not verify: %v", err)
				}
			case *ecdsa.PublicKey:
				if pub.Curve != elliptic.P256() {
					t.Fatalf("EC curve %s, want P-256", pub.Curve.Params().Name)
				}
				if len(sig) != 64 {
					t.Fatalf("ES256 signature is %d bytes, want 64 (R || S)", len(sig))
				}
				r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
				if !ecdsa.Verify(pub, digest[:], r, s) {
					t.Fatal("ES256 signature does not verify")
				}
			default:
				t.Fatalf("unexpected public key type %T", pub)
			}
		})
	}
}

func TestPublicKeysContainNoPrivateMaterial(t *testing.T) {
	for _, alg := range []string{"RS256", "ES256"} {
		s := newTestStore(t, newFakeClock(testStart), "signer-a", alg)
		keys, err := s.PublicKeys(context.Background())
		if err != nil {
			t.Fatalf("PublicKeys: %v", err)
		}
		for _, k := range keys {
			switch k.Key.(type) {
			case *rsa.PublicKey, *ecdsa.PublicKey:
			default:
				t.Fatalf("%s: published key of type %T", alg, k.Key)
			}
		}
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	clock := newFakeClock(testStart)
	s := newTestStore(t, clock, "signer-a", "RS256")
	clock.Advance(testPublishAhead)
	kid := activeID(t, s)

	if _, err := s.Sign(context.Background(), "2026-09-29-other-key-1", make([]byte, sha256.Size)); !errors.Is(err, ErrKeyNotActive) {
		t.Fatalf("unknown kid: got %v, want ErrKeyNotActive", err)
	}
	if _, err := s.Sign(context.Background(), kid, []byte("short")); err == nil {
		t.Fatal("Sign accepted a digest that is not SHA-256 sized")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Sign(ctx, kid, make([]byte, sha256.Size)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: got %v, want context.Canceled", err)
	}
}

func TestNewEphemeralValidation(t *testing.T) {
	tests := []struct {
		name      string
		replicaID string
		algorithm string
		options   []Option
	}{
		{"empty replica id", "", "RS256", nil},
		{"uppercase replica id", "Signer-A", "RS256", nil},
		{"replica id with dot", "signer.a", "RS256", nil},
		{"replica id with trailing dash", "signer-", "RS256", nil},
		{"unknown algorithm", "signer-a", "HS256", nil},
		{"zero rotation", "signer-a", "RS256", []Option{WithRotationInterval(0)}},
		{"zero publish ahead", "signer-a", "RS256", []Option{WithPublishAhead(0)}},
		{"publish ahead not shorter than rotation", "signer-a", "RS256", []Option{WithRotationInterval(time.Hour), WithPublishAhead(time.Hour)}},
		{"zero retention", "signer-a", "RS256", []Option{WithRetention(0)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewEphemeral(context.Background(), tt.replicaID, tt.algorithm, tt.options...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDefaults(t *testing.T) {
	s, err := NewEphemeral(context.Background(), "signer-a", "")
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	if s.algorithm != iid.Algorithm || s.rotation != 24*time.Hour || s.publishAhead != 2*time.Minute || s.retention != iid.TTL {
		t.Fatalf("unexpected defaults: alg %q, rotation %v, publish ahead %v, retention %v", s.algorithm, s.rotation, s.publishAhead, s.retention)
	}
}

func TestRunRotatesAndStopsOnCancel(t *testing.T) {
	s, err := NewEphemeral(context.Background(), "signer-a", "ES256",
		WithRotationInterval(300*time.Millisecond),
		WithPublishAhead(100*time.Millisecond),
		WithRetention(100*time.Millisecond))
	if err != nil {
		t.Fatalf("NewEphemeral: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	seen := map[string]bool{}
	deadline := time.Now().Add(5 * time.Second)
	for len(seen) < 3 && time.Now().Before(deadline) {
		if info, err := s.Active(ctx); err == nil {
			seen[info.ID] = true
			digest := sha256.Sum256([]byte("x"))
			// the key may retire between Active and Sign: that is the
			// documented ErrKeyNotActive case, anything else is a bug
			if _, err := s.Sign(ctx, info.ID, digest[:]); err != nil && !errors.Is(err, ErrKeyNotActive) {
				t.Fatalf("Sign: %v", err)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(seen) < 3 {
		t.Fatalf("Run did not rotate keys: saw %d active kids", len(seen))
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v after cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}
