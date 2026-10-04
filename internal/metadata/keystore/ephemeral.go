package keystore

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	rsaKeyBits = 2048
	// maxSleep bounds how long Run sleeps between maintenance runs, so that
	// wall-clock jumps are caught up with in reasonable time.
	maxSleep = time.Minute
	// retryDelay is how long Run waits after a failed maintenance run.
	retryDelay = 10 * time.Second
)

// ephemeralKey is a key pair held in memory.
type ephemeralKey struct {
	id          string
	algorithm   string
	signer      crypto.Signer
	publishedAt time.Time
	// activatesAt is publishedAt plus the publish-ahead period; the key is
	// retired when its successor activates.
	activatesAt time.Time
}

// Ephemeral is a KeyStore that generates its key pairs in memory and never
// persists them: a restarted replica simply starts over with a new key. Each
// key is published publish-ahead before it becomes active, stays active for
// the rotation interval and is still published for the retention window
// after its successor takes over. Key generation happens at construction and
// in Run, never on the signing path.
//
// kids have the form <YYYY-MM-DD>-<replica-id>-key-<n>, where the date is the
// UTC generation date and n the number of seconds since UTC midnight, bumped
// if needed so that it strictly increases within the process; kids are thus
// unique across replicas (distinct replica IDs) and across restarts of the
// same replica.
//
// Ephemeral is safe for concurrent use.
type Ephemeral struct {
	replicaID    string
	algorithm    string
	rotation     time.Duration
	publishAhead time.Duration
	retention    time.Duration
	now          func() time.Time

	mu sync.RWMutex
	// keys is ordered by activation time; the last one is either active or
	// pending, earlier ones are active (at most one) or retired.
	keys []*ephemeralKey
	// lastDate and lastN are the date and sequence of the latest kid.
	lastDate string
	lastN    int
}

var _ KeyStore = (*Ephemeral)(nil)

// Option configures an Ephemeral key store.
type Option func(*Ephemeral)

// WithClock sets the source of the current time (default: time.Now).
func WithClock(now func() time.Time) Option {
	return func(e *Ephemeral) { e.now = now }
}

// WithRotationInterval sets how long each key stays active (default: 24h).
func WithRotationInterval(d time.Duration) Option {
	return func(e *Ephemeral) { e.rotation = d }
}

// WithPublishAhead sets how long each key is published before it becomes
// active; it must be shorter than the rotation interval (default: 2m).
func WithPublishAhead(d time.Duration) Option {
	return func(e *Ephemeral) { e.publishAhead = d }
}

// WithRetention sets how long a retired key is still published; it must
// cover the lifetime of the tokens it signed (default: iid.TTL).
func WithRetention(d time.Duration) Option {
	return func(e *Ephemeral) { e.retention = d }
}

// NewEphemeral creates an in-memory key store for the given replica and
// algorithm (RS256 or ES256; empty means iid.Algorithm) and generates its
// first key, which becomes active once it has been published for the
// publish-ahead period.
func NewEphemeral(ctx context.Context, replicaID, algorithm string, options ...Option) (*Ephemeral, error) {
	if algorithm == "" {
		algorithm = iid.Algorithm
	}
	e := &Ephemeral{
		replicaID:    replicaID,
		algorithm:    algorithm,
		rotation:     24 * time.Hour,
		publishAhead: 2 * time.Minute,
		retention:    iid.TTL,
		now:          time.Now,
	}
	for _, option := range options {
		option(e)
	}
	if err := iid.ValidateReplicaID(e.replicaID); err != nil {
		return nil, err
	}
	if e.algorithm != "RS256" && e.algorithm != "ES256" {
		return nil, fmt.Errorf("unsupported signing algorithm %q (want RS256 or ES256)", e.algorithm)
	}
	if e.rotation <= 0 {
		return nil, fmt.Errorf("rotation interval %v must be positive", e.rotation)
	}
	if e.publishAhead <= 0 || e.publishAhead >= e.rotation {
		return nil, fmt.Errorf("publish-ahead period %v must be positive and shorter than the rotation interval %v", e.publishAhead, e.rotation)
	}
	if e.retention <= 0 {
		return nil, fmt.Errorf("retention %v must be positive", e.retention)
	}
	if err := e.addKey(ctx); err != nil {
		return nil, fmt.Errorf("creating ephemeral key store: %w", err)
	}
	return e, nil
}

// Active implements KeyStore.
func (e *Ephemeral) Active(ctx context.Context) (KeyInfo, error) {
	if err := ctx.Err(); err != nil {
		return KeyInfo{}, err
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := e.now()
	i := e.activeIndex(now)
	if i < 0 {
		return KeyInfo{}, fmt.Errorf("%w: first key %q activates at %s", ErrNoActiveKey, e.keys[0].id, e.keys[0].activatesAt.Format(time.RFC3339))
	}
	return KeyInfo{ID: e.keys[i].id, Algorithm: e.keys[i].algorithm}, nil
}

// Sign implements KeyStore.
func (e *Ephemeral) Sign(ctx context.Context, kid string, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("signing with key %q: digest is %d bytes, want a %d-byte SHA-256 digest", kid, len(digest), sha256.Size)
	}
	e.mu.RLock()
	var key *ephemeralKey
	if i := e.activeIndex(e.now()); i >= 0 && e.keys[i].id == kid {
		key = e.keys[i]
	}
	e.mu.RUnlock()
	if key == nil {
		return nil, fmt.Errorf("signing with key %q: %w", kid, ErrKeyNotActive)
	}

	switch k := key.signer.(type) {
	case *rsa.PrivateKey:
		signature, err := rsa.SignPKCS1v15(nil, k, crypto.SHA256, digest)
		if err != nil {
			return nil, fmt.Errorf("signing with key %q: %w", kid, err)
		}
		return signature, nil
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			return nil, fmt.Errorf("signing with key %q: %w", kid, err)
		}
		// JWS (RFC 7518, section 3.4) wants R and S as fixed-size
		// big-endian integers, not ASN.1
		signature := make([]byte, 64)
		r.FillBytes(signature[:32])
		s.FillBytes(signature[32:])
		return signature, nil
	default:
		return nil, fmt.Errorf("signing with key %q: unsupported key type %T", kid, k)
	}
}

// PublicKeys implements KeyStore.
func (e *Ephemeral) PublicKeys(ctx context.Context) ([]PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := e.now()
	var keys []PublicKey
	for i, k := range e.keys {
		if e.expired(i, now) {
			continue
		}
		keys = append(keys, PublicKey{ID: k.id, Algorithm: k.algorithm, Key: k.signer.Public()})
	}
	return keys, nil
}

// Check implements KeyStore.
func (e *Ephemeral) Check(ctx context.Context) error {
	_, err := e.Active(ctx)
	return err
}

// Run performs key maintenance until the context is cancelled: it generates
// each next key publish-ahead before the active one is due to rotate and
// purges retired keys once their retention window has passed. It returns nil
// when the context is cancelled.
func (e *Ephemeral) Run(ctx context.Context) error {
	for {
		sleep := retryDelay
		next, err := e.maintain(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "key maintenance failed, retrying", "replica_id", e.replicaID, "retry_in", retryDelay, "error", err)
		} else {
			sleep = min(max(next.Sub(e.now()), 0), maxSleep)
		}
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// maintain purges the keys whose retention window has passed, generates the
// next key if it is due and returns the time at which it needs to run again.
func (e *Ephemeral) maintain(ctx context.Context) (time.Time, error) {
	now := e.now()

	e.mu.Lock()
	purged := 0
	for purged < len(e.keys) && e.expired(purged, now) {
		slog.InfoContext(ctx, "retired signing key purged", "replica_id", e.replicaID, "kid", e.keys[purged].id)
		purged++
	}
	e.keys = slices.Delete(e.keys, 0, purged)
	last := e.keys[len(e.keys)-1]
	due := !last.activatesAt.After(now) && !now.Before(e.generationDue(last))
	e.mu.Unlock()

	if due {
		// only maintain adds keys, and it is not run concurrently, so the
		// decision still holds once the (slow) generation is done
		if err := e.addKey(ctx); err != nil {
			return time.Time{}, fmt.Errorf("rotating signing key: %w", err)
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	last = e.keys[len(e.keys)-1]
	next := e.generationDue(last)
	if last.activatesAt.After(now) {
		// wake up when the pending key activates, to schedule what follows
		next = last.activatesAt
	}
	if len(e.keys) > 1 {
		// the oldest key is retired, or will be once its successor activates
		if purge := e.keys[1].activatesAt.Add(e.retention); purge.Before(next) {
			next = purge
		}
	}
	return next, nil
}

// addKey generates a new key pair and publishes it, to become active after
// the publish-ahead period.
func (e *Ephemeral) addKey(ctx context.Context) error {
	var (
		signer crypto.Signer
		err    error
	)
	switch e.algorithm {
	case "RS256":
		signer, err = rsa.GenerateKey(rand.Reader, rsaKeyBits)
	case "ES256":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return fmt.Errorf("generating %s key: %w", e.algorithm, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	key := &ephemeralKey{
		id:          e.newKeyID(now),
		algorithm:   e.algorithm,
		signer:      signer,
		publishedAt: now,
		activatesAt: now.Add(e.publishAhead),
	}
	e.keys = append(e.keys, key)
	slog.InfoContext(ctx, "signing key published", "replica_id", e.replicaID, "kid", key.id, "algorithm", key.algorithm, "activates_at", key.activatesAt)
	return nil
}

// newKeyID returns the kid for a key generated at t; callers must hold the
// write lock (or own e exclusively).
func (e *Ephemeral) newKeyID(t time.Time) string {
	t = t.UTC()
	date := t.Format(time.DateOnly)
	n := t.Hour()*3600 + t.Minute()*60 + t.Second()
	if date == e.lastDate && n <= e.lastN {
		n = e.lastN + 1
	}
	e.lastDate, e.lastN = date, n
	return fmt.Sprintf("%s-%s-key-%d", date, e.replicaID, n)
}

// activeIndex returns the index of the key active at now, or -1 if none is;
// callers must hold the lock.
func (e *Ephemeral) activeIndex(now time.Time) int {
	for i := len(e.keys) - 1; i >= 0; i-- {
		if !e.keys[i].activatesAt.After(now) {
			return i
		}
	}
	return -1
}

// expired reports whether the i-th key was retired longer than the retention
// window before now; callers must hold the lock.
func (e *Ephemeral) expired(i int, now time.Time) bool {
	// the key is retired when its successor activates
	return i+1 < len(e.keys) && !now.Before(e.keys[i+1].activatesAt.Add(e.retention))
}

// generationDue returns when the successor of the given key must be
// generated, so that it has been published for the publish-ahead period when
// the key is due to rotate.
func (e *Ephemeral) generationDue(key *ephemeralKey) time.Time {
	return key.activatesAt.Add(e.rotation - e.publishAhead)
}
