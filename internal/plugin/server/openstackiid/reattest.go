package openstackiid

import (
	"container/list"
	"sync"
	"time"
)

// maxTrackedInstances bounds the re-attestation tracker.
const maxTrackedInstances = 100_000

// reattestTracker remembers the last successful attestation of each
// instance, to detect a second presenter of an instance's tokens (S-4,
// E-1): a running SPIRE Agent re-attests only near its SVID's expiry, and a
// restarted one reuses its persisted SVID, so a quick second attestation
// means an agent that lost its state, or someone else with the instance's
// token. Like the replay cache, it belongs to the process: a new Configure
// keeps it, and a restart loses it. It is bounded, the least recently
// attested instance forgotten first, and safe for concurrent use.
type reattestTracker struct {
	max int

	mu    sync.Mutex
	order *list.List // of *attestation, least recent first
	byID  map[string]*list.Element
}

type attestation struct {
	instance, jti string
	at            time.Time
}

func newReattestTracker(max int) *reattestTracker {
	return &reattestTracker{max: max, order: list.New(), byID: map[string]*list.Element{}}
}

// record notes an attestation of instance with the token jti at now, and
// returns the previous one's jti and how long ago it was, if any.
func (r *reattestTracker) record(instance, jti string, now time.Time) (previous string, interval time.Duration, seen bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.byID[instance]; ok {
		a := e.Value.(*attestation)
		previous, interval, seen = a.jti, now.Sub(a.at), true
		a.jti, a.at = jti, now
		r.order.MoveToBack(e)
		return previous, interval, seen
	}
	if r.order.Len() >= r.max {
		oldest := r.order.Front()
		delete(r.byID, oldest.Value.(*attestation).instance)
		r.order.Remove(oldest)
	}
	r.byID[instance] = r.order.PushBack(&attestation{instance: instance, jti: jti, at: now})
	return "", 0, false
}

func (r *reattestTracker) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.order.Len()
}
