package openstackiid

import (
	"testing"
	"time"
)

func TestReattestTracker(t *testing.T) {
	r := newReattestTracker(3)
	now := testNow
	if _, _, seen := r.record("i-1", "jti-1", now); seen {
		t.Fatal("a first attestation reported as a re-attestation")
	}
	previous, interval, seen := r.record("i-1", "jti-2", now.Add(90*time.Second))
	if !seen || previous != "jti-1" || interval != 90*time.Second {
		t.Fatalf("second attestation: %q, %v, %v; want jti-1 after 90s", previous, interval, seen)
	}
	// bounded: the oldest instance is forgotten first
	r.record("i-2", "jti-3", now.Add(2*time.Minute))
	r.record("i-3", "jti-4", now.Add(3*time.Minute))
	r.record("i-4", "jti-5", now.Add(4*time.Minute))
	if n := r.len(); n != 3 {
		t.Fatalf("tracker holds %d instances, want at most 3", n)
	}
	if _, _, seen := r.record("i-1", "jti-6", now.Add(5*time.Minute)); seen {
		t.Error("the least recently attested instance (i-1) was not evicted first")
	}
	if _, _, seen := r.record("i-4", "jti-7", now.Add(6*time.Minute)); !seen {
		t.Error("a recent instance was forgotten")
	}
}
