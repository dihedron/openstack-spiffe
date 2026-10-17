//go:build lab

package main

import (
	"testing"
	"time"
)

func TestChaosSchedule(t *testing.T) {
	for _, duration := range []time.Duration{time.Hour, 2 * time.Hour, 45 * time.Minute} {
		for seed := range uint64(50) {
			faults := chaosSchedule(seed, duration)
			kinds := map[string]bool{}
			for i, f := range faults {
				kinds[f.Fault] = true
				if f.At < chaosMargin || f.At > duration-chaosMargin {
					t.Errorf("%v seed %d: fault at %v, within %v of the start or end", duration, seed, f.At, chaosMargin)
				}
				if i > 0 && f.At-faults[i-1].At < chaosSpacing {
					t.Errorf("%v seed %d: faults %v apart", duration, seed, f.At-faults[i-1].At)
				}
			}
			if duration >= time.Hour && (!kinds[faultRestartIssuerB] || !kinds[faultRestartSpire]) {
				t.Errorf("%v seed %d: not both faults: %+v", duration, seed, faults)
			}
		}
	}
	if len(chaosSchedule(1, 15*time.Minute)) != 0 {
		t.Error("faults in a run too short for the margins")
	}
	a, b := chaosSchedule(7, time.Hour), chaosSchedule(7, time.Hour)
	if len(a) != len(b) {
		t.Fatal("the same seed gave different schedules")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Error("the same seed gave different schedules")
		}
	}
}

func TestFaultsExtendBounds(t *testing.T) {
	f := &Faults{}
	start := t0
	deadline := start.Add(5 * time.Minute)
	if got := f.extend(start, deadline, t0.Add(time.Minute)); !got.Equal(deadline) {
		t.Errorf("extended without a fault: %v", got)
	}
	f.windows = []FaultWindow{{Fault: faultRestartSpire, Start: t0.Add(2 * time.Minute), Healthy: t0.Add(3 * time.Minute), End: t0.Add(4 * time.Minute), Downtime: time.Minute}}
	if got := f.extend(start, deadline, t0.Add(6*time.Minute)); !got.Equal(deadline.Add(time.Minute)) {
		t.Errorf("deadline %v, want extended by the downtime", got)
	}
	// a fault still going on extends by the time so far
	f.windows = []FaultWindow{{Fault: faultRestartSpire, Start: t0.Add(4 * time.Minute)}}
	if got := f.extend(start, deadline, t0.Add(5*time.Minute)); !got.Equal(deadline.Add(time.Minute)) {
		t.Errorf("deadline %v, want extended by the ongoing fault's minute", got)
	}
	// the self-test's faults must cause failures: no extension
	f.windows = []FaultWindow{{Fault: faultStopIssuerA, Start: t0.Add(time.Minute), Healthy: t0.Add(4 * time.Minute), End: t0.Add(5 * time.Minute), Downtime: 3 * time.Minute, Expected: true}}
	if got := f.extend(start, deadline, t0.Add(6*time.Minute)); !got.Equal(deadline) {
		t.Errorf("extended for an expected fault: %v", got)
	}
	// a fault before the step does not extend it
	f.windows = []FaultWindow{{Fault: faultRestartSpire, Start: t0.Add(-10 * time.Minute), Healthy: t0.Add(-9 * time.Minute), End: t0.Add(-8 * time.Minute), Downtime: time.Minute}}
	if got := f.extend(start, deadline, t0.Add(6*time.Minute)); !got.Equal(deadline) {
		t.Errorf("extended for an earlier fault: %v", got)
	}
}

func TestTransientAllowance(t *testing.T) {
	f := &Faults{}
	start, end := t0, t0.Add(10*time.Minute)
	if got := f.transientAllowance(start, end); got != 1 {
		t.Errorf("allowance %d without a fault, want 1 (the freshness bound)", got)
	}
	f.windows = []FaultWindow{{Fault: faultRestartSpire, Start: t0.Add(2 * time.Minute), End: t0.Add(4 * time.Minute)}}
	if got := f.transientAllowance(start, end); got != 2 {
		t.Errorf("allowance %d with a SPIRE Server restart, want 2", got)
	}
	f.windows = []FaultWindow{{Fault: faultRestartIssuerB, Start: t0.Add(2 * time.Minute), End: t0.Add(4 * time.Minute)}}
	if got := f.transientAllowance(start, end); got != 1 {
		t.Errorf("allowance %d with an issuer-b restart, want 1", got)
	}
}
