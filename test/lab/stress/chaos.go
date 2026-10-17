//go:build lab

package main

import (
	"math/rand/v2"
	"slices"
	"sync"
	"time"
)

// Faults.
const (
	// chaos: must cause no failure
	faultRestartIssuerB = "restart issuer-b"
	faultRestartSpire   = "restart SPIRE Server"
	// self-test: must be detected
	faultStopIssuerA    = "stop issuer-a"
	faultRemoveWorkload = "remove the workload entry"
	faultSelfTestSpire  = "restart SPIRE Server (self-test)"
	faultWipeTOFUAgent  = "wipe an attested agent (TOFU)"
	// the set-up's restarts of the services it reconfigures
	faultSetUp           = "set up the run"
	chaosMargin          = 10 * time.Minute
	chaosSpacing         = 10 * time.Minute
	chaosSpacingSpread   = 5 * time.Minute
	faultSettleAfterHeal = time.Minute
)

// ScheduledFault is a fault and when it starts, from the run's start.
type ScheduledFault struct {
	Fault string
	At    time.Duration
}

// chaosSchedule draws the chaos faults with the run's seed: at least
// chaosSpacing apart, none within chaosMargin of the start or the end,
// alternating the two faults from a random first one.
func chaosSchedule(seed uint64, duration time.Duration) []ScheduledFault {
	rng := rand.New(rand.NewPCG(seed, 0x4348414f53)) // "CHAOS"
	kinds := []string{faultRestartIssuerB, faultRestartSpire}
	if rng.IntN(2) == 1 {
		slices.Reverse(kinds)
	}
	var faults []ScheduledFault
	at := chaosMargin + time.Duration(rng.Int64N(int64(chaosSpacingSpread)))
	for i := 0; at <= duration-chaosMargin; i++ {
		faults = append(faults, ScheduledFault{Fault: kinds[i%2], At: at})
		at += chaosSpacing + time.Duration(rng.Int64N(int64(chaosSpacingSpread)))
	}
	// short runs: make room for both faults when the window holds two
	if len(faults) == 1 && duration-2*chaosMargin >= chaosSpacing {
		faults = []ScheduledFault{{kinds[0], chaosMargin}, {kinds[1], chaosMargin + chaosSpacing}}
	}
	return faults
}

// Faults holds the run's fault windows; it is safe for concurrent use.
type Faults struct {
	mu      sync.Mutex
	windows []FaultWindow
}

// begin records the start of a fault, and returns its index.
func (f *Faults) begin(fault string, expected bool, now time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.windows = append(f.windows, FaultWindow{Fault: fault, Start: now, Expected: expected})
	return len(f.windows) - 1
}

// healed records that the faulted service is healthy again; the window
// lasts faultSettleAfterHeal more.
func (f *Faults) healed(i int, now time.Time, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := &f.windows[i]
	w.Healthy = now
	w.Downtime = now.Sub(w.Start)
	w.End = now.Add(faultSettleAfterHeal)
	if err != nil {
		w.Error = err.Error()
	}
}

// Windows is a copy of the fault windows.
func (f *Faults) Windows() []FaultWindow {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.windows)
}

// extend is a step's deadline extended by how long the services were down
// during the step (spec, chaos); the self-test's faults extend nothing,
// since they must cause failures.
func (f *Faults) extend(start, deadline, now time.Time) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	extended := deadline
	for _, w := range f.windows {
		if w.Expected || w.Start.Before(start) || w.Start.After(extended) {
			continue
		}
		if w.Healthy.IsZero() {
			extended = extended.Add(now.Sub(w.Start))
		} else {
			extended = extended.Add(w.Downtime)
		}
	}
	return extended
}

// inSpireRestart reports whether a time falls within a SPIRE Server
// restart's window, which lasts past the plugin's clock_skew_tolerance (30s
// by default) after the restart.
func (f *Faults) inSpireRestart(t time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, w := range f.windows {
		if (w.Fault == faultRestartSpire || w.Fault == faultSelfTestSpire) && w.contains(t) {
			return true
		}
	}
	return false
}

// transientAllowance is how many transient rejections ("token already
// used", "token issued before this server started") an agent may get
// between two times: one (the plugins spec's freshness bound), plus one for
// each SPIRE Server restart in between.
func (f *Faults) transientAllowance(start, end time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 1
	for _, w := range f.windows {
		if (w.Fault == faultRestartSpire || w.Fault == faultSelfTestSpire) && !w.Start.After(end) && (w.End.IsZero() || !w.End.Before(start)) {
			n++
		}
	}
	return n
}
