//go:build lab

package main

import (
	"math/rand/v2"
	"time"
)

// Capacity holds the inputs of the parallelism target (spec, parallelism).
// A negative value is unknown and ignored.
type Capacity struct {
	Max              int     // --max-parallel
	Running          int     // the run's instances its cycles hold (not kept, not in ERROR)
	PlacementFree    int     // lab.guest instances Placement can still allocate
	PlacementTotal   int     // lab.guest instances the compute host holds in all
	Kept             int     // failed instances kept for inspection
	DevstackAvailMiB int64   // the devstack VM's MemAvailable
	FlavorRAMMiB     int64   // lab.guest's RAM
	HostAvailMiB     int64   // the lab host's MemAvailable
	HostLoad         float64 // the lab host's 1-minute load average
	HostCPUs         int
}

const (
	devstackMarginMiB = 3 * 1024
	hostMarginMiB     = 4 * 1024
)

// capacityTarget is the number of cycles the lab can hold now, and whether
// the lab host is under pressure (which lowers the target by one).
func capacityTarget(c Capacity) (int, bool) {
	limit := c.Max
	if c.PlacementFree >= 0 {
		limit = min(limit, c.Running+c.PlacementFree)
	}
	// the free slots and the running instances are read a few seconds
	// apart: an instance deleted meanwhile counts in both, but never beyond
	// the host's total
	if c.PlacementTotal > 0 {
		limit = min(limit, c.PlacementTotal-c.Kept)
	}
	if c.DevstackAvailMiB >= 0 && c.FlavorRAMMiB > 0 {
		limit = min(limit, c.Running+int(max(c.DevstackAvailMiB-devstackMarginMiB, 0)/c.FlavorRAMMiB))
	}
	pressure := (c.HostAvailMiB >= 0 && c.HostAvailMiB-hostMarginMiB <= 0) ||
		(c.HostCPUs > 0 && c.HostLoad >= float64(c.HostCPUs))
	return max(limit, 1), pressure
}

// nextTarget moves the target toward the capacity by at most one, except
// for the first computation, which takes it.
func nextTarget(current, desired int, pressure, first bool) int {
	if first {
		if pressure {
			desired--
		}
		return max(desired, 1)
	}
	want := desired
	if pressure {
		want = min(want, current-1)
	}
	switch {
	case want > current:
		current++
	case want < current:
		current--
	}
	return max(current, 1)
}

// admission spaces the cycles' starts, so that a target raised by several
// does not start them all in the same second.
type admission struct {
	spacing time.Duration
	last    time.Time
}

func (a *admission) admit(active, target int, now time.Time) bool {
	if active >= target || (!a.last.IsZero() && now.Sub(a.last) < a.spacing) {
		return false
	}
	a.last = now
	return true
}

// Plan is what the scheduler chose for a cycle.
type Plan struct {
	Kind   Kind
	Distro string
	Hold   time.Duration
}

// chooser draws the cycles' plans from the run's seed: a seed reproduces the
// same sequence.
type chooser struct {
	rng     *rand.Rand
	mix     []Weight
	total   int
	distros []string
	holdMin time.Duration
	holdMax time.Duration
	n       int
}

func newChooser(c *Config) *chooser {
	total := 0
	for _, w := range c.Mix {
		total += w.Weight
	}
	return &chooser{
		rng: rand.New(rand.NewPCG(c.Seed, 0x5354524553535445)), // "STRESSTE"
		mix: c.Mix, total: total, distros: c.Distros, holdMin: c.HoldMin, holdMax: c.HoldMax,
	}
}

func (c *chooser) next() Plan {
	p := Plan{Distro: c.distros[c.n%len(c.distros)], Hold: c.holdMin}
	c.n++
	pick := c.rng.IntN(c.total)
	for _, w := range c.mix {
		if pick < w.Weight {
			p.Kind = w.Kind
			break
		}
		pick -= w.Weight
	}
	if spread := c.holdMax - c.holdMin; spread > 0 {
		p.Hold += time.Duration(c.rng.Int64N(int64(spread) + 1))
	}
	return p
}
