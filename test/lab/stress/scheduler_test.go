//go:build lab

package main

import (
	"testing"
	"time"
)

func TestCapacityTarget(t *testing.T) {
	const gib = 1024
	for name, tc := range map[string]struct {
		in           Capacity
		want         int
		wantPressure bool
	}{
		"bounded by max": {
			Capacity{Max: 8, PlacementFree: 20, DevstackAvailMiB: 100 * gib, FlavorRAMMiB: 2 * gib, HostAvailMiB: 50 * gib, HostLoad: 1, HostCPUs: 16}, 8, false},
		"bounded by placement": {
			Capacity{Max: 8, Running: 2, PlacementFree: 3, DevstackAvailMiB: 100 * gib, FlavorRAMMiB: 2 * gib, HostAvailMiB: 50 * gib, HostLoad: 1, HostCPUs: 16}, 5, false},
		"bounded by devstack memory, minus 3 GiB": {
			Capacity{Max: 8, Running: 1, PlacementFree: 20, DevstackAvailMiB: 11 * gib, FlavorRAMMiB: 2 * gib, HostAvailMiB: 50 * gib, HostLoad: 1, HostCPUs: 16}, 5, false},
		"unknown inputs ignored": {
			Capacity{Max: 4, PlacementFree: -1, PlacementTotal: -1, DevstackAvailMiB: -1, FlavorRAMMiB: 2 * gib, HostAvailMiB: -1, HostCPUs: 16}, 4, false},
		"bounded by the host's total slots, less the kept failures": {
			Capacity{Max: 8, Running: 3, PlacementFree: 2, PlacementTotal: 4, Kept: 1, DevstackAvailMiB: 100 * gib, FlavorRAMMiB: 2 * gib, HostAvailMiB: 50 * gib, HostCPUs: 16}, 3, false},
		"never below one": {
			Capacity{Max: 8, PlacementFree: 0, DevstackAvailMiB: 1 * gib, FlavorRAMMiB: 2 * gib, HostAvailMiB: 50 * gib, HostCPUs: 16}, 1, false},
		"host memory pressure": {
			Capacity{Max: 8, PlacementFree: 20, DevstackAvailMiB: 100 * gib, FlavorRAMMiB: 2 * gib, HostAvailMiB: 3 * gib, HostCPUs: 16}, 8, true},
		"host load pressure": {
			Capacity{Max: 8, PlacementFree: 20, DevstackAvailMiB: 100 * gib, FlavorRAMMiB: 2 * gib, HostAvailMiB: 50 * gib, HostLoad: 16, HostCPUs: 16}, 8, true},
	} {
		t.Run(name, func(t *testing.T) {
			got, pressure := capacityTarget(tc.in)
			if got != tc.want || pressure != tc.wantPressure {
				t.Errorf("capacityTarget = %d, %v; want %d, %v", got, pressure, tc.want, tc.wantPressure)
			}
		})
	}
}

func TestNextTarget(t *testing.T) {
	for name, tc := range map[string]struct {
		current, desired int
		pressure, first  bool
		want             int
	}{
		"first takes the capacity":         {0, 6, false, true, 6},
		"first under pressure":             {0, 6, true, true, 5},
		"grows by one":                     {2, 6, false, false, 3},
		"shrinks by one":                   {6, 2, false, false, 5},
		"stays":                            {4, 4, false, false, 4},
		"pressure lowers by one":           {4, 6, true, false, 3},
		"pressure never below one":         {1, 6, true, false, 1},
		"first never below one":            {0, 1, true, true, 1},
		"shrinking never skips past floor": {2, 1, false, false, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nextTarget(tc.current, tc.desired, tc.pressure, tc.first); got != tc.want {
				t.Errorf("nextTarget(%d, %d, %v, %v) = %d, want %d", tc.current, tc.desired, tc.pressure, tc.first, got, tc.want)
			}
		})
	}
}

func testConfig(t *testing.T, edit func(*RunOptions)) *Config {
	t.Helper()
	o := defaults()
	if edit != nil {
		edit(&o)
	}
	c, err := o.Validate(func() uint64 { return 99 })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestChooserIsReproducible(t *testing.T) {
	c := testConfig(t, nil)
	a, b := newChooser(c), newChooser(c)
	for i := range 200 {
		pa, pb := a.next(), b.next()
		if pa != pb {
			t.Fatalf("plan %d differs with the same seed: %+v, %+v", i, pa, pb)
		}
		if pa.Hold < c.HoldMin || pa.Hold > c.HoldMax {
			t.Errorf("hold %v outside %v-%v", pa.Hold, c.HoldMin, c.HoldMax)
		}
		if want := c.Distros[i%len(c.Distros)]; pa.Distro != want {
			t.Errorf("plan %d: distro %s, want %s (alternated)", i, pa.Distro, want)
		}
	}
	other := testConfig(t, func(o *RunOptions) { o.Seed = "100" })
	differs := false
	x, y := newChooser(c), newChooser(other)
	for range 50 {
		if x.next() != y.next() {
			differs = true
		}
	}
	if !differs {
		t.Error("two seeds gave the same 50 plans")
	}
}

func TestChooserFollowsTheMix(t *testing.T) {
	only := newChooser(testConfig(t, func(o *RunOptions) { o.Mix = "create=1,restart=0" }))
	for range 100 {
		if p := only.next(); p.Kind != KindCreate {
			t.Fatalf("a restart cycle with a zero weight")
		}
	}
	counts := map[Kind]int{}
	mixed := newChooser(testConfig(t, nil))
	for range 4000 {
		counts[mixed.next().Kind]++
	}
	if r := float64(counts[KindCreate]) / 4000; r < 0.70 || r > 0.80 {
		t.Errorf("create share %.2f, want about 0.75 for create=3,restart=1", r)
	}
}

func TestAdmitNeverExceedsTheTarget(t *testing.T) {
	s := &admission{spacing: 10 * time.Second}
	now := time.Now()
	if !s.admit(0, 2, now) {
		t.Fatal("not admitted below the target")
	}
	if s.admit(1, 2, now.Add(5*time.Second)) {
		t.Error("admitted before the spacing between starts")
	}
	if !s.admit(1, 2, now.Add(11*time.Second)) {
		t.Error("not admitted below the target after the spacing")
	}
	if s.admit(2, 2, now.Add(time.Minute)) {
		t.Error("admitted at the target")
	}
	if s.admit(3, 2, now.Add(2*time.Minute)) {
		t.Error("admitted above the target")
	}
}
