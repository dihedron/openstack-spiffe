//go:build lab

package main

import (
	"strings"
	"testing"
	"time"
)

func TestStats(t *testing.T) {
	var ds []time.Duration
	for i := 1; i <= 100; i++ {
		ds = append(ds, time.Duration(i)*time.Second)
	}
	s := stats(ds)
	if s.N != 100 || s.Min != time.Second || s.Max != 100*time.Second || s.P50 != 50*time.Second || s.P95 != 95*time.Second || s.P99 != 99*time.Second {
		t.Errorf("stats %+v", s)
	}
	if empty := stats(nil); empty.N != 0 {
		t.Errorf("stats of nothing %+v", empty)
	}
}

func TestDrift(t *testing.T) {
	var flat, growing []Sample
	for i := range 120 {
		at := t0.Add(time.Duration(i) * time.Minute)
		flat = append(flat, Sample{Time: at, RSS: map[string]int64{"issuer-a/openstack-spire-issuer": 50000 + int64(i%3)}})
		// +20% per hour of the starting value
		growing = append(growing, Sample{Time: at, RSS: map[string]int64{"spire/spire-server": 100000 + int64(i)*20000/60}})
	}
	if w := drift(flat); len(w) != 0 {
		t.Errorf("drift warnings on flat memory: %v", w)
	}
	w := drift(growing)
	if len(w) != 1 || !strings.Contains(w[0], "spire/spire-server") {
		t.Errorf("drift warnings %v, want one for spire-server", w)
	}
	if w := drift(growing[:4]); len(w) != 0 {
		t.Errorf("drift warnings from 4 samples: %v", w)
	}
}

func TestBuildReport(t *testing.T) {
	cycles := []CycleResult{
		{ID: "c1", Kind: KindCreate, Distro: "ubuntu", Outcome: outcomePassed, Steps: []StepResult{{Step: StepBoot, Duration: 30 * time.Second, OK: true}, {Step: StepAttest, Duration: time.Minute, OK: true}}},
		{ID: "c2", Kind: KindRestart, Distro: "rhel", Outcome: outcomeFailed, Reattested: true, Steps: []StepResult{{Step: StepBoot, Duration: 40 * time.Second, OK: true}, {Step: StepAttest, Duration: 5 * time.Minute, OK: false}}},
		{ID: "c3", Kind: KindCreate, Distro: "rhel", Outcome: outcomeAborted, Kept: true, Name: "stress-x-c3-rhel"},
	}
	failures := []Failure{{Class: ClassNode, Cycle: "c2", Reason: "not attested"}, {Class: ClassHarness, Reason: "ssh dropped"}}
	r := buildReport(ReportInputs{Cycles: cycles, Failures: failures, Bounds: DefaultBounds, MaxInfraRate: 0.05,
		Serials: []SerialChange{{AgentID: "a1"}, {AgentID: "a2"}}})
	if r.Cycles.Started != 3 || r.Cycles.Passed != 1 || r.Cycles.Failed != 1 || r.Cycles.Aborted != 1 {
		t.Errorf("counts %+v", r.Cycles)
	}
	if r.Status != 1 || r.Failures[0].Class != ClassHarness {
		t.Errorf("status %d, failures %+v: want 1 with the harness failure first", r.Status, r.Failures)
	}
	if r.Latency[StepBoot].N != 2 || r.Latency[StepAttest].N != 1 {
		t.Errorf("latency counts only passed steps: %+v", r.Latency)
	}
	if r.Reattestations != 1 || r.Renewals != 1 {
		t.Errorf("renewals %d, re-attestations %d; want 1 and 1", r.Renewals, r.Reattestations)
	}
	text := r.Text()
	for _, want := range []string{"FAIL", "ssh dropped", "not attested", "stress-x-c3-rhel", "attest"} {
		if !strings.Contains(text, want) {
			t.Errorf("the report lacks %q:\n%s", want, text)
		}
	}
}
