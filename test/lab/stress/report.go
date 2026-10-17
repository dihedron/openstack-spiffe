//go:build lab

package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

// Sample is what the run samples every minute (spec, records).
type Sample struct {
	Time             time.Time        `json:"time"`
	Target           int              `json:"target"`
	Active           int              `json:"active"`
	Running          int              `json:"running"`
	PlacementFree    int              `json:"placement_free"`
	DevstackAvailMiB int64            `json:"devstack_mem_available_mib"`
	HostAvailMiB     int64            `json:"host_mem_available_mib"`
	HostLoad         float64          `json:"host_load"`
	RSS              map[string]int64 `json:"rss_kib,omitempty"`
}

// Stats summarizes a step's durations.
type Stats struct {
	N                       int
	Min, P50, P95, P99, Max time.Duration
	Bound                   time.Duration
}

func stats(ds []time.Duration) Stats {
	if len(ds) == 0 {
		return Stats{}
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	rank := func(p float64) time.Duration {
		i := int(float64(len(s))*p+0.999999) - 1 // nearest rank
		return s[min(max(i, 0), len(s)-1)]
	}
	return Stats{N: len(s), Min: s[0], P50: rank(0.50), P95: rank(0.95), P99: rank(0.99), Max: s[len(s)-1]}
}

// driftThreshold is the growth per hour, as a share of the starting value,
// above which a process's memory is reported.
const driftThreshold = 0.10

// drift fits the RSS of each process over the last half of the samples,
// and warns of a sustained growth (spec, run-wide checks).
func drift(samples []Sample) []string {
	if len(samples) < 10 {
		return nil
	}
	half := samples[len(samples)/2:]
	series := map[string][][2]float64{}
	first := map[string]float64{}
	for _, s := range samples {
		for k, v := range s.RSS {
			if _, ok := first[k]; !ok && v > 0 {
				first[k] = float64(v)
			}
		}
	}
	for _, s := range half {
		for k, v := range s.RSS {
			series[k] = append(series[k], [2]float64{s.Time.Sub(half[0].Time).Hours(), float64(v)})
		}
	}
	var warnings []string
	for k, points := range series {
		if len(points) < 5 || first[k] == 0 {
			continue
		}
		var sx, sy, sxx, sxy float64
		for _, p := range points {
			sx, sy, sxx, sxy = sx+p[0], sy+p[1], sxx+p[0]*p[0], sxy+p[0]*p[1]
		}
		n := float64(len(points))
		den := n*sxx - sx*sx
		if den == 0 {
			continue
		}
		slope := (n*sxy - sx*sy) / den // KiB per hour
		if share := slope / first[k]; share > driftThreshold {
			warnings = append(warnings, fmt.Sprintf("%s: memory grows by %.0f%% of its starting %d MiB per hour over the last half of the run", k, share*100, int64(first[k])/1024))
		}
	}
	sort.Strings(warnings)
	return warnings
}

// ReportInputs is what the report summarizes.
type ReportInputs struct {
	Run            map[string]any
	Cycles         []CycleResult
	Failures       []Failure
	Bounds         map[string]time.Duration
	MaxInfraRate   float64
	TeardownFailed bool
	Samples        []Sample
	Serials        []SerialChange
	Faults         []FaultWindow
	SelfTest       *SelfTestResult
}

// Report is the run's summary.
type Report struct {
	Run     map[string]any `json:"run"`
	Status  int            `json:"exit_status"`
	Verdict string         `json:"verdict"`
	Cycles  struct {
		Started, Passed, Failed, Aborted int
		ByKind                           map[Kind]map[string]int
		ByDistro                         map[string]map[string]int
	} `json:"cycles"`
	Failures       []Failure                `json:"failures"`
	ByClass        map[Class]int            `json:"failures_by_class"`
	Latency        map[string]Stats         `json:"latency"`
	MaxTarget      int                      `json:"max_parallel_target"`
	MaxActive      int                      `json:"max_active"`
	Renewals       int                      `json:"svid_renewals"`
	Reattestations int                      `json:"reattestations"`
	Faults         []FaultWindow            `json:"faults,omitempty"`
	Drift          []string                 `json:"drift_warnings,omitempty"`
	Kept           []string                 `json:"kept_instances,omitempty"`
	Bounds         map[string]time.Duration `json:"bounds_ns"`
	SelfTest       *SelfTestResult          `json:"self_test,omitempty"`
}

func buildReport(in ReportInputs) Report {
	r := Report{Run: in.Run, Bounds: in.Bounds, Faults: in.Faults, SelfTest: in.SelfTest, ByClass: map[Class]int{}, Latency: map[string]Stats{}}
	r.Cycles.ByKind = map[Kind]map[string]int{}
	r.Cycles.ByDistro = map[string]map[string]int{}
	durations := map[string][]time.Duration{}
	reattested := map[string]bool{}
	for _, c := range in.Cycles {
		r.Cycles.Started++
		switch c.Outcome {
		case outcomePassed:
			r.Cycles.Passed++
		case outcomeFailed:
			r.Cycles.Failed++
		default:
			r.Cycles.Aborted++
		}
		if r.Cycles.ByKind[c.Kind] == nil {
			r.Cycles.ByKind[c.Kind] = map[string]int{}
		}
		r.Cycles.ByKind[c.Kind][c.Outcome]++
		if r.Cycles.ByDistro[c.Distro] == nil {
			r.Cycles.ByDistro[c.Distro] = map[string]int{}
		}
		r.Cycles.ByDistro[c.Distro][c.Outcome]++
		for _, s := range c.Steps {
			if s.OK {
				durations[s.Step] = append(durations[s.Step], s.Duration)
			}
		}
		if c.Reattested {
			r.Reattestations++
			reattested[c.AgentID] = true
		}
		if c.Kept {
			r.Kept = append(r.Kept, c.Name)
		}
	}
	for step, ds := range durations {
		s := stats(ds)
		s.Bound = in.Bounds[step]
		r.Latency[step] = s
	}
	// a serial change without a re-attestation is a renewal
	r.Renewals = len(in.Serials) - r.Reattestations
	if r.Renewals < 0 {
		r.Renewals = 0
	}
	r.Failures = slices.Clone(in.Failures)
	sort.SliceStable(r.Failures, func(i, j int) bool {
		return (r.Failures[i].Class == ClassHarness) && (r.Failures[j].Class != ClassHarness)
	})
	for _, f := range r.Failures {
		r.ByClass[f.Class]++
	}
	for _, s := range in.Samples {
		r.MaxTarget = max(r.MaxTarget, s.Target)
		r.MaxActive = max(r.MaxActive, s.Active)
	}
	r.Drift = drift(in.Samples)
	r.Status, r.Verdict = verdict(in.Cycles, in.Failures, in.MaxInfraRate, in.TeardownFailed)
	if in.SelfTest != nil {
		r.Status, r.Verdict = in.SelfTest.Status, in.SelfTest.Verdict
	}
	return r
}

var stepOrder = []string{StepBoot, StepAttest, StepSVID, StepStop, StepStart, StepBack, StepDelete}

// Text is the report as report.txt and the console show it.
func (r Report) Text() string {
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	p("Stress test report")
	p("==================")
	for _, k := range []string{"run_id", "commit", "started", "ended", "options", "seed"} {
		if v, ok := r.Run[k]; ok {
			p("%-9s %v", k+":", v)
		}
	}
	p("")
	p("Verdict: %s (exit status %d)", r.Verdict, r.Status)
	p("")
	p("Cycles: %d started, %d passed, %d failed, %d aborted", r.Cycles.Started, r.Cycles.Passed, r.Cycles.Failed, r.Cycles.Aborted)
	for _, kind := range []Kind{KindCreate, KindRestart} {
		if m := r.Cycles.ByKind[kind]; m != nil {
			p("  %-8s %3d passed, %3d failed, %3d aborted", kind, m[outcomePassed], m[outcomeFailed], m[outcomeAborted])
		}
	}
	distros := make([]string, 0, len(r.Cycles.ByDistro))
	for d := range r.Cycles.ByDistro {
		distros = append(distros, d)
	}
	sort.Strings(distros)
	for _, d := range distros {
		m := r.Cycles.ByDistro[d]
		p("  %-8s %3d passed, %3d failed, %3d aborted", d, m[outcomePassed], m[outcomeFailed], m[outcomeAborted])
	}
	p("Parallelism: target up to %d, %d cycles at once at most", r.MaxTarget, r.MaxActive)
	p("Agent SVIDs: %d renewed, %d re-attested after a restart", r.Renewals, r.Reattestations)
	p("")
	p("Latency of the passed steps (bound):")
	p("  %-7s %5s %8s %8s %8s %8s %8s %8s", "step", "n", "min", "p50", "p95", "p99", "max", "bound")
	for _, step := range stepOrder {
		s, ok := r.Latency[step]
		if !ok {
			continue
		}
		p("  %-7s %5d %8s %8s %8s %8s %8s %8s", step, s.N, round(s.Min), round(s.P50), round(s.P95), round(s.P99), round(s.Max), round(s.Bound))
	}
	p("")
	if len(r.Failures) == 0 {
		p("Failures: none")
	} else {
		classes := make([]string, 0, len(r.ByClass))
		for c, n := range r.ByClass {
			classes = append(classes, fmt.Sprintf("%s %d", c, n))
		}
		sort.Strings(classes)
		p("Failures: %s", strings.Join(classes, ", "))
		for _, f := range r.Failures {
			where := f.Cycle
			if where == "" {
				where = "run"
			}
			security := ""
			if f.Security {
				security = " [SECURITY]"
			}
			p("  %-6s %-9s %-7s%s %s", where, f.Class, f.Step, security, f.Reason)
		}
	}
	if len(r.Faults) > 0 {
		p("")
		p("Faults injected:")
		for _, w := range r.Faults {
			status := "healthy again after " + round(w.Downtime)
			if w.Error != "" {
				status = "did not heal: " + w.Error
			}
			p("  %s  %-34s %s", w.Start.Format(time.TimeOnly), w.Fault, status)
		}
	}
	if r.SelfTest != nil {
		p("")
		p("Self-test expectations:")
		for _, e := range r.SelfTest.Expectations {
			mark := "ok  "
			if !e.Met {
				mark = "MISS"
			}
			p("  %s %s: %s", mark, e.Name, e.Detail)
		}
	}
	if len(r.Drift) > 0 {
		p("")
		p("Warnings:")
		for _, w := range r.Drift {
			p("  %s", w)
		}
	}
	if len(r.Kept) > 0 {
		p("")
		p("Kept for inspection (lab.sh stress --cleanup deletes them): %s", strings.Join(r.Kept, ", "))
	}
	return b.String()
}

func round(d time.Duration) string {
	if d == 0 {
		return "-"
	}
	return d.Round(time.Second).String()
}
