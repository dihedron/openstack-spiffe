//go:build lab

package main

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// RunOptions are the options of "stress run" (lab.sh stress), as the spec's
// command line table defines them.
type RunOptions struct {
	Duration     time.Duration `long:"duration" default:"1h" description:"how long new cycles keep starting"`
	Cycles       int           `long:"cycles" description:"stop after this many cycles have started"`
	Parallel     string        `long:"parallel" default:"auto" description:"cycles running at once: a number, or auto"`
	MaxParallel  int           `long:"max-parallel" default:"8" description:"upper bound for --parallel auto"`
	Mix          string        `long:"mix" default:"create=3,restart=1" description:"relative weights of the cycle kinds"`
	Distros      string        `long:"distros" default:"ubuntu,rhel" description:"guest images to use, alternated"`
	Hold         string        `long:"hold" default:"0s-2m" description:"how long an instance stays up after its checks: D or MIN-MAX"`
	Bound        string        `long:"bound" description:"time bounds of cycle steps: STEP=D,..."`
	Rotation     time.Duration `long:"rotation" description:"the issuers' rotation_interval for the run (at least 5m)"`
	AgentTTL     time.Duration `long:"agent-ttl" description:"SPIRE Server's agent_ttl for the run (at least 15m)"`
	TOFU         bool          `long:"tofu" description:"run with the server plugin's reattest = false"`
	Chaos        bool          `long:"chaos" description:"inject faults that must cause no failure"`
	SelfTest     bool          `long:"self-test" description:"inject faults that must be detected, and check that they are"`
	KeepFailed   int           `long:"keep-failed" default:"3" description:"failed instances kept for inspection"`
	MaxInfraRate string        `long:"max-infra-rate" default:"5%" description:"share of cycles with infra failures above which the run fails"`
	NoDeploy     bool          `long:"no-deploy" description:"skip the build and lab.sh deploy"`
	NoReset      bool          `long:"no-reset" description:"skip lab.sh reset"`
	Out          string        `long:"out" description:"directory of the run's records and report"`
	Seed         string        `long:"seed" description:"seed of the cycle choices (default: random)"`
	StateDir     string        `long:"state-dir" env:"LAB_STATE_DIR" description:"the lab's state directory"`
	LabDir       string        `long:"lab-dir" env:"LAB_DIR" description:"the lab's directory (test/lab)"`
}

// Kind is a cycle kind.
type Kind string

const (
	KindCreate  Kind = "create"
	KindRestart Kind = "restart"
)

// Step names, as --bound takes them.
const (
	StepBoot   = "boot"
	StepAttest = "attest"
	StepSVID   = "svid"
	StepStop   = "stop"
	StepStart  = "start"
	StepBack   = "back"
	StepDelete = "delete"
)

// DefaultBounds are the steps' time bounds (spec, cycles).
var DefaultBounds = map[string]time.Duration{
	StepBoot:   5 * time.Minute,
	StepAttest: 5 * time.Minute,
	StepSVID:   60 * time.Second,
	StepStop:   2 * time.Minute,
	StepStart:  3 * time.Minute,
	StepBack:   3 * time.Minute,
	StepDelete: 2 * time.Minute,
}

// Weight is a cycle kind's weight in the mix.
type Weight struct {
	Kind   Kind
	Weight int
}

// Config is RunOptions validated and parsed.
type Config struct {
	RunOptions
	Auto         bool // --parallel auto
	Fixed        int  // --parallel N
	Mix          []Weight
	Distros      []string
	HoldMin      time.Duration
	HoldMax      time.Duration
	Bounds       map[string]time.Duration
	MaxInfraRate float64
	Seed         uint64
}

// Validate checks the options and parses them; every problem is reported.
func (o RunOptions) Validate(randomSeed func() uint64) (*Config, error) {
	c := &Config{RunOptions: o}
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if o.Duration <= 0 {
		fail("--duration must be positive, not %v", o.Duration)
	}
	if o.Cycles < 0 {
		fail("--cycles must not be negative")
	}
	if o.Parallel == "auto" {
		c.Auto = true
	} else if n, err := strconv.Atoi(o.Parallel); err != nil || n < 1 {
		fail("--parallel must be auto or a positive number, not %q", o.Parallel)
	} else {
		c.Fixed = n
	}
	if o.MaxParallel < 1 {
		fail("--max-parallel must be positive")
	}
	var err error
	if c.Mix, err = parseMix(o.Mix); err != nil {
		errs = append(errs, err)
	}
	if c.Distros, err = parseDistros(o.Distros); err != nil {
		errs = append(errs, err)
	}
	if c.HoldMin, c.HoldMax, err = parseHold(o.Hold); err != nil {
		errs = append(errs, err)
	}
	if c.Bounds, err = parseBounds(o.Bound); err != nil {
		errs = append(errs, err)
	}
	if o.Rotation != 0 && o.Rotation < 5*time.Minute {
		fail("--rotation must be at least 5m, not %v", o.Rotation)
	}
	if o.AgentTTL != 0 && o.AgentTTL < 15*time.Minute {
		fail("--agent-ttl must be at least 15m (twice the server plugin's reattest_alert_window, with a margin), not %v", o.AgentTTL)
	}
	if o.KeepFailed < 0 {
		fail("--keep-failed must not be negative")
	}
	if c.MaxInfraRate, err = parseRate(o.MaxInfraRate); err != nil {
		errs = append(errs, err)
	}
	if o.Seed == "" {
		c.Seed = randomSeed()
	} else if c.Seed, err = strconv.ParseUint(o.Seed, 10, 64); err != nil {
		fail("--seed must be a non-negative integer, not %q", o.Seed)
	}
	if o.StateDir == "" {
		fail("no lab state directory: run through lab.sh stress, or set --state-dir")
	}
	if o.LabDir == "" && (!o.NoReset || !o.NoDeploy) {
		fail("no lab directory to run lab.sh reset and deploy: run through lab.sh stress, or set --lab-dir")
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// parseMix parses "create=3,restart=1".
func parseMix(s string) ([]Weight, error) {
	var mix []Weight
	total := 0
	seen := map[Kind]bool{}
	for _, part := range strings.Split(s, ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		kind := Kind(name)
		if !ok || (kind != KindCreate && kind != KindRestart) {
			return nil, fmt.Errorf("--mix: %q is not create=W or restart=W", part)
		}
		if seen[kind] {
			return nil, fmt.Errorf("--mix: %s given twice", kind)
		}
		seen[kind] = true
		w, err := strconv.Atoi(value)
		if err != nil || w < 0 {
			return nil, fmt.Errorf("--mix: the weight of %s must be a non-negative number, not %q", kind, value)
		}
		total += w
		mix = append(mix, Weight{kind, w})
	}
	if total == 0 {
		return nil, errors.New("--mix: at least one weight must be positive")
	}
	return mix, nil
}

func parseDistros(s string) ([]string, error) {
	var distros []string
	for _, d := range strings.Split(s, ",") {
		d = strings.TrimSpace(d)
		if d != "ubuntu" && d != "rhel" {
			return nil, fmt.Errorf("--distros: %q is neither ubuntu nor rhel", d)
		}
		if !slices.Contains(distros, d) {
			distros = append(distros, d)
		}
	}
	return distros, nil
}

// parseHold parses a duration or a MIN-MAX range of durations.
func parseHold(s string) (time.Duration, time.Duration, error) {
	low, high, isRange := strings.Cut(s, "-")
	minimum, err := time.ParseDuration(strings.TrimSpace(low))
	if err != nil || minimum < 0 {
		return 0, 0, fmt.Errorf("--hold: %q is not a duration or a MIN-MAX range", s)
	}
	if !isRange {
		return minimum, minimum, nil
	}
	maximum, err := time.ParseDuration(strings.TrimSpace(high))
	if err != nil || maximum < minimum {
		return 0, 0, fmt.Errorf("--hold: %q is not a MIN-MAX range with MIN at most MAX", s)
	}
	return minimum, maximum, nil
}

// parseBounds overrides DefaultBounds with "STEP=D,...".
func parseBounds(s string) (map[string]time.Duration, error) {
	bounds := map[string]time.Duration{}
	for step, d := range DefaultBounds {
		bounds[step] = d
	}
	if strings.TrimSpace(s) == "" {
		return bounds, nil
	}
	for _, part := range strings.Split(s, ",") {
		step, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if _, known := DefaultBounds[step]; !ok || !known {
			return nil, fmt.Errorf("--bound: %q is not STEP=D with STEP one of %s", part, strings.Join(stepNames(), ", "))
		}
		d, err := time.ParseDuration(value)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("--bound: the bound of %s must be a positive duration, not %q", step, value)
		}
		bounds[step] = d
	}
	return bounds, nil
}

func stepNames() []string {
	names := make([]string, 0, len(DefaultBounds))
	for step := range DefaultBounds {
		names = append(names, step)
	}
	sort.Strings(names)
	return names
}

// parseRate parses "5%" or "0.05".
func parseRate(s string) (float64, error) {
	value, percent := strings.CutSuffix(strings.TrimSpace(s), "%")
	r, err := strconv.ParseFloat(value, 64)
	if err == nil && percent {
		r /= 100
	}
	if err != nil || r < 0 || r > 1 {
		return 0, fmt.Errorf("--max-infra-rate: %q is not a share between 0%% and 100%%", s)
	}
	return r, nil
}
