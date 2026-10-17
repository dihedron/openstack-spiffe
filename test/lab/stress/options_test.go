//go:build lab

package main

import (
	"strings"
	"testing"
	"time"
)

func defaults() RunOptions {
	return RunOptions{
		Duration: time.Hour, Parallel: "auto", MaxParallel: 8, Mix: "create=3,restart=1",
		Distros: "ubuntu,rhel", Hold: "0s-2m", KeepFailed: 3, MaxInfraRate: "5%",
		StateDir: "/state", LabDir: "/lab",
	}
}

func TestValidateDefaults(t *testing.T) {
	c, err := defaults().Validate(func() uint64 { return 42 })
	if err != nil {
		t.Fatal(err)
	}
	if !c.Auto || c.Seed != 42 || c.MaxInfraRate != 0.05 || c.HoldMin != 0 || c.HoldMax != 2*time.Minute {
		t.Errorf("unexpected config %+v", c)
	}
	if len(c.Mix) != 2 || c.Mix[0] != (Weight{KindCreate, 3}) || c.Mix[1] != (Weight{KindRestart, 1}) {
		t.Errorf("mix %v", c.Mix)
	}
	for step, d := range DefaultBounds {
		if c.Bounds[step] != d {
			t.Errorf("bound of %s is %v, want the default %v", step, c.Bounds[step], d)
		}
	}
}

func TestBoundOverridesOnlyNamedSteps(t *testing.T) {
	o := defaults()
	o.Bound = "attest=8m, svid=2m"
	c, err := o.Validate(func() uint64 { return 1 })
	if err != nil {
		t.Fatal(err)
	}
	if c.Bounds[StepAttest] != 8*time.Minute || c.Bounds[StepSVID] != 2*time.Minute {
		t.Errorf("overrides not applied: %v", c.Bounds)
	}
	if c.Bounds[StepBoot] != DefaultBounds[StepBoot] || c.Bounds[StepDelete] != DefaultBounds[StepDelete] {
		t.Errorf("steps not named were changed: %v", c.Bounds)
	}
	if DefaultBounds[StepAttest] != 5*time.Minute {
		t.Error("the defaults were modified")
	}
}

func TestValidateRefuses(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*RunOptions)
		want string
	}{
		"unknown step":      {func(o *RunOptions) { o.Bound = "reboot=1m" }, "--bound"},
		"zero bound":        {func(o *RunOptions) { o.Bound = "svid=0s" }, "positive duration"},
		"negative bound":    {func(o *RunOptions) { o.Bound = "svid=-1m" }, "positive duration"},
		"malformed bound":   {func(o *RunOptions) { o.Bound = "svid" }, "--bound"},
		"short agent ttl":   {func(o *RunOptions) { o.AgentTTL = 10 * time.Minute }, "--agent-ttl"},
		"short rotation":    {func(o *RunOptions) { o.Rotation = time.Minute }, "--rotation"},
		"parallel":          {func(o *RunOptions) { o.Parallel = "0" }, "--parallel"},
		"mix kind":          {func(o *RunOptions) { o.Mix = "reboot=1" }, "--mix"},
		"mix zero":          {func(o *RunOptions) { o.Mix = "create=0,restart=0" }, "positive"},
		"distro":            {func(o *RunOptions) { o.Distros = "debian" }, "--distros"},
		"hold range":        {func(o *RunOptions) { o.Hold = "2m-1m" }, "--hold"},
		"infra rate":        {func(o *RunOptions) { o.MaxInfraRate = "150%" }, "--max-infra-rate"},
		"seed":              {func(o *RunOptions) { o.Seed = "-3" }, "--seed"},
		"no state":          {func(o *RunOptions) { o.StateDir = "" }, "state directory"},
		"no lab dir to set": {func(o *RunOptions) { o.LabDir = "" }, "lab directory"},
	} {
		t.Run(name, func(t *testing.T) {
			o := defaults()
			tc.edit(&o)
			_, err := o.Validate(func() uint64 { return 1 })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want one mentioning %q", err, tc.want)
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	o := defaults()
	o.Parallel, o.Hold, o.MaxInfraRate, o.Seed = "3", "5m", "0.1", "7"
	o.AgentTTL, o.Rotation = 15*time.Minute, 5*time.Minute
	o.LabDir, o.NoReset, o.NoDeploy = "", true, true
	c, err := o.Validate(func() uint64 { t.Error("random seed drawn"); return 0 })
	if err != nil {
		t.Fatal(err)
	}
	if c.Auto || c.Fixed != 3 || c.HoldMin != 5*time.Minute || c.HoldMax != 5*time.Minute || c.MaxInfraRate != 0.1 || c.Seed != 7 {
		t.Errorf("unexpected config %+v", c)
	}
}
