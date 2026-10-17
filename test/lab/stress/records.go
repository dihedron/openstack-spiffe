//go:build lab

package main

import "time"

// Class is a failure's class (spec, detection).
type Class string

const (
	ClassNode      Class = "node"
	ClassWorkload  Class = "workload"
	ClassInvariant Class = "invariant"
	ClassInfra     Class = "infra"
	ClassCapacity  Class = "capacity"
	ClassHarness   Class = "harness"
)

// counts reports whether a failure of the class counts against the verdict
// on its own (infra counts only above its rate).
func (c Class) counts() bool {
	return c == ClassNode || c == ClassWorkload || c == ClassInvariant
}

// Failure is a failure record.
type Failure struct {
	Time       time.Time `json:"time"`
	Cycle      string    `json:"cycle,omitempty"`
	InstanceID string    `json:"instance_id,omitempty"`
	Class      Class     `json:"class"`
	Step       string    `json:"step,omitempty"`
	Reason     string    `json:"reason"`
	Security   bool      `json:"security,omitempty"`
	Evidence   string    `json:"evidence,omitempty"`
}

// Cycle outcomes.
const (
	outcomePassed  = "passed"
	outcomeFailed  = "failed"
	outcomeAborted = "aborted"
)

// StepResult is how one step of a cycle went.
type StepResult struct {
	Step     string        `json:"step"`
	Start    time.Time     `json:"start"`
	Duration time.Duration `json:"duration_ns"`
	Bound    time.Duration `json:"bound_ns"`
	OK       bool          `json:"ok"`
}

// CycleResult is a cycle's record.
type CycleResult struct {
	ID         string        `json:"cycle"`
	Kind       Kind          `json:"kind"`
	Distro     string        `json:"distro"`
	Name       string        `json:"name"`
	InstanceID string        `json:"instance_id,omitempty"`
	AgentID    string        `json:"agent_id,omitempty"`
	Hold       time.Duration `json:"hold_ns"`
	Started    time.Time     `json:"started"`
	Ended      time.Time     `json:"ended"`
	Outcome    string        `json:"outcome"`
	Steps      []StepResult  `json:"steps"`
	Failure    *Failure      `json:"failure,omitempty"`
	// restart cycles: the SVID expired while the instance was stopped, and
	// whether the agent attested again
	SVIDExpiredWhileStopped bool `json:"svid_expired_while_stopped,omitempty"`
	Reattested              bool `json:"reattested,omitempty"`
	// TOFU restart cycles: SPIRE Server refused the expired agent, as it must
	ExpectedRefusal bool `json:"expected_refusal,omitempty"`
	Kept            bool `json:"kept,omitempty"`
}

// FaultWindow is an injected fault, from its start until one minute after
// the service is healthy again.
type FaultWindow struct {
	Fault    string        `json:"fault"`
	Start    time.Time     `json:"start"`
	Healthy  time.Time     `json:"healthy"`
	End      time.Time     `json:"end"`
	Downtime time.Duration `json:"downtime_ns"`
	// Expected: the self-test's faults, which must cause failures
	Expected bool   `json:"expected,omitempty"`
	Error    string `json:"error,omitempty"`
}

func (w FaultWindow) contains(t time.Time) bool {
	return !t.Before(w.Start) && (w.End.IsZero() || !t.After(w.End))
}

// SelfTestResult is how the self-test's expectations went.
type SelfTestResult struct {
	Status       int           `json:"status"`
	Verdict      string        `json:"verdict"`
	Expectations []Expectation `json:"expectations"`
}

// Expectation is one of the self-test's expectations.
type Expectation struct {
	Name   string `json:"name"`
	Met    bool   `json:"met"`
	Detail string `json:"detail"`
}
