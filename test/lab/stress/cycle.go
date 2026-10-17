//go:build lab

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// LabAPI is what the cycles do to the lab; kitLab implements it on the real
// lab, the unit tests with a fake.
type LabAPI interface {
	Lister
	CreateServer(ctx context.Context, name, distro string) (string, error)
	ServerAction(ctx context.Context, id, action string) error
	ServerFault(ctx context.Context, id string) (string, error)
	EvictAgent(ctx context.Context, agentID string) error
	CheckWorkload(ctx context.Context, s Server, distro string) WorkloadCheck
	GuestState(ctx context.Context, s Server, distro string) GuestState
	ConsoleLog(ctx context.Context, id string) (string, error)
	AgentShow(ctx context.Context, agentID string) (string, error)
}

// WorkloadCheck is the result of the in-guest check (spec, workload
// attestation).
type WorkloadCheck struct {
	Reachable   bool
	Error       string // why the guest could not be checked
	WorkloadID  string // the workload user's SVID, empty if none
	Verified    bool   // its chain verifies against the bundle
	WorkloadErr string
	OutsiderID  string // the outsider's SVID: must stay empty
	OutsiderErr string
}

// GuestState is what a guest says about its agent, for evidence.
type GuestState struct {
	Reachable      bool
	AgentInstalled bool
	AgentActive    bool
	Output         string
}

// Runner runs the cycles.
type Runner struct {
	cfg         *Config
	lab         LabAPI
	obs         *Observer
	ledger      *Ledger
	faults      *Faults
	journals    *Journals
	rec         *Recorder
	log         *slog.Logger
	runID       string
	projectID   string
	trustDomain string
	agentTTL    time.Duration // SPIRE Server's agent_ttl in effect
	pollEvery   time.Duration // the in-guest checks' interval

	mu        sync.Mutex
	kept      int
	evictions map[string][]time.Time
}

// workloadID and the expected selectors.
func (r *Runner) workloadID() string { return "spiffe://" + r.trustDomain + "/stress/workload" }

func (r *Runner) agentID(instance string) string {
	return fmt.Sprintf("spiffe://%s/spire/agent/openstack_iid/%s/%s", r.trustDomain, r.projectID, instance)
}

// cycleState is a cycle under way.
type cycleState struct {
	res    *CycleResult
	server Server
	start  time.Time // of the cycle
}

// stepFailure ends a cycle.
type stepFailure struct {
	class    Class
	step     string
	reason   string
	security bool
	// the attestation evidence was gathered (classified)
	evidence string
}

func (f *stepFailure) Error() string { return f.step + ": " + f.reason }

func fail(class Class, step, format string, args ...any) *stepFailure {
	return &stepFailure{class: class, step: step, reason: fmt.Sprintf(format, args...)}
}

// Cycle runs one cycle to its end; ctx ending aborts it.
func (r *Runner) Cycle(ctx context.Context, id string, plan Plan) CycleResult {
	res := &CycleResult{ID: id, Kind: plan.Kind, Distro: plan.Distro, Hold: plan.Hold, Started: time.Now(),
		Name: fmt.Sprintf("stress-%s-%s-%s", r.runID, id, plan.Distro)}
	c := &cycleState{res: res, start: res.Started}
	log := r.log.With("cycle", id, "kind", plan.Kind, "distro", plan.Distro)
	log.Info("cycle started", "name", res.Name, "hold", plan.Hold.String())

	var err error
	switch plan.Kind {
	case KindRestart:
		err = r.restart(ctx, c, plan)
	default:
		err = r.create(ctx, c, plan)
	}
	cleanup := context.WithoutCancel(ctx)
	var sf *stepFailure
	switch {
	case err == nil:
		res.Outcome = outcomePassed
	case ctx.Err() != nil && !errors.As(err, &sf):
		res.Outcome = outcomeAborted
		log.Warn("cycle aborted", "error", err)
	default:
		if !errors.As(err, &sf) {
			sf = fail(ClassHarness, "", "%v", err)
		}
		res.Outcome = outcomeFailed
		f := Failure{Time: time.Now(), Cycle: id, InstanceID: res.InstanceID, Class: sf.class, Step: sf.step, Reason: sf.reason, Security: sf.security}
		f.Evidence = r.evidence(cleanup, c, f, sf.evidence)
		res.Failure = &f
		r.rec.Failure(f)
	}
	// a passed cycle has already deleted its instance and evicted its agent
	if res.Outcome != outcomePassed && res.InstanceID != "" {
		if res.Outcome == outcomeFailed && res.Failure.Class != ClassCapacity && r.keep() {
			res.Kept = true
			log.Warn("failed instance kept for inspection", "instance_id", res.InstanceID, "name", res.Name)
		} else if err := r.remove(cleanup, c, false); err != nil {
			log.Warn("removing the instance of a failed cycle", "error", err)
		}
	}
	res.Ended = time.Now()
	log.Info("cycle ended", "outcome", res.Outcome, "duration", res.Ended.Sub(res.Started).Round(time.Second).String())
	return *res
}

func (r *Runner) keep() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.kept < r.cfg.KeepFailed {
		r.kept++
		return true
	}
	return false
}

// step runs fn as a named step, records its result and duration.
func (r *Runner) step(c *cycleState, name string, fn func(start time.Time, bound time.Duration) error) error {
	start := time.Now()
	bound := r.cfg.Bounds[name]
	err := fn(start, bound)
	sr := StepResult{Step: name, Start: start, Duration: time.Since(start), Bound: bound, OK: err == nil}
	c.res.Steps = append(c.res.Steps, sr)
	r.rec.Step(c.res, sr, err)
	return err
}

// create is the create cycle (spec, cycles).
func (r *Runner) create(ctx context.Context, c *cycleState, plan Plan) error {
	if err := r.bootAndAttest(ctx, c, plan); err != nil {
		return err
	}
	if err := sleep(ctx, plan.Hold); err != nil {
		return err
	}
	if err := r.step(c, StepSVID, func(start time.Time, bound time.Duration) error {
		return r.waitWorkload(ctx, c, start, bound, StepSVID)
	}); err != nil {
		return err
	}
	if err := r.checkRejections(c); err != nil {
		return err
	}
	return r.remove(ctx, c, true)
}

// bootAndAttest boots the instance and checks its node and workload
// attestation (create, steps 1 to 3).
func (r *Runner) bootAndAttest(ctx context.Context, c *cycleState, plan Plan) error {
	if err := r.step(c, StepBoot, func(start time.Time, bound time.Duration) error {
		id, err := r.lab.CreateServer(ctx, c.res.Name, plan.Distro)
		if err != nil {
			if strings.Contains(err.Error(), "No valid host") {
				return fail(ClassCapacity, StepBoot, "%v", err)
			}
			return fail(ClassInfra, StepBoot, "creating the instance: %v", err)
		}
		c.res.InstanceID, c.res.AgentID = id, r.agentID(id)
		snap, err := r.obs.Wait(ctx, start, bound, start, func(s Snapshot) bool {
			st := s.Servers[id].Status
			return st == "ACTIVE" || st == "ERROR"
		})
		if errors.Is(err, errTimeout) {
			return fail(ClassInfra, StepBoot, "not ACTIVE within %v (status %q)", bound, snap.Servers[id].Status)
		}
		if err != nil {
			return err
		}
		c.server = snap.Servers[id]
		if c.server.Status == "ERROR" {
			fault, ferr := r.lab.ServerFault(context.WithoutCancel(ctx), id)
			if ferr != nil {
				fault = "(no fault: " + ferr.Error() + ")"
			}
			return fail(classifyBoot(fault), StepBoot, "the instance went to ERROR: %s", fault)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := r.step(c, StepAttest, func(start time.Time, bound time.Duration) error {
		snap, err := r.obs.Wait(ctx, start, bound, start, func(s Snapshot) bool {
			_, ok := s.Agents[c.res.AgentID]
			return ok
		})
		if errors.Is(err, errTimeout) {
			return r.attestTimeout(context.WithoutCancel(ctx), c, StepAttest, bound)
		}
		if err != nil {
			return err
		}
		c.server = snap.Servers[c.res.InstanceID]
		a := snap.Agents[c.res.AgentID]
		for _, want := range []string{"openstack_iid:project_id:" + r.projectID, "openstack_iid:instance_id:" + c.res.InstanceID} {
			if !slices.Contains(a.Selectors, want) {
				return fail(ClassNode, StepAttest, "the agent %s lacks the selector %s: %v", a.ID, want, a.Selectors)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return r.step(c, StepSVID, func(start time.Time, bound time.Duration) error {
		return r.waitWorkload(ctx, c, start, bound, StepSVID)
	})
}

// attestTimeout gathers why an agent did not attest, and classes it.
func (r *Runner) attestTimeout(ctx context.Context, c *cycleState, step string, bound time.Duration) error {
	state := r.lab.GuestState(ctx, c.server, c.res.Distro)
	e := AttestEvidence{
		GuestReachable:   state.Reachable,
		AgentInstalled:   state.AgentInstalled,
		TokensIssued:     r.ledger.TokensFor(c.res.InstanceID),
		IssuerProblems:   r.ledger.IssuerProblems(c.res.InstanceID),
		PluginRejections: len(r.ledger.RejectionsSince(c.res.InstanceID, c.start)),
	}
	sf := fail(classifyAttest(e), step, "the agent was not attested within %v (guest reachable %v, agent installed %v, active %v; %d token(s) issued, %d issuer warning(s), %d plugin rejection(s))",
		bound, e.GuestReachable, e.AgentInstalled, state.AgentActive, e.TokensIssued, e.IssuerProblems, e.PluginRejections)
	sf.evidence = state.Output
	return sf
}

// waitWorkload checks, until it passes or its bound, that the workload user
// gets its SVID and the outsider none.
func (r *Runner) waitWorkload(ctx context.Context, c *cycleState, start time.Time, bound time.Duration, step string) error {
	deadline := start.Add(bound)
	var last WorkloadCheck
	for {
		check := r.lab.CheckWorkload(ctx, c.server, c.res.Distro)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		last = check
		if check.OutsiderID != "" {
			sf := fail(ClassWorkload, step, "the outsider user, with no registration entry, got an SVID: %s", check.OutsiderID)
			sf.security = true
			return sf
		}
		if check.WorkloadID != "" {
			if check.WorkloadID != r.workloadID() {
				return fail(ClassWorkload, step, "the workload user got %s, want %s", check.WorkloadID, r.workloadID())
			}
			if !check.Verified {
				return fail(ClassWorkload, step, "the workload SVID %s does not verify against the trust bundle", check.WorkloadID)
			}
			return nil
		}
		now := time.Now()
		if now.After(r.faults.extend(start, deadline, now)) {
			break
		}
		if err := sleep(ctx, r.pollEvery); err != nil {
			return err
		}
	}
	if !last.Reachable {
		return fail(ClassInfra, step, "the guest was not reachable within %v: %s", bound, last.Error)
	}
	return fail(ClassWorkload, step, "the workload user got no SVID within %v: %s", bound, last.WorkloadErr)
}

// checkRejections checks the transient rejections of the cycle's agent
// against the freshness bound.
func (r *Runner) checkRejections(c *cycleState) error {
	now := time.Now()
	n := 0
	for _, rej := range r.ledger.RejectionsSince(c.res.InstanceID, c.start) {
		switch {
		case rej.Kind == rejectBeforeStart && r.faults.inSpireRestart(rej.Time):
			// the startup watermark refuses every attempt for the plugin's
			// clock_skew_tolerance after a restart, by design
		case rej.Kind == rejectAlreadyUsed || rej.Kind == rejectBeforeStart:
			n++
		}
	}
	if allowed := r.faults.transientAllowance(c.start, now); n > allowed {
		return fail(ClassNode, "", "%d transient rejections (token already used, or issued before the server started), at most %d expected", n, allowed)
	}
	return nil
}

// restart is the restart cycle (spec, cycles).
func (r *Runner) restart(ctx context.Context, c *cycleState, plan Plan) error {
	if err := r.bootAndAttest(ctx, c, plan); err != nil {
		return err
	}
	before := r.obs.Snapshot().Agents[c.res.AgentID]
	stopped := time.Now()
	if err := r.step(c, StepStop, func(start time.Time, bound time.Duration) error {
		return r.action(ctx, c, "stop", "SHUTOFF", start, bound)
	}); err != nil {
		return err
	}
	if err := sleep(ctx, plan.Hold); err != nil {
		return err
	}
	if err := r.step(c, StepStart, func(start time.Time, bound time.Duration) error {
		return r.action(ctx, c, "start", "ACTIVE", start, bound)
	}); err != nil {
		return err
	}
	active := time.Now()
	expired := !before.ExpiresAt.IsZero() && before.ExpiresAt.Before(active)
	// an agent past half its SVID's lifetime renews it, by attesting again
	// when it can (plugins spec, re-attestation cadence)
	renewing := !before.ExpiresAt.IsZero() && active.After(before.ExpiresAt.Add(-r.agentTTL/2))
	c.res.SVIDExpiredWhileStopped = expired
	if r.cfg.TOFU && expired {
		return r.step(c, StepBack, func(start time.Time, bound time.Duration) error {
			return r.waitRefusal(ctx, c, start, bound)
		})
	}
	if err := r.step(c, StepBack, func(start time.Time, bound time.Duration) error {
		return r.waitWorkload(ctx, c, start, bound, StepBack)
	}); err != nil {
		return err
	}
	attested := r.ledger.AttestedSince(c.res.InstanceID, stopped)
	switch {
	case len(attested) == 0:
	case r.cfg.TOFU:
		sf := fail(ClassNode, StepBack, "the agent attested again after the restart (jti %s): TOFU must have refused it", attested[0].JTI)
		sf.security = true
		return sf
	case len(attested) == 1 && (expired || renewing):
		c.res.Reattested = true
	case len(attested) == 1:
		return fail(ClassNode, StepBack, "the agent attested again after the restart (jti %s) although its SVID, valid until %s, was not due for renewal", attested[0].JTI, before.ExpiresAt.Format(time.TimeOnly))
	default:
		return fail(ClassNode, StepBack, "the agent attested %d times after the restart", len(attested))
	}
	if err := r.checkRejections(c); err != nil {
		return err
	}
	return r.remove(ctx, c, true)
}

// waitRefusal waits for SPIRE Server to refuse a TOFU agent whose SVID
// expired: the expected outcome.
func (r *Runner) waitRefusal(ctx context.Context, c *cycleState, start time.Time, bound time.Duration) error {
	deadline := start.Add(bound)
	for time.Now().Before(deadline) {
		if len(r.ledger.AttestedSince(c.res.InstanceID, start)) > 0 {
			sf := fail(ClassNode, StepBack, "the agent of an expired SVID attested again: TOFU must have refused it")
			sf.security = true
			return sf
		}
		if len(r.ledger.RejectionsSince(c.res.InstanceID, start)) > 0 || r.ledger.ErrorsSince(c.res.InstanceID, start) > 0 {
			c.res.ExpectedRefusal = true
			return nil
		}
		if err := sleep(ctx, r.pollEvery); err != nil {
			return err
		}
	}
	return fail(ClassNode, StepBack, "SPIRE Server logged no refusal of the expired TOFU agent within %v", bound)
}

// action stops or starts the instance and waits for its status.
func (r *Runner) action(ctx context.Context, c *cycleState, action, status string, start time.Time, bound time.Duration) error {
	if err := r.lab.ServerAction(ctx, c.res.InstanceID, action); err != nil {
		return fail(ClassInfra, action, "%s: %v", action, err)
	}
	snap, err := r.obs.Wait(ctx, start, bound, start, func(s Snapshot) bool {
		st := s.Servers[c.res.InstanceID].Status
		return st == status || st == "ERROR"
	})
	if errors.Is(err, errTimeout) {
		return fail(ClassInfra, action, "not %s within %v (status %q)", status, bound, snap.Servers[c.res.InstanceID].Status)
	}
	if err != nil {
		return err
	}
	c.server = snap.Servers[c.res.InstanceID]
	if c.server.Status == "ERROR" {
		fault, _ := r.lab.ServerFault(context.WithoutCancel(ctx), c.res.InstanceID)
		return fail(ClassInfra, action, "the instance went to ERROR: %s", fault)
	}
	return nil
}

// remove deletes the instance and evicts its agent (create, step 5); as a
// step when asStep, as a failed cycle's cleanup otherwise.
func (r *Runner) remove(ctx context.Context, c *cycleState, asStep bool) error {
	do := func(start time.Time, bound time.Duration) error {
		if err := r.lab.ServerAction(ctx, c.res.InstanceID, "delete"); err != nil {
			return fail(ClassInfra, StepDelete, "delete: %v", err)
		}
		if _, err := r.obs.Wait(ctx, start, bound, start, func(s Snapshot) bool {
			_, alive := s.Servers[c.res.InstanceID]
			return !alive
		}); errors.Is(err, errTimeout) {
			return fail(ClassInfra, StepDelete, "not deleted within %v", bound)
		} else if err != nil {
			return err
		}
		if _, listed := r.obs.Snapshot().Agents[c.res.AgentID]; !listed && !asStep {
			return nil
		}
		evicted := time.Now()
		if err := r.lab.EvictAgent(ctx, c.res.AgentID); err != nil && !strings.Contains(err.Error(), "NotFound") && !strings.Contains(err.Error(), "not found") {
			return fail(ClassHarness, StepDelete, "evicting %s: %v", c.res.AgentID, err)
		}
		r.mu.Lock()
		r.evictions[c.res.AgentID] = append(r.evictions[c.res.AgentID], evicted)
		r.mu.Unlock()
		if _, err := r.obs.Wait(ctx, evicted, time.Minute, evicted, func(s Snapshot) bool {
			_, listed := s.Agents[c.res.AgentID]
			return !listed
		}); errors.Is(err, errTimeout) {
			return fail(ClassNode, StepDelete, "the agent %s is still attested a minute after its eviction", c.res.AgentID)
		} else if err != nil {
			return err
		}
		return nil
	}
	if !asStep {
		return do(time.Now(), r.cfg.Bounds[StepDelete])
	}
	return r.step(c, StepDelete, do)
}

// Evictions is when the run evicted each agent.
func (r *Runner) Evictions() map[string][]time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string][]time.Time, len(r.evictions))
	for k, v := range r.evictions {
		out[k] = slices.Clone(v)
	}
	return out
}

// evidence writes a failure's evidence (spec, detection) and returns its
// directory.
func (r *Runner) evidence(ctx context.Context, c *cycleState, f Failure, extra string) string {
	dir := filepath.Join(r.rec.dir, "failures", c.res.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		r.log.Error("creating the evidence directory", "error", err)
		return ""
	}
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			r.log.Error("writing evidence", "file", name, "error", err)
		}
	}
	write("failure.txt", fmt.Sprintf("cycle %s (%s, %s) %s\ninstance %s\nclass %s, step %s, security %v\n%s\n",
		c.res.ID, c.res.Kind, c.res.Distro, c.res.Name, c.res.InstanceID, f.Class, f.Step, f.Security, f.Reason))
	if c.res.InstanceID == "" {
		return dir
	}
	if console, err := r.lab.ConsoleLog(ctx, c.res.InstanceID); err == nil {
		write("console.log", console)
	}
	if extra == "" && c.server.ID != "" {
		extra = r.lab.GuestState(ctx, c.server, c.res.Distro).Output
	}
	if extra != "" {
		write("guest.txt", extra)
	}
	if show, err := r.lab.AgentShow(ctx, c.res.AgentID); err == nil {
		write("agent.txt", show)
	}
	needles := []string{c.res.InstanceID}
	for _, t := range r.ledger.Facts().Tokens {
		if t.Instance == c.res.InstanceID {
			needles = append(needles, t.JTI)
		}
	}
	write("journals.txt", r.journals.Grep(needles))
	return dir
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
