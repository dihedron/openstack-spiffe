//go:build lab

package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"
)

var kidPattern = regexp.MustCompile(`"kid"\s*:\s*"([^"]+)"`)

// tofuGuestSuffix ends the name of the self-test's TOFU guest.
const tofuGuestSuffix = "-tofu-ubuntu"

// The self-test's schedule, from the run's start (spec, ST-3 and ST-5).
const (
	selfTestIssuerAAt   = 4 * time.Minute
	selfTestIssuerAFor  = 3 * time.Minute
	selfTestWorkloadAt  = 12 * time.Minute
	selfTestWorkloadFor = 3 * time.Minute
	selfTestSpireAt     = 18 * time.Minute
	selfTestTOFUAt      = 21 * time.Minute
	selfTestTOFUWait    = 3 * time.Minute
)

// selfTest injects faults that must be detected (lab.sh stress --self-test),
// and checks afterwards that they were.
type selfTest struct {
	r *stressRun

	mu   sync.Mutex
	tofu *Expectation
}

func (s *selfTest) inject(startCtx, root context.Context) {
	r := s.r
	start := time.Now()
	var tofuGuest *cycleState
	if r.cfg.TOFU {
		tofuGuest = s.bootTOFUGuest(startCtx)
	}
	at := func(d time.Duration) bool { return sleep(startCtx, time.Until(start.Add(d))) == nil }

	if at(selfTestIssuerAAt) {
		r.log.Warn("self-test fault", "fault", faultStopIssuerA, "for", selfTestIssuerAFor.String())
		r.issuerA.Store(true)
		i := r.faults.begin(faultStopIssuerA, true, time.Now())
		_, err := r.kit.Run(root, "issuer-a", "sudo systemctl stop openstack-spire-issuer", nil)
		if err == nil {
			_ = sleep(root, selfTestIssuerAFor)
			_, err = r.kit.Run(root, "issuer-a", "sudo systemctl start openstack-spire-issuer", nil)
		}
		if err == nil {
			err = r.kit.WaitIssuerReady(root, "issuer-a", 5*time.Minute)
		}
		r.faults.healed(i, time.Now(), err)
		if err != nil {
			r.rec.Harness("self-test: stopping and starting issuer-a: " + err.Error())
		}
	}
	if at(selfTestWorkloadAt) {
		r.log.Warn("self-test fault", "fault", faultRemoveWorkload, "for", selfTestWorkloadFor.String())
		i := r.faults.begin(faultRemoveWorkload, true, time.Now())
		err := r.setup.removeWorkloadEntry(root, r.pending)
		if err == nil {
			_ = sleep(root, selfTestWorkloadFor)
			err = r.setup.createWorkloadEntry(root, r.pending)
		}
		r.faults.healed(i, time.Now(), err)
		if err != nil {
			r.rec.Harness("self-test: removing and restoring the workload entry: " + err.Error())
		}
	}
	if at(selfTestSpireAt) {
		r.restartSpire(root, faultSelfTestSpire)
	}
	if tofuGuest != nil {
		if at(selfTestTOFUAt) {
			s.wipeTOFUAgent(root, tofuGuest)
		}
		if err := r.runner.remove(root, tofuGuest, false); err != nil {
			r.log.Warn("self-test: removing the TOFU guest", "error", err)
		}
		r.held.Add(-1)
	}
}

// bootTOFUGuest boots the guest whose agent the TOFU step wipes.
func (s *selfTest) bootTOFUGuest(ctx context.Context) *cycleState {
	r := s.r
	r.held.Add(1)
	res := &CycleResult{ID: "tofu", Kind: KindCreate, Distro: "ubuntu", Name: fmt.Sprintf("stress-%s%s", r.runID, tofuGuestSuffix), Started: time.Now()}
	c := &cycleState{res: res, start: res.Started}
	if err := r.runner.bootAndAttest(ctx, c, Plan{Kind: KindCreate, Distro: "ubuntu"}); err != nil {
		s.setTOFU(false, "the TOFU guest did not attest: "+err.Error())
		if res.InstanceID != "" {
			_ = r.runner.remove(context.WithoutCancel(ctx), c, false)
		}
		r.held.Add(-1)
		return nil
	}
	r.log.Info("self-test: TOFU guest attested", "instance_id", res.InstanceID)
	return c
}

// wipeTOFUAgent makes the TOFU guest's agent lose its state: SPIRE Server
// must refuse its new attestation.
func (s *selfTest) wipeTOFUAgent(ctx context.Context, c *cycleState) {
	r := s.r
	r.log.Warn("self-test fault", "fault", faultWipeTOFUAgent, "instance_id", c.res.InstanceID)
	i := r.faults.begin(faultWipeTOFUAgent, true, time.Now())
	wiped := time.Now()
	err := r.lab.WipeAgent(ctx, c.server, c.res.Distro)
	_ = sleep(ctx, selfTestTOFUWait)
	r.faults.healed(i, time.Now(), err)
	attested := r.ledger.AttestedSince(c.res.InstanceID, wiped)
	refused := len(r.ledger.RejectionsSince(c.res.InstanceID, wiped)) + r.ledger.ErrorsSince(c.res.InstanceID, wiped)
	switch {
	case err != nil:
		s.setTOFU(false, "wiping the agent: "+err.Error())
	case len(attested) > 0:
		s.setTOFU(false, fmt.Sprintf("the wiped agent attested again (jti %s): TOFU did not refuse it", attested[0].JTI))
	case refused == 0:
		s.setTOFU(false, "SPIRE Server logged no refusal of the wiped agent")
	default:
		s.setTOFU(true, fmt.Sprintf("the wiped agent was refused (%d record(s)) and not attested again", refused))
	}
	// its refusal records are expected
	c.res.ExpectedRefusal = true
	r.rec.Cycle(*c.res)
}

func (s *selfTest) setTOFU(met bool, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tofu = &Expectation{Name: "TOFU refuses a wiped agent", Met: met, Detail: detail}
}

// evaluate checks the self-test's expectations.
func (s *selfTest) evaluate(cycles []CycleResult, failures []Failure, facts Facts, windows []FaultWindow) *SelfTestResult {
	started := map[string]time.Time{}
	for _, c := range cycles {
		started[c.ID] = c.Started
	}
	attributed := map[int]bool{}
	var exps []Expectation
	for _, w := range windows {
		end := w.End
		if end.IsZero() {
			end = time.Now()
		}
		switch w.Fault {
		case faultStopIssuerA:
			n := 0
			for i, f := range failures {
				if f.Class == ClassNode && !f.Time.Before(w.Start) && !started[f.Cycle].After(end) {
					n++
					attributed[i] = true
				}
			}
			nova := 0
			for _, p := range facts.NovaProblems {
				if w.contains(p.Time) {
					nova++
				}
			}
			exps = append(exps, Expectation{Name: "stopping issuer-a causes node failures", Met: n > 0 && nova > 0,
				Detail: fmt.Sprintf("%d node failure(s); %d nova-api-metadata vendordata warning(s) during the outage", n, nova)})
			recovered := false
			for _, c := range cycles {
				if c.Outcome == outcomePassed && c.Started.After(end) {
					recovered = true
				}
			}
			exps = append(exps, Expectation{Name: "the run recovers after issuer-a is back", Met: recovered,
				Detail: fmt.Sprintf("a cycle started after %s passed: %v", end.Format(time.TimeOnly), recovered)})
		case faultRemoveWorkload:
			n := 0
			for i, f := range failures {
				if f.Class == ClassWorkload && !f.Time.Before(w.Start) && !f.Time.After(end.Add(s.r.cfg.Bounds[StepSVID])) {
					n++
					attributed[i] = true
				}
			}
			exps = append(exps, Expectation{Name: "removing the workload entry causes workload failures", Met: n > 0,
				Detail: fmt.Sprintf("%d workload failure(s)", n)})
		case faultSelfTestSpire:
			n := 0
			for _, f := range failures {
				if f.Class == ClassInvariant && !f.Time.Before(w.Start) && !f.Time.After(end.Add(5*time.Minute)) {
					n++
				}
			}
			exps = append(exps, Expectation{Name: "restarting SPIRE Server causes no invariant failure", Met: n == 0,
				Detail: fmt.Sprintf("%d invariant failure(s) around the restart", n)})
		}
	}
	s.mu.Lock()
	if s.tofu != nil {
		exps = append(exps, *s.tofu)
	}
	s.mu.Unlock()
	if s.r.cfg.TOFU && s.tofu == nil {
		exps = append(exps, Expectation{Name: "TOFU refuses a wiped agent", Detail: "the TOFU step did not run"})
	}
	var others []error
	for i, f := range failures {
		if f.Class.counts() && !attributed[i] {
			others = append(others, errors.New(string(f.Class)+": "+f.Reason))
		}
	}
	exps = append(exps, Expectation{Name: "no failure outside the injected faults", Met: len(others) == 0,
		Detail: fmt.Sprintf("%d other failure(s)", len(others))})
	res := &SelfTestResult{Status: exitPass, Verdict: "SELF-TEST PASS", Expectations: exps}
	for _, e := range exps {
		if !e.Met {
			res.Status, res.Verdict = exitFail, "SELF-TEST FAIL: the harness missed an injected fault, or reported a false one"
		}
	}
	if len(windows) == 0 {
		res.Status, res.Verdict = exitFail, "SELF-TEST FAIL: no fault was injected (run too short?)"
	}
	return res
}
