//go:build lab

package acceptance

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// attestTimeout bounds a fresh guest's boot and first attestation (about
// half a minute on the reference host).
const attestTimeout = 6 * time.Minute

// TestAttestation is E2E-1: an Ubuntu and a RHEL-like guest boot, and each
// agent attests with the expected SPIFFE ID and selectors.
func TestAttestation(t *testing.T) {
	l := theLab
	for _, distro := range []string{"ubuntu", "rhel"} {
		t.Run(distro, func(t *testing.T) {
			t.Parallel()
			g := l.bootGuest(t, distro, "demo")
			id := l.agentID(g, l.env.OpenStack.ProjectID)
			a := l.waitAttested(t, id, "", attestTimeout)
			t.Logf("attested: %s", id)
			for _, want := range []string{
				"openstack_iid:project_id:" + l.env.OpenStack.ProjectID,
				"openstack_iid:instance_id:" + g.id,
				"openstack_iid:hostname:" + g.name,
				// the enrichment claims the issuers are configured for
				"openstack_iid:availability_zone:nova",
				"openstack_iid:project_name:demo",
			} {
				if !slices.Contains(a.selectors, want) {
					t.Errorf("selector %s missing from %v", want, a.selectors)
				}
			}
		})
	}
}

// reattest makes a guest's agent attest again from scratch, as one that lost
// its state would: no SVID left to renew.
func (l *lab) reattest(t *testing.T, g guest) {
	t.Helper()
	l.guestRun(t, g, "sudo systemctl stop spire-agent && sudo rm -rf /var/lib/spire/agent/* && sudo systemctl start spire-agent")
}

// TestFreshness is E2E-2: an agent that lost its state attests again within
// the spec's bound (Nova's metadata cache, the issuer's per-instance limit,
// SPIRE Agent's retry), and is rejected as "already used" at most once.
func TestFreshness(t *testing.T) {
	l := theLab
	g := l.bootGuest(t, "ubuntu", "demo")
	id := l.agentID(g, l.env.OpenStack.ProjectID)
	first := l.waitAttested(t, id, "", attestTimeout)

	since := strings.TrimSpace(l.must(t, "spire", "date -u '+%Y-%m-%d %H:%M:%S'"))
	start := time.Now()
	l.reattest(t, g)
	l.waitAttested(t, id, first.serial, 3*time.Minute)
	elapsed := time.Since(start)
	t.Logf("attested again %v after losing its state", elapsed.Round(time.Second))
	// Nova's cache (15s) + one token per 5s + SPIRE Agent's retry, with margin
	if elapsed > 2*time.Minute {
		t.Errorf("attesting again took %v, more than 2 minutes", elapsed)
	}
	if n := strings.Count(l.spireLog(since+" UTC", g.id), "already used"); n > 1 {
		t.Errorf("rejected %d times as already used, at most once expected", n)
	}
}

// TestUnlistedProject is E2E-4: an instance of a project missing from
// allowed_project_ids gets a token from the issuer, but SPIRE Server refuses
// to attest it.
func TestUnlistedProject(t *testing.T) {
	l := theLab
	// alt_demo boots on demo's private network, shared with it
	altDemo := strings.TrimSpace(mustOpenstack(t, l, "admin", "admin", "project", "show", "alt_demo", "-f", "value", "-c", "id"))
	if out, err := l.openstack("admin", "admin", "network", "rbac", "create", "--type", "network",
		"--action", "access_as_shared", "--target-project", altDemo, "private"); err != nil &&
		!strings.Contains(out+err.Error(), "already exists") && !strings.Contains(out+err.Error(), "Conflict") {
		t.Fatal(err)
	}

	g := l.bootGuest(t, "ubuntu", "alt_demo")
	deadline := time.Now().Add(attestTimeout)
	for !strings.Contains(l.spireLog("-10min", g.id), "project not allowed") {
		if time.Now().After(deadline) {
			t.Fatalf("no rejection of %s by SPIRE Server within %v:\n%s", g.id, attestTimeout, l.spireLog("-10min", "openstack_iid"))
		}
		time.Sleep(10 * time.Second)
	}
	if _, ok := l.attestedAgent(l.agentID(g, altDemo)); ok {
		t.Error("the instance of an unlisted project was attested")
	}
	// the refusal is SPIRE Server's: the issuer did issue a token
	if !regexp.MustCompile(`token issued.*instance_id=` + g.id).MatchString(l.issuerLog(t, "issuer-a", "-10min", "")) {
		t.Errorf("issuer-a issued no token for %s", g.id)
	}
}

func mustOpenstack(t *testing.T, l *lab, user, project string, args ...string) string {
	t.Helper()
	out, err := l.openstack(user, project, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
