//go:build lab

package acceptance

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

const spireConfig = "/etc/spire/server.conf"

// editSpireConfig replaces SPIRE Server's configuration with the result of
// edit, restarts it, and restores the original (and restarts it again) when
// the test ends.
func (l *lab) editSpireConfig(t *testing.T, edit func(string) string) {
	t.Helper()
	original := l.must(t, "spire", "sudo cat "+spireConfig)
	write := func(content string) error {
		_, err := l.run("spire", "sudo tee "+spireConfig+" >/dev/null", []byte(content))
		return err
	}
	if err := write(edit(original)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := write(original); err != nil {
			t.Errorf("restoring %s: %v", spireConfig, err)
			return
		}
		l.restartSpire(t)
	})
	l.restartSpire(t)
}

// restartSpire restarts SPIRE Server and waits for its health check.
func (l *lab) restartSpire(t *testing.T) {
	t.Helper()
	l.must(t, "spire", "sudo systemctl restart spire-server")
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, err := l.spireServer("healthcheck"); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("SPIRE Server not healthy within 2 minutes")
		}
		time.Sleep(3 * time.Second)
	}
}

// TestTrustOnFirstUse is E2E-5: with the server plugin's reattest = false,
// an agent that lost its state is refused, by the plugin, until an operator
// evicts it; then it attests again.
func TestTrustOnFirstUse(t *testing.T) {
	l := theLab
	l.editSpireConfig(t, func(config string) string {
		return regexp.MustCompile(`(?m)^(\s*)jwks_url`).ReplaceAllString(config, "${1}reattest            = false\n${1}jwks_url")
	})
	g := l.bootGuest(t, "ubuntu", "demo")
	id := l.agentID(g, l.env.OpenStack.ProjectID)
	first := l.waitAttested(t, id, "", attestTimeout)

	since := strings.TrimSpace(l.must(t, "spire", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	l.reattest(t, g)
	deadline := time.Now().Add(3 * time.Minute)
	for !strings.Contains(l.spireLog(since, g.id), "already attested and reattest is false") {
		if time.Now().After(deadline) {
			t.Fatalf("no refusal of the agent that lost its state within 3 minutes:\n%s", l.spireLog(since, "openstack_iid"))
		}
		time.Sleep(10 * time.Second)
	}
	if a, ok := l.attestedAgent(id); !ok || a.serial != first.serial {
		t.Fatalf("the agent's identity changed (serial %s, was %s): it attested again despite reattest = false", a.serial, first.serial)
	}
	if !strings.Contains(l.spireLog(since, g.id), "audit=reattest_refused") {
		t.Error("no reattest_refused audit record")
	}

	// an operator's eviction lets it attest again
	if _, err := l.spireServer("agent evict -spiffeID " + quote(id)); err != nil {
		t.Fatal(err)
	}
	l.waitAttested(t, id, first.serial, 3*time.Minute)
	t.Logf("refused until evicted, then attested again: %s", id)
}
