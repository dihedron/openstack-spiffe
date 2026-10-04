//go:build lab

package acceptance

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var kidOf = regexp.MustCompile(`audit=token_issued .*\bkid=(\S+)`)

// TestKeyRotation is E2E-3 (long: lab.sh test -long): with the shortest
// rotation interval (5 minutes) on both issuers, a guest keeps attesting
// from scratch across two rotations, with tokens signed by three keys and
// no attestation failing on an unknown kid.
func TestKeyRotation(t *testing.T) {
	if !long() {
		t.Skip("long scenario (about 20 minutes): lab.sh test -long")
	}
	l := theLab
	since := strings.TrimSpace(l.must(t, "spire", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	for _, vm := range []string{"issuer-a", "issuer-b"} {
		l.editIssuerFile(t, vm, "/etc/openstack-spire-issuer/signer.yaml", func(config string) string {
			return config + "key_store:\n  rotation_interval: \"5m\"\n"
		})
	}
	g := l.bootGuest(t, "ubuntu", "demo")
	id := l.agentID(g, l.env.OpenStack.ProjectID)
	last := l.waitAttested(t, id, "", attestTimeout)

	// two rotations: the first key activates 2 minutes after the restart and
	// rotates 5 minutes later, its successor 5 minutes after that
	end := time.Now().Add(14 * time.Minute)
	attestations := 1
	for time.Now().Before(end) {
		time.Sleep(time.Minute)
		l.reattest(t, g)
		last = l.waitAttested(t, id, last.serial, 3*time.Minute)
		attestations++
	}

	kids := map[string]bool{}
	for _, m := range kidOf.FindAllStringSubmatch(l.issuerLog(t, "issuer-a", since, "_TRANSPORT=stdout -o cat"), -1) {
		if strings.Contains(m[0], "instance_id="+g.id) {
			kids[m[1]] = true
		}
	}
	t.Logf("%d attestations, tokens signed by %d keys", attestations, len(kids))
	if len(kids) < 3 {
		t.Errorf("tokens signed by %d keys %v, want at least 3 (two rotations)", len(kids), kids)
	}
	if rejected := l.spireLog(since, "unknown kid"); strings.TrimSpace(rejected) != "" {
		t.Errorf("attestations rejected on an unknown kid:\n%s", rejected)
	}
}
