//go:build lab

package acceptance

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// metadataStatus is a shell command printing the HTTP status of a request
// to the metadata service (000 when refused).
const metadataStatus = `curl -s -m 5 -o /dev/null -w '%{http_code}' http://169.254.169.254/openstack/latest/meta_data.json || true`

// TestGuestHardening is GST-1: with the sample nftables rule loaded at boot,
// an unprivileged user cannot reach the metadata service, while root and
// SPIRE Agent's user can, and the agent, running as its own user, attests.
func TestGuestHardening(t *testing.T) {
	l := theLab
	for _, distro := range []string{"ubuntu", "rhel"} {
		t.Run(distro, func(t *testing.T) {
			t.Parallel()
			g := l.bootGuest(t, distro, "demo")
			l.waitAttested(t, l.agentID(g, l.env.OpenStack.ProjectID), "", attestTimeout)
			if user := strings.TrimSpace(l.guestRun(t, g, "ps -o user= -C spire-agent")); user != "spire" {
				t.Errorf("SPIRE Agent runs as %q, want spire", user)
			}
			for who, want := range map[string]string{
				"":               "000", // the login user, unprivileged
				"sudo ":          "200",
				"sudo -u spire ": "200",
			} {
				if got := strings.TrimSpace(l.guestRun(t, g, who+metadataStatus)); got != want {
					t.Errorf("%q: the metadata service answered %s, want %s", who+"curl", got, want)
				}
			}
			if out := l.guestRun(t, g, "sudo nft list table inet openstack_metadata"); !strings.Contains(out, "169.254.169.254") {
				t.Errorf("the rule is not loaded:\n%s", out)
			}
			// the package ships the sample as documentation only
			sample, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "agent-metadata-nftables.conf"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(sample)
			installed, _, _ := strings.Cut(l.guestRun(t, g, "sha256sum /usr/share/doc/openstack-agent-plugin/agent-metadata-nftables.conf"), " ")
			if installed != hex.EncodeToString(sum[:]) {
				t.Errorf("the agent package installed no copy of the sample (%q)", installed)
			}
		})
	}
}
