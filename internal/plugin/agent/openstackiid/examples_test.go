package openstackiid

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/plugin/config"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

func TestExampleConfiguration(t *testing.T) {
	conf, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "examples", "agent.conf"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := config.PluginData(conf, "NodeAttestor", iid.TargetName)
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseConfig(data)
	if err != nil {
		t.Fatalf("examples/agent.conf: %v", err)
	}
	if s.url != DefaultVendorDataURL {
		t.Fatalf("examples/agent.conf: vendordata_url %q, want the default %q", s.url, DefaultVendorDataURL)
	}
}

// TestMetadataNftablesSample checks the guest hardening sample (S-4) with
// nft's check mode, in an unprivileged user and network namespace. The
// agent's user is replaced with the current one, which exists here.
func TestMetadataNftablesSample(t *testing.T) {
	sample, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "examples", "agent-metadata-nftables.conf"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"169.254.169.254", "fe80::a9fe:a9fe", "hook output", "meta skuid { 0, $spire_agent_user } accept"} {
		if !strings.Contains(string(sample), want) {
			t.Errorf("the sample has no %q", want)
		}
	}
	define := regexp.MustCompile(`(?m)^define spire_agent_user = "[^"]+"$`)
	if !define.Match(sample) {
		t.Fatal("the sample does not define spire_agent_user")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
	if err := exec.Command("unshare", "-rn", "true").Run(); err != nil {
		t.Skipf("no unprivileged user namespaces: %v", err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "nftables.conf")
	if err := os.WriteFile(path, define.ReplaceAll(sample, []byte(`define spire_agent_user = "`+current.Username+`"`)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("unshare", "-rn", "nft", "-c", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("nft -c: %v\n%s", err, out)
	}
}
