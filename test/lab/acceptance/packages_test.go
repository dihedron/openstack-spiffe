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

// built returns the SHA-256 of a binary as goreleaser built it (the
// baseline amd64 build, which the lab installs).
func built(t *testing.T, binary string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "dist", binary+"_linux_amd64_v1", binary))
	if err != nil {
		t.Fatalf("the build is gone (run lab.sh deploy): %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestPackages is PKG-1: the deb and rpm packages are installed, with the
// binaries just built; the package installs its units disabled (deploy only
// enables the signer's); config check passes on the deployed files as the
// service user; and reinstalling the package keeps the service running.
func TestPackages(t *testing.T) {
	l := theLab
	installed := map[string]string{
		"issuer-a": "dpkg-query -W -f '${Status}' openstack-spire-issuer",
		"issuer-b": "rpm -q openstack-spire-issuer",
		"spire":    "dpkg-query -W -f '${Status}' openstack-server-plugin",
	}
	for vm, query := range installed {
		if out, err := l.run(vm, query, nil); err != nil || strings.Contains(out, "not installed") {
			t.Errorf("%s: package not installed: %s %v", vm, out, err)
		}
	}
	for vm, binary := range map[string]string{"issuer-a": "openstack-spire-issuer", "issuer-b": "openstack-spire-issuer", "spire": "openstack-server-plugin"} {
		got, _, _ := strings.Cut(l.must(t, vm, "sha256sum /usr/bin/"+binary), " ")
		if want := built(t, binary); got != want {
			t.Errorf("%s: /usr/bin/%s is %s, the build is %s", vm, binary, got, want)
		}
	}

	for _, vm := range []string{"issuer-a", "issuer-b"} {
		if out, _ := l.run(vm, "systemctl is-enabled openstack-spire-issuer-aggregator", nil); strings.TrimSpace(out) != "disabled" {
			t.Errorf("%s: the aggregator unit is %q, want disabled (the package never enables its units)", vm, strings.TrimSpace(out))
		}
		if out, _ := l.run(vm, "systemctl is-active openstack-spire-issuer", nil); strings.TrimSpace(out) != "active" {
			t.Errorf("%s: the signer is %q", vm, strings.TrimSpace(out))
		}
		if out, err := l.run(vm, "sudo -u openstack-spire-issuer /usr/bin/openstack-spire-issuer config check --signer /etc/openstack-spire-issuer/signer.yaml", nil); err != nil {
			t.Errorf("%s: config check failed: %v\n%s", vm, err, out)
		}
	}

	// reinstalling (as an upgrade would) restarts the running service
	deb, err := filepath.Glob(filepath.Join("..", "..", "..", "dist", "openstack-spire-issuer_*_linux_amd64.deb"))
	if err != nil || len(deb) != 1 {
		t.Fatalf("no single baseline deb in dist/: %v %v", deb, err)
	}
	data, err := os.ReadFile(deb[0])
	if err != nil {
		t.Fatal(err)
	}
	before := strings.TrimSpace(l.must(t, "issuer-a", "systemctl show -p MainPID --value openstack-spire-issuer"))
	if _, err := l.run("issuer-a", "cat > /tmp/reinstall.deb && sudo dpkg -i /tmp/reinstall.deb >/dev/null && rm -f /tmp/reinstall.deb", data); err != nil {
		t.Fatal(err)
	}
	l.waitIssuerReady(t, "issuer-a")
	after := strings.TrimSpace(l.must(t, "issuer-a", "systemctl show -p MainPID --value openstack-spire-issuer"))
	if after == before || after == "0" {
		t.Errorf("the signer was not restarted by the reinstall (main PID %s, then %s)", before, after)
	}
}
