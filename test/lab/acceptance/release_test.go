//go:build lab

package acceptance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// tamper is a shell snippet copying the file $f to $t with one byte of its
// payload, near the end, changed.
const tamper = `cp "$f" "$t" && printf X | dd of="$t" bs=1 seek=$(($(stat -c %s "$t") - 64)) conv=notrunc status=none`

// TestSignedRelease is REL-1: deploy builds the release as CI does, signed
// with the (lab) packaging key, and what an operator verifies verifies: the
// checksums file's signature, and each package's own signature with the
// tools of its distribution. A tampered copy fails each check.
func TestSignedRelease(t *testing.T) {
	l := theLab
	dist := filepath.Join("..", "..", "..", "dist")
	checksums, err := filepath.Glob(filepath.Join(dist, "*_checksums.txt"))
	if err != nil || len(checksums) != 1 {
		t.Fatalf("no single checksums file in dist/: %v %v", checksums, err)
	}
	keyring := filepath.Join(l.stateDir, "pki", "packaging-key.gpg")
	if out, err := exec.Command("gpgv", "--keyring", keyring, checksums[0]+".asc", checksums[0]).CombinedOutput(); err != nil {
		t.Errorf("the checksums file's signature does not verify: %v\n%s", err, out)
	}
	data, err := os.ReadFile(checksums[0])
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(t.TempDir(), filepath.Base(checksums[0]))
	if err := os.WriteFile(tampered, append(data, []byte(strings.Repeat("0", 64)+"  extra.tar.gz\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("gpgv", "--keyring", keyring, checksums[0]+".asc", tampered).Run(); err == nil {
		t.Error("the signature verifies a tampered checksums file")
	}
	for _, line := range []string{"_linux_amd64.deb", "_linux_amd64.rpm", ".cdx.json"} {
		if !strings.Contains(string(data), line) {
			t.Errorf("the checksums file covers no %s", line)
		}
	}

	// the packages' own signatures, where operators install them
	tests := []struct {
		vm, pattern, verify string
	}{
		{"issuer-a", "openstack-agent-plugin_*_linux_amd64.deb", `debsig-verify --quiet "$1"`},
		{"issuer-b", "openstack-agent-plugin_*_linux_amd64.rpm", `rpm --checksig "$1" | grep -q 'signatures OK'`},
	}
	for _, tt := range tests {
		t.Run(filepath.Ext(tt.pattern)[1:], func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join(dist, tt.pattern))
			if err != nil || len(files) != 1 {
				t.Fatalf("no single %s in dist/: %v %v", tt.pattern, files, err)
			}
			data, err := os.ReadFile(files[0])
			if err != nil {
				t.Fatal(err)
			}
			f := "/tmp/" + filepath.Base(files[0])
			script := `set -e; f=` + f + `; t=/tmp/tampered` + filepath.Ext(f) + `; cat > "$f"
verify() { ` + tt.verify + `; }
trap 'rm -f "$f" "$t"' EXIT
verify "$f" || { echo "SIGNED-FAILS"; exit 0; }
` + tamper + `
verify "$t" && echo "TAMPERED-PASSES" || true`
			out, err := l.run(tt.vm, script, data)
			if err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			if strings.Contains(out, "SIGNED-FAILS") {
				t.Errorf("%s: the signature of %s does not verify", tt.vm, filepath.Base(f))
			}
			if strings.Contains(out, "TAMPERED-PASSES") {
				t.Errorf("%s: a tampered %s verifies", tt.vm, filepath.Base(f))
			}
		})
	}
}
