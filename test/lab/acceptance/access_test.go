//go:build lab

package acceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDedicatedVendordataUser is S3-1: the nova service user, whose
// credentials are on every compute node, cannot get a token from /attest;
// Nova's calls come from the dedicated user (checked by the audit tests).
func TestDedicatedVendordataUser(t *testing.T) {
	l := theLab
	password, err := os.ReadFile(filepath.Join(l.stateDir, "devstack-admin-password"))
	if err != nil {
		t.Fatal(err)
	}
	ip := l.env.VMs["devstack"].IP
	script := `set -e
token=$(OS_AUTH_URL=https://` + ip + `/identity/v3 OS_USERNAME=nova OS_PASSWORD=` + quote(strings.TrimSpace(string(password))) + ` \
	OS_USER_DOMAIN_NAME=Default OS_PROJECT_NAME=service OS_PROJECT_DOMAIN_NAME=Default OS_IDENTITY_API_VERSION=3 \
	OS_CACERT=/opt/stack/data/CA/int-ca/ca-chain.pem /opt/stack/data/venv/bin/openstack token issue -f value -c id)
# from nova-api-metadata's host with Nova's certificate: only the user differs
sudo curl -s -o /dev/null -w '%{http_code}' --cacert /etc/nova/lab-ca.pem -H "X-Auth-Token: $token" \
	--cert /etc/nova/lab-nova-vendordata.pem --key /etc/nova/lab-nova-vendordata.key \
	-H 'Content-Type: application/json' -d '{"project-id":"` + l.env.OpenStack.ProjectID + `","instance-id":"8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a","hostname":"x","metadata":{}}' \
	https://issuer-a.lab:8443/attest`
	since := strings.TrimSpace(l.must(t, "issuer-a", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	code, err := l.run("devstack", script, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(code) != "403" {
		t.Errorf("/attest with the nova user's token: HTTP %s, want 403", code)
	}
	if !strings.Contains(l.issuerLog(t, "issuer-a", since, "-o cat"), "rejecting unauthorized caller") {
		t.Error("issuer-a did not log the rejection")
	}
}
