//go:build lab

package acceptance

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// vendordataToken returns a Keystone token of the dedicated vendordata user,
// as Nova would get one.
func (l *lab) vendordataToken(t *testing.T) string {
	t.Helper()
	password, err := os.ReadFile(filepath.Join(l.stateDir, "nova-vendordata-password"))
	if err != nil {
		t.Fatal(err)
	}
	token := l.must(t, "devstack", `OS_AUTH_URL=https://`+l.env.VMs["devstack"].IP+`/identity/v3 OS_USERNAME=nova-vendordata \
	OS_PASSWORD=`+quote(strings.TrimSpace(string(password)))+` OS_USER_DOMAIN_NAME=Default OS_PROJECT_NAME=service \
	OS_PROJECT_DOMAIN_NAME=Default OS_IDENTITY_API_VERSION=3 OS_CACERT=/opt/stack/data/CA/int-ca/ca-chain.pem \
	/opt/stack/data/venv/bin/openstack token issue -f value -c id`)
	return strings.TrimSpace(token)
}

// unknownInstance is a well-formed instance ID that Nova does not know.
const unknownInstance = "8f7c1b6e-6a0e-4d4b-9a51-3f0e8b1d2c3a"

func (l *lab) attestBody() string {
	return `{"project-id":"` + l.env.OpenStack.ProjectID + `","instance-id":"` + unknownInstance + `","hostname":"x","metadata":{}}`
}

// TestSourceAllowlist is NET-1: from the lab host, outside
// attest.allowed_sources, a valid vendordata token and even Nova's client
// certificate get a 403 from /attest; the JWK Set is not restricted.
func TestSourceAllowlist(t *testing.T) {
	l := theLab
	pki := filepath.Join(l.stateDir, "pki")
	caPEM, err := os.ReadFile(filepath.Join(pki, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	cert, err := tls.LoadX509KeyPair(filepath.Join(pki, "nova-vendordata.pem"), filepath.Join(pki, "nova-vendordata.key"))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: "issuer-a.lab", Certificates: []tls.Certificate{cert},
	}}}
	base := "https://" + l.env.VMs["issuer-a"].IP + ":8443"
	token := l.vendordataToken(t)

	since := strings.TrimSpace(l.must(t, "issuer-a", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	req, _ := http.NewRequest(http.MethodPost, base+"/attest", strings.NewReader(l.attestBody()))
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("/attest from the lab host: HTTP %d, want 403", resp.StatusCode)
	}
	if log := l.issuerLog(t, "issuer-a", since, "-o cat"); !strings.Contains(log, "source not in attest.allowed_sources") {
		t.Errorf("issuer-a did not log the refused source:\n%s", log)
	}

	resp, err = client.Get(base + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("the JWK Set from the lab host: HTTP %d, want 200", resp.StatusCode)
	}
}

// TestClientCertificate is NET-2: from the nova-api-metadata host, /attest
// refuses a request without Nova's client certificate (403) and lets one
// with it through; the JWK Set needs none; and Nova presents it, through
// its [vendordata_dynamic_auth] certfile and keyfile, when guests read
// their vendordata.
func TestClientCertificate(t *testing.T) {
	l := theLab
	token := l.vendordataToken(t)
	curl := `sudo curl -s -o /dev/null -w '%{http_code}' --cacert /etc/nova/lab-ca.pem -H 'Content-Type: application/json' -H 'X-Auth-Token: ` + token + `' -d ` + quote(l.attestBody())

	since := strings.TrimSpace(l.must(t, "issuer-a", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	if code := strings.TrimSpace(l.must(t, "devstack", curl+" https://issuer-a.lab:8443/attest")); code != "403" {
		t.Errorf("/attest without a client certificate: HTTP %s, want 403", code)
	}
	if log := l.issuerLog(t, "issuer-a", since, "-o cat"); !strings.Contains(log, "no client certificate") {
		t.Errorf("issuer-a did not log the missing certificate:\n%s", log)
	}

	// journalctl --since has a one-second resolution: keep the previous
	// request's records out of the next window
	time.Sleep(1100 * time.Millisecond)
	since = strings.TrimSpace(l.must(t, "issuer-a", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	l.must(t, "devstack", curl+" --cert /etc/nova/lab-nova-vendordata.pem --key /etc/nova/lab-nova-vendordata.key https://issuer-a.lab:8443/attest")
	log := l.issuerLog(t, "issuer-a", since, "-o cat")
	if strings.Contains(log, "rejecting /attest request") {
		t.Errorf("/attest with Nova's certificate refused by the guard:\n%s", log)
	}
	// past the guard and the authentication: the instance is unknown to Nova
	if !strings.Contains(log, "instance verification failed") {
		t.Errorf("/attest with Nova's certificate did not reach instance verification:\n%s", log)
	}

	if code := strings.TrimSpace(l.must(t, "devstack", "curl -s -o /dev/null -w '%{http_code}' --cacert /etc/nova/lab-ca.pem https://issuer-a.lab:8443/.well-known/jwks.json")); code != "200" {
		t.Errorf("the JWK Set without a client certificate: HTTP %s, want 200", code)
	}

	// Nova itself presents the certificate
	since = strings.TrimSpace(l.must(t, "issuer-a", "date -u '+%Y-%m-%d %H:%M:%S'")) + " UTC"
	g := l.bootGuest(t, "ubuntu", "demo")
	l.waitAttested(t, l.agentID(g, l.env.OpenStack.ProjectID), "", attestTimeout)
	issued := 0
	for _, line := range strings.Split(l.issuerLog(t, "issuer-a", since, "_TRANSPORT=stdout -o cat"), "\n") {
		if !strings.Contains(line, "audit=token_issued") || !strings.Contains(line, "instance_id="+g.id) {
			continue
		}
		issued++
		if !strings.Contains(line, `client_cert_subject="CN=nova-vendordata`) {
			t.Errorf("a token issued without Nova's certificate in its audit record: %s", line)
		}
	}
	if issued == 0 {
		t.Errorf("no token issued for %s", g.id)
	}
}
