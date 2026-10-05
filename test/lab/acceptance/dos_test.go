//go:build lab

package acceptance

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPublicEndpointLimit is DOS-1: a burst on the JWK Set from the lab
// host gets 429s from its per-source limit (50/1s by default), while other
// sources are served and Nova's calls are unaffected (D-5).
func TestPublicEndpointLimit(t *testing.T) {
	l := theLab
	caPEM, err := os.ReadFile(filepath.Join(l.stateDir, "pki", "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "issuer-a.lab"}, MaxIdleConnsPerHost: 50,
	}}
	url := "https://" + l.env.VMs["issuer-a"].IP + ":8443/.well-known/jwks.json"

	const burst = 150
	var ok, limited, other atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range burst {
		wg.Go(func() {
			<-start
			resp, err := client.Get(url)
			if err != nil {
				other.Add(1)
				return
			}
			_ = resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				ok.Add(1)
			case http.StatusTooManyRequests:
				limited.Add(1)
			default:
				other.Add(1)
			}
		})
	}
	close(start)
	// meanwhile, another source is served
	code := strings.TrimSpace(l.must(t, "devstack", "curl -s -o /dev/null -w '%{http_code}' --cacert /etc/nova/lab-ca.pem https://issuer-a.lab:8443/.well-known/jwks.json"))
	wg.Wait()
	t.Logf("burst of %d: %d served, %d limited, %d other", burst, ok.Load(), limited.Load(), other.Load())
	if limited.Load() == 0 {
		t.Error("no request of the burst was limited")
	}
	if other.Load() != 0 {
		t.Errorf("%d requests failed otherwise", other.Load())
	}
	if code != "200" {
		t.Errorf("the JWK Set from devstack during the burst: HTTP %s, want 200", code)
	}

	// Nova's calls are unaffected
	g := l.bootGuest(t, "ubuntu", "demo")
	l.waitAttested(t, l.agentID(g, l.env.OpenStack.ProjectID), "", attestTimeout)
}
