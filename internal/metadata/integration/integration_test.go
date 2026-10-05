// Package integration runs the whole system end to end, over TLS on loopback
// listeners, against a fake OpenStack control plane, in both topologies: two
// signer replicas and one JWKS aggregator, and three signer replicas listing
// each other as peers, without aggregator. It checks the acceptance criteria
// that only hold for the system as a whole: tokens from any replica verify by
// kid against every merged JWKS the SPIRE Server may use, every kid is
// published there before its first use, and tokens signed before a rotation
// keep verifying after it. The openstack_iid SPIRE plugins run against the
// same deployments (plugins_test.go), as SPIRE Agent and Server load them.
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/openstack-spiffe/internal/metadata/auditsink"
	"github.com/dihedron/openstack-spiffe/internal/metadata/config"
	"github.com/dihedron/openstack-spiffe/internal/metadata/jwks"
	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
	"github.com/dihedron/openstack-spiffe/internal/metadata/openstacktest"
	"github.com/dihedron/openstack-spiffe/internal/metadata/osclient"
	"github.com/dihedron/openstack-spiffe/internal/metadata/server"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	projectID = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	// publishAhead exceeds the poll_interval + fetch_timeout + cache_max_age
	// (300ms + 200ms + 0s) of the aggregator and of the peers, as the
	// configuration checks require.
	publishAhead = 1500 * time.Millisecond
	// rotationInterval is far below the 5-minute minimum of the
	// configuration, so that the drill completes in seconds; it is the only
	// setting changed after the configuration check.
	rotationInterval = 4 * time.Second
)

var novaUser = openstacktest.User{
	ID: "0123456789abcdef0123456789abcdef", Name: "nova", DomainID: "default", DomainName: "Default",
	Roles: []string{"service"},
}

// topology selects how the replicas' keys are merged for the SPIRE Server.
type topology struct {
	name     string
	replicas []string
	// peers makes every replica list the others as peers; otherwise a
	// standalone aggregator polls them.
	peers bool
}

var topologies = []topology{
	{name: "signers plus aggregator", replicas: []string{"signer-a", "signer-b"}},
	{name: "peered signers", replicas: []string{"signer-a", "signer-b", "signer-c"}, peers: true},
}

// system is a running deployment.
type system struct {
	cloud   *openstacktest.Server
	client  *http.Client
	signers map[string]string // replica ID -> base URL
	// merged lists the merged JWK Set URLs the SPIRE Server may fetch: the
	// aggregator's, or every peered replica's.
	merged     []string
	aggregator string // base URL, empty without aggregator
	novaToken  string
	// caPath is the CA bundle trusted by every server's certificate.
	caPath string
	// syslog receives what the replicas' syslog audit sink sends.
	syslog *syslogDaemon
}

// writeTLS writes a self-signed certificate for 127.0.0.1, shared by every
// server, and returns the certificate (also the CA bundle) and key paths and
// a pool trusting it.
func writeTLS(t *testing.T) (certPath, keyPath string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "integration"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certPath, keyPath, pool
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

// start deploys the topology's signer replicas, plus an aggregator polling
// them unless they are peered.
func start(t *testing.T, topo topology) *system {
	t.Helper()
	cloud := openstacktest.New(t)
	cloud.AddProject(openstacktest.Project{ID: projectID, Name: "web", DomainID: "default"})
	certPath, keyPath, pool := writeTLS(t)
	daemon := newSyslogDaemon(t)

	listeners := map[string]net.Listener{}
	for _, id := range topo.replicas {
		listeners[id] = listen(t)
	}
	localURL := func(id string) string { return "https://" + listeners[id].Addr().String() + "/jwks/local.json" }

	var signerResults []*config.Result[config.Signer]
	for _, id := range topo.replicas {
		doc := fmt.Sprintf(`listen_addr: %s
tls_cert_path: %s
tls_key_path: %s
replica_id: %s
key_store:
  algorithm: ES256
  publish_ahead: %s
tags:
  allowlist: [role]
keystone:
  allowed_users: [%s]   # Nova's vendordata user, by ID
  ca_cert_path: %s
enrich: [availability_zone, project_name]
audit:
  syslog:
    enabled: true
    socket: %s
attest:
  allowed_sources: [127.0.0.1]   # the tests' client, standing in for nova-api-metadata
`, listeners[id].Addr(), certPath, keyPath, id, publishAhead, novaUser.ID, cloud.CAFile(t), daemon.path)
		if topo.peers {
			doc += fmt.Sprintf("peers:\n  ca_cert_path: %s\n  poll_interval: 300ms\n  fetch_timeout: 200ms\n  cache_max_age: 0s\n  urls:\n", certPath)
			for _, peer := range topo.replicas {
				if peer != id {
					doc += "    - " + localURL(peer) + "\n"
				}
			}
		}
		signerResults = append(signerResults, config.CheckSigner(id+".yaml", []byte(doc), config.CheckOptions{}))
	}
	var aggResult *config.Result[config.Aggregator]
	var aggListener net.Listener
	if !topo.peers {
		aggListener = listen(t)
		aggDoc := fmt.Sprintf(`listen_addr: %s
tls_cert_path: %s
tls_key_path: %s
replica_ca_cert_path: %s
poll_interval: 300ms
fetch_timeout: 200ms
cache_max_age: 0s
replicas:
`, aggListener.Addr(), certPath, keyPath, certPath)
		for _, id := range topo.replicas {
			aggDoc += "  - " + localURL(id) + "\n"
		}
		aggResult = config.CheckAggregator("aggregator.yaml", []byte(aggDoc), config.CheckOptions{})
		if err := aggResult.Err(); err != nil {
			t.Fatalf("configuration: %v", err)
		}
	}
	config.CrossCheck(signerResults, aggResult)
	for _, r := range signerResults {
		if err := r.Err(); err != nil {
			t.Fatalf("configuration: %v", err)
		}
		if len(r.Findings) != 0 {
			t.Fatalf("configuration warnings: %v", r.Findings)
		}
	}

	// the log handler service start installs, around the test's own
	handler, closeSink, err := auditsink.New(slog.Default().Handler(), signerResults[0].Config.Audit.Syslog)
	if err != nil {
		t.Fatalf("auditsink.New: %v", err)
	}
	previous := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() {
		// after the servers have stopped (cleanups run last-in, first-out)
		if err := closeSink(context.Background()); err != nil {
			t.Errorf("closing the syslog audit sink: %v", err)
		}
		slog.SetDefault(previous)
	})

	ctx, cancel := context.WithCancel(context.Background())
	servers := len(topo.replicas)
	done := make(chan error, servers+1)
	sys := &system{
		cloud:     cloud,
		client:    &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 10 * time.Second},
		signers:   map[string]string{},
		novaToken: cloud.IssueToken(novaUser, time.Now().Add(time.Hour)),
		caPath:    certPath,
		syslog:    daemon,
	}
	env := cloud.Env()
	creds, err := osclient.CredentialsFromEnv(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range topo.replicas {
		cfg := signerResults[i].Config
		cfg.KeyStore.RotationInterval = rotationInterval
		client, err := osclient.New(ctx, creds, cfg.Keystone.CACertPath)
		if err != nil {
			t.Fatalf("osclient.New: %v", err)
		}
		signer, err := server.NewSigner(ctx, cfg, client)
		if err != nil {
			t.Fatalf("NewSigner %s: %v", id, err)
		}
		ln := listeners[id]
		sys.signers[id] = "https://" + ln.Addr().String()
		if topo.peers {
			sys.merged = append(sys.merged, sys.signers[id]+"/.well-known/jwks.json")
		}
		go func() { done <- signer.Serve(ctx, ln) }()
	}
	if aggResult != nil {
		agg, err := server.NewAggregator(aggResult.Config)
		if err != nil {
			t.Fatalf("NewAggregator: %v", err)
		}
		sys.aggregator = "https://" + aggListener.Addr().String()
		sys.merged = append(sys.merged, sys.aggregator+"/.well-known/jwks.json")
		servers++
		go func() { done <- agg.Serve(ctx, aggListener) }()
	}

	t.Cleanup(func() {
		cancel()
		for range servers {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("server returned %v", err)
				}
			case <-time.After(20 * time.Second):
				t.Error("a server did not shut down")
				return
			}
		}
	})
	return sys
}

// newInstance registers a fresh instance of the project in Nova.
func (s *system) newInstance() string {
	id := uuid.NewV4().String()
	s.cloud.AddInstance(openstacktest.Instance{
		ID: id, ProjectID: projectID, UserID: "u1", Status: "ACTIVE", AvailabilityZone: "az-1", FlavorName: "m1.small",
	})
	return id
}

// attest posts a Nova vendordata request for the instance to a replica.
func (s *system) attest(t *testing.T, replica, token, instance string) (int, string) {
	t.Helper()
	body := `{"project-id":"` + projectID + `","instance-id":"` + instance + `","image-id":"img","hostname":"vm",` +
		`"metadata":{"role":"web"},"user-data":"I2Nsb3VkLWNvbmZpZw=="}`
	req, _ := http.NewRequest(http.MethodPost, s.signers[replica]+"/attest", strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Auth-Token", token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		t.Fatalf("attest on %s: %v", replica, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, ""
	}
	return resp.StatusCode, instanceToken(t, data)
}

// instanceToken returns the token an instance finds in vendor_data2.json for
// the issuer's /attest response body: Nova nests every DynamicJSON target's
// response under the target's name, and the agent plugin reads it back with
// iid.VendorDataResponse.
func instanceToken(t *testing.T, body []byte) string {
	t.Helper()
	vendorData := fmt.Appendf(nil, `{"static":{},%q:%s}`, iid.TargetName, body)
	var vd iid.VendorDataResponse
	if err := json.Unmarshal(vendorData, &vd); err != nil {
		t.Fatalf("decoding vendor_data2.json %s: %v", vendorData, err)
	}
	if vd.Target.JWT == "" {
		t.Fatalf("no token at %s.jwt in vendor_data2.json %s", iid.TargetName, vendorData)
	}
	return vd.Target.JWT
}

// keysAt fetches the JWK Set at url, by kid.
func (s *system) keysAt(t *testing.T, url string) map[string]keystore.PublicKey {
	t.Helper()
	resp, err := s.client.Get(url)
	if err != nil {
		t.Fatalf("fetching %s: %v", url, err)
	}
	defer resp.Body.Close()
	var set jwks.Set
	if err := json.UnmarshalRead(resp.Body, &set); err != nil {
		t.Fatalf("decoding %s: %v", url, err)
	}
	keys := map[string]keystore.PublicKey{}
	for _, k := range set.Keys {
		pub, err := k.PublicKey()
		if err != nil {
			t.Fatalf("key %s at %s: %v", k.KeyID, url, err)
		}
		keys[k.KeyID] = pub
	}
	return keys
}

// verifyEverywhere verifies the token against every merged JWK Set the SPIRE
// Server may fetch, and returns its header and claims.
func (s *system) verifyEverywhere(t *testing.T, jwt string) (iid.Header, iid.Claims) {
	t.Helper()
	var header iid.Header
	var claims iid.Claims
	for _, url := range s.merged {
		header, claims = verify(t, jwt, s.keysAt(t, url))
	}
	return header, claims
}

// verify checks the token against the keys by its header kid, as the SPIRE
// Server-side plugin does, and returns its header and claims.
func verify(t *testing.T, jwt string, keys map[string]keystore.PublicKey) (iid.Header, iid.Claims) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", jwt)
	}
	decode := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var header iid.Header
	if err := json.Unmarshal(decode(parts[0]), &header); err != nil {
		t.Fatal(err)
	}
	key, ok := keys[header.KeyID]
	if !ok {
		t.Fatalf("kid %q is not in the merged JWKS", header.KeyID)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig := decode(parts[2])
	r, sVal := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key.Key.(*ecdsa.PublicKey), digest[:], r, sVal) {
		t.Fatalf("token signed with %s does not verify against the merged JWKS", header.KeyID)
	}
	var c iid.Claims
	if err := json.Unmarshal(decode(parts[1]), &c); err != nil {
		t.Fatal(err)
	}
	return header, c
}

// mint obtains a token from a replica for a fresh instance, waiting for the
// replica's first key if needed, and checks that every merged JWK Set
// already publishes its kid: a token must never carry a kid the merged JWKS
// cannot serve yet.
func (s *system) mint(t *testing.T, replica string) (string, iid.Header, iid.Claims) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, jwt := s.attest(t, replica, s.novaToken, s.newInstance())
		if status == http.StatusOK {
			header, claims := s.verifyEverywhere(t, jwt)
			return jwt, header, claims
		}
		if status != http.StatusServiceUnavailable || time.Now().After(deadline) {
			t.Fatalf("attest on %s: status %d", replica, status)
		}
		time.Sleep(100 * time.Millisecond) // no active key yet
	}
}

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test with key rotation takes several seconds")
	}
	for _, topo := range topologies {
		t.Run(topo.name, func(t *testing.T) { testEndToEnd(t, topo) })
	}
}

func testEndToEnd(t *testing.T, topo topology) {
	s := start(t, topo)

	t.Run("required negative test", func(t *testing.T) {
		for replica := range s.signers {
			if status, _ := s.attest(t, replica, "", s.newInstance()); status != http.StatusUnauthorized {
				t.Fatalf("%s without X-Auth-Token: status %d, want 401", replica, status)
			}
		}
	})

	var tokenA string
	var headerA iid.Header
	t.Run("tokens from every replica verify against every merged set", func(t *testing.T) {
		var hb iid.Header
		var ca, cb iid.Claims
		tokenA, headerA, ca = s.mint(t, "signer-a")
		_, hb, cb = s.mint(t, "signer-b")
		for _, id := range topo.replicas[2:] {
			if _, h, _ := s.mint(t, id); !strings.Contains(h.KeyID, "-"+id+"-key-") {
				t.Fatalf("kid %q does not name %s", h.KeyID, id)
			}
		}
		if !strings.Contains(headerA.KeyID, "-signer-a-key-") || !strings.Contains(hb.KeyID, "-signer-b-key-") {
			t.Fatalf("kids %q and %q do not name their replicas", headerA.KeyID, hb.KeyID)
		}
		for _, c := range []iid.Claims{ca, cb} {
			if c.ProjectID != projectID || c.AvailabilityZone != "az-1" || c.ProjectName != "web" || c.Tags["role"] != "web" {
				t.Fatalf("claims %+v", c)
			}
		}
	})

	t.Run("per-instance rate limit, per replica", func(t *testing.T) {
		instance := s.newInstance()
		if status, _ := s.attest(t, "signer-a", s.novaToken, instance); status != http.StatusOK {
			t.Fatalf("first request: status %d", status)
		}
		if status, _ := s.attest(t, "signer-a", s.novaToken, instance); status != http.StatusTooManyRequests {
			t.Fatalf("burst on signer-a: status %d, want 429", status)
		}
		// replicas share nothing: the other replica has its own budget
		if status, _ := s.attest(t, "signer-b", s.novaToken, instance); status != http.StatusOK {
			t.Fatalf("same instance on signer-b: status %d, want 200", status)
		}
		// and other instances are unaffected
		if status, _ := s.attest(t, "signer-a", s.novaToken, s.newInstance()); status != http.StatusOK {
			t.Fatalf("other instance on signer-a: status %d, want 200", status)
		}
	})

	t.Run("key rotation drill", func(t *testing.T) {
		deadline := time.Now().Add(3 * rotationInterval)
		for {
			// every token minted during the drill is checked against the
			// aggregate at once (publication before use)
			_, header, _ := s.mint(t, "signer-a")
			if header.KeyID != headerA.KeyID {
				t.Logf("rotated from %s to %s", headerA.KeyID, header.KeyID)
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("signer-a never rotated away from %s", headerA.KeyID)
			}
			time.Sleep(200 * time.Millisecond)
		}
		// the token signed before the rotation still verifies
		s.verifyEverywhere(t, tokenA)
	})

	t.Run("local sets never carry peer keys", func(t *testing.T) {
		for id, base := range s.signers {
			for kid := range s.keysAt(t, base+"/jwks/local.json") {
				if !strings.Contains(kid, "-"+id+"-key-") {
					t.Fatalf("%s/jwks/local.json serves %s", id, kid)
				}
			}
		}
	})

	t.Run("readiness", func(t *testing.T) {
		var urls []string
		for _, id := range topo.replicas {
			urls = append(urls, s.signers[id])
		}
		if s.aggregator != "" {
			urls = append(urls, s.aggregator)
		}
		deadline := time.Now().Add(15 * time.Second)
		for _, u := range urls {
			for {
				resp, err := s.client.Get(u + "/readiness")
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s never became ready", u)
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	})
}
