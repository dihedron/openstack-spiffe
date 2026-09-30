// Package integration runs the whole system end to end: two signer replicas
// and one JWKS aggregator, over TLS on loopback listeners, against a fake
// OpenStack control plane. It checks the acceptance criteria that only hold
// for the system as a whole: tokens from either replica verify against the
// aggregated JWKS by kid, every kid is published by the aggregator before
// its first use, and tokens signed before a rotation keep verifying after it.
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
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/config"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/jwks"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/keystore"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/openstacktest"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/osclient"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/server"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	projectID = "f3c9a1d2b4e54a6b8c7d9e0f1a2b3c4d"
	// publishAhead exceeds the aggregator's poll_interval + fetch_timeout
	// (300ms + 200ms), as the cross-file check requires.
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

// system is a running deployment.
type system struct {
	cloud      *openstacktest.Server
	client     *http.Client
	signers    map[string]string // replica ID -> base URL
	aggregator string            // base URL
	novaToken  string
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

// start deploys two signer replicas and an aggregator polling them.
func start(t *testing.T) *system {
	t.Helper()
	cloud := openstacktest.New(t)
	cloud.AddProject(openstacktest.Project{ID: projectID, Name: "web", DomainID: "default"})
	certPath, keyPath, pool := writeTLS(t)

	replicaIDs := []string{"signer-a", "signer-b"}
	listeners := map[string]net.Listener{"signer-a": listen(t), "signer-b": listen(t)}
	aggListener := listen(t)

	var signerResults []*config.Result[config.Signer]
	for _, id := range replicaIDs {
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
  allowed_users: [nova@Default]
  ca_cert_path: %s
enrich: [availability_zone, project_name]
`, listeners[id].Addr(), certPath, keyPath, id, publishAhead, cloud.CAFile(t))
		signerResults = append(signerResults, config.CheckSigner(id+".yaml", []byte(doc), config.CheckOptions{}))
	}
	aggDoc := fmt.Sprintf(`listen_addr: %s
tls_cert_path: %s
tls_key_path: %s
replica_ca_cert_path: %s
poll_interval: 300ms
fetch_timeout: 200ms
replicas:
  - https://%s/.well-known/jwks.json
  - https://%s/.well-known/jwks.json
`, aggListener.Addr(), certPath, keyPath, certPath, listeners["signer-a"].Addr(), listeners["signer-b"].Addr())
	aggResult := config.CheckAggregator("aggregator.yaml", []byte(aggDoc), config.CheckOptions{})
	config.CrossCheck(signerResults, aggResult)
	for _, r := range append([]error{aggResult.Err()}, signerResults[0].Err(), signerResults[1].Err()) {
		if r != nil {
			t.Fatalf("configuration: %v", r)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 3)
	sys := &system{
		cloud:      cloud,
		client:     &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 10 * time.Second},
		signers:    map[string]string{},
		aggregator: "https://" + aggListener.Addr().String(),
		novaToken:  cloud.IssueToken(novaUser, time.Now().Add(time.Hour)),
	}
	env := cloud.Env()
	creds, err := osclient.CredentialsFromEnv(func(name string) string { return env[name] })
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range replicaIDs {
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
		go func() { done <- signer.Serve(ctx, ln) }()
	}
	agg, err := server.NewAggregator(aggResult.Config)
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	go func() { done <- agg.Serve(ctx, aggListener) }()

	t.Cleanup(func() {
		cancel()
		for range 3 {
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
	var vd iid.VendorDataResponse
	if err := json.Unmarshal(data, &vd); err != nil {
		t.Fatalf("decoding %s: %v", data, err)
	}
	return resp.StatusCode, vd.Target.JWT
}

// aggregated fetches the aggregator's JWK Set, by kid.
func (s *system) aggregated(t *testing.T) map[string]keystore.PublicKey {
	t.Helper()
	resp, err := s.client.Get(s.aggregator + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("fetching the aggregated JWKS: %v", err)
	}
	defer resp.Body.Close()
	var set jwks.Set
	if err := json.UnmarshalRead(resp.Body, &set); err != nil {
		t.Fatalf("decoding the aggregated JWKS: %v", err)
	}
	keys := map[string]keystore.PublicKey{}
	for _, k := range set.Keys {
		pub, err := k.PublicKey()
		if err != nil {
			t.Fatalf("aggregated key %s: %v", k.KeyID, err)
		}
		keys[k.KeyID] = pub
	}
	return keys
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
		t.Fatalf("kid %q is not in the aggregated JWKS", header.KeyID)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig := decode(parts[2])
	r, sVal := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key.Key.(*ecdsa.PublicKey), digest[:], r, sVal) {
		t.Fatalf("token signed with %s does not verify against the aggregated JWKS", header.KeyID)
	}
	var c iid.Claims
	if err := json.Unmarshal(decode(parts[1]), &c); err != nil {
		t.Fatal(err)
	}
	return header, c
}

// mint obtains a token from a replica for a fresh instance, waiting for the
// replica's first key if needed, and checks that the aggregator already
// publishes its kid: a token must never carry a kid the aggregated JWKS
// cannot serve yet.
func (s *system) mint(t *testing.T, replica string) (string, iid.Header, iid.Claims) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status, jwt := s.attest(t, replica, s.novaToken, s.newInstance())
		if status == http.StatusOK {
			header, claims := verify(t, jwt, s.aggregated(t))
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
	s := start(t)

	t.Run("required negative test", func(t *testing.T) {
		for replica := range s.signers {
			if status, _ := s.attest(t, replica, "", s.newInstance()); status != http.StatusUnauthorized {
				t.Fatalf("%s without X-Auth-Token: status %d, want 401", replica, status)
			}
		}
	})

	var tokenA string
	var headerA iid.Header
	t.Run("tokens from either replica verify against the aggregate", func(t *testing.T) {
		var hb iid.Header
		var ca, cb iid.Claims
		tokenA, headerA, ca = s.mint(t, "signer-a")
		_, hb, cb = s.mint(t, "signer-b")
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
		verify(t, tokenA, s.aggregated(t))
	})

	t.Run("readiness", func(t *testing.T) {
		urls := []string{s.signers["signer-a"], s.signers["signer-b"], s.aggregator}
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
