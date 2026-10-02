package openstackiid

import (
	"context"
	"encoding/json/v2"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

type harness struct {
	plugin *Plugin
	clock  *fakeClock
	na     *nodeattestorv1.NodeAttestorPluginClient
	config *configv1.ConfigServiceClient
	jwks   *jwksServer
	caPath string
}

// serve runs the plugin with a fake clock at testNow, a startup watermark
// an hour earlier, and a JWKS server publishing keys.
func serve(t *testing.T, keys ...*signingKey) *harness {
	t.Helper()
	h := &harness{
		plugin: New(),
		clock:  &fakeClock{now: testNow},
		na:     new(nodeattestorv1.NodeAttestorPluginClient),
		config: new(configv1.ConfigServiceClient),
	}
	h.plugin.now = h.clock.Now
	h.plugin.replay = newReplayCache(maxReplayEntries, testNow.Add(-time.Hour))
	var public []keystore.PublicKey
	for _, k := range keys {
		public = append(public, k.public())
	}
	h.jwks = newJWKSServer(t, public...)
	h.caPath = filepath.Join(t.TempDir(), "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.jwks.Certificate().Raw})
	if err := os.WriteFile(h.caPath, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   nodeattestorv1.NodeAttestorPluginServer(h.plugin),
		PluginClient:   h.na,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(h.plugin)},
		ServiceClients: []pluginsdk.ServiceClient{h.config},
	})
	t.Cleanup(h.plugin.close)
	return h
}

func (h *harness) baseConfig() string {
	return `jwks_url = "` + h.jwks.url() + `"
jwks_ca_cert_path = "` + h.caPath + `"
`
}

func (h *harness) configure(t *testing.T, trustDomain, hcl string) error {
	t.Helper()
	_, err := h.config.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: trustDomain},
		HclConfiguration:  hcl,
	})
	return err
}

func (h *harness) mustConfigure(t *testing.T, extra string) {
	t.Helper()
	if err := h.configure(t, "example.org", h.baseConfig()+extra); err != nil {
		t.Fatalf("Configure: %v", err)
	}
}

// attestPayload runs Attest with a raw payload.
func (h *harness) attestPayload(t *testing.T, payload []byte) (*nodeattestorv1.AgentAttributes, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := h.na.Attest(ctx)
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if err := stream.Send(&nodeattestorv1.AttestRequest{Request: &nodeattestorv1.AttestRequest_Payload{Payload: payload}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetAgentAttributes(), nil
}

func (h *harness) attest(t *testing.T, token string) (*nodeattestorv1.AgentAttributes, error) {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"jwt": token})
	if err != nil {
		t.Fatal(err)
	}
	return h.attestPayload(t, payload)
}

func wantCode(t *testing.T, err error, code codes.Code, mention string) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("error = %v, want code %v", err, code)
	}
	if mention != "" && !strings.Contains(err.Error(), mention) {
		t.Fatalf("error %q does not mention %q", err, mention)
	}
}

func TestAttest(t *testing.T) {
	rs, es, _ := testKeys(t)
	h := serve(t, rs, es)
	h.mustConfigure(t, "")
	for _, key := range []*signingKey{rs, es} {
		t.Run(key.alg, func(t *testing.T) {
			claims := with(validClaims(), map[string]any{"jti": "jti-" + key.alg, "availability_zone": "az-1"})
			attrs, err := h.attest(t, sign(t, key, nil, claims))
			if err != nil {
				t.Fatalf("Attest: %v", err)
			}
			if want := "spiffe://example.org/spire/agent/openstack_iid/" + testProjectID + "/" + testInstanceID; attrs.SpiffeId != want {
				t.Fatalf("SPIFFE ID %q, want %q", attrs.SpiffeId, want)
			}
			want := []string{
				"project_id:" + testProjectID, "instance_id:" + testInstanceID, "hostname:vm-01",
				"tag:role:web", "tag:url:https://example.org:8443/", "availability_zone:az-1",
			}
			if !slices.Equal(attrs.SelectorValues, want) {
				t.Fatalf("selectors %v, want %v", attrs.SelectorValues, want)
			}
			if !attrs.CanReattest {
				t.Fatal("CanReattest is false")
			}
		})
	}
}

func TestAttestRejects(t *testing.T) {
	rs, es, other := testKeys(t)
	valid := validClaims()
	iat := valid["iat"].(int64)
	tests := []struct {
		name    string
		payload func(t *testing.T) []byte
		code    codes.Code
		mention string
	}{
		{"malformed payload", func(t *testing.T) []byte { return []byte(`{"jwt":`) }, codes.InvalidArgument, "payload"},
		{"no jwt", func(t *testing.T) []byte { return []byte(`{}`) }, codes.InvalidArgument, "jwt"},
		{"payload over the limit", func(t *testing.T) []byte {
			return []byte(`{"jwt":"` + strings.Repeat("a", iid.MaxTokenBytes+1024) + `"}`)
		}, codes.InvalidArgument, "bytes"},
		// required negative test: a valid key, but not in the JWK Set
		{"key not in the set", func(t *testing.T) []byte { return tokenPayload(t, sign(t, other, nil, valid)) }, codes.PermissionDenied, "kid"},
		{"alg none", func(t *testing.T) []byte {
			hdr := b64(mustJSON(t, map[string]any{"alg": "none", "kid": es.kid}))
			return tokenPayload(t, hdr+"."+b64(mustJSON(t, valid))+".")
		}, codes.PermissionDenied, "algorithm"},
		{"tampered signature", func(t *testing.T) []byte {
			tok := sign(t, es, nil, valid)
			return tokenPayload(t, tok[:len(tok)-2]+"AA")
		}, codes.PermissionDenied, "signature"},
		{"expired", func(t *testing.T) []byte {
			return tokenPayload(t, sign(t, es, nil, with(valid, map[string]any{"iat": iat - 900, "nbf": iat - 900, "exp": iat - 600})))
		}, codes.PermissionDenied, "expired"},
		{"wrong aud", func(t *testing.T) []byte {
			return tokenPayload(t, sign(t, rs, nil, with(valid, map[string]any{"aud": "x"})))
		}, codes.PermissionDenied, "audience"},
		{"wrong iss", func(t *testing.T) []byte {
			return tokenPayload(t, sign(t, rs, nil, with(valid, map[string]any{"iss": "x"})))
		}, codes.PermissionDenied, "issuer"},
		{"tag key with ':'", func(t *testing.T) []byte {
			return tokenPayload(t, sign(t, es, nil, with(valid, map[string]any{"tags": map[string]any{"a:b": "c"}})))
		}, codes.PermissionDenied, "tag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := serve(t, rs, es)
			h.mustConfigure(t, "")
			attrs, err := h.attestPayload(t, tt.payload(t))
			if err == nil {
				t.Fatalf("attested as %v", attrs)
			}
			wantCode(t, err, tt.code, tt.mention)
		})
	}
}

func tokenPayload(t *testing.T, token string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"jwt": token})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// required negative test: a project outside allowed_project_ids
func TestAttestUnlistedProject(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, `allowed_project_ids = ["`+strings.Repeat("a", 32)+`", "e5f6"]`)
	_, err := h.attest(t, sign(t, es, nil, validClaims()))
	wantCode(t, err, codes.PermissionDenied, testProjectID)

	h.mustConfigure(t, `allowed_project_ids = ["e5f6", "`+testProjectID+`"]`)
	if _, err := h.attest(t, sign(t, es, nil, validClaims())); err != nil {
		t.Fatalf("listed project rejected: %v", err)
	}
}

// required negative test: a token is accepted once
func TestAttestReplay(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, "")
	token := sign(t, es, nil, validClaims())
	if _, err := h.attest(t, token); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := h.attest(t, token)
	wantCode(t, err, codes.PermissionDenied, "already used")

	// a reconfiguration keeps the cache
	h.mustConfigure(t, "clock_skew_tolerance = \"10s\"")
	_, err = h.attest(t, token)
	wantCode(t, err, codes.PermissionDenied, "already used")
}

func TestAttestRejectedTokenNotRecorded(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.mustConfigure(t, `allowed_project_ids = ["e5f6"]`)
	token := sign(t, es, nil, validClaims())
	if _, err := h.attest(t, token); err == nil {
		t.Fatal("unlisted project accepted")
	}
	h.mustConfigure(t, "")
	if _, err := h.attest(t, token); err != nil {
		t.Fatalf("token rejected earlier for another reason is now refused: %v", err)
	}
}

func TestAttestStartupWatermark(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.plugin.replay = newReplayCache(maxReplayEntries, testNow.Add(-15*time.Second))
	h.mustConfigure(t, "")
	// validClaims are issued 10s before testNow: after the start, but within
	// the tolerance, so possibly before it on the issuer's clock
	_, err := h.attest(t, sign(t, es, nil, validClaims()))
	wantCode(t, err, codes.PermissionDenied, "before this server started")

	fresh := testNow.Add(20 * time.Second).Unix()
	if _, err := h.attest(t, sign(t, es, nil, with(validClaims(), map[string]any{"iat": fresh, "nbf": fresh, "exp": fresh + 300}))); err != nil {
		t.Fatalf("token minted after start + tolerance rejected: %v", err)
	}
}

func TestAttestReplayCacheFull(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.plugin.replay = newReplayCache(1, testNow.Add(-time.Hour))
	h.mustConfigure(t, "")
	if _, err := h.attest(t, sign(t, es, nil, validClaims())); err != nil {
		t.Fatal(err)
	}
	_, err := h.attest(t, sign(t, es, nil, with(validClaims(), map[string]any{"jti": "another"})))
	wantCode(t, err, codes.Unavailable, "replay cache full")
}

func TestAttestUnknownKIDRecoveredByRefetch(t *testing.T) {
	rs, es, _ := testKeys(t)
	h := serve(t, rs)
	h.mustConfigure(t, "")
	waitForKeys(t, h)
	// a key published after the last poll (refresh is 30s)
	h.jwks.publish(t, rs.public(), es.public())
	h.clock.Advance(5 * time.Second)
	if _, err := h.attest(t, sign(t, es, nil, validClaims())); err != nil {
		t.Fatalf("token with a newly published kid rejected: %v", err)
	}
}

func TestAttestWithoutKeys(t *testing.T) {
	_, es, _ := testKeys(t)
	h := serve(t, es)
	h.jwks.serve(http.StatusServiceUnavailable, nil)
	h.mustConfigure(t, "")
	_, err := h.attest(t, sign(t, es, nil, validClaims()))
	wantCode(t, err, codes.Unavailable, "no verification keys")
}

// waitForKeys waits for the background poll after Configure.
func waitForKeys(t *testing.T, h *harness) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := h.plugin.getSettings()
		if err != nil {
			t.Fatal(err)
		}
		if keys, _ := s.keys.keys(context.Background()); len(keys) > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no keys fetched within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestAttestNotConfigured(t *testing.T) {
	h := serve(t)
	_, err := h.attest(t, "a.b.c")
	wantCode(t, err, codes.FailedPrecondition, "")
}

func TestConfigureDefaults(t *testing.T) {
	h := serve(t)
	h.mustConfigure(t, "")
	s, err := h.plugin.getSettings()
	if err != nil {
		t.Fatal(err)
	}
	if s.trustDomain != "example.org" || s.skew != 30*time.Second || s.allowedProjects != nil {
		t.Fatalf("settings %+v", s)
	}
}

func TestConfigureErrors(t *testing.T) {
	h := serve(t)
	base := h.baseConfig()
	tests := []struct {
		name        string
		trustDomain string
		hcl         string
		want        string
	}{
		{"no trust domain", "", base, "trust domain"},
		{"bad trust domain", "Example.ORG", base, "trust domain"},
		{"unknown key", "example.org", base + "trust_domain = \"example.org\"\n", "trust_domain"},
		{"no jwks_url", "example.org", "", "jwks_url"},
		{"http jwks_url", "example.org", strings.Replace(base, "https://", "http://", 1), "jwks_url"},
		{"local JWK Set", "example.org", strings.Replace(base, "/.well-known/jwks.json", "/jwks/local.json", 1), "jwks_url"},
		{"missing CA", "example.org", strings.Replace(base, h.caPath, "/nonexistent/ca.pem", 1), "jwks_ca_cert_path"},
		{"bad TLS version", "example.org", base + "tls_min_version = \"1.1\"\n", "tls_min_version"},
		{"fetch timeout not below refresh", "example.org", base + "jwks_refresh_interval = \"5s\"\njwks_fetch_timeout = \"5s\"\n", "jwks_fetch_timeout"},
		{"bad refresh", "example.org", base + "jwks_refresh_interval = \"often\"\n", "jwks_refresh_interval"},
		{"refetch interval zero", "example.org", base + "jwks_min_refetch_interval = \"0s\"\n", "jwks_min_refetch_interval"},
		{"retention below 5m", "example.org", base + "jwks_stale_key_retention = \"4m\"\n", "jwks_stale_key_retention"},
		{"skew over 60s", "example.org", base + "clock_skew_tolerance = \"61s\"\n", "clock_skew_tolerance"},
		{"bad project", "example.org", base + "allowed_project_ids = [\"a/b\"]\n", "allowed_project_ids"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.configure(t, tt.trustDomain, tt.hcl)
			wantCode(t, err, codes.InvalidArgument, tt.want)
		})
	}
}
