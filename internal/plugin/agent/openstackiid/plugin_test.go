package openstackiid

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// fakeToken returns a compact JWS-shaped token carrying the given jti; the
// agent never verifies signatures, so the signature is a placeholder.
func fakeToken(jti string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","kid":"k","typ":"JWT"}`)) + "." +
		enc([]byte(`{"jti":"`+jti+`","sub":"i"}`)) + "." + enc([]byte("signature"))
}

func vendorData(token string) string {
	return `{"static":{"x":1},"` + iid.TargetName + `":{"jwt":"` + token + `"}}`
}

// metadataServer serves vendor_data2.json; the handler can be swapped by the
// test while the server runs.
type metadataServer struct {
	*httptest.Server
	mu       sync.Mutex
	handler  http.HandlerFunc
	requests atomic.Int32
}

func newMetadataServer(t *testing.T, body string) *metadataServer {
	t.Helper()
	m := &metadataServer{}
	m.serve(body)
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		m.mu.Lock()
		h := m.handler
		m.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *metadataServer) serve(body string) {
	m.handle(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	})
}

func (m *metadataServer) handle(h http.HandlerFunc) {
	m.mu.Lock()
	m.handler = h
	m.mu.Unlock()
}

func (m *metadataServer) url() string { return m.URL + "/openstack/latest/vendor_data2.json" }

type harness struct {
	plugin *Plugin
	na     *nodeattestorv1.NodeAttestorPluginClient
	config *configv1.ConfigServiceClient
}

func serve(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		plugin: New(),
		na:     new(nodeattestorv1.NodeAttestorPluginClient),
		config: new(configv1.ConfigServiceClient),
	}
	h.plugin.pollInterval = 10 * time.Millisecond
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   nodeattestorv1.NodeAttestorPluginServer(h.plugin),
		PluginClient:   h.na,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(h.plugin)},
		ServiceClients: []pluginsdk.ServiceClient{h.config},
	})
	return h
}

func (h *harness) configure(t *testing.T, hcl string) error {
	t.Helper()
	_, err := h.config.Configure(context.Background(), &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  hcl,
	})
	return err
}

func (h *harness) mustConfigure(t *testing.T, hcl string) {
	t.Helper()
	if err := h.configure(t, hcl); err != nil {
		t.Fatalf("Configure: %v", err)
	}
}

// attest runs AidAttestation and returns the JWT sent as payload.
func (h *harness) attest(t *testing.T) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := h.na.AidAttestation(ctx)
	if err != nil {
		t.Fatalf("AidAttestation: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return "", err
	}
	var payload struct {
		JWT string `json:"jwt"`
	}
	if err := json.Unmarshal(resp.GetPayload(), &payload, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("payload %q: %v", resp.GetPayload(), err)
	}
	return payload.JWT, nil
}

func urlConfig(m *metadataServer) string {
	return `vendordata_url = "` + m.url() + `"`
}

func TestAttestationSendsToken(t *testing.T) {
	token := fakeToken("jti-1")
	m := newMetadataServer(t, vendorData(token))
	h := serve(t)
	h.mustConfigure(t, urlConfig(m))

	got, err := h.attest(t)
	if err != nil {
		t.Fatalf("attestation failed: %v", err)
	}
	if got != token {
		t.Fatalf("payload jwt = %q, want %q", got, token)
	}
}

func TestEveryAttestationFetchesAnew(t *testing.T) {
	m := newMetadataServer(t, vendorData(fakeToken("jti-1")))
	h := serve(t)
	h.mustConfigure(t, urlConfig(m))
	for i := 1; i <= 3; i++ {
		token := fakeToken(fmt.Sprintf("jti-%d", i))
		m.serve(vendorData(token))
		if got, err := h.attest(t); err != nil || got != token {
			t.Fatalf("attestation %d = %q, %v; want %q", i, got, err, token)
		}
	}
	if n := m.requests.Load(); n != 3 {
		t.Fatalf("%d vendordata requests, want 3 (no caching)", n)
	}
}

func TestAttestationFailures(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    string
	}{
		{"server error", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "oops", http.StatusInternalServerError)
		}, "500"},
		{"redirect not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		}, "302"},
		{"malformed JSON", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, `{"openstack_iid":`)
		}, "decoding"},
		{"target missing", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, `{"static":{}}`)
		}, "openstack_iid"},
		{"no jwt", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, `{"openstack_iid":{}}`)
		}, "token"},
		{"not a compact JWS", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, vendorData("abc.def"))
		}, "compact"},
		{"empty segment", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, vendorData("abc..def"))
		}, "compact"},
		{"token too large", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, vendorData(fakeToken(strings.Repeat("x", iid.MaxTokenBytes))))
		}, "bytes"},
		{"payload without jti", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, vendorData(fakeToken("")))
		}, "jti"},
		{"document too large", func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, `{"pad":"`+strings.Repeat("x", maxDocumentBytes)+`"}`)
		}, "larger"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newMetadataServer(t, "")
			m.handle(tt.handler)
			h := serve(t)
			h.mustConfigure(t, urlConfig(m))
			got, err := h.attest(t)
			if err == nil {
				t.Fatalf("attestation sent %q, want an error mentioning %q", got, tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestAttestationTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	m := newMetadataServer(t, "")
	m.handle(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	h := serve(t)
	h.mustConfigure(t, urlConfig(m)+"\nhttp_timeout = \"100ms\"\nfresh_token_timeout = \"100ms\"")
	start := time.Now()
	if _, err := h.attest(t); err == nil {
		t.Fatal("attestation succeeded against a hanging metadata service")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("attestation took %v, want about http_timeout", elapsed)
	}
}

func TestSameTokenIsNeverPresentedTwice(t *testing.T) {
	first, second := fakeToken("jti-1"), fakeToken("jti-2")
	m := newMetadataServer(t, vendorData(first))
	h := serve(t)
	h.mustConfigure(t, urlConfig(m))
	if got, err := h.attest(t); err != nil || got != first {
		t.Fatalf("first attestation = %q, %v; want the first token", got, err)
	}

	// Nova's metadata cache keeps serving the first token for a while
	var served atomic.Int32
	m.handle(func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1) <= 3 {
			_, _ = fmt.Fprint(w, vendorData(first))
			return
		}
		_, _ = fmt.Fprint(w, vendorData(second))
	})
	got, err := h.attest(t)
	if err != nil || got != second {
		t.Fatalf("second attestation = %q, %v; want the fresh token", got, err)
	}
	if n := served.Load(); n != 4 {
		t.Fatalf("%d fetches for the second attestation, want 4 (3 stale, 1 fresh)", n)
	}
}

func TestStaleTokenTimeout(t *testing.T) {
	token := fakeToken("jti-1")
	m := newMetadataServer(t, vendorData(token))
	h := serve(t)
	h.mustConfigure(t, urlConfig(m)+"\nhttp_timeout = \"100ms\"\nfresh_token_timeout = \"200ms\"")
	if _, err := h.attest(t); err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	_, err := h.attest(t)
	if err == nil || !strings.Contains(err.Error(), "already presented") {
		t.Fatalf("second attestation error = %v, want the already-presented token error", err)
	}
}

func TestErrorWhileWaitingIsReturnedAtOnce(t *testing.T) {
	token := fakeToken("jti-1")
	m := newMetadataServer(t, vendorData(token))
	h := serve(t)
	h.mustConfigure(t, urlConfig(m))
	if _, err := h.attest(t); err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	var served atomic.Int32
	m.handle(func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1) == 1 {
			_, _ = fmt.Fprint(w, vendorData(token))
			return
		}
		http.Error(w, "oops", http.StatusInternalServerError)
	})
	_, err := h.attest(t)
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want the fetch error", err)
	}
	if n := served.Load(); n != 2 {
		t.Fatalf("%d fetches, want 2: no retry after an error", n)
	}
}

func TestPresentedTokenIsRecorded(t *testing.T) {
	// a token different from the last presented one is sent at once, and
	// becomes the last presented one
	token := fakeToken("jti-1")
	m := newMetadataServer(t, vendorData(token))
	h := serve(t)
	h.mustConfigure(t, urlConfig(m))
	h.plugin.mu.Lock()
	h.plugin.lastJTI = "jti-0"
	h.plugin.mu.Unlock()
	if got, err := h.attest(t); err != nil || got != token {
		t.Fatalf("attestation = %q, %v", got, err)
	}
	h.plugin.mu.Lock()
	last := h.plugin.lastJTI
	h.plugin.mu.Unlock()
	if last != "jti-1" {
		t.Fatalf("last presented jti = %q, want jti-1", last)
	}
}

func TestNotConfigured(t *testing.T) {
	h := serve(t)
	_, err := h.attest(t)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("error = %v, want FailedPrecondition", err)
	}
}

func TestConfigure(t *testing.T) {
	h := serve(t)
	h.mustConfigure(t, "")
	s, err := h.plugin.getSettings()
	if err != nil {
		t.Fatal(err)
	}
	if s.url != DefaultVendorDataURL || s.httpTimeout != 5*time.Second || s.freshTokenTimeout != 30*time.Second {
		t.Fatalf("defaults = %+v", s)
	}
}

func TestConfigureErrors(t *testing.T) {
	tests := []struct {
		hcl  string
		want string
	}{
		{`bogus = 1`, "bogus"},
		{`vendordata_url = "ftp://169.254.169.254/x"`, "vendordata_url"},
		{`vendordata_url = "http://"`, "vendordata_url"},
		{`vendordata_url = "::"`, "vendordata_url"},
		{`http_timeout = "fast"`, "http_timeout"},
		{`http_timeout = "0s"`, "http_timeout"},
		{`fresh_token_timeout = "-1s"`, "fresh_token_timeout"},
		{"http_timeout = \"10s\"\nfresh_token_timeout = \"5s\"", "fresh_token_timeout"},
		{`vendordata_url = `, ""}, // HCL v1 accepts an empty value: the default applies
	}
	for _, tt := range tests {
		t.Run(tt.hcl, func(t *testing.T) {
			h := serve(t)
			err := h.configure(t, tt.hcl)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Configure: %v", err)
				}
				return
			}
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Configure error = %v, want InvalidArgument naming %q", err, tt.want)
			}
		})
	}
}

func TestReconfigureKeepsLastPresentedToken(t *testing.T) {
	token := fakeToken("jti-1")
	m := newMetadataServer(t, vendorData(token))
	h := serve(t)
	h.mustConfigure(t, urlConfig(m))
	if _, err := h.attest(t); err != nil {
		t.Fatal(err)
	}
	h.mustConfigure(t, urlConfig(m)+"\nhttp_timeout = \"100ms\"\nfresh_token_timeout = \"100ms\"")
	if _, err := h.attest(t); err == nil {
		t.Fatal("same token presented again after a reconfiguration")
	}
}
