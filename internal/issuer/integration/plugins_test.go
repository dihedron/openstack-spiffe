package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	agentv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	serverv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	agentplugin "github.com/dihedron/openstack-spiffe/internal/plugin/agent/openstackiid"
	serverplugin "github.com/dihedron/openstack-spiffe/internal/plugin/server/openstackiid"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// metadataService plays nova-api-metadata for one instance: it serves the
// token the signer last issued, as Nova's metadata cache would.
type metadataService struct {
	*httptest.Server
	mu    sync.Mutex
	token string
}

func newMetadataService(t *testing.T) *metadataService {
	t.Helper()
	m := &metadataService{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		token := m.token
		m.mu.Unlock()
		fmt.Fprintf(w, `{"%s":{"jwt":%q}}`, iid.TargetName, token)
	}))
	t.Cleanup(m.Close)
	return m
}

func (m *metadataService) serve(token string) {
	m.mu.Lock()
	m.token = token
	m.mu.Unlock()
}

// spire runs the agent and server plugins as SPIRE Agent and SPIRE Server
// would load them, and relays the attestation between them.
type spire struct {
	agent        *agentv1.NodeAttestorPluginClient
	server       *serverv1.NodeAttestorPluginClient
	agentConfig  *configv1.ConfigServiceClient
	serverConfig *configv1.ConfigServiceClient
}

func startPlugins(t *testing.T, s *system, metadataURL string) *spire {
	t.Helper()
	sp := &spire{
		agent: new(agentv1.NodeAttestorPluginClient), server: new(serverv1.NodeAttestorPluginClient),
		agentConfig: new(configv1.ConfigServiceClient), serverConfig: new(configv1.ConfigServiceClient),
	}
	agent, server := agentplugin.New(), serverplugin.New()
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   agentv1.NodeAttestorPluginServer(agent),
		PluginClient:   sp.agent,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(agent)},
		ServiceClients: []pluginsdk.ServiceClient{sp.agentConfig},
	})
	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer:   serverv1.NodeAttestorPluginServer(server),
		PluginClient:   sp.server,
		ServiceServers: []pluginsdk.ServiceServer{configv1.ConfigServiceServer(server)},
		ServiceClients: []pluginsdk.ServiceClient{sp.serverConfig},
	})

	ctx := context.Background()
	core := &configv1.CoreConfiguration{TrustDomain: "example.org"}
	if _, err := sp.agentConfig.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: core,
		HclConfiguration:  fmt.Sprintf("vendordata_url = %q\nfresh_token_timeout = \"10s\"\n", metadataURL),
	}); err != nil {
		t.Fatalf("configuring the agent plugin: %v", err)
	}
	// the server plugin rejects tokens minted before its process started
	// plus the tolerance: the signers share this host's clock, so no
	// tolerance is needed, and their first token comes after publish_ahead
	if _, err := sp.serverConfig.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: core,
		HclConfiguration: fmt.Sprintf("jwks_url = %q\njwks_ca_cert_path = %q\nclock_skew_tolerance = \"0s\"\nallowed_project_ids = [%q]\n",
			s.merged[0], s.caPath, projectID),
	}); err != nil {
		t.Fatalf("configuring the server plugin: %v", err)
	}
	return sp
}

// attestAgent runs the agent plugin, as SPIRE Agent does, and returns the
// payload it produced.
func (sp *spire) attestAgent(t *testing.T) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := sp.agent.AidAttestation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetPayload(), nil
}

// attestServer runs the server plugin on a payload, as SPIRE Server does.
func (sp *spire) attestServer(t *testing.T, payload []byte) (*serverv1.AgentAttributes, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := sp.server.Attest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&serverv1.AttestRequest{Request: &serverv1.AttestRequest_Payload{Payload: payload}}); err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	return resp.GetAgentAttributes(), nil
}

func (sp *spire) attest(t *testing.T) *serverv1.AgentAttributes {
	t.Helper()
	payload, err := sp.attestAgent(t)
	if err != nil {
		t.Fatalf("agent plugin: %v", err)
	}
	attrs, err := sp.attestServer(t, payload)
	if err != nil {
		t.Fatalf("server plugin: %v", err)
	}
	return attrs
}

func checkAttributes(t *testing.T, attrs *serverv1.AgentAttributes, c iid.Claims) {
	t.Helper()
	if want := "spiffe://example.org/spire/agent/openstack_iid/" + projectID + "/" + c.InstanceID; attrs.SpiffeId != want {
		t.Fatalf("SPIFFE ID %q, want %q", attrs.SpiffeId, want)
	}
	want := []string{
		"project_id:" + projectID, "instance_id:" + c.InstanceID, "hostname:vm",
		"tag:role:web", "availability_zone:az-1", "project_name:web",
	}
	if !slices.Equal(attrs.SelectorValues, want) {
		t.Fatalf("selectors %v, want %v", attrs.SelectorValues, want)
	}
	if !attrs.CanReattest {
		t.Fatal("CanReattest is false")
	}
}

func TestPluginsEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test with key rotation takes several seconds")
	}
	for _, topo := range topologies {
		t.Run(topo.name, func(t *testing.T) { testPluginsEndToEnd(t, topo) })
	}
}

func testPluginsEndToEnd(t *testing.T, topo topology) {
	s := start(t, topo)
	metadata := newMetadataService(t)
	sp := startPlugins(t, s, metadata.URL+"/openstack/latest/vendor_data2.json")

	var first string
	t.Run("token from every replica attests", func(t *testing.T) {
		for _, replica := range topo.replicas {
			token, _, c := s.mint(t, replica)
			if first == "" {
				first = token
			}
			metadata.serve(token)
			checkAttributes(t, sp.attest(t), c)
		}
	})

	t.Run("a token is accepted once", func(t *testing.T) {
		payload := fmt.Appendf(nil, `{"jwt":%q}`, first)
		_, err := sp.attestServer(t, payload)
		if err == nil || !strings.Contains(err.Error(), "already used") {
			t.Fatalf("replayed token: error %v, want already used", err)
		}
	})

	t.Run("the agent waits for a fresh token", func(t *testing.T) {
		// the metadata service still serves the token presented last, then,
		// as Nova's cache expires, a fresh one
		fresh, _, _ := s.mint(t, topo.replicas[0])
		stale := make(chan struct{})
		go func() {
			defer close(stale)
			time.Sleep(1500 * time.Millisecond)
			metadata.serve(fresh)
		}()
		start := time.Now()
		payload, err := sp.attestAgent(t)
		<-stale
		if err != nil {
			t.Fatalf("agent plugin: %v", err)
		}
		if time.Since(start) < time.Second {
			t.Fatal("the agent did not wait for a fresh token")
		}
		if _, err := sp.attestServer(t, payload); err != nil {
			t.Fatalf("server plugin rejected the fresh token: %v", err)
		}
	})

	t.Run("key rotation drill", func(t *testing.T) {
		before, hb, cb := s.mint(t, topo.replicas[0])
		time.Sleep(rotationInterval + time.Second)
		after, ha, ca := s.mint(t, topo.replicas[0])
		if ha.KeyID == hb.KeyID {
			t.Fatalf("kid %q unchanged after a rotation", ha.KeyID)
		}
		// the new kid was published after the server plugin's last poll:
		// its re-fetch on an unknown kid picks it up
		metadata.serve(after)
		checkAttributes(t, sp.attest(t), ca)
		// a token signed just before the rotation still attests
		metadata.serve(before)
		checkAttributes(t, sp.attest(t), cb)
	})
}
