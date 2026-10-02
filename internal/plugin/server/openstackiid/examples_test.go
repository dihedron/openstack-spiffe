package openstackiid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/dihedron/openstack-spiffe/internal/plugin/config"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

func TestExampleConfiguration(t *testing.T) {
	conf, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "examples", "server.conf"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := config.PluginData(conf, "NodeAttestor", iid.TargetName)
	if err != nil {
		t.Fatal(err)
	}
	// the sample's CA bundle does not exist here: use a test one
	h := serve(t)
	data = strings.Replace(data, "/etc/ssl/openstack-metadata-ca.pem", h.caPath, 1)
	p := New()
	s, err := p.parseConfig(&configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  data,
	})
	if err != nil {
		t.Fatalf("examples/server.conf: %v", err)
	}
	s.keys.close()
	if len(s.allowedProjects) != 2 {
		t.Fatalf("examples/server.conf: allowed projects %v", s.allowedProjects)
	}
}
