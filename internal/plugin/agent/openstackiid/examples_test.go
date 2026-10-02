package openstackiid

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dihedron/openstack-spiffe/internal/plugin/config"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

func TestExampleConfiguration(t *testing.T) {
	conf, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "examples", "agent.conf"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := config.PluginData(conf, "NodeAttestor", iid.TargetName)
	if err != nil {
		t.Fatal(err)
	}
	s, err := parseConfig(data)
	if err != nil {
		t.Fatalf("examples/agent.conf: %v", err)
	}
	if s.url != DefaultVendorDataURL {
		t.Fatalf("examples/agent.conf: vendordata_url %q, want the default %q", s.url, DefaultVendorDataURL)
	}
}
