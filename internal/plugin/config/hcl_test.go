package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type sample struct {
	URL     string   `hcl:"url"`
	Timeout string   `hcl:"timeout"`
	IDs     []string `hcl:"ids"`
}

var sampleKeys = []string{"url", "timeout", "ids"}

func TestDecode(t *testing.T) {
	var s sample
	err := Decode(`
url     = "https://example.org"
timeout = "5s"
ids     = ["a", "b"]
`, &s, sampleKeys)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.URL != "https://example.org" || s.Timeout != "5s" || len(s.IDs) != 2 {
		t.Fatalf("decoded %+v", s)
	}
}

func TestDecodeJSON(t *testing.T) {
	// SPIRE may hand over plugin_data as JSON, which HCL v1 also parses
	var s sample
	if err := Decode(`{"url": "https://example.org"}`, &s, sampleKeys); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if s.URL != "https://example.org" {
		t.Fatalf("decoded %+v", s)
	}
}

func TestDecodeEmpty(t *testing.T) {
	var s sample
	if err := Decode("", &s, sampleKeys); err != nil {
		t.Fatalf("Decode of empty configuration: %v", err)
	}
}

func TestDecodeUnknownKeys(t *testing.T) {
	var s sample
	err := Decode("url = \"x\"\ntimout = \"5s\"\nbogus = 1\n", &s, sampleKeys)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v, want ErrInvalid", err)
	}
	for _, key := range []string{"timout", "bogus"} {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error %q does not name unknown key %q", err, key)
		}
	}
}

func TestDecodeMalformed(t *testing.T) {
	var s sample
	for _, doc := range []string{`url = "unterminated`, `url = ["a"`, `ids = "not a list"`} {
		if err := Decode(doc, &s, sampleKeys); !errors.Is(err, ErrInvalid) {
			t.Errorf("Decode(%q) = %v, want ErrInvalid", doc, err)
		}
	}
}

func TestDuration(t *testing.T) {
	tests := []struct {
		value   string
		min     time.Duration
		max     time.Duration
		want    time.Duration
		wantErr bool
	}{
		{"", time.Second, time.Minute, 30 * time.Second, false}, // default
		{"5s", time.Second, time.Minute, 5 * time.Second, false},
		{"1m", time.Second, time.Minute, time.Minute, false},
		{"61s", time.Second, time.Minute, 0, true},
		{"500ms", time.Second, time.Minute, 0, true},
		{"0s", time.Second, time.Minute, 0, true},
		{"-5s", time.Second, time.Minute, 0, true},
		{"5", time.Second, time.Minute, 0, true},
		{"5s", time.Second, 0, 5 * time.Second, false}, // no maximum
	}
	for _, tt := range tests {
		got, err := Duration("timeout", tt.value, 30*time.Second, tt.min, tt.max)
		if tt.wantErr {
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "timeout") {
				t.Errorf("Duration(%q) = %v, %v; want an ErrInvalid naming the key", tt.value, got, err)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("Duration(%q) = %v, %v; want %v", tt.value, got, err, tt.want)
		}
	}
}

func TestPluginData(t *testing.T) {
	conf := `
agent {
  data_dir = "/opt/spire/data/agent"
}
plugins {
  KeyManager "disk" {
    plugin_data {
      directory = "/opt/spire/data/agent"
    }
  }
  NodeAttestor "openstack_iid" {
    plugin_cmd = "/usr/bin/openstack-agent-plugin"
    plugin_data {
      vendordata_url = "http://169.254.169.254/openstack/latest/vendor_data2.json"
      http_timeout   = "5s"
    }
  }
}
`
	data, err := PluginData([]byte(conf), "NodeAttestor", "openstack_iid")
	if err != nil {
		t.Fatalf("PluginData: %v", err)
	}
	var s struct {
		URL     string `hcl:"vendordata_url"`
		Timeout string `hcl:"http_timeout"`
	}
	if err := Decode(data, &s, []string{"vendordata_url", "http_timeout"}); err != nil {
		t.Fatalf("Decode(%q): %v", data, err)
	}
	if s.URL != "http://169.254.169.254/openstack/latest/vendor_data2.json" || s.Timeout != "5s" {
		t.Fatalf("decoded %+v from %q", s, data)
	}
	if _, err := PluginData([]byte(conf), "NodeAttestor", "aws_iid"); err == nil {
		t.Fatal("PluginData found a plugin that is not configured")
	}
}

type withBlock struct {
	URL   string       `hcl:"url"`
	Block *blockConfig `hcl:"block"`
}

type blockConfig struct {
	Enabled bool   `hcl:"enabled"`
	Socket  string `hcl:"socket"`
}

var withBlockKeys = []string{"url", "block.enabled", "block.socket"}

func TestDecodeBlock(t *testing.T) {
	for name, doc := range map[string]string{
		"hcl":  "url = \"x\"\nblock {\n  enabled = true\n  socket = \"/run/log\"\n}\n",
		"json": `{"url": "x", "block": {"enabled": true, "socket": "/run/log"}}`,
	} {
		var v withBlock
		if err := Decode(doc, &v, withBlockKeys); err != nil {
			t.Fatalf("%s: Decode: %v", name, err)
		}
		if v.Block == nil || !v.Block.Enabled || v.Block.Socket != "/run/log" {
			t.Fatalf("%s: decoded %+v", name, v.Block)
		}
	}
	var v withBlock
	if err := Decode("url = \"x\"\n", &v, withBlockKeys); err != nil || v.Block != nil {
		t.Fatalf("without the block: %+v, %v", v.Block, err)
	}
}

func TestDecodeUnknownBlockKeys(t *testing.T) {
	var v withBlock
	err := Decode("block {\n  enabled = true\n  sockt = \"/run/log\"\n}\n", &v, withBlockKeys)
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "block.sockt") {
		t.Fatalf("a typo in a block: %v, want ErrInvalid naming block.sockt", err)
	}
	if err := Decode("bloc {\n  enabled = true\n}\n", &v, withBlockKeys); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "bloc") {
		t.Fatalf("an unknown block: %v, want ErrInvalid", err)
	}
}
