// Package docs holds the tests that keep the release documents complete
// (see .specs/openstack-spire-docs.md): the documents themselves are
// Markdown, built to PDF by build.sh.
package docs

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	agent "github.com/dihedron/openstack-spiffe/internal/plugin/agent/openstackiid"
	server "github.com/dihedron/openstack-spiffe/internal/plugin/server/openstackiid"
	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"go.yaml.in/yaml/v3"
)

// configurationReference is the Setup Guide's configuration reference.
const configurationReference = "setup-guide/12-configuration-reference.md"

// sections splits a Markdown document by its level-2 headings.
func sections(t *testing.T, path string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	heading := ""
	for _, line := range strings.Split(string(data), "\n") {
		if title, ok := strings.CutPrefix(line, "## "); ok {
			heading = strings.TrimSpace(title)
			continue
		}
		out[heading] += line + "\n"
	}
	return out
}

var unmarshaler = reflect.TypeFor[yaml.Unmarshaler]()

// yamlKeys returns the dotted YAML paths of every configuration key of t,
// a configuration struct: nested structs are blocks, everything else (and
// types decoding themselves, like rates) is a key.
func yamlKeys(t reflect.Type, prefix string) []string {
	var keys []string
	for field := range t.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		ft := field.Type
		block := ft.Kind() == reflect.Struct && ft != reflect.TypeFor[time.Duration]() &&
			!ft.Implements(unmarshaler) && !reflect.PointerTo(ft).Implements(unmarshaler)
		if block {
			keys = append(keys, yamlKeys(ft, prefix+name+".")...)
			continue
		}
		keys = append(keys, prefix+name)
	}
	return keys
}

// TestConfigurationReferenceIsComplete fails when a configuration key of
// any of the three components is missing from its section of the Setup
// Guide's configuration reference, in code font.
func TestConfigurationReferenceIsComplete(t *testing.T) {
	doc := sections(t, configurationReference)
	for _, component := range []struct {
		section string
		keys    []string
	}{
		{"Signer", yamlKeys(reflect.TypeFor[config.Signer](), "")},
		{"JWKS aggregator", yamlKeys(reflect.TypeFor[config.Aggregator](), "")},
		{"Server plugin", server.ConfigKeys()},
		{"Agent plugin", agent.ConfigKeys()},
	} {
		text, ok := doc[component.section]
		if !ok {
			t.Errorf("%s: no \"## %s\" section", configurationReference, component.section)
			continue
		}
		if len(component.keys) == 0 {
			t.Errorf("%s: no keys found (the test is broken)", component.section)
		}
		for _, key := range component.keys {
			if !regexp.MustCompile("`" + regexp.QuoteMeta(key) + "`").MatchString(text) {
				t.Errorf("%s: the key `%s` is not documented in the %s section", configurationReference, key, component.section)
			}
		}
	}
}

// separator matches a pipe table's header separator line.
var separator = regexp.MustCompile(`^\|(\s*:?-+:?\s*\|)+\s*$`)

// TestTablesSetColumnWidths fails on a pipe table whose separator line
// leaves the column widths to pandoc ("| --- | --- |"). With a cell wider
// than the line, pandoc then gives every column the same width, and code,
// which LaTeX cannot wrap, overflows into the next column. The dashes'
// relative lengths set the columns' relative widths.
func TestTablesSetColumnWidths(t *testing.T) {
	files, err := filepath.Glob("*/[0-9][0-9]-*.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !separator.MatchString(strings.TrimSpace(line)) {
				continue
			}
			lengths := map[int]bool{}
			for _, cell := range strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|") {
				lengths[len(strings.Trim(strings.TrimSpace(cell), ":"))] = true
			}
			if len(lengths) == 1 {
				t.Errorf("%s:%d: the table's columns all have the same width: set their proportions with the dashes' lengths", file, i+1)
			}
		}
	}
}
