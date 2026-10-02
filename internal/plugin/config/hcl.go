// Package config decodes the plugin_data block SPIRE hands to the
// openstack_iid plugins (HCL, or JSON), rejecting unknown keys so that typos
// are never silently ignored, as in the issuer's configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

// ErrInvalid is returned (wrapped) for any configuration error; messages
// name the offending key.
var ErrInvalid = errors.New("invalid plugin configuration")

// Decode parses the configuration into v, a pointer to a struct with hcl
// tags, after checking that every top-level key is one of known.
func Decode(configuration string, v any, known []string) error {
	file, err := hcl.Parse(configuration)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if list, ok := file.Node.(*ast.ObjectList); ok {
		var unknown []string
		for _, item := range list.Items {
			if len(item.Keys) == 0 {
				continue
			}
			key := strings.Trim(item.Keys[0].Token.Text, `"`)
			if !slices.Contains(known, key) && !slices.Contains(unknown, key) {
				unknown = append(unknown, key)
			}
		}
		if len(unknown) > 0 {
			return fmt.Errorf("%w: unknown keys %s (known: %s)", ErrInvalid, strings.Join(unknown, ", "), strings.Join(known, ", "))
		}
	}
	if err := hcl.DecodeObject(v, file); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

// Duration parses the duration set for key, returning def if the value is
// empty. The result must be at least min and, if max is positive, at most
// max.
func Duration(key, value string, def, min, max time.Duration) (time.Duration, error) {
	if value == "" {
		return def, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%w: %s: %w", ErrInvalid, key, err)
	}
	if d < min {
		return 0, fmt.Errorf("%w: %s: %v is less than the minimum %v", ErrInvalid, key, d, min)
	}
	if max > 0 && d > max {
		return 0, fmt.Errorf("%w: %s: %v exceeds the maximum %v", ErrInvalid, key, d, max)
	}
	return d, nil
}

// PluginData returns the plugin_data block of a plugin in a SPIRE Agent or
// Server configuration file, e.g. NodeAttestor "openstack_iid", as the HCL
// that SPIRE hands to the plugin's Configure.
func PluginData(spireConfig []byte, pluginType, name string) (string, error) {
	file, err := hcl.ParseBytes(spireConfig)
	if err != nil {
		return "", fmt.Errorf("parsing SPIRE configuration: %w", err)
	}
	var data *ast.ObjectList
	ast.Walk(file.Node, func(n ast.Node) (ast.Node, bool) {
		item, ok := n.(*ast.ObjectItem)
		if !ok || data != nil || len(item.Keys) != 2 || keyText(item.Keys[0]) != pluginType || keyText(item.Keys[1]) != name {
			return n, data == nil
		}
		if plugin, ok := item.Val.(*ast.ObjectType); ok {
			for _, member := range plugin.List.Items {
				if len(member.Keys) == 1 && keyText(member.Keys[0]) == "plugin_data" {
					if block, ok := member.Val.(*ast.ObjectType); ok {
						data = block.List
					}
				}
			}
		}
		return n, false
	})
	if data == nil {
		return "", fmt.Errorf("no plugin_data for %s %q", pluginType, name)
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, data); err != nil {
		return "", fmt.Errorf("printing plugin_data: %w", err)
	}
	return buf.String(), nil
}

func keyText(k *ast.ObjectKey) string {
	return strings.Trim(k.Token.Text, `"`)
}
