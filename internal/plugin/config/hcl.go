// Package config decodes the plugin_data block SPIRE hands to the
// openstack_iid plugins (HCL, or JSON), rejecting unknown keys so that typos
// are never silently ignored, as in the issuer's configuration.
package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
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
