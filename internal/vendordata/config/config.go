// Package config loads and validates the configuration files of the
// vendordata JWT issuer (signer) and of the JWKS aggregator.
package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"go.yaml.in/yaml/v3"
)

// ErrInvalidConfig is returned (wrapped) for every configuration problem.
var ErrInvalidConfig = errors.New("invalid configuration")

// replicaIDPattern is a DNS label: it ends up in every kid the replica issues.
var replicaIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// decode parses a YAML document into target, which must already hold the
// defaults; unknown keys are rejected so that typos don't go unnoticed.
func decode(r io.Reader, target any) error {
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	return nil
}

// load opens path and hands it to parse.
func load[T any](path string, parse func(io.Reader) (*T, error)) (*T, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("opening configuration file: %w", err)
	}
	defer f.Close()
	cfg, err := parse(f)
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", path, err)
	}
	return cfg, nil
}

// problems accumulates validation errors, so that operators see all of them
// at once.
type problems []error

func (p *problems) add(format string, args ...any) {
	*p = append(*p, fmt.Errorf("%w: "+format, append([]any{ErrInvalidConfig}, args...)...))
}

func (p problems) err() error {
	return errors.Join(p...)
}
