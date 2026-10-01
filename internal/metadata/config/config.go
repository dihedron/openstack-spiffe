// Package config loads and validates the configuration files of the
// OpenStack metadata JWT issuer (signer) and of the JWKS aggregator. Checking
// a file yields every finding at once (syntax errors, unknown keys, invalid
// values, rule violations, file problems and risky settings), each with its
// line and YAML path; loading a file fails if any finding is an error.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// ErrInvalidConfig is wrapped by every error returned for a configuration
// with error findings.
var ErrInvalidConfig = errors.New("invalid configuration")

// replicaIDPattern is a DNS label: it ends up in every kid the replica issues.
var replicaIDPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// CheckOptions tunes how configuration files are checked.
type CheckOptions struct {
	// Hostname returns the host name used to derive a missing replica_id
	// (default: os.Hostname).
	Hostname func() (string, error)
	// Now returns the current time, used to check certificate validity
	// (default: time.Now).
	Now func() time.Time
	// SkipFiles disables the checks on the TLS and CA files the
	// configuration refers to.
	SkipFiles bool
}

func (o CheckOptions) withDefaults() CheckOptions {
	if o.Hostname == nil {
		o.Hostname = os.Hostname
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// LoadSigner reads and checks the signer configuration file at path, with
// the same rules as "config check", file checks included: it is the
// pre-flight check of the service, which must not start with a configuration
// that is not sane. It fails if there is any error finding (e.g. an expired
// or mismatched TLS certificate); otherwise it returns the configuration and
// the warnings, for the service to log.
func LoadSigner(path string) (*Signer, []Finding, error) {
	return load(path, CheckSigner)
}

// LoadAggregator reads and checks the aggregator configuration file at path,
// like LoadSigner.
func LoadAggregator(path string) (*Aggregator, []Finding, error) {
	return load(path, CheckAggregator)
}

func load[T any](path string, check func(string, []byte, CheckOptions) *Result[T]) (*T, []Finding, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, nil, fmt.Errorf("reading configuration file: %w", err)
	}
	result := check(path, data, CheckOptions{})
	if err := result.Err(); err != nil {
		return nil, nil, fmt.Errorf("loading %s: %w", path, err)
	}
	return result.Config, result.Warnings(), nil
}

// checkList flags empty and duplicate entries of the list at path.
func checkList[T any](r *Result[T], path string, list []string) {
	seen := map[string]bool{}
	for i, item := range list {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case item == "":
			r.errorf(KindRuleViolation, itemPath, "empty entry")
		case seen[item]:
			r.errorf(KindRuleViolation, itemPath, "%q is listed more than once", item)
		}
		seen[item] = true
	}
}

// TLS minimum versions accepted by tls_min_version.
const (
	TLSVersion12 = "1.2"
	TLSVersion13 = "1.3"
)

// tlsVersions maps tls_min_version values to crypto/tls versions.
var tlsVersions = map[string]uint16{TLSVersion12: tls.VersionTLS12, TLSVersion13: tls.VersionTLS13}

// checkTLSMinVersion flags an unsupported tls_min_version and warns about
// TLS 1.2.
func checkTLSMinVersion[T any](r *Result[T], version string) {
	switch version {
	case TLSVersion13:
	case TLSVersion12:
		r.warnf("tls_min_version", "TLS 1.2 is allowed: prefer %q unless a peer cannot negotiate TLS 1.3", TLSVersion13)
	default:
		r.errorf(KindRuleViolation, "tls_min_version", "%q is not one of %q, %q", version, TLSVersion12, TLSVersion13)
	}
}

// minTLSVersion returns the crypto/tls version for a checked
// tls_min_version, TLS 1.3 for anything else.
func minTLSVersion(version string) uint16 {
	if v, ok := tlsVersions[version]; ok {
		return v
	}
	return tls.VersionTLS13
}
