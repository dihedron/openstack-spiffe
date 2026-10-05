package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// Aggregator is the configuration of the JWKS aggregator, which merges the
// key sets published by the signer replicas.
type Aggregator struct {
	// ListenAddr is the address the HTTPS server listens on.
	ListenAddr string `yaml:"listen_addr"`
	// TLSCertPath is the path to the server certificate (PEM).
	TLSCertPath string `yaml:"tls_cert_path"`
	// TLSKeyPath is the path to the server private key (PEM).
	TLSKeyPath string `yaml:"tls_key_path"`
	// TLSMinVersion is the minimum TLS version ("1.2" or "1.3") of the HTTPS
	// server and of the connections to the replicas.
	TLSMinVersion string `yaml:"tls_min_version"`
	// Replicas lists the local JWKS URLs (/jwks/local.json) of the signer
	// replicas.
	Replicas []string `yaml:"replicas"`
	// PollInterval is how often each replica is polled; with fetch_timeout
	// and cache_max_age, it must be shorter than the replicas'
	// key_store.publish_ahead.
	PollInterval time.Duration `yaml:"poll_interval"`
	// FetchTimeout bounds each replica fetch.
	FetchTimeout time.Duration `yaml:"fetch_timeout"`
	// ReplicaCACertPath is an optional CA bundle to verify the replicas.
	ReplicaCACertPath string `yaml:"replica_ca_cert_path"`
	// StaleKeyRetention is how long the keys of an unreachable replica are
	// still served; at least the token TTL.
	StaleKeyRetention time.Duration `yaml:"stale_key_retention"`
	// CacheMaxAge is the Cache-Control max-age of the merged JWKS.
	CacheMaxAge time.Duration `yaml:"cache_max_age"`
}

func defaultAggregator() *Aggregator {
	return &Aggregator{
		ListenAddr:        "0.0.0.0:8444",
		TLSMinVersion:     TLSVersion13,
		PollInterval:      30 * time.Second,
		FetchTimeout:      5 * time.Second,
		StaleKeyRetention: iid.TTL,
		CacheMaxAge:       30 * time.Second,
	}
}

// CheckAggregator checks an aggregator configuration document, like
// CheckSigner.
func CheckAggregator(file string, data []byte, opts CheckOptions) *Result[Aggregator] {
	opts = opts.withDefaults()
	result := &Result[Aggregator]{File: file}
	cfg := defaultAggregator()
	if !decodeDocument(result, data, cfg) {
		return result
	}
	result.Config = cfg
	cfg.validate(result)
	cfg.warn(result)
	if !opts.SkipFiles {
		checkKeyPair(result, "tls_cert_path", cfg.TLSCertPath, "tls_key_path", cfg.TLSKeyPath, opts.Now())
		checkCABundle(result, "replica_ca_cert_path", cfg.ReplicaCACertPath)
	}
	return result
}

// MinTLSVersion returns tls_min_version as a crypto/tls version.
func (a *Aggregator) MinTLSVersion() uint16 { return minTLSVersion(a.TLSMinVersion) }

func (a *Aggregator) validate(r *Result[Aggregator]) {
	checkTLSMinVersion(r, a.TLSMinVersion)
	if a.ListenAddr == "" {
		r.errorf(KindRuleViolation, "listen_addr", "is required")
	}
	if a.TLSCertPath == "" {
		r.errorf(KindRuleViolation, "tls_cert_path", "is required")
	}
	if a.TLSKeyPath == "" {
		r.errorf(KindRuleViolation, "tls_key_path", "is required")
	}
	if len(a.Replicas) == 0 {
		r.errorf(KindRuleViolation, "replicas", "must list at least one replica JWKS URL")
	}
	checkJWKSURLs(r, "replicas", a.Replicas)
	checkPolling(r, "", a.PollInterval, a.FetchTimeout, a.StaleKeyRetention, a.CacheMaxAge)
}

// warn flags valid but risky settings.
func (a *Aggregator) warn(r *Result[Aggregator]) {
	if a.ReplicaCACertPath == "" {
		r.warnf("replica_ca_cert_path", "not set: every public CA is trusted for the replicas' keys")
	}
	for i, replica := range a.Replicas {
		if u, err := url.Parse(replica); err == nil && strings.HasSuffix(u.Path, mergedJWKSPath) {
			r.warnf(fmt.Sprintf("replicas[%d]", i),
				"%q is a replica's merged JWKS: with peers it also carries the peers' keys, imported twice and dropped late; poll /jwks/local.json instead", replica)
		}
	}
}
