package config

import (
	"fmt"
	"net/url"
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
	// Replicas lists the JWKS URLs of the signer replicas.
	Replicas []string `yaml:"replicas"`
	// PollInterval is how often each replica is polled; it must be shorter
	// than the replicas' key_store.publish_ahead.
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
	if !opts.SkipFiles {
		checkKeyPair(result, "tls_cert_path", cfg.TLSCertPath, "tls_key_path", cfg.TLSKeyPath, opts.Now())
		checkCABundle(result, "replica_ca_cert_path", cfg.ReplicaCACertPath)
	}
	return result
}

func (a *Aggregator) validate(r *Result[Aggregator]) {
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
	checkList(r, "replicas", a.Replicas)
	for i, replica := range a.Replicas {
		path := fmt.Sprintf("replicas[%d]", i)
		u, err := url.Parse(replica)
		switch {
		case err != nil:
			r.errorf(KindRuleViolation, path, "%q is not a valid URL: %v", replica, err)
		case u.Scheme != "https" || u.Host == "":
			r.errorf(KindRuleViolation, path, "%q must be an https URL with a host", replica)
		}
	}
	if a.PollInterval <= 0 {
		r.errorf(KindRuleViolation, "poll_interval", "%v must be positive", a.PollInterval)
	}
	if a.FetchTimeout <= 0 || a.FetchTimeout >= a.PollInterval {
		r.errorf(KindRuleViolation, "fetch_timeout", "%v must be positive and shorter than poll_interval (%v)", a.FetchTimeout, a.PollInterval)
	}
	if a.StaleKeyRetention < iid.TTL {
		r.errorf(KindRuleViolation, "stale_key_retention", "%v must be at least the maximum token TTL (%v)", a.StaleKeyRetention, iid.TTL)
	}
	if a.CacheMaxAge < 0 || a.CacheMaxAge%time.Second != 0 {
		r.errorf(KindRuleViolation, "cache_max_age", "%v must be a non-negative whole number of seconds", a.CacheMaxAge)
	}
}
