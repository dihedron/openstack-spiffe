package config

import (
	"io"
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

// LoadAggregator reads and validates the aggregator configuration file at path.
func LoadAggregator(path string) (*Aggregator, error) {
	return load(path, parseAggregator)
}

func parseAggregator(r io.Reader) (*Aggregator, error) {
	cfg := defaultAggregator()
	if err := decode(r, cfg); err != nil {
		return nil, err
	}
	var p problems
	cfg.validate(&p)
	if err := p.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (a *Aggregator) validate(p *problems) {
	if a.ListenAddr == "" {
		p.add("listen_addr is required")
	}
	if a.TLSCertPath == "" {
		p.add("tls_cert_path is required")
	}
	if a.TLSKeyPath == "" {
		p.add("tls_key_path is required")
	}
	if len(a.Replicas) == 0 {
		p.add("replicas must list at least one replica JWKS URL")
	}
	checkList(p, "replicas", a.Replicas)
	for _, replica := range a.Replicas {
		u, err := url.Parse(replica)
		switch {
		case err != nil:
			p.add("replicas: %q is not a valid URL: %w", replica, err)
		case u.Scheme != "https" || u.Host == "":
			p.add("replicas: %q must be an https URL with a host", replica)
		}
	}
	if a.PollInterval <= 0 {
		p.add("poll_interval %v must be positive", a.PollInterval)
	}
	if a.FetchTimeout <= 0 || a.FetchTimeout >= a.PollInterval {
		p.add("fetch_timeout %v must be positive and shorter than poll_interval", a.FetchTimeout)
	}
	if a.StaleKeyRetention < iid.TTL {
		p.add("stale_key_retention %v must be at least the token TTL (%v)", a.StaleKeyRetention, iid.TTL)
	}
	if a.CacheMaxAge < 0 {
		p.add("cache_max_age %v must not be negative", a.CacheMaxAge)
	}
}
