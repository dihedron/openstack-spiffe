package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// mergedJWKSPath is the path of a replica's merged JWK Set: with peers, it
// also carries the peers' keys, so other replicas must never poll it.
const mergedJWKSPath = "/.well-known/jwks.json"

// Peers configures peer aggregation: a signer replica polls the own keys of
// the other replicas and serves them merged with its own, acting as a JWKS
// aggregator itself.
type Peers struct {
	// URLs lists the local JWKS URLs (/jwks/local.json) of the other
	// replicas; empty disables peer aggregation.
	URLs []string `yaml:"urls"`
	// CACertPath is an optional CA bundle to verify the peers.
	CACertPath string `yaml:"ca_cert_path"`
	// PollInterval is how often each peer is polled.
	PollInterval time.Duration `yaml:"poll_interval"`
	// FetchTimeout bounds each peer fetch.
	FetchTimeout time.Duration `yaml:"fetch_timeout"`
	// StaleKeyRetention is how long the keys of an unreachable peer are
	// still served; at least the token TTL.
	StaleKeyRetention time.Duration `yaml:"stale_key_retention"`
	// CacheMaxAge is the Cache-Control max-age of the merged JWKS.
	CacheMaxAge time.Duration `yaml:"cache_max_age"`
}

// peerSettings are the peers keys that only matter with peers.urls.
var peerSettings = []string{"ca_cert_path", "poll_interval", "fetch_timeout", "stale_key_retention", "cache_max_age"}

func defaultPeers() Peers {
	return Peers{
		PollInterval:      30 * time.Second,
		FetchTimeout:      5 * time.Second,
		StaleKeyRetention: iid.TTL,
		CacheMaxAge:       30 * time.Second,
	}
}

// Enabled reports whether peer aggregation is configured.
func (p *Peers) Enabled() bool { return len(p.URLs) > 0 }

func (p *Peers) validate(r *Result[Signer]) {
	checkJWKSURLs(r, "peers.urls", p.URLs)
	for i, raw := range p.URLs {
		if u, err := url.Parse(raw); err == nil && strings.HasSuffix(u.Path, mergedJWKSPath) {
			r.errorf(KindRuleViolation, fmt.Sprintf("peers.urls[%d]", i),
				"%q is a merged JWKS: peers must be polled at their /jwks/local.json, or keys would circulate between replicas forever", raw)
		}
	}
	checkPolling(r, "peers.", p.PollInterval, p.FetchTimeout, p.StaleKeyRetention, p.CacheMaxAge)
}

// warn flags peers settings that are ignored without peers.urls.
func (p *Peers) warn(r *Result[Signer]) {
	if p.Enabled() {
		return
	}
	for _, key := range peerSettings {
		if path := "peers." + key; r.lines[path] != 0 {
			r.warnf(path, "ignored without peers.urls")
		}
	}
}

// publicationWindow is the longest a merged JWKS consumer may go without
// seeing a newly published key: the poll interval, plus the fetch timeout,
// plus the time the consumer may cache the merged set.
func publicationWindow(pollInterval, fetchTimeout, cacheMaxAge time.Duration) time.Duration {
	return pollInterval + fetchTimeout + cacheMaxAge
}

// checkJWKSURLs flags missing, empty, duplicate and non-https entries of a
// list of JWKS URLs.
func checkJWKSURLs[T any](r *Result[T], path string, urls []string) {
	checkList(r, path, urls)
	for i, raw := range urls {
		itemPath := fmt.Sprintf("%s[%d]", path, i)
		u, err := url.Parse(raw)
		switch {
		case raw == "":
		case err != nil:
			r.errorf(KindRuleViolation, itemPath, "%q is not a valid URL: %v", raw, err)
		case u.Scheme != "https" || u.Host == "":
			r.errorf(KindRuleViolation, itemPath, "%q must be an https URL with a host", raw)
		}
	}
}

// checkPolling checks the polling and caching settings shared by the
// aggregator and the peers; prefix is prepended to their YAML paths.
func checkPolling[T any](r *Result[T], prefix string, pollInterval, fetchTimeout, retention, cacheMaxAge time.Duration) {
	if pollInterval <= 0 {
		r.errorf(KindRuleViolation, prefix+"poll_interval", "%v must be positive", pollInterval)
	}
	if fetchTimeout <= 0 || fetchTimeout >= pollInterval {
		r.errorf(KindRuleViolation, prefix+"fetch_timeout", "%v must be positive and shorter than %spoll_interval (%v)", fetchTimeout, prefix, pollInterval)
	}
	if retention < iid.TTL {
		r.errorf(KindRuleViolation, prefix+"stale_key_retention", "%v must be at least the maximum token TTL (%v)", retention, iid.TTL)
	}
	if cacheMaxAge < 0 || cacheMaxAge%time.Second != 0 {
		r.errorf(KindRuleViolation, prefix+"cache_max_age", "%v must be a non-negative whole number of seconds", cacheMaxAge)
	}
}
