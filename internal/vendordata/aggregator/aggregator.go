// Package aggregator merges the JWK Sets published by the signer replicas
// into the single set the SPIRE Server-side plugin fetches. Each replica
// signs with its own keys, so the merged set must hold every replica's keys;
// it fails closed on conflicts and keeps an unreachable replica's keys for a
// while, so that in-flight tokens keep verifying during short outages.
package aggregator

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/jwks"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/keystore"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// maxResponseBytes caps a replica's JWKS response: a replica publishes a
// handful of keys, a few KiB at most.
const maxResponseBytes = 1 << 20

// privateMembers are the JWK members holding private key material (RFC 7518,
// sections 6.2.2, 6.3.2 and 6.4.1).
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// NewHTTPClient returns the client used to fetch the replicas: minTLSVersion
// (tls.VersionTLS12 or tls.VersionTLS13) or later, verified against
// caCertPath (replica_ca_cert_path; the system roots if empty), never
// following redirects.
func NewHTTPClient(caCertPath string, minTLSVersion uint16) (*http.Client, error) {
	if minTLSVersion != tls.VersionTLS12 && minTLSVersion != tls.VersionTLS13 {
		return nil, fmt.Errorf("unsupported minimum TLS version %#x", minTLSVersion)
	}
	tlsConfig := &tls.Config{MinVersion: minTLSVersion}
	if caCertPath != "" {
		pem, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("reading replica CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("reading replica CA bundle %s: no certificates found", caCertPath)
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport: transport,
		// a redirect could point anywhere: the configured URL must answer
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

type replicaState struct {
	url         string
	keys        []keystore.PublicKey
	lastSuccess time.Time
	fetched     bool
	failing     bool
}

// Aggregator polls the replicas and serves their merged keys. It is a
// jwks.KeySource and is safe for concurrent use.
type Aggregator struct {
	client       *http.Client
	pollInterval time.Duration
	fetchTimeout time.Duration
	retention    time.Duration
	now          func() time.Time

	mu       sync.RWMutex
	replicas []*replicaState
}

// Option configures an Aggregator.
type Option func(*Aggregator)

// WithPollInterval sets how often the replicas are polled (default: 30s).
func WithPollInterval(d time.Duration) Option {
	return func(a *Aggregator) { a.pollInterval = d }
}

// WithFetchTimeout bounds each replica fetch (default: 5s).
func WithFetchTimeout(d time.Duration) Option {
	return func(a *Aggregator) { a.fetchTimeout = d }
}

// WithStaleKeyRetention sets how long the keys of a replica's last
// successful fetch are served (default: iid.TTL).
func WithStaleKeyRetention(d time.Duration) Option {
	return func(a *Aggregator) { a.retention = d }
}

// WithClock sets the source of the current time (default: time.Now).
func WithClock(now func() time.Time) Option {
	return func(a *Aggregator) { a.now = now }
}

// New creates an Aggregator for the given replica JWKS URLs (https only),
// fetched with client (see NewHTTPClient).
func New(replicas []string, client *http.Client, options ...Option) (*Aggregator, error) {
	if len(replicas) == 0 {
		return nil, errors.New("creating aggregator: no replicas")
	}
	if client == nil {
		return nil, errors.New("creating aggregator: no HTTP client")
	}
	a := &Aggregator{
		client:       client,
		pollInterval: 30 * time.Second,
		fetchTimeout: 5 * time.Second,
		retention:    iid.TTL,
		now:          time.Now,
	}
	for _, option := range options {
		option(a)
	}
	if a.pollInterval <= 0 || a.fetchTimeout <= 0 || a.retention <= 0 {
		return nil, fmt.Errorf("creating aggregator: poll interval (%v), fetch timeout (%v) and stale key retention (%v) must be positive", a.pollInterval, a.fetchTimeout, a.retention)
	}
	seen := map[string]bool{}
	for _, raw := range replicas {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("creating aggregator: replica %q is not an https URL", raw)
		}
		if seen[raw] {
			return nil, fmt.Errorf("creating aggregator: replica %q is listed twice", raw)
		}
		seen[raw] = true
		a.replicas = append(a.replicas, &replicaState{url: raw})
	}
	return a, nil
}

// Run polls the replicas at once and then every poll interval, until the
// context is cancelled; it returns nil when the context is cancelled.
func (a *Aggregator) Run(ctx context.Context) error {
	ticker := time.NewTicker(a.pollInterval)
	defer ticker.Stop()
	for {
		a.poll(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// poll fetches every replica concurrently and records the outcomes.
func (a *Aggregator) poll(ctx context.Context) {
	type outcome struct {
		keys []keystore.PublicKey
		err  error
	}
	outcomes := make([]outcome, len(a.replicas))
	var wg sync.WaitGroup
	for i, r := range a.replicas {
		wg.Go(func() {
			keys, err := a.fetch(ctx, r.url)
			outcomes[i] = outcome{keys, err}
		})
	}
	wg.Wait()

	a.mu.Lock()
	now := a.now()
	for i, r := range a.replicas {
		switch o := outcomes[i]; {
		case o.err != nil:
			if !r.failing {
				slog.WarnContext(ctx, "replica fetch failing", "replica", r.url, "error", o.err)
			}
			r.failing = true
		default:
			if r.failing {
				slog.InfoContext(ctx, "replica fetch recovered", "replica", r.url)
			}
			r.keys, r.lastSuccess, r.fetched, r.failing = o.keys, now, true, false
		}
	}
	_, conflicts := a.merge(now)
	a.mu.Unlock()

	for kid, replicas := range conflicts {
		slog.ErrorContext(ctx, "replicas publish different keys under the same kid: kid excluded", "kid", kid, "replicas", replicas)
	}
}

// fetch reads and validates a replica's JWK Set. Invalid keys are left out
// and logged; any key carrying private key material is left out and logged
// as an error.
func (a *Aggregator) fetch(ctx context.Context, replica string) ([]keystore.PublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, a.fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, replica, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return nil, fmt.Errorf("response larger than %d bytes", maxResponseBytes)
	}
	var set struct {
		Keys []jsontext.Value `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decoding JWK Set: %w", err)
	}

	var keys []keystore.PublicKey
	for _, raw := range set.Keys {
		var members map[string]any
		if err := json.Unmarshal(raw, &members); err != nil {
			slog.WarnContext(ctx, "replica published a malformed key, ignored", "replica", replica, "error", err)
			continue
		}
		kid, _ := members["kid"].(string)
		if leaked := slices.IndexFunc(privateMembers, func(m string) bool { _, ok := members[m]; return ok }); leaked >= 0 {
			slog.ErrorContext(ctx, "replica published private key material: key rejected", "replica", replica, "kid", kid, "member", privateMembers[leaked])
			continue
		}
		var jwk jwks.Key
		if err := json.Unmarshal(raw, &jwk); err != nil {
			slog.WarnContext(ctx, "replica published a malformed key, ignored", "replica", replica, "kid", kid, "error", err)
			continue
		}
		key, err := jwk.PublicKey()
		if err != nil {
			slog.WarnContext(ctx, "replica published an unacceptable key, ignored", "replica", replica, "kid", kid, "error", err)
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// PublicKeys returns the merged keys of the replicas fetched successfully
// within the stale key retention, sorted by kid, without any kid published
// with different key material.
func (a *Aggregator) PublicKeys(ctx context.Context) ([]keystore.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	keys, _ := a.merge(a.now())
	return keys, nil
}

// Check reports whether at least one replica has been fetched successfully
// within the stale key retention, i.e. whether the merged set holds any
// replica's keys; it backs the readiness probe.
func (a *Aggregator) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	now := a.now()
	for _, r := range a.replicas {
		if a.current(r, now) {
			return nil
		}
	}
	return errors.New("no replica fetched successfully within the stale key retention")
}

// current reports whether a replica's keys are still served; callers must
// hold the lock.
func (a *Aggregator) current(r *replicaState, now time.Time) bool {
	return r.fetched && now.Sub(r.lastSuccess) < a.retention
}

// merge returns the merged keys at now and the excluded kids, each with the
// replicas publishing it; callers must hold the lock.
func (a *Aggregator) merge(now time.Time) ([]keystore.PublicKey, map[string][]string) {
	byKid := map[string][]keystore.PublicKey{}
	sources := map[string][]string{}
	for _, r := range a.replicas {
		if !a.current(r, now) {
			continue
		}
		for _, k := range r.keys {
			byKid[k.ID] = append(byKid[k.ID], k)
			sources[k.ID] = append(sources[k.ID], r.url)
		}
	}
	var merged []keystore.PublicKey
	conflicts := map[string][]string{}
	for kid, candidates := range byKid {
		first := candidates[0]
		if slices.ContainsFunc(candidates[1:], func(k keystore.PublicKey) bool { return !sameKey(first, k) }) {
			conflicts[kid] = sources[kid]
			continue
		}
		merged = append(merged, first)
	}
	slices.SortFunc(merged, func(x, y keystore.PublicKey) int { return strings.Compare(x.ID, y.ID) })
	return merged, conflicts
}

// sameKey reports whether two keys have the same algorithm and material.
func sameKey(x, y keystore.PublicKey) bool {
	xe, ok := x.Key.(interface{ Equal(crypto.PublicKey) bool })
	return ok && x.Algorithm == y.Algorithm && xe.Equal(y.Key)
}
