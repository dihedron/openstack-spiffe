package config

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/auth"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/novalookup"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// Key store backends.
const (
	// BackendEphemeralMemory keeps a per-replica key pair in memory only.
	BackendEphemeralMemory = "ephemeral_memory"
	// BackendVaultTransit delegates signing to HashiCorp Vault's transit
	// engine (not implemented yet).
	BackendVaultTransit = "vault_transit"
)

const (
	minRotationInterval   = iid.TTL
	minMaxBodyBytes       = 1024
	maxMaxBodyBytes       = 16 << 20
	maxValidationCacheTTL = 10 * time.Minute
	maxProjectCacheTTL    = time.Hour
)

// recommendedInstanceRate is the per-instance rate limit recommended by the
// specification.
var recommendedInstanceRate = Rate{Events: 1, Per: 5 * time.Second}

var (
	signingAlgorithms = []string{"RS256", "ES256"}
	// novaStatusesAllowable are the Nova server statuses in which an instance
	// may legitimately request metadata; anything else (DELETED, ERROR,
	// SHELVED_OFFLOADED, ...) can never be configured as allowed.
	novaStatusesAllowable = []string{
		"ACTIVE", "BUILD", "REBOOT", "HARD_REBOOT", "REBUILD", "RESIZE",
		"VERIFY_RESIZE", "REVERT_RESIZE", "MIGRATING", "PASSWORD", "RESCUE",
	}
	// serverEnrichments are the enrichment claims that require the Nova
	// server lookup.
	serverEnrichments = []string{iid.ClaimAvailabilityZone, iid.ClaimFlavor, iid.ClaimUserID}
)

// Signer is the configuration of the vendordata JWT issuer.
type Signer struct {
	// ListenAddr is the address the HTTPS server listens on.
	ListenAddr string `yaml:"listen_addr"`
	// TLSCertPath is the path to the server certificate (PEM).
	TLSCertPath string `yaml:"tls_cert_path"`
	// TLSKeyPath is the path to the server private key (PEM).
	TLSKeyPath string `yaml:"tls_key_path"`
	// TLSMinVersion is the minimum TLS version ("1.2" or "1.3") of the HTTPS
	// server and of the connections to Keystone and Nova.
	TLSMinVersion string `yaml:"tls_min_version"`
	// ReplicaID uniquely identifies this replica and is embedded in every
	// kid it issues; defaults to the first label of the hostname.
	ReplicaID string `yaml:"replica_id"`
	// KeyStore configures the signing keys.
	KeyStore KeyStore `yaml:"key_store"`
	// TokenTTLSeconds is the validity of issued tokens (exp - iat).
	TokenTTLSeconds int `yaml:"token_ttl_seconds"`
	// RateLimitPerInstance limits token issuance per instance ID.
	RateLimitPerInstance Rate `yaml:"rate_limit_per_instance"`
	// RateLimitPerSource limits requests per source IP, before the body is read.
	RateLimitPerSource Rate `yaml:"rate_limit_per_source"`
	// MaxBodyBytes caps the size of the Nova request body.
	MaxBodyBytes int64 `yaml:"max_body_bytes"`
	// ClientAddress configures how the client address is determined.
	ClientAddress ClientAddress `yaml:"client_address"`
	// CustomClaims are static claims added to every token.
	CustomClaims map[string]string `yaml:"custom_claims"`
	// Tags configures the "tags" claim.
	Tags Tags `yaml:"tags"`
	// Keystone configures caller authentication and project lookups; the
	// service's own credentials come from the OS_* environment variables.
	Keystone Keystone `yaml:"keystone"`
	// NovaLookup configures instance verification against the Nova API.
	NovaLookup NovaLookup `yaml:"nova_lookup"`
	// Enrich lists the optional enrichment claims to add (see
	// iid.EnrichmentClaims).
	Enrich []string `yaml:"enrich"`
}

// KeyStore configures the signing keys.
type KeyStore struct {
	// Backend is one of BackendEphemeralMemory, BackendVaultTransit.
	Backend string `yaml:"backend"`
	// Algorithm is the JWS algorithm: RS256 or ES256.
	Algorithm string `yaml:"algorithm"`
	// RotationInterval is how long a key stays active.
	RotationInterval time.Duration `yaml:"rotation_interval"`
	// PublishAhead is how long a new key is published before it is used; it
	// must exceed the JWKS aggregator's poll interval.
	PublishAhead time.Duration `yaml:"publish_ahead"`
	// VaultProxyEndpoint is the Vault proxy URL (vault_transit only).
	VaultProxyEndpoint string `yaml:"vault_proxy_endpoint"`
}

// ClientAddress configures how the client address, which keys the
// per-source rate limit, is determined.
type ClientAddress struct {
	// TrustedProxies lists the IP addresses or CIDR ranges of the reverse
	// proxies or load balancers in front of the replicas; empty means the
	// service is not proxied and the TCP peer address is the client's.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// Header carries the client address set by the trusted proxies
	// (default: X-Forwarded-For); ignored without trusted proxies.
	Header string `yaml:"header"`
}

// Tags configures the "tags" claim.
type Tags struct {
	// Allowlist restricts the metadata keys copied into the claim; empty
	// means every string-valued entry.
	Allowlist []string `yaml:"allowlist"`
}

// Keystone configures caller authentication and project lookups.
type Keystone struct {
	// AllowedUsers lists the Keystone users (e.g. Nova's vendordata service
	// user) allowed to request tokens, each as a user ID or name@domain
	// (see auth.ParseAllowedUser).
	AllowedUsers []string `yaml:"allowed_users"`
	// RequiredRole is the role the caller's token must carry.
	RequiredRole string `yaml:"required_role"`
	// ValidationCacheTTL bounds how long a validated caller token is cached.
	ValidationCacheTTL time.Duration `yaml:"validation_cache_ttl"`
	// ProjectCacheTTL bounds how long project records are cached.
	ProjectCacheTTL time.Duration `yaml:"project_cache_ttl"`
	// CACertPath is an optional CA bundle for Keystone and Nova endpoints.
	CACertPath string `yaml:"ca_cert_path"`
}

// NovaLookup configures instance verification against the Nova API.
type NovaLookup struct {
	// Enabled turns instance verification on.
	Enabled bool `yaml:"enabled"`
	// CacheTTL bounds how long server records are cached; at most the token TTL.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// AllowedStatuses lists the server statuses for which tokens are issued.
	AllowedStatuses []string `yaml:"allowed_statuses"`
}

func defaultSigner() *Signer {
	return &Signer{
		ListenAddr:    "0.0.0.0:8443",
		TLSMinVersion: TLSVersion13,
		KeyStore: KeyStore{
			Backend:          BackendEphemeralMemory,
			Algorithm:        iid.Algorithm,
			RotationInterval: 24 * time.Hour,
			PublishAhead:     2 * time.Minute,
		},
		TokenTTLSeconds:      int(iid.TTL / time.Second),
		RateLimitPerInstance: recommendedInstanceRate,
		RateLimitPerSource:   Rate{Events: 200, Per: time.Second},
		// Nova forwards user-data (up to 64 KiB, base64-encoded) and metadata
		// in the same body, so legitimate requests can exceed 150 KiB.
		MaxBodyBytes: 256 * 1024,
		Keystone: Keystone{
			RequiredRole:       "service",
			ValidationCacheTTL: time.Minute,
			ProjectCacheTTL:    10 * time.Minute,
		},
		NovaLookup: NovaLookup{
			Enabled:         true,
			CacheTTL:        time.Minute,
			AllowedStatuses: novalookup.DefaultAllowedStatuses(),
		},
	}
}

// CheckSigner checks a signer configuration document: it decodes it on top of
// the defaults, derives a missing replica_id from the hostname and records
// every finding. file is only used to label the findings.
func CheckSigner(file string, data []byte, opts CheckOptions) *Result[Signer] {
	opts = opts.withDefaults()
	result := &Result[Signer]{File: file}
	cfg := defaultSigner()
	if !decodeDocument(result, data, cfg) {
		return result
	}
	result.Config = cfg

	if cfg.ReplicaID == "" {
		name, err := opts.Hostname()
		if err != nil {
			result.errorf(KindRuleViolation, "replica_id", "not set, and the hostname is unavailable: %v", err)
		} else {
			cfg.ReplicaID, _, _ = strings.Cut(strings.ToLower(name), ".")
			result.warnf("replica_id", "not set: each host derives it from its hostname (here %q); set it explicitly for stable, predictable kids", cfg.ReplicaID)
		}
	}
	cfg.validate(result)
	cfg.warn(result)
	if len(cfg.ClientAddress.TrustedProxies) > 0 && cfg.ClientAddress.Header == "" {
		// defaulted here rather than in defaultSigner, so that warn can tell
		// an explicitly set (and ignored) header apart
		cfg.ClientAddress.Header = clientaddr.DefaultHeader
	}
	if !opts.SkipFiles {
		checkKeyPair(result, "tls_cert_path", cfg.TLSCertPath, "tls_key_path", cfg.TLSKeyPath, opts.Now())
		checkCABundle(result, "keystone.ca_cert_path", cfg.Keystone.CACertPath)
	}
	return result
}

// TokenTTL returns the configured token validity as a duration.
func (s *Signer) TokenTTL() time.Duration {
	return time.Duration(s.TokenTTLSeconds) * time.Second
}

// MinTLSVersion returns tls_min_version as a crypto/tls version.
func (s *Signer) MinTLSVersion() uint16 { return minTLSVersion(s.TLSMinVersion) }

func (s *Signer) validate(r *Result[Signer]) {
	checkTLSMinVersion(r, s.TLSMinVersion)
	if s.ListenAddr == "" {
		r.errorf(KindRuleViolation, "listen_addr", "is required")
	}
	if s.TLSCertPath == "" {
		r.errorf(KindRuleViolation, "tls_cert_path", "is required")
	}
	if s.TLSKeyPath == "" {
		r.errorf(KindRuleViolation, "tls_key_path", "is required")
	}
	if s.ReplicaID != "" && !replicaIDPattern.MatchString(s.ReplicaID) {
		r.errorf(KindRuleViolation, "replica_id", "%q must be a lowercase DNS label (set it explicitly if the hostname is not one)", s.ReplicaID)
	}

	switch s.KeyStore.Backend {
	case BackendEphemeralMemory:
	case BackendVaultTransit:
		r.errorf(KindRuleViolation, "key_store.backend", "%q is not supported yet", BackendVaultTransit)
	default:
		r.errorf(KindRuleViolation, "key_store.backend", "%q is not one of %v", s.KeyStore.Backend, []string{BackendEphemeralMemory, BackendVaultTransit})
	}
	if !slices.Contains(signingAlgorithms, s.KeyStore.Algorithm) {
		r.errorf(KindRuleViolation, "key_store.algorithm", "%q is not one of %v", s.KeyStore.Algorithm, signingAlgorithms)
	}
	if s.KeyStore.RotationInterval < minRotationInterval {
		r.errorf(KindRuleViolation, "key_store.rotation_interval", "%v must be at least %v", s.KeyStore.RotationInterval, minRotationInterval)
	}
	if s.KeyStore.PublishAhead <= 0 || s.KeyStore.PublishAhead >= s.KeyStore.RotationInterval {
		r.errorf(KindRuleViolation, "key_store.publish_ahead", "%v must be positive and shorter than key_store.rotation_interval (%v)", s.KeyStore.PublishAhead, s.KeyStore.RotationInterval)
	}

	if s.TokenTTLSeconds < 1 || s.TokenTTL() > iid.TTL {
		r.errorf(KindRuleViolation, "token_ttl_seconds", "%d must be between 1 and %d", s.TokenTTLSeconds, int(iid.TTL/time.Second))
	}
	if s.MaxBodyBytes < minMaxBodyBytes || s.MaxBodyBytes > maxMaxBodyBytes {
		r.errorf(KindRuleViolation, "max_body_bytes", "%d must be between %d and %d", s.MaxBodyBytes, minMaxBodyBytes, maxMaxBodyBytes)
	}
	checkList(r, "client_address.trusted_proxies", s.ClientAddress.TrustedProxies)
	for i, entry := range s.ClientAddress.TrustedProxies {
		if _, err := clientaddr.ParseTrustedProxy(entry); entry != "" && err != nil {
			r.errorf(KindRuleViolation, fmt.Sprintf("client_address.trusted_proxies[%d]", i), "%v", err)
		}
	}
	if s.ClientAddress.Header != "" {
		if err := clientaddr.ValidateHeaderName(s.ClientAddress.Header); err != nil {
			r.errorf(KindRuleViolation, "client_address.header", "%v", err)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(s.CustomClaims)) {
		switch {
		case name == "":
			r.errorf(KindRuleViolation, "custom_claims", "a custom claim has an empty name")
		case iid.IsReservedClaim(name):
			r.errorf(KindRuleViolation, "custom_claims."+name, "%q is a reserved claim", name)
		}
	}
	checkList(r, "tags.allowlist", s.Tags.Allowlist)

	if len(s.Keystone.AllowedUsers) == 0 {
		r.errorf(KindRuleViolation, "keystone.allowed_users", "must list at least one user")
	}
	checkList(r, "keystone.allowed_users", s.Keystone.AllowedUsers)
	for i, entry := range s.Keystone.AllowedUsers {
		if _, err := auth.ParseAllowedUser(entry); entry != "" && err != nil {
			r.errorf(KindRuleViolation, fmt.Sprintf("keystone.allowed_users[%d]", i), "%v", err)
		}
	}
	if s.Keystone.RequiredRole == "" {
		r.errorf(KindRuleViolation, "keystone.required_role", "is required")
	}
	if s.Keystone.ValidationCacheTTL <= 0 || s.Keystone.ValidationCacheTTL > maxValidationCacheTTL {
		r.errorf(KindRuleViolation, "keystone.validation_cache_ttl", "%v must be positive and at most %v", s.Keystone.ValidationCacheTTL, maxValidationCacheTTL)
	}
	if s.Keystone.ProjectCacheTTL <= 0 || s.Keystone.ProjectCacheTTL > maxProjectCacheTTL {
		r.errorf(KindRuleViolation, "keystone.project_cache_ttl", "%v must be positive and at most %v", s.Keystone.ProjectCacheTTL, maxProjectCacheTTL)
	}

	if s.NovaLookup.CacheTTL <= 0 || s.NovaLookup.CacheTTL > s.TokenTTL() {
		r.errorf(KindRuleViolation, "nova_lookup.cache_ttl", "%v must be positive and at most the token TTL (%v)", s.NovaLookup.CacheTTL, s.TokenTTL())
	}
	if len(s.NovaLookup.AllowedStatuses) == 0 {
		r.errorf(KindRuleViolation, "nova_lookup.allowed_statuses", "must list at least one status")
	}
	for i, status := range s.NovaLookup.AllowedStatuses {
		if !slices.Contains(novaStatusesAllowable, status) {
			r.errorf(KindRuleViolation, fmt.Sprintf("nova_lookup.allowed_statuses[%d]", i), "%q is not one of %v", status, novaStatusesAllowable)
		}
	}

	checkList(r, "enrich", s.Enrich)
	for i, claim := range s.Enrich {
		path := fmt.Sprintf("enrich[%d]", i)
		if !slices.Contains(iid.EnrichmentClaims(), claim) {
			r.errorf(KindRuleViolation, path, "%q is not one of %v", claim, iid.EnrichmentClaims())
		} else if slices.Contains(serverEnrichments, claim) && !s.NovaLookup.Enabled {
			r.errorf(KindRuleViolation, path, "%q requires nova_lookup.enabled", claim)
		}
	}
}

// warn flags valid but risky settings.
func (s *Signer) warn(r *Result[Signer]) {
	if !s.NovaLookup.Enabled {
		r.warnf("nova_lookup.enabled", "instance verification is disabled: Nova's claims about project and instance are not checked against the Nova API")
	}
	if len(s.Tags.Allowlist) == 0 {
		r.warnf("tags.allowlist", "not set: every string-valued metadata entry (up to %d bytes) is copied into tokens", iid.MaxTagsBytes)
	}
	if s.KeyStore.VaultProxyEndpoint != "" && s.KeyStore.Backend != BackendVaultTransit {
		r.warnf("key_store.vault_proxy_endpoint", "ignored by the %q backend", s.KeyStore.Backend)
	}
	if s.ClientAddress.Header != "" && len(s.ClientAddress.TrustedProxies) == 0 {
		r.warnf("client_address.header", "ignored without client_address.trusted_proxies: the TCP peer address is used")
	}
	for i, entry := range s.ClientAddress.TrustedProxies {
		if p, err := clientaddr.ParseTrustedProxy(entry); err == nil && p.Bits() == 0 {
			r.warnf(fmt.Sprintf("client_address.trusted_proxies[%d]", i), "%q trusts every address: any client can choose its own rate-limiting key", entry)
		}
	}
	if limit := s.RateLimitPerInstance; limit.Events > 0 && time.Duration(limit.Events)*recommendedInstanceRate.Per > limit.Per*time.Duration(recommendedInstanceRate.Events) {
		r.warnf("rate_limit_per_instance", "%s is looser than the recommended %s", limit, recommendedInstanceRate)
	}
}
