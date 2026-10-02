package openstackiid

import (
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dihedron/openstack-spiffe/internal/metadata/aggregator"
	"github.com/dihedron/openstack-spiffe/internal/metadata/keystore"
	"github.com/dihedron/openstack-spiffe/internal/plugin/config"
	"github.com/dihedron/openstack-spiffe/internal/plugin/logging"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

// maxPayloadBytes caps the attestation payload: a token of at most
// iid.MaxTokenBytes in a small JSON envelope.
const maxPayloadBytes = iid.MaxTokenBytes + 1024

// trustDomainPattern matches the characters a SPIFFE trust domain name may
// hold.
var trustDomainPattern = regexp.MustCompile(`^[a-z0-9._-]+$`)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

// Config is the plugin_data block of the server configuration.
type Config struct {
	JWKSURL                string   `hcl:"jwks_url"`
	JWKSCACertPath         string   `hcl:"jwks_ca_cert_path"`
	TLSMinVersion          string   `hcl:"tls_min_version"`
	JWKSRefreshInterval    string   `hcl:"jwks_refresh_interval"`
	JWKSFetchTimeout       string   `hcl:"jwks_fetch_timeout"`
	JWKSMinRefetchInterval string   `hcl:"jwks_min_refetch_interval"`
	JWKSStaleKeyRetention  string   `hcl:"jwks_stale_key_retention"`
	AllowedProjectIDs      []string `hcl:"allowed_project_ids"`
	ClockSkewTolerance     string   `hcl:"clock_skew_tolerance"`
}

var configKeys = []string{
	"jwks_url", "jwks_ca_cert_path", "tls_min_version",
	"jwks_refresh_interval", "jwks_fetch_timeout", "jwks_min_refetch_interval", "jwks_stale_key_retention",
	"allowed_project_ids", "clock_skew_tolerance",
}

// settings is the validated configuration, with the key source it drives.
type settings struct {
	trustDomain string
	skew        time.Duration
	// allowedProjects is nil when every project is allowed.
	allowedProjects map[string]bool
	keys            *keySource
}

// Plugin is the server-side openstack_iid node attestor.
type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	now func() time.Time
	// replay belongs to the process, not to the configuration: a new
	// Configure call keeps it, with its startup watermark.
	replay *replayCache

	mu       sync.RWMutex
	settings *settings
}

// New returns an unconfigured Plugin.
func New() *Plugin {
	return &Plugin{now: time.Now, replay: newReplayCache(maxReplayEntries, processStart)}
}

// SetLogger routes the plugin's logs, and those of log/slog, to SPIRE.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	slog.SetDefault(slog.New(logging.NewHandler(logger)))
}

// Configure validates the plugin_data block and the trust domain, then
// replaces the configuration and the key source atomically.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	s, err := p.parseConfig(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p.mu.Lock()
	previous := p.settings
	p.settings = s
	p.mu.Unlock()
	if previous != nil {
		previous.keys.close()
	}
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) parseConfig(req *configv1.ConfigureRequest) (*settings, error) {
	trustDomain := req.GetCoreConfiguration().GetTrustDomain()
	if !trustDomainPattern.MatchString(trustDomain) {
		return nil, fmt.Errorf("%w: trust domain %q from the core configuration is not a valid SPIFFE trust domain name", config.ErrInvalid, trustDomain)
	}
	var c Config
	if err := config.Decode(req.GetHclConfiguration(), &c, configKeys); err != nil {
		return nil, err
	}
	s := &settings{trustDomain: trustDomain}

	u, err := url.Parse(c.JWKSURL)
	switch {
	case c.JWKSURL == "":
		return nil, fmt.Errorf("%w: jwks_url is required", config.ErrInvalid)
	case err != nil || u.Scheme != "https" || u.Host == "":
		return nil, fmt.Errorf("%w: jwks_url: %q is not an https URL", config.ErrInvalid, c.JWKSURL)
	case strings.HasSuffix(u.Path, "/jwks/local.json"):
		return nil, fmt.Errorf("%w: jwks_url: %q serves a single replica's keys; use the peered replicas' or the aggregator's /.well-known/jwks.json", config.ErrInvalid, c.JWKSURL)
	}

	var minTLS uint16
	switch c.TLSMinVersion {
	case "", "1.3":
		minTLS = tls.VersionTLS13
	case "1.2":
		minTLS = tls.VersionTLS12
	default:
		return nil, fmt.Errorf("%w: tls_min_version: %q, want \"1.2\" or \"1.3\"", config.ErrInvalid, c.TLSMinVersion)
	}
	client, err := aggregator.NewHTTPClient(c.JWKSCACertPath, minTLS)
	if err != nil {
		return nil, fmt.Errorf("%w: jwks_ca_cert_path: %w", config.ErrInvalid, err)
	}

	refresh, err := config.Duration("jwks_refresh_interval", c.JWKSRefreshInterval, 30*time.Second, time.Second, 0)
	if err != nil {
		return nil, err
	}
	fetchTimeout, err := config.Duration("jwks_fetch_timeout", c.JWKSFetchTimeout, 5*time.Second, time.Millisecond, 0)
	if err != nil {
		return nil, err
	}
	if fetchTimeout >= refresh {
		return nil, fmt.Errorf("%w: jwks_fetch_timeout: %v must be less than jwks_refresh_interval (%v)", config.ErrInvalid, fetchTimeout, refresh)
	}
	minRefetch, err := config.Duration("jwks_min_refetch_interval", c.JWKSMinRefetchInterval, 5*time.Second, time.Millisecond, 0)
	if err != nil {
		return nil, err
	}
	retention, err := config.Duration("jwks_stale_key_retention", c.JWKSStaleKeyRetention, iid.TTL, iid.TTL, 0)
	if err != nil {
		return nil, err
	}
	if s.skew, err = config.Duration("clock_skew_tolerance", c.ClockSkewTolerance, 30*time.Second, 0, time.Minute); err != nil {
		return nil, err
	}
	if len(c.AllowedProjectIDs) > 0 {
		s.allowedProjects = map[string]bool{}
		for i, id := range c.AllowedProjectIDs {
			if err := iid.ValidateProjectID(id); err != nil {
				return nil, fmt.Errorf("%w: allowed_project_ids[%d]: %w", config.ErrInvalid, i, err)
			}
			s.allowedProjects[id] = true
		}
	}

	if s.keys, err = newKeySource(keySourceConfig{
		url: c.JWKSURL, client: client,
		refresh: refresh, fetchTimeout: fetchTimeout, retention: retention, minRefetch: minRefetch,
		now: p.now,
	}); err != nil {
		return nil, fmt.Errorf("%w: jwks_url: %w", config.ErrInvalid, err)
	}
	return s, nil
}

func (p *Plugin) getSettings() (*settings, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.settings == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.settings, nil
}

// close stops the key source's background polling.
func (p *Plugin) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.settings != nil {
		p.settings.keys.close()
	}
}

// Attest verifies the agent's token and, if it passes every check, returns
// the agent's SPIFFE ID and selectors, built from the verified claims only.
func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	s, err := p.getSettings()
	if err != nil {
		return err
	}
	ctx := stream.Context()
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	payload := req.GetPayload()
	if len(payload) > maxPayloadBytes {
		return status.Errorf(codes.InvalidArgument, "attestation payload of %d bytes, at most %d allowed", len(payload), maxPayloadBytes)
	}
	var body struct {
		JWT string `json:"jwt"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return status.Errorf(codes.InvalidArgument, "decoding attestation payload: %v", err)
	}
	if body.JWT == "" {
		return status.Error(codes.InvalidArgument, "attestation payload carries no jwt")
	}

	claims, err := p.verify(ctx, s, body.JWT)
	if err != nil {
		return err
	}
	attributes := &nodeattestorv1.AgentAttributes{
		SpiffeId:       SPIFFEID(s.trustDomain, claims),
		SelectorValues: Selectors(claims),
		CanReattest:    true,
	}
	slog.InfoContext(ctx, "agent attested", "project_id", claims.ProjectID, "instance_id", claims.InstanceID, "spiffe_id", attributes.SpiffeId)
	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{AgentAttributes: attributes},
	})
}

// verify runs every check on the token, the replay checks last so that
// only tokens passing every other check reach the replay cache, and maps
// failures to gRPC statuses. The token itself is never logged.
func (p *Plugin) verify(ctx context.Context, s *settings, token string) (iid.Claims, error) {
	keys, err := s.keys.keys(ctx)
	if err != nil {
		return iid.Claims{}, status.Errorf(codes.Unavailable, "reading verification keys: %v", err)
	}
	now := p.now()
	header, claims, err := Verify(token, lookupIn(keys), now, s.skew)
	if errors.Is(err, ErrUnknownKID) {
		// a key published since the last poll, or a peer that was briefly
		// unreachable: re-fetch (rate-limited) and try once more
		s.keys.refetch(ctx)
		if keys, err = s.keys.keys(ctx); err != nil {
			return iid.Claims{}, status.Errorf(codes.Unavailable, "reading verification keys: %v", err)
		}
		header, claims, err = Verify(token, lookupIn(keys), now, s.skew)
	}
	log := slog.With("kid", header.KeyID, "project_id", claims.ProjectID, "instance_id", claims.InstanceID)
	switch {
	case errors.Is(err, ErrUnknownKID) && len(keys) == 0:
		log.ErrorContext(ctx, "attestation rejected: no verification keys", "error", err)
		return iid.Claims{}, status.Error(codes.Unavailable, "no verification keys: the JWK Set has not been fetched successfully within jwks_stale_key_retention")
	case err != nil:
		log.WarnContext(ctx, "attestation rejected", "error", err)
		return iid.Claims{}, status.Errorf(codes.PermissionDenied, "attestation rejected: %v", err)
	}

	if s.allowedProjects != nil && !s.allowedProjects[claims.ProjectID] {
		log.WarnContext(ctx, "attestation rejected: project not allowed")
		return iid.Claims{}, status.Errorf(codes.PermissionDenied, "attestation rejected: project %s is not in allowed_project_ids", claims.ProjectID)
	}

	if err := p.replay.record(claims, now, s.skew); err != nil {
		switch {
		case errors.Is(err, ErrReplayCacheFull):
			log.ErrorContext(ctx, "attestation rejected: replay cache full", "error", err)
			return iid.Claims{}, status.Errorf(codes.Unavailable, "attestation rejected: %v", err)
		default:
			// transient for a legitimate agent: its next attempt carries a
			// fresh token
			log.WarnContext(ctx, "attestation rejected", "error", err)
			return iid.Claims{}, status.Errorf(codes.PermissionDenied, "attestation rejected: %v; a fresh token is needed", err)
		}
	}
	return claims, nil
}

func lookupIn(keys map[string]keystore.PublicKey) KeyLookup {
	return func(kid string) (keystore.PublicKey, bool) {
		k, ok := keys[kid]
		return k, ok
	}
}
