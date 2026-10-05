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

	"github.com/dihedron/openstack-spiffe/internal/issuer/aggregator"
	"github.com/dihedron/openstack-spiffe/internal/issuer/keystore"
	"github.com/dihedron/openstack-spiffe/internal/plugin/config"
	"github.com/dihedron/openstack-spiffe/internal/plugin/logging"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
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
	// AllowedTagKeys lists the tag keys that become selectors; unset, every
	// tag does (T-3).
	AllowedTagKeys []string `hcl:"allowed_tag_keys"`
	// Reattest is CanReattest (default true; S-4, E-4).
	Reattest *bool `hcl:"reattest"`
	// ReattestAlertWindow is how soon a second attestation of an instance
	// raises an alert (default 5m, 0 disables, at most 1h; S-4, E-1).
	ReattestAlertWindow string `hcl:"reattest_alert_window"`
	// AuditSyslog sends the audit records to syslog too (R-2).
	AuditSyslog *AuditSyslogConfig `hcl:"audit_syslog"`
}

// AuditSyslogConfig is the audit_syslog block.
type AuditSyslogConfig struct {
	Enabled  bool   `hcl:"enabled"`
	Socket   string `hcl:"socket"`
	Facility string `hcl:"facility"`
	AppName  string `hcl:"app_name"`
}

var configKeys = []string{
	"jwks_url", "jwks_ca_cert_path", "tls_min_version",
	"jwks_refresh_interval", "jwks_fetch_timeout", "jwks_min_refetch_interval", "jwks_stale_key_retention",
	"allowed_project_ids", "clock_skew_tolerance",
	"allowed_tag_keys", "reattest", "reattest_alert_window",
	"audit_syslog.enabled", "audit_syslog.socket", "audit_syslog.facility", "audit_syslog.app_name",
}

// auditSettings is the validated audit_syslog block; comparable, so that a
// new Configure replaces the sink only when it changed.
type auditSettings struct {
	enabled         bool
	socket, appName string
	facility        syslog.Facility
}

// settings is the validated configuration, with the key source it drives.
type settings struct {
	trustDomain string
	skew        time.Duration
	// allowedProjects is nil when every project is allowed.
	allowedProjects map[string]bool
	// allowedTags is nil when every tag becomes a selector.
	allowedTags map[string]bool
	reattest    bool
	// alertWindow is 0 when re-attestation alerts are disabled.
	alertWindow time.Duration
	audit       auditSettings
	// warnings are logged once the configuration is in place.
	warnings []string
	keys     *keySource
}

// Plugin is the server-side openstack_iid node attestor.
type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	now func() time.Time
	// replay and reattests belong to the process, not to the
	// configuration: a new Configure call keeps them, with the startup
	// watermark.
	replay    *replayCache
	reattests *reattestTracker

	mu       sync.RWMutex
	settings *settings

	// logMu guards the logging setup: the handler records go to (SPIRE's
	// log, through hclog) and the syslog audit sink, if any.
	logMu   sync.Mutex
	logBase slog.Handler
	sink    *auditSink
}

// auditSink sends the audit records to syslog.
type auditSink struct {
	settings auditSettings
	handler  *syslog.AuditHandler
}

// auditDrainTimeout bounds how long a replaced sink's queued records are
// sent for.
const auditDrainTimeout = 5 * time.Second

// New returns an unconfigured Plugin.
func New() *Plugin {
	return &Plugin{
		now:       time.Now,
		replay:    newReplayCache(maxReplayEntries, processStart),
		reattests: newReattestTracker(maxTrackedInstances),
	}
}

// SetLogger routes the plugin's logs, and those of log/slog, to SPIRE.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	p.logBase = logging.NewHandler(logger)
	p.installLogging()
}

// installLogging makes the default logger write to the base handler and,
// if a sink is set, its audit records to syslog too; callers hold logMu.
func (p *Plugin) installLogging() {
	handler := p.logBase
	if p.sink != nil {
		handler = slog.NewMultiHandler(p.logBase, p.sink.handler)
	}
	slog.SetDefault(slog.New(handler))
}

// applyAudit sets up the syslog audit sink for the configured settings,
// unless they did not change, draining the previous sink if any. It fails,
// keeping the previous setup, if the socket cannot be opened.
func (p *Plugin) applyAudit(a auditSettings) error {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if (p.sink == nil && !a.enabled) || (p.sink != nil && p.sink.settings == a) {
		return nil
	}
	var next *auditSink
	if a.enabled {
		client, err := syslog.New(syslog.WithSocket(a.socket), syslog.WithApplication(a.appName))
		if err != nil {
			return fmt.Errorf("%w: audit_syslog: %w", config.ErrInvalid, err)
		}
		handler, err := syslog.NewAuditHandler(client, a.facility,
			syslog.WithFailureFunc(func(err error) {
				slog.Warn("syslog audit records dropped, they remain in SPIRE Server's log", "socket", a.socket, "error", err)
			}),
			syslog.WithRecoveryFunc(func(dropped uint64) {
				slog.Warn("syslog audit records delivered again", "socket", a.socket, "dropped", dropped)
			}))
		if err != nil {
			_ = client.Close()
			return fmt.Errorf("%w: audit_syslog: %w", config.ErrInvalid, err)
		}
		next = &auditSink{settings: a, handler: handler}
	}
	if p.sink == nil {
		// combine with whatever handler is in place: normally SPIRE's
		p.logBase = slog.Default().Handler()
	}
	previous := p.sink
	p.sink = next
	p.installLogging()
	if previous != nil {
		ctx, cancel := context.WithTimeout(context.Background(), auditDrainTimeout)
		defer cancel()
		_ = previous.handler.Close(ctx)
	}
	return nil
}

// Configure validates the plugin_data block and the trust domain, then
// replaces the configuration and the key source atomically.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	s, err := p.parseConfig(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := p.applyAudit(s.audit); err != nil {
		s.keys.close()
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p.mu.Lock()
	previous := p.settings
	p.settings = s
	p.mu.Unlock()
	if previous != nil {
		previous.keys.close()
	}
	for _, warning := range s.warnings {
		slog.WarnContext(ctx, "configuration warning", "message", warning)
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

	if len(c.AllowedTagKeys) > 0 {
		s.allowedTags = map[string]bool{}
		for i, key := range c.AllowedTagKeys {
			if err := iid.ValidateTagKey(key); err != nil {
				return nil, fmt.Errorf("%w: allowed_tag_keys[%d]: %w", config.ErrInvalid, i, err)
			}
			s.allowedTags[key] = true
		}
	}
	s.reattest = c.Reattest == nil || *c.Reattest
	if s.alertWindow, err = config.Duration("reattest_alert_window", c.ReattestAlertWindow, 5*time.Minute, 0, time.Hour); err != nil {
		return nil, err
	}
	if s.audit, err = parseAuditSyslog(c.AuditSyslog); err != nil {
		return nil, err
	}

	if c.JWKSCACertPath == "" {
		s.warnings = append(s.warnings, "jwks_ca_cert_path is not set: every public CA is trusted for the JWK Set (S-5)")
	}
	if s.allowedProjects == nil {
		s.warnings = append(s.warnings, "allowed_project_ids is not set: any project's instances attest, including those meant for another SPIRE deployment trusting the same issuer (S-8)")
	}
	if s.allowedTags == nil {
		s.warnings = append(s.warnings, "allowed_tag_keys is not set: every tag of a token becomes a selector, and tags are set by the instance's owner (T-3)")
	}
	if !s.audit.enabled {
		s.warnings = append(s.warnings, "audit_syslog is disabled: audit records reach only SPIRE Server's log (R-2)")
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

// parseAuditSyslog validates the audit_syslog block, with its defaults.
func parseAuditSyslog(c *AuditSyslogConfig) (auditSettings, error) {
	a := auditSettings{socket: syslog.DefaultSocket, appName: "openstack-server-plugin", facility: syslog.FacilityAuthpriv}
	if c == nil {
		return a, nil
	}
	a.enabled = c.Enabled
	if c.Socket != "" {
		a.socket = c.Socket
	}
	if c.AppName != "" {
		a.appName = c.AppName
	}
	if err := syslog.ValidateAppName(a.appName); err != nil {
		return a, fmt.Errorf("%w: audit_syslog.app_name: %w", config.ErrInvalid, err)
	}
	if c.Facility != "" {
		facility, err := syslog.ParseFacility(c.Facility)
		if err != nil {
			return a, fmt.Errorf("%w: audit_syslog.facility: %w", config.ErrInvalid, err)
		}
		a.facility = facility
	}
	return a, nil
}

func (p *Plugin) getSettings() (*settings, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.settings == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.settings, nil
}

// close stops the key source's background polling, and drains and closes
// the syslog audit sink.
func (p *Plugin) close() {
	p.mu.Lock()
	if p.settings != nil {
		p.settings.keys.close()
	}
	p.mu.Unlock()
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if p.sink != nil {
		ctx, cancel := context.WithTimeout(context.Background(), auditDrainTimeout)
		defer cancel()
		_ = p.sink.handler.Close(ctx)
		p.sink = nil
		p.installLogging()
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

	header, claims, err := p.verify(ctx, s, body.JWT)
	if err != nil {
		return err
	}
	for key := range claims.Tags {
		if s.allowedTags != nil && !s.allowedTags[key] {
			// tenants set tags: only the operator's keys become selectors
			slog.DebugContext(ctx, "tag ignored: not in allowed_tag_keys", "instance_id", claims.InstanceID, "key", key)
		}
	}
	attributes := &nodeattestorv1.AgentAttributes{
		SpiffeId:       SPIFFEID(s.trustDomain, claims),
		SelectorValues: Selectors(claims, s.allowedTags),
		CanReattest:    s.reattest,
	}
	// R-2: the jti ties this agent identity to the issuer's token_issued
	// record, and so to the Nova call and the key behind its token
	slog.InfoContext(ctx, "agent attested", syslog.AuditKey, "agent_attested",
		"project_id", claims.ProjectID, "instance_id", claims.InstanceID, "spiffe_id", attributes.SpiffeId,
		"jti", claims.ID, "kid", header.KeyID, "iat", claims.IssuedAt, "exp", claims.Expiry,
		"selectors", len(attributes.SelectorValues))
	now := p.now()
	if previous, interval, seen := p.reattests.record(claims.InstanceID, claims.ID, now); seen && s.alertWindow > 0 && interval < s.alertWindow {
		// never a rejection: a thief attesting first would lock the
		// legitimate agent out
		slog.WarnContext(ctx, "possible token theft: instance re-attested", syslog.AuditKey, "reattest_alert",
			"project_id", claims.ProjectID, "instance_id", claims.InstanceID,
			"jti", claims.ID, "previous_jti", previous, "interval", interval.Round(time.Second).String())
	}
	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{AgentAttributes: attributes},
	})
}

// verify runs every check on the token, the replay checks last so that
// only tokens passing every other check reach the replay cache, and maps
// failures to gRPC statuses. The token itself is never logged.
func (p *Plugin) verify(ctx context.Context, s *settings, token string) (iid.Header, iid.Claims, error) {
	keys, err := s.keys.keys(ctx)
	if err != nil {
		return iid.Header{}, iid.Claims{}, status.Errorf(codes.Unavailable, "reading verification keys: %v", err)
	}
	now := p.now()
	header, claims, err := Verify(token, lookupIn(keys), now, s.skew)
	if errors.Is(err, ErrUnknownKID) {
		// a key published since the last poll, or a peer that was briefly
		// unreachable: re-fetch (rate-limited) and try once more
		s.keys.refetch(ctx)
		if keys, err = s.keys.keys(ctx); err != nil {
			return iid.Header{}, iid.Claims{}, status.Errorf(codes.Unavailable, "reading verification keys: %v", err)
		}
		header, claims, err = Verify(token, lookupIn(keys), now, s.skew)
	}
	log := slog.With(append(kidAttributes(header.KeyID), "project_id", claims.ProjectID, "instance_id", claims.InstanceID)...)
	switch {
	case errors.Is(err, ErrUnknownKID) && len(keys) == 0:
		log.ErrorContext(ctx, "attestation rejected: no verification keys", "error", err)
		return iid.Header{}, iid.Claims{}, status.Error(codes.Unavailable, "no verification keys: the JWK Set has not been fetched successfully within jwks_stale_key_retention")
	case err != nil:
		log.WarnContext(ctx, "attestation rejected", "error", err)
		return iid.Header{}, iid.Claims{}, status.Errorf(codes.PermissionDenied, "attestation rejected: %v", err)
	}

	if s.allowedProjects != nil && !s.allowedProjects[claims.ProjectID] {
		log.WarnContext(ctx, "attestation rejected: project not allowed")
		return iid.Header{}, iid.Claims{}, status.Errorf(codes.PermissionDenied, "attestation rejected: project %s is not in allowed_project_ids", claims.ProjectID)
	}

	if err := p.replay.record(claims, now, s.skew); err != nil {
		switch {
		case errors.Is(err, ErrReplayCacheFull):
			log.ErrorContext(ctx, "attestation rejected: replay cache full", "error", err)
			return iid.Header{}, iid.Claims{}, status.Errorf(codes.Unavailable, "attestation rejected: %v", err)
		default:
			// transient for a legitimate agent: its next attempt carries a
			// fresh token
			log.WarnContext(ctx, "attestation rejected", "error", err)
			return iid.Header{}, iid.Claims{}, status.Errorf(codes.PermissionDenied, "attestation rejected: %v; a fresh token is needed", err)
		}
	}
	return header, claims, nil
}

// kidAttributes returns the log attributes describing a token's kid: the kid
// itself if it is well-formed, otherwise only its length, since a malformed
// kid is attacker-controlled content.
func kidAttributes(kid string) []any {
	if iid.ValidateKeyID(kid) != nil {
		return []any{"kid", "invalid", "kid_length", len(kid)}
	}
	return []any{"kid", kid}
}

func lookupIn(keys map[string]keystore.PublicKey) KeyLookup {
	return func(kid string) (keystore.PublicKey, bool) {
		k, ok := keys[kid]
		return k, ok
	}
}
