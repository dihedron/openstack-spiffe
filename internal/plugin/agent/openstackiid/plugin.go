// Package openstackiid implements the agent side of the openstack_iid SPIRE
// node attestor: it fetches the instance identity token that the OpenStack
// metadata JWT issuer (openstack-spire-issuer) hands to the instance through
// Nova's DynamicJSON vendordata, and sends it to SPIRE Server as the
// attestation payload.
//
// The token's claims are bound to the real instance by the issuer, which
// authenticates Nova's service token against Keystone and cross-checks the
// instance and project against the Nova API before signing; this plugin
// relies on that invariant without being able to enforce it, and does not
// verify the token: it holds no keys, and SPIRE Server verifies anyway.
package openstackiid

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dihedron/openstack-spiffe/internal/plugin/config"
	"github.com/dihedron/openstack-spiffe/internal/plugin/logging"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
)

const (
	// DefaultVendorDataURL is Nova's metadata service, as seen from inside
	// the instance.
	DefaultVendorDataURL = "http://169.254.169.254/openstack/latest/vendor_data2.json"
	// maxDocumentBytes caps the whole vendor_data2.json document, which may
	// carry other vendordata targets besides the token.
	maxDocumentBytes = 1 << 20
	// defaultPollInterval is how often the vendordata is polled while
	// waiting for a fresh token.
	defaultPollInterval = time.Second
)

var (
	// ErrTargetMissing is returned (wrapped) when the vendordata has no
	// openstack_iid entry: Nova omits a DynamicJSON target whose call failed,
	// so the issuer was most likely unavailable.
	ErrTargetMissing = errors.New("vendordata has no " + iid.TargetName + " target")
	// ErrInvalidToken is returned (wrapped) when the vendordata carries
	// something that cannot be an openstack_iid token.
	ErrInvalidToken = errors.New("invalid token in vendordata")
	// ErrStaleToken is returned (wrapped) when the vendordata keeps serving
	// the token this plugin presented last, beyond fresh_token_timeout.
	ErrStaleToken = errors.New("vendordata keeps serving an already presented token")
)

var (
	_ pluginsdk.NeedsLogger = (*Plugin)(nil)
)

// Config is the plugin_data block of the agent configuration.
type Config struct {
	// VendorDataURL is the URL of vendor_data2.json.
	VendorDataURL string `hcl:"vendordata_url"`
	// HTTPTimeout bounds each fetch of the vendordata.
	HTTPTimeout string `hcl:"http_timeout"`
	// FreshTokenTimeout bounds the wait for a token different from the one
	// presented last.
	FreshTokenTimeout string `hcl:"fresh_token_timeout"`
}

var configKeys = []string{"vendordata_url", "http_timeout", "fresh_token_timeout"}

// ConfigKeys returns the keys plugin_data accepts (the documentation's
// completeness test reads them).
func ConfigKeys() []string { return slices.Clone(configKeys) }

// settings is the validated configuration.
type settings struct {
	url               string
	httpTimeout       time.Duration
	freshTokenTimeout time.Duration
	client            *http.Client
}

// Plugin is the agent-side openstack_iid node attestor.
type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	pollInterval time.Duration

	mu       sync.RWMutex
	settings *settings
	// lastJTI is the jti of the last token sent to SPIRE Server; it belongs
	// to the process, not to the configuration.
	lastJTI string
}

// New returns an unconfigured Plugin.
func New() *Plugin {
	return &Plugin{pollInterval: defaultPollInterval}
}

// SetLogger routes the plugin's logs, and those of log/slog, to SPIRE.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	slog.SetDefault(slog.New(logging.NewHandler(logger)))
}

// Configure validates and applies the plugin_data block.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	s, err := parseConfig(req.GetHclConfiguration())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	p.mu.Lock()
	p.settings = s
	p.mu.Unlock()
	return &configv1.ConfigureResponse{}, nil
}

func parseConfig(hcl string) (*settings, error) {
	var c Config
	if err := config.Decode(hcl, &c, configKeys); err != nil {
		return nil, err
	}
	s := &settings{url: c.VendorDataURL}
	if s.url == "" {
		s.url = DefaultVendorDataURL
	}
	u, err := url.Parse(s.url)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%w: vendordata_url: %q is not an http or https URL", config.ErrInvalid, s.url)
	}
	if s.httpTimeout, err = config.Duration("http_timeout", c.HTTPTimeout, 5*time.Second, time.Millisecond, 0); err != nil {
		return nil, err
	}
	if s.freshTokenTimeout, err = config.Duration("fresh_token_timeout", c.FreshTokenTimeout, 30*time.Second, s.httpTimeout, 0); err != nil {
		return nil, fmt.Errorf("%w (it must be at least http_timeout)", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// the metadata service is link-local: never route it through a proxy
	transport.Proxy = nil
	s.client = &http.Client{
		Transport: transport,
		// the configured URL itself must answer
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
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

// AidAttestation sends the token found in the vendordata as the attestation
// payload. It never sends the token it presented last: SPIRE Server accepts
// each token once, and Nova may keep serving the same one from its metadata
// cache, so it waits, bounded by fresh_token_timeout, for a fresh one.
// Errors are returned at once: retries are SPIRE Agent's business.
func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	s, err := p.getSettings()
	if err != nil {
		return err
	}
	ctx := stream.Context()

	token, jti, err := fetchToken(ctx, s)
	if err != nil {
		return attestationError(err)
	}
	p.mu.RLock()
	last := p.lastJTI
	p.mu.RUnlock()
	if jti == last {
		slog.InfoContext(ctx, "vendordata serves the token presented last, waiting for a fresh one", "jti", jti, "timeout", s.freshTokenTimeout)
		if token, jti, err = p.waitForFreshToken(ctx, s, last); err != nil {
			return attestationError(err)
		}
	}

	payload, err := json.Marshal(struct {
		JWT string `json:"jwt"`
	}{token})
	if err != nil {
		return status.Errorf(codes.Internal, "encoding payload: %v", err)
	}
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{Payload: payload},
	}); err != nil {
		return err
	}
	p.mu.Lock()
	p.lastJTI = jti
	p.mu.Unlock()
	// no challenge/response: the stream may be closed right after the payload
	return nil
}

// waitForFreshToken polls the vendordata until it serves a token whose jti
// differs from last, or fresh_token_timeout elapses.
func (p *Plugin) waitForFreshToken(ctx context.Context, s *settings, last string) (string, string, error) {
	deadline := time.Now().Add(s.freshTokenTimeout)
	ticker := time.NewTicker(p.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-ticker.C:
		}
		token, jti, err := fetchToken(ctx, s)
		if err != nil {
			return "", "", err
		}
		if jti != last {
			return token, jti, nil
		}
		if time.Now().After(deadline) {
			return "", "", fmt.Errorf("%w (jti %s) after %v; Nova may be caching it longer ([api] metadata_cache_expiration)", ErrStaleToken, last, s.freshTokenTimeout)
		}
	}
}

// attestationError maps a failure to obtain a token to a gRPC status: every
// such failure is transient from SPIRE Agent's point of view.
func attestationError(err error) error {
	return status.Errorf(codes.Unavailable, "fetching the instance identity token: %v", err)
}

// fetchToken reads vendor_data2.json and returns the openstack_iid token
// and its jti, read from the payload without verifying the signature.
func fetchToken(ctx context.Context, s *settings) (token, jti string, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.httpTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }() // read in full or abandoned: nothing to report
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("vendordata: unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("reading vendordata: %w", err)
	}
	if len(body) > maxDocumentBytes {
		return "", "", fmt.Errorf("vendordata larger than %d bytes", maxDocumentBytes)
	}

	var targets map[string]jsontext.Value
	if err := json.Unmarshal(body, &targets); err != nil {
		return "", "", fmt.Errorf("decoding vendordata: %w", err)
	}
	raw, ok := targets[iid.TargetName]
	if !ok {
		return "", "", fmt.Errorf("%w (Nova omits it when the issuer fails: check the issuer's readiness)", ErrTargetMissing)
	}
	var vd iid.VendorData
	if err := json.Unmarshal(raw, &vd); err != nil {
		return "", "", fmt.Errorf("decoding vendordata %s target: %w", iid.TargetName, err)
	}
	if jti, err = checkToken(vd.JWT); err != nil {
		return "", "", err
	}
	return vd.JWT, jti, nil
}

// checkToken checks that the token is a compact-serialized JWS within the
// size limit and returns its jti.
func checkToken(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("%w: no token", ErrInvalidToken)
	}
	if len(token) > iid.MaxTokenBytes {
		return "", fmt.Errorf("%w: %d bytes, at most %d allowed", ErrInvalidToken, len(token), iid.MaxTokenBytes)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", fmt.Errorf("%w: not a compact-serialized JWS", ErrInvalidToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("%w: decoding payload: %w", ErrInvalidToken, err)
	}
	var claims struct {
		ID string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("%w: decoding payload: %w", ErrInvalidToken, err)
	}
	if claims.ID == "" {
		return "", fmt.Errorf("%w: no jti", ErrInvalidToken)
	}
	return claims.ID, nil
}
