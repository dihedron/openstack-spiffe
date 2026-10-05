// Package attest implements POST /attest, the endpoint Nova calls as the
// openstack_iid DynamicJSON vendordata target. The caller has already been
// authenticated, and the per-source limit applied, by the surrounding
// middleware; this handler validates the request, applies the per-instance
// limit, verifies the instance, and returns a freshly minted token. Every
// failure ends in "no token issued".
package attest

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/auth"
	"github.com/dihedron/openstack-spiffe/internal/issuer/claims"
	"github.com/dihedron/openstack-spiffe/internal/issuer/clientaddr"
	"github.com/dihedron/openstack-spiffe/internal/issuer/metrics"
	"github.com/dihedron/openstack-spiffe/internal/issuer/novalookup"
	"github.com/dihedron/openstack-spiffe/internal/issuer/token"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
)

// InstanceLimiter limits token issuance per instance ID;
// *ratelimit.Limiter implements it.
type InstanceLimiter interface {
	Allow(key string) (bool, time.Duration)
}

// Verifier verifies the instance and looks up the enrichment claims;
// *novalookup.Verifier implements it.
type Verifier interface {
	Verify(ctx context.Context, projectID, instanceID string) (claims.Enrichment, error)
}

// Minter mints signed tokens; *token.Minter implements it.
type Minter interface {
	Mint(ctx context.Context, req claims.NovaRequest, enrichment claims.Enrichment) (token.Issued, error)
}

// Handler serves POST /attest.
type Handler struct {
	limiter      InstanceLimiter
	verifier     Verifier
	minter       Minter
	maxBodyBytes int64
	metrics      *metrics.Metrics // nil: none recorded
}

// Option configures a Handler.
type Option func(*Handler)

// WithMetrics records the issued tokens in m. The reasons of refusals are
// named whether or not it is set (see metrics.Reject).
func WithMetrics(m *metrics.Metrics) Option {
	return func(h *Handler) { h.metrics = m }
}

// NewHandler creates the /attest handler. maxBodyBytes caps the request
// body (max_body_bytes), independently of any cap set by the middleware.
func NewHandler(limiter InstanceLimiter, verifier Verifier, minter Minter, maxBodyBytes int64, options ...Option) (*Handler, error) {
	switch {
	case limiter == nil:
		return nil, errors.New("creating attest handler: no per-instance limiter")
	case verifier == nil:
		return nil, errors.New("creating attest handler: no instance verifier")
	case minter == nil:
		return nil, errors.New("creating attest handler: no minter")
	case maxBodyBytes <= 0:
		return nil, fmt.Errorf("creating attest handler: body cap %d must be positive", maxBodyBytes)
	}
	h := &Handler{limiter: limiter, verifier: verifier, minter: minter, maxBodyBytes: maxBodyBytes}
	for _, option := range options {
		option(h)
	}
	return h, nil
}

// ServeHTTP handles a Nova vendordata request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(ctx, w, http.StatusMethodNotAllowed, metrics.ReasonInvalidRequest)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	if err != nil {
		if tooLarge := (*http.MaxBytesError)(nil); errors.As(err, &tooLarge) {
			slog.WarnContext(ctx, "rejecting oversized request body", "max_body_bytes", h.maxBodyBytes)
		} else {
			slog.WarnContext(ctx, "cannot read request body", "error", err)
		}
		fail(ctx, w, http.StatusBadRequest, metrics.ReasonInvalidRequest)
		return
	}
	var req claims.NovaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		slog.WarnContext(ctx, "rejecting malformed request body", append([]any{"error", err}, redact(body)...)...)
		fail(ctx, w, http.StatusBadRequest, metrics.ReasonInvalidRequest)
		return
	}
	if err := req.Validate(); err != nil {
		slog.WarnContext(ctx, "rejecting invalid request", append([]any{"error", err}, redact(body)...)...)
		fail(ctx, w, http.StatusBadRequest, metrics.ReasonInvalidRequest)
		return
	}
	log := slog.With("project_id", req.ProjectID, "instance_id", req.InstanceID)

	if ok, retryAfter := h.limiter.Allow(req.InstanceID); !ok {
		log.WarnContext(ctx, "per-instance rate limit exceeded")
		w.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(retryAfter.Seconds())), 10))
		fail(ctx, w, http.StatusTooManyRequests, metrics.ReasonRateLimitedInstance)
		return
	}

	enrichment, err := h.verifier.Verify(ctx, req.ProjectID, req.InstanceID)
	if err != nil {
		// the verifier logs the details
		switch {
		case errors.Is(err, novalookup.ErrInstanceMismatch):
			fail(ctx, w, http.StatusForbidden, metrics.ReasonInstanceNotAllowed)
		case errors.Is(err, novalookup.ErrEnrichmentInvalid):
			fail(ctx, w, http.StatusServiceUnavailable, metrics.ReasonEnrichmentInvalid)
		default:
			fail(ctx, w, http.StatusServiceUnavailable, metrics.ReasonLookupUnavailable)
		}
		return
	}

	issued, err := h.minter.Mint(ctx, req, enrichment)
	if err != nil {
		// the minter logs the details
		switch {
		case errors.Is(err, token.ErrKeyStoreUnavailable):
			fail(ctx, w, http.StatusServiceUnavailable, metrics.ReasonKeyStoreUnavailable)
		case errors.Is(err, claims.ErrInvalidRequest):
			fail(ctx, w, http.StatusBadRequest, metrics.ReasonInvalidRequest)
		default:
			log.ErrorContext(ctx, "cannot mint token", "error", err)
			fail(ctx, w, http.StatusInternalServerError, metrics.ReasonSigningFailed)
		}
		return
	}

	// Nova nests the body under the target name: vendor_data2.json then
	// holds the token at openstack_iid.jwt (iid.VendorDataResponse)
	response, err := json.Marshal(iid.VendorData{JWT: issued.Token})
	if err != nil {
		log.ErrorContext(ctx, "cannot encode response", "error", err)
		fail(ctx, w, http.StatusInternalServerError, metrics.ReasonSigningFailed)
		return
	}
	auditIssued(ctx, r, req, issued)
	h.metrics.TokenIssued(ctx, issued.Algorithm, req.ProjectID, len(issued.Token))
	w.Header().Set("Content-Type", "application/json")
	// the body is a credential: nobody may store it
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(response); err != nil {
		log.DebugContext(ctx, "cannot write response", "error", err)
	}
}

// auditIssued writes the token_issued audit record (R-1): one per issued
// token, once the response is ready and before it is sent. With the server
// plugin's agent_attested record, which carries the same jti, it ties every
// agent identity to the Nova call, the replica and the key behind its token.
// The request ID is added by the log handler; the token itself is never
// part of the record.
func auditIssued(ctx context.Context, r *http.Request, req claims.NovaRequest, issued token.Issued) {
	attrs := []any{syslog.AuditKey, "token_issued"}
	if identity, ok := auth.IdentityFrom(ctx); ok {
		attrs = append(attrs, "user_id", identity.UserID)
	}
	attrs = append(attrs, "client_address", clientaddr.String(r))
	if client, ok := clientaddr.From(r); ok {
		if peer, ok := clientaddr.Peer(r); ok && peer != client {
			attrs = append(attrs, "peer_address", peer.String())
		}
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cert := r.TLS.PeerCertificates[0]
		attrs = append(attrs, "client_cert_subject", cert.Subject.String(), "client_cert_serial", cert.SerialNumber.Text(16))
	}
	attrs = append(attrs,
		"project_id", req.ProjectID,
		"instance_id", req.InstanceID,
		"jti", issued.ID,
		"kid", issued.KeyID,
		"iat", issued.IssuedAt,
		"exp", issued.Expiry,
	)
	slog.InfoContext(ctx, "token issued", attrs...)
}

// fail replies with a bare status, naming the reason for the metrics:
// details are logged, never sent to the client.
func fail(ctx context.Context, w http.ResponseWriter, status int, reason string) {
	metrics.Reject(ctx, reason)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}
