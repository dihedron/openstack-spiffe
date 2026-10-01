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

	"github.com/dihedron/openstack-spiffe/internal/metadata/claims"
	"github.com/dihedron/openstack-spiffe/internal/metadata/novalookup"
	"github.com/dihedron/openstack-spiffe/internal/metadata/token"
	"github.com/dihedron/openstack-spiffe/pkg/iid"
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
	Mint(ctx context.Context, req claims.NovaRequest, enrichment claims.Enrichment) (string, error)
}

// Handler serves POST /attest.
type Handler struct {
	limiter      InstanceLimiter
	verifier     Verifier
	minter       Minter
	maxBodyBytes int64
}

// NewHandler creates the /attest handler. maxBodyBytes caps the request
// body (max_body_bytes), independently of any cap set by the middleware.
func NewHandler(limiter InstanceLimiter, verifier Verifier, minter Minter, maxBodyBytes int64) (*Handler, error) {
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
	return &Handler{limiter: limiter, verifier: verifier, minter: minter, maxBodyBytes: maxBodyBytes}, nil
}

// ServeHTTP handles a Nova vendordata request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(w, http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	if err != nil {
		if tooLarge := (*http.MaxBytesError)(nil); errors.As(err, &tooLarge) {
			slog.WarnContext(ctx, "rejecting oversized request body", "max_body_bytes", h.maxBodyBytes)
		} else {
			slog.WarnContext(ctx, "cannot read request body", "error", err)
		}
		fail(w, http.StatusBadRequest)
		return
	}
	var req claims.NovaRequest
	if err := json.Unmarshal(body, &req); err != nil {
		slog.WarnContext(ctx, "rejecting malformed request body", "error", err, "payload", redact(body))
		fail(w, http.StatusBadRequest)
		return
	}
	if err := req.Validate(); err != nil {
		slog.WarnContext(ctx, "rejecting invalid request", "error", err, "payload", redact(body))
		fail(w, http.StatusBadRequest)
		return
	}
	log := slog.With("project_id", req.ProjectID, "instance_id", req.InstanceID)

	if ok, retryAfter := h.limiter.Allow(req.InstanceID); !ok {
		log.WarnContext(ctx, "per-instance rate limit exceeded")
		w.Header().Set("Retry-After", strconv.FormatInt(int64(math.Ceil(retryAfter.Seconds())), 10))
		fail(w, http.StatusTooManyRequests)
		return
	}

	enrichment, err := h.verifier.Verify(ctx, req.ProjectID, req.InstanceID)
	if err != nil {
		// the verifier logs the details
		if errors.Is(err, novalookup.ErrInstanceMismatch) {
			fail(w, http.StatusForbidden)
		} else {
			fail(w, http.StatusServiceUnavailable)
		}
		return
	}

	jwt, err := h.minter.Mint(ctx, req, enrichment)
	if err != nil {
		// the minter logs the details
		switch {
		case errors.Is(err, token.ErrKeyStoreUnavailable):
			fail(w, http.StatusServiceUnavailable)
		case errors.Is(err, claims.ErrInvalidRequest):
			fail(w, http.StatusBadRequest)
		default:
			log.ErrorContext(ctx, "cannot mint token", "error", err)
			fail(w, http.StatusInternalServerError)
		}
		return
	}

	response, err := json.Marshal(iid.NewVendorDataResponse(jwt))
	if err != nil {
		log.ErrorContext(ctx, "cannot encode response", "error", err)
		fail(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	// the body is a credential: nobody may store it
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(response); err != nil {
		log.DebugContext(ctx, "cannot write response", "error", err)
	}
}

// fail replies with a bare status: details are logged, never sent to the
// client.
func fail(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}
