package jwks

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/keystore"
)

// KeySource provides the public keys to serve; keystore.KeyStore implements
// it, and so will the aggregator's merged set.
type KeySource interface {
	PublicKeys(ctx context.Context) ([]keystore.PublicKey, error)
}

// Handler serves a KeySource as a JSON Web Key Set, typically at
// /.well-known/jwks.json. The content is read from the source on every
// request, so rotations are published without any further step.
type Handler struct {
	source       KeySource
	cacheControl string
}

// Option configures a Handler.
type Option func(*Handler) error

// WithMaxAge lets clients and intermediaries cache the set for the given
// whole number of seconds ("Cache-Control: public, max-age=N"). Zero, the
// default, sends "Cache-Control: no-cache", as signer replicas must: a cached
// replica set could hide a key published ahead from the aggregator.
func WithMaxAge(d time.Duration) Option {
	return func(h *Handler) error {
		if d < 0 || d%time.Second != 0 {
			return fmt.Errorf("max-age %v must be a non-negative whole number of seconds", d)
		}
		if d > 0 {
			h.cacheControl = fmt.Sprintf("public, max-age=%d", int64(d/time.Second))
		}
		return nil
	}
}

// NewHandler creates a Handler serving the given source.
func NewHandler(source KeySource, options ...Option) (*Handler, error) {
	if source == nil {
		return nil, errors.New("creating JWKS handler: no key source")
	}
	h := &Handler{source: source, cacheControl: "no-cache"}
	for _, option := range options {
		if err := option(h); err != nil {
			return nil, fmt.Errorf("creating JWKS handler: %w", err)
		}
	}
	return h, nil
}

// ServeHTTP answers GET and HEAD with the current key set; it replies 503 if
// the source fails and 500 if a key cannot be encoded, never a partial set.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	keys, err := h.source.PublicKeys(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "cannot read public keys for the JWKS", "error", err)
		h.fail(w, http.StatusServiceUnavailable)
		return
	}
	set := Set{Keys: make([]Key, 0, len(keys))}
	for _, k := range keys {
		key, err := FromPublicKey(k)
		if err != nil {
			slog.ErrorContext(ctx, "cannot encode public key for the JWKS", "kid", k.ID, "error", err)
			h.fail(w, http.StatusInternalServerError)
			return
		}
		set.Keys = append(set.Keys, key)
	}
	body, err := json.Marshal(set)
	if err != nil {
		slog.ErrorContext(ctx, "cannot encode the JWKS", "error", err)
		h.fail(w, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", h.cacheControl)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		if _, err := w.Write(body); err != nil {
			slog.DebugContext(ctx, "cannot write the JWKS response", "error", err)
		}
	}
}

// fail replies with a bare status, which nobody may cache; the cause is
// logged, never sent to the client.
func (h *Handler) fail(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}
