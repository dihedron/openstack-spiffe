// Package requestid gives every HTTP request a unique ID, returned to the
// client in the X-Request-Id header and added as "request_id" to every log
// record written with the request's context, so that all the records of a
// request can be correlated.
package requestid

import (
	"context"
	"log/slog"
	"net/http"
	"uuid"
)

// Header is the response header carrying the request ID.
const Header = "X-Request-Id"

type contextKey struct{}

// Middleware assigns a fresh random ID to each request. Incoming X-Request-Id
// headers are ignored: IDs are generated here, so clients cannot forge or
// collide them.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewV4().String()
		w.Header().Set(Header, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, id)))
	})
}

// From returns the request ID stored in the context, if any.
func From(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(contextKey{}).(string)
	return id, ok
}

// LogHandler wraps a slog.Handler, adding the request ID found in each
// record's context as the "request_id" attribute.
type LogHandler struct {
	slog.Handler
}

// NewLogHandler wraps next.
func NewLogHandler(next slog.Handler) *LogHandler {
	return &LogHandler{Handler: next}
}

// Handle adds the request ID, if any, and passes the record on.
func (h *LogHandler) Handle(ctx context.Context, r slog.Record) error {
	if id, ok := From(ctx); ok {
		r = r.Clone()
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs keeps the wrapper around the derived handler.
func (h *LogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LogHandler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup keeps the wrapper around the derived handler.
func (h *LogHandler) WithGroup(name string) slog.Handler {
	return &LogHandler{Handler: h.Handler.WithGroup(name)}
}
