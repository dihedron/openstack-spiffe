package requestid

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestMiddleware(t *testing.T) {
	var seen string
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = From(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(Header, "forged")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !uuidPattern.MatchString(seen) {
		t.Fatalf("request ID %q is not a random UUID", seen)
	}
	if got := w.Header().Get(Header); got != seen {
		t.Fatalf("response header %q, want %q", got, seen)
	}

	first := seen
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/", nil))
	if w2.Header().Get(Header) == first {
		t.Fatal("two requests share an ID")
	}
}

func TestLogHandler(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(slog.NewTextHandler(&buf, nil))).With("component", "test")
	ctx := context.WithValue(context.Background(), contextKey{}, "req-1")

	logger.InfoContext(ctx, "with id")
	logger.WithGroup("g").InfoContext(ctx, "grouped", "k", "v")
	logger.InfoContext(context.Background(), "without id")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines:\n%s", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "request_id=req-1") || !strings.Contains(lines[0], "component=test") {
		t.Fatalf("line %q lacks request_id or the logger's attributes", lines[0])
	}
	if !strings.Contains(lines[1], "req-1") {
		t.Fatalf("grouped line %q lacks the request ID", lines[1])
	}
	if strings.Contains(lines[2], "request_id") {
		t.Fatalf("line %q has a request_id without one in the context", lines[2])
	}
}
