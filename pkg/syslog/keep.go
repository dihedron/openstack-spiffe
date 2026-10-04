package syslog

import (
	"context"
	"log/slog"
	"slices"
)

// keepAudit is the handler returned by KeepAudit.
type keepAudit struct {
	next   slog.Handler
	level  slog.Leveler
	groups []string
	kind   string // audit kind added with WithAttrs, if any
}

// KeepAudit returns a handler passing to next the records at or above level,
// and the audit records whatever the level, so that lowering the verbosity
// of the regular log (even turning it off) never removes the audit trail
// from it. A record is an audit record exactly when AuditHandler would
// forward it: it is at slog.LevelInfo or above and carries a non-empty
// AuditKey attribute outside any group. next must be enabled at
// slog.LevelInfo for audit records to reach it.
func KeepAudit(next slog.Handler, level slog.Leveler) slog.Handler {
	return &keepAudit{next: next, level: level}
}

// Enabled implements slog.Handler.
func (h *keepAudit) Enabled(ctx context.Context, level slog.Level) bool {
	return (level >= h.level.Level() || level >= slog.LevelInfo) && h.next.Enabled(ctx, level)
}

// Handle implements slog.Handler.
func (h *keepAudit) Handle(ctx context.Context, record slog.Record) error {
	if record.Level < h.level.Level() && !h.isAudit(record) {
		return nil
	}
	return h.next.Handle(ctx, record)
}

func (h *keepAudit) isAudit(record slog.Record) bool {
	if record.Level < slog.LevelInfo {
		return false
	}
	kind := h.kind
	prefix := groupPrefix(h.groups)
	record.Attrs(func(a slog.Attr) bool {
		for _, f := range flatten(nil, prefix, a) {
			if f.key == AuditKey {
				kind = f.value.String()
			}
		}
		return true
	})
	return kind != ""
}

// WithAttrs implements slog.Handler.
func (h *keepAudit) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	clone := *h
	clone.next = h.next.WithAttrs(attrs)
	prefix := groupPrefix(h.groups)
	for _, a := range attrs {
		for _, f := range flatten(nil, prefix, a) {
			if f.key == AuditKey {
				clone.kind = f.value.String()
			}
		}
	}
	return &clone
}

// WithGroup implements slog.Handler.
func (h *keepAudit) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.next = h.next.WithGroup(name)
	clone.groups = append(slices.Clone(h.groups), name)
	return &clone
}
