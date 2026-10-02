// Package logging bridges log/slog to the hclog logger SPIRE hands to its
// plugins, so that the openstack_iid plugins, and the issuer code they reuse,
// log into SPIRE's own log rather than to the plugin process's stderr.
package logging

import (
	"context"
	"log/slog"
	"slices"

	"github.com/hashicorp/go-hclog"
)

// Handler is a slog.Handler writing to an hclog.Logger. Attributes in
// groups are flattened into dotted keys (e.g. "req.instance_id").
type Handler struct {
	logger hclog.Logger
	attrs  []any
	groups []string
}

// NewHandler returns a Handler writing to logger.
func NewHandler(logger hclog.Logger) *Handler {
	return &Handler{logger: logger}
}

// Enabled reports whether the hclog logger emits records at level.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	switch {
	case level < slog.LevelInfo:
		return h.logger.IsDebug()
	case level < slog.LevelWarn:
		return h.logger.IsInfo()
	case level < slog.LevelError:
		return h.logger.IsWarn()
	default:
		return h.logger.IsError()
	}
}

// Handle writes the record with its attributes.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	args := slices.Clone(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		args = appendAttr(args, h.groups, a)
		return true
	})
	switch {
	case r.Level < slog.LevelInfo:
		h.logger.Debug(r.Message, args...)
	case r.Level < slog.LevelWarn:
		h.logger.Info(r.Message, args...)
	case r.Level < slog.LevelError:
		h.logger.Warn(r.Message, args...)
	default:
		h.logger.Error(r.Message, args...)
	}
	return nil
}

// WithAttrs returns a Handler adding attrs to every record.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = slices.Clone(h.attrs)
	for _, a := range attrs {
		c.attrs = appendAttr(c.attrs, h.groups, a)
	}
	return &c
}

// WithGroup returns a Handler qualifying the keys of later attributes with
// name.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := *h
	c.groups = append(slices.Clone(h.groups), name)
	return &c
}

// appendAttr appends a as hclog key/value pairs, flattening groups.
func appendAttr(args []any, groups []string, a slog.Attr) []any {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return args
	}
	if a.Value.Kind() == slog.KindGroup {
		if a.Key != "" {
			groups = append(slices.Clone(groups), a.Key)
		}
		for _, member := range a.Value.Group() {
			args = appendAttr(args, groups, member)
		}
		return args
	}
	key := a.Key
	for i := len(groups) - 1; i >= 0; i-- {
		key = groups[i] + "." + key
	}
	return append(args, key, a.Value.Any())
}
