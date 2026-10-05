// Package auditsink assembles the issuer's log handler: the regular log,
// optionally combined with the syslog audit sink, which sends the audit
// records (token_issued, key_lifecycle) to the local syslog daemon so that
// they can be forwarded off the host (R-1, R-3). The same handler is
// installed by "service start" and by the integration tests.
package auditsink

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"github.com/dihedron/openstack-spiffe/internal/issuer/requestid"
	"github.com/dihedron/openstack-spiffe/pkg/syslog"
)

// builtin is slog's built-in default handler, read before any program sets
// its own: dependencies are initialised before their importers.
var builtin = slog.Default().Handler()

// errBuiltin is returned for a base that is slog's built-in default handler.
var errBuiltin = errors.New("log handler: slog's built-in default handler cannot be wrapped (it writes through package log, which slog.SetDefault redirects to the wrapper, deadlocking); install a handler of your own first")

// Sink is the installed logging: its handler and, when the sink is enabled,
// the syslog audit handler behind it.
type Sink struct {
	// Handler is the handler to install as the default.
	Handler slog.Handler
	audit   *syslog.AuditHandler // nil when the sink is disabled
}

// Close sends the records still queued until the context is done, then
// closes the connection; it does nothing when the sink is disabled.
func (s *Sink) Close(ctx context.Context) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Close(ctx)
}

// Stats returns the syslog delivery statistics, and false when the sink is
// disabled.
func (s *Sink) Stats() (syslog.AuditStats, bool) {
	if s.audit == nil {
		return syslog.AuditStats{}, false
	}
	return s.audit.Stats(), true
}

// New returns the Sink whose handler is to be installed as the default: every record goes to
// base, the regular log, and, when the sink is enabled, the audit records
// also go to syslog. The request ID handler wraps both, so that the copy
// sent to syslog carries the request ID too. base decides which records the
// regular log keeps (see syslog.KeepAudit); the sink takes every audit
// record, whatever the regular log's level.
//
// Delivery to syslog never blocks: dropped records are reported on base,
// once when dropping starts and once when delivery resumes. New fails if
// the sink is enabled and its socket cannot be opened.
func New(base slog.Handler, cfg config.AuditSyslog) (*Sink, error) {
	if base == builtin {
		return nil, errBuiltin
	}
	if !cfg.Enabled {
		return &Sink{Handler: requestid.NewLogHandler(base)}, nil
	}
	facility, err := syslog.ParseFacility(cfg.Facility)
	if err != nil {
		return nil, fmt.Errorf("syslog audit sink: %w", err)
	}
	client, err := syslog.New(syslog.WithSocket(cfg.Socket), syslog.WithApplication(cfg.AppName))
	if err != nil {
		return nil, fmt.Errorf("syslog audit sink: %w", err)
	}
	log := slog.New(base)
	audit, err := syslog.NewAuditHandler(client, facility,
		syslog.WithFailureFunc(func(err error) {
			log.Warn("syslog audit records dropped, they remain in the regular log", "socket", cfg.Socket, "error", err)
		}),
		syslog.WithRecoveryFunc(func(dropped uint64) {
			log.Warn("syslog audit records delivered again", "socket", cfg.Socket, "dropped", dropped)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("syslog audit sink: %w", errors.Join(err, client.Close()))
	}
	return &Sink{Handler: requestid.NewLogHandler(slog.NewMultiHandler(base, audit)), audit: audit}, nil
}
