package integration

import (
	"log/slog"
	"os"
	"testing"

	"github.com/dihedron/openstack-spiffe/pkg/syslog"
)

// TestMain installs the regular log handler the binary's init installs:
// start wraps the default handler as service start does, which slog's
// built-in one does not allow.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(syslog.KeepAudit(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}), slog.LevelInfo)))
	os.Exit(m.Run())
}
