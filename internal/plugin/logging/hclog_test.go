package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func newLogger(level hclog.Level) (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	h := NewHandler(hclog.New(&hclog.LoggerOptions{Output: &buf, Level: level}))
	return slog.New(h), &buf
}

func TestLevels(t *testing.T) {
	logger, buf := newLogger(hclog.Info)
	logger.Debug("hidden")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message")
	out := buf.String()
	if strings.Contains(out, "hidden") {
		t.Errorf("debug record emitted at info level:\n%s", out)
	}
	for _, want := range []string{"[INFO]  info message", "[WARN]  warn message", "[ERROR] error message"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug enabled at info level")
	}
}

func TestAttributes(t *testing.T) {
	logger, buf := newLogger(hclog.Debug)
	logger.With("kid", "k1").WithGroup("req").Info("rejected", "instance_id", "i-1", slog.Group("tls", "version", "1.3"))
	out := buf.String()
	for _, want := range []string{"kid=k1", "req.instance_id=i-1", "req.tls.version=1.3"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}
