package syslog

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// levelOff is above every level a record is logged at.
const levelOff = slog.Level(1000)

func keepLogger(level slog.Level) (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	text := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(KeepAudit(text, level)), &buf
}

func TestKeepAuditWithLoggingOff(t *testing.T) {
	logger, buf := keepLogger(levelOff)
	logger.Info("token issued", AuditKey, "token_issued", "jti", "j1")
	logger.Log(context.Background(), LevelNotice, "signing key dropped", AuditKey, "key_lifecycle")
	logger.With(AuditKey, "key_lifecycle").Info("signing key active")
	logger.Info("serving")
	logger.Error("cannot sign token")
	logger.Debug("debug")

	out := buf.String()
	for _, want := range []string{"token issued", "signing key dropped", "signing key active"} {
		if strings.Count(out, want) != 1 {
			t.Errorf("audit record %q logged %d times, want 1:\n%s", want, strings.Count(out, want), out)
		}
	}
	for _, unwanted := range []string{"serving", "cannot sign token", "debug"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("ordinary record %q logged with logging off:\n%s", unwanted, out)
		}
	}
}

func TestKeepAuditAppliesTheLevelToOrdinaryRecords(t *testing.T) {
	logger, buf := keepLogger(slog.LevelWarn)
	logger.Info("info")
	logger.Warn("warn")
	logger.Info("token issued", AuditKey, "token_issued")
	out := buf.String()
	if strings.Contains(out, "msg=info") || !strings.Contains(out, "msg=warn") || !strings.Contains(out, "token issued") {
		t.Fatalf("unexpected output at level warn:\n%s", out)
	}
}

func TestKeepAuditLogsEverythingOnceAtDebug(t *testing.T) {
	logger, buf := keepLogger(slog.LevelDebug)
	logger.Debug("debug")
	logger.Info("token issued", AuditKey, "token_issued")
	out := buf.String()
	if strings.Count(out, "msg=debug") != 1 || strings.Count(out, "token issued") != 1 {
		t.Fatalf("each record should appear exactly once:\n%s", out)
	}
}

func TestKeepAuditRecognisesAuditRecordsLikeAuditHandler(t *testing.T) {
	logger, buf := keepLogger(levelOff)
	// not audit records for AuditHandler either: grouped, empty, or below info
	logger.WithGroup("g").Info("grouped", AuditKey, "token_issued")
	logger.Info("nested", slog.Group("g", AuditKey, "token_issued"))
	logger.Info("empty", AuditKey, "")
	logger.Debug("too low", AuditKey, "token_issued")
	// audit records: an attribute added before a group still counts
	logger.With(AuditKey, "token_issued").WithGroup("req").Info("with attrs then group", "id", "r1")
	logger.With("component", "signer").Info("with other attrs", AuditKey, "token_issued")

	out := buf.String()
	for _, unwanted := range []string{"grouped", "nested", "empty", "too low"} {
		if strings.Contains(out, "msg="+unwanted) || strings.Contains(out, `msg="`+unwanted) {
			t.Errorf("%q logged as an audit record:\n%s", unwanted, out)
		}
	}
	for _, want := range []string{"with attrs then group", "with other attrs"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q not logged:\n%s", want, out)
		}
	}
}

func TestKeepAuditEnabled(t *testing.T) {
	h := KeepAudit(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelDebug}), levelOff)
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("enabled at debug with logging off: no audit record is logged below info")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("not enabled at info with logging off: audit records would be lost")
	}
}
