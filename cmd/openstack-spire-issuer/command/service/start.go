// Package service implements the "service" command group, which runs an
// OpenStack metadata signer replica.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dihedron/openstack-spiffe/internal/issuer/auditsink"
	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"github.com/dihedron/openstack-spiffe/internal/issuer/hardening"
	"github.com/dihedron/openstack-spiffe/internal/issuer/osclient"
	"github.com/dihedron/openstack-spiffe/internal/issuer/server"
)

// Service groups the commands running the signer.
type Service struct {
	// Start runs a signer replica.
	Start Start `command:"start" description:"Run an OpenStack metadata signer replica."`
}

// Start runs a signer replica until SIGINT or SIGTERM.
type Start struct {
	// Config is the path of the signer configuration file.
	Config string `short:"c" long:"config" description:"Path to the signer configuration file." value-name:"PATH" required:"true"`
}

// auditDrainTimeout bounds how long the syslog audit records still queued
// at shutdown are sent for, after the HTTP server's own graceful shutdown;
// together they stay within the systemd unit's stop timeout.
const auditDrainTimeout = 5 * time.Second

// Execute loads and checks the configuration (refusing to start on any
// error, logging warnings), installs the syslog audit sink if enabled
// (refusing to start if its socket cannot be opened), authenticates with
// Keystone using the OS_* environment variables, and serves until SIGINT or
// SIGTERM, then shuts down gracefully and drains the audit records still
// queued for syslog.
func (cmd *Start) Execute(args []string) error {
	cfg, warnings, err := config.LoadSigner(cmd.Config)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}

	sink, err := auditsink.New(slog.Default().Handler(), cfg.Audit.Syslog)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	slog.SetDefault(slog.New(sink.Handler))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), auditDrainTimeout)
		defer cancel()
		if err := sink.Close(ctx); err != nil {
			slog.Error("cannot send every queued audit record to syslog, they remain in the regular log", "error", err)
		}
	}()

	for _, w := range warnings {
		slog.Warn("configuration warning", "file", w.File, "line", w.Line, "path", w.Path, "message", w.Message)
	}

	// before any key exists: the keys live in this process's memory only
	// (I-4, I-5)
	if err := hardening.SetNonDumpable(); err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	if cfg.KeyStore.LockMemory {
		if err := hardening.LockMemory(); err != nil {
			return fmt.Errorf("refusing to start: %w", err)
		}
	}
	for _, kind := range []string{"CPU", "MEM"} {
		if variable := profileVariable(kind); os.Getenv(variable) != "" {
			slog.Warn("profiling is enabled: profiles may contain private key material; keep them private and delete them after use", "variable", variable)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	creds, err := osclient.CredentialsFromEnv(nil)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	client, err := osclient.New(ctx, creds, cfg.Keystone.CACertPath, osclient.WithMinTLSVersion(cfg.MinTLSVersion()))
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	signer, err := server.NewSigner(ctx, cfg, client, server.WithAuditSink(sink.Stats))
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	return signer.Run(ctx)
}

// profileVariable is the environment variable enabling a kind of profiling
// (CPU or MEM) for this binary, as its init reads it.
func profileVariable(kind string) string {
	name := strings.ReplaceAll(strings.ToUpper(filepath.Base(os.Args[0])), "-", "_")
	return name + "_" + kind + "_PROFILE"
}
