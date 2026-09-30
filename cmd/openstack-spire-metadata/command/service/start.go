// Package service implements the "service" command group, which runs a
// vendordata signer replica.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/dihedron/openstack-spiffe/internal/vendordata/config"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/osclient"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/requestid"
	"github.com/dihedron/openstack-spiffe/internal/vendordata/server"
)

// Service groups the commands running the signer.
type Service struct {
	// Start runs a signer replica.
	Start Start `command:"start" description:"Run a vendordata signer replica."`
}

// Start runs a signer replica until SIGINT or SIGTERM.
type Start struct {
	// Config is the path of the signer configuration file.
	Config string `short:"c" long:"config" description:"Path to the signer configuration file." value-name:"PATH" required:"true"`
}

// Execute loads and checks the configuration (refusing to start on any
// error, logging warnings), authenticates with Keystone using the OS_*
// environment variables, and serves until SIGINT or SIGTERM, then shuts down
// gracefully.
func (cmd *Start) Execute(args []string) error {
	slog.SetDefault(slog.New(requestid.NewLogHandler(slog.Default().Handler())))

	cfg, warnings, err := config.LoadSigner(cmd.Config)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	for _, w := range warnings {
		slog.Warn("configuration warning", "file", w.File, "line", w.Line, "path", w.Path, "message", w.Message)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	creds, err := osclient.CredentialsFromEnv(nil)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	client, err := osclient.New(ctx, creds, cfg.Keystone.CACertPath)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	signer, err := server.NewSigner(ctx, cfg, client)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	return signer.Run(ctx)
}
