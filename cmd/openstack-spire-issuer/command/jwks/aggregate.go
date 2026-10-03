// Package jwks implements the "jwks" command group, which runs the JWKS
// aggregator.
package jwks

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/dihedron/openstack-spiffe/internal/metadata/config"
	"github.com/dihedron/openstack-spiffe/internal/metadata/requestid"
	"github.com/dihedron/openstack-spiffe/internal/metadata/server"
)

// JWKS groups the commands acting on JSON Web Key Sets.
type JWKS struct {
	// Aggregate runs the JWKS aggregator.
	Aggregate Aggregate `command:"aggregate" description:"Run the JWKS aggregator, merging the signer replicas' key sets."`
}

// Aggregate runs the JWKS aggregator until SIGINT or SIGTERM.
type Aggregate struct {
	// Config is the path of the aggregator configuration file.
	Config string `short:"c" long:"config" description:"Path to the aggregator configuration file." value-name:"PATH" required:"true"`
}

// Execute loads and checks the configuration, file checks included
// (refusing to start on any error, logging warnings), and serves the merged
// key set until SIGINT or SIGTERM, then shuts down gracefully.
func (cmd *Aggregate) Execute(args []string) error {
	slog.SetDefault(slog.New(requestid.NewLogHandler(slog.Default().Handler())))

	cfg, warnings, err := config.LoadAggregator(cmd.Config)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	for _, w := range warnings {
		slog.Warn("configuration warning", "file", w.File, "line", w.Line, "path", w.Path, "message", w.Message)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	aggregator, err := server.NewAggregator(cfg)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	return aggregator.Run(ctx)
}
