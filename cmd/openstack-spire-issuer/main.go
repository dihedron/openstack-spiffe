package main

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/dihedron/openstack-spiffe/cmd/openstack-spire-issuer/command"
	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
)

func main() {
	defer cleanup()

	// a .env file in the working directory is optional
	if err := godotenv.Load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("error loading .env file", "error", err)
	}

	options := command.Commands{}
	if _, err := flags.NewParser(&options, flags.HelpFlag|flags.PassDoubleDash).Parse(); err != nil {
		os.Exit(exitCode(err))
	}
}

// exitCode reports err and maps it to the process exit code: commands may
// carry their own code (e.g. "config check"), command line errors exit with 2
// and any other failure with 1.
func exitCode(err error) int {
	var coder interface{ ExitCode() int }
	if errors.As(err, &coder) {
		if message := err.Error(); message != "" { // empty: already reported
			fmt.Fprintf(os.Stderr, "error: %s\n", message)
		}
		return coder.ExitCode()
	}
	var flagsErr *flags.Error
	if errors.As(err, &flagsErr) {
		if flagsErr.Type == flags.ErrHelp {
			fmt.Fprintln(os.Stdout, flagsErr.Message)
			return 0
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return 1
}
