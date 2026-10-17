//go:build lab

// Command stress is the lab's stress test (.specs/openstack-spire-stress-test.md):
// it boots, stops, starts and deletes Nova instances on the lab for a given
// duration, as many in parallel as the lab holds, and checks the node and
// workload attestation of every one of them. Run it through "lab.sh stress".
//
//	stress run [options]   the stress test
//	stress cleanup         undo an interrupted run and delete kept instances
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	flags "github.com/jessevdk/go-flags"

	"github.com/dihedron/openstack-spiffe/test/lab/labkit"
)

// CleanupOptions are the options of "stress cleanup".
type CleanupOptions struct {
	StateDir string `long:"state-dir" env:"LAB_STATE_DIR" required:"true" description:"the lab's state directory"`
}

func main() {
	var global struct{}
	parser := flags.NewParser(&global, flags.Default)
	var runOptions RunOptions
	var cleanupOptions CleanupOptions
	runCommand, err := parser.AddCommand("run", "run the stress test",
		"Builds and deploys the code on the lab, then runs cycles of Nova instances for --duration, checking every node and workload attestation.", &runOptions)
	if err != nil {
		panic(err)
	}
	if _, err := parser.AddCommand("cleanup", "undo an interrupted run",
		"Undoes what an interrupted run left on the lab, and deletes the instances kept for inspection.", &cleanupOptions); err != nil {
		panic(err)
	}
	if _, err := parser.Parse(); err != nil {
		var ferr *flags.Error
		if errors.As(err, &ferr) && ferr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(exitLabSetup)
	}
	switch parser.Active.Name {
	case "run":
		// go-flags marks an option set by its default as set too
		given := func(name string) bool {
			o := runCommand.FindOptionByLongName(name)
			return o.IsSet() && !o.IsSetDefault()
		}
		durationSet := given("duration")
		if runOptions.SelfTest && !given("keep-failed") {
			// the self-test fails cycles on purpose: keeping them would
			// fill the lab
			runOptions.KeepFailed = 0
		}
		attestBoundSet := false
		if b, err := parseBounds(runOptions.Bound); err == nil && b[StepAttest] != DefaultBounds[StepAttest] {
			attestBoundSet = true
		}
		os.Exit(run(runOptions, durationSet, attestBoundSet))
	case "cleanup":
		os.Exit(cleanup(cleanupOptions))
	}
}

// cleanup is "stress cleanup".
func cleanup(o CleanupOptions) int {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	kit, err := labkit.Load(o.StateDir)
	if err != nil {
		log.Error("reading the lab", "error", err)
		return exitLabSetup
	}
	s := &Setup{kit: kit, lab: &kitLab{kit: kit}, log: log}
	if err := s.Recover(context.Background(), true); err != nil {
		log.Error("cleaning up", "error", err)
		return exitLabSetup
	}
	if err := os.Remove(keptPath(o.StateDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Error("forgetting the kept instances", "error", err)
		return exitLabSetup
	}
	fmt.Println("the lab is clean: no stress instance, entry or pending change left")
	return exitPass
}
