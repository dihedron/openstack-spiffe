package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"runtime"
	"runtime/pprof"
	"strings"

	"github.com/dihedron/openstack-spiffe/pkg/metadata"
	"github.com/joho/godotenv"
)

var (
	cpuprof *os.File
	memprof *os.File
)

func init() {
	const LevelNone = slog.Level(1000)

	options := &slog.HandlerOptions{
		Level:     LevelNone,
		AddSource: true,
	}

	// load .env file if specified and present
	if dotenv, ok := os.LookupEnv(metadata.DotEnvVarName); ok {
		slog.Info("loading .env file", "path", dotenv)
		if err := godotenv.Load(dotenv); err != nil {
			slog.Error("error loading .env file", "error", err)
		}
		slog.Info("successfully loaded .env file", "path", dotenv)
	}

	// get log elevel from environment variable where, given
	// the binary name "my-app", the environment variable is "MY_APP_LOG_LEVEL"
	level, ok := os.LookupEnv(
		fmt.Sprintf(
			"%s_LOG_LEVEL",
			strings.ReplaceAll(
				strings.ToUpper(
					path.Base(os.Args[0]),
				),
				"-",
				"_",
			),
		),
	)
	if ok {
		switch strings.ToLower(level) {
		case "debug", "dbg", "d", "trace", "trc", "t":
			options.Level = slog.LevelDebug
		case "informational", "info", "inf", "i":
			options.Level = slog.LevelInfo
		case "warning", "warn", "wrn", "w":
			options.Level = slog.LevelWarn
		case "error", "err", "e", "fatal", "ftl", "f":
			options.Level = slog.LevelError
		case "off", "none", "null", "nil", "no", "n":
			options.Level = LevelNone
			return
		}
	}

	// get the name of the file to log to from environment variable where, given
	// the binary name "my-app", the environment variable is "MY_APP_LOG_STREAM"
	var writer io.Writer = os.Stderr
	stream, ok := os.LookupEnv(
		fmt.Sprintf(
			"%s_LOG_STREAM",
			strings.ReplaceAll(
				strings.ToUpper(
					path.Base(os.Args[0]),
				),
				"-",
				"_",
			),
		),
	)
	if ok {
		switch strings.ToLower(stream) {
		case "stderr", "error", "err", "e":
			writer = os.Stderr
		case "stdout", "output", "out", "o":
			writer = os.Stdout
		case "file":
			filename := fmt.Sprintf("%s-%d.log", path.Base(os.Args[0]), os.Getpid())
			var err error
			writer, err = os.OpenFile(path.Clean(filename), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				writer = os.Stderr
			}
		}
	}

	// initialise the logger
	handler := slog.NewTextHandler(writer, options)
	slog.SetDefault(slog.New(handler))

	// check if CPU profiling should be enabled
	filename, ok := os.LookupEnv(
		fmt.Sprintf(
			"%s_CPU_PROFILE",
			strings.ReplaceAll(
				strings.ToUpper(
					path.Base(os.Args[0]),
				),
				"-",
				"_",
			),
		),
	)
	if ok && filename != "" {
		f, err := createPrivate(filename)
		if err != nil {
			slog.Error("could not create CPU profile", "error", err)
		}
		cpuprof = f
		if err := pprof.StartCPUProfile(f); err != nil {
			slog.Error("could not start CPU profile", "error", err)
		}
	}

	// check if CPU profiling should be enabled
	filename, ok = os.LookupEnv(
		fmt.Sprintf(
			"%s_MEM_PROFILE",
			strings.ReplaceAll(
				strings.ToUpper(
					path.Base(os.Args[0]),
				),
				"-",
				"_",
			),
		),
	)
	if ok && filename != "" {
		f, err := createPrivate(filename)
		if err != nil {
			slog.Error("could not create memory profile", "error", err)
		}
		memprof = f
	}
}

func cleanup() {
	if cpuprof != nil {
		defer cpuprof.Close()
		defer pprof.StopCPUProfile()
	}
	if memprof != nil {
		defer memprof.Close()
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(memprof); err != nil {
			slog.Error("could not write memory profile", "error", err)
		}
	}
}

// createPrivate creates (or truncates) a file only its owner can read, even
// if it already existed with a looser mode: profiles contain process memory,
// and the signer's holds private keys.
func createPrivate(name string) (*os.File, error) {
	f, err := os.OpenFile(path.Clean(name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
