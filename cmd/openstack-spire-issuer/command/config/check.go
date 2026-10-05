// Package config implements the "config" command group, which operates on
// the configuration files of the OpenStack metadata signer and JWKS
// aggregator.
package config

import (
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/dihedron/openstack-spiffe/internal/issuer/config"
	"go.yaml.in/yaml/v3"
)

// Exit codes of the check command.
const (
	exitValid   = 0
	exitInvalid = 1
	exitUsage   = 2
)

// Config groups the commands acting on configuration files.
type Config struct {
	// Check validates configuration files.
	Check Check `command:"check" alias:"c" description:"Validate signer and aggregator configuration files, reporting every problem found."`
}

// Check validates signer and aggregator configuration files and reports every
// finding: unknown keys, invalid values, rule violations, cross-file
// inconsistencies, problems with the referenced TLS/CA files and risky
// settings.
type Check struct {
	// Signers are the paths of the signer configuration files.
	Signers []string `short:"s" long:"signer" description:"Path to a signer configuration file (repeatable)." value-name:"PATH"`
	// Aggregator is the path of the JWKS aggregator configuration file.
	Aggregator *string `short:"a" long:"aggregator" description:"Path to the JWKS aggregator configuration file." value-name:"PATH"`
	// Format is the output format.
	//nolint:staticcheck // SA5008: go-flags reads repeated choice tags
	Format string `short:"f" long:"format" description:"The format of the report." default:"text" choice:"text" choice:"json" choice:"yaml"`
	// Strict turns warnings into failures.
	Strict bool `long:"strict" description:"Fail on warnings too."`
	// SkipFiles disables the checks on referenced TLS and CA files.
	SkipFiles bool `long:"skip-files" description:"Do not check the TLS and CA files referenced by the configuration."`
	// PrintEffective prints the configuration with defaults applied.
	PrintEffective bool `long:"print-effective" description:"Print the effective configuration, defaults included."`
}

// ExitError carries the process exit code of a command; a nil Err means the
// command has already reported the failure to the user.
type ExitError struct {
	// Code is the process exit code.
	Code int
	// Err describes the failure, if not reported yet.
	Err error
}

// Error returns the description of the failure, if any.
func (e *ExitError) Error() string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode returns the process exit code.
func (e *ExitError) ExitCode() int { return e.Code }

// Execute runs the check command.
func (cmd *Check) Execute(args []string) error {
	if len(args) > 0 {
		return &ExitError{Code: exitUsage, Err: fmt.Errorf("unexpected arguments: %s (configuration files are given with --signer and --aggregator)", strings.Join(args, " "))}
	}
	color := os.Getenv("NO_COLOR") == "" && isTerminal(os.Stdout)
	if code := cmd.run(os.Stdout, os.Stderr, color); code != exitValid {
		return &ExitError{Code: code} // already reported
	}
	return nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// fileReport is the report about a single configuration file.
type fileReport struct {
	File      string           `json:"file" yaml:"file"`
	Type      string           `json:"type" yaml:"type"`
	Valid     bool             `json:"valid" yaml:"valid"`
	Findings  []config.Finding `json:"findings" yaml:"findings"`
	Effective map[string]any   `json:"effective,omitempty" yaml:"effective,omitempty"`
	effective []byte           // YAML form, for text output
}

// report is the overall result of the check.
type report struct {
	Files    []fileReport `json:"files" yaml:"files"`
	Errors   int          `json:"errors" yaml:"errors"`
	Warnings int          `json:"warnings" yaml:"warnings"`
}

// run performs the check, writes the report to stdout and returns the exit
// code; problems preventing the check are written to stderr.
func (cmd *Check) run(stdout, stderr io.Writer, color bool) int {
	if len(cmd.Signers) == 0 && cmd.Aggregator == nil {
		_, _ = fmt.Fprintln(stderr, "error: specify at least one --signer or --aggregator configuration file")
		return exitUsage
	}
	opts := config.CheckOptions{SkipFiles: cmd.SkipFiles}

	var signers []*config.Result[config.Signer]
	for _, path := range cmd.Signers {
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return exitUsage
		}
		signers = append(signers, config.CheckSigner(path, data, opts))
	}
	var aggregator *config.Result[config.Aggregator]
	if cmd.Aggregator != nil {
		data, err := os.ReadFile(filepath.Clean(*cmd.Aggregator))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "error: %v\n", err)
			return exitUsage
		}
		aggregator = config.CheckAggregator(*cmd.Aggregator, data, opts)
	}
	config.CrossCheck(signers, aggregator)

	var r report
	for _, signer := range signers {
		r.add(newFileReport("signer", signer.File, signer.Findings, signer.Config, cmd.PrintEffective))
	}
	if aggregator != nil {
		r.add(newFileReport("aggregator", aggregator.File, aggregator.Findings, aggregator.Config, cmd.PrintEffective))
	}

	if err := r.write(stdout, cmd.Format, color); err != nil {
		slog.Error("cannot write the configuration report", "error", err)
		_, _ = fmt.Fprintf(stderr, "error: writing report: %v\n", err)
		return exitUsage
	}
	if r.Errors > 0 || (cmd.Strict && r.Warnings > 0) {
		return exitInvalid
	}
	return exitValid
}

func newFileReport[T any](kind, file string, findings []config.Finding, cfg *T, effective bool) fileReport {
	fr := fileReport{File: file, Type: kind, Valid: true, Findings: slices.Clone(findings)}
	// findings with a line first, in line order; then those without a line
	slices.SortStableFunc(fr.Findings, func(a, b config.Finding) int {
		if (a.Line == 0) != (b.Line == 0) {
			return cmp.Compare(b.Line, a.Line) // the one with a line first
		}
		return cmp.Compare(a.Line, b.Line)
	})
	for _, f := range fr.Findings {
		if f.Severity == config.SeverityError {
			fr.Valid = false
		}
	}
	if fr.Findings == nil {
		fr.Findings = []config.Finding{}
	}
	if effective && cfg != nil {
		// the YAML form is canonical (durations and rates as strings); the
		// generic map lets JSON output reuse it
		if data, err := yaml.Marshal(cfg); err == nil {
			fr.effective = data
			_ = yaml.Unmarshal(data, &fr.Effective)
		}
	}
	return fr
}

func (r *report) add(fr fileReport) {
	for _, f := range fr.Findings {
		switch f.Severity {
		case config.SeverityError:
			r.Errors++
		case config.SeverityWarning:
			r.Warnings++
		}
	}
	r.Files = append(r.Files, fr)
}

func (r *report) write(w io.Writer, format string, color bool) error {
	switch format {
	case "json":
		data, err := json.Marshal(r, jsontext.WithIndent("  "))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w, "%s\n", data)
		return err
	case "yaml":
		data, err := yaml.Marshal(r)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	default:
		return r.writeText(w, color)
	}
}

// ANSI escape sequences used to highlight the text report.
const (
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
	ansiBold   = "\x1b[1m"
	ansiReset  = "\x1b[0m"
)

// stickyWriter writes until the first error, which it keeps: the text
// report checks it once, at the end.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	var n int
	n, s.err = s.w.Write(p)
	return n, s.err
}

func (s *stickyWriter) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(s, format, args...) // kept in s.err
}

func (r *report) writeText(out io.Writer, color bool) error {
	w := &stickyWriter{w: out}
	paint := func(style, text string) string {
		if !color {
			return text
		}
		return style + text + ansiReset
	}

	for i, fr := range r.Files {
		if i > 0 {
			w.printf("\n")
		}
		errors, warnings := 0, 0
		for _, f := range fr.Findings {
			if f.Severity == config.SeverityError {
				errors++
			} else {
				warnings++
			}
		}
		status := paint(ansiGreen, "valid")
		if !fr.Valid {
			status = paint(ansiRed, "invalid")
		}
		w.printf("%s (%s): %s, %s, %s\n", paint(ansiBold, fr.File), fr.Type, status, plural(errors, "error"), plural(warnings, "warning"))

		if len(fr.Findings) > 0 {
			tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
			for _, f := range fr.Findings {
				line := "-"
				if f.Line > 0 {
					line = strconv.Itoa(f.Line)
				}
				severity := paint(ansiYellow, f.Severity.String())
				if f.Severity == config.SeverityError {
					severity = paint(ansiRed, f.Severity.String())
				}
				message := f.Message
				if f.Suggestion != "" {
					message += fmt.Sprintf(" (did you mean %q?)", f.Suggestion)
				}
				path := f.Path
				if path == "" {
					path = "-"
				}
				// buffered: Flush reports any write error
				_, _ = fmt.Fprintf(tw, "  line %s\t%s\t%s\t%s\t%s\n", line, severity, f.Kind, path, message)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
		}
		if len(fr.effective) > 0 {
			w.printf("  effective configuration:\n")
			for _, line := range strings.Split(strings.TrimRight(string(fr.effective), "\n"), "\n") {
				w.printf("    %s\n", line)
			}
		}
	}

	w.printf("\n")
	if r.Errors == 0 {
		summary := "configuration is valid"
		if r.Warnings > 0 {
			summary += " (" + plural(r.Warnings, "warning") + ")"
		}
		w.printf("%s\n", paint(ansiGreen, summary))
		return w.err
	}
	w.printf("%s\n", paint(ansiRed, fmt.Sprintf("configuration is invalid: %s, %s", plural(r.Errors, "error"), plural(r.Warnings, "warning"))))
	return w.err
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
