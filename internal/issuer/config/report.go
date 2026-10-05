package config

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Severity tells whether a finding prevents the configuration from being used.
type Severity int8

const (
	// SeverityError marks a finding that makes the configuration unusable.
	SeverityError Severity = iota + 1
	// SeverityWarning marks a valid but risky setting.
	SeverityWarning
)

// String returns the lowercase name of the severity.
func (s Severity) String() string {
	switch s {
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	default:
		return "unknown"
	}
}

// MarshalText encodes the severity by name.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// Kind classifies a finding.
type Kind int8

const (
	// KindSyntax marks a malformed YAML document.
	KindSyntax Kind = iota + 1
	// KindUnknownKey marks a key that is not part of the configuration schema.
	KindUnknownKey
	// KindInvalidValue marks a value of the wrong type or format.
	KindInvalidValue
	// KindRuleViolation marks a value breaking a validation rule.
	KindRuleViolation
	// KindInconsistency marks values that conflict across files.
	KindInconsistency
	// KindFile marks a problem with a file referenced by the configuration.
	KindFile
	// KindRisky marks a valid but risky setting.
	KindRisky
)

// String returns the name of the kind.
func (k Kind) String() string {
	switch k {
	case KindSyntax:
		return "syntax"
	case KindUnknownKey:
		return "unknown-key"
	case KindInvalidValue:
		return "invalid-value"
	case KindRuleViolation:
		return "rule-violation"
	case KindInconsistency:
		return "inconsistency"
	case KindFile:
		return "file"
	case KindRisky:
		return "risky"
	default:
		return "unknown"
	}
}

// MarshalText encodes the kind by name.
func (k Kind) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

// Finding is a single problem found in a configuration file.
type Finding struct {
	// File is the configuration file the finding refers to.
	File string `json:"-" yaml:"-"`
	// Line is the 1-based line of the offending key, or 0 when the value is
	// not in the file (e.g. a default or a missing required key).
	Line int `json:"line,omitzero" yaml:"line,omitempty"`
	// Path is the YAML path of the offending key (e.g. "key_store.algorithm").
	Path string `json:"path,omitzero" yaml:"path,omitempty"`
	// Severity tells whether the finding is an error or a warning.
	Severity Severity `json:"severity" yaml:"severity"`
	// Kind classifies the finding.
	Kind Kind `json:"kind" yaml:"kind"`
	// Message describes the problem.
	Message string `json:"message" yaml:"message"`
	// Suggestion is the closest known key, for unknown keys.
	Suggestion string `json:"suggestion,omitzero" yaml:"suggestion,omitempty"`
}

// String formats the finding as "file:line: path: message".
func (f Finding) String() string {
	var b strings.Builder
	if f.File != "" {
		b.WriteString(f.File)
		if f.Line > 0 {
			b.WriteString(":" + strconv.Itoa(f.Line))
		}
		b.WriteString(": ")
	} else if f.Line > 0 {
		b.WriteString("line " + strconv.Itoa(f.Line) + ": ")
	}
	if f.Path != "" {
		b.WriteString(f.Path + ": ")
	}
	b.WriteString(f.Message)
	if f.Suggestion != "" {
		fmt.Fprintf(&b, " (did you mean %q?)", f.Suggestion)
	}
	return b.String()
}

// Result is the outcome of checking a configuration file: the decoded
// configuration (nil if the document could not be parsed at all) and every
// finding.
type Result[T any] struct {
	// File is the name of the checked file.
	File string
	// Config is the decoded configuration, defaults included.
	Config *T
	// Findings lists every problem found, in discovery order.
	Findings []Finding
	// lines maps YAML paths to the line of their key.
	lines map[string]int
	// linePaths maps lines to the first YAML path found on them.
	linePaths map[int]string
}

// Errors returns the findings with error severity.
func (r *Result[T]) Errors() []Finding {
	return r.filter(SeverityError)
}

// Warnings returns the findings with warning severity.
func (r *Result[T]) Warnings() []Finding {
	return r.filter(SeverityWarning)
}

func (r *Result[T]) filter(severity Severity) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Severity == severity {
			out = append(out, f)
		}
	}
	return out
}

// Err joins all error findings, each wrapping ErrInvalidConfig; it is nil if
// there are none (warnings do not count).
func (r *Result[T]) Err() error {
	var errs []error
	for _, f := range r.Errors() {
		errs = append(errs, fmt.Errorf("%w: %s", ErrInvalidConfig, f))
	}
	return errors.Join(errs...)
}

func (r *Result[T]) add(f Finding) {
	f.File = r.File
	if f.Line == 0 && f.Path != "" {
		f.Line = r.lines[f.Path]
	}
	r.Findings = append(r.Findings, f)
}

// errorf records an error finding about the key at path.
func (r *Result[T]) errorf(kind Kind, path, format string, args ...any) {
	r.add(Finding{Path: path, Severity: SeverityError, Kind: kind, Message: fmt.Sprintf(format, args...)})
}

// warnf records a warning about a risky setting at path.
func (r *Result[T]) warnf(path, format string, args ...any) {
	r.add(Finding{Path: path, Severity: SeverityWarning, Kind: KindRisky, Message: fmt.Sprintf(format, args...)})
}
