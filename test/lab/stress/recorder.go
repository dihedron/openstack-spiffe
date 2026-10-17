//go:build lab

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Recorder writes the run's records as they happen (spec, records and
// report), so that an interrupted run still has them.
type Recorder struct {
	dir     string
	events  *os.File
	samples *os.File
	log     *slog.Logger

	mu       sync.Mutex
	failures []Failure
	cycles   []CycleResult
}

func newRecorder(dir string, console io.Writer) (*Recorder, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	events, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("creating the events file: %w", err)
	}
	samples, err := os.OpenFile(filepath.Join(dir, "samples.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("creating the samples file: %w", err)
	}
	r := &Recorder{dir: dir, events: events, samples: samples}
	r.log = slog.New(fanout{
		slog.NewJSONHandler(events, &slog.HandlerOptions{Level: slog.LevelDebug}),
		slog.NewTextHandler(console, &slog.HandlerOptions{Level: slog.LevelInfo}),
	})
	return r, nil
}

func (r *Recorder) Close() {
	_ = r.events.Close()
	_ = r.samples.Close()
}

// Step records a cycle step.
func (r *Recorder) Step(c *CycleResult, s StepResult, err error) {
	attrs := []any{"cycle", c.ID, "kind", c.Kind, "distro", c.Distro, "instance_id", c.InstanceID,
		"step", s.Step, "duration", s.Duration.Seconds(), "bound", s.Bound.Seconds()}
	if err != nil {
		attrs = append(attrs, "outcome", "failed", "error", err.Error())
		r.log.Warn("step", attrs...)
		return
	}
	r.log.Info("step", append(attrs, "outcome", "ok")...)
}

// Failure records a failure.
func (r *Recorder) Failure(f Failure) {
	r.mu.Lock()
	r.failures = append(r.failures, f)
	r.mu.Unlock()
	r.log.Error("failure", "cycle", f.Cycle, "instance_id", f.InstanceID, "class", f.Class, "step", f.Step,
		"reason", f.Reason, "security", f.Security, "evidence", f.Evidence)
}

// Harness records a harness failure.
func (r *Recorder) Harness(reason string) {
	r.Failure(Failure{Time: time.Now(), Class: ClassHarness, Reason: reason})
}

// Cycle records a finished cycle.
func (r *Recorder) Cycle(c CycleResult) {
	r.mu.Lock()
	r.cycles = append(r.cycles, c)
	r.mu.Unlock()
	data, _ := json.Marshal(c)
	r.log.Debug("cycle", "record", json.RawMessage(data))
}

// Sample records a sample.
func (r *Recorder) Sample(s Sample) {
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, _ = r.samples.Write(append(data, '\n'))
}

func (r *Recorder) Failures() []Failure {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.failures)
}

func (r *Recorder) Cycles() []CycleResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.cycles)
}

// WriteJSON writes a file of the run's directory.
func (r *Recorder) WriteJSON(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", name, err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, name), append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}
	return nil
}

// fanout sends records to several handlers.
type fanout []slog.Handler

func (f fanout) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (f fanout) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (f fanout) WithGroup(name string) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(name)
	}
	return out
}
