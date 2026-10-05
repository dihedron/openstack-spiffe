// Package health implements the /liveness and /readiness endpoints of the
// signer and of the JWKS aggregator. Readiness checks run in the background
// at a fixed interval, so that probes are answered at once, from the latest
// results, and dependencies are checked at a fixed rate however often the
// orchestrator probes.
package health

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Liveness returns the /liveness handler: 200 as long as the server serves.
func Liveness() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("ok\n"))
		}
	})
}

// Check is a named readiness check; Run returns nil when the dependency is
// usable.
type Check struct {
	Name string
	Run  func(ctx context.Context) error
}

// Readiness is the /readiness handler. It reports ready (200) only when
// every check passed in the latest run and that run is recent (within three
// intervals); before the first run, it reports not ready (503). The body
// lists each check as "ok" or "failing", without error details, which are
// logged when a check changes state. It is safe for concurrent use.
type Readiness struct {
	checks   []Check
	interval time.Duration
	timeout  time.Duration
	now      func() time.Time

	mu        sync.RWMutex
	results   map[string]error
	checkedAt time.Time
}

// Option configures a Readiness.
type Option func(*Readiness)

// WithInterval sets how often the checks run (default: 5s).
func WithInterval(d time.Duration) Option {
	return func(r *Readiness) { r.interval = d }
}

// WithTimeout bounds each check (default: 2s).
func WithTimeout(d time.Duration) Option {
	return func(r *Readiness) { r.timeout = d }
}

// WithClock sets the source of the current time (default: time.Now).
func WithClock(now func() time.Time) Option {
	return func(r *Readiness) { r.now = now }
}

// NewReadiness creates a Readiness running the given checks.
func NewReadiness(checks []Check, options ...Option) (*Readiness, error) {
	if len(checks) == 0 {
		return nil, errors.New("creating readiness: no checks")
	}
	seen := map[string]bool{}
	for _, c := range checks {
		switch {
		case c.Name == "" || c.Run == nil:
			return nil, errors.New("creating readiness: every check needs a name and a function")
		case seen[c.Name]:
			return nil, fmt.Errorf("creating readiness: duplicate check %q", c.Name)
		}
		seen[c.Name] = true
	}
	r := &Readiness{
		checks:   checks,
		interval: 5 * time.Second,
		timeout:  2 * time.Second,
		now:      time.Now,
	}
	for _, option := range options {
		option(r)
	}
	if r.interval <= 0 || r.timeout <= 0 {
		return nil, fmt.Errorf("creating readiness: interval (%v) and timeout (%v) must be positive", r.interval, r.timeout)
	}
	return r, nil
}

// Run runs the checks at once and then every interval, until the context
// is cancelled; it returns nil when the context is cancelled.
func (r *Readiness) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		r.runChecks(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// runChecks runs every check concurrently, each bounded by the timeout, and
// records the results.
func (r *Readiness) runChecks(ctx context.Context) {
	results := make([]error, len(r.checks))
	var wg sync.WaitGroup
	for i, c := range r.checks {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, r.timeout)
			defer cancel()
			results[i] = c.Run(ctx)
		})
	}
	wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()
	first := r.results == nil
	previous := r.results
	r.results = map[string]error{}
	for i, c := range r.checks {
		err := results[i]
		r.results[c.Name] = err
		switch {
		case err != nil && (first || previous[c.Name] == nil):
			slog.WarnContext(ctx, "readiness check failing", "check", c.Name, "error", err)
		case err == nil && !first && previous[c.Name] != nil:
			slog.InfoContext(ctx, "readiness check recovered", "check", c.Name)
		}
	}
	r.checkedAt = r.now()
}

// Results returns whether each check passed in its latest run; a check
// that has not run yet is absent.
func (r *Readiness) Results() map[string]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	results := make(map[string]bool, len(r.results))
	for name, err := range r.results {
		results[name] = err == nil
	}
	return results
}

// ServeHTTP reports the latest results.
func (r *Readiness) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if !allowed(w, req) {
		return
	}
	r.mu.RLock()
	ready := r.results != nil && r.now().Sub(r.checkedAt) < 3*r.interval
	report := struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}{Checks: map[string]string{}}
	for _, c := range r.checks {
		switch err, ran := r.results[c.Name]; {
		case !ran:
			report.Checks[c.Name] = "pending"
			ready = false
		case err != nil:
			report.Checks[c.Name] = "failing"
			ready = false
		default:
			report.Checks[c.Name] = "ok"
		}
	}
	r.mu.RUnlock()

	status := http.StatusOK
	report.Status = "ready"
	if !ready {
		status = http.StatusServiceUnavailable
		report.Status = "not ready"
	}
	body, err := json.Marshal(report, json.Deterministic(true))
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if req.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// allowed accepts GET and HEAD, replying 405 to anything else.
func allowed(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	return false
}
