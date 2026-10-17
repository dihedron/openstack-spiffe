//go:build lab

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Streamer runs a long-running command on a VM (labkit.Lab.Stream).
type Streamer interface {
	Stream(ctx context.Context, vm, command string) (io.ReadCloser, error)
}

// followedJournals are the journals the run follows (spec, detection), as
// journalctl matches: the services' own records and their syslog audit.
var followedJournals = map[string]string{
	"issuer-a": "_SYSTEMD_UNIT=openstack-spire-issuer.service + SYSLOG_IDENTIFIER=openstack-spire-issuer",
	"issuer-b": "_SYSTEMD_UNIT=openstack-spire-issuer.service + SYSLOG_IDENTIFIER=openstack-spire-issuer",
	"spire":    "_SYSTEMD_UNIT=spire-server.service + SYSLOG_IDENTIFIER=openstack-server-plugin",
	"devstack": "_SYSTEMD_UNIT=devstack@n-api-meta.service",
}

// Journals follows the journals into the run's directory and the ledger,
// resuming after its last cursor when a stream ends (a VM restarted, an SSH
// connection dropped).
type Journals struct {
	lab    Streamer
	dir    string
	ledger *Ledger
	since  time.Time
	log    *slog.Logger

	mu   sync.Mutex
	last map[string]time.Time // the last entry's time per VM
}

func newJournals(lab Streamer, dir string, ledger *Ledger, since time.Time, log *slog.Logger) *Journals {
	return &Journals{lab: lab, dir: dir, ledger: ledger, since: since, log: log, last: map[string]time.Time{}}
}

// Run follows every journal until ctx ends.
func (j *Journals) Run(ctx context.Context) error {
	if err := os.MkdirAll(j.dir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", j.dir, err)
	}
	var wg sync.WaitGroup
	for vm, match := range followedJournals {
		f, err := os.OpenFile(filepath.Join(j.dir, vm+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return fmt.Errorf("creating the journal file of %s: %w", vm, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { _ = f.Close() }()
			j.follow(ctx, vm, match, f)
		}()
	}
	wg.Wait()
	return nil
}

func (j *Journals) follow(ctx context.Context, vm, match string, out io.Writer) {
	cursor := ""
	for ctx.Err() == nil {
		from := fmt.Sprintf("--since=@%d", j.since.Unix())
		if cursor != "" {
			from = "--after-cursor=" + quoteShell(cursor)
		}
		stream, err := j.lab.Stream(ctx, vm, "sudo journalctl -f -o json --no-pager "+from+" "+match)
		if err != nil {
			j.log.Warn("following a journal", "vm", vm, "error", err)
		} else {
			scanner := bufio.NewScanner(stream)
			scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
			for scanner.Scan() {
				line := scanner.Bytes()
				_, _ = out.Write(append(line, '\n'))
				e, err := parseEntry(vm, line)
				if err != nil {
					continue
				}
				if e.Cursor != "" {
					cursor = e.Cursor
				}
				j.ledger.Add(e)
				j.mu.Lock()
				j.last[vm] = e.Time
				j.mu.Unlock()
			}
			_ = stream.Close()
		}
		if ctx.Err() != nil {
			return
		}
		j.log.Warn("journal stream ended: resuming", "vm", vm)
		select {
		case <-ctx.Done():
		case <-time.After(5 * time.Second):
		}
	}
}

// Last is the time of the last entry received from a VM.
func (j *Journals) Last(vm string) time.Time {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.last[vm]
}

// Grep returns the lines of the saved journals that contain any of the
// needles, as "vm: message", for a failure's evidence.
func (j *Journals) Grep(needles []string) string {
	var b strings.Builder
	for vm := range followedJournals {
		f, err := os.Open(filepath.Join(j.dir, vm+".jsonl"))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			for _, n := range needles {
				if n != "" && strings.Contains(line, n) {
					if e, err := parseEntry(vm, []byte(line)); err == nil {
						fmt.Fprintf(&b, "%s %s: %s\n", e.Time.Format(time.RFC3339), vm, e.Message)
					}
					break
				}
			}
		}
		_ = f.Close()
	}
	return b.String()
}

func quoteShell(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
