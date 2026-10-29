//go:build linux

package apply

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
)

// TestRunCatchUp (PR #71 review F9): with more directory versions queued
// in the spool than one capture reads (spool.MaxVersionsPerKind), keyroster
// -agent run applies again until the spool is drained, so the last
// version, which removes a principal, takes effect without waiting for
// another version to arrive.
func TestRunCatchUp(t *testing.T) {
	h := newTestHost(t, newFixture(t))
	h.installed("role:ops", "role:old")
	for range 68 {
		h.publishDir(h.spec("role:ops", "role:old"))
	}
	h.publishDir(h.spec("role:ops"))
	h.write()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, RunConfig{Config: h.cfg, Interval: 20 * time.Millisecond, Retry: time.Hour}, h.l)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !slices.Equal(h.principals("deploy"), []string{"role:ops"}) {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("70 queued directory versions: principals %v after 10 s, want the last version's [role:ops]", h.principals("deploy"))
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}

// TestRunChecks (AGENT-05, 03-08): keyroster-agent run writes the status
// at start (never applied), after an apply, and after the drift check that
// follows every apply; then the check runs again only once CheckEvery has
// passed on the clock, each time writing a status with the new last_check.
func TestRunChecks(t *testing.T) {
	h := newTestHost(t, newFixture(t))
	withOutbox(t, h)
	statuses := make(chan *heartbeat.Status, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var log syncLog
	h.cfg.Log = &log
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("run log:\n%s", log.String())
		}
	})
	go func() {
		done <- Run(ctx, RunConfig{Config: h.cfg, Interval: 20 * time.Millisecond, Retry: time.Hour,
			Status: func(s *heartbeat.Status) { statuses <- s }}, h.l)
	}()
	defer func() {
		cancel()
		<-done
	}()
	next := func(what string, cond func(s *heartbeat.Status) bool) *heartbeat.Status {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case s := <-statuses:
				if cond(s) {
					return s
				}
			case <-deadline:
				t.Fatalf("no status %s within 10 s", what)
			}
		}
	}
	if s := next("at start", func(*heartbeat.Status) bool { return true }); s.Generation != 0 || s.LastApply != nil {
		t.Fatalf("the first status: %+v", s)
	}
	h.publishDir(h.spec("role:ops"))
	h.write()
	applied := next("after the check that follows the apply", func(s *heartbeat.Status) bool { return s.LastApply != nil && s.LastCheck != nil })
	if applied.Generation == 0 || applied.LastCheck.Drift {
		t.Fatalf("after the apply and its check: %+v %+v", applied, applied.LastCheck)
	}
	// The spool was written file by file, so the loop may have applied
	// (and checked) more than once; once it is quiet, no further check
	// comes before CheckEvery has passed on the clock.
	for quiet := false; !quiet; {
		select {
		case s := <-statuses:
			if s.LastCheck == nil || s.LastCheck.At != applied.LastCheck.At {
				t.Fatalf("a check before CheckEvery passed: %+v", s.LastCheck)
			}
			applied = s
		case <-time.After(500 * time.Millisecond):
			quiet = true
		}
	}
	// 15 min +- 60 s: nothing at 13 min, a check by 16 min.
	h.clock.advance(13 * time.Minute)
	select {
	case s := <-statuses:
		t.Fatalf("a check 13 min after the last one: %+v", s.LastCheck)
	case <-time.After(500 * time.Millisecond):
	}
	h.clock.advance(3 * time.Minute)
	later := next("from the periodic check", func(s *heartbeat.Status) bool { return s.LastCheck != nil && s.LastCheck.At != applied.LastCheck.At })
	if later.Seq <= applied.Seq {
		t.Fatalf("seq %d after %d", later.Seq, applied.Seq)
	}
}

// TestRunPublishesFailedCheck (PR #72 review C16): a drift check that
// fails, for example because sshd -T refuses an sshd_config with a syntax
// error, writes a status that says so, instead of leaving the last
// healthy one in the outbox.
func TestRunPublishesFailedCheck(t *testing.T) {
	h := newTestHost(t, newFixture(t))
	withOutbox(t, h)
	h.installed("role:ops")
	statuses := make(chan *heartbeat.Status, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var log syncLog
	h.cfg.Log = &log
	go func() {
		done <- Run(ctx, RunConfig{Config: h.cfg, Interval: 20 * time.Millisecond, Retry: time.Hour,
			Status: func(s *heartbeat.Status) { statuses <- s }}, h.l)
	}()
	defer func() {
		cancel()
		<-done
	}()
	next := func(what string, cond func(s *heartbeat.Status) bool) *heartbeat.Status {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case s := <-statuses:
				if cond(s) {
					return s
				}
			case <-deadline:
				t.Fatalf("no status %s within 10 s; run log:\n%s", what, log.String())
			}
		}
	}
	first := next("from the first check", func(s *heartbeat.Status) bool { return s.LastCheck != nil })
	h.run.mu.Lock()
	h.run.rejectDropIn = func([]byte) bool { return true }
	h.run.mu.Unlock()
	h.clock.advance(17 * time.Minute)
	next("from the failed check", func(s *heartbeat.Status) bool { return s.LastCheck != nil && s.LastCheck.At != first.LastCheck.At })
	b, err := os.ReadFile(filepath.Join(h.l.Outbox(), heartbeat.StatusFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"error":"sshd_T_failed: `) {
		t.Fatalf("the outbox after a failed check names no sshd_T_failed:\n%s", b)
	}
	if _, err := heartbeat.ParseStatus(b); err != nil {
		t.Fatalf("the failed check's status does not pass the server's checks: %v", err)
	}
}

// TestCheckJitter: the drift check's period is 15 min +- 60 s, uniformly.
func TestCheckJitter(t *testing.T) {
	lo, hi := DefaultCheckEvery, DefaultCheckEvery
	for range 2000 {
		d := jitter(DefaultCheckEvery, DefaultCheckJitter)
		if d < DefaultCheckEvery-DefaultCheckJitter || d > DefaultCheckEvery+DefaultCheckJitter {
			t.Fatalf("jitter %s outside 15 min +- 60 s", d)
		}
		lo, hi = min(lo, d), max(hi, d)
	}
	if hi-lo < 100*time.Second {
		t.Fatalf("2000 draws span only %s", hi-lo)
	}
}

// syncLog is a goroutine-safe log buffer.
type syncLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *syncLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *syncLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
