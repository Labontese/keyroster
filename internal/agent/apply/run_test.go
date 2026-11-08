//go:build linux

package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/hostcert"
	probecert "github.com/Labontese/keyroster/internal/agent/probe"
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

// TestRunHostCertsWhenDue: the run loop calls HostCerts once at start,
// after an Apply, after a check, when the host-certificate answers' digest
// changes and when the due time it returned has passed, and not otherwise
// (03-09). The loop is driven iteration by iteration through the
// Iteration hook and the fake clock; nothing sleeps.
func TestRunHostCertsWhenDue(t *testing.T) {
	h := newHostCertHost(t)
	h.publishDir(h.hostSpec(h.sshd.pub))
	h.write()
	var calls atomic.Int32
	iter := make(chan int32)
	step := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, RunConfig{Config: h.cfg, Interval: time.Millisecond, Retry: time.Hour, CheckEvery: 10 * time.Minute,
			HostCerts: func() { calls.Add(1) },
			Iteration: func() {
				select {
				case iter <- calls.Load():
				case <-ctx.Done():
					return
				}
				select {
				case <-step:
				case <-ctx.Done():
				}
			}}, h.l)
	}()
	defer func() {
		cancel()
		<-done
	}()
	// next lets the loop finish one iteration and returns the call count.
	next := func(t *testing.T) int32 {
		t.Helper()
		select {
		case n := <-iter:
			return n
		case <-time.After(30 * time.Second):
			t.Fatal("no loop iteration within 30 s")
			return 0
		}
	}
	idle := func(t *testing.T, what string, want int32) {
		t.Helper()
		for i := range 10 {
			step <- struct{}{}
			if n := next(t); n != want {
				t.Fatalf("%s: iteration %d called HostCerts (%d calls, want %d)", what, i, n, want)
			}
		}
	}
	// Once at start (with the round's apply and check).
	if n := next(t); n != 1 {
		t.Fatalf("the first iteration called HostCerts %d times, want once", n)
	}
	idle(t, "after start", 1)

	// The answers' digest changes.
	h.answer()
	step <- struct{}{}
	if n := next(t); n != 2 {
		t.Fatalf("a new answer: %d calls, want 2", n)
	}
	idle(t, "after the answer", 2)

	t.Run("answer_replaced_under_same_name", func(t *testing.T) {
		ents, err := os.ReadDir(h.spool)
		if err != nil {
			t.Fatal(err)
		}
		replaced := false
		for _, d := range ents {
			if !hostcert.AnswerFileRE.MatchString(d.Name()) {
				continue
			}
			p := filepath.Join(h.spool, d.Name())
			b, err := os.ReadFile(p) //nolint:gosec // test fixture
			if err != nil {
				t.Fatal(err)
			}
			// The same name and size, another mtime.
			if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			at := time.Unix(1_700_000_000, 0)
			if err := os.Chtimes(p, at, at); err != nil {
				t.Fatal(err)
			}
			replaced = true
		}
		if !replaced {
			t.Fatal("no answer in the spool to replace")
		}
		step <- struct{}{}
		if n := next(t); n != 3 {
			t.Fatalf("an answer replaced under its name: %d calls, want 3", n)
		}
		idle(t, "after the replaced answer", 3)
	})

	// A check (the clock passes CheckEvery; the next renewal is days
	// away) calls it once.
	h.clock.advance(11 * time.Minute)
	step <- struct{}{}
	if n := next(t); n != 4 {
		t.Fatalf("after a check: %d calls, want 4", n)
	}
	idle(t, "after the check", 4)

	// An Apply calls it once.
	h.publishDir(h.hostSpec(h.sshd.pub))
	h.write()
	step <- struct{}{}
	n := next(t)
	if n < 5 {
		t.Fatalf("after an apply: %d calls, want one more", n)
	}
	for {
		// The spool was written file by file: the loop may apply more
		// than once, each time once more. Wait until it is quiet.
		step <- struct{}{}
		m := next(t)
		if m == n {
			break
		}
		n = m
	}
	idle(t, "after the apply", n)

	// The renewal time passes (a check is due as well): one call, which
	// requests the renewal.
	h.renewDue()
	step <- struct{}{}
	if m := next(t); m != n+1 {
		t.Fatalf("after RenewAt: %d calls, want %d", m, n+1)
	}
	idle(t, "after the renewal request", n+1)
	// The due time it returned passes (the request's 330 s), before the
	// next check: one call.
	h.clock.advance(331 * time.Second)
	step <- struct{}{}
	if m := next(t); m != n+2 {
		t.Fatalf("after the due time: %d calls, want %d", m, n+2)
	}
	idle(t, "after the due time", n+2)
}

// TestRunProbeTrigger (03-10b): the probe answers are no spool documents
// and no apply trigger; ProbeCerts runs once at start, once when the
// probe answers' digest changes, and when its due time passes.
func TestRunProbeTrigger(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "probecert-positive.answer"), []byte("{}"))
	if names, err := spoolDocuments(dir); err != nil || names != "" {
		t.Fatalf("spool documents %q, %v: a probe answer is no document", names, err)
	}
	h := newProbeHost(t)
	h.installed("role:ops")
	var calls atomic.Int32
	iter := make(chan int32)
	step := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, RunConfig{Config: h.cfg, Interval: time.Millisecond, Retry: time.Hour, CheckEvery: 24 * time.Hour,
			ProbeCerts: func() { calls.Add(1) },
			Iteration: func() {
				select {
				case iter <- calls.Load():
				case <-ctx.Done():
					return
				}
				select {
				case <-step:
				case <-ctx.Done():
				}
			}}, h.l)
	}()
	defer func() {
		cancel()
		<-done
	}()
	next := func() int32 {
		t.Helper()
		select {
		case n := <-iter:
			return n
		case <-time.After(30 * time.Second):
			t.Fatal("no loop iteration within 30 s")
			return 0
		}
	}
	idle := func(what string, want int32) {
		t.Helper()
		for i := range 5 {
			step <- struct{}{}
			if n := next(); n != want {
				t.Fatalf("%s: iteration %d: %d ProbeCerts calls, want %d", what, i, n, want)
			}
		}
	}
	if n := next(); n != 1 {
		t.Fatalf("the first iteration: %d calls, want 1", n)
	}
	idle("after start", 1)
	out := h.outbox()
	c := h.issueFor(out[probecert.Positive], nil)
	h.writeProbeAnswer(probecert.Positive, hostcert.Answer{RequestID: hexOf(out[probecert.Positive].RequestID[:]), Certificate: c.Marshal()})
	step <- struct{}{}
	if n := next(); n != 2 {
		t.Fatalf("a new probe answer: %d calls, want 2", n)
	}
	idle("after the answer", 2)
	// The negative's request is abandoned after hostcert.RequestTTL: due.
	h.clock.advance((hostcert.RequestTTL + 1) * time.Second)
	step <- struct{}{}
	if n := next(); n != 3 {
		t.Fatalf("past the due time: %d calls, want 3", n)
	}
}

// TestRunHeldTrigger (03-10b, D9, T-03-384): a new probe pair while a held
// record exists makes the next round apply at once, without waiting for
// Retry; with no held record it does not. Identical held applies in a row
// are printed and logged once.
func TestRunHeldTrigger(t *testing.T) {
	type loop struct {
		applies, held atomic.Int32
		log           *syncLog
		step          chan struct{}
		iter          chan struct{}
	}
	start := func(t *testing.T, h *probeHost, retry time.Duration, exec Runner) *loop {
		t.Helper()
		lp := &loop{log: &syncLog{}, step: make(chan struct{}), iter: make(chan struct{})}
		cfg := h.cfg
		cfg.Log = lp.log
		if exec != nil {
			cfg.Exec = exec
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- Run(ctx, RunConfig{Config: cfg, Interval: time.Millisecond, Retry: retry, CheckEvery: 24 * time.Hour,
				Out: func(_ *Report, err error) {
					lp.applies.Add(1)
					if errors.Is(err, ErrProbeHeld) {
						lp.held.Add(1)
					}
				},
				Iteration: func() {
					select {
					case lp.iter <- struct{}{}:
					case <-ctx.Done():
						return
					}
					select {
					case <-lp.step:
					case <-ctx.Done():
					}
				}}, h.l)
		}()
		t.Cleanup(func() {
			cancel()
			<-done
		})
		return lp
	}
	next := func(t *testing.T, lp *loop) {
		t.Helper()
		select {
		case <-lp.iter:
		case <-time.After(60 * time.Second):
			t.Fatal("no loop iteration within 60 s")
		}
	}
	// pairInSpool: the host's probe requests are answered in the spool and
	// the KRL in force lists the negative, so ProbeCerts makes a usable pair.
	pairInSpool := func(t *testing.T, h *probeHost) {
		t.Helper()
		h.mustProbeCerts()
		certs := h.answerAll()
		h.listMach(certs[probecert.Negative].Serial)
	}
	t.Run("held_record_applies_at_once", func(t *testing.T) {
		h := newProbeHost(t)
		h.gateOn()
		h.installed("role:ops")
		pairInSpool(t, h)
		h.publishDir(h.spec("role:ops", "role:new"))
		r, err := h.apply()
		// The pair's requests are live: the gate names them.
		mustHeld(t, h.testHost, r, err, "issue_unanswered")
		lp := start(t, h, time.Hour, nil)
		next(t, lp) // the first round: the held apply, then ProbeCerts keeps the pair
		if n := lp.applies.Load(); n != 1 {
			t.Fatalf("the first round: %d applies, want 1", n)
		}
		lp.step <- struct{}{}
		next(t, lp)
		if n := lp.applies.Load(); n != 2 || !slices.Contains(h.principals("deploy"), "role:new") {
			t.Fatalf("after the new pair: %d applies, principals %v", n, h.principals("deploy"))
		}
		if h.heldNow() != "" {
			t.Fatalf("held %q after the addition landed", h.heldNow())
		}
	})
	t.Run("no_held_record_waits", func(t *testing.T) {
		h := newProbeHost(t)
		h.gateOn()
		h.installed("role:ops")
		pairInSpool(t, h)
		h.mustApply()
		lp := start(t, h, time.Hour, nil)
		next(t, lp)
		for range 3 {
			lp.step <- struct{}{}
			next(t, lp)
		}
		if n := lp.applies.Load(); n != 0 {
			t.Fatalf("%d applies without a held record, want 0", n)
		}
		if rec := h.record(); rec == nil || rec.Committed.Empty() {
			t.Fatal("ProbeCerts kept no pair: the trigger was not exercised")
		}
	})
	t.Run("identical_holds_print_and_log_once", func(t *testing.T) {
		h := newProbeHost(t)
		h.gateOn()
		h.installed("role:ops")
		// account_missing comes first in the gate, so the reason stays the
		// same while ProbeCerts requests a pair.
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n")
		h.publishDir(h.spec("role:ops", "role:new"))
		h.write()
		// Every apply runs sshd -T: a round whose runner count moved applied.
		cr := &countRunner{Runner: h.run}
		lp := start(t, h, time.Millisecond, cr)
		next(t, lp)
		for i := range 4 {
			time.Sleep(5 * time.Millisecond) // past Retry
			n := cr.n.Load()
			lp.step <- struct{}{}
			next(t, lp)
			if cr.n.Load() == n {
				t.Fatalf("round %d did not apply again", i+2)
			}
		}
		logged := strings.Count(lp.log.String(), "ERROR apply: probe_held: account_missing")
		if n := lp.held.Load(); n != 1 || logged != 1 {
			t.Fatalf("held applies printed %d times and logged %d times, want 1 and 1:\n%s", n, logged, lp.log.String())
		}
		if slices.Contains(h.principals("deploy"), "role:new") || h.heldNow() == "" {
			t.Fatalf("held %q, principals %v", h.heldNow(), h.principals("deploy"))
		}
	})
	t.Run("held_apply_that_writes_something_prints", func(t *testing.T) {
		// PR #91 review, F5: a held apply that lands a KRL (a new generation
		// and KRL version) with the same held message is printed and logged;
		// the identical retry after it is quiet.
		h := newProbeHost(t)
		h.gateOn()
		h.installed("role:ops")
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n")
		h.publishDir(h.spec("role:ops", "role:new"))
		h.write()
		cr := &countRunner{Runner: h.run}
		lp := start(t, h, time.Millisecond, cr)
		next(t, lp)
		gen := h.current()
		h.publishKRL(77)
		h.write()
		for i := range 2 {
			time.Sleep(5 * time.Millisecond) // past Retry
			n := cr.n.Load()
			lp.step <- struct{}{}
			next(t, lp)
			if cr.n.Load() == n {
				t.Fatalf("round %d did not apply again", i+2)
			}
		}
		if h.current() == gen || !h.krlRevokes(h.l.Current(), 77) {
			t.Fatalf("the held apply did not land the KRL: current %d (was %d)", h.current(), gen)
		}
		logged := strings.Count(lp.log.String(), "ERROR apply: probe_held: account_missing")
		if n := lp.held.Load(); n != 2 || logged != 2 {
			t.Fatalf("held applies printed %d times and logged %d times, want 2 and 2:\n%s", n, logged, lp.log.String())
		}
	})
	t.Run("held_retry_that_repairs_the_dropin_prints", func(t *testing.T) {
		// PR #91 review, F5 with F6: a held retry that repairs an edited
		// drop-in (and reloads sshd) wrote something, so it is printed and
		// logged even though its versions and message are unchanged.
		h := newProbeHost(t)
		h.gateOn()
		h.installed("role:ops")
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n")
		h.publishDir(h.spec("role:ops", "role:new"))
		h.write()
		cr := &countRunner{Runner: h.run}
		lp := start(t, h, time.Millisecond, cr)
		next(t, lp)
		want := readFile(t, h.l.DropIn())
		appendFile(t, h.l.DropIn(), "# edited\n")
		for i := range 2 {
			time.Sleep(5 * time.Millisecond) // past Retry
			n := cr.n.Load()
			lp.step <- struct{}{}
			next(t, lp)
			if cr.n.Load() == n {
				t.Fatalf("round %d did not apply again", i+2)
			}
		}
		if got := readFile(t, h.l.DropIn()); got != want {
			t.Fatalf("the held retry did not repair the drop-in:\n%s", got)
		}
		logged := strings.Count(lp.log.String(), "ERROR apply: probe_held: account_missing")
		if n := lp.held.Load(); n != 2 || logged != 2 {
			t.Fatalf("held applies printed %d times and logged %d times, want 2 and 2:\n%s", n, logged, lp.log.String())
		}
	})
}

// countRunner counts the commands a Runner runs.
type countRunner struct {
	Runner
	n atomic.Int32
}

func (c *countRunner) Run(ctx context.Context, cmd execsite.Cmd) (Result, error) {
	c.n.Add(1)
	return c.Runner.Run(ctx, cmd)
}

// TestRunHeldNoise (03-10b, D9, T-03-384): two identical consecutive held
// errors are logged and printed once; a different reason, another
// result in between, or 15 minutes on the clock log again.
func TestRunHeldNoise(t *testing.T) {
	held := func(reason string) error { return fmt.Errorf("%w: %s", ErrProbeHeld, reason) }
	t0 := time.Unix(1_800_000_000, 0)
	var n heldNoise
	for i, c := range []struct {
		err   error
		at    time.Duration
		quiet bool
	}{
		{held("cert_missing"), 0, false},
		{held("cert_missing"), time.Minute, true},
		{held("cert_missing"), 14 * time.Minute, true},
		{held("budget"), 14*time.Minute + 30*time.Second, false},
		{held("budget"), 15 * time.Minute, true},
		{held("budget"), 29*time.Minute + 30*time.Second, false},
		{held("budget"), 29*time.Minute + 40*time.Second, true},
		{nil, 30 * time.Minute, false},
		{held("budget"), 31 * time.Minute, false},
		{errors.New("sshd_T_failed"), 32 * time.Minute, false},
		{held("budget"), 33 * time.Minute, false},
		{held("budget"), 34 * time.Minute, true},
	} {
		if got := n.quiet(c.err, &Report{Generation: 3}, t0.Add(c.at)); got != c.quiet {
			t.Fatalf("step %d (%v at %s): quiet %t, want %t", i, c.err, c.at, got, c.quiet)
		}
	}
	// PR #91 review, F5: the same message is quiet only when the apply
	// wrote nothing new; a held retry reports generation 0.
	var w heldNoise
	for i, c := range []struct {
		r     *Report
		quiet bool
	}{
		{&Report{Generation: 4, BundleVersion: 1, DirectoryVersion: 2}, false},
		{&Report{BundleVersion: 1, DirectoryVersion: 2}, true},
		{&Report{Generation: 5, BundleVersion: 1, DirectoryVersion: 2, KRLVersion: 7}, false},
		{&Report{BundleVersion: 1, DirectoryVersion: 2, KRLVersion: 7}, true},
		{&Report{Generation: 6, BundleVersion: 1, DirectoryVersion: 2, KRLVersion: 7}, false},
		{&Report{Generation: 6, BundleVersion: 1, DirectoryVersion: 3, KRLVersion: 7}, false},
		{&Report{Generation: 6, BundleVersion: 2, DirectoryVersion: 3, KRLVersion: 7}, false},
		{&Report{BundleVersion: 2, DirectoryVersion: 3, KRLVersion: 7}, true},
		// A held retry that repaired the drop-in (F6) reloaded sshd: it
		// wrote something, so it is reported.
		{&Report{BundleVersion: 2, DirectoryVersion: 3, KRLVersion: 7, Reloaded: true}, false},
		{&Report{BundleVersion: 2, DirectoryVersion: 3, KRLVersion: 7}, true},
	} {
		if got := w.quiet(held("budget"), c.r, t0.Add(time.Duration(i)*time.Second)); got != c.quiet {
			t.Fatalf("report step %d (%+v): quiet %t, want %t", i, c.r, got, c.quiet)
		}
	}
}
