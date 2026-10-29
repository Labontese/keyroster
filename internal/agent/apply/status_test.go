//go:build linux

package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
)

// withOutbox gives h the outbox an enrolled host has (the applier writes
// status.json only there).
func withOutbox(t *testing.T, h *testHost) {
	t.Helper()
	if err := os.Mkdir(h.l.Outbox(), 0o750); err != nil { //nolint:gosec // the outbox's mode
		t.Fatal(err)
	}
}

// outboxStatus reads and checks outbox/status.json.
func outboxStatus(t *testing.T, h *testHost) *heartbeat.Status {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.l.Outbox(), heartbeat.StatusFile))
	if err != nil {
		t.Fatal(err)
	}
	s, err := heartbeat.ParseStatus(b)
	if err != nil {
		t.Fatalf("status.json does not pass the server's checks: %v\n%s", err, b)
	}
	return s
}

func writeStatus(t *testing.T, h *testHost, u StatusUpdate) *heartbeat.Status {
	t.Helper()
	s, err := WriteStatus(context.Background(), h.cfg, h.l, u)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestStatus (03-08, AGENT-07): what status.json holds, where it is
// written and how its seq grows.
func TestStatus(t *testing.T) {
	t.Run("never_applied", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		writeStatus(t, h, StatusUpdate{})
		s := outboxStatus(t, h)
		if s.Generation != 0 || s.Bundle.Version != 0 || s.Directory.Version != 0 || s.KRL.Version != 0 || len(s.Files) != 0 || s.LastApply != nil || s.Pending != nil {
			t.Fatalf("a host that never applied: %+v", s)
		}
		if s.SSHDVersion != "OpenSSH_10.5p1, OpenSSL 3.5.0 8 Apr 2025" {
			t.Fatalf("sshd_version %q", s.SSHDVersion)
		}
	})
	t.Run("after_apply", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		h.publishKRL(7)
		h.installed("role:ops")
		s := outboxStatus(t, h)
		if s.Generation != h.current() || s.Bundle.Version != 1 || s.Policy.Version != 1 || s.Directory.Version != 1 || s.KRL.Version != h.f.krlVersion ||
			s.KRL.IssuedAt != "2026-10-01T00:00:00Z" || s.LastApply == nil || s.LastApply.Result != heartbeat.ResultOK || s.DropInSHA256 == "" {
			t.Fatalf("after the first install: %+v %+v", s, s.LastApply)
		}
		var paths []string
		for _, f := range s.Files {
			paths = append(paths, f.Path)
		}
		if strings.Join(paths, " ") != "principals/deploy revoked.krl user_ca_keys" {
			t.Fatalf("files %q", paths)
		}
		if s.Effective.TrustedUserCAKeys != filepath.Join(h.l.Current(), CAFile) {
			t.Fatalf("effective trustedusercakeys %q", s.Effective.TrustedUserCAKeys)
		}
		st, err := os.Stat(filepath.Join(h.l.Outbox(), heartbeat.StatusFile))
		if err != nil || st.Mode().Perm() != 0o640 {
			t.Fatalf("status.json mode %v (%v), want 0640", st.Mode(), err)
		}
	})
	t.Run("seq_grows_and_survives_a_reset", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		a := writeStatus(t, h, StatusUpdate{})
		b := writeStatus(t, h, StatusUpdate{})
		if a.Seq != uint64(h.clock.Now().UnixMicro()) || b.Seq != a.Seq+1 {
			t.Fatalf("seq %d then %d at one clock reading, want now in microseconds then +1", a.Seq, b.Seq)
		}
		// The state directory's copy is gone (a reset): seq starts from
		// the clock, above every earlier one once time moved on.
		if err := os.Remove(h.l.State(heartbeatStateFile)); err != nil {
			t.Fatal(err)
		}
		h.clock.advance(time.Second)
		c := writeStatus(t, h, StatusUpdate{})
		if c.Seq <= b.Seq {
			t.Fatalf("seq %d after a reset, not above %d", c.Seq, b.Seq)
		}
	})
	t.Run("seq_restarts_from_the_clock_after_running_ahead", func(t *testing.T) {
		// D-R2 (PR #72 review): the server refuses a seq more than
		// heartbeat.MaxSeqAhead beyond its clock. A host whose clock ran
		// two hours ahead, then was corrected, restarts from its clock
		// instead of counting on from the far-future seq for two hours.
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		a := writeStatus(t, h, StatusUpdate{})
		h.clock.advance(-2 * time.Hour)
		b := writeStatus(t, h, StatusUpdate{})
		if want := uint64(h.clock.Now().UnixMicro()); b.Seq != want {
			t.Fatalf("seq %d after the clock went back two hours (from %d), want the clock's %d", b.Seq, a.Seq, want)
		}
		// Within the bound it still only grows.
		h.clock.advance(-30 * time.Minute)
		c := writeStatus(t, h, StatusUpdate{})
		if c.Seq != b.Seq+1 {
			t.Fatalf("seq %d after the clock went back 30 min, want %d", c.Seq, b.Seq+1)
		}
	})
	t.Run("applier_never_reads_the_outbox", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		a := writeStatus(t, h, StatusUpdate{Applied: true, Report: &Report{Errors: []string{}}})
		// Whatever is in the outbox, the next status comes from the state
		// directory's copy.
		planted := *a
		planted.Seq, planted.LastApply = a.Seq+1_000_000_000, &heartbeat.LastApply{At: "2026-10-01T00:00:00Z", Result: heartbeat.ResultError, Error: "planted"}
		pb, err := trust.CanonicalJSON(planted)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h.l.Outbox(), heartbeat.StatusFile), pb, 0o640); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		b := writeStatus(t, h, StatusUpdate{})
		if b.Seq != a.Seq+1 || b.LastApply == nil || b.LastApply.Result != heartbeat.ResultOK {
			t.Fatalf("after the outbox was ignored: seq %d (want %d), last apply %+v", b.Seq, a.Seq+1, b.LastApply)
		}
		if err := os.WriteFile(filepath.Join(h.l.Outbox(), heartbeat.StatusFile), []byte("{}"), 0o640); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		c := writeStatus(t, h, StatusUpdate{})
		if c.Seq != b.Seq+1 || c.LastApply.Result != heartbeat.ResultOK {
			t.Fatalf("a junk outbox file changed the status: %+v", c)
		}
	})
	t.Run("status_written_without_following_symlink", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(h.l.Outbox(), heartbeat.StatusFile)); err != nil {
			t.Fatal(err)
		}
		writeStatus(t, h, StatusUpdate{})
		if b, _ := os.ReadFile(target); !bytes.Equal(b, []byte("keep")) { //nolint:gosec // test fixture
			t.Fatalf("the symlink's target was written: %q", b)
		}
		if st, err := os.Lstat(filepath.Join(h.l.Outbox(), heartbeat.StatusFile)); err != nil || !st.Mode().IsRegular() {
			t.Fatalf("status.json is not a regular file after the write: %v", err)
		}
		outboxStatus(t, h)
	})
	t.Run("no_outbox_no_status", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		if s, err := WriteStatus(context.Background(), h.cfg, h.l, StatusUpdate{}); err != nil || s != nil {
			t.Fatalf("without an outbox: %v %v", s, err)
		}
		if _, err := os.Lstat(h.l.State(heartbeatStateFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a status was kept without an outbox")
		}
	})
	t.Run("pending_swap_reports_the_committed_generation", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		h.installed("role:ops")
		from := h.current()
		h.publishDir(h.spec("role:web"))
		// role:ops -> role:web adds and removes, so the apply swaps to an
		// intermediate first; it crashes before the second swap, with
		// current naming the intermediate.
		stop := &crash{point: "swap"}
		swaps := 0
		h.cfg.Fault = func(p string) error {
			if p == "swap" {
				if swaps++; swaps == 2 {
					return stop
				}
			}
			return nil
		}
		if _, err := h.apply(); !errors.Is(err, error(stop)) {
			t.Fatalf("apply: %v, want the fault at the second swap", err)
		}
		h.cfg.Fault = nil
		s := writeStatus(t, h, StatusUpdate{})
		if s.Pending == nil || s.Pending.Intermediate == 0 || h.current() != s.Pending.Intermediate {
			t.Fatalf("not mid-swap at the intermediate: pending %+v, current %d", s.Pending, h.current())
		}
		if s.Generation != from || s.Pending.From != from || s.Pending.Step != heartbeat.StepFinal || s.Directory.Version != 1 {
			t.Fatalf("mid-swap: generation %d (want the committed %d, not the intermediate %d), pending %+v, directory %d",
				s.Generation, from, s.Pending.Intermediate, s.Pending, s.Directory.Version)
		}
	})
	t.Run("stuck_is_reported_and_kept", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		r := &Report{Stuck: heartbeat.StuckPendingStateUnknown, Errors: []string{"pending_state_unknown: current names \"x\"\x1b[2J"}}
		s := writeStatus(t, h, StatusUpdate{Applied: true, Report: r, ApplyErr: ErrPendingStateUnknown})
		if s.Stuck != heartbeat.StuckPendingStateUnknown || s.LastApply.Result != heartbeat.ResultRefused || strings.ContainsRune(s.LastApply.Error, 0x1b) {
			t.Fatalf("stuck: %+v %+v", s, s.LastApply)
		}
		if s := writeStatus(t, h, StatusUpdate{Checked: true, Drift: &DriftReport{}}); s.Stuck != heartbeat.StuckPendingStateUnknown {
			t.Fatal("a check-only status dropped stuck")
		}
	})
	t.Run("apply_result", func(t *testing.T) {
		for _, c := range []struct {
			r    *Report
			err  error
			want string
		}{
			{&Report{}, nil, heartbeat.ResultOK},
			{&Report{Rollback: true}, errors.New("self-test failed"), heartbeat.ResultRolledBack},
			{&Report{}, fmt.Errorf("verify: %w", state.ErrDir), heartbeat.ResultRefused},
			{&Report{}, ErrPhase2Pending, heartbeat.ResultRefused},
			{&Report{}, ErrReload, heartbeat.ResultError},
		} {
			if got := applyResult(c.r, c.err); got != c.want {
				t.Errorf("applyResult(%+v, %v) = %s, want %s", c.r, c.err, got, c.want)
			}
		}
	})
}

// TestStale is D-10's staleness (03-08): at issued_at + 24 h - 1 s
// nothing is flagged; at 24 h krl_stale is set and an error line is
// logged, with the journald priority under the journal; the apply still
// succeeds and the generation keeps its KRL (no login is refused).
func TestStale(t *testing.T) {
	t.Run("krl_age_24h_alerts_no_refusal", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		withOutbox(t, h)
		issued := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) // the fixture's manifests
		h.clock.mu.Lock()
		h.clock.wall = issued.Add(time.Hour)
		h.clock.mu.Unlock()
		h.publishKRL(9)
		h.installed("role:ops")
		var log bytes.Buffer
		cfg := h.cfg
		cfg.Log = &log
		t.Setenv("JOURNAL_STREAM", "8:12345")
		at := func(d time.Duration) *heartbeat.Status {
			t.Helper()
			h.clock.mu.Lock()
			h.clock.wall = issued.Add(d)
			h.clock.mu.Unlock()
			log.Reset()
			s, err := WriteStatus(context.Background(), cfg, h.l, StatusUpdate{Checked: true, Drift: &DriftReport{}})
			if err != nil {
				t.Fatal(err)
			}
			LogKRLAge(cfg, s)
			return s
		}
		if s := at(KRLStaleAfter - time.Second); s.KRLStale || log.Len() != 0 {
			t.Fatalf("at 24 h - 1 s: krl_stale %v, log %q", s.KRLStale, log.String())
		}
		s := at(KRLStaleAfter)
		if !s.KRLStale || !strings.HasPrefix(log.String(), "<3>keyroster-agent run: ERROR krl_stale: the installed KRL version ") {
			t.Fatalf("at 24 h: krl_stale %v, log %q", s.KRLStale, log.String())
		}
		t.Setenv("JOURNAL_STREAM", "")
		at(KRLStaleAfter + time.Hour)
		if !strings.HasPrefix(log.String(), "keyroster-agent run: ERROR krl_stale") {
			t.Fatalf("outside the journal: %q", log.String())
		}
		// Nothing else changes: an apply goes through and the KRL stays.
		h.publishDir(h.spec("role:ops", "role:web"))
		r := h.mustApply()
		if len(r.Errors) != 0 || h.file(KRLFile) == "" {
			t.Fatalf("an apply with a stale KRL: %+v, KRL file %d bytes", r, len(h.file(KRLFile)))
		}
		if s := outboxStatus(t, h); !s.KRLStale || s.KRL.Version != h.f.krlVersion {
			t.Fatalf("after the apply: krl_stale %v, KRL %d", s.KRLStale, s.KRL.Version)
		}
	})
}
