//go:build linux

package apply

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/trust"
)

// lockedEngine is h's bare engine past the apply lock, as the gate's
// writer needs it.
func lockedEngine(h *testHost) *engine {
	e := h.engine()
	e.locked = true
	return e
}

// isReset reports whether st is the exhausted hour a refused
// probe-state.json reads as (T-03-376).
func isReset(st *probeState, now uint64) bool {
	if !st.reset || st.ResetAt != now || len(st.Negatives) != ProbeNegativesPerHour {
		return false
	}
	for _, n := range st.Negatives {
		if n != now {
			return false
		}
	}
	return true
}

// TestProbeStateIO (03-10b, T-03-376): the reader of probe-state.json
// fails closed, and the writer needs the lock.
func TestProbeStateIO(t *testing.T) {
	full := func(now uint64) *probeState {
		return &probeState{Version: 1, Negatives: []uint64{now - 100, now - 10}, LastPair: now - 10, LastOpportunistic: now - 700,
			Failure: &probeFailure{Code: "probe_inconclusive", Key: strings.Repeat("cd", 32), At: now - 10, Count: 2},
			Alarm:   "probe_positive_refused", Held: &probeHeld{Reason: "failure_backoff", Bundle: 1, Directory: 4, KRL: 9, At: now - 10}}
	}
	setup := func(t *testing.T) (*testHost, *engine, uint64) {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		return h, lockedEngine(h), uint64(h.clock.Now().Unix()) //nolint:gosec // G115: test clock
	}
	good := func(t *testing.T, now uint64) []byte {
		t.Helper()
		b, err := full(now).encode()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("missing_is_empty", func(t *testing.T) {
		_, e, _ := setup(t)
		st := e.readProbeState()
		if st.reset || st.Version != 1 || len(st.Negatives) != 0 || st.Held != nil || st.Failure != nil || st.Alarm != "" || st.ResetAt != 0 {
			t.Fatalf("a missing file: %+v", st)
		}
	})
	t.Run("roundtrip_canonical_0600", func(t *testing.T) {
		h, e, now := setup(t)
		if err := e.writeProbeState(full(now)); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(h.l.State(probeStateFile))
		if err != nil {
			t.Fatal(err)
		}
		c, err := trust.CanonicalJSON(full(now))
		if err != nil || !bytes.Equal(b, c) {
			t.Fatalf("not canonical (%v):\n%s\n%s", err, b, c)
		}
		if fi, err := os.Stat(h.l.State(probeStateFile)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v (%v)", fi.Mode(), err)
		}
		st := e.readProbeState()
		if st.reset || st.Held == nil || *st.Held != *full(now).Held || *st.Failure != *full(now).Failure || len(st.Negatives) != 2 || st.Alarm != "probe_positive_refused" {
			t.Fatalf("read back %+v", st)
		}
		// The empty state encodes negatives as a list, never null.
		if err := e.writeProbeState(&probeState{Version: 1}); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(h.l.State(probeStateFile)); !strings.Contains(string(b), `"negatives":[]`) {
			t.Fatalf("the empty state: %s", b)
		}
	})
	resets := func(t *testing.T, write func(h *testHost, now uint64)) {
		t.Helper()
		h, e, now := setup(t)
		write(h, now)
		if st := e.readProbeState(); !isReset(st, now) {
			t.Fatalf("read %+v, want the exhausted hour", st)
		}
	}
	t.Run("unknown_field_resets", func(t *testing.T) {
		resets(t, func(h *testHost, now uint64) {
			b := strings.Replace(string(good(t, now)), `"version":1`, `"version":1,"extra":1`, 1)
			if err := os.WriteFile(h.l.State(probeStateFile), []byte(b), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("symlink_resets", func(t *testing.T) {
		resets(t, func(h *testHost, now uint64) {
			other := filepath.Join(t.TempDir(), "probe-state.json")
			if err := os.WriteFile(other, good(t, now), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(other, h.l.State(probeStateFile)); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("mode_0644_resets", func(t *testing.T) {
		resets(t, func(h *testHost, now uint64) {
			if err := os.WriteFile(h.l.State(probeStateFile), good(t, now), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(h.l.State(probeStateFile), 0o644); err != nil { //nolint:gosec // the mode under test
				t.Fatal(err)
			}
		})
	})
	t.Run("foreign_owner_resets", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("chown needs root; the owner is compared like the mode")
		}
		resets(t, func(h *testHost, now uint64) {
			if err := os.WriteFile(h.l.State(probeStateFile), good(t, now), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(h.l.State(probeStateFile), 65534, 65534); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("oversize_resets", func(t *testing.T) {
		resets(t, func(h *testHost, _ uint64) {
			if err := os.WriteFile(h.l.State(probeStateFile), bytes.Repeat([]byte(" "), maxProbeState+1), 0o600); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("truncated_resets", func(t *testing.T) {
		resets(t, func(h *testHost, now uint64) {
			b := good(t, now)
			if err := os.WriteFile(h.l.State(probeStateFile), b[:len(b)/2], 0o600); err != nil {
				t.Fatal(err)
			}
		})
	})
	t.Run("reset_counts_an_exhausted_hour", func(t *testing.T) {
		h, e, now := setup(t)
		h.cfg.probeOff = false
		e.cfg.probeOff = false
		if err := os.WriteFile(h.l.State(probeStateFile), []byte(`{"version":2}`), 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := e.loadProbeState()
		if st.reset = true; err != nil || !isReset(st, now) {
			t.Fatalf("load %+v (%v), want the exhausted hour", st, err)
		}
		// Rewritten once: the file now reads as six negatives at now with
		// reset_at now, which reports probe_state_reset for an hour.
		again := e.readProbeState()
		if again.reset || again.ResetAt != now || len(again.Negatives) != ProbeNegativesPerHour {
			t.Fatalf("after the rewrite %+v", again)
		}
		var s heartbeat.Status
		e.probeStatus(&s)
		if s.ProbeDetail != DetailProbeStateReset {
			t.Fatalf("probe_detail %q", s.ProbeDetail)
		}
	})
	t.Run("future_entries_clamped_to_now", func(t *testing.T) {
		h, e, now := setup(t)
		st := full(now)
		st.Negatives = []uint64{now + 5000, now - 5}
		st.LastPair, st.LastOpportunistic, st.ResetAt = now+50, now+60, now+70
		st.Failure.At, st.Held.At = now+80, now+90
		b, err := st.encode()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.l.State(probeStateFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		got := e.readProbeState()
		if got.reset || got.Negatives[0] != now || got.Negatives[1] != now-5 || got.LastPair != now || got.LastOpportunistic != now ||
			got.ResetAt != now || got.Failure.At != now || got.Held.At != now {
			t.Fatalf("read %+v %+v %+v", got, got.Failure, got.Held)
		}
	})
	t.Run("never_written_outside_lock", func(t *testing.T) {
		h, e, now := setup(t)
		e.locked = false
		if err := e.writeProbeState(full(now)); err == nil {
			t.Fatal("written without the lock")
		}
		if _, err := os.Lstat(h.l.State(probeStateFile)); !os.IsNotExist(err) {
			t.Fatalf("the file exists: %v", err)
		}
	})
}

// FuzzParseState (03-10b): the strict decode of probe-state.json never
// panics, whatever it accepts re-encodes to the same bytes, and any input
// reads either as that state with nothing after now or as the exhausted
// hour.
func FuzzParseState(f *testing.F) {
	const now = 1_800_000_000
	st := &probeState{Version: 1, Negatives: []uint64{now - 1}, LastPair: now - 1,
		Failure: &probeFailure{Code: "probe_inconclusive", Key: strings.Repeat("ab", 32), At: now, Count: 1},
		Held:    &probeHeld{Reason: "budget", Bundle: 1, Directory: 1, KRL: 1, At: now}, Alarm: "probe_krl_not_enforced"}
	for _, s := range []*probeState{st, {Version: 1}} {
		b, err := s.encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add([]byte(`{"version":1,"negatives":null}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got := decodeProbeState(data, now)
		if got.reset {
			if !isReset(got, now) {
				t.Fatalf("a refused input reads as %+v", got)
			}
			return
		}
		parsed, err := parseProbeState(data)
		if err != nil {
			t.Fatalf("accepted by decodeProbeState, refused by parseProbeState: %v", err)
		}
		b, err := parsed.encode()
		if err != nil || !bytes.Equal(b, data) {
			t.Fatalf("an accepted state re-encodes differently (%v):\n%s\n%s", err, data, b)
		}
		late := got.LastPair > now || got.LastOpportunistic > now || got.ResetAt > now ||
			got.Failure != nil && got.Failure.At > now || got.Held != nil && got.Held.At > now
		for _, n := range got.Negatives {
			late = late || n > now
		}
		if late {
			t.Fatalf("an entry after now survived the read: %+v", got)
		}
	})
}
