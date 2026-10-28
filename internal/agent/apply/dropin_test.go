//go:build linux

package apply

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// appendFile appends text to the file at p.
func appendFile(t *testing.T, p, text string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestDropInRepair is owner decision D-R2 (PR #68 review, F15: "Repair +
// report") and F1: once a generation of the agent's is installed,
// 00-keyroster.conf is the agent's own file. A drop-in that differs from
// DropIn is drift the apply repairs and check reports, never a refusal
// that would hold back a KRL; a foreign file there is refused only at the
// first install; a preflight's trial left on an installed host is
// replaced, and sshd reloaded, even by a no-op apply.
func TestDropInRepair(t *testing.T) {
	t.Run("edited_dropin_repaired_and_krl_installed", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		first := h.current()
		appendFile(t, h.l.DropIn(), "# managed by ansible\n")
		d, err := h.check()
		if err != nil || !slices.ContainsFunc(d.Files, func(f FileDrift) bool { return f.File == h.l.DropIn() }) || !d.Drift() {
			t.Fatalf("check with an edited drop-in: %+v, %v", d, err)
		}
		h.publishKRL(7)
		r := h.mustApply()
		if h.current() == first || r.SelfTest != "pass" || !r.Reloaded || !h.krlRevokes(h.l.Current(), 7) {
			t.Fatalf("the KRL apply over an edited drop-in: current %d (first %d), %+v", h.current(), first, r)
		}
		if readFile(t, h.l.DropIn()) != string(DropIn(h.l)) || h.exists(h.l.State(dropinPrevFile)) {
			t.Fatalf("the drop-in was not repaired: %q", readFile(t, h.l.DropIn()))
		}
		if d, err := h.check(); err != nil || d.Drift() {
			t.Fatalf("check after the repair: %+v, %v", d, err)
		}
	})
	t.Run("edited_trust_line_repaired", func(t *testing.T) {
		t.Parallel()
		// The edit changes a value sshd -T reports; it is the agent's own
		// file, so the apply's preflight does not take it for a setting
		// made elsewhere, and activateDropIn checks the repaired value.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		edited := strings.Replace(string(DropIn(h.l)), filepath.Join(h.l.Current(), CAFile), "/etc/ssh/other_ca.pub", 1)
		if err := os.WriteFile(h.l.DropIn(), []byte(edited), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		h.publishKRL(8)
		if r := h.mustApply(); r.SelfTest != "pass" || readFile(t, h.l.DropIn()) != string(DropIn(h.l)) || !h.krlRevokes(h.l.Current(), 8) {
			t.Fatalf("an edited TrustedUserCAKeys line: %+v, drop-in %q", r, readFile(t, h.l.DropIn()))
		}
	})
	// PR #68 review fix round 2, P1: the config-graph checks evaluate the
	// drop-in the apply writes, so an edit they would refuse elsewhere (a
	// group-writable mode, a line the tokeniser cannot read, an Include
	// of an open directory) is repaired, never a refusal that holds back
	// a KRL.
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, h *testHost)
	}{
		{"edited_group_writable_dropin_repaired", func(t *testing.T, h *testHost) {
			appendFile(t, h.l.DropIn(), "# managed by ansible\n")
			chmod(t, h.l.DropIn(), 0o664)
		}},
		{"edited_dropin_with_unbalanced_include_repaired", func(t *testing.T, h *testHost) {
			appendFile(t, h.l.DropIn(), "Include \"/etc/ssh/local.d/*.conf\n")
		}},
		{"edited_dropin_including_open_dir_repaired", func(t *testing.T, h *testHost) {
			open := filepath.Join(h.l.Root, "srv/open")
			if err := os.MkdirAll(open, 0o755); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			chmod(t, open, 0o777) //nolint:gosec // the directory under test is world-writable
			appendFile(t, h.l.DropIn(), "Include "+open+"/*.conf\n")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHost(t, newFixture(t))
			h.installed("role:ops")
			first := h.current()
			tc.edit(t, h)
			if r, err := h.preflight(); err != nil || finding(r, CodeConfigUnsafe) != nil || finding(r, CodeDropInDrift) == nil {
				t.Fatalf("preflight with the edited drop-in: %+v, %v", r, err)
			}
			h.publishKRL(7)
			r := h.mustApply()
			if h.current() == first || r.SelfTest != "pass" || !h.krlRevokes(h.l.Current(), 7) {
				t.Fatalf("the KRL apply over the edited drop-in: current %d (first %d), %+v", h.current(), first, r)
			}
			st, err := os.Stat(h.l.DropIn())
			if err != nil || readFile(t, h.l.DropIn()) != string(DropIn(h.l)) || st.Mode().Perm() != 0o644 {
				t.Fatalf("the drop-in was not repaired: %q, %v, %v", readFile(t, h.l.DropIn()), st.Mode(), err)
			}
		})
	}
	// PR #68 carry-over: an edit sshd itself refuses (an unbalanced quote)
	// makes the start-of-run sshd -T fail. On an installed host the agent
	// writes its own drop-in back first, reads sshd -T again, reloads and
	// self-tests, so the KRL still lands; with no new state the run is a
	// repair, not a no-op.
	for _, tc := range []struct {
		name string
		krl  bool
	}{{"dropin_sshd_refuses_repaired_before_dump", true}, {"dropin_sshd_refuses_repaired_by_noop_run", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newTestHost(t, newFixture(t))
			h.installed("role:ops")
			gen, reloads := h.current(), h.run.reloads
			appendFile(t, h.l.DropIn(), "Banner \"/etc/issue\n")
			h.run.rejectDropIn = func(b []byte) bool { return strings.Contains(string(b), "Banner \"") }
			if tc.krl {
				h.publishKRL(7)
			}
			r, err := h.apply()
			if err != nil || r.NoOp || r.SelfTest != "pass" || h.run.reloads != reloads+1 {
				t.Fatalf("an apply over a drop-in sshd refuses: %v, %+v, %d reloads (before %d)", err, r, h.run.reloads, reloads)
			}
			if readFile(t, h.l.DropIn()) != string(DropIn(h.l)) || h.exists(h.l.State(dropinPrevFile)) {
				t.Fatalf("the drop-in was not repaired: %q", readFile(t, h.l.DropIn()))
			}
			if tc.krl != (h.current() != gen) || (tc.krl && !h.krlRevokes(h.l.Current(), 7)) {
				t.Fatalf("current %d (before %d), KRL applied: %t", h.current(), gen, tc.krl)
			}
		})
	}
	t.Run("sshd_dump_failure_with_own_dropin_not_repaired", func(t *testing.T) {
		t.Parallel()
		// sshd -T fails for another reason: nothing is written.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.run.rejectDropIn = func([]byte) bool { return true }
		if _, err := h.apply(); !errors.Is(err, ErrSSHDDump) || readFile(t, h.l.DropIn()) != string(DropIn(h.l)) {
			t.Fatalf("sshd -T failing with the agent's own drop-in: %v", err)
		}
	})
	t.Run("rollback_restores_agents_dropin_not_the_edit", func(t *testing.T) {
		t.Parallel()
		// PR #68 carry-over: an edited drop-in is repaired by an apply
		// whose self-test then fails (sshd stopped). The rollback puts the
		// agent's own drop-in back, never the edit dropin.prev held.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		appendFile(t, h.l.DropIn(), "# managed by ansible\n")
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.stop()
		h.publishKRL(7)
		r, err := h.apply()
		if !errors.Is(err, ErrSelfTest) || !r.Rollback {
			t.Fatalf("self-test failure after the repair: %+v, %v", r, err)
		}
		if got := readFile(t, h.l.DropIn()); got != string(DropIn(h.l)) {
			t.Fatalf("the rollback restored %q, want the agent's drop-in", got)
		}
		if h.exists(h.l.State(dropinPrevFile)) {
			t.Fatal("dropin.prev left after the rollback")
		}
	})
	t.Run("foreign_file_refused_at_first_install", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.publishDir(h.spec("role:ops"))
		if err := os.WriteFile(h.l.DropIn(), []byte("PasswordAuthentication yes\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if _, err := h.apply(); !errors.Is(err, ErrForeignTrust) || h.exists(h.l.Current()) || readFile(t, h.l.DropIn()) != "PasswordAuthentication yes\n" {
			t.Fatalf("a foreign 00-keyroster.conf at the first install: %v, current %t", err, h.exists(h.l.Current()))
		}
	})
	t.Run("noop_apply_replaces_trial_on_installed_host", func(t *testing.T) {
		t.Parallel()
		// F1: a trial (current's CA keys, no KRL) in place of the agent's
		// drop-in on an installed host; nothing new in the spool.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		gen, reloads := h.current(), h.run.reloads
		if err := os.WriteFile(h.l.DropIn(), trialDropIn(h.l), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		r := h.mustApply()
		if r.NoOp || !r.Reloaded || r.SelfTest != "pass" || h.run.reloads != reloads+1 || h.current() != gen {
			t.Fatalf("a no-op apply over a trial: %+v, %d reloads (before %d)", r, h.run.reloads, reloads)
		}
		if readFile(t, h.l.DropIn()) != string(DropIn(h.l)) || h.exists(h.l.State(dropinPrevFile)) {
			t.Fatalf("the trial was not replaced: %q", readFile(t, h.l.DropIn()))
		}
	})
}
