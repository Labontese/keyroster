//go:build linux

package apply

import (
	"errors"
	"slices"
	"testing"
	"time"
)

// TestSocketActivatedReload is owner decision D-R1 (PR #68 review, F3,
// F4, F13: "try-reload-or-restart"): on a socket-activated sshd every
// reload, the activation's and every rollback's, runs systemctl
// try-reload-or-restart, so a daemon that a connection started with the
// old configuration, or with the agent's drop-in, never keeps it.
func TestSocketActivatedReload(t *testing.T) {
	const try = "systemctl try-reload-or-restart ssh.service"
	socketHost := func(t *testing.T) *testHost {
		h := newTestHost(t, newFixture(t))
		h.cfg.Reload = ReloadSocket + "ssh.service"
		writeRootFile(t, h, "usr/bin/systemctl", "#!/bin/false\n")
		return h
	}
	t.Run("first_install_runs_try_reload_or_restart", func(t *testing.T) {
		t.Parallel()
		h := socketHost(t)
		r := h.installed("role:ops")
		if !r.Reloaded || !slices.Equal(r.ReloadActions, []string{"/usr/bin/systemctl try-reload-or-restart ssh.service"}) || !slices.Contains(h.run.calls, try) {
			t.Fatalf("first install on a socket-activated host: %+v, calls %v", r, h.run.calls)
		}
	})
	t.Run("rollback_reloads_before_current_is_removed", func(t *testing.T) {
		t.Parallel()
		// The self-test's connection is accepted (systemd would start sshd
		// with the agent's drop-in), then the self-test fails; the rollback
		// must make that daemon re-read the restored configuration before
		// current, which its RevokedKeys names, goes.
		h := socketHost(t)
		h.publishDir(h.spec("role:ops"))
		type seen struct{ dropIn, current bool }
		var at []seen
		h.run.onReload = func(string) { at = append(at, seen{h.exists(h.l.DropIn()), h.exists(h.l.Current())}) }
		h.sshd.setStall(true)
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		r, err := h.apply()
		if !errors.Is(err, ErrFirstInstallFailed) || !errors.Is(err, ErrSelfTest) {
			t.Fatalf("a self-test that fails after the connection was accepted: %v", err)
		}
		h.sshd.mu.Lock()
		accepted := h.sshd.accepted
		h.sshd.mu.Unlock()
		if accepted == 0 {
			t.Fatal("the fake sshd accepted no connection")
		}
		// The activation's reload with the drop-in on disk, then the
		// rollback's with it removed and current still there.
		if want := []seen{{dropIn: true, current: true}, {dropIn: false, current: true}}; !slices.Equal(at, want) {
			t.Fatalf("reloads saw %+v, want %+v", at, want)
		}
		if h.exists(h.l.Current()) || h.exists(h.l.DropIn()) || len(r.ReloadActions) != 2 || !r.Rollback {
			t.Fatalf("after the rollback: current %t, drop-in %t, %+v", h.exists(h.l.Current()), h.exists(h.l.DropIn()), r)
		}
	})
	t.Run("adoption_reloads_before_phase2_removal", func(t *testing.T) {
		t.Parallel()
		// F3: the Phase 2 paths go only after try-reload-or-restart made a
		// running sshd read the agent's drop-in and the self-test passed.
		h := socketHost(t)
		h.cfg.AllowAdoption = true
		h.publishDir(h.spec("role:ops"))
		h.installPhase2(phase2Layout{})
		var before []string
		h.cfg.Fault = func(p string) error {
			if p == "phase2-remove" && before == nil {
				h.run.mu.Lock()
				before = slices.Clone(h.run.calls)
				h.run.mu.Unlock()
			}
			return nil
		}
		r := h.mustApply()
		if !slices.Contains(before, try) || r.SelfTest != "pass" || len(r.Phase2Removed) != 4 {
			t.Fatalf("adoption on a socket-activated host: calls before the removal %v, %+v", before, r)
		}
	})
	t.Run("none_is_no_strategy", func(t *testing.T) {
		t.Parallel()
		if err := CheckReload("none"); !errors.Is(err, ErrReload) {
			t.Fatalf("CheckReload(none) = %v", err)
		}
		if err := CheckReload(ReloadSocket + "ssh.service"); err != nil {
			t.Fatal(err)
		}
	})
}
