//go:build linux

package apply

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

// phase2Layout is a hand-set Phase 2 runbook layout for a test host.
type phase2Layout struct {
	dropIn     string            // 50-keyroster.conf; "" is the runbook's two lines
	caLine     string            // keyroster_user_ca.pub; "" is the active user CA with ca-key's comment
	principals map[string][]byte // principals/<account>; nil is deploy rendered from rendered
	rendered   *directory.Directory
}

// installPhase2 writes p under the host's root and makes the fake sshd -T
// report the runbook's values while the agent's drop-in is absent (50-
// is read after 00-keyroster.conf).
func (h *testHost) installPhase2(p phase2Layout) {
	h.t.Helper()
	if p.dropIn == "" {
		p.dropIn = phase2CALine + "\n" + phase2PrincipalsLine + "\n"
	}
	if p.caLine == "" {
		p.caLine = trust.FormatKey(h.f.user.PublicKey()) + " keyroster user CA (bundle v1)\n"
	}
	if p.principals == nil {
		d := p.rendered
		if d == nil {
			d = h.directory(len(h.dirs))
		}
		b, err := directory.RenderPrincipalsFile(d, "lab", "deploy")
		if err != nil {
			h.t.Fatal(err)
		}
		p.principals = map[string][]byte{"deploy": b}
	}
	write := func(path string, b []byte) {
		if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // test fixture
			h.t.Fatal(err)
		}
	}
	write(h.l.Phase2DropIn(), []byte(p.dropIn))
	write(h.l.Phase2CAFile(), []byte(p.caLine))
	if err := os.Mkdir(h.l.Phase2PrincipalsDir(), 0o755); err != nil { //nolint:gosec // test fixture
		h.t.Fatal(err)
	}
	for a, b := range p.principals {
		write(filepath.Join(h.l.Phase2PrincipalsDir(), a), b)
	}
	if h.run.after == nil {
		h.run.after = map[string]string{}
	}
	h.run.after["trustedusercakeys"] = phase2CAValue
	h.run.after["authorizedprincipalsfile"] = phase2PrincipalsVal
}

// directory is directory version n (1-based) as published.
func (h *testHost) directory(n int) *directory.Directory {
	h.t.Helper()
	d, err := directory.Parse(h.dirs[n-1].Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return d
}

// phase2Intact reports whether the three Phase 2 paths all exist.
func (h *testHost) phase2Intact() bool {
	return h.exists(h.l.Phase2DropIn()) && h.exists(h.l.Phase2CAFile()) && h.exists(filepath.Join(h.l.Phase2PrincipalsDir(), "deploy"))
}

// nothingWritten fails unless the apply left /etc/ssh as it was: no
// current, no drop-in, the Phase 2 layout intact, no takeover plan.
func (h *testHost) nothingWritten(what string) {
	h.t.Helper()
	if h.exists(h.l.Current()) || h.exists(h.l.DropIn()) || !h.phase2Intact() || h.exists(h.l.State(adoptFile)) || h.run.reloads != 0 {
		h.t.Fatalf("%s: current %t, drop-in %t, Phase 2 intact %t, plan %t, %d reloads", what,
			h.exists(h.l.Current()), h.exists(h.l.DropIn()), h.phase2Intact(), h.exists(h.l.State(adoptFile)), h.run.reloads)
	}
}

// TestAdopt is D-08: only the Phase 2 runbook's exact layout, matching
// the signed state, is taken over, only by apply --once
// (Config.AllowAdoption), and its paths go only after the agent's
// generation passed its self-test.
func TestAdopt(t *testing.T) {
	adoptHost := func(t *testing.T) *testHost {
		h := newTestHost(t, newFixture(t))
		h.cfg.AllowAdoption = true
		h.publishDir(h.spec("role:ops"))
		return h
	}
	t.Run("exact_layout_adopted", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		h.installPhase2(phase2Layout{})
		r := h.mustApply()
		if r.SelfTest != "pass" || !r.Reloaded || h.current() == 0 || h.lastGood() != h.current() {
			t.Fatalf("adoption apply: %+v", r)
		}
		want := []string{h.l.Phase2DropIn(), h.l.Phase2CAFile(), filepath.Join(h.l.Phase2PrincipalsDir(), "deploy"), h.l.Phase2PrincipalsDir()}
		if !slices.Equal(r.Phase2Removed, want) {
			t.Fatalf("phase2_removed = %v, want %v", r.Phase2Removed, want)
		}
		for _, p := range want {
			if h.exists(p) {
				t.Fatalf("%s still exists", p)
			}
		}
		if h.exists(h.l.State(adoptFile)) || h.exists(h.l.State(adoptBak)) {
			t.Fatal("the takeover plan or its copies were left behind")
		}
		if !slices.Equal(h.principals("deploy"), []string{"role:ops"}) {
			t.Fatalf("principals = %v", h.principals("deploy"))
		}
		// sshd -T -C ran for the managed account before the reload.
		if h.run.dumps["user=deploy,host=127.0.0.1,addr=127.0.0.1,laddr=127.0.0.1,lport="+portOf(h)] == 0 {
			t.Fatalf("no sshd -T -C for deploy: %v", h.run.dumps)
		}
	})
	t.Run("ca_file_comment_differs_adopted", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		h.installPhase2(phase2Layout{caLine: trust.FormatKey(h.f.user.PublicKey()) + " a comment of the operator's own\n"})
		if r := h.mustApply(); len(r.Phase2Removed) != 4 {
			t.Fatalf("adoption with another CA comment: %+v", r)
		}
	})
	t.Run("dropin_extra_line_refused", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		h.installPhase2(phase2Layout{dropIn: phase2CALine + "\n" + phase2PrincipalsLine + "\nPasswordAuthentication no\n"})
		_, err := h.apply()
		if !errors.Is(err, ErrPhase2Differs) || !strings.Contains(err.Error(), "PasswordAuthentication no") {
			t.Fatalf("an extra line: %v, want phase2_layout_differs naming it", err)
		}
		h.nothingWritten("after the refusal")
	})
	t.Run("ca_file_other_key_refused", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		h.installPhase2(phase2Layout{caLine: trust.FormatKey(h.f.mach.PublicKey()) + " keyroster user CA (bundle v1)\n"})
		if _, err := h.apply(); !errors.Is(err, ErrPhase2Differs) || !strings.Contains(err.Error(), "not the active user CA key") {
			t.Fatalf("another CA key: %v", err)
		}
		h.nothingWritten("after the refusal")
	})
	t.Run("principals_from_older_directory_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.cfg.AllowAdoption = true
		h.publishDir(h.spec("role:old"))
		v1 := h.directory(1)
		h.publishDir(h.spec("role:ops"))
		h.installPhase2(phase2Layout{rendered: v1})
		_, err := h.apply()
		if !errors.Is(err, ErrPhase2Differs) || !strings.Contains(err.Error(), "keyroster host principals lab deploy") || !strings.Contains(err.Error(), "apply --dry-run") {
			t.Fatalf("principals from an older directory: %v, want the re-render and dry-run hints", err)
		}
		h.nothingWritten("after the refusal")
	})
	t.Run("principals_header_only_differs_reported", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.cfg.AllowAdoption = true
		h.publishDir(h.spec("role:ops"))
		v1 := h.directory(1)
		h.publishDir(h.spec("role:ops")) // the approval's new version, same principals
		h.installPhase2(phase2Layout{rendered: v1})
		_, err := h.apply()
		if !errors.Is(err, ErrPhase2Differs) || !strings.Contains(err.Error(), "only the header differs (the file names directory version 1, the agent's verified directory is version 2)") {
			t.Fatalf("a header-only difference: %v", err)
		}
		h.nothingWritten("after the refusal")
		// Re-rendered from version 2, it is adopted.
		b, err := directory.RenderPrincipalsFile(h.directory(2), "lab", "deploy")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h.l.Phase2PrincipalsDir(), "deploy"), b, 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if r := h.mustApply(); len(r.Phase2Removed) != 4 {
			t.Fatalf("after re-rendering: %+v", r)
		}
	})
	t.Run("settings_in_sshd_config_refused", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		h.installPhase2(phase2Layout{})
		f, err := os.OpenFile(h.cfg.SSHDConfig, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("AuthorizedPrincipalsFile /etc/ssh/principals/%u\n")
		_ = f.Close()
		_, err = h.apply()
		if !errors.Is(err, ErrPhase2Differs) || !strings.Contains(err.Error(), h.cfg.SSHDConfig+":2 sets \"AuthorizedPrincipalsFile /etc/ssh/principals/%u\"; remove that line") {
			t.Fatalf("the setting in sshd_config: %v", err)
		}
		h.nothingWritten("after the refusal")
	})
	t.Run("failed_selftest_restores_old_files", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		h.installPhase2(phase2Layout{})
		before := readFile(t, h.l.Phase2CAFile())
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.stop()
		_, err := h.apply()
		if !errors.Is(err, ErrFirstInstallFailed) || !errors.Is(err, ErrSelfTest) {
			t.Fatalf("a failing self-test: %v", err)
		}
		if !h.phase2Intact() || readFile(t, h.l.Phase2CAFile()) != before || h.exists(h.l.Current()) || h.exists(h.l.DropIn()) || h.exists(h.l.State(adoptFile)) {
			t.Fatalf("after the failed takeover: Phase 2 intact %t, current %t, drop-in %t, plan %t", h.phase2Intact(), h.exists(h.l.Current()), h.exists(h.l.DropIn()), h.exists(h.l.State(adoptFile)))
		}
	})
	t.Run("adoption_not_allowed_reports_pending", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		h.cfg.AllowAdoption = false
		h.installPhase2(phase2Layout{})
		_, err := h.apply()
		if !errors.Is(err, ErrPhase2Pending) || !strings.Contains(err.Error(), "sudo keyroster-agent apply --once") {
			t.Fatalf("without AllowAdoption: %v, want phase2_adoption_pending with the command", err)
		}
		h.nothingWritten("phase2_adoption_pending")
	})
	t.Run("crash_during_removal_resumes", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		h.installPhase2(phase2Layout{})
		n := 0
		h.cfg.Fault = func(p string) error {
			if p == "phase2-remove" {
				if n++; n == 3 {
					return &crash{point: p}
				}
			}
			return nil
		}
		if _, err := h.apply(); !isCrash(err) || h.lastGood() == 0 || !h.exists(h.l.State(adoptFile)) {
			t.Fatalf("crash in the removal: %v, last-good %d", err, h.lastGood())
		}
		if h.exists(h.l.Phase2DropIn()) || !h.exists(filepath.Join(h.l.Phase2PrincipalsDir(), "deploy")) {
			t.Fatal("the removal did not stop where it crashed")
		}
		h.cfg.Fault = nil
		r := h.mustApply()
		if h.exists(h.l.Phase2PrincipalsDir()) || h.exists(h.l.State(adoptFile)) || h.exists(h.l.State(adoptBak)) || len(r.Phase2Removed) != 4 {
			t.Fatalf("the next run did not finish the removal: %+v", r)
		}
	})
	t.Run("crash_after_final_removal_resumes", func(t *testing.T) {
		t.Parallel()
		// PR #68 review, F14: a crash after the principals directory went,
		// before the plan did; the resume finds every path and the
		// principals files' directory gone.
		h := adoptHost(t)
		h.installPhase2(phase2Layout{})
		h.cfg.Fault = func(p string) error {
			if p == "phase2-removed" {
				return &crash{point: p}
			}
			return nil
		}
		if _, err := h.apply(); !isCrash(err) || h.lastGood() == 0 || !h.exists(h.l.State(adoptFile)) || h.exists(h.l.Phase2PrincipalsDir()) {
			t.Fatalf("crash after the removal: %v, last-good %d, plan %t, principals dir %t", err, h.lastGood(), h.exists(h.l.State(adoptFile)), h.exists(h.l.Phase2PrincipalsDir()))
		}
		h.cfg.Fault = nil
		r, err := h.apply()
		if err != nil || h.exists(h.l.State(adoptFile)) || h.exists(h.l.State(adoptBak)) || len(r.Phase2Removed) != 4 {
			t.Fatalf("the resume after the final removal: %v, %+v, plan %t", err, r, h.exists(h.l.State(adoptFile)))
		}
	})
	// PR #68 review fix round 2, P2 (D-R2): a takeover cut short during its
	// removal, then the agent's drop-in edited (a trust line) or removed,
	// and a new KRL published. The resume repairs the drop-in before it
	// removes anything, and the KRL installs in the same run.
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, h *testHost)
	}{
		{"resume_repairs_edited_dropin", func(t *testing.T, h *testHost) {
			edited := strings.Replace(string(DropIn(h.l)), filepath.Join(h.l.Current(), CAFile), "/etc/ssh/other_ca.pub", 1)
			if err := os.WriteFile(h.l.DropIn(), []byte(edited), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}},
		{"resume_repairs_missing_dropin", func(t *testing.T, h *testHost) {
			if err := os.Remove(h.l.DropIn()); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := adoptHost(t)
			h.installPhase2(phase2Layout{})
			h.cfg.Fault = func(p string) error {
				if p == "phase2-remove" {
					return &crash{point: p}
				}
				return nil
			}
			if _, err := h.apply(); !isCrash(err) || h.lastGood() == 0 || !h.exists(h.l.State(adoptFile)) {
				t.Fatalf("crash during the removal: %v, last-good %d", err, h.lastGood())
			}
			tc.edit(t, h)
			h.publishKRL(9)
			// PR #68 carry-over (mutant M8): the repair runs before any Phase
			// 2 path goes, so at every removal the drop-in on disk is already
			// the agent's.
			removals := 0
			h.cfg.Fault = func(p string) error {
				if p == "phase2-remove" {
					removals++
					if got := readFile(t, h.l.DropIn()); got != string(DropIn(h.l)) {
						t.Errorf("removal %d of the Phase 2 layout ran before the drop-in was repaired: it holds %q", removals, got)
					}
				}
				return nil
			}
			r, err := h.apply()
			h.cfg.Fault = nil
			if removals == 0 {
				t.Fatal("the resume removed no Phase 2 path; the order check did not run")
			}
			if err != nil || !h.krlRevokes(h.l.Current(), 9) || h.exists(h.l.State(adoptFile)) || len(r.Phase2Removed) != 4 || !r.Reloaded {
				t.Fatalf("the resume: %v, %+v, plan %t", err, r, h.exists(h.l.State(adoptFile)))
			}
			if readFile(t, h.l.DropIn()) != string(DropIn(h.l)) || h.exists(h.l.State(dropinPrevFile)) {
				t.Fatalf("the drop-in was not repaired: %q", readFile(t, h.l.DropIn()))
			}
		})
	}
	// PR #71 review F15: a takeover cut short during its removal, then the
	// drop-in edited into a line sshd itself refuses, so the start-of-run
	// sshd -T fails and the pre-repair writes the agent's drop-in back. That
	// repair is reloaded and self-tested before any Phase 2 path goes: with
	// sshd stopped the self-test fails and the Phase 2 layout, its copies in
	// phase2/ and the plan are all still there; with sshd up the first
	// removal comes after the repair's reload.
	for _, tc := range []struct {
		name    string
		stopped bool
	}{{"resume_after_refused_edit_sshd_stopped_keeps_phase2", true}, {"resume_after_refused_edit_reloads_before_removal", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := adoptHost(t)
			h.installPhase2(phase2Layout{})
			h.cfg.Fault = func(p string) error {
				if p == "phase2-remove" {
					return &crash{point: p}
				}
				return nil
			}
			if _, err := h.apply(); !isCrash(err) || h.lastGood() == 0 || !h.exists(h.l.State(adoptFile)) {
				t.Fatalf("crash during the removal: %v, last-good %d", err, h.lastGood())
			}
			appendFile(t, h.l.DropIn(), "Banner \"/etc/issue\n")
			h.run.rejectDropIn = func(b []byte) bool { return strings.Contains(string(b), "Banner \"") }
			h.publishKRL(9)
			reloads := h.run.reloads
			removals, reloadedFirst := 0, false
			h.cfg.Fault = func(p string) error {
				if p == "phase2-remove" {
					if removals == 0 {
						reloadedFirst = h.run.reloads > reloads
					}
					removals++
				}
				return nil
			}
			if tc.stopped {
				h.cfg.SelfTestTimeout = 300 * time.Millisecond
				h.sshd.stop()
			}
			r, err := h.apply()
			h.cfg.Fault = nil
			if tc.stopped {
				if !errors.Is(err, ErrSelfTest) || removals != 0 || len(r.Phase2Removed) != 0 {
					t.Fatalf("the resume with sshd stopped: %v, %d removals, %+v", err, removals, r)
				}
				if !h.phase2Intact() || !h.exists(h.l.State(adoptFile)) || !h.exists(h.l.State(adoptBak)) {
					t.Fatalf("a failed self-test of the repair lost the Phase 2 fallback: Phase 2 intact %t, plan %t, phase2/ %t",
						h.phase2Intact(), h.exists(h.l.State(adoptFile)), h.exists(h.l.State(adoptBak)))
				}
				return
			}
			if err != nil || removals == 0 || !reloadedFirst || len(r.Phase2Removed) != 4 || h.exists(h.l.State(adoptFile)) {
				t.Fatalf("the resume: %v, %d removals, reloaded before the first %t, %+v", err, removals, reloadedFirst, r)
			}
		})
	}
	t.Run("marker_write_failure_leaves_no_plan", func(t *testing.T) {
		t.Parallel()
		// PR #68 review, F2: the marker write fails (ENOSPC, EIO) at the
		// start of the takeover's first install; no plan may outlive it.
		h := adoptHost(t)
		h.installPhase2(phase2Layout{})
		h.cfg.Fault = func(p string) error {
			if p == "marker" {
				return errors.New("no space left on device")
			}
			return nil
		}
		if _, err := h.apply(); err == nil {
			t.Fatal("the apply passed with a failing marker write")
		}
		h.nothingWritten("after the failed marker write")
		h.cfg.Fault = nil
		if r := h.mustApply(); len(r.Phase2Removed) != 4 {
			t.Fatalf("the takeover after the failure: %+v", r)
		}
	})
	t.Run("plan_write_failure_or_crash_undone", func(t *testing.T) {
		t.Parallel()
		for _, inject := range []error{errors.New("no space left on device"), &crash{point: "adopt-plan"}} {
			h := adoptHost(t)
			h.installPhase2(phase2Layout{})
			h.cfg.Fault = func(p string) error {
				if p == "adopt-plan" {
					return inject
				}
				return nil
			}
			if _, err := h.apply(); err == nil {
				t.Fatalf("%v: the apply passed", inject)
			}
			if h.exists(h.l.State(adoptFile)) || h.exists(h.l.Current()) || h.exists(h.l.DropIn()) || !h.phase2Intact() {
				t.Fatalf("%v: plan %t, current %t, drop-in %t, Phase 2 intact %t", inject, h.exists(h.l.State(adoptFile)), h.exists(h.l.Current()), h.exists(h.l.DropIn()), h.phase2Intact())
			}
			h.cfg.Fault = nil
			if r := h.mustApply(); len(r.Phase2Removed) != 4 || h.exists(h.l.State(pendingFile)) {
				t.Fatalf("%v: the takeover afterwards: %+v", inject, r)
			}
		}
	})
	t.Run("stale_plan_never_executed", func(t *testing.T) {
		t.Parallel()
		// PR #68 review, F2: a plan left with no marker and no generation
		// (the state a failure or crash between the plan and the marker
		// writes left before this fix). The operator removed the Phase 2
		// drop-in by hand and kept the other files with new content; the
		// first install adopts nothing and must not remove them.
		h := newTestHost(t, newFixture(t))
		h.publishDir(h.spec("role:ops"))
		writeRootFile(t, h, "etc/ssh/keyroster_user_ca.pub", "ssh-ed25519 AAAA kept by the operator\n")
		kept := writeRootFile(t, h, "etc/ssh/principals/deploy", "role:other\n")
		e := h.engine()
		if err := e.writeAdopt(&AdoptPlan{Remove: []string{h.l.Phase2DropIn(), h.l.Phase2CAFile(), kept, h.l.Phase2PrincipalsDir()}}); err != nil {
			t.Fatal(err)
		}
		r := h.mustApply()
		if len(r.Phase2Removed) != 0 || !h.exists(h.l.Phase2CAFile()) || readFile(t, kept) != "role:other\n" || h.exists(h.l.State(adoptFile)) || h.exists(h.l.State(adoptBak)) {
			t.Fatalf("a stale plan: removed %v, CA file %t, plan %t", r.Phase2Removed, h.exists(h.l.Phase2CAFile()), h.exists(h.l.State(adoptFile)))
		}
		if h.lastGood() == 0 {
			t.Fatal("the first install did not commit")
		}
	})
	t.Run("removal_only_through_allowed_removal", func(t *testing.T) {
		t.Parallel()
		h := adoptHost(t)
		e := h.engine()
		if err := e.removePhase2(filepath.Join(h.l.Root, "etc", "ssh", "sshd_config")); err == nil {
			t.Fatal("removePhase2 removed sshd_config")
		}
		if err := e.writeFile(h.l.Phase2PrincipalsDir(), "deploy", []byte("x\n"), 0o644); err == nil {
			t.Fatal("the agent wrote into the Phase 2 principals directory")
		}
	})
}

// portOf is the fake sshd's port, as the -C specifications name it.
func portOf(h *testHost) string { return strconv.Itoa(h.sshd.port) }
