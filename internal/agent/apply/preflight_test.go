//go:build linux

package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/trust"
)

// fixtureWithoutPoP is newFixture with a genesis policy that does not set
// pop.hosts.
func fixtureWithoutPoP(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	f.policy.PoP = nil
	f.policyDoc = mustCanonical(t, f.policy)
	f.policySigs = f.rootSign(trust.NamespacePolicy, f.policyDoc)
	f.bundle.PolicySHA256 = trust.SHA256Hex(f.policyDoc)
	f.bundleDoc = mustCanonical(t, f.bundle)
	f.bundleSigs = f.rootSign(trust.NamespaceBundle, f.bundleDoc)
	return f
}

// preflight writes the offered state into the spool and runs Preflight.
func (h *testHost) preflight() (*PreflightReport, error) {
	h.t.Helper()
	h.write()
	return Preflight(context.Background(), h.cfg, h.l)
}

func (h *testHost) mustPreflight() *PreflightReport {
	h.t.Helper()
	r, err := h.preflight()
	if err != nil {
		h.t.Fatalf("preflight: %v", err)
	}
	if h.exists(h.l.DropIn()) {
		h.t.Fatal("the preflight left a drop-in behind")
	}
	if h.run.reloads != 0 {
		h.t.Fatalf("the preflight reloaded sshd %d times", h.run.reloads)
	}
	return r
}

// finding returns the first finding with code, or nil.
func finding(r *PreflightReport, code string) *Finding {
	for i := range r.Findings {
		if r.Findings[i].Code == code {
			return &r.Findings[i]
		}
	}
	return nil
}

func writeRootFile(t *testing.T, h *testHost, rel, content string) string {
	t.Helper()
	p := filepath.Join(h.l.Root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return p
}

// TestPreflight is the D-07 refusal table: each code, its fix, and that
// the preflight changes nothing (no drop-in left, no reload).
func TestPreflight(t *testing.T) {
	host := func(t *testing.T) *testHost {
		h := newTestHost(t, newFixture(t))
		h.publishDir(h.spec("role:ops"))
		return h
	}
	refused := func(t *testing.T, r *PreflightReport, code string) *Finding {
		t.Helper()
		f := finding(r, code)
		if f == nil || !f.Refusal || !r.Refused() {
			t.Fatalf("findings %+v, want the refusal %s", r.Findings, code)
		}
		return f
	}
	t.Run("clean_host", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		r := h.mustPreflight()
		if len(r.Findings) != 0 || r.Refused() {
			t.Fatalf("a clean host: %+v", r)
		}
		// sshd -T without and with the trial drop-in, then -C for deploy.
		if h.run.dumps[""] != 2 || h.run.dumps["user=deploy,host=127.0.0.1,addr=127.0.0.1,laddr=127.0.0.1,lport="+portOf(h)] != 1 {
			t.Fatalf("sshd -T runs %v", h.run.dumps)
		}
	})
	t.Run("ssh_keygen_missing", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.cfg.SSHKeygen = filepath.Join(t.TempDir(), "ssh-keygen")
		refused(t, h.mustPreflight(), CodeSSHKeygenMissing)
	})
	t.Run("sshd_missing_is_a_tool_error", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.cfg.SSHD = "/nonexistent/sshd"
		if _, err := h.preflight(); !errors.Is(err, ErrConfig) {
			t.Fatalf("a missing sshd: %v, want a tool error", err)
		}
	})
	t.Run("no_dropin_dir", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		if err := os.Remove(h.l.DropInDir()); err != nil {
			t.Fatal(err)
		}
		refused(t, h.mustPreflight(), CodeNoDropInDir)
	})
	t.Run("no_dropin_dir_include_missing", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.run.noInclude = true
		f := refused(t, h.mustPreflight(), CodeNoDropInDir)
		if !strings.Contains(f.Message, "does not read sshd_config.d") {
			t.Fatalf("message %q", f.Message)
		}
	})
	t.Run("foreign_trust_setting_names_file_and_line", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		if err := os.WriteFile(h.cfg.SSHDConfig, []byte("Include x\n# a comment\ntrustedusercakeys=/etc/ssh/other_ca.pub\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		h.run.after = map[string]string{"trustedusercakeys": "/etc/ssh/other_ca.pub"}
		f := refused(t, h.mustPreflight(), CodeForeignTrust)
		if f.File != h.cfg.SSHDConfig || f.Line != 3 || !strings.Contains(f.Fix, "remove or comment out") {
			t.Fatalf("finding %+v, want %s line 3", f, h.cfg.SSHDConfig)
		}
	})
	t.Run("foreign_trust_setting_in_other_dropin", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		p := writeRootFile(t, h, "etc/ssh/sshd_config.d/10-other.conf", "RevokedKeys /etc/ssh/revoked\n")
		h.run.before = map[string]string{"revokedkeys": "/etc/ssh/revoked"}
		if f := refused(t, h.mustPreflight(), CodeForeignTrust); f.File != p || f.Line != 1 {
			t.Fatalf("finding %+v, want %s line 1", f, p)
		}
	})
	t.Run("foreign_trust_setting_effective_elsewhere", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.run.before = map[string]string{"authorizedprincipalsfile": "/opt/principals/%u"}
		if f := refused(t, h.mustPreflight(), CodeForeignTrust); f.File != "" || !strings.Contains(f.Message, "Include elsewhere") {
			t.Fatalf("finding %+v", f)
		}
	})
	t.Run("no_loopback_listener", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.run.listen = []string{"192.0.2.10:22"}
		if f := refused(t, h.mustPreflight(), CodeNoLoopbackListener); !strings.Contains(f.Fix, "ListenAddress 127.0.0.1") {
			t.Fatalf("fix %q", f.Fix)
		}
	})
	t.Run("account_excluded_allowusers", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.run.extra = "allowusers alice\n"
		r := h.mustPreflight()
		f := finding(r, CodeAccountExcluded)
		if f == nil || f.Account != "deploy" || f.Refusal || r.Refused() {
			t.Fatalf("AllowUsers alice with deploy managed: %+v", r.Findings)
		}
	})
	t.Run("account_excluded_denygroups", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		writeRootFile(t, h, "etc/passwd", "root:x:0:0::/root:/bin/sh\ndeploy:x:1000:1000::/home/deploy:/bin/sh\n")
		writeRootFile(t, h, "etc/group", "root:x:0:\nwheel:x:10:deploy\ndeploy:x:1000:\n")
		h.run.extra = "denygroups wheel\n"
		f := finding(h.mustPreflight(), CodeAccountExcluded)
		if f == nil || !strings.Contains(f.Message, "DenyGroups wheel refuses its group wheel") {
			t.Fatalf("DenyGroups wheel: %+v", f)
		}
	})
	t.Run("report_only_codes_do_not_refuse", func(t *testing.T) {
		t.Parallel()
		r := &PreflightReport{}
		r.add(Finding{Code: CodeAccountExcluded})
		r.add(Finding{Code: CodePhase2Adoptable})
		if r.Refused() {
			t.Fatalf("report-only codes refused: %+v", r.Findings)
		}
		r.add(Finding{Code: CodeForeignTrust})
		if !r.Refused() {
			t.Fatal("a refusal code did not refuse")
		}
	})
	t.Run("rhel8_unsupported", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		writeRootFile(t, h, "etc/redhat-release", "Rocky Linux release 8.10 (Green Obsidian)\n")
		refused(t, h.mustPreflight(), CodeRHEL8)
	})
	t.Run("rhel9_supported", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		writeRootFile(t, h, "etc/redhat-release", "AlmaLinux release 9.8 (Olive Jaguar)\n")
		if r := h.mustPreflight(); r.Refused() {
			t.Fatalf("RHEL 9: %+v", r.Findings)
		}
	})
	t.Run("fips_unsupported", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		writeRootFile(t, h, "proc/sys/crypto/fips_enabled", "1\n")
		refused(t, h.mustPreflight(), CodeFIPS)
	})
	t.Run("host_pop_not_enabled", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, fixtureWithoutPoP(t))
		h.publishDir(h.spec("role:ops"))
		refused(t, h.mustPreflight(), CodeHostPoPNotEnabled)
		// The apply refuses it too, and writes nothing.
		if _, err := h.apply(); !errors.Is(err, ErrHostPoPNotEnabled) || h.exists(h.l.Current()) || h.exists(h.l.DropIn()) || h.exists(h.l.KeyrosterDir()) {
			t.Fatalf("apply without pop.hosts: %v, current %t", err, h.exists(h.l.Current()))
		}
	})
	t.Run("no_policy_yet_not_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, fixtureWithoutPoP(t))
		// Before enrollment: no state directory at all, then pins with an
		// empty spool.
		l := h.l
		l.StateDir = filepath.Join(t.TempDir(), "not-enrolled")
		r, err := Preflight(context.Background(), h.cfg, l)
		if err != nil || r.Refused() || finding(r, CodeHostPoPNotEnabled) != nil || len(r.Notes) == 0 {
			t.Fatalf("no state directory: %+v, %v", r, err)
		}
		h.state = spool.State{}
		if r := h.mustPreflight(); r.Refused() || finding(r, CodeHostPoPNotEnabled) != nil || len(r.Notes) == 0 {
			t.Fatalf("pins without a bundle yet: %+v", r)
		}
	})
	t.Run("login_grace_unbounded", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.run.grace = "0"
		if f := refused(t, h.mustPreflight(), CodeLoginGraceUnbounded); !strings.Contains(f.Fix, "LoginGraceTime") {
			t.Fatalf("fix %q", f.Fix)
		}
	})
	t.Run("login_grace_unknown", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.run.grace = "2m"
		refused(t, h.mustPreflight(), CodeLoginGraceUnknown)
	})
	t.Run("phase2_layout_structural_adoptable", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.installPhase2(phase2Layout{})
		r := h.mustPreflight()
		if f := finding(r, CodePhase2Adoptable); f == nil || f.Refusal || r.Refused() || len(r.Findings) != 1 {
			t.Fatalf("the runbook's layout: %+v", r.Findings)
		}
		if !h.phase2Intact() {
			t.Fatal("the preflight changed the Phase 2 layout")
		}
	})
	t.Run("phase2_like_layout_extra_line_foreign", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.installPhase2(phase2Layout{dropIn: phase2CALine + "\n" + phase2PrincipalsLine + "\nRevokedKeys /etc/ssh/revoked.krl\n"})
		h.run.after["revokedkeys"] = "/etc/ssh/revoked.krl"
		r := h.mustPreflight()
		refused(t, r, CodeForeignTrust)
		if finding(r, CodePhase2Adoptable) != nil {
			t.Fatalf("a layout with an extra line is adoptable: %+v", r.Findings)
		}
	})
	t.Run("trial_leftover_removed", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		if err := os.WriteFile(h.l.DropIn(), trialDropIn(h.l), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		r := h.mustPreflight()
		if r.Refused() || !strings.Contains(strings.Join(r.Notes, " "), "removed a trial drop-in") {
			t.Fatalf("a leftover trial: %+v", r)
		}
	})
	t.Run("apply_replaces_leftover_trial", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		if err := os.WriteFile(h.l.DropIn(), trialDropIn(h.l), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		r := h.mustApply()
		if !r.Reloaded || readFile(t, h.l.DropIn()) != string(DropIn(h.l, DropInSpec{})) || h.exists(h.l.State(dropinPrevFile)) {
			t.Fatalf("the first install over a leftover trial: %+v", r)
		}
	})
	t.Run("installed_host_keeps_its_dropin", func(t *testing.T) {
		t.Parallel()
		// The trial's own header keeps a preflight (and an apply's
		// leftover-trial cleanup) from ever taking the agent's real drop-in
		// for a trial and removing it.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		r, err := h.preflight()
		if err != nil || r.Refused() || readFile(t, h.l.DropIn()) != string(DropIn(h.l, DropInSpec{})) {
			t.Fatalf("preflight on an installed host: %+v, %v, drop-in present %t", r, err, h.exists(h.l.DropIn()))
		}
		if h.run.dumps[""] != 3 { // the apply's start and activation, then the preflight's one: no trial
			t.Fatalf("sshd -T runs %v", h.run.dumps)
		}
	})
	// PR #68 review, F1, F5 and D-R2: on an installed host the preflight
	// writes no trial, and a missing, trial or edited drop-in is
	// dropin_drift, never foreign_trust_setting.
	installedDrift := func(t *testing.T, edit func(h *testHost)) (*testHost, *PreflightReport) {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		edit(h)
		before := h.run.dumps[""]
		r, err := h.preflight()
		if err != nil {
			t.Fatal(err)
		}
		if f := refused(t, r, CodeDropInDrift); f.File != h.l.DropIn() || finding(r, CodeForeignTrust) != nil {
			t.Fatalf("findings %+v", r.Findings)
		}
		if h.run.dumps[""] != before+1 || h.run.reloads != 1 { // one sshd -T, no trial; only the install's reload
			t.Fatalf("sshd -T runs %v, %d reloads", h.run.dumps, h.run.reloads)
		}
		return h, r
	}
	t.Run("installed_host_missing_dropin_no_trial", func(t *testing.T) {
		t.Parallel()
		h, _ := installedDrift(t, func(h *testHost) {
			if err := os.Remove(h.l.DropIn()); err != nil {
				t.Fatal(err)
			}
		})
		if h.exists(h.l.DropIn()) {
			t.Fatal("the preflight wrote a drop-in on an installed host")
		}
	})
	t.Run("installed_host_trial_reported_and_left", func(t *testing.T) {
		t.Parallel()
		h, _ := installedDrift(t, func(h *testHost) {
			if err := os.WriteFile(h.l.DropIn(), trialDropIn(h.l), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		})
		if readFile(t, h.l.DropIn()) != string(trialDropIn(h.l)) {
			t.Fatal("the preflight changed the trial on an installed host (the apply replaces it and reloads)")
		}
	})
	t.Run("installed_host_edited_dropin_is_drift", func(t *testing.T) {
		t.Parallel()
		installedDrift(t, func(h *testHost) { appendFile(t, h.l.DropIn(), "# managed by ansible\n") })
	})
	t.Run("installed_host_edited_trust_line_is_drift", func(t *testing.T) {
		t.Parallel()
		installedDrift(t, func(h *testHost) {
			b := strings.Replace(string(DropIn(h.l, DropInSpec{})), filepath.Join(h.l.Current(), CAFile), "/etc/ssh/other_ca.pub", 1)
			if err := os.WriteFile(h.l.DropIn(), []byte(b), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		})
	})
	t.Run("foreign_file_with_the_agents_name", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		if err := os.WriteFile(h.l.DropIn(), []byte("PasswordAuthentication yes\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		r, err := h.preflight()
		if err != nil || finding(r, CodeForeignTrust) == nil || readFile(t, h.l.DropIn()) != "PasswordAuthentication yes\n" {
			t.Fatalf("a foreign 00-keyroster.conf: %+v, %v", r, err)
		}
	})
	t.Run("apply_in_progress_is_a_tool_error", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		fd, err := unix.Open(h.l.State(lockFile), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(fd) }()
		if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
			t.Fatal(err)
		}
		if _, err := h.preflight(); err == nil || !strings.Contains(err.Error(), "an apply holds") {
			t.Fatalf("with the lock held: %v", err)
		}
	})
}

// TestExcluded is sshd's AllowUsers, DenyUsers and group rules.
func TestExcluded(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("deploy:x:1000:1000::/home/deploy:/bin/sh\n"), 0o644) //nolint:gosec // test fixture
	_ = os.WriteFile(filepath.Join(root, "etc", "group"), []byte("deploy:x:1000:\nadm:x:4:deploy\n"), 0o644)            //nolint:gosec // test fixture
	for _, tc := range []struct {
		dump string
		want string // "" not excluded, else a substring
	}{
		{"", ""},
		{"allowusers deploy\n", ""},
		{"allowusers dep*\n", ""},
		{"allowusers d?ploy\n", ""},
		{"allowusers alice\n", "does not list it"},
		{"allowusers deploy@192.0.2.1\n", "only as deploy@192.0.2.1"},
		{"allowusers alice\nallowusers deploy\n", ""},
		{"denyusers deploy\n", "DenyUsers deploy refuses it"},
		{"denyusers *\n", "DenyUsers * refuses it"},
		{"denyusers deploy@10.*\n", "from matching client hosts"},
		{"allowgroups adm\n", ""},
		{"allowgroups wheel\n", "lists none of its groups"},
		{"allowgroups wheel,!adm\n", "lists none of its groups"},
		{"denygroups adm\n", "DenyGroups adm refuses its group adm"},
		{"denygroups *,!adm\n", ""},
		{"denygroups adm,wheel\n", ""},
		{"allowgroups adm,wheel\n", "lists none of its groups"},
	} {
		got := Excluded(ParseDump([]byte(tc.dump)), "deploy", root)
		if tc.want == "" && got != "" || tc.want != "" && !strings.Contains(got, tc.want) {
			t.Errorf("%q: %q, want %q", tc.dump, got, tc.want)
		}
	}
	if got := Excluded(ParseDump([]byte("allowgroups adm\n")), "nobody-here", root); !strings.Contains(got, "groups are unknown") {
		t.Errorf("an account outside /etc/passwd: %q", got)
	}
}

// TestExcludedDefinite (03-10c, D3, sec-06): Excluded's text from origin
// byte for byte (the main cases of TestExcluded, with host names for the
// user@host entries), and definite computed over all entries.
func TestExcludedDefinite(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "etc", "passwd"), []byte("deploy:x:1000:1000::/home/deploy:/bin/sh\n"), 0o644) //nolint:gosec // test fixture
	_ = os.WriteFile(filepath.Join(root, "etc", "group"), []byte("deploy:x:1000:\nadm:x:4:deploy\n"), 0o644)            //nolint:gosec // test fixture
	const mayDeny = "DenyUsers deploy@remote.example refuses it from matching client hosts"
	const mayAllow = "AllowUsers admits it only as deploy@remote.example, from matching client hosts"
	check := func(t *testing.T, dump, account, why string, definite bool) {
		t.Helper()
		d := ParseDump([]byte(dump))
		gotWhy, gotDef := ExcludedDefinite(d, account, root)
		if gotWhy != why || gotDef != definite {
			t.Fatalf("%q: (%q, %v), want (%q, %v)", dump, gotWhy, gotDef, why, definite)
		}
		if got := Excluded(d, account, root); got != why {
			t.Fatalf("%q: Excluded %q, want %q", dump, got, why)
		}
	}
	for _, c := range []struct {
		dump, why string
		definite  bool
	}{
		{"", "", false},
		{"allowusers deploy\n", "", false},
		{"allowusers dep*\n", "", false},
		{"allowusers d?ploy\n", "", false},
		{"allowusers alice\n", "AllowUsers (alice) does not list it", true},
		{"allowusers deploy@remote.example\n", mayAllow, false},
		{"allowusers alice\nallowusers deploy\n", "", false},
		{"denyusers deploy\n", "DenyUsers deploy refuses it", true},
		{"denyusers *\n", "DenyUsers * refuses it", true},
		{"denyusers deploy@remote.example\n", mayDeny, false},
		{"allowgroups adm\n", "", false},
		{"allowgroups wheel\n", "AllowGroups (wheel) lists none of its groups (deploy, adm)", true},
		{"allowgroups wheel,!adm\n", "AllowGroups (wheel,!adm) lists none of its groups (deploy, adm)", true},
		{"denygroups adm\n", "DenyGroups adm refuses its group adm", true},
		// One pattern per entry, as sshd applies it: no comma list, no !.
		{"denygroups *,!adm\n", "", false},
		{"denygroups adm,wheel\n", "", false},
		{"allowgroups adm,wheel\n", "AllowGroups (adm,wheel) lists none of its groups (deploy, adm)", true},
		{"denygroups ad?\n", "DenyGroups ad? refuses its group adm", true},
	} {
		check(t, c.dump, "deploy", c.why, c.definite)
	}
	t.Run("unknown_groups_not_definite", func(t *testing.T) {
		check(t, "allowgroups adm\n", "nobody-here", "AllowGroups or DenyGroups is set and nobody-here is not in "+filepath.Join(root, "etc", "passwd")+", so its groups are unknown here", false)
	})
	t.Run("definite_after_user_at_host", func(t *testing.T) {
		check(t, "denyusers deploy@remote.example\ndenyusers dep*\n", "deploy", mayDeny, true)
		check(t, "denyusers deploy@remote.example\nallowgroups wheel\n", "deploy", mayDeny, true)
		check(t, "allowusers deploy@remote.example\ndenygroups adm\n", "deploy", mayAllow, true)
	})
	// 03-10c: an AllowGroups non-match is definite only while sshd's group
	// lookups see root/etc/group alone; a DenyGroups match always is.
	t.Run("nss_group_sources", func(t *testing.T) {
		const none = "AllowGroups (wheel) lists none of its groups (deploy, adm)"
		maybe := none + " in " + filepath.Join(root, "etc", "group") + "; " + filepath.Join(root, "etc", "nsswitch.conf") + " takes groups from more than files, so sshd may still admit it"
		for _, c := range []struct {
			name, nss string
			definite  bool
		}{
			{"files", "passwd: files\ngroup: files\n", true},
			{"files_systemd", "group:          files systemd\n", true},
			{"files_action_systemd", "group: files [SUCCESS=merge] systemd\n", true},
			{"files_spaced_action", "group: files [ NOTFOUND=return ] systemd\n", true},
			{"comment_ignored", "# group: files sss\ngroup: files # was sss\n", true},
			{"second_group_line", "group: files\ngroup: files sss\n", false},
			{"upper_case", "Group: Files SSS\n", false},
			{"files_sss", "group: files sss\n", false},
			{"sss_first", "group: sss files\n", false},
			{"compat", "group: compat\n", false},
			{"systemd_only", "group: systemd\n", false},
			{"initgroups_sss", "group: files\ninitgroups: files sss\n", false},
		} {
			t.Run(c.name, func(t *testing.T) {
				if err := os.WriteFile(filepath.Join(root, "etc", "nsswitch.conf"), []byte(c.nss), 0o644); err != nil { //nolint:gosec // test fixture
					t.Fatal(err)
				}
				why := maybe
				if c.definite {
					why = none
				}
				check(t, "allowgroups wheel\n", "deploy", why, c.definite)
				check(t, "denygroups adm\n", "deploy", "DenyGroups adm refuses its group adm", true)
			})
		}
		if err := os.Remove(filepath.Join(root, "etc", "nsswitch.conf")); err != nil {
			t.Fatal(err)
		}
		t.Run("missing_is_files", func(t *testing.T) {
			check(t, "allowgroups wheel\n", "deploy", none, true)
		})
	})
}

// probeFindings is r's findings of code probe_account.
func probeFindings(r *PreflightReport) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Code == CodeProbeAccount {
			out = append(out, f)
		}
	}
	return out
}

// TestPreflightProbeAccount (03-10c, T-03-387): preflight reports the probe
// account's full check report only, also before enrolment, and never
// refuses an apply for it.
func TestPreflightProbeAccount(t *testing.T) {
	mustOne := func(t *testing.T, r *PreflightReport, reason string) {
		t.Helper()
		got := probeFindings(r)
		if len(got) != 1 || !strings.HasPrefix(got[0].Message, reason+":") || got[0].Account != probeAcct || got[0].Refusal || got[0].Fix == "" {
			t.Fatalf("%s: probe findings %+v", reason, got)
		}
		if r.Refused() {
			t.Fatalf("%s: the preflight refuses: %+v", reason, r.Findings)
		}
	}
	host := func(t *testing.T) *testHost {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		h.gateOn()
		h.writeRootFile("bin/sh", []byte("#!/bin/false\n"), 0o755)
		return h
	}
	mapped := func(t *testing.T) *testHost {
		t.Helper()
		h := host(t)
		s := h.spec("role:a")
		s.accounts = []string{"deploy", probeAcct}
		h.publishDir(s)
		return h
	}
	t.Run("reports_each_reason_report_only", func(t *testing.T) {
		t.Parallel()
		for _, c := range []struct {
			reason string
			set    func(h *testHost)
		}{
			{accountMissing, func(h *testHost) { h.writePasswd("root:x:0:0:root:/root:/bin/bash\n") }},
			{accountUnparsable, func(h *testHost) { h.writePasswd(probeAcct + ":x:990:990::/nonexistent\n") }},
			{accountUIDZero, func(h *testHost) { h.writePasswd(probeAcct + ":x:0:0::/nonexistent:/usr/sbin/nologin\n") }},
			{shellMissing, func(h *testHost) { h.writePasswd(probeLine("x", "/sbin/nologin") + "\n") }},
			{shellNotNologin, func(h *testHost) { h.writePasswd(probeLine("x", "/bin/sh") + "\n") }},
			{passwordEmpty, func(h *testHost) { h.setShadow("") }},
			{passwordSet, func(h *testHost) { h.setShadow("$6$salt$abcdef") }},
			{sshdOverride, func(h *testHost) { h.setFor("pubkeyauthentication no\n") }},
			{accountExcluded, func(h *testHost) { h.setFor("denyusers " + probeAcct + "\n") }},
		} {
			h := host(t)
			c.set(h)
			mustOne(t, h.mustPreflight(), c.reason)
		}
		h := mapped(t)
		mustOne(t, h.mustPreflight(), "account_is_managed")
	})
	t.Run("no_verified_state_still_runs", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n")
		// No h.write(): the spool holds no signed state.
		r, err := Preflight(context.Background(), h.cfg, h.l)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(r.Notes, func(n string) bool { return strings.Contains(n, "the policy and account checks run once") }) {
			t.Fatalf("notes %q: want the no-verified-state note", r.Notes)
		}
		mustOne(t, r, accountMissing)
	})
	t.Run("no_loopback_listener_no_finding_no_error", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n")
		h.run.listen = []string{"remote.example:22"}
		r, err := h.preflight()
		if err != nil {
			t.Fatalf("preflight: %v", err)
		}
		if finding(r, CodeNoLoopbackListener) == nil || len(probeFindings(r)) != 0 {
			t.Fatalf("findings %+v", r.Findings)
		}
	})
	t.Run("healthy_account_before_the_dropin_has_no_finding", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.setShadow("*")
		r := h.mustPreflight()
		if got := probeFindings(r); len(got) != 0 || r.Refused() {
			t.Fatalf("a healthy probe account before the first install: %+v", r.Findings)
		}
		if h.exists(h.l.LastGood()) || h.exists(h.l.DropIn()) {
			t.Fatal("the host is installed")
		}
	})
	// 03-10c: on an installed host the check compares the trust settings,
	// so a Match block that overrides one of them, or sets a principals
	// command, for the probe account is one sshd_override finding, report
	// only.
	t.Run("installed_host_compares_trust", func(t *testing.T) {
		t.Parallel()
		for _, m := range []map[string]string{
			{"authorizedprincipalsfile": "/etc/ssh/other/%u"},
			{principalsCommand: "/usr/local/bin/principals %u"},
		} {
			h := gateHost(t, "role:a")
			if !h.exists(h.l.LastGood()) || !h.exists(h.l.DropIn()) {
				t.Fatal("the host is not installed")
			}
			h.run.match = map[string]map[string]string{probeAcct: m}
			r, err := h.preflight()
			if err != nil {
				t.Fatalf("preflight: %v", err)
			}
			mustOne(t, r, sshdOverride)
		}
	})
	t.Run("account_is_managed_finding_with_state", func(t *testing.T) {
		t.Parallel()
		h := mapped(t)
		r := h.mustPreflight()
		mustOne(t, r, "account_is_managed")
		h = host(t)
		h.publishDir(h.spec("role:a"))
		if got := probeFindings(h.mustPreflight()); len(got) != 0 {
			t.Fatalf("an unmapped probe account: %+v", got)
		}
	})
	t.Run("shadow_unreadable_is_a_note", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.cfg.openShadow = openErr(syscall.EACCES)
		r := h.mustPreflight()
		if got := probeFindings(r); len(got) != 0 {
			t.Fatalf("an unreadable shadow holds: %+v", got)
		}
		if !slices.ContainsFunc(r.Notes, func(n string) bool { return strings.HasPrefix(n, noteShadowUnreadable+":") }) {
			t.Fatalf("notes %q", r.Notes)
		}
	})
	t.Run("silent_when_probes_off", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n")
		r := h.mustPreflight()
		if got := probeFindings(r); len(got) != 0 || h.run.dumps[probeSpecKey(h, ProbeSource, "127.0.0.1")] != 0 {
			t.Fatalf("probes off: %+v, dumps %v", got, h.run.dumps)
		}
	})
	t.Run("hash_never_in_report", func(t *testing.T) {
		t.Parallel()
		// The hash in shadow, then in passwd field 2.
		const marker = "$6$Zq9MarkerSalt$Zq9MarkerHashValue"
		for _, inPasswd := range []bool{false, true} {
			h := host(t)
			h.setShadow(marker)
			if inPasswd {
				h.setShadow("*")
				h.writePasswd(probeLine(marker, "/usr/sbin/nologin") + "\n")
			}
			r := h.mustPreflight()
			mustOne(t, r, passwordSet)
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(b, []byte("Zq9Marker")) {
				t.Fatalf("the report carries the hash (in passwd: %t): %s", inPasswd, b)
			}
		}
	})
	t.Run("apply_not_refused", func(t *testing.T) {
		t.Parallel()
		h := host(t)
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n")
		h.publishDir(h.spec("role:a"))
		_, err := h.apply()
		var pe *PreflightError
		if err != nil || errors.As(err, &pe) {
			t.Fatalf("the first apply with a broken probe account: %v", err)
		}
		mustPrincipals(t, h, "role:a")
	})
}
