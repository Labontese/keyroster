//go:build linux

package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestIncludeGraph is owner decision D-R3 (PR #68 review, F12 and F16:
// "whole Include graph + AuthorizedPrincipalsCommand"): preflight, the
// apply's preflight and check read every file sshd reads, following
// Include lines (relative to /etc/ssh, globs, inside Match blocks,
// nested), and a trust setting anywhere but the agent's own drop-in,
// AuthorizedPrincipalsCommand included, is foreign_trust_setting; a file
// or Include graph the agent cannot follow safely is sshd_config_unsafe.
func TestIncludeGraph(t *testing.T) {
	// host is a test host whose sshd_config is the harness's Include of
	// sshd_config.d followed by extra lines, with files below the root.
	host := func(t *testing.T, extra string, files map[string]string) *testHost {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		h.publishDir(h.spec("role:ops"))
		appendFile(t, h.cfg.SSHDConfig, extra)
		for rel, content := range files {
			writeRootFile(t, h, rel, content)
		}
		return h
	}
	foreignAt := func(t *testing.T, r *PreflightReport, file string, line int) {
		t.Helper()
		if !slices.ContainsFunc(r.Findings, func(f Finding) bool {
			return f.Code == CodeForeignTrust && f.Refusal && f.File == file && f.Line == line
		}) {
			t.Fatalf("findings %+v, want foreign_trust_setting at %s:%d", r.Findings, file, line)
		}
	}
	unsafe := func(t *testing.T, r *PreflightReport) {
		t.Helper()
		if f := finding(r, CodeConfigUnsafe); f == nil || !f.Refusal {
			t.Fatalf("findings %+v, want sshd_config_unsafe", r.Findings)
		}
	}
	matchBlock := "Match User root\n    AuthorizedPrincipalsFile /etc/ssh/ops_principals/%u\n"
	t.Run("relative_include_outside_dropin_dir_with_match_block", func(t *testing.T) {
		t.Parallel()
		// F12: only deploy is managed; root's Match block names another
		// principals file under a CA the agent would make trusted.
		h := host(t, "Include extra/ops.conf\n", map[string]string{"etc/ssh/extra/ops.conf": matchBlock})
		foreignAt(t, h.mustPreflight(), filepath.Join(h.l.Root, "etc/ssh/extra/ops.conf"), 2)
		if _, err := h.apply(); !errors.Is(err, ErrForeignTrust) || h.exists(h.l.Current()) {
			t.Fatalf("the first install: %v, current %t", err, h.exists(h.l.Current()))
		}
	})
	t.Run("include_inside_match_block_followed", func(t *testing.T) {
		t.Parallel()
		h := host(t, "Match User root\n    Include extra/ops.conf\n", map[string]string{"etc/ssh/extra/ops.conf": "    AuthorizedPrincipalsFile /etc/ssh/ops_principals/%u\n"})
		foreignAt(t, h.mustPreflight(), filepath.Join(h.l.Root, "etc/ssh/extra/ops.conf"), 1)
	})
	t.Run("nested_include", func(t *testing.T) {
		t.Parallel()
		h := host(t, "Include extra/a.conf\n", map[string]string{
			"etc/ssh/extra/a.conf":        "# level one\nInclude = \"extra/deeper/b.conf\"\n",
			"etc/ssh/extra/deeper/b.conf": "TrustedUserCAKeys /etc/ssh/other_ca.pub\n",
		})
		foreignAt(t, h.mustPreflight(), filepath.Join(h.l.Root, "etc/ssh/extra/deeper/b.conf"), 1)
	})
	t.Run("glob_include", func(t *testing.T) {
		t.Parallel()
		h := host(t, "Include extra/*.conf\n", map[string]string{
			"etc/ssh/extra/10-a.conf": "PermitRootLogin no\n",
			"etc/ssh/extra/20-b.conf": "\nrevokedkeys=/etc/ssh/other.krl\n",
		})
		foreignAt(t, h.mustPreflight(), filepath.Join(h.l.Root, "etc/ssh/extra/20-b.conf"), 2)
	})
	t.Run("include_matching_nothing_skipped", func(t *testing.T) {
		t.Parallel()
		h := host(t, "Include extra/*.conf\nInclude nothere/x.conf\n", nil)
		if r := h.mustPreflight(); r.Refused() {
			t.Fatalf("an Include that matches nothing: %+v", r.Findings)
		}
	})
	t.Run("include_cycle_unsafe", func(t *testing.T) {
		t.Parallel()
		h := host(t, "Include extra/loop.conf\n", map[string]string{"etc/ssh/extra/loop.conf": "Include extra/loop.conf\n"})
		unsafe(t, h.mustPreflight())
	})
	t.Run("include_past_sshd_depth_unsafe", func(t *testing.T) {
		t.Parallel()
		files := map[string]string{}
		for i := 1; i <= maxIncludeDepth+1; i++ {
			files[fmt.Sprintf("etc/ssh/extra/%02d.conf", i)] = fmt.Sprintf("Include extra/%02d.conf\n", i+1)
		}
		files[fmt.Sprintf("etc/ssh/extra/%02d.conf", maxIncludeDepth+2)] = "PermitRootLogin no\n"
		h := host(t, "Include extra/01.conf\n", files)
		unsafe(t, h.mustPreflight())
		// sshd's own limit: 16 levels below sshd_config pass.
		delete(files, fmt.Sprintf("etc/ssh/extra/%02d.conf", maxIncludeDepth+2))
		files[fmt.Sprintf("etc/ssh/extra/%02d.conf", maxIncludeDepth)] = "PermitRootLogin no\n"
		h = host(t, "Include extra/01.conf\n", files)
		if r := h.mustPreflight(); r.Refused() {
			t.Fatalf("%d levels of Include: %+v", maxIncludeDepth, r.Findings)
		}
	})
	t.Run("included_file_writable_by_others_unsafe", func(t *testing.T) {
		t.Parallel()
		h := host(t, "Include extra/ops.conf\n", map[string]string{"etc/ssh/extra/ops.conf": "PermitRootLogin no\n"})
		chmod(t, filepath.Join(h.l.Root, "etc/ssh/extra/ops.conf"), 0o666)
		unsafe(t, h.mustPreflight())
	})
	t.Run("include_dir_writable_by_others_unsafe", func(t *testing.T) {
		t.Parallel()
		// Nothing matches yet, but anyone could add a file sshd would read.
		h := host(t, "Include extra/*.conf\n", nil)
		if err := os.MkdirAll(filepath.Join(h.l.Root, "etc/ssh/extra"), 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		chmod(t, filepath.Join(h.l.Root, "etc/ssh/extra"), 0o777) //nolint:gosec // the directory under test is world-writable
		unsafe(t, h.mustPreflight())
	})
	t.Run("include_through_symlink_into_open_dir_unsafe", func(t *testing.T) {
		t.Parallel()
		h := host(t, "Include extra/ops.conf\n", map[string]string{"open/ops.conf": "PermitRootLogin no\n"})
		chmod(t, filepath.Join(h.l.Root, "open"), 0o777)                                     //nolint:gosec // the directory under test is world-writable
		if err := os.MkdirAll(filepath.Join(h.l.Root, "etc/ssh/extra"), 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if err := os.Symlink("../../../open/ops.conf", filepath.Join(h.l.Root, "etc/ssh/extra/ops.conf")); err != nil {
			t.Fatal(err)
		}
		unsafe(t, h.mustPreflight())
	})
	t.Run("include_through_owned_symlink_followed", func(t *testing.T) {
		t.Parallel()
		// Arch's 20-systemd-userdb.conf and EL9's crypto-policies Include
		// are root-owned symlinks.
		h := host(t, "Include extra/ops.conf\n", map[string]string{"usr/lib/ssh/ops.conf": matchBlock})
		if err := os.MkdirAll(filepath.Join(h.l.Root, "etc/ssh/extra"), 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if err := os.Symlink("../../../usr/lib/ssh/ops.conf", filepath.Join(h.l.Root, "etc/ssh/extra/ops.conf")); err != nil {
			t.Fatal(err)
		}
		foreignAt(t, h.mustPreflight(), filepath.Join(h.l.Root, "etc/ssh/extra/ops.conf"), 2)
	})
	t.Run("tilde_include_unsafe", func(t *testing.T) {
		t.Parallel()
		unsafe(t, host(t, "Include ~/ssh.conf\n", nil).mustPreflight())
	})
	t.Run("sshd_config_writable_by_others_unsafe", func(t *testing.T) {
		t.Parallel()
		h := host(t, "", nil)
		chmod(t, h.cfg.SSHDConfig, 0o666)
		unsafe(t, h.mustPreflight())
	})
	// F16: AuthorizedPrincipalsCommand.
	t.Run("principals_command_in_main_config", func(t *testing.T) {
		t.Parallel()
		h := host(t, "AuthorizedPrincipalsCommand /usr/local/bin/principals %u\nAuthorizedPrincipalsCommandUser nobody\n", nil)
		r := h.mustPreflight()
		foreignAt(t, r, h.cfg.SSHDConfig, 2)
		foreignAt(t, r, h.cfg.SSHDConfig, 3)
	})
	t.Run("principals_command_in_match_block", func(t *testing.T) {
		t.Parallel()
		h := host(t, "Include extra/cmd.conf\n", map[string]string{"etc/ssh/extra/cmd.conf": "Match User deploy\n    AuthorizedPrincipalsCommand /usr/local/bin/principals %u\n    AuthorizedPrincipalsCommandUser nobody\n"})
		foreignAt(t, h.mustPreflight(), filepath.Join(h.l.Root, "etc/ssh/extra/cmd.conf"), 2)
	})
	t.Run("principals_command_none_and_user_alone_pass", func(t *testing.T) {
		t.Parallel()
		h := host(t, "AuthorizedPrincipalsCommand none\nAuthorizedPrincipalsCommandUser nobody\nAuthorizedKeysCommand /usr/bin/userdbctl ssh-authorized-keys %u\nAuthorizedKeysCommandUser root\n", nil)
		if r := h.mustPreflight(); r.Refused() {
			t.Fatalf("a command of none, a user alone and an AuthorizedKeysCommand: %+v", r.Findings)
		}
	})
	t.Run("principals_command_reported_by_sshd_t", func(t *testing.T) {
		t.Parallel()
		// Set in no file the agent read (globally), or by a Match block for
		// the managed account (sshd -T -C).
		h := host(t, "", nil)
		h.run.after = map[string]string{principalsCommand: "/usr/local/bin/principals %u"}
		if f := finding(h.mustPreflight(), CodeForeignTrust); f == nil || !strings.Contains(f.Message, principalsCommand) {
			t.Fatalf("a global principals command: %+v", f)
		}
		h = host(t, "", nil)
		h.run.match = map[string]map[string]string{"deploy": {principalsCommand: "/usr/local/bin/principals"}}
		if f := finding(h.mustPreflight(), CodeForeignTrust); f == nil || f.Account != "deploy" {
			t.Fatalf("a principals command for deploy: %+v", f)
		}
	})
	t.Run("principals_command_for_account_not_effective_at_install", func(t *testing.T) {
		t.Parallel()
		h := host(t, "", nil)
		h.run.match = map[string]map[string]string{"deploy": {principalsCommand: "/usr/local/bin/principals"}}
		if _, err := h.apply(); !errors.Is(err, ErrDropInNotEffective) || h.exists(h.l.Current()) {
			t.Fatalf("a principals command for a managed account: %v", err)
		}
	})
	t.Run("check_reports_included_settings_and_principals_command", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		appendFile(t, h.cfg.SSHDConfig, "Include extra/cmd.conf\n")
		writeRootFile(t, h, "etc/ssh/extra/cmd.conf", "Match User deploy\n    AuthorizedPrincipalsCommand /usr/local/bin/principals %u\n    AuthorizedPrincipalsCommandUser nobody\n")
		h.run.match = map[string]map[string]string{"deploy": {principalsCommand: "/usr/local/bin/principals %u"}}
		r, err := h.check()
		if err != nil || !r.Drift() || len(r.Foreign) != 2 || r.Foreign[0].File != filepath.Join(h.l.Root, "etc/ssh/extra/cmd.conf") || r.Foreign[0].Line != 2 {
			t.Fatalf("check with an included principals command: %+v, %v", r, err)
		}
		if !slices.Contains(r.Settings, SettingDrift{Keyword: principalsCommand, Account: "deploy", Want: "none", Got: "/usr/local/bin/principals %u"}) {
			t.Fatalf("settings %+v", r.Settings)
		}
	})
}
