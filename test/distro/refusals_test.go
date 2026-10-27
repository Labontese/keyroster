//go:build e2edistro && linux

package distro

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/apply"
	"github.com/Labontese/keyroster/internal/directory"
)

// restartSSHD restarts sshd, so it loads configuration written by hand.
func restartSSHD(t *testing.T) {
	t.Helper()
	if err := stopSSHD(); err != nil {
		t.Fatal(err)
	}
	if err := startSSHD(); err != nil {
		t.Fatal(err)
	}
}

// nothingWritten fails when an apply or preflight left any of the
// agent's files in /etc/ssh.
func nothingWritten(t *testing.T, what string) {
	t.Helper()
	for _, p := range []string{"/etc/ssh/keyroster", filepath.Join(dropInDir, "00-keyroster.conf")} {
		if _, err := os.Lstat(p); err == nil {
			t.Fatalf("%s: %s exists", what, p)
		}
	}
}

func findingOf(r apply.PreflightReport, code string) *apply.Finding {
	for i := range r.Findings {
		if r.Findings[i].Code == code {
			return &r.Findings[i]
		}
	}
	return nil
}

func prepend(lines string) func(string) string {
	return func(c string) string { return lines + c }
}

// TestDistroRefusals: the D-07 refusals on the distribution's own sshd,
// with keyroster-agent preflight's exit codes (0 clean or report only, 3
// refused, 2 tool error), and LoginGraceTime 0 refused by preflight and
// apply --once alike with nothing written. It runs the codes a container
// can provoke; login_grace_unknown (a real sshd -T always prints seconds),
// rhel8_unsupported, fips_unsupported, dropin_drift, sshd_config_unsafe
// and the systemd path of sshd_command_unknown are unit-tested only
// (TestPreflight, TestIncludeGraph, TestDetect; host-setup.md).
func TestDistroRefusals(t *testing.T) {
	other := filepath.Join(dropInDir, "10-other.conf")
	for _, tc := range []struct {
		name string
		edit hostEdit
		args func() []string
		code int
		want string // a finding code; "" none
		file string // the finding's file
		line int
		// noPoP signs a policy without pop.hosts; lock holds the apply lock
		// while the preflight runs.
		noPoP, lock bool
	}{
		{name: "clean", code: 0},
		{name: "foreign_ca_in_other_dropin", edit: hostEdit{files: map[string]string{other: "TrustedUserCAKeys /etc/ssh/other_ca.pub\n"}}, code: 3, want: apply.CodeForeignTrust, file: other, line: 1},
		{name: "foreign_ca_in_sshd_config", edit: hostEdit{config: prepend("TrustedUserCAKeys /etc/ssh/other_ca.pub\n")}, code: 3, want: apply.CodeForeignTrust, file: sshdConfig, line: 1},
		{name: "no_include", edit: hostEdit{config: func(c string) string {
			var out []string
			for _, l := range strings.Split(c, "\n") {
				if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), "include") {
					out = append(out, l)
				}
			}
			return strings.Join(out, "\n")
		}}, code: 3, want: apply.CodeNoDropInDir},
		{name: "allowusers_excludes_account_report_only", edit: hostEdit{config: prepend("AllowUsers alice\n")}, code: 0, want: apply.CodeAccountExcluded},
		{name: "sshd_nonexistent_tool_error", args: func() []string {
			return []string{"preflight", "--root", "/", "--sshd", "/nonexistent/sshd", "--sshd-config", sshdConfig, "--ssh-keygen", keygen, "--state-dir", stateDir, "--spool", spoolDir}
		}, code: 2},
		{name: "login_grace_unbounded", edit: hostEdit{config: prepend("LoginGraceTime 0\n")}, code: 3, want: apply.CodeLoginGraceUnbounded},
		// PR #68 review F7: the cheap remaining cases of the preflight table
		// on the distribution's own sshd.
		{name: "ssh_keygen_missing", args: func() []string {
			return []string{"preflight", "--root", "/", "--sshd", sshdBin, "--sshd-config", sshdConfig, "--ssh-keygen", "/nonexistent/ssh-keygen", "--state-dir", stateDir, "--spool", spoolDir}
		}, code: 3, want: apply.CodeSSHKeygenMissing, file: "/nonexistent/ssh-keygen"},
		{name: "host_pop_not_enabled", noPoP: true, code: 3, want: apply.CodeHostPoPNotEnabled},
		// sshd -T needs no listener, so sshd stays stopped (it cannot bind
		// a TEST-NET address).
		{name: "no_loopback_listener", edit: hostEdit{config: prepend("ListenAddress 192.0.2.10\n"), noStart: true}, code: 3, want: apply.CodeNoLoopbackListener},
		{name: "apply_lock_held_tool_error", lock: true, code: 2},
		// PR #68 review D-R3: the whole Include graph, relative to /etc/ssh,
		// Match blocks and AuthorizedPrincipalsCommand included.
		{name: "foreign_principals_file_in_included_match_block", edit: hostEdit{config: prepend("Include keyroster-test/ops.conf\n"),
			files: map[string]string{"/etc/ssh/keyroster-test/ops.conf": "Match User root\n    AuthorizedPrincipalsFile /etc/ssh/ops_principals/%u\n"}},
			code: 3, want: apply.CodeForeignTrust, file: "/etc/ssh/keyroster-test/ops.conf", line: 2},
		{name: "foreign_ca_in_nested_glob_include", edit: hostEdit{config: prepend("Include keyroster-test/*.conf\n"),
			files: map[string]string{"/etc/ssh/keyroster-test/10-a.conf": "Include keyroster-test/deeper/b.conf\n", "/etc/ssh/keyroster-test/deeper/b.conf": "TrustedUserCAKeys /etc/ssh/other_ca.pub\n"}},
			code: 3, want: apply.CodeForeignTrust, file: "/etc/ssh/keyroster-test/deeper/b.conf", line: 1},
		{name: "principals_command_in_sshd_config", edit: hostEdit{config: prepend("AuthorizedPrincipalsCommand /bin/false\nAuthorizedPrincipalsCommandUser nobody\n")},
			code: 3, want: apply.CodeForeignTrust, file: sshdConfig, line: 1},
		{name: "principals_command_in_included_match_block", edit: hostEdit{config: prepend("Include keyroster-test/cmd.conf\n"),
			files: map[string]string{"/etc/ssh/keyroster-test/cmd.conf": "Match User " + account + "\n    AuthorizedPrincipalsCommand /bin/false\n    AuthorizedPrincipalsCommandUser nobody\n"}},
			code: 3, want: apply.CodeForeignTrust, file: "/etc/ssh/keyroster-test/cmd.conf", line: 2},
		// A real sshd refuses an Include cycle itself: sshd -T fails, a
		// tool error (the agent's own sshd_config_unsafe is unit-tested).
		{name: "include_cycle_sshd_fails", edit: hostEdit{config: prepend("Include keyroster-test/loop.conf\n"), noStart: true,
			files: map[string]string{"/etc/ssh/keyroster-test/loop.conf": "Include keyroster-test/loop.conf\n"}}, code: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHost(t, !tc.noPoP, tc.edit)
			h.w.publish(account, h.hostKey, "role:ops")
			h.enroll()
			if tc.lock {
				fd, err := unix.Open(filepath.Join(stateDir, "apply.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = unix.Close(fd) }()
				if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
					t.Fatal(err)
				}
			}
			args := preflightArgs(true)
			if tc.args != nil {
				args = tc.args()
			}
			code, out, _ := agent(t, args...)
			if code != tc.code {
				t.Fatalf("preflight exit %d, want %d", code, tc.code)
			}
			nothingWritten(t, "after the preflight")
			if tc.code == 2 {
				return
			}
			r := decode[apply.PreflightReport](t, out)
			if tc.want == "" {
				if len(r.Findings) != 0 {
					t.Fatalf("a clean host: %+v", r.Findings)
				}
				return
			}
			f := findingOf(r, tc.want)
			if f == nil || !f.Refusal && tc.code == 3 || tc.file != "" && (f.File != tc.file || f.Line != tc.line) {
				t.Fatalf("findings %+v, want %s at %s:%d", r.Findings, tc.want, tc.file, tc.line)
			}
			if tc.want == apply.CodeLoginGraceUnbounded {
				code, out, _ := agent(t, applyArgs()...)
				if r := decode[apply.Report](t, out); code == 0 || !strings.Contains(strings.Join(r.Errors, " "), "login_grace_unbounded") {
					t.Fatalf("apply --once with LoginGraceTime 0: exit %d, %+v", code, r)
				}
				nothingWritten(t, "after apply --once with LoginGraceTime 0")
			}
		})
	}
}

// phase2 writes the Phase 2 runbook's layout by hand, rendered from
// directory d, and restarts sshd so it is in force. dropIn "" is the
// runbook's two lines.
func (h *host) phase2(d *directory.Directory, dropIn string) {
	h.t.Helper()
	if dropIn == "" {
		dropIn = "TrustedUserCAKeys /etc/ssh/keyroster_user_ca.pub\nAuthorizedPrincipalsFile /etc/ssh/principals/%u\n"
	}
	principals, err := directory.RenderPrincipalsFile(d, "lab", account)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := os.Mkdir("/etc/ssh/principals", 0o755); err != nil { //nolint:gosec // the runbook's mode
		h.t.Fatal(err)
	}
	for p, b := range map[string]string{
		filepath.Join(dropInDir, "50-keyroster.conf"): dropIn,
		"/etc/ssh/keyroster_user_ca.pub":              h.w.caLine(),
		"/etc/ssh/principals/" + account:              string(principals),
	} {
		if err := os.WriteFile(p, []byte(b), 0o644); err != nil { //nolint:gosec // the runbook's mode
			h.t.Fatal(err)
		}
	}
	restartSSHD(h.t)
}

// TestDistroAdoptPhase2 is D-08 on the distribution's own sshd: the exact
// runbook layout, rendered from directory version v, passes the
// pre-enrollment preflight as phase2_adoptable; once the spool holds
// version v+1 (the approval's), apply --once refuses with "only the header
// differs"; after re-rendering it takes the host over, the three paths are
// gone and the login still works. A modified layout is refused.
func TestDistroAdoptPhase2(t *testing.T) {
	t.Run("exact_layout", func(t *testing.T) {
		h := newHost(t, true, hostEdit{})
		h.w.publish(account, h.hostKey, "role:ops")
		h.phase2(h.w.lastDirectory(), "")
		if err := h.login(h.w.userCert(1, "role:ops")); err != nil {
			t.Fatalf("the hand-set Phase 2 layout refuses the certificate: %v", err)
		}
		// Before enrollment: no pins, an empty spool.
		code, out, _ := agent(t, preflightArgs(false)...)
		if r := decode[apply.PreflightReport](t, out); code != 0 || findingOf(r, apply.CodePhase2Adoptable) == nil || len(r.Findings) != 1 {
			t.Fatalf("pre-enrollment preflight: exit %d, %+v", code, r.Findings)
		}
		nothingWritten(t, "after the preflight")
		// The approval installs version v+1: the hand-rendered file names v.
		h.w.publish(account, h.hostKey, "role:ops")
		h.enroll()
		code, out, _ = agent(t, applyArgs()...)
		if r := decode[apply.Report](t, out); code == 0 || !strings.Contains(strings.Join(r.Errors, " "), "only the header differs") {
			t.Fatalf("apply --once with a file from version 1: exit %d, %+v", code, r)
		}
		nothingWritten(t, "after the header-only refusal")
		b, err := directory.RenderPrincipalsFile(h.w.lastDirectory(), "lab", account)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("/etc/ssh/principals/"+account, b, 0o644); err != nil { //nolint:gosec // re-rendered by hand
			t.Fatal(err)
		}
		code, out, _ = agent(t, applyArgs()...)
		r := decode[apply.Report](t, out)
		if code != 0 || r.SelfTest != "pass" || len(r.Phase2Removed) != 4 {
			t.Fatalf("the takeover: exit %d, %+v", code, r)
		}
		for _, p := range []string{filepath.Join(dropInDir, "50-keyroster.conf"), "/etc/ssh/keyroster_user_ca.pub", "/etc/ssh/principals"} {
			if _, err := os.Lstat(p); err == nil {
				t.Fatalf("%s survived the takeover", p)
			}
		}
		if err := h.login(h.w.userCert(2, "role:ops")); err != nil {
			t.Fatalf("login after the takeover: %v", err)
		}
		if code, out, _ := agent(t, checkArgs()...); code != 0 {
			t.Fatalf("check after the takeover: exit %d: %s", code, out)
		}
	})
	t.Run("modified_layout_refused", func(t *testing.T) {
		h := newHost(t, true, hostEdit{})
		h.w.publish(account, h.hostKey, "role:ops")
		h.phase2(h.w.lastDirectory(), "TrustedUserCAKeys /etc/ssh/keyroster_user_ca.pub\nAuthorizedPrincipalsFile /etc/ssh/principals/%u\nAuthorizedKeysFile none\n")
		h.enroll()
		code, out, _ := agent(t, preflightArgs(true)...)
		if r := decode[apply.PreflightReport](t, out); code != 3 || findingOf(r, apply.CodeForeignTrust) == nil || findingOf(r, apply.CodePhase2Adoptable) != nil {
			t.Fatalf("preflight of a modified layout: exit %d, %+v", code, r.Findings)
		}
		code, out, _ = agent(t, applyArgs()...)
		if r := decode[apply.Report](t, out); code == 0 || !strings.Contains(strings.Join(r.Errors, " "), apply.CodePhase2Differs) {
			t.Fatalf("apply --once of a modified layout: exit %d, %+v", code, r)
		}
		nothingWritten(t, "after the refusal")
	})
}

// TestDistroFacts records what each image ships, for the SUMMARY: the
// OpenSSH version, where sshd_config includes sshd_config.d, the packaged
// casignaturealgorithms and logingracetime (the widening wait is that
// plus 30 s), whether ssh-keygen needed its own package, whether sshd -T
// prints revokedkeys while it is unset, and what Detect finds in the
// container (no service manager runs there).
func TestDistroFacts(t *testing.T) {
	_ = newHost(t, true, hostEdit{})
	out, _ := exec.Command(sshdBin, "-V").CombinedOutput()
	version := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	include := "none"
	b, err := os.ReadFile(sshdConfig)
	if err != nil {
		t.Fatal(err)
	}
	for i, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), "include") {
			include = strconv.Itoa(i+1) + ": " + strings.TrimSpace(l)
			break
		}
	}
	d := sshdT(t, "")
	_, hasRevoked := d["revokedkeys"]
	var detected string
	if svc, err := apply.Detect(t.Context(), nil, "/"); err != nil {
		detected = "error: " + err.Error()
	} else {
		detected = fmt.Sprintf("%s %s %s %s", svc.Manager, svc.SSHD, svc.Config, svc.Reload)
	}
	t.Logf("FACT image=%s | sshd=%q | include=%q | casignaturealgorithms=%s | logingracetime=%s | strictmodes=%s | keygen_package=%s | revokedkeys_line_when_unset=%t | detect=%q",
		distro, version, include, d.One("casignaturealgorithms"), d.One("logingracetime"), d.One("strictmodes"), os.Getenv("KEYROSTER_KEYGEN_PACKAGE"), hasRevoked, detected)
}
