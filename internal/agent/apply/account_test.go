//go:build linux

package apply

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	certpkg "github.com/Labontese/keyroster/internal/cert"
)

// probeAcct is the probe account of the account tests: the default name.
const probeAcct = certpkg.ReservedAccountName

// probeSpecKey is the sshd -T -C spec the full check runs for the probe
// account from src to laddr (03-10c), spelled out here rather than built
// with probeAccountSpec, so that a wrong spec cannot also change what the
// tests expect.
func probeSpecKey(h *testHost, src, laddr string) string {
	return "user=" + probeAcct + ",host=" + src + ",addr=" + src + ",laddr=" + laddr + ",lport=" + portOf(h)
}

// accountHost is a host with the probes on (the probe account in passwd,
// an executable nologin, no shadow file) and a log.
func accountHost(t *testing.T) (*testHost, *bytes.Buffer) {
	t.Helper()
	h := newTestHost(t, newFixture(t))
	h.gateOn()
	var log bytes.Buffer
	h.cfg.Log = &log
	return h, &log
}

// fullCheck runs the full check on an engine of h against h's base dump.
func fullCheck(h *testHost, compareTrust bool, tweak ...func(e *engine)) accountResult {
	h.t.Helper()
	e := h.engine()
	for _, f := range tweak {
		f(e)
	}
	return e.checkProbeAccountFull(context.Background(), probeAcct, ParseDump([]byte(h.run.dump())), compareTrust)
}

// probeLine is the probe account's passwd line with field 2 and the shell.
func probeLine(field2, shell string) string {
	return probeAcct + ":" + field2 + ":990:990::/nonexistent:" + shell
}

// setShadow writes <root>/etc/shadow with one line per field for the probe
// account, after a line for root.
func (h *testHost) setShadow(fields ...string) {
	h.t.Helper()
	b := "root:$6$rootsalt$roothash:20000:0:99999:7:::\n"
	for _, f := range fields {
		b += probeAcct + ":" + f + ":20000::::::\n"
	}
	h.writeRootFile("etc/shadow", []byte(b), 0o640)
}

// setFor sets the extra sshd -T -C lines for the probe account.
func (h *testHost) setFor(lines string) {
	h.t.Helper()
	if h.run.extraFor == nil {
		h.run.extraFor = map[string]string{}
	}
	h.run.extraFor[probeAcct] = lines
}

func mustReason(t *testing.T, got accountResult, want string) {
	t.Helper()
	if got.Reason != want {
		t.Fatalf("reason %q, want %q (class %q, notes %v)", got.Reason, want, got.Shadow, got.Notes)
	}
}

// openErr is an open seam that fails with err.
func openErr(err error) func(string) (*os.File, error) {
	return func(p string) (*os.File, error) { return nil, &os.PathError{Op: "open", Path: p, Err: err} }
}

// TestProbeAccountFull (03-10c, owner decision Q3, T-03-385, T-03-386):
// the full probe account check, stage by stage and in order.
func TestProbeAccountFull(t *testing.T) {
	for _, c := range []struct{ name, passwd, reason string }{
		{"missing", "root:x:0:0:root:/root:/bin/bash\n", accountMissing},
		{"unparsable", probeAcct + ":x:990:990::/nonexistent\n", accountUnparsable},
		{"uid_zero", probeAcct + ":x:0:0::/nonexistent:/usr/sbin/nologin\n", accountUIDZero},
		{"shell_missing", probeLine("x", "/sbin/nologin") + "\n", shellMissing},
		{"shell_not_nologin", probeLine("x", "/bin/sh") + "\n", shellNotNologin},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h, _ := accountHost(t)
			h.writeRootFile("bin/sh", []byte("#!/bin/false\n"), 0o755)
			h.writePasswd(c.passwd)
			h.setShadow("$6$salt$abc")
			mustReason(t, fullCheck(h, false), c.reason)
			if n := h.run.dumps[probeSpecKey(h, ProbeSource, "127.0.0.1")]; n != 0 {
				t.Fatalf("%d sshd -T -C runs before the passwd stage passed", n)
			}
		})
	}
	t.Run("password_empty", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setShadow("")
		mustReason(t, fullCheck(h, false), passwordEmpty)
	})
	t.Run("password_set", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setShadow("$6$salt$abcdef")
		mustReason(t, fullCheck(h, false), passwordSet)
	})
	t.Run("password_locked_ok", func(t *testing.T) {
		t.Parallel()
		for _, f := range []string{"*", "!", "!!", "!*", "!$6$x$y"} {
			h, _ := accountHost(t)
			h.setFor("usepam yes\n")
			h.setShadow(f)
			got := fullCheck(h, false)
			mustReason(t, got, "")
			if want := map[bool]string{true: pwStar, false: pwLocked}[f == "*"]; got.Shadow != want {
				t.Fatalf("field %q: class %q, want %q", f, got.Shadow, want)
			}
		}
	})
	t.Run("shadow_unreadable_note", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setShadow("$6$salt$abcdef")
		got := fullCheck(h, false, func(e *engine) { e.cfg.openShadow = openErr(syscall.EACCES) })
		mustReason(t, got, "")
		if got.Shadow != pwUnreadable || !slices.Equal(got.Notes, []string{noteShadowUnreadable}) {
			t.Fatalf("class %q, notes %v", got.Shadow, got.Notes)
		}
	})
	t.Run("shadow_symlink_is_unreadable_note", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writeRootFile("etc/real-shadow", []byte(probeAcct+":$6$salt$abcdef:20000::::::\n"), 0o640)
		if err := os.Symlink("real-shadow", filepath.Join(h.l.Root, "etc", "shadow")); err != nil {
			t.Fatal(err)
		}
		got := fullCheck(h, false)
		mustReason(t, got, "")
		if got.Shadow != pwUnreadable || !slices.Contains(got.Notes, noteShadowUnreadable) {
			t.Fatalf("a symlinked shadow: class %q, notes %v", got.Shadow, got.Notes)
		}
	})
	t.Run("shadow_oversize_fails_closed", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writeRootFile("etc/shadow", []byte(probeAcct+":*:20000::::::\n"+strings.Repeat("#", maxShadow)+"\n"), 0o640)
		mustReason(t, fullCheck(h, false), accountUnparsable)
	})
	t.Run("shadow_fifo_fails_closed", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		p := filepath.Join(h.l.Root, "etc", "shadow")
		if err := syscall.Mkfifo(p, 0o640); err != nil {
			t.Fatal(err)
		}
		// A blocked open of the read end (a check without O_NONBLOCK) ends
		// once a writer opens; with no reader left the open fails (ENXIO).
		t.Cleanup(func() {
			if fd, err := syscall.Open(p, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = syscall.Close(fd)
			}
		})
		e := h.engine()
		dump := ParseDump([]byte(h.run.dump()))
		done := make(chan accountResult, 1)
		go func() { done <- e.checkProbeAccountFull(context.Background(), probeAcct, dump, false) }()
		select {
		case got := <-done:
			mustReason(t, got, accountUnparsable)
		case <-time.After(5 * time.Second):
			t.Fatalf("the check blocked on a FIFO at %s", p)
		}
	})
	t.Run("shadow_malformed_line_fails_closed", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writeRootFile("etc/shadow", []byte("root:*:1::::::\n"+probeAcct+"\n"), 0o640)
		mustReason(t, fullCheck(h, false), accountUnparsable)
	})
	t.Run("shadow_duplicate_worst_wins", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setShadow("*", "$6$salt$abcdef")
		mustReason(t, fullCheck(h, false), passwordSet)
	})
	t.Run("shadow_absent_x_is_no_password", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("permitemptypasswords yes\n")
		got := fullCheck(h, false)
		mustReason(t, got, "")
		if got.Shadow != pwAbsent || len(got.Notes) != 0 {
			t.Fatalf("no shadow file: class %q, notes %v", got.Shadow, got.Notes)
		}
	})
	t.Run("shadow_other_open_error_fails_closed", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		mustReason(t, fullCheck(h, false, func(e *engine) { e.cfg.openShadow = openErr(syscall.EIO) }), accountUnparsable)
		got := fullCheck(h, false, func(e *engine) { e.cfg.openShadow = openErr(syscall.ENOTDIR) })
		mustReason(t, got, "")
		if got.Shadow != pwAbsent {
			t.Fatalf("ENOTDIR: class %q, want absent", got.Shadow)
		}
	})
	t.Run("passwd_star_with_shadow_hash_holds", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writePasswd(probeLine("*", "/usr/sbin/nologin") + "\n")
		h.setShadow("$6$salt$abcdef")
		mustReason(t, fullCheck(h, false), passwordSet)
	})
	t.Run("passwd_hash_with_shadow_star_holds", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writePasswd(probeLine("$6$salt$abcdef", "/usr/sbin/nologin") + "\n")
		h.setShadow("*")
		mustReason(t, fullCheck(h, false), passwordSet)
	})
	t.Run("no_loopback_target_holds_sshd_override", func(t *testing.T) {
		t.Parallel()
		h, log := accountHost(t)
		e := h.engine()
		mustReason(t, e.checkProbeAccountFull(context.Background(), probeAcct, Dump{}, false), sshdOverride)
		if !strings.Contains(log.String(), "no loopback target") {
			t.Fatalf("the error is not logged: %q", log.String())
		}
	})
	t.Run("passwd_field2_hash_holds", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writePasswd(probeLine("$6$salt$abcdef", "/usr/sbin/nologin") + "\n")
		mustReason(t, fullCheck(h, false), passwordSet)
	})
	t.Run("passwd_field2_empty_holds", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writePasswd(probeLine("", "/usr/sbin/nologin") + "\n")
		mustReason(t, fullCheck(h, false), passwordEmpty)
	})
	t.Run("passwd_field2_x_defers_to_shadow", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setShadow("$6$salt$abcdef")
		mustReason(t, fullCheck(h, false), passwordSet)
		h.setShadow("*")
		mustReason(t, fullCheck(h, false), "")
	})
	t.Run("passwd_field2_star_still_reads_shadow", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writePasswd(probeLine("*", "/usr/sbin/nologin") + "\n")
		h.setShadow("")
		mustReason(t, fullCheck(h, false), passwordEmpty)
	})
	t.Run("permitemptypasswords_yes_with_unreadable_shadow", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("permitemptypasswords yes\n")
		mustReason(t, fullCheck(h, false, func(e *engine) { e.cfg.openShadow = openErr(syscall.EACCES) }), sshdOverride)
		h.setFor("permitemptypasswords no\n")
		mustReason(t, fullCheck(h, false, func(e *engine) { e.cfg.openShadow = openErr(syscall.EACCES) }), "")
	})
	t.Run("permitemptypasswords_yes_with_readable_star_ok", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("permitemptypasswords yes\n")
		h.setShadow("*")
		mustReason(t, fullCheck(h, false), "")
	})
	t.Run("sshd_override_pubkey_no", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("pubkeyauthentication no\n")
		mustReason(t, fullCheck(h, false), sshdOverride)
		h.setFor("pubkeyauthentication yes\n")
		mustReason(t, fullCheck(h, false), "")
	})
	t.Run("sshd_override_authenticationmethods", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		for _, c := range []struct{ value, reason string }{
			{"password", sshdOverride},
			{"keyboard-interactive:pam,publickey", sshdOverride},
			{"publickey,password", ""},
			{"password publickey:x", ""},
			{"any", ""},
			{"publickey", ""},
			{"", ""},
		} {
			lines := ""
			if c.value != "" {
				lines = "authenticationmethods " + c.value + "\n"
			}
			h.setFor(lines)
			if got := fullCheck(h, false); got.Reason != c.reason {
				t.Fatalf("authenticationmethods %q: reason %q, want %q", c.value, got.Reason, c.reason)
			}
		}
	})
	t.Run("sshd_override_trust_trio", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.installed("role:a")
		mustReason(t, fullCheck(h, true), "")
		h.run.match = map[string]map[string]string{probeAcct: {"authorizedprincipalsfile": "/etc/ssh/other/%u"}}
		mustReason(t, fullCheck(h, true), sshdOverride)
	})
	t.Run("sshd_override_principals_command", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.installed("role:a")
		h.run.match = map[string]map[string]string{probeAcct: {principalsCommand: "/usr/local/bin/principals"}}
		mustReason(t, fullCheck(h, true), sshdOverride)
	})
	t.Run("usepam_no_with_bang", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("usepam no\n")
		h.setShadow("!")
		mustReason(t, fullCheck(h, false), sshdOverride)
	})
	t.Run("usepam_yes_with_bang_ok", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("usepam yes\n")
		h.setShadow("!")
		mustReason(t, fullCheck(h, false), "")
	})
	t.Run("usepam_no_with_star_ok", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("usepam no\n")
		h.setShadow("*")
		mustReason(t, fullCheck(h, false), "")
	})
	t.Run("usepam_absent_is_no_pam", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setShadow("!")
		mustReason(t, fullCheck(h, false), sshdOverride)
	})
	t.Run("sshd_failure_holds_override", func(t *testing.T) {
		t.Parallel()
		h, log := accountHost(t)
		mustReason(t, fullCheck(h, false, func(e *engine) { e.cfg.SSHD = filepath.Join(h.l.Root, "no-sshd") }), sshdOverride)
		if !strings.Contains(log.String(), sshdOverride) {
			t.Fatalf("the sshd failure is not logged: %q", log.String())
		}
	})
	t.Run("excluded_by_allowusers", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("allowusers deploy\n")
		mustReason(t, fullCheck(h, false), accountExcluded)
		h.setFor("allowusers deploy\nallowusers " + probeAcct + "\n")
		mustReason(t, fullCheck(h, false), "")
	})
	t.Run("excluded_by_denyusers", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("denyusers keyroster-*\n")
		mustReason(t, fullCheck(h, false), accountExcluded)
	})
	t.Run("excluded_by_allowgroups", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writeRootFile("etc/group", []byte("wheel:x:10:root\nkeyroster-probe:x:990:\n"), 0o644)
		h.setFor("allowgroups wheel\n")
		mustReason(t, fullCheck(h, false), accountExcluded)
		h.setFor("allowgroups wheel\nallowgroups keyroster-probe\n")
		mustReason(t, fullCheck(h, false), "")
	})
	t.Run("excluded_user_at_host_does_not_hold", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.setFor("denyusers " + probeAcct + "@remote.example\n")
		mustReason(t, fullCheck(h, false), "")
		h.setFor("allowusers " + probeAcct + "@remote.example\n")
		mustReason(t, fullCheck(h, false), "")
	})
	t.Run("spec_uses_probe_source", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		mustReason(t, fullCheck(h, false), "")
		if n := h.run.dumps[probeSpecKey(h, "127.0.0.2", "127.0.0.1")]; n != 1 {
			t.Fatalf("sshd -T -C runs %v, want one for the probe source 127.0.0.2", h.run.dumps)
		}
		h.run.listen = []string{"127.0.0.2:" + portOf(h)}
		mustReason(t, fullCheck(h, false), "")
		if n := h.run.dumps[probeSpecKey(h, "127.0.0.3", "127.0.0.2")]; n != 1 {
			t.Fatalf("sshd -T -C runs %v, want one from 127.0.0.3 to 127.0.0.2", h.run.dumps)
		}
	})
	t.Run("spec_uses_probe_source_ipv6_off", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		// The IPv4 wildcard is built, not written, so that no added line
		// names an address outside loopback (Task 4's scrub gate).
		h.run.listen = []string{"[::]:" + portOf(h), netip.IPv4Unspecified().String() + ":" + portOf(h)}
		mustReason(t, fullCheck(h, false, func(e *engine) { e.ipv6Off = func() bool { return true } }), "")
		if n := h.run.dumps[probeSpecKey(h, "127.0.0.2", "127.0.0.1")]; n != 1 {
			t.Fatalf("sshd -T -C runs %v, want one from 127.0.0.2 to 127.0.0.1 while IPv6 is off", h.run.dumps)
		}
	})
	t.Run("trust_trio_not_compared_before_install", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		// No drop-in: sshd -T -C reports the packaged trust values.
		mustReason(t, fullCheck(h, false), "")
		mustReason(t, fullCheck(h, true), sshdOverride)
	})
	t.Run("order_passwd_then_shadow_then_sshd", func(t *testing.T) {
		t.Parallel()
		h, _ := accountHost(t)
		h.writeRootFile("bin/sh", []byte("#!/bin/false\n"), 0o755)
		h.writePasswd(probeLine("x", "/bin/sh") + "\n")
		h.setShadow("$6$salt$abcdef")
		h.setFor("pubkeyauthentication no\n")
		key := probeSpecKey(h, ProbeSource, "127.0.0.1")
		mustReason(t, fullCheck(h, false), shellNotNologin)
		h.writePasswd(probeLogin + "\n")
		mustReason(t, fullCheck(h, false), passwordSet)
		if n := h.run.dumps[key]; n != 0 {
			t.Fatalf("sshd -T -C ran %d times before the shadow stage passed", n)
		}
		h.setShadow("*")
		mustReason(t, fullCheck(h, false), sshdOverride)
		if n := h.run.dumps[key]; n != 1 {
			t.Fatalf("sshd -T -C ran %d times, want 1", n)
		}
	})
	t.Run("key_input_has_class_not_hash", func(t *testing.T) {
		t.Parallel()
		const marker = "$6$Zq9MarkerSalt$Zq9MarkerHashValue"
		h, _ := accountHost(t)
		h.setShadow(marker)
		in := h.engine().accountKeyInput(probeAcct)
		if strings.Contains(in, "Zq9Marker") || in != probeLogin+"\x00"+pwHash {
			t.Fatalf("key input %q (hash in shadow)", in)
		}
		h.writePasswd(probeLine(marker, "/usr/sbin/nologin") + "\n")
		h.setShadow("*")
		in = h.engine().accountKeyInput(probeAcct)
		if strings.Contains(in, "Zq9Marker") || in != probeLine(pwHash, "/usr/sbin/nologin")+"\x00"+pwHash {
			t.Fatalf("key input %q (hash in passwd field 2)", in)
		}
		h.setShadow("*", "!")
		h.writePasswd(probeLogin + "\n")
		if in := h.engine().accountKeyInput(probeAcct); in != probeLogin+"\x00"+pwLocked {
			t.Fatalf("key input %q, want the locked class", in)
		}
	})
}

// FuzzParseShadowLine (03-10c, T-03-385): never panics, returns one of the
// five classes, deterministically, malformed exactly for a line without a
// second field, and the class of field 2 derived independently.
func FuzzParseShadowLine(f *testing.F) {
	for _, s := range []string{"", "x", "a:", "a::", "a:*:1", "a:!:1", "a:!!", "a:!*", "a:!$6$x$y", "a:$6$s$h:1:2", "a:*LK*", ":", "::::", "a:\x00:b"} {
		f.Add(s)
	}
	want := map[string]bool{pwEmpty: true, pwStar: true, pwLocked: true, pwHash: true, pwMalformed: true}
	f.Fuzz(func(t *testing.T, line string) {
		got := ParseShadowLine(line)
		if !want[got] {
			t.Fatalf("%q: class %q", line, got)
		}
		if again := ParseShadowLine(line); again != got {
			t.Fatalf("%q: %q then %q", line, got, again)
		}
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			if got != pwMalformed {
				t.Fatalf("%q: one field, class %q", line, got)
			}
			return
		}
		var ind string
		switch {
		case fields[1] == "":
			ind = pwEmpty
		case fields[1] == "*":
			ind = pwStar
		case fields[1][0] == '!':
			ind = pwLocked
		default:
			ind = pwHash
		}
		if got != ind {
			t.Fatalf("%q: class %q, field 2 says %q", line, got, ind)
		}
	})
}

// TestProbeHoldReasonsDocumented (03-10c): every closed hold reason of the
// gate is written as probe_held:<reason> in the host setup runbook, so a
// reason added here cannot ship without its meaning and fix.
func TestProbeHoldReasonsDocumented(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "runbooks", "host-setup.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range probeHoldReasons {
		if !strings.Contains(string(b), "`probe_held:"+r+"`") {
			t.Errorf("docs/runbooks/host-setup.md does not document probe_held:%s", r)
		}
	}
}
