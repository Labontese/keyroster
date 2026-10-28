//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestUnits (03-08, D-05): install writes the two systemd units on a
// systemd host and the two OpenRC scripts on an OpenRC host, refuses with
// neither before writing anything, and creates /etc/ssh/keyroster
// (root:root 0755 here the test's uid) before the units, since systemd
// refuses a unit whose ReadWritePaths path does not exist.
func TestUnits(t *testing.T) {
	who := currentUserName(t)
	install := func(t *testing.T, root, state string, extra ...string) (int, string, string) {
		t.Helper()
		jf, _ := joinFile(t)
		return runCmd(t, append([]string{"install", "--root", root, "--state-dir", state, "--join-file", jf, "--fetch-user", who}, extra...)...)
	}
	mode := func(t *testing.T, p string) uint32 {
		t.Helper()
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		return uint32(st.Mode) & 0o7777
	}
	t.Run("install_writes_systemd_units", func(t *testing.T) {
		root, state := installRoot(t)
		code, out, errOut := install(t, root, state)
		if code != 0 {
			t.Fatalf("install exited %d:\n%s%s", code, out, errOut)
		}
		for _, n := range []string{"keyroster-agent.service", "keyroster-agent-fetch.service"} {
			p := filepath.Join(root, "etc/systemd/system", n)
			b, err := os.ReadFile(p) //nolint:gosec // G304: the test's own file
			if err != nil || !strings.Contains(string(b), "ProtectSystem=strict") {
				t.Fatalf("%s: %v", p, err)
			}
			if m := mode(t, p); m != 0o644 {
				t.Errorf("%s: mode %04o, want 0644", p, m)
			}
		}
		// The units name the state directory as the host sees it: below
		// --root without the prefix, or as given when outside it.
		b, _ := os.ReadFile(filepath.Join(root, "etc/systemd/system/keyroster-agent.service")) //nolint:gosec // G304: the test's own file
		if !strings.Contains(string(b), "ReadWritePaths=/etc/ssh/keyroster /etc/ssh/sshd_config.d "+state+"\n") {
			t.Fatalf("the applier unit's ReadWritePaths:\n%s", b)
		}
		if _, err := os.Lstat(filepath.Join(root, "etc/init.d")); !errors.Is(err, os.ErrNotExist) {
			t.Error("install wrote OpenRC scripts on a systemd host")
		}
		if !strings.Contains(out, "systemctl daemon-reload && systemctl enable --now keyroster-agent keyroster-agent-fetch") {
			t.Errorf("install's next step:\n%s", out)
		}
	})
	t.Run("install_writes_openrc_scripts", func(t *testing.T) {
		root, state := installRootWith(t, "etc/init.d", "sbin")
		if err := os.WriteFile(filepath.Join(root, "sbin/openrc-run"), []byte("#!/bin/false\n"), 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if code, out, errOut := install(t, root, state); code != 0 {
			t.Fatalf("install exited %d:\n%s%s", code, out, errOut)
		}
		f, err := os.ReadFile(filepath.Join(root, "etc/init.d/keyroster-agent-fetch")) //nolint:gosec // G304: the test's own file
		if err != nil || !strings.Contains(string(f), "command_user=\"keyroster-agent\"\n") {
			t.Fatalf("the fetcher's script (%v):\n%s", err, f)
		}
		if m := mode(t, filepath.Join(root, "etc/init.d/keyroster-agent")); m != 0o755 {
			t.Errorf("the applier's script: mode %04o, want 0755", m)
		}
		if _, err := os.Lstat(filepath.Join(root, "etc/systemd")); !errors.Is(err, os.ErrNotExist) {
			t.Error("install wrote systemd units on an OpenRC host")
		}
	})
	t.Run("install_no_service_manager_refused", func(t *testing.T) {
		root, state := installRootWith(t)
		code, _, errOut := install(t, root, state)
		if code == 0 || !strings.Contains(errOut, "install_no_service_manager") {
			t.Fatalf("install on a host with neither: exit %d: %s", code, errOut)
		}
		if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("the state directory was created")
		}
		requireNoPath(t, filepath.Join(root, "etc/ssh/keyroster"), filepath.Join(root, "etc/keyroster-agent"))
	})
	t.Run("install_creates_readwrite_dirs", func(t *testing.T) {
		root, state := installRoot(t)
		if code, out, errOut := install(t, root, state); code != 0 {
			t.Fatalf("install exited %d:\n%s%s", code, out, errOut)
		}
		var st unix.Stat_t
		// Every ReadWritePaths path of both units.
		for _, p := range []string{filepath.Join(root, "etc/ssh/keyroster"), filepath.Join(root, "etc/ssh/sshd_config.d"), state, filepath.Join(state, "spool"),
			filepath.Join(root, "var/lib/keyroster-agent-fetch")} {
			if err := unix.Lstat(p, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
				t.Errorf("%s: not a directory (%v): a ReadWritePaths path systemd would refuse", p, err)
			}
		}
		if m := mode(t, filepath.Join(root, "etc/ssh/keyroster")); m != 0o755 {
			t.Errorf("/etc/ssh/keyroster: mode %04o, want 0755", m)
		}
		if err := unix.Lstat(filepath.Join(root, "etc/ssh/keyroster"), &st); err != nil || int(st.Uid) != os.Geteuid() {
			t.Errorf("/etc/ssh/keyroster: owner %d, want the installing uid %d", st.Uid, os.Geteuid())
		}
	})
	t.Run("no_sshd_config_d_refused", func(t *testing.T) {
		root, state := installRoot(t)
		if err := os.Remove(filepath.Join(root, "etc/ssh/sshd_config.d")); err != nil {
			t.Fatal(err)
		}
		code, _, errOut := install(t, root, state)
		if code == 0 || !strings.Contains(errOut, "install_no_sshd_config_d") {
			t.Fatalf("a systemd host without sshd_config.d: exit %d: %s", code, errOut)
		}
		requireNoPath(t, state, filepath.Join(root, "etc/ssh/keyroster"), filepath.Join(root, "etc/systemd/system/keyroster-agent.service"))
	})
	t.Run("relative_bin_dir_refused", func(t *testing.T) {
		root, state := installRoot(t)
		if code, _, errOut := install(t, root, state, "--bin-dir", "bin"); code == 0 || !strings.Contains(errOut, "install_bin_dir_not_absolute") {
			t.Fatalf("a relative --bin-dir: exit %d: %s", code, errOut)
		}
	})
}

// requireNoPath fails for every path that exists.
func requireNoPath(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s exists", p)
		}
	}
}
