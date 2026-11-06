//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/directory"
)

// useHome makes the writer compute ~/.ssh itself (defaultSSHDir, QB-5)
// with $HOME set to home and the account database answering acct.
func useHome(t *testing.T, home string, acct func() (string, error)) {
	t.Helper()
	prevDir, prevAcct := userSSHDir, accountHome
	userSSHDir, accountHome = defaultSSHDir, acct
	t.Cleanup(func() { userSSHDir, accountHome = prevDir, prevAcct })
	t.Setenv("HOME", home)
}

// TestKnownHostsUnix (03-09b, T-03-241, QB-5): file modes, symlinks, no
// leftovers, and the account-home check.
func TestKnownHostsUnix(t *testing.T) {
	web1 := func(t *testing.T, f *htFix) hostTrustInput {
		return f.in(t, f.dirDoc(t, 1, "", htHost(t, "web1", directory.StatusActive, "web1")), f.krlV(t, 1))
	}
	t.Run("managed_files_0644_ssh_dir_0700", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, web1(t, f), hostTrustFull)
		if fi, err := os.Stat(f.sshDir); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("~/.ssh: %v, %v; want 0700", fi.Mode(), err)
		}
		for _, n := range []string{hostTrustKRLFile, hostTrustKnownHosts, hostTrustSSHConfig} {
			if fi, err := os.Stat(filepath.Join(f.sshDir, n)); err != nil || fi.Mode().Perm() != 0o644 {
				t.Fatalf("%s: %v, %v; want 0644", n, fi.Mode(), err)
			}
		}
		if fi, err := os.Stat(f.statePath); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("state: %v, %v; want 0600", fi.Mode(), err)
		}
	})
	t.Run("existing_ssh_dir_mode_kept", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		if err := os.Mkdir(f.sshDir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(f.sshDir, 0o750); err != nil { //nolint:gosec // G302: the test's own mode
			t.Fatal(err)
		}
		mustRun(t, web1(t, f), hostTrustFull)
		if fi, err := os.Stat(f.sshDir); err != nil || fi.Mode().Perm() != 0o750 {
			t.Fatalf("~/.ssh: %v, %v; want its 0750 kept", fi.Mode(), err)
		}
	})
	t.Run("symlink_at_managed_name_replaced_not_followed", func(t *testing.T) {
		// A first run leaves the state (since 03-09b Task 4 a managed name
		// without a state refuses every write), then the managed name is
		// made a symlink.
		f := newHTFix(t, 1, 1)
		mustRun(t, web1(t, f), hostTrustFull)
		target := filepath.Join(t.TempDir(), "target")
		writeTestFile(t, target, []byte("the target's bytes\n"))
		link := filepath.Join(f.sshDir, hostTrustKnownHosts)
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		mustRun(t, f.in(t, f.dirDoc(t, 2, "", htHost(t, "web2", directory.StatusActive, "web2")), f.krlV(t, 2)), hostTrustFull)
		if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("%s is not a regular file after the run: %v", link, err)
		}
		if got := string(readTestFile(t, target)); got != "the target's bytes\n" {
			t.Fatalf("the symlink's target was written: %q", got)
		}
	})
	t.Run("no_backup_or_temp_files_left", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, web1(t, f), hostTrustFull)
		mustRun(t, f.in(t, f.dirDoc(t, 2, "", htHost(t, "web2", directory.StatusActive, "web2")), f.krlV(t, 2)), hostTrustFull)
		for dir, want := range map[string]int{f.sshDir: 3, filepath.Dir(f.statePath): 1} {
			ents, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(ents) != want {
				var names []string
				for _, e := range ents {
					names = append(names, e.Name())
				}
				t.Fatalf("%s holds %q, want %d files", dir, names, want)
			}
		}
	})
	t.Run("home_differs_from_account_refuses", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		home, acct := t.TempDir(), t.TempDir()
		useHome(t, home, func() (string, error) { return acct, nil })
		res, stdout, _ := htWrite(web1(t, f))
		want := "Host trust not refreshed: $HOME (" + home + ") is not your account home (" + acct + "), which ssh reads.\n"
		if res != hostTrustNone || stdout != want {
			t.Fatalf("result %d, stdout %q, want %q", res, stdout, want)
		}
		if _, err := os.Lstat(filepath.Join(home, ".ssh")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("~/.ssh under $HOME was created: %v", err)
		}
		if _, err := os.Lstat(f.statePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the state was written: %v", err)
		}
	})
	t.Run("home_lookup_failure_warns_and_continues", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		home := t.TempDir()
		useHome(t, home, func() (string, error) { return "", errors.New("user: unknown userid 4242") })
		res, _, stderr := htWrite(web1(t, f))
		if res != hostTrustFull || !strings.Contains(stderr, "the account database names no home for this user") {
			t.Fatalf("result %d, stderr %q", res, stderr)
		}
		if _, err := os.Stat(filepath.Join(home, ".ssh", hostTrustSSHConfig)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("state_symlink_refuses", func(t *testing.T) {
		f := newHTFix(t, 1, 1)
		mustRun(t, web1(t, f), hostTrustFull)
		copied := filepath.Join(t.TempDir(), "state.json")
		writeTestFile(t, copied, readTestFile(t, f.statePath))
		if err := os.Remove(f.statePath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(copied, f.statePath); err != nil {
			t.Fatal(err)
		}
		before := f.files(t)
		stdout, _ := mustRun(t, f.in(t, f.dirDoc(t, 2, "", htHost(t, "web2", directory.StatusActive, "web2")), f.krlV(t, 2)), hostTrustNone)
		htStartOver(t, f, stdout)
		if !mapsEqual(before, f.files(t)) {
			t.Fatal("a run with a symlinked state wrote a file")
		}
	})
	t.Run("state_unreadable_refuses", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a 0000 file")
		}
		f := newHTFix(t, 1, 1)
		mustRun(t, web1(t, f), hostTrustFull)
		if err := os.Chmod(f.statePath, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(f.statePath, 0o600) })
		stdout, _ := mustRun(t, f.in(t, f.dirDoc(t, 2, "", htHost(t, "web2", directory.StatusActive, "web2")), f.krlV(t, 2)), hostTrustNone)
		htStartOver(t, f, stdout)
	})
	t.Run("home_symlink_or_trailing_slash_accepted", func(t *testing.T) {
		for _, kind := range []string{"trailing_slash", "symlink"} {
			acct := t.TempDir()
			home := acct + "/"
			if kind == "symlink" {
				home = filepath.Join(t.TempDir(), "home-link")
				if err := os.Symlink(acct, home); err != nil {
					t.Fatal(err)
				}
			}
			f := newHTFix(t, 1, 1)
			useHome(t, home, func() (string, error) { return acct, nil })
			if res, stdout, _ := htWrite(web1(t, f)); res != hostTrustFull {
				t.Fatalf("$HOME %s, account home %s: result %d, stdout %q", home, acct, res, stdout)
			}
		}
	})
}
