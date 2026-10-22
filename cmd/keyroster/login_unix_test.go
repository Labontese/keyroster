//go:build !windows

package main

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

// startLoginTestAgent starts a real OpenSSH ssh-agent on its own socket
// and points SSH_AUTH_SOCK at it, so keyroster login's default
// connectLoginAgent runs unchanged. It returns a function that lists the
// agent. Like 02-02's TestAgentLifetime (whose lookup this copies), it
// skips when ssh-agent is not on PATH, unless KEYROSTER_REQUIRE_SSH_AGENT=1
// (set in CI's build-test and cli-macos jobs), where that is a failure.
func startLoginTestAgent(t *testing.T) func(t *testing.T) []*agent.Key {
	t.Helper()
	sshAgent, err := exec.LookPath("ssh-agent")
	if err != nil {
		if os.Getenv("KEYROSTER_REQUIRE_SSH_AGENT") == "1" {
			t.Fatalf("ssh-agent not found and KEYROSTER_REQUIRE_SSH_AGENT=1: %v", err)
		}
		t.Skipf("ssh-agent not found (set KEYROSTER_REQUIRE_SSH_AGENT=1 to fail instead): %v", err)
	}
	// A short directory: Unix socket paths are limited to about 104 bytes
	// on macOS.
	dir, err := os.MkdirTemp("", "kr-login-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	cmd := exec.Command(sshAgent, "-D", "-a", sock) //nolint:gosec // G204: the ssh-agent under test, found on PATH
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	for deadline := time.Now().Add(5 * time.Second); ; {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ssh-agent did not create %s within 5 s", sock)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Setenv("SSH_AUTH_SOCK", sock)
	return func(t *testing.T) []*agent.Key {
		t.Helper()
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		keys, err := agent.NewClient(conn).List()
		if err != nil {
			t.Fatal(err)
		}
		return keys
	}
}

// TestLoginAgentUnix: the Unix default of connectLoginAgent refuses to run
// without SSH_AUTH_SOCK and says how to start an agent.
func TestLoginAgentUnix(t *testing.T) {
	t.Run("ssh_auth_sock_unset_refused", func(t *testing.T) {
		e := newLoginServer(t)
		dirs := useEmptyHomes(t)
		t.Setenv("SSH_AUTH_SOCK", "")
		stderr, wait := e.start(t)
		e.drive(t, stderr)
		r := wait()
		requireLoginRefused(t, r, "start ssh-agent (eval $(ssh-agent)) and retry; keyroster never writes the key to a file")
		if strings.Contains(r.stdout, "Serial:") {
			t.Fatalf("a refused login printed a serial:\n%s", r.stdout)
		}
		requireNoFiles(t, dirs)
	})
}
