//go:build !windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
)

// TestAgentLifetime adds a key and its certificate with a 2 s lifetime to a
// real OpenSSH ssh-agent through dialAgent, and checks that both are listed
// and then gone after 3 s. It skips when ssh-agent is not on PATH, unless
// KEYROSTER_REQUIRE_SSH_AGENT=1 (set in CI), where that is a failure.
func TestAgentLifetime(t *testing.T) {
	sshAgent, err := exec.LookPath("ssh-agent")
	if err != nil {
		if os.Getenv("KEYROSTER_REQUIRE_SSH_AGENT") == "1" {
			t.Fatalf("ssh-agent not found and KEYROSTER_REQUIRE_SSH_AGENT=1: %v", err)
		}
		t.Skipf("ssh-agent not found (set KEYROSTER_REQUIRE_SSH_AGENT=1 to fail instead): %v", err)
	}

	// A short directory: Unix socket paths are limited to about 104 bytes
	// on macOS, and t.TempDir() names can come close.
	dir, err := os.MkdirTemp("", "kr-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")

	// 1. A foreground ssh-agent on its own socket.
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

	// 2. Key plus certificate with a 2 s lifetime, through dialAgent.
	t.Setenv("SSH_AUTH_SOCK", sock)
	conn, err := dialAgent()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	client := agent.NewClient(conn)
	priv, c := lifetimeTestCert(t)
	if err := client.Add(agent.AddedKey{PrivateKey: priv, LifetimeSecs: 2}); err != nil {
		t.Fatalf("add key with lifetime: %v", err)
	}
	if err := client.Add(agent.AddedKey{PrivateKey: priv, Certificate: c, LifetimeSecs: 2}); err != nil {
		t.Fatalf("add certificate with lifetime: %v", err)
	}

	// 3. Two entries, one a certificate; none after 3 s.
	keys, err := client.List()
	if err != nil {
		t.Fatal(err)
	}
	certs := 0
	for _, k := range keys {
		if k.Type() == ssh.CertAlgoED25519v01 {
			certs++
		}
	}
	if len(keys) != 2 || certs != 1 {
		t.Fatalf("after add: %d entries (%d certificates), want 2 (1 certificate)", len(keys), certs)
	}
	time.Sleep(3 * time.Second)
	keys, err = client.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("after 3 s: %d entries, want 0 (lifetime 2 s)", len(keys))
	}
}

// lifetimeTestCert returns a fresh Ed25519 key and a user certificate for
// it from a throwaway CA, issued through internal/cert.Build.
func lifetimeTestCert(t *testing.T) (ed25519.PrivateKey, *ssh.Certificate) {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cert.Build(cert.Request{
		Profile:    cert.DefaultUserProfile(),
		Subject:    subject,
		Principals: []string{"alice"},
		Now:        time.Now(),
		ValidFor:   10 * time.Minute,
		KeyID:      cert.KeyID{CA: "user", Subject: "u:alice", Request: "0123456789abcdef0123456789abcdef", Serial: 1},
		Serial:     1,
	}, ca, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, c
}
