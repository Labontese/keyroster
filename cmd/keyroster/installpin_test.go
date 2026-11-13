package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// trustDocInstallation returns the installation ID of the bundle in an
// /api/v1/trust document, "" for none (03-14c, F06).
func trustDocInstallation(t *testing.T, doc []byte) string {
	t.Helper()
	var tr serverclient.TrustResponse
	if err := json.Unmarshal(doc, &tr); err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(tr.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	return b.InstallationID
}

// freshKeyLike returns a new public key, in trust.FormatKey form, of the
// algorithm alg names.
func freshKeyLike(t *testing.T, alg string) string {
	t.Helper()
	var pub any
	if strings.HasPrefix(alg, "ecdsa-") {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = &k.PublicKey
	} else {
		k, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub = k
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(sp)
}

// serveOtherInstallation serves F06's shape: e's bundle re-signed by e's
// own root for another installation, with another ops key and other CA
// keys, while the saved config keeps its pin. It returns the pinned and
// the served installation IDs.
func serveOtherInstallation(t *testing.T, e *dirEnv) (pinned, served string) {
	t.Helper()
	other, err := trust.NewInstallationID()
	if err != nil {
		t.Fatal(err)
	}
	pinned = e.cfg.InstallationID
	if pinned == "" || pinned == other {
		t.Fatalf("the fixture pins %q", pinned)
	}
	e.serveResigned(t, func(b *trust.Bundle) {
		b.InstallationID = other
		b.OpsKey.Key = freshKeyLike(t, b.OpsKey.Alg)
		cas := make([]trust.CAEntry, len(b.CAs))
		copy(cas, b.CAs)
		for i := range cas {
			cas[i].Key = freshKeyLike(t, cas[i].Alg)
		}
		b.CAs = cas
	})
	return pinned, other
}

// pinRefusal is the part of Trust's refusal that names both IDs.
func pinRefusal(pinned, served string) string {
	return "names installation " + served + ", but your config pins installation " + pinned
}

// signCounter is an ssh-agent that counts every sign request, an admin
// API request's included.
type signCounter struct {
	agent.ExtendedAgent
	mu sync.Mutex
	n  int
}

func (c *signCounter) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.ExtendedAgent.Sign(key, data)
}

func (c *signCounter) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (c *signCounter) signs() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// countSigns routes the CLI's ssh-agent connection through a signCounter
// in front of e's keyring.
func countSigns(t *testing.T, e *dirEnv) *signCounter {
	t.Helper()
	c := &signCounter{ExtendedAgent: e.agent}
	prev := dialAgent
	dialAgent = func() (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_ = agent.ServeAgent(c, server)
			_ = server.Close()
		}()
		return client, nil
	}
	t.Cleanup(func() { dialAgent = prev })
	return c
}

// adminPosts returns the admin POSTs the stub received.
func (e *dirEnv) adminPosts() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.calls...)
}

// TestInstallationPinned (03-14c, F06): a CLI pinned at init to one
// installation refuses a server that serves another installation's bundle
// under the same roots, before any admin signature, state-changing request
// or file write; an unpinned config under a bundle with an ID, and a
// pinned one under an ID-less bundle, are refused too.
func TestInstallationPinned(t *testing.T) {
	t.Run("revoke_serial_refused_before_signing", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		pinned, served := serveOtherInstallation(t, e)
		signs := countSigns(t, e)
		reached := false
		e.mu.Lock()
		e.override["POST "+serverclient.AdminRevokePath] = func(http.ResponseWriter) { reached = true }
		e.mu.Unlock()
		code, _, stderr := run(t, "revoke", "serial", "1729", "--admin-key", e.fps[0])
		e.mu.Lock()
		gotReached, body := reached, e.revokeBody
		e.mu.Unlock()
		if code == 0 || !strings.Contains(stderr, pinRefusal(pinned, served)) || signs.signs() != 0 || gotReached || body != nil {
			t.Fatalf("exit %d, %d signatures, revoke route reached %v: %s; want a pin refusal before any signature", code, signs.signs(), gotReached, stderr)
		}
	})
	t.Run("join_token_refused", func(t *testing.T) {
		e := popHostsEnv(t)
		pinned, served := serveOtherInstallation(t, e)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminJoinTokensPath, &called,
			`{"expected_name":"web1","token":"`+strings.Repeat("A", 43)+`","expires_at":"2026-10-28T12:30:00Z","agent_port":8443}`, http.StatusCreated)
		out := filepath.Join(t.TempDir(), "join.txt")
		code, _, stderr := run(t, "host", "join-token", "web1", "--out", out)
		if code == 0 || !strings.Contains(stderr, pinRefusal(pinned, served)) || fileExists(out) || e.wasCalled(&called) || len(e.adminPosts()) != 0 {
			t.Fatalf("exit %d, file %v, posts %q: %s; want a pin refusal, no file and no post", code, fileExists(out), e.adminPosts(), stderr)
		}
	})
	t.Run("directory_command_refused", func(t *testing.T) {
		e := roleEnv(t, nil)
		pinned, served := serveOtherInstallation(t, e)
		code, stdout, stderr := run(t, "directory", "show")
		if code == 0 || stdout != "" || !strings.Contains(stderr, pinRefusal(pinned, served)) {
			t.Fatalf("exit %d, stdout %q, stderr %q; want the pin refusal", code, stdout, stderr)
		}
	})
	t.Run("old_config_refused", func(t *testing.T) {
		e := roleEnv(t, nil)
		e.cfg.InstallationID = ""
		if _, err := saveConfig(e.cfg, true); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := run(t, "directory", "show")
		if code == 0 || !strings.Contains(stderr, serverclient.ErrInstallationNotPinned.Error()) || !strings.Contains(stderr, "names installation "+e.bundle.InstallationID) {
			t.Fatalf("exit %d, stderr %q; want ErrInstallationNotPinned naming the served ID", code, stderr)
		}
	})
	t.Run("rollback_to_id_less_refused", func(t *testing.T) {
		e := roleEnv(t, nil)
		pinned := e.cfg.InstallationID
		e.serveResigned(t, func(b *trust.Bundle) { b.InstallationID = "" })
		code, _, stderr := run(t, "directory", "show")
		if code == 0 || !strings.Contains(stderr, "names no installation ID, but your config pins "+pinned) {
			t.Fatalf("exit %d, stderr %q; want the ID-less refusal", code, stderr)
		}
	})
	t.Run("rebind_needs_reinit", func(t *testing.T) {
		// The rebind transition: a bundle that names an ID, a directory
		// that names none, and a config saved before the pin.
		e := roleEnv(t, nil)
		e.cfg.InstallationID = ""
		if _, err := saveConfig(e.cfg, true); err != nil {
			t.Fatal(err)
		}
		check := unchanged(t, e)
		code, _, stderr := run(t, "directory", "rebind", "--yes")
		if code == 0 || !strings.Contains(stderr, serverclient.ErrInstallationNotPinned.Error()) {
			t.Fatalf("rebind under an unpinned config: exit %d, stderr %q; want ErrInstallationNotPinned", code, stderr)
		}
		check()
		// The config as keyroster init --force saves it under this bundle.
		e.cfg.InstallationID = e.bundle.InstallationID
		if _, err := saveConfig(e.cfg, true); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := run(t, "directory", "rebind", "--yes")
		if code != 0 || !strings.Contains(stdout, "+ installation_id "+e.bundle.InstallationID) {
			t.Fatalf("rebind after the re-init: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		if d := installedDir(t, e); d.InstallationID != e.bundle.InstallationID {
			t.Fatalf("installed directory names %q, want %s", d.InstallationID, e.bundle.InstallationID)
		}
	})
	t.Run("admin_error_names_installation", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.mu.Lock()
		e.override["GET "+serverclient.AdminPendingPath("alice")] = func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"admin authentication failed"}`)
		}
		e.mu.Unlock()
		pinned, served := serveOtherInstallation(t, e)
		code, _, stderr := run(t, "user", "approve", "alice")
		if code == 0 || !strings.Contains(stderr, serverclient.ErrInstallationMismatch.Error()) || !strings.Contains(stderr, pinRefusal(pinned, served)) {
			t.Fatalf("exit %d, stderr %q; want the installation mismatch named, not only the admin-auth error", code, stderr)
		}
	})
	t.Run("known_hosts_sync_refused", func(t *testing.T) {
		e, _ := hostEnv(t)
		doc := e.krlDoc(t, 1, 1, e.bundle.InstallationID, e.ops)
		e.mu.Lock()
		e.override["GET "+serverclient.KRLPath] = func(w http.ResponseWriter) { _, _ = w.Write(doc) }
		e.mu.Unlock()
		pinned, served := serveOtherInstallation(t, e)
		sshDir := useSSHDir(t)
		cfgPath, err := configPath()
		if err != nil {
			t.Fatal(err)
		}
		code, _, stderr := run(t, "known-hosts", "sync")
		if code == 0 || !strings.Contains(stderr, pinRefusal(pinned, served)) {
			t.Fatalf("exit %d, stderr %q; want the pin refusal", code, stderr)
		}
		if entries, err := os.ReadDir(sshDir); err == nil && len(entries) != 0 {
			t.Fatalf("known-hosts sync wrote %d files under ~/.ssh", len(entries))
		}
		if fileExists(filepath.Join(filepath.Dir(cfgPath), hostTrustStateFile)) {
			t.Fatal("known-hosts sync wrote host-trust.json")
		}
	})
	t.Run("machine_renew_refused", func(t *testing.T) {
		e := newRenewEnv(t)
		renewAnswer(t, e, renewOpts{})
		pinned, served := serveOtherInstallation(t, e)
		key, _ := machineKeyFile(t)
		out := filepath.Join(t.TempDir(), "ci-cert.pub")
		code, _, stderr := run(t, "machine", "renew", "ci", "--key", key, "--out", out)
		if code != 1 || !strings.Contains(stderr, pinRefusal(pinned, served)) || e.renewCount() != 0 || fileExists(out) {
			t.Fatalf("exit %d, %d sent, certificate written %v: %s; want 1, the pin refusal, nothing sent or written", code, e.renewCount(), fileExists(out), stderr)
		}
	})
	t.Run("own_installation_ok", func(t *testing.T) {
		roleEnv(t, nil)
		if code, stdout, stderr := run(t, "directory", "show"); code != 0 || stdout == "" {
			t.Fatalf("directory show under the pinned installation: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})
}
