//go:build linux

package agent_test

import (
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/keystore/agent"
)

// agentServer serves an agent on a Unix socket until stop, which closes
// the listener and every open connection, as an agent restart does.
type agentServer struct {
	l     net.Listener
	mu    sync.Mutex
	conns []net.Conn
	wg    sync.WaitGroup
}

// startAgentServer serves keyring on path. With hang set it accepts
// connections and reads requests but never answers, like a stuck agent or
// PKCS#11 helper.
func startAgentServer(t *testing.T, path string, keyring sshagent.Agent, hang bool) *agentServer {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	s := &agentServer{l: l}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				if hang {
					buf := make([]byte, 4096)
					for {
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
				}
				_ = sshagent.ServeAgent(keyring, c)
			}()
		}
	}()
	t.Cleanup(s.stop)
	return s
}

func (s *agentServer) stop() {
	_ = s.l.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		_ = c.Close()
	}
	s.conns = nil
	s.mu.Unlock()
	s.wg.Wait()
}

func agentSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kra")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "agent.sock")
}

// TestAgentRestart (D-WR-06): after the signer's ssh-agent restarts on the
// same socket, a key opened before the restart signs again, through a new
// connection, without restarting the signer.
func TestAgentRestart(t *testing.T) {
	keyring := sshagent.NewKeyring()
	k, pub := ed25519Key(t)
	addKey(t, keyring, sshagent.AddedKey{PrivateKey: k})
	path := agentSocketPath(t)
	srv := startAgentServer(t, path, keyring, false)
	b := openBackend(t, map[string]string{"socket": path})
	key, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pub))
	if err != nil {
		t.Fatal(err)
	}
	signThrough(t, key)

	srv.stop() // the agent goes away, and comes back on the same path
	startAgentServer(t, path, keyring, false)
	signThrough(t, key)
	if _, err := b.Key(keystore.RoleHost, ssh.FingerprintSHA256(pub)); err != nil {
		t.Fatalf("Key after the agent restart: %v", err)
	}
}

// TestAgentDown (D-WR-06): with the agent gone, a signature fails at once
// with an error; when the agent is back, the key signs again.
func TestAgentDown(t *testing.T) {
	keyring := sshagent.NewKeyring()
	k, pub := ed25519Key(t)
	addKey(t, keyring, sshagent.AddedKey{PrivateKey: k})
	path := agentSocketPath(t)
	srv := startAgentServer(t, path, keyring, false)
	b := openBackend(t, map[string]string{"socket": path})
	key, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pub))
	if err != nil {
		t.Fatal(err)
	}
	srv.stop()
	if _, err := key.Sign(rand.Reader, []byte("data")); err == nil {
		t.Fatal("signed with no agent running")
	}
	startAgentServer(t, path, keyring, false)
	signThrough(t, key)
}

// TestAgentHang (D-WR-06): an agent that accepts requests but never
// answers does not block the signer: each request gives up after the
// request timeout (once retried on a new connection).
func TestAgentHang(t *testing.T) {
	defer agent.SetRequestTimeout(200 * time.Millisecond)()
	keyring := sshagent.NewKeyring()
	k, pub := ed25519Key(t)
	addKey(t, keyring, sshagent.AddedKey{PrivateKey: k})

	// Open a key on a working agent, then replace it by a hanging one.
	path := agentSocketPath(t)
	srv := startAgentServer(t, path, keyring, false)
	b := openBackend(t, map[string]string{"socket": path})
	key, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pub))
	if err != nil {
		t.Fatal(err)
	}
	srv.stop()
	hung := startAgentServer(t, path, keyring, true)

	for name, call := range map[string]func() error{
		"sign": func() error { _, err := key.Sign(rand.Reader, []byte("data")); return err },
		"key":  func() error { _, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pub)); return err },
	} {
		start := time.Now()
		done := make(chan error, 1)
		go func() { done <- call() }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%s through a hanging agent succeeded", name)
			}
			if d := time.Since(start); d > 2*time.Second {
				t.Fatalf("%s took %v, want about two request timeouts", name, d)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s through a hanging agent blocked", name)
		}
	}

	// The agent recovers: the next signature uses a fresh connection.
	hung.stop()
	startAgentServer(t, path, keyring, false)
	signThrough(t, key)
}
