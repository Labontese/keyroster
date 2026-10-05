//go:build linux

package agent_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/keystore/agent"
)

// serveKeyring serves keyring on a Unix socket in a short temporary
// directory until the test ends and returns the socket path.
func serveKeyring(t *testing.T, keyring sshagent.Agent) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kra")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sshagent.ServeAgent(keyring, c)
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		wg.Wait()
	})
	return path
}

func openBackend(t *testing.T, opts map[string]string) keystore.Backend {
	t.Helper()
	b, err := keystore.Open("agent", opts)
	if err != nil {
		t.Fatalf("keystore.Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func ed25519Key(t *testing.T) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func ecdsaKey(t *testing.T, curve elliptic.Curve) (*ecdsa.PrivateKey, ssh.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func addKey(t *testing.T, keyring sshagent.Agent, k sshagent.AddedKey) {
	t.Helper()
	if err := keyring.Add(k); err != nil {
		t.Fatalf("keyring.Add: %v", err)
	}
}

func buildRequest(subject ssh.PublicKey) cert.Request {
	return cert.Request{
		Profile:    cert.DefaultUserProfile(),
		Subject:    subject,
		Principals: []string{"alice"},
		Now:        time.Now(),
		ValidFor:   time.Hour,
		KeyID:      cert.KeyID{CA: "user", Subject: "u:alice", Request: "0123456789abcdef0123456789abcdef", Serial: 7},
		Serial:     7,
	}
}

// signThrough builds a certificate with key as the CA and checks its
// signature with x/crypto's CertChecker.
func signThrough(t *testing.T, key keystore.CAKey) {
	t.Helper()
	_, subject := ed25519Key(t)
	c, err := cert.Build(buildRequest(subject), key, rand.Reader)
	if err != nil {
		t.Fatalf("cert.Build through the agent backend: %v", err)
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), key.PublicKey().Marshal()) },
	}
	if err := checker.CheckCert("alice", c); err != nil {
		t.Fatalf("certificate signed through the agent does not verify: %v", err)
	}
}

func TestKeySelection(t *testing.T) {
	t.Run("decoy_first", func(t *testing.T) {
		keyring := sshagent.NewKeyring()
		decoy, decoyPub := ed25519Key(t)
		ca, caPub := ed25519Key(t)
		addKey(t, keyring, sshagent.AddedKey{PrivateKey: decoy, Comment: "decoy"})
		addKey(t, keyring, sshagent.AddedKey{PrivateKey: ca, Comment: "ca"})
		b := openBackend(t, map[string]string{"socket": serveKeyring(t, keyring)})
		key, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(caPub))
		if err != nil {
			t.Fatalf("Key: %v", err)
		}
		if bytes.Equal(key.PublicKey().Marshal(), decoyPub.Marshal()) {
			t.Fatal("backend returned the decoy key")
		}
		if !bytes.Equal(key.PublicKey().Marshal(), caPub.Marshal()) {
			t.Fatal("backend returned a key other than the pinned one")
		}
		signThrough(t, key)
	})
	t.Run("certificate_entry_skipped", func(t *testing.T) {
		keyring := sshagent.NewKeyring()
		priv, pub := ed25519Key(t)
		issuer, _ := ed25519Key(t)
		issuerSigner, err := ssh.NewSignerFromKey(issuer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := cert.Build(buildRequest(pub), issuerSigner, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		addKey(t, keyring, sshagent.AddedKey{PrivateKey: priv, Certificate: c})
		b := openBackend(t, map[string]string{"socket": serveKeyring(t, keyring)})
		for name, fp := range map[string]string{
			"certificate_fingerprint": ssh.FingerprintSHA256(c),
			"inner_key_fingerprint":   ssh.FingerprintSHA256(pub),
		} {
			key, err := b.Key(keystore.RoleUser, fp)
			if !errors.Is(err, agent.ErrKeyNotPresent) {
				t.Fatalf("%s: Key = %v, %v; want ErrKeyNotPresent (certificate entries are skipped)", name, key, err)
			}
		}
	})
	t.Run("pinned_key_absent", func(t *testing.T) {
		keyring := sshagent.NewKeyring()
		present, _ := ed25519Key(t)
		_, absentPub := ed25519Key(t)
		addKey(t, keyring, sshagent.AddedKey{PrivateKey: present})
		b := openBackend(t, map[string]string{"socket": serveKeyring(t, keyring)})
		_, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(absentPub))
		if !errors.Is(err, agent.ErrKeyNotPresent) {
			t.Fatalf("Key error = %v, want ErrKeyNotPresent", err)
		}
		if !strings.Contains(err.Error(), "keystore: pinned CA key not present in agent") {
			t.Fatalf("error text = %q", err.Error())
		}
	})
	t.Run("empty_fingerprint", func(t *testing.T) {
		keyring := sshagent.NewKeyring()
		k, _ := ed25519Key(t)
		addKey(t, keyring, sshagent.AddedKey{PrivateKey: k})
		b := openBackend(t, map[string]string{"socket": serveKeyring(t, keyring)})
		if _, err := b.Key(keystore.RoleUser, ""); err == nil || !strings.Contains(err.Error(), "no pinned fingerprint") {
			t.Fatalf("Key(\"\") error = %v, want the no-pinned-fingerprint refusal", err)
		}
	})
}

func TestCAKeyAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p384, p384Pub := ecdsaKey(t, elliptic.P384())
	p256, p256Pub := ecdsaKey(t, elliptic.P256())
	edKey, edPub := ed25519Key(t)
	tests := []struct {
		name string
		priv any
		pub  ssh.PublicKey
		want error
	}{
		{"rsa_ca_refused", rsaKey, rsaPub, cert.ErrCAKeyAlgorithm},
		{"p384_ca_refused", p384, p384Pub, cert.ErrCAKeyAlgorithm},
		{"ed25519_ca_signs", edKey, edPub, nil},
		{"p256_ca_signs", p256, p256Pub, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyring := sshagent.NewKeyring()
			addKey(t, keyring, sshagent.AddedKey{PrivateKey: tc.priv})
			b := openBackend(t, map[string]string{"socket": serveKeyring(t, keyring)})
			key, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(tc.pub))
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("Key = %v, %v; want %v", key, err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("Key: %v", err)
			}
			if key.Algorithm() != tc.pub.Type() || key.Custody() != keystore.CustodyAgent {
				t.Fatalf("Algorithm %q, Custody %q; want %q, %q", key.Algorithm(), key.Custody(), tc.pub.Type(), keystore.CustodyAgent)
			}
			signThrough(t, key)
		})
	}
}

func TestOptions(t *testing.T) {
	keyring := sshagent.NewKeyring()
	k, pub := ed25519Key(t)
	addKey(t, keyring, sshagent.AddedKey{PrivateKey: k})
	sock := serveKeyring(t, keyring)

	t.Run("custody_pkcs11_agent", func(t *testing.T) {
		b := openBackend(t, map[string]string{"socket": sock, "custody": "pkcs11-agent"})
		key, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pub))
		if err != nil {
			t.Fatal(err)
		}
		if key.Custody() != keystore.CustodyPKCS11Agent {
			t.Fatalf("Custody = %q, want %q", key.Custody(), keystore.CustodyPKCS11Agent)
		}
	})
	tests := []struct {
		name    string
		opts    map[string]string
		wantMsg string
	}{
		{"unknown_option", map[string]string{"socket": sock, "slot": "1"}, `unknown backend option "slot"`},
		{"unknown_custody", map[string]string{"socket": sock, "custody": "tpm"}, "custody must be"},
		{"missing_socket", map[string]string{}, "option socket is required"},
		{"socket_absent", map[string]string{"socket": sock + ".missing"}, "keystore agent: connect"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := keystore.Open("agent", tc.opts)
			if err == nil {
				_ = b.Close()
				t.Fatal("keystore.Open succeeded")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("keystore.Open error = %v, want %q", err, tc.wantMsg)
			}
		})
	}
	t.Run("unknown_backend", func(t *testing.T) {
		if _, err := keystore.Open("no-such-backend", nil); err == nil || !strings.Contains(err.Error(), `unknown backend "no-such-backend"`) {
			t.Fatalf("keystore.Open error = %v, want the unknown-backend refusal", err)
		}
	})
}
