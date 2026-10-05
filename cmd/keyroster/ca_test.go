package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestCAIssueRefusesPrivateKey proves that ca issue refuses a private key
// passed as --pubkey before it dials the signer (CA-06): the --socket path
// does not exist, so a dial would fail with "signerclient: connect", and the
// public-key control case shows that it does dial when the key is public.
func TestCAIssueRefusesPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	openssh, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	_, admin, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminSigner, err := ssh.NewSignerFromKey(admin)
	if err != nil {
		t.Fatal(err)
	}
	useKeyring(t, admin)
	dir := t.TempDir()
	socket := filepath.Join(dir, "no-such-signer.sock")
	tests := []struct {
		name       string
		content    []byte
		wantStderr string
	}{
		{"private_key_as_pubkey", pem.EncodeToMemory(openssh), "contains a private key"},
		{"pkcs8_private_key_as_pubkey", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), "contains a private key"},
		{"public_key_dials_signer", ssh.MarshalAuthorizedKey(sshPub), "signerclient: connect"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyFile := filepath.Join(dir, tc.name)
			if err := os.WriteFile(keyFile, tc.content, 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			code := dispatch(context.Background(), []string{
				"ca", "issue",
				"--socket", socket,
				"--pubkey", keyFile,
				"--subject", "u:alice",
				"--principal", "alice",
				"--admin-key", ssh.FingerprintSHA256(adminSigner.PublicKey()),
			}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("exit status %d, want 1 (stderr %q)", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Fatalf("stderr = %q, want it to contain %q", stderr.String(), tc.wantStderr)
			}
			if tc.wantStderr != "signerclient: connect" && strings.Contains(stderr.String(), "signerclient") {
				t.Fatalf("stderr = %q: the CLI dialed the signer before refusing the private key", stderr.String())
			}
			if _, err := os.Stat(strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"); !os.IsNotExist(err) {
				t.Fatalf("a certificate file was written (stat error %v)", err)
			}
		})
	}
}

// TestCAIssueAdminEvidence: ca issue signs the request's exact signing
// bytes with every --admin-key from the agent, as admin-sshsig/v1 evidence
// under keyroster/issue-request/v1 (D-13), and refuses to send a request
// without an admin key or with a key the agent does not hold.
func TestCAIssueAdminEvidence(t *testing.T) {
	var admins []ed25519.PrivateKey
	var fps []string
	for range 2 {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		admins = append(admins, k)
		fps = append(fps, ssh.FingerprintSHA256(s.PublicKey()))
	}
	useKeyring(t, admins...)
	req := &wire.IssueRequest{CARole: wire.CARoleUser, SubjectKey: []byte("k"), Subject: "u:alice",
		Principals: []string{"alice"}, ValidForSeconds: 60, CreatedAt: 1, Extensions: []string{"permit-port-forwarding"}}

	t.Run("two_admins_sign_the_signing_bytes", func(t *testing.T) {
		ev, err := adminEvidence(req, fps)
		if err != nil {
			t.Fatal(err)
		}
		if len(ev) != 2 {
			t.Fatalf("%d evidence items, want 2", len(ev))
		}
		for i, e := range ev {
			if e.Type != "admin-sshsig/v1" {
				t.Fatalf("evidence type %q", e.Type)
			}
			sig, err := sshsig.Parse(e.Blob)
			if err != nil {
				t.Fatal(err)
			}
			if got := ssh.FingerprintSHA256(sig.PublicKey()); got != fps[i] {
				t.Fatalf("evidence %d signed by %s, want %s", i, got, fps[i])
			}
			if err := sig.Verify("keyroster/issue-request/v1", req.SigningBytes()); err != nil {
				t.Fatalf("evidence %d does not verify over the signing bytes: %v", i, err)
			}
		}
	})
	t.Run("key_not_in_agent", func(t *testing.T) {
		if _, err := adminEvidence(req, []string{"SHA256:" + strings.Repeat("A", 43)}); err == nil || !strings.Contains(err.Error(), "does not hold the admin key") {
			t.Fatalf("err = %v, want the agent refusal", err)
		}
	})
	t.Run("no_admin_key_is_a_usage_error", func(t *testing.T) {
		pub := filepath.Join(t.TempDir(), "id.pub")
		s, err := ssh.NewSignerFromKey(admins[0])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pub, ssh.MarshalAuthorizedKey(s.PublicKey()), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := dispatch(context.Background(), []string{"ca", "issue", "--socket", filepath.Join(t.TempDir(), "none.sock"),
			"--pubkey", pub, "--subject", "u:alice", "--principal", "alice"}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "--admin-key") {
			t.Fatalf("exit %d, want 2 naming --admin-key:\n%s", code, stderr.String())
		}
	})
}
