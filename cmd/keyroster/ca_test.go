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
