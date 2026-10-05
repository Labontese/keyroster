package sshsig

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

const testNamespace = "keyroster/test/v1"

func pemEncode(b *pem.Block) []byte { return pem.EncodeToMemory(b) }

// TestOracleSSHKeygenVerifiesOurSignatures checks that signatures made by
// Sign verify with `ssh-keygen -Y verify` for every accepted key type,
// including an sk-ssh-ed25519 key.
func TestOracleSSHKeygenVerifiesOurSignatures(t *testing.T) {
	keygen := sshKeygen(t)
	msg := []byte("{\"version\":1}\n")
	for _, k := range testKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			dir := t.TempDir()
			armored, err := Sign(rand.Reader, k.signer, testNamespace, msg)
			if err != nil {
				t.Fatal(err)
			}
			sigFile := filepath.Join(dir, "msg.sig")
			allowed := filepath.Join(dir, "allowed_signers")
			writeFile(t, sigFile, armored)
			writeFile(t, allowed, append([]byte("root "), ssh.MarshalAuthorizedKey(k.signer.PublicKey())...))

			out, err := keygenVerify(keygen, allowed, testNamespace, sigFile, msg)
			if err != nil {
				t.Fatalf("ssh-keygen -Y verify refused our signature: %v\n%s", err, out)
			}
			// Control: the oracle refuses the same signature under another
			// namespace, so the pass above is meaningful.
			if out, err := keygenVerify(keygen, allowed, "keyroster/other/v1", sigFile, msg); err == nil {
				t.Fatalf("ssh-keygen accepted the signature under the wrong namespace:\n%s", out)
			}
		})
	}
}

// TestOracleWeVerifySSHKeygenSignatures checks that signatures made by
// `ssh-keygen -Y sign` parse and verify with this package. The sk key type
// needs a security-key provider for ssh-keygen to sign; that direction runs
// in the e2e suite (TestRootSK, sk-dummy.so).
func TestOracleWeVerifySSHKeygenSignatures(t *testing.T) {
	keygen := sshKeygen(t)
	msg := []byte("{\"version\":1}\n")
	for _, k := range testKeys(t) {
		if k.private == nil {
			continue
		}
		t.Run(k.name, func(t *testing.T) {
			dir := t.TempDir()
			keyFile := filepath.Join(dir, "key")
			msgFile := filepath.Join(dir, "msg")
			writeFile(t, keyFile, k.private)
			writeFile(t, msgFile, msg)
			cmd := exec.Command(keygen, "-Y", "sign", "-f", keyFile, "-n", testNamespace, msgFile) //nolint:gosec // G204: test oracle
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen -Y sign: %v\n%s", err, out)
			}
			armored, err := os.ReadFile(msgFile + ".sig") //nolint:gosec // test file
			if err != nil {
				t.Fatal(err)
			}
			sig, err := Parse(armored)
			if err != nil {
				t.Fatalf("Parse(ssh-keygen output): %v\n%s", err, armored)
			}
			if !bytes.Equal(sig.PublicKey().Marshal(), k.signer.PublicKey().Marshal()) {
				t.Fatal("parsed public key differs from the signing key")
			}
			if err := sig.Verify(testNamespace, msg); err != nil {
				t.Fatalf("Verify(ssh-keygen signature): %v", err)
			}
			if sig.Verify(testNamespace, append(msg, 'x')) == nil {
				t.Fatal("Verify accepted a different message")
			}
			// Our armor of the parsed blob is byte-identical to ssh-keygen's.
			if got := armor(sig.blob); !bytes.Equal(got, armored) {
				t.Fatalf("re-armored signature differs from ssh-keygen output:\n%s\nvs\n%s", got, armored)
			}
		})
	}
}

func keygenVerify(keygen, allowed, namespace, sigFile string, msg []byte) ([]byte, error) {
	cmd := exec.Command(keygen, "-Y", "verify", "-f", allowed, "-I", "root", "-n", namespace, "-s", sigFile) //nolint:gosec // G204: test oracle
	cmd.Stdin = bytes.NewReader(msg)
	return cmd.CombinedOutput()
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
