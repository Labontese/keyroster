package sshsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/crypto/ssh"
)

// skEd25519Signer is a test-only software stand-in for a FIDO security key
// holding an sk-ssh-ed25519@openssh.com key with application "ssh:". It
// produces the signature layout of PROTOCOL.u2f: Ed25519 over
// SHA-256(application) || flags || counter || SHA-256(data).
type skEd25519Signer struct {
	priv  ed25519.PrivateKey
	pub   ssh.PublicKey
	flags byte
}

func newSKEd25519Signer(t testing.TB, flags byte) *skEd25519Signer {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wire := ssh.Marshal(struct {
		Name string
		Key  []byte
		App  string
	}{ssh.KeyAlgoSKED25519, pubKey, "ssh:"})
	pub, err := ssh.ParsePublicKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	return &skEd25519Signer{priv: priv, pub: pub, flags: flags}
}

func (s *skEd25519Signer) PublicKey() ssh.PublicKey { return s.pub }

func (s *skEd25519Signer) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	app := sha256.Sum256([]byte("ssh:"))
	msg := sha256.Sum256(data)
	var rest [5]byte
	rest[0] = s.flags
	binary.BigEndian.PutUint32(rest[1:], 7) // signature counter
	signed := append(append(append([]byte{}, app[:]...), rest[:]...), msg[:]...)
	return &ssh.Signature{
		Format: ssh.KeyAlgoSKED25519,
		Blob:   ed25519.Sign(s.priv, signed),
		Rest:   rest[:],
	}, nil
}

// testKey is a signer plus, for keys ssh-keygen can sign with, its private
// key in OpenSSH format.
type testKey struct {
	name    string
	signer  ssh.Signer
	private []byte // nil for the sk stand-in
}

func testKeys(t testing.TB) []testKey {
	t.Helper()
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var keys []testKey
	for name, priv := range map[string]any{"ed25519": edPriv, "ecdsa-p256": ecPriv} {
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		pemBlock, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, testKey{name: name, signer: s, private: pemEncode(pemBlock)})
	}
	keys = append(keys, testKey{name: "sk-ssh-ed25519", signer: newSKEd25519Signer(t, skUserPresent)})
	return keys
}

// sshKeygen returns the path of ssh-keygen, the SSHSIG oracle. It skips the
// test when ssh-keygen is missing, unless KEYROSTER_REQUIRE_ORACLE=1 (set
// in CI), where a missing oracle is a failure.
func sshKeygen(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("KEYROSTER_REQUIRE_ORACLE") == "1" {
			t.Fatalf("ssh-keygen not found and KEYROSTER_REQUIRE_ORACLE=1: %v", err)
		}
		t.Skipf("ssh-keygen not found (set KEYROSTER_REQUIRE_ORACLE=1 to fail instead): %v", err)
	}
	return p
}
