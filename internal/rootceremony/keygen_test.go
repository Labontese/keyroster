package rootceremony

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

const testPassphrase = "twenty-plus characters of passphrase"

// TestGenerateOpenRoot round-trips a software root: armored age output, the
// same public key after decryption, signatures that verify under their
// namespaces, refusal of any other document, and no signing after Close.
func TestGenerateOpenRoot(t *testing.T) {
	enc, pub, err := GenerateRoot(rand.Reader, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(enc, []byte("-----BEGIN AGE ENCRYPTED FILE-----\n")) {
		t.Fatalf("GenerateRoot output is not armored age: %q", enc[:min(len(enc), 40)])
	}
	if pub.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("root key type %s, want %s", pub.Type(), ssh.KeyAlgoED25519)
	}
	if !strings.Contains(string(enc), "\n-----END AGE ENCRYPTED FILE-----") {
		t.Fatal("armor footer missing")
	}

	root, err := OpenRoot(enc, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(root.PublicKey().Marshal(), pub.Marshal()) {
		t.Fatal("OpenRoot returned a different public key")
	}

	bundle, policy := readVector(t, "bundle_genesis_v1.json"), readVector(t, "policy_genesis_v1.json")
	bsig, err := root.SignBundle(rand.Reader, bundle)
	if err != nil {
		t.Fatal(err)
	}
	psig, err := root.SignPolicy(rand.Reader, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		armored, doc []byte
		ns           string
	}{{bsig, bundle, trust.NamespaceBundle}, {psig, policy, trust.NamespacePolicy}} {
		sig, err := sshsig.Parse(c.armored)
		if err != nil {
			t.Fatal(err)
		}
		if err := sig.Verify(c.ns, c.doc); err != nil {
			t.Fatalf("%s signature: %v", c.ns, err)
		}
		if !bytes.Equal(sig.PublicKey().Marshal(), pub.Marshal()) {
			t.Fatalf("%s signature by the wrong key", c.ns)
		}
	}
	if _, err := root.SignBundle(rand.Reader, policy); err == nil {
		t.Fatal("Root.SignBundle signed a policy")
	}
	if _, err := root.SignPolicy(rand.Reader, []byte("arbitrary bytes\n")); err == nil {
		t.Fatal("Root.SignPolicy signed arbitrary bytes")
	}

	priv := root.priv
	root.Close()
	if !bytes.Equal(priv, make([]byte, len(priv))) {
		t.Fatal("Close did not zero the private key")
	}
	if _, err := root.SignBundle(rand.Reader, bundle); err == nil {
		t.Fatal("a closed root signed a bundle")
	}
	if _, err := root.SignPolicy(rand.Reader, policy); err == nil {
		t.Fatal("a closed root signed a policy")
	}
}

// TestOpenRootRefusals pins what OpenRoot refuses: a wrong passphrase, a
// non-Ed25519 key, an unarmored file, a file encrypted to a recipient
// other than a passphrase, and garbage.
func TestOpenRootRefusals(t *testing.T) {
	enc, _, err := GenerateRoot(rand.Reader, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("wrong_passphrase", func(t *testing.T) {
		if _, err := OpenRoot(enc, []byte(testPassphrase+"x")); err == nil {
			t.Fatal("OpenRoot accepted a wrong passphrase")
		}
	})

	t.Run("ecdsa_key", func(t *testing.T) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		block, err := ssh.MarshalPrivateKey(k, "not a root")
		if err != nil {
			t.Fatal(err)
		}
		r, err := age.NewScryptRecipient(testPassphrase)
		if err != nil {
			t.Fatal(err)
		}
		r.SetWorkFactor(10)
		file := encryptArmored(t, pem.EncodeToMemory(block), r)
		_, err = OpenRoot(file, []byte(testPassphrase))
		if err == nil || !strings.Contains(err.Error(), "Ed25519 only") {
			t.Fatalf("OpenRoot of an ECDSA key: err = %v, want an Ed25519-only refusal", err)
		}
	})

	t.Run("unarmored", func(t *testing.T) {
		r, err := age.NewScryptRecipient(testPassphrase)
		if err != nil {
			t.Fatal(err)
		}
		r.SetWorkFactor(10)
		var out bytes.Buffer
		w, err := age.Encrypt(&out, r)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenRoot(out.Bytes(), []byte(testPassphrase)); err == nil {
			t.Fatal("OpenRoot accepted a binary (unarmored) age file")
		}
	})

	t.Run("x25519_recipient", func(t *testing.T) {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		file := encryptArmored(t, []byte("x"), id.Recipient())
		if _, err := OpenRoot(file, []byte(testPassphrase)); err == nil {
			t.Fatal("OpenRoot accepted a file that is not passphrase-encrypted")
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := OpenRoot([]byte("-----BEGIN AGE ENCRYPTED FILE-----\nnope\n-----END AGE ENCRYPTED FILE-----\n"), []byte(testPassphrase)); err == nil {
			t.Fatal("OpenRoot accepted garbage")
		}
	})
}

func encryptArmored(t *testing.T, plain []byte, r age.Recipient) []byte {
	t.Helper()
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// TestValidatePassphrase pins the 20-character minimum, counted in
// Unicode code points.
func TestValidatePassphrase(t *testing.T) {
	for _, c := range []struct {
		name string
		pass []byte
		ok   bool
	}{
		{"empty", nil, false},
		{"19_ascii", []byte(strings.Repeat("a", 19)), false},
		{"20_ascii", []byte(strings.Repeat("a", 20)), true},
		{"19_runes_38_bytes", []byte(strings.Repeat("ä", 19)), false},
		{"20_runes", []byte(strings.Repeat("ä", 20)), true},
		{"invalid_utf8", append([]byte(strings.Repeat("a", 20)), 0xff), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidatePassphrase(c.pass); (err == nil) != c.ok {
				t.Fatalf("ValidatePassphrase(%q) = %v, want ok=%v", c.pass, err, c.ok)
			}
		})
	}
	if _, _, err := GenerateRoot(rand.Reader, []byte(strings.Repeat("a", 19))); err == nil {
		t.Fatal("GenerateRoot accepted a 19-character passphrase")
	}
}

// pipeFD returns the read end of a pipe holding data, as a descriptor
// number; the test closes it.
func pipeFD(t *testing.T, data string) int {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if _, err := w.WriteString(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return int(r.Fd()) //nolint:gosec // G115: a descriptor or handle fits in int
}

// TestReadPassphraseFD pins descriptor input: one line, line ending
// dropped, nothing past the line consumed, empty and oversized lines
// refused.
func TestReadPassphraseFD(t *testing.T) {
	fd := pipeFD(t, "first passphrase line\r\nsecond line\n")
	got, err := ReadPassphrase(fd, "", true)
	if err != nil || string(got) != "first passphrase line" {
		t.Fatalf("first read = %q, %v", got, err)
	}
	got, err = ReadPassphrase(fd, "", false)
	if err != nil || string(got) != "second line" {
		t.Fatalf("second read = %q, %v (the first read consumed past its line)", got, err)
	}
	if got, err := ReadPassphrase(fd, "", false); err == nil {
		t.Fatalf("read at end of input = %q, want an error", got)
	}
	if got, err := ReadPassphrase(pipeFD(t, "\n"), "", false); err == nil {
		t.Fatalf("empty line = %q, want an error", got)
	}
	if got, err := ReadPassphrase(pipeFD(t, "no newline at end"), "", false); err != nil || string(got) != "no newline at end" {
		t.Fatalf("unterminated line = %q, %v", got, err)
	}
	if _, err := ReadPassphrase(pipeFD(t, strings.Repeat("a", maxPassphraseBytes+1)+"\n"), "", false); err == nil {
		t.Fatal("an oversized passphrase line was accepted")
	}
}

// TestReadPassphraseNeedsTerminal pins that without --passphrase-fd the
// passphrase comes only from a terminal, never from piped stdin.
func TestReadPassphraseNeedsTerminal(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) { //nolint:gosec // G115: descriptor fits in int
		t.Skip("stdin is a terminal")
	}
	if _, err := ReadPassphrase(-1, "", false); err == nil || !strings.Contains(err.Error(), "not a terminal") {
		t.Fatalf("ReadPassphrase(-1) with non-terminal stdin: err = %v", err)
	}
}
