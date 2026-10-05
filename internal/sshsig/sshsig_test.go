package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

func edSigner(t testing.TB) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignVerifyRoundTrip(t *testing.T) {
	msg := []byte("message\n")
	for _, k := range testKeys(t) {
		t.Run(k.name, func(t *testing.T) {
			armored, err := Sign(rand.Reader, k.signer, testNamespace, msg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(armored, []byte(armorBegin+"\n")) || !bytes.HasSuffix(armored, []byte(armorEnd+"\n")) {
				t.Fatalf("armor:\n%s", armored)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(armored)), "\n") {
				if len(line) > lineLen {
					t.Fatalf("line longer than %d: %q", lineLen, line)
				}
			}
			sig, err := Parse(armored)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig.PublicKey().Marshal(), k.signer.PublicKey().Marshal()) {
				t.Fatal("public key differs")
			}
			if err := sig.Verify(testNamespace, msg); err != nil {
				t.Fatal(err)
			}
			if err := sig.Verify(testNamespace, []byte("other\n")); err == nil {
				t.Fatal("verified another message")
			}
			if err := sig.Verify("keyroster/other/v1", msg); !errors.Is(err, ErrNamespace) {
				t.Fatalf("wrong namespace: err = %v, want ErrNamespace", err)
			}
		})
	}
}

// customBlob builds an armored signature with full control over the
// namespace, reserved field and hash algorithm, signing the matching
// signed data so that only the property under test is wrong.
func customBlob(t *testing.T, s ssh.Signer, namespace, reserved, hashAlg string, msg []byte) []byte {
	t.Helper()
	var digest []byte
	switch hashAlg {
	case "sha256":
		h := sha256.Sum256(msg)
		digest = h[:]
	default:
		data := signedData(namespace, msg)
		return armor(blobWith(t, s, namespace, reserved, hashAlg, data))
	}
	var b cryptobyte.Builder
	b.AddBytes([]byte(magic))
	for _, f := range [][]byte{[]byte(namespace), []byte(reserved), []byte(hashAlg), digest} {
		b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(f) })
	}
	return armor(blobWith(t, s, namespace, reserved, hashAlg, b.BytesOrPanic()))
}

func blobWith(t *testing.T, s ssh.Signer, namespace, reserved, hashAlg string, data []byte) []byte {
	t.Helper()
	sig, err := s.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddBytes([]byte(magic))
	b.AddUint32(sigVersion)
	for _, f := range [][]byte{s.PublicKey().Marshal(), []byte(namespace), []byte(reserved), []byte(hashAlg), ssh.Marshal(sig)} {
		b.AddUint32LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(f) })
	}
	return b.BytesOrPanic()
}

func TestRefusals(t *testing.T) {
	msg := []byte("message\n")
	s := edSigner(t)

	t.Run("hash_algorithm_sha256_refused", func(t *testing.T) {
		sig, err := Parse(customBlob(t, s, testNamespace, "", "sha256", msg))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if err := sig.Verify(testNamespace, msg); !errors.Is(err, ErrHashAlgorithm) {
			t.Fatalf("err = %v, want ErrHashAlgorithm", err)
		}
	})
	t.Run("empty_namespace_refused", func(t *testing.T) {
		if _, err := Sign(rand.Reader, s, "", msg); !errors.Is(err, ErrNamespace) {
			t.Fatalf("Sign: err = %v, want ErrNamespace", err)
		}
		if _, err := Parse(customBlob(t, s, "", "", hashAlgorithm, msg)); !errors.Is(err, ErrNamespace) {
			t.Fatalf("Parse: err = %v, want ErrNamespace", err)
		}
		good, err := Sign(rand.Reader, s, testNamespace, msg)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Parse(good)
		if err != nil {
			t.Fatal(err)
		}
		if err := sig.Verify("", msg); !errors.Is(err, ErrNamespace) {
			t.Fatalf("Verify: err = %v, want ErrNamespace", err)
		}
	})
	t.Run("non_empty_reserved_refused", func(t *testing.T) {
		if _, err := Parse(customBlob(t, s, testNamespace, "x", hashAlgorithm, msg)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("err = %v, want ErrMalformed", err)
		}
	})
	t.Run("sk_without_user_presence_refused", func(t *testing.T) {
		noUP := newSKEd25519Signer(t, 0)
		if _, err := Sign(rand.Reader, noUP, testNamespace, msg); !errors.Is(err, ErrUserPresence) {
			t.Fatalf("Sign: err = %v, want ErrUserPresence", err)
		}
		sig, err := Parse(customBlob(t, noUP, testNamespace, "", hashAlgorithm, msg))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if err := sig.Verify(testNamespace, msg); !errors.Is(err, ErrUserPresence) {
			t.Fatalf("Verify: err = %v, want ErrUserPresence", err)
		}
	})
	t.Run("rsa_signer_refused", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Sign(rand.Reader, rs, testNamespace, msg); !errors.Is(err, ErrKeyType) {
			t.Fatalf("err = %v, want ErrKeyType", err)
		}
	})
	t.Run("certificate_signer_refused", func(t *testing.T) {
		cert := &ssh.Certificate{Key: s.PublicKey(), CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity}
		cs, err := ssh.NewCertSigner(cert, s)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Sign(rand.Reader, cs, testNamespace, msg); !errors.Is(err, ErrKeyType) {
			t.Fatalf("err = %v, want ErrKeyType", err)
		}
	})
}

func TestParseMalformed(t *testing.T) {
	good, err := Sign(rand.Reader, edSigner(t), testNamespace, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(good), "\n")
	cases := map[string][]byte{
		"empty":                 nil,
		"missing_end_line":      []byte(strings.Join(lines[:len(lines)-2], "\n") + "\n"),
		"truncated_base64":      bytes.Replace(good, []byte(lines[1]), []byte(lines[1][:len(lines[1])-7]), 1),
		"missing_begin_line":    []byte(strings.Join(lines[1:], "\n")),
		"data_after_end":        append(bytes.Clone(good), []byte("trailing\n")...),
		"text_after_end_marker": bytes.Replace(good, []byte(armorEnd+"\n"), []byte(armorEnd+" x\n"), 1),
		"not_base64":            bytes.Replace(good, []byte(lines[1]), []byte(strings.Repeat("!", len(lines[1]))), 1),
		"crlf":                  bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n")),
		"overlong_line":         bytes.Replace(good, []byte(lines[1]+"\n"+lines[2]), []byte(lines[1]+lines[2]), 1),
		"empty_body":            []byte(armorBegin + "\n" + armorEnd + "\n"),
		"wrong_magic":           armor(append([]byte("SSHSIH"), mustBlob(t, good)[6:]...)),
		"wrong_version":         armor(append(append([]byte(magic), 0, 0, 0, 2), mustBlob(t, good)[10:]...)),
		"trailing_blob_bytes":   armor(append(mustBlob(t, good), 0)),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(data); err == nil {
				t.Fatal("Parse accepted malformed input")
			}
			if _, err := ParseAll(data); err == nil {
				t.Fatal("ParseAll accepted malformed input")
			}
		})
	}
}

func mustBlob(t *testing.T, armored []byte) []byte {
	t.Helper()
	sig, err := Parse(armored)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(sig.blob)
}

func TestParseAllConcatenatedBlocks(t *testing.T) {
	msg := []byte("bundle\n")
	var all []byte
	var keys []ssh.Signer
	for _, k := range testKeys(t) {
		sig, err := Sign(rand.Reader, k.signer, testNamespace, msg)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, sig...)
		keys = append(keys, k.signer)
	}
	sigs, err := ParseAll(all)
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) != len(keys) {
		t.Fatalf("parsed %d signatures, want %d", len(sigs), len(keys))
	}
	for i, s := range sigs {
		if !bytes.Equal(s.PublicKey().Marshal(), keys[i].PublicKey().Marshal()) {
			t.Fatalf("signature %d has the wrong key", i)
		}
		if err := s.Verify(testNamespace, msg); err != nil {
			t.Fatalf("signature %d: %v", i, err)
		}
	}
	// The last block may lack its final newline.
	if got, err := ParseAll(bytes.TrimSuffix(all, []byte("\n"))); err != nil || len(got) != len(keys) {
		t.Fatalf("without final newline: %d signatures, %v", len(got), err)
	}
	// Garbage between blocks invalidates the whole file.
	first, _ := Sign(rand.Reader, keys[0], testNamespace, msg)
	if _, err := ParseAll(append(append(bytes.Clone(first), []byte("junk\n")...), first...)); err == nil {
		t.Fatal("ParseAll accepted junk between blocks")
	}
	if _, err := Parse(all); err == nil {
		t.Fatal("Parse accepted several blocks")
	}
}
