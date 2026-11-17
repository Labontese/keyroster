package krl

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"

	"golang.org/x/crypto/ssh"
)

// zeroNonce is a reader of zero bytes: the certificates of the drain tests
// carry a fixed nonce, so nothing but key generation is random (03-12e).
type zeroNonce struct{}

func (zeroNonce) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// drainCA returns a fresh Ed25519 CA signer.
func drainCA(t testing.TB) ssh.Signer {
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

// drainCert returns a user certificate of ca with serial and validBefore,
// whose key ID names the serial.
func drainCert(t testing.TB, ca ssh.Signer, serial, validBefore uint64) *ssh.Certificate {
	t.Helper()
	c := &ssh.Certificate{
		Key: drainCA(t).PublicKey(), Serial: serial, CertType: ssh.UserCert, KeyId: fmt.Sprintf("kid-%d", serial),
		ValidPrincipals: []string{"alice"}, ValidAfter: 1, ValidBefore: validBefore,
	}
	if err := c.SignCert(zeroNonce{}, ca); err != nil { //nolint:forbidigo // a test double with ValidBefore values cert.Build cannot make (03-12e)
		t.Fatal(err)
	}
	return c
}

// TestDrainMax (03-12e): the accumulator keeps, per CA key, the logged
// certificate with the largest ValidBefore, with its leaf, serial and key
// ID; a key it was never given is not found.
func TestDrainMax(t *testing.T) {
	a, b := drainCA(t), drainCA(t)
	t.Run("largest_valid_before_per_key", func(t *testing.T) {
		d := NewDrainMax()
		for i, c := range []*ssh.Certificate{drainCert(t, a, 11, 100), drainCert(t, a, 12, 300), drainCert(t, a, 13, 200), drainCert(t, b, 14, 900)} {
			if err := d.Add(uint64(i+1), c); err != nil { //nolint:gosec // G115: a small index
				t.Fatalf("Add(%d): %v", i+1, err)
			}
		}
		if got, ok := d.For(a.PublicKey().Marshal()); !ok || got != (DrainEntry{ValidBefore: 300, Leaf: 2, Serial: 12, KeyID: "kid-12"}) {
			t.Fatalf("For(A) = %+v, %t; want ValidBefore 300 of leaf 2, serial 12", got, ok)
		}
		if got, ok := d.For(b.PublicKey().Marshal()); !ok || got != (DrainEntry{ValidBefore: 900, Leaf: 4, Serial: 14, KeyID: "kid-14"}) {
			t.Fatalf("For(B) = %+v, %t; want ValidBefore 900 of leaf 4, serial 14", got, ok)
		}
	})
	t.Run("other_keys_do_not_count", func(t *testing.T) {
		d := NewDrainMax()
		if err := d.Add(1, drainCert(t, a, 21, 500)); err != nil {
			t.Fatal(err)
		}
		if got, ok := d.For(b.PublicKey().Marshal()); ok {
			t.Fatalf("For(a key with no certificate) = %+v, want not found", got)
		}
	})
}
