package krl

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
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
	t.Run("ties_keep_the_earliest_leaf", func(t *testing.T) {
		d := NewDrainMax()
		for i, c := range []*ssh.Certificate{drainCert(t, a, 31, 400), drainCert(t, a, 32, 400)} {
			if err := d.Add(uint64(i+5), c); err != nil { //nolint:gosec // G115: a small index
				t.Fatal(err)
			}
		}
		if got, ok := d.For(a.PublicKey().Marshal()); !ok || got.Leaf != 5 || got.Serial != 31 {
			t.Fatalf("For(A) = %+v, %t; want leaf 5, serial 31 (the earliest of the tie)", got, ok)
		}
	})
	t.Run("never_expiring_certificate_is_kept", func(t *testing.T) {
		d := NewDrainMax()
		for i, c := range []*ssh.Certificate{drainCert(t, a, 41, 500), drainCert(t, a, 42, ssh.CertTimeInfinity), drainCert(t, a, 43, 600)} {
			if err := d.Add(uint64(i+1), c); err != nil { //nolint:gosec // G115: a small index
				t.Fatal(err)
			}
		}
		if got, ok := d.For(a.PublicKey().Marshal()); !ok || got.ValidBefore != ssh.CertTimeInfinity || got.Serial != 42 {
			t.Fatalf("For(A) = %+v, %t; want the never-expiring serial 42", got, ok)
		}
	})
	t.Run("too_many_keys_refused", func(t *testing.T) {
		d := NewDrainMax()
		c := drainCert(t, a, 51, 700)
		for i := range MaxDrainKeys {
			c.SignatureKey = drainCA(t).PublicKey()
			if err := d.Add(uint64(i), c); err != nil { //nolint:gosec // G115: a small index
				t.Fatalf("Add of key %d: %v", i+1, err)
			}
		}
		// A key the accumulator already holds is still accepted.
		if err := d.Add(MaxDrainKeys, c); err != nil {
			t.Fatalf("Add of a held key at the cap: %v", err)
		}
		c.SignatureKey = drainCA(t).PublicKey()
		if err := d.Add(MaxDrainKeys+1, c); !errors.Is(err, ErrDrainTooManyKeys) {
			t.Fatalf("Add of key %d = %v, want ErrDrainTooManyKeys", MaxDrainKeys+1, err)
		}
	})
	t.Run("nil_certificate_refused", func(t *testing.T) {
		if err := NewDrainMax().Add(1, nil); err == nil {
			t.Fatal("Add(nil) = nil, want an error")
		}
	})
	t.Run("certificate_without_signature_key_refused", func(t *testing.T) {
		c := drainCert(t, a, 61, 800)
		c.SignatureKey = nil
		if err := NewDrainMax().Add(1, c); err == nil {
			t.Fatal("Add of a certificate without a signature key = nil, want an error")
		}
	})
	t.Run("for_on_a_nil_accumulator_finds_nothing", func(t *testing.T) {
		var d *DrainMax
		if got, ok := d.For(a.PublicKey().Marshal()); ok || got != (DrainEntry{}) {
			t.Fatalf("For on a nil accumulator = %+v, %t; want the zero entry and false", got, ok)
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

// TestEarliestTrustedUntil (03-12e): the earliest trusted_until a
// switch's binding accepts is ValidBefore plus PruneMargin, at which
// DrainBindingHolds first holds, and none when that sum saturates.
func TestEarliestTrustedUntil(t *testing.T) {
	t.Run("adds_prune_margin", func(t *testing.T) {
		if e, ok := EarliestTrustedUntil(1000); !ok || e != 1000+PruneMargin {
			t.Fatalf("EarliestTrustedUntil(1000) = %d, %t; want %d", e, ok, 1000+PruneMargin)
		}
		if !DrainBindingHolds(1000, 1000+PruneMargin) || DrainBindingHolds(1000, 1000+PruneMargin-1) {
			t.Fatal("the earliest trusted_until is not where DrainBindingHolds first holds")
		}
	})
	t.Run("saturates", func(t *testing.T) {
		for _, vb := range []uint64{math.MaxUint64 - PruneMargin + 1, math.MaxUint64 - 1, math.MaxUint64} {
			if e, ok := EarliestTrustedUntil(vb); ok {
				t.Fatalf("EarliestTrustedUntil(%d) = %d, true; want false (the sum saturates)", vb, e)
			}
		}
	})
	t.Run("exactly_at_the_threshold", func(t *testing.T) {
		vb := uint64(math.MaxUint64 - PruneMargin)
		if e, ok := EarliestTrustedUntil(vb); !ok || e != math.MaxUint64 {
			t.Fatalf("EarliestTrustedUntil(2^64 - 1 - %d) = %d, %t; want 2^64 - 1, true", PruneMargin, e, ok)
		}
	})
}

// TestDrainMarginIsPruneMargin (03-12e): the switch floor's margin in
// internal/trust is the KRL prune margin, which trust cannot import, and
// the allowance's cap is seven days.
func TestDrainMarginIsPruneMargin(t *testing.T) {
	if trust.DrainMargin != PruneMargin {
		t.Fatalf("trust.DrainMargin = %d, krl.PruneMargin = %d; want them equal", trust.DrainMargin, PruneMargin)
	}
	if trust.MaxDrainAllowance != 168*time.Hour {
		t.Fatalf("trust.MaxDrainAllowance = %s, want 168h", trust.MaxDrainAllowance)
	}
}
