//go:build piv

package piv

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ykpiv "github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
)

// These tests run the real backend (option and secret-file checks, slot
// map, algorithm choice, provisioning, Key, the mutex) against fakeCard, an
// in-memory PIV card with real Ed25519 and ECDSA keys. They do not run
// yubikey.go or piv-go's signing code; see docs/security/needs-hardware.md.

const (
	testPIN = "40961758"
)

var (
	testMgmtKey = bytes.Repeat([]byte{0x5a, 0xc3}, 12) // 24 bytes, not the default
	allRoles    = []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog}
)

// fakeSlot is one occupied slot of a fakeCard.
type fakeSlot struct {
	priv crypto.Signer
	info ykpiv.KeyInfo
}

// fakeCard behaves like a YubiKey for what the backend uses: GenerateKey
// needs the management key and, like a real card, replaces an existing key;
// PrivateKey needs the PIN. It has no lock of its own, so only the
// backend's mutex keeps concurrent use race-free: signs is updated without
// synchronisation, and -race reports it if the backend does not serialise.
type fakeCard struct {
	major, minor, patch int
	mgmtKey             []byte
	pin                 string
	slots               map[uint32]*fakeSlot
	generateCalls       int
	signs               int
	closed              bool
}

func newFakeCard(major, minor, patch int) *fakeCard {
	return &fakeCard{major: major, minor: minor, patch: patch, mgmtKey: testMgmtKey, pin: testPIN, slots: map[uint32]*fakeSlot{}}
}

func (f *fakeCard) Version() (int, int, int) { return f.major, f.minor, f.patch }

func (f *fakeCard) KeyInfo(slot ykpiv.Slot) (ykpiv.KeyInfo, error) {
	s, ok := f.slots[slot.Key]
	if !ok {
		return ykpiv.KeyInfo{}, fmt.Errorf("fake card: slot %s: %w", slot, ykpiv.ErrNotFound)
	}
	return s.info, nil
}

func (f *fakeCard) GenerateKey(mgmtKey []byte, slot ykpiv.Slot, key ykpiv.Key) (crypto.PublicKey, error) {
	if !bytes.Equal(mgmtKey, f.mgmtKey) {
		return nil, errors.New("fake card: management key authentication failed")
	}
	if key.PINPolicy != ykpiv.PINPolicyOnce || key.TouchPolicy != ykpiv.TouchPolicyNever {
		return nil, fmt.Errorf("fake card: unexpected policies %v/%v", key.PINPolicy, key.TouchPolicy)
	}
	priv, err := newKey(key.Algorithm)
	if err != nil {
		return nil, err
	}
	f.generateCalls++
	f.slots[slot.Key] = &fakeSlot{priv: priv, info: ykpiv.KeyInfo{
		Algorithm: key.Algorithm, PINPolicy: key.PINPolicy, TouchPolicy: key.TouchPolicy,
		Origin: ykpiv.OriginGenerated, PublicKey: priv.Public(),
	}}
	return priv.Public(), nil
}

func (f *fakeCard) PrivateKey(slot ykpiv.Slot, pub crypto.PublicKey, auth ykpiv.KeyAuth) (crypto.PrivateKey, error) {
	s, ok := f.slots[slot.Key]
	if !ok {
		return nil, fmt.Errorf("fake card: slot %s: %w", slot, ykpiv.ErrNotFound)
	}
	if !publicEqual(s.priv.Public(), pub) {
		return nil, errors.New("fake card: public key does not match the slot")
	}
	if auth.PIN != f.pin {
		return nil, errors.New("fake card: wrong PIN")
	}
	return &fakeSigner{card: f, priv: s.priv}, nil
}

func (f *fakeCard) Close() error {
	f.closed = true
	return nil
}

// fakeSigner signs with the slot's in-memory key and counts signatures on
// the card without a lock (see fakeCard).
type fakeSigner struct {
	card *fakeCard
	priv crypto.Signer
}

func (s *fakeSigner) Public() crypto.PublicKey { return s.priv.Public() }

func (s *fakeSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.card.signs++
	return s.priv.Sign(r, digest, opts)
}

func newKey(alg ykpiv.Algorithm) (crypto.Signer, error) {
	switch alg {
	case ykpiv.AlgorithmEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	case ykpiv.AlgorithmEC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	default:
		return nil, fmt.Errorf("fake card: unsupported algorithm %v", alg)
	}
}

func publicEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

// writeSecret writes content to a new file with mode perm and returns its
// path.
func writeSecret(t *testing.T, name, content string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil { // umask may have narrowed it
		t.Fatal(err)
	}
	return p
}

// validOpts returns backend options with a 0600 PIN file and a 0600
// management key file.
func validOpts(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"pin-file":      writeSecret(t, "pin", testPIN+"\n", 0o600),
		"mgmt-key-file": writeSecret(t, "mgmt-key", hex.EncodeToString(testMgmtKey)+"\n", 0o600),
	}
}

func openFake(t *testing.T, c *fakeCard, opts map[string]string) *backend {
	t.Helper()
	b, err := newWithCard(c, opts)
	if err != nil {
		t.Fatalf("newWithCard: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
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

// issue builds a user certificate with key as the CA and checks it with
// x/crypto's CertChecker against the provisioned public key.
func issue(t *testing.T, key keystore.CAKey, caPub ssh.PublicKey) {
	t.Helper()
	subPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := ssh.NewPublicKey(subPub)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cert.Build(buildRequest(subject), key, rand.Reader)
	if err != nil {
		t.Fatalf("cert.Build through the PIV backend: %v", err)
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), caPub.Marshal()) },
	}
	if err := checker.CheckCert("alice", c); err != nil {
		t.Fatalf("certificate signed through the PIV backend does not verify: %v", err)
	}
}

// TestPIVProvisionAndIssue: provisioning fills slots 0x82-0x86 with
// Ed25519 keys on firmware 5.7.0 and P-256 keys on 5.4.3; each key opens
// through Key with custody piv and the matching algorithm, and the user key
// issues a certificate that verifies with the provisioned public key.
func TestPIVProvisionAndIssue(t *testing.T) {
	for _, tc := range []struct {
		name                string
		major, minor, patch int
		alg                 string
	}{
		{"firmware_5.7.0_ed25519", 5, 7, 0, ssh.KeyAlgoED25519},
		{"firmware_5.4.3_p256", 5, 4, 3, ssh.KeyAlgoECDSA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeCard(tc.major, tc.minor, tc.patch)
			b := openFake(t, c, validOpts(t))
			pubs, err := b.Provision(allRoles)
			if err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if len(pubs) != len(allRoles) || c.generateCalls != len(allRoles) {
				t.Fatalf("got %d keys from %d GenerateKey calls, want %d", len(pubs), c.generateCalls, len(allRoles))
			}
			for role, id := range map[keystore.Role]uint32{
				keystore.RoleUser: 0x82, keystore.RoleHost: 0x83, keystore.RoleMachine: 0x84,
				keystore.RoleOps: 0x85, keystore.RoleLog: 0x86,
			} {
				pub := pubs[role]
				if pub == nil || pub.Type() != tc.alg {
					t.Fatalf("role %s: got %v, want a %s key", role, pub, tc.alg)
				}
				s, ok := c.slots[id]
				if !ok || !publicEqual(s.priv.Public(), pub.(ssh.CryptoPublicKey).CryptoPublicKey()) {
					t.Fatalf("role %s: slot %#x does not hold the provisioned key", role, id)
				}
				k, err := b.Key(role, ssh.FingerprintSHA256(pub))
				if err != nil {
					t.Fatalf("Key(%s): %v", role, err)
				}
				if k.Custody() != keystore.CustodyPIV || k.Algorithm() != pub.Type() {
					t.Fatalf("Key(%s): custody %s algorithm %s, want piv %s", role, k.Custody(), k.Algorithm(), pub.Type())
				}
			}
			user, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleUser]))
			if err != nil {
				t.Fatal(err)
			}
			issue(t, user, pubs[keystore.RoleUser])
			if c.signs == 0 {
				t.Fatal("the certificate was not signed through the card")
			}
			if !strings.Contains(b.Describe(), tc.alg) {
				t.Fatalf("Describe() = %q, want it to name %s", b.Describe(), tc.alg)
			}
		})
	}
}
