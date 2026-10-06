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
	"sync"
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

// fakeCard behaves like a YubiKey, as driven through piv-go, for what the
// backend uses: GenerateKey needs the management key and, like a real card,
// replaces an existing key; PrivateKey checks nothing about the PIN (piv-go
// only builds a handle); VerifyPIN logs the session in, and a PIN-once key
// signs only in a logged-in session. It has no lock of its own, so only the
// backend's mutex keeps concurrent use race-free: signs is updated without
// synchronisation, and -race reports it if the backend does not serialise.
type fakeCard struct {
	major, minor, patch int
	mgmtKey             []byte
	pin                 string
	slots               map[uint32]*fakeSlot
	infoErr             map[uint32]error // injected KeyInfo failures
	loggedIn            bool
	pinAttempts         int
	generateCalls       int
	signs               int
	closed              bool
}

func (f *fakeCard) VerifyPIN(pin string) error {
	f.pinAttempts++
	if pin != f.pin {
		f.loggedIn = false
		return errors.New("fake card: wrong PIN")
	}
	f.loggedIn = true
	return nil
}

func newFakeCard(major, minor, patch int) *fakeCard {
	return &fakeCard{major: major, minor: minor, patch: patch, mgmtKey: testMgmtKey, pin: testPIN, slots: map[uint32]*fakeSlot{}}
}

func (f *fakeCard) Version() (int, int, int) { return f.major, f.minor, f.patch }

func (f *fakeCard) KeyInfo(slot ykpiv.Slot) (ykpiv.KeyInfo, error) {
	if err := f.infoErr[slot.Key]; err != nil {
		return ykpiv.KeyInfo{}, err
	}
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
	if auth.PINPolicy != ykpiv.PINPolicyOnce {
		return nil, fmt.Errorf("fake card: unexpected PIN policy %v", auth.PINPolicy)
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
	if !s.card.loggedIn {
		return nil, errors.New("fake card: security status not satisfied (PIN not verified)")
	}
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
			if c.pinAttempts != 1 {
				t.Fatalf("the PIN was sent to the card %d times, want once (at open)", c.pinAttempts)
			}
			if !strings.Contains(b.Describe(), tc.alg) {
				t.Fatalf("Describe() = %q, want it to name %s", b.Describe(), tc.alg)
			}
		})
	}
}

func mustSlot(t *testing.T, id uint32) ykpiv.Slot {
	t.Helper()
	s, ok := ykpiv.RetiredKeyManagementSlot(id)
	if !ok {
		t.Fatalf("no slot %#x", id)
	}
	return s
}

func provisionAll(t *testing.T, b *backend) map[keystore.Role]ssh.PublicKey {
	t.Helper()
	pubs, err := b.Provision(allRoles)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return pubs
}

// TestPIVRefusals: every refusal leaves the card unchanged and opens or
// generates nothing it should not.
func TestPIVRefusals(t *testing.T) {
	t.Run("slot_occupied_refused", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		old, err := c.GenerateKey(testMgmtKey, mustSlot(t, 0x82), ykpiv.Key{
			Algorithm: ykpiv.AlgorithmEd25519, PINPolicy: ykpiv.PINPolicyOnce, TouchPolicy: ykpiv.TouchPolicyNever,
		})
		if err != nil {
			t.Fatal(err)
		}
		c.generateCalls = 0
		b := openFake(t, c, validOpts(t))
		if _, err := b.Provision(allRoles); !errors.Is(err, ErrSlotOccupied) {
			t.Fatalf("Provision with slot 0x82 occupied: got %v, want ErrSlotOccupied", err)
		}
		if c.generateCalls != 0 || len(c.slots) != 1 || !publicEqual(c.slots[0x82].priv.Public(), old) {
			t.Fatalf("the card changed: %d GenerateKey calls, %d slots", c.generateCalls, len(c.slots))
		}
	})
	t.Run("slot_unreadable_refused", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		c.infoErr = map[uint32]error{0x84: errors.New("fake card: transmit failed")}
		b := openFake(t, c, validOpts(t))
		if _, err := b.Provision(allRoles); err == nil || errors.Is(err, ErrSlotOccupied) {
			t.Fatalf("Provision with an unreadable slot: got %v, want a read error", err)
		}
		if c.generateCalls != 0 {
			t.Fatalf("%d GenerateKey calls after a refusal", c.generateCalls)
		}
	})
	t.Run("provision_without_mgmt_key_refused", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		opts := validOpts(t)
		delete(opts, "mgmt-key-file")
		b := openFake(t, c, opts)
		if _, err := b.Provision(allRoles); err == nil || !strings.Contains(err.Error(), "mgmt-key-file") {
			t.Fatalf("Provision without a management key: got %v", err)
		}
		if c.generateCalls != 0 {
			t.Fatalf("%d GenerateKey calls after a refusal", c.generateCalls)
		}
	})

	for _, tc := range []struct {
		name string
		opts func(t *testing.T) map[string]string
		want string
	}{
		{"pin_file_mode_0644_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			o["pin-file"] = writeSecret(t, "pin", testPIN, 0o644)
			return o
		}, "mode 0644"},
		{"mgmt_key_file_mode_0640_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			o["mgmt-key-file"] = writeSecret(t, "mgmt-key", hex.EncodeToString(testMgmtKey), 0o640)
			return o
		}, "mode 0640"},
		{"pin_file_symlink_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			link := filepath.Join(t.TempDir(), "pin-link")
			if err := os.Symlink(o["pin-file"], link); err != nil {
				t.Fatal(err)
			}
			o["pin-file"] = link
			return o
		}, "not a regular file"},
		{"pin_file_missing_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			delete(o, "pin-file")
			return o
		}, "pin-file is required"},
		{"default_pin_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			o["pin-file"] = writeSecret(t, "pin", ykpiv.DefaultPIN+"\n", 0o600)
			return o
		}, "default PIN"},
		{"default_mgmt_key_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			o["mgmt-key-file"] = writeSecret(t, "mgmt-key", hex.EncodeToString(ykpiv.DefaultManagementKey)+"\n", 0o600)
			return o
		}, "default management key"},
		{"mgmt_key_not_hex_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			o["mgmt-key-file"] = writeSecret(t, "mgmt-key", "not hex", 0o600)
			return o
		}, "hex"},
		{"unknown_option_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			o["pin"] = testPIN
			return o
		}, "unknown backend option"},
		{"bad_serial_refused", func(t *testing.T) map[string]string {
			o := validOpts(t)
			o["serial"] = "0x1234"
			return o
		}, "serial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newFakeCard(5, 7, 0)
			if b, err := newWithCard(c, tc.opts(t)); err == nil || !strings.Contains(err.Error(), tc.want) {
				if b != nil {
					_ = b.Close()
				}
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
			if c.pinAttempts != 0 {
				t.Fatalf("an option refusal sent the PIN to the card (%d attempts)", c.pinAttempts)
			}
		})
	}

	t.Run("firmware_5.2.7_refused", func(t *testing.T) {
		c := newFakeCard(5, 2, 7)
		if _, err := newWithCard(c, validOpts(t)); err == nil || !strings.Contains(err.Error(), "5.3.0") {
			t.Fatalf("firmware 5.2.7: got %v, want a refusal", err)
		}
		if !c.closed || c.pinAttempts != 0 {
			t.Fatalf("refused firmware: card closed %v, %d PIN attempts; want closed and none", c.closed, c.pinAttempts)
		}
	})

	t.Run("wrong_fingerprint_refused", func(t *testing.T) {
		b := openFake(t, newFakeCard(5, 7, 0), validOpts(t))
		pubs := provisionAll(t, b)
		if _, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleHost])); !errors.Is(err, ErrKeyNotPresent) {
			t.Fatalf("Key with the fingerprint of the host key: got %v, want ErrKeyNotPresent", err)
		}
	})
	t.Run("empty_slot_refused", func(t *testing.T) {
		b := openFake(t, newFakeCard(5, 7, 0), validOpts(t))
		if _, err := b.Key(keystore.RoleUser, "SHA256:AAAA"); !errors.Is(err, ErrKeyNotPresent) {
			t.Fatalf("Key on an empty slot: got %v, want ErrKeyNotPresent", err)
		}
	})
	t.Run("unknown_role_refused", func(t *testing.T) {
		b := openFake(t, newFakeCard(5, 7, 0), validOpts(t))
		if _, err := b.Provision([]keystore.Role{"admin"}); err == nil {
			t.Fatal("Provision of an unknown role succeeded")
		}
		if _, err := b.Key("admin", "SHA256:AAAA"); err == nil {
			t.Fatal("Key of an unknown role succeeded")
		}
	})
	t.Run("imported_key_refused", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		b := openFake(t, c, validOpts(t))
		pubs := provisionAll(t, b)
		c.slots[0x82].info.Origin = ykpiv.OriginImported
		if _, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleUser])); err == nil || !strings.Contains(err.Error(), "not generated on the card") {
			t.Fatalf("Key on an imported key: got %v", err)
		}
	})
	// A wrong PIN fails once, when the backend opens the card, not at every
	// signing request (each failure costs one of the card's PIN retries).
	t.Run("wrong_pin_refused", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		c.pin = "87654321"
		if _, err := newWithCard(c, validOpts(t)); err == nil || !strings.Contains(err.Error(), "refused the PIN") {
			t.Fatalf("open with a wrong PIN: got %v, want a refusal", err)
		}
		if c.pinAttempts != 1 || !c.closed {
			t.Fatalf("wrong PIN: %d PIN attempts, card closed %v; want 1 attempt and a closed card", c.pinAttempts, c.closed)
		}
	})
}

// TestPIVSignWithoutMgmtKey: after provisioning, the backend signs with
// only the PIN (mgmt-key-file overridden to empty, as serve does once the
// management key is moved off the host) and refuses to provision.
func TestPIVSignWithoutMgmtKey(t *testing.T) {
	c := newFakeCard(5, 4, 3)
	opts := validOpts(t)
	b, err := newWithCard(c, opts)
	if err != nil {
		t.Fatal(err)
	}
	pubs := provisionAll(t, b)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	opts["mgmt-key-file"] = ""
	b = openFake(t, c, opts)
	k, err := b.Key(keystore.RoleUser, ssh.FingerprintSHA256(pubs[keystore.RoleUser]))
	if err != nil {
		t.Fatalf("Key without a management key: %v", err)
	}
	issue(t, k, pubs[keystore.RoleUser])
	if _, err := b.Provision([]keystore.Role{keystore.RoleUser}); err == nil {
		t.Fatal("Provision without a management key succeeded")
	}
}

// TestPIVConcurrency: eight goroutines open and use keys of one backend at
// once. The fake card counts signatures without a lock, so -race fails
// this test if the backend does not serialise card access.
func TestPIVConcurrency(t *testing.T) {
	t.Run("concurrent_sign", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		b := openFake(t, c, validOpts(t))
		pubs := provisionAll(t, b)
		const workers, perWorker = 8, 16
		var wg sync.WaitGroup
		errs := make(chan error, workers)
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				role := allRoles[w%len(allRoles)]
				k, err := b.Key(role, ssh.FingerprintSHA256(pubs[role]))
				if err != nil {
					errs <- err
					return
				}
				for i := range perWorker {
					msg := fmt.Appendf(nil, "worker %d message %d", w, i)
					sig, err := k.Sign(rand.Reader, msg)
					if err != nil {
						errs <- err
						return
					}
					if err := pubs[role].Verify(msg, sig); err != nil {
						errs <- fmt.Errorf("worker %d: signature %d does not verify: %w", w, i, err)
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if c.signs != workers*perWorker {
			t.Fatalf("the card made %d signatures, want %d", c.signs, workers*perWorker)
		}
	})
}
