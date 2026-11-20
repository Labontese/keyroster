//go:build piv && pivfake

package piv

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
// in-memory PIV card with real Ed25519 and ECDSA keys (fake.go, compiled
// only with the pivfake tag, as these tests are). They do not run
// yubikey.go or piv-go's signing code; see docs/security/needs-hardware.md.

var allRoles = []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog}

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

// TestPIVPINRetriesGuard (D-CR-01): a signer restarted again and again with
// a wrong PIN in pin-file never spends the card's last PIN retries. Every
// refusal wraps keystore.ErrCredentialRefused, which keyroster-signer turns
// into the exit status its systemd unit does not restart on.
func TestPIVPINRetriesGuard(t *testing.T) {
	t.Run("restart_loop_keeps_last_retry", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		c.pin = "87654321" // pin-file holds testPIN: wrong for this card
		opts := validOpts(t)
		for start := 1; start <= 10; start++ {
			c.closed = false
			_, err := newWithCard(c, opts)
			if err == nil {
				t.Fatalf("start %d: open with a wrong PIN succeeded", start)
			}
			if !errors.Is(err, keystore.ErrCredentialRefused) {
				t.Fatalf("start %d: %v, want it to wrap keystore.ErrCredentialRefused", start, err)
			}
			if !c.closed {
				t.Fatalf("start %d: the refused card was not closed", start)
			}
			if c.pinRetries < 1 {
				t.Fatalf("start %d: the PIN retry counter reached %d; the backend spent the card's last retry", start, c.pinRetries)
			}
		}
		if c.pinAttempts != fakePINRetries-minPINRetries+1 {
			t.Fatalf("%d PIN attempts over ten starts, want %d", c.pinAttempts, fakePINRetries-minPINRetries+1)
		}
		if c.pinRetries != minPINRetries-1 {
			t.Fatalf("%d PIN retries left, want %d", c.pinRetries, minPINRetries-1)
		}
	})
	t.Run("too_few_retries_refused_before_verify", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		c.pinRetries = minPINRetries - 1
		_, err := newWithCard(c, validOpts(t)) // the right PIN: still not tried
		if !errors.Is(err, keystore.ErrCredentialRefused) || !strings.Contains(err.Error(), "PIN retries left") {
			t.Fatalf("open with %d retries left: %v, want a retries refusal wrapping keystore.ErrCredentialRefused", minPINRetries-1, err)
		}
		if c.pinAttempts != 0 || !c.closed {
			t.Fatalf("%d PIN attempts, card closed %v; want none and a closed card", c.pinAttempts, c.closed)
		}
	})
	t.Run("retries_unreadable_refused", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		c.retriesErr = errors.New("fake card: transmit failed")
		_, err := newWithCard(c, validOpts(t))
		if err == nil || !strings.Contains(err.Error(), "PIN retry counter") {
			t.Fatalf("open with an unreadable retry counter: %v, want a refusal", err)
		}
		if c.pinAttempts != 0 || !c.closed {
			t.Fatalf("%d PIN attempts, card closed %v; want none and a closed card", c.pinAttempts, c.closed)
		}
	})
	t.Run("right_pin_with_enough_retries_opens", func(t *testing.T) {
		c := newFakeCard(5, 7, 0)
		c.pinRetries = minPINRetries
		b := openFake(t, c, validOpts(t))
		if c.pinAttempts != 1 || c.pinRetries != fakePINRetries {
			t.Fatalf("%d PIN attempts, %d retries left; want 1 and a reset counter of %d", c.pinAttempts, c.pinRetries, fakePINRetries)
		}
		_ = b
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

// fp is a key's SHA-256 fingerprint, as a generation row pins it.
func fp(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }

// putKey generates a key into slot id directly on the card, as a key put
// there by hand or another tool would be, and returns its public key. It
// goes around the backend, and it counts as a generate attempt: tests take
// their counts after it.
func putKey(t *testing.T, c *fakeCard, id uint32) crypto.PublicKey {
	t.Helper()
	pub, err := c.GenerateKey(testMgmtKey, mustSlot(t, id), ykpiv.Key{
		Algorithm: ykpiv.AlgorithmEd25519, PINPolicy: ykpiv.PINPolicyOnce, TouchPolicy: ykpiv.TouchPolicyNever,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// cardState is what a test compares to show that the card did not change:
// the public key in each occupied slot and the generate attempts.
type cardState struct {
	keys     map[uint32]crypto.PublicKey
	attempts int
}

func stateOf(c *fakeCard) cardState {
	s := cardState{keys: map[uint32]crypto.PublicKey{}, attempts: c.generateAttempts}
	for id, slot := range c.slots {
		s.keys[id] = slot.priv.Public()
	}
	return s
}

// unchanged fails the test if any slot of c holds another key than in
// before, a slot was filled or emptied, or a generate was attempted.
func unchanged(t *testing.T, what string, before cardState, c *fakeCard) {
	t.Helper()
	if c.generateAttempts != before.attempts {
		t.Fatalf("%s: %d generate attempts, want none", what, c.generateAttempts-before.attempts)
	}
	slotsKept(t, what, before, c, 0)
}

// slotsKept fails the test if any slot of c other than except (0: none)
// holds another key than in before, or was filled or emptied.
func slotsKept(t *testing.T, what string, before cardState, c *fakeCard, except uint32) {
	t.Helper()
	for id := uint32(0x82); id <= 0x95; id++ {
		if id == except {
			continue
		}
		old, had := before.keys[id]
		s, has := c.slots[id]
		if had != has || (has && !publicEqual(s.priv.Public(), old)) {
			t.Fatalf("%s: slot %x changed (held a key before: %v, now: %v)", what, id, had, has)
		}
	}
}

// genBackend opens a backend with a management key on a new fake card of
// the given firmware and provisions the five genesis keys (slots 0x82 to
// 0x86).
func genBackend(t *testing.T, major, minor, patch int) (*fakeCard, *backend, map[keystore.Role]ssh.PublicKey) {
	t.Helper()
	c := newFakeCard(major, minor, patch)
	b := openFake(t, c, validOpts(t))
	return c, b, provisionAll(t, b)
}

// withGeneration2 is genBackend on firmware 5.7.0 plus generation 2 of
// user, which the allocator puts in slot 0x87 (location "87"). The
// genesis slot 0x82 then holds fp1 and only the recorded slot holds fp2.
func withGeneration2(t *testing.T) (c *fakeCard, b *backend, pub1, pub2 ssh.PublicKey, loc2 string) {
	t.Helper()
	c, b, pubs := genBackend(t, 5, 7, 0)
	pub2, loc2, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil)
	if err != nil {
		t.Fatalf("ProvisionGeneration(user, 2): %v", err)
	}
	if loc2 != "87" {
		t.Fatalf("generation 2 of user at location %q, want 87", loc2)
	}
	return c, b, pubs[keystore.RoleUser], pub2, loc2
}

// slotHolds reports whether slot id of c holds pub.
func slotHolds(c *fakeCard, id uint32, pub ssh.PublicKey) bool {
	s, ok := c.slots[id]
	return ok && publicEqual(s.priv.Public(), pub.(ssh.CryptoPublicKey).CryptoPublicKey())
}

// generatedOnCard fails the test unless slot id holds a key that the card
// generated with PIN policy once, touch policy never and alg.
func generatedOnCard(t *testing.T, c *fakeCard, id uint32, alg ykpiv.Algorithm) {
	t.Helper()
	s, ok := c.slots[id]
	if !ok {
		t.Fatalf("slot %x is empty", id)
	}
	if s.info.Origin != ykpiv.OriginGenerated || s.info.PINPolicy != ykpiv.PINPolicyOnce || s.info.TouchPolicy != ykpiv.TouchPolicyNever || s.info.Algorithm != alg {
		t.Fatalf("slot %x: origin %v, PIN policy %v, touch policy %v, algorithm %v; want generated, once, never, %v",
			id, s.info.Origin, s.info.PINPolicy, s.info.TouchPolicy, s.info.Algorithm, alg)
	}
}

// lastGenerated fails the test unless the card's generate log ends in id.
func lastGenerated(t *testing.T, c *fakeCard, id uint32) {
	t.Helper()
	if n := len(c.generated); n == 0 || c.generated[n-1] != id {
		t.Fatalf("the card's generate log %x does not end in %x", c.generated, id)
	}
}

// TestPIVGenerationAllocator (03-12f): a later generation takes the first
// slot from 0x87 to 0x95 that no generation row records, by the rows and
// never by occupancy; it refuses before any card write when every slot is
// recorded, when an entry of used is malformed or repeated, when the
// candidate already holds a key that no row records, and without the
// management key.
func TestPIVGenerationAllocator(t *testing.T) {
	t.Run("first_generation_slot_is_87", func(t *testing.T) {
		c, b, _ := genBackend(t, 5, 7, 0)
		pins := c.pinAttempts
		pub, loc, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil)
		if err != nil {
			t.Fatalf("ProvisionGeneration(user, 2): %v", err)
		}
		if loc != "87" {
			t.Fatalf("location %q, want 87", loc)
		}
		if !slotHolds(c, 0x87, pub) {
			t.Fatal("slot 0x87 does not hold the returned key")
		}
		generatedOnCard(t, c, 0x87, ykpiv.AlgorithmEd25519)
		lastGenerated(t, c, 0x87)
		if c.pinAttempts != pins {
			t.Fatalf("the PIN was sent %d more times, want none (PIN once, verified at open)", c.pinAttempts-pins)
		}
	})
	t.Run("piv_deleted_slot_not_reused", func(t *testing.T) {
		c, b, _ := genBackend(t, 5, 7, 0)
		if _, loc, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil); err != nil || loc != "87" {
			t.Fatalf("ProvisionGeneration(user, 2): location %q, %v; want 87", loc, err)
		}
		delete(c.slots, 0x87) // emptied, as an operator's ykman delete would
		n := len(c.generated)
		pub, loc, err := b.ProvisionGeneration(keystore.RoleUser, 3, []string{"87"})
		if err != nil {
			t.Fatalf("ProvisionGeneration(user, 3, [87]): %v", err)
		}
		if loc != "88" || !slotHolds(c, 0x88, pub) {
			t.Fatalf("generation 3 at location %q, want 88 holding its key", loc)
		}
		if _, ok := c.slots[0x87]; ok {
			t.Fatal("the emptied recorded slot 0x87 was used again")
		}
		if got := c.generated[n:]; len(got) != 1 || got[0] != 0x88 {
			t.Fatalf("the card generated into %x, want only 88", got)
		}
	})
	t.Run("piv_no_free_slot_refused", func(t *testing.T) {
		c, b, _ := genBackend(t, 5, 7, 0)
		var used []string
		for id := 0x87; id <= 0x94; id++ {
			used = append(used, fmt.Sprintf("%x", id))
		}
		if _, loc, err := b.ProvisionGeneration(keystore.RoleUser, 2, used); err != nil || loc != "95" {
			t.Fatalf("ProvisionGeneration with 14 of 15 recorded: location %q, %v; want 95", loc, err)
		}
		used = append(used, "95")
		before := stateOf(c)
		_, _, err := b.ProvisionGeneration(keystore.RoleUser, 3, used)
		if !errors.Is(err, ErrNoFreeSlot) || !strings.Contains(err.Error(), "every generation slot from 0x87 to 0x95") {
			t.Fatalf("ProvisionGeneration with all 15 recorded: got %v, want ErrNoFreeSlot", err)
		}
		unchanged(t, "piv_no_free_slot", before, c)
	})
	t.Run("never_overwrites", func(t *testing.T) {
		_, b, _ := genBackend(t, 5, 7, 0)
		if _, loc, err := b.ProvisionGeneration(keystore.RoleUser, 2, []string{"87"}); err != nil || loc != "88" {
			t.Fatalf("ProvisionGeneration(user, 2, [87]): location %q, %v; want 88", loc, err)
		}
		c, b, _ := genBackend(t, 5, 7, 0)
		putKey(t, c, 0x87) // a key that no generation row records
		for i := 1; i <= 2; i++ {
			before := stateOf(c)
			_, _, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil)
			if !errors.Is(err, ErrSlotOccupied) {
				t.Fatalf("call %d with an unrecorded key in 0x87: got %v, want ErrSlotOccupied", i, err)
			}
			for _, want := range []string{"slot 87", "nothing was generated", "until the slot is emptied", "(docs/backends/piv.md)"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("call %d: %q does not contain %q", i, err, want)
				}
			}
			unchanged(t, "never_overwrites", before, c)
		}
	})
	t.Run("used_malformed_refused", func(t *testing.T) {
		_, b, _ := genBackend(t, 5, 7, 0)
		if _, loc, err := b.ProvisionGeneration(keystore.RoleUser, 2, []string{"87"}); err != nil || loc != "88" {
			t.Fatalf("ProvisionGeneration(user, 2, [87]): location %q, %v; want 88", loc, err)
		}
		for _, used := range [][]string{{"0x87"}, {"8A"}, {"86"}, {"96"}, {"87", "87"}} {
			c, b, _ := genBackend(t, 5, 7, 0)
			before, infos := stateOf(c), c.infoCalls
			if _, _, err := b.ProvisionGeneration(keystore.RoleUser, 2, used); err == nil {
				t.Fatalf("ProvisionGeneration with used %q succeeded", used)
			}
			if c.infoCalls != infos {
				t.Fatalf("used %q: %d slot reads before the refusal, want none", used, c.infoCalls-infos)
			}
			unchanged(t, fmt.Sprintf("used %q", used), before, c)
		}
	})
	t.Run("without_mgmt_key_refused", func(t *testing.T) {
		if _, loc, err := func() (ssh.PublicKey, string, error) {
			_, b, _ := genBackend(t, 5, 7, 0)
			return b.ProvisionGeneration(keystore.RoleUser, 2, nil)
		}(); err != nil || loc != "87" {
			t.Fatalf("ProvisionGeneration with the management key: location %q, %v; want 87", loc, err)
		}
		c := newFakeCard(5, 7, 0)
		opts := validOpts(t)
		delete(opts, "mgmt-key-file")
		b := openFake(t, c, opts)
		before := stateOf(c)
		if _, _, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil); err == nil || !strings.Contains(err.Error(), "mgmt-key-file") {
			t.Fatalf("ProvisionGeneration without mgmt-key-file: got %v, want a refusal naming mgmt-key-file", err)
		}
		unchanged(t, "without mgmt-key-file", before, c)
	})
	t.Run("generation_below_2_refused", func(t *testing.T) {
		c, b, _ := genBackend(t, 5, 7, 0)
		if _, loc, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil); err != nil || loc != "87" {
			t.Fatalf("ProvisionGeneration(user, 2): location %q, %v; want 87", loc, err)
		}
		for _, g := range []uint32{0, 1} {
			before := stateOf(c)
			if _, _, err := b.ProvisionGeneration(keystore.RoleUser, g, nil); err == nil {
				t.Fatalf("ProvisionGeneration(user, %d) succeeded", g)
			}
			unchanged(t, fmt.Sprintf("generation %d", g), before, c)
		}
	})
	t.Run("ops_and_log_allocate_from_the_same_pool", func(t *testing.T) {
		c, b, _ := genBackend(t, 5, 7, 0)
		pub, loc, err := b.ProvisionGeneration(keystore.RoleOps, 2, []string{"87"})
		if err != nil || loc != "88" || !slotHolds(c, 0x88, pub) {
			t.Fatalf("ProvisionGeneration(ops, 2, [87]): location %q, %v; want 88 holding its key", loc, err)
		}
		pub, loc, err = b.ProvisionGeneration(keystore.RoleLog, 2, []string{"87", "88"})
		if err != nil || loc != "89" || !slotHolds(c, 0x89, pub) {
			t.Fatalf("ProvisionGeneration(log, 2, [87 88]): location %q, %v; want 89 holding its key", loc, err)
		}
	})
	t.Run("algorithm_by_firmware", func(t *testing.T) {
		for _, tc := range []struct {
			major, minor, patch int
			alg                 ykpiv.Algorithm
			sshAlg              string
		}{
			{5, 4, 3, ykpiv.AlgorithmEC256, ssh.KeyAlgoECDSA256},
			{5, 7, 0, ykpiv.AlgorithmEd25519, ssh.KeyAlgoED25519},
		} {
			c, b, _ := genBackend(t, tc.major, tc.minor, tc.patch)
			pub, loc, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil)
			if err != nil || loc != "87" {
				t.Fatalf("firmware %d.%d.%d: location %q, %v; want 87", tc.major, tc.minor, tc.patch, loc, err)
			}
			if pub.Type() != tc.sshAlg {
				t.Fatalf("firmware %d.%d.%d: a %s key, want %s", tc.major, tc.minor, tc.patch, pub.Type(), tc.sshAlg)
			}
			generatedOnCard(t, c, 0x87, tc.alg)
		}
	})
}

// TestGenerationKeyAfterReopen (03-12f): after a reopen, a later
// generation opens only at the slot its row records; the genesis slot is
// never a fall back for it, and generation 1 takes no location.
func TestGenerationKeyAfterReopen(t *testing.T) {
	c := newFakeCard(5, 7, 0)
	opts := validOpts(t)
	b, err := newWithCard(c, opts)
	if err != nil {
		t.Fatal(err)
	}
	pubs := provisionAll(t, b)
	pub2, loc2, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil)
	if err != nil {
		_ = b.Close()
		t.Fatalf("ProvisionGeneration(user, 2): %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b = openFake(t, c, opts)
	pub1 := pubs[keystore.RoleUser]
	fp1, fp2 := fp(pub1), fp(pub2)

	t.Run("generation_2_by_its_slot", func(t *testing.T) {
		k, err := b.KeyAt(keystore.RoleUser, 2, fp2, loc2)
		if err != nil {
			t.Fatalf("KeyAt(user, 2, fp2, %q): %v", loc2, err)
		}
		issue(t, k, pub2)
	})
	t.Run("empty_location_refused", func(t *testing.T) {
		if _, err := b.KeyAt(keystore.RoleUser, 2, fp2, loc2); err != nil {
			t.Fatalf("KeyAt(user, 2, fp2, %q): %v", loc2, err)
		}
		for _, f := range []string{fp2, fp1} {
			if _, err := b.KeyAt(keystore.RoleUser, 2, f, ""); !errors.Is(err, ErrBadLocation) {
				t.Fatalf("KeyAt(user, 2, %s, \"\"): got %v, want ErrBadLocation", f, err)
			}
		}
	})
	t.Run("genesis_key_not_at_generation_slot", func(t *testing.T) {
		if _, err := b.KeyAt(keystore.RoleUser, 2, fp1, loc2); err == nil {
			t.Fatal("KeyAt(user, 2) with generation 1's fingerprint opened a key")
		}
	})
	t.Run("generation_1_with_a_location_refused", func(t *testing.T) {
		k, err := b.KeyAt(keystore.RoleUser, 1, fp1, "")
		if err != nil {
			t.Fatalf("KeyAt(user, 1, fp1, \"\"): %v", err)
		}
		issue(t, k, pub1)
		if _, err := b.KeyAt(keystore.RoleUser, 1, fp1, "82"); !errors.Is(err, ErrBadLocation) {
			t.Fatalf("KeyAt(user, 1, fp1, \"82\"): got %v, want ErrBadLocation", err)
		}
	})
}

// TestPIVGenerationSlots (03-12f): a later generation's location is one of
// the 15 strings "87" to "95"; anything else, and any location for
// generation 1, is ErrBadLocation from KeyAt, Holds and RemoveGeneration,
// with no card write.
func TestPIVGenerationSlots(t *testing.T) {
	t.Run("location_range_refused", func(t *testing.T) {
		c, b, _, pub2, _ := withGeneration2(t)
		fp2 := fp(pub2)
		k, err := b.KeyAt(keystore.RoleUser, 2, fp2, "87")
		if err != nil {
			t.Fatalf("KeyAt at 87: %v", err)
		}
		issue(t, k, pub2)
		if _, err := b.KeyAt(keystore.RoleUser, 2, fp2, "95"); !errors.Is(err, ErrKeyNotPresent) {
			t.Fatalf("KeyAt at the empty slot 95: got %v, want ErrKeyNotPresent", err)
		}
		if held, err := b.Holds(keystore.RoleUser, 2, fp2, "87"); !held || err != nil {
			t.Fatalf("Holds at 87: %v, %v; want true, nil", held, err)
		}
		if held, err := b.Holds(keystore.RoleUser, 2, fp2, "95"); held || err != nil {
			t.Fatalf("Holds at the empty slot 95: %v, %v; want false, nil", held, err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, fp2, "95"); err != nil {
			t.Fatalf("RemoveGeneration at the empty slot 95: %v", err)
		}
		for _, loc := range []string{"82", "83", "84", "85", "86", "96", "0x87", "8A", " 87", ""} {
			before := stateOf(c)
			if _, err := b.KeyAt(keystore.RoleUser, 2, fp2, loc); !errors.Is(err, ErrBadLocation) {
				t.Fatalf("KeyAt at %q: got %v, want ErrBadLocation", loc, err)
			}
			if held, err := b.Holds(keystore.RoleUser, 2, fp2, loc); !held || !errors.Is(err, ErrBadLocation) {
				t.Fatalf("Holds at %q: %v, %v; want true with ErrBadLocation", loc, held, err)
			}
			if err := b.RemoveGeneration(keystore.RoleUser, 2, fp2, loc); !errors.Is(err, ErrBadLocation) {
				t.Fatalf("RemoveGeneration at %q: got %v, want ErrBadLocation", loc, err)
			}
			unchanged(t, fmt.Sprintf("location %q", loc), before, c)
		}
	})
	t.Run("generation_1_takes_no_location", func(t *testing.T) {
		c, b, pubs := genBackend(t, 5, 7, 0)
		pub1 := pubs[keystore.RoleUser]
		k, err := b.KeyAt(keystore.RoleUser, 1, fp(pub1), "")
		if err != nil {
			t.Fatalf("KeyAt(user, 1, fp1, \"\"): %v", err)
		}
		issue(t, k, pub1)
		before := stateOf(c)
		if _, err := b.KeyAt(keystore.RoleUser, 1, fp(pub1), "82"); !errors.Is(err, ErrBadLocation) {
			t.Fatalf("KeyAt(user, 1) at 82: got %v, want ErrBadLocation", err)
		}
		if held, err := b.Holds(keystore.RoleUser, 1, fp(pub1), "82"); !held || !errors.Is(err, ErrBadLocation) {
			t.Fatalf("Holds(user, 1) at 82: %v, %v; want true with ErrBadLocation", held, err)
		}
		if err := b.RemoveGeneration(keystore.RoleUser, 1, fp(pub1), "82"); !errors.Is(err, ErrBadLocation) {
			t.Fatalf("RemoveGeneration(user, 1) at 82: got %v, want ErrBadLocation", err)
		}
		unchanged(t, "generation 1 at 82", before, c)
	})
}

// TestPIVHolds (03-12f): Holds reads the recorded slot and compares the
// key, never its occupancy: the draining fingerprint is held, another key
// or an empty slot is not, and a read error or a bad location is held with
// the error. Each leaf has its own card.
func TestPIVHolds(t *testing.T) {
	t.Run("held_by_fingerprint", func(t *testing.T) {
		_, b, _, pub2, loc2 := withGeneration2(t)
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), loc2); !held || err != nil {
			t.Fatalf("Holds(user, 2, fp2, %q): %v, %v; want true, nil", loc2, held, err)
		}
	})
	t.Run("throwaway_not_held", func(t *testing.T) {
		c, b, _, pub2, loc2 := withGeneration2(t)
		putKey(t, c, 0x87) // another key in the recorded slot: still occupied
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), loc2); held || err != nil {
			t.Fatalf("Holds with another key in the slot: %v, %v; want false, nil", held, err)
		}
	})
	t.Run("empty_slot_not_held", func(t *testing.T) {
		c, b, _, pub2, loc2 := withGeneration2(t)
		delete(c.slots, 0x87)
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), loc2); held || err != nil {
			t.Fatalf("Holds on the emptied slot: %v, %v; want false, nil", held, err)
		}
	})
	t.Run("read_error_held", func(t *testing.T) {
		c, b, _, pub2, loc2 := withGeneration2(t)
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), loc2); !held || err != nil {
			t.Fatalf("Holds(user, 2, fp2, %q): %v, %v; want true, nil", loc2, held, err)
		}
		readErr := errors.New("fake card: transmit failed")
		c.infoErr = map[uint32]error{0x87: readErr}
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), loc2); !held || !errors.Is(err, readErr) {
			t.Fatalf("Holds on an unreadable slot: %v, %v; want true with the read error", held, err)
		}
	})
	t.Run("bad_location_held_with_error", func(t *testing.T) {
		_, b, _, pub2, loc2 := withGeneration2(t)
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), loc2); !held || err != nil {
			t.Fatalf("Holds(user, 2, fp2, %q): %v, %v; want true, nil", loc2, held, err)
		}
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), "86"); !held || !errors.Is(err, ErrBadLocation) {
			t.Fatalf("Holds(user, 2) at 86: %v, %v; want true with ErrBadLocation", held, err)
		}
	})
	t.Run("genesis_slot_for_generation_1", func(t *testing.T) {
		_, b, pub1, _, _ := withGeneration2(t)
		if held, err := b.Holds(keystore.RoleUser, 1, fp(pub1), ""); !held || err != nil {
			t.Fatalf("Holds(user, 1, fp1, \"\"): %v, %v; want true, nil", held, err)
		}
	})
}

// TestPIVRemoveGeneration (03-12f): removal overwrites the recorded slot
// with a throwaway key generated on the card, and only when that slot
// holds the draining key; another key or an empty slot is left alone, the
// management key is needed for the write, and a write whose answer was lost
// converges through Holds.
func TestPIVRemoveGeneration(t *testing.T) {
	// overwritten fails the test unless slot id no longer holds pub and
	// holds a key the card generated, the last one it generated, and every
	// other slot is as before.
	overwritten := func(t *testing.T, c *fakeCard, before cardState, id uint32, pub ssh.PublicKey) {
		t.Helper()
		if slotHolds(c, id, pub) {
			t.Fatalf("slot %x still holds the draining key", id)
		}
		generatedOnCard(t, c, id, ykpiv.AlgorithmEd25519)
		lastGenerated(t, c, id)
		slotsKept(t, "the other slots", before, c, id)
	}
	t.Run("overwrites_the_genesis_slot", func(t *testing.T) {
		c, b, pubs := genBackend(t, 5, 7, 0)
		pub1 := pubs[keystore.RoleUser]
		before := stateOf(c)
		if err := b.RemoveGeneration(keystore.RoleUser, 1, fp(pub1), ""); err != nil {
			t.Fatalf("RemoveGeneration(user, 1, fp1, \"\"): %v", err)
		}
		overwritten(t, c, before, 0x82, pub1)
		if held, err := b.Holds(keystore.RoleUser, 1, fp(pub1), ""); held || err != nil {
			t.Fatalf("Holds after the removal: %v, %v; want false, nil", held, err)
		}
	})
	t.Run("overwrites_a_generation_slot", func(t *testing.T) {
		c, b, _, pub2, loc2 := withGeneration2(t)
		before := stateOf(c)
		if err := b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2); err != nil {
			t.Fatalf("RemoveGeneration(user, 2, fp2, %q): %v", loc2, err)
		}
		overwritten(t, c, before, 0x87, pub2)
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), loc2); held || err != nil {
			t.Fatalf("Holds after the removal: %v, %v; want false, nil", held, err)
		}
	})
	t.Run("other_key_refused", func(t *testing.T) {
		if err := func() error {
			_, b, _, pub2, loc2 := withGeneration2(t)
			return b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2)
		}(); err != nil {
			t.Fatalf("RemoveGeneration of the draining key in a second backend: %v", err)
		}
		c, b, _, pub2, loc2 := withGeneration2(t)
		putKey(t, c, 0x87)
		before := stateOf(c)
		if err := b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2); !errors.Is(err, ErrSlotHoldsAnotherKey) {
			t.Fatalf("RemoveGeneration with another key in the slot: got %v, want ErrSlotHoldsAnotherKey", err)
		}
		unchanged(t, "another key in the slot", before, c)
	})
	t.Run("empty_slot_writes_nothing", func(t *testing.T) {
		c, b, _, pub2, loc2 := withGeneration2(t)
		delete(c.slots, 0x87)
		before := stateOf(c)
		if err := b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2); err != nil {
			t.Fatalf("RemoveGeneration on the emptied slot: %v, want nil", err)
		}
		unchanged(t, "the emptied slot", before, c)
	})
	t.Run("without_mgmt_key_refused", func(t *testing.T) {
		if err := func() error {
			_, b, _, pub2, loc2 := withGeneration2(t)
			return b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2)
		}(); err != nil {
			t.Fatalf("RemoveGeneration with the management key: %v", err)
		}
		c, b, _, pub2, loc2 := withGeneration2(t)
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		opts := validOpts(t)
		delete(opts, "mgmt-key-file")
		b = openFake(t, c, opts)
		before := stateOf(c)
		err := b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2)
		if err == nil || !strings.Contains(err.Error(), "mgmt-key-file") || !strings.Contains(err.Error(), "--backend-opt") {
			t.Fatalf("RemoveGeneration without mgmt-key-file: got %v, want a refusal naming mgmt-key-file and --backend-opt", err)
		}
		unchanged(t, "without mgmt-key-file", before, c)
		if !slotHolds(c, 0x87, pub2) {
			t.Fatal("the slot no longer holds the draining key")
		}
	})
	t.Run("half_finished_overwrite_converges", func(t *testing.T) {
		c, b, _, pub2, loc2 := withGeneration2(t)
		c.genFail = map[uint32]fakeGenFailure{0x87: genFailAfterReplace}
		if err := b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2); err == nil {
			t.Fatal("RemoveGeneration returned nil although the card's answer was lost")
		}
		if held, err := b.Holds(keystore.RoleUser, 2, fp(pub2), loc2); held || err != nil {
			t.Fatalf("Holds after the lost answer: %v, %v; want false, nil", held, err)
		}
		before := stateOf(c)
		if err := b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2); !errors.Is(err, ErrSlotHoldsAnotherKey) {
			t.Fatalf("the second RemoveGeneration: got %v, want ErrSlotHoldsAnotherKey", err)
		}
		unchanged(t, "the second RemoveGeneration", before, c)
	})
	t.Run("bad_location_refused", func(t *testing.T) {
		c, b, _, pub2, loc2 := withGeneration2(t)
		before, infos := stateOf(c), c.infoCalls
		if err := b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), "86"); !errors.Is(err, ErrBadLocation) {
			t.Fatalf("RemoveGeneration(user, 2) at 86: got %v, want ErrBadLocation", err)
		}
		if c.infoCalls != infos {
			t.Fatalf("%d slot reads before the refusal, want none", c.infoCalls-infos)
		}
		unchanged(t, "location 86", before, c)
		if err := b.RemoveGeneration(keystore.RoleUser, 2, fp(pub2), loc2); err != nil {
			t.Fatalf("RemoveGeneration(user, 2) at %q: %v", loc2, err)
		}
	})
}

// mgmtKeyWrite is one card write that reads the management key: Provision
// on a new card, ProvisionGeneration and RemoveGeneration of generation 1
// on a card with the genesis keys.
type mgmtKeyWrite struct {
	name string
	// setup provisions what the write needs, with a valid management-key
	// file at path, and returns the draining key the write must leave in
	// place on a refusal (nil: none).
	setup func(t *testing.T, b *backend) ssh.PublicKey
	write func(b *backend, drain ssh.PublicKey) error
}

var mgmtKeyWrites = []mgmtKeyWrite{
	{"Provision", func(*testing.T, *backend) ssh.PublicKey { return nil },
		func(b *backend, _ ssh.PublicKey) error { _, err := b.Provision(allRoles); return err }},
	{"ProvisionGeneration", func(t *testing.T, b *backend) ssh.PublicKey { provisionAll(t, b); return nil },
		func(b *backend, _ ssh.PublicKey) error {
			_, _, err := b.ProvisionGeneration(keystore.RoleUser, 2, nil)
			return err
		}},
	{"RemoveGeneration", func(t *testing.T, b *backend) ssh.PublicKey { return provisionAll(t, b)[keystore.RoleUser] },
		func(b *backend, drain ssh.PublicKey) error {
			return b.RemoveGeneration(keystore.RoleUser, 1, fp(drain), "")
		}},
}

// mgmtKeyState opens a backend on a new card with a valid 0600
// management-key file and runs w's setup; it returns the card, the
// backend, the file's path and the draining key.
func mgmtKeyState(t *testing.T, w mgmtKeyWrite) (*fakeCard, *backend, string, ssh.PublicKey) {
	t.Helper()
	c := newFakeCard(5, 7, 0)
	opts := validOpts(t)
	b := openFake(t, c, opts)
	return c, b, opts["mgmt-key-file"], w.setup(t, b)
}

// mgmtKeyWritesSucceed is the positive control of the management-key
// leaves: with a valid file each write succeeds, in a backend of its own.
func mgmtKeyWritesSucceed(t *testing.T) {
	t.Helper()
	for _, w := range mgmtKeyWrites {
		_, b, _, drain := mgmtKeyState(t, w)
		if err := w.write(b, drain); err != nil {
			t.Fatalf("%s with a valid mgmt-key-file: %v", w.name, err)
		}
	}
}

// refusedAtWrite fails the test unless err refuses the write naming
// mgmt-key-file, the path and want, the card is unchanged, and a draining
// key is still in its slot.
func refusedAtWrite(t *testing.T, what string, err error, path, want string, before cardState, c *fakeCard, drain ssh.PublicKey) {
	t.Helper()
	if err == nil || !strings.HasPrefix(err.Error(), "keystore piv: mgmt-key-file ") || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), want) {
		t.Fatalf("%s: got %v, want a refusal that begins %q and names %s and %q", what, err, "keystore piv: mgmt-key-file ", path, want)
	}
	unchanged(t, what, before, c)
	if drain != nil && !slotHolds(c, 0x82, drain) {
		t.Fatalf("%s: slot 82 no longer holds the draining key", what)
	}
}

// TestPIVManagementKeyAtUse (03-12f): the backend never reads the
// management-key file at open, so every command that does not write to the
// card opens with the file missing or one it would refuse; each card write
// (Provision, ProvisionGeneration, RemoveGeneration) reads and checks it
// first and refuses a missing or refused file before any card write. Each
// leaf has its own cards, files and backends.
func TestPIVManagementKeyAtUse(t *testing.T) {
	t.Run("open_with_the_file_missing", func(t *testing.T) {
		c, b, pubs := genBackend(t, 5, 7, 0)
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		opts := validOpts(t)
		opts["mgmt-key-file"] = filepath.Join(t.TempDir(), "absent")
		pins := c.pinAttempts
		b = openFake(t, c, opts)
		if c.pinAttempts != pins+1 {
			t.Fatalf("open sent the PIN %d times, want once", c.pinAttempts-pins)
		}
		k, err := b.Key(keystore.RoleUser, fp(pubs[keystore.RoleUser]))
		if err != nil {
			t.Fatalf("Key with mgmt-key-file missing: %v", err)
		}
		issue(t, k, pubs[keystore.RoleUser])
		fresh := newFakeCard(5, 7, 0)
		fb := openFake(t, fresh, opts)
		if _, err := fb.Provision(allRoles); err == nil || !strings.Contains(err.Error(), "mgmt-key-file") {
			t.Fatalf("Provision with mgmt-key-file missing: got %v, want a refusal naming mgmt-key-file", err)
		}
		if fresh.generateAttempts != 0 {
			t.Fatalf("%d generate attempts after the refusal", fresh.generateAttempts)
		}
	})
	t.Run("open_does_not_read_the_file", func(t *testing.T) {
		c, b, pubs := genBackend(t, 5, 7, 0)
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		for _, mk := range []struct{ content, mode string }{
			{hex.EncodeToString(testMgmtKey) + "\n", "0640"},
			{hex.EncodeToString(ykpiv.DefaultManagementKey) + "\n", "0600"},
		} {
			perm := os.FileMode(0o600)
			if mk.mode == "0640" {
				perm = 0o640
			}
			opts := validOpts(t)
			opts["mgmt-key-file"] = writeSecret(t, "mgmt-key", mk.content, perm)
			nb, err := newWithCard(c, opts)
			if err != nil {
				t.Fatalf("open with a mode %s management-key file: %v", mk.mode, err)
			}
			k, err := nb.Key(keystore.RoleUser, fp(pubs[keystore.RoleUser]))
			if err != nil {
				_ = nb.Close()
				t.Fatalf("Key: %v", err)
			}
			issue(t, k, pubs[keystore.RoleUser])
			if err := nb.Close(); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("missing_file_refused_at_each_write", func(t *testing.T) {
		mgmtKeyWritesSucceed(t)
		for _, w := range mgmtKeyWrites {
			c, b, path, drain := mgmtKeyState(t, w)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			before := stateOf(c)
			refusedAtWrite(t, w.name+" with the file removed", w.write(b, drain), path, "", before, c, drain)
		}
	})
	t.Run("invalid_file_refused_at_each_write", func(t *testing.T) {
		mgmtKeyWritesSucceed(t)
		valid := hex.EncodeToString(testMgmtKey) + "\n"
		for _, bad := range []struct {
			name, want string
			put        func(t *testing.T, path string)
		}{
			{"mode_0640", "want 0600 or stricter", func(t *testing.T, path string) {
				t.Helper()
				replaceFile(t, path, valid, 0o640)
			}},
			{"link", "not a regular file", func(t *testing.T, path string) {
				t.Helper()
				target := writeSecret(t, "mgmt-key-target", valid, 0o600)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			}},
			{"not_hex", "hex", func(t *testing.T, path string) {
				t.Helper()
				replaceFile(t, path, "not hex\n", 0o600)
			}},
			{"20_bytes", "want 16, 24 or 32", func(t *testing.T, path string) {
				t.Helper()
				replaceFile(t, path, hex.EncodeToString(bytes.Repeat([]byte{0x11}, 20))+"\n", 0o600)
			}},
			{"default_key", "default management key", func(t *testing.T, path string) {
				t.Helper()
				replaceFile(t, path, hex.EncodeToString(ykpiv.DefaultManagementKey)+"\n", 0o600)
			}},
		} {
			for _, w := range mgmtKeyWrites {
				c, b, path, drain := mgmtKeyState(t, w)
				bad.put(t, path)
				before := stateOf(c)
				refusedAtWrite(t, w.name+" with "+bad.name, w.write(b, drain), path, bad.want, before, c, drain)
			}
		}
		// A well-formed wrong key passes the file checks; the card refuses
		// it at GenerateKey and nothing changes.
		wrong := hex.EncodeToString(bytes.Repeat([]byte{0x3c, 0x96}, 12)) + "\n"
		for _, w := range mgmtKeyWrites {
			c, b, path, drain := mgmtKeyState(t, w)
			replaceFile(t, path, wrong, 0o600)
			before := stateOf(c)
			if err := w.write(b, drain); err == nil {
				t.Fatalf("%s with a wrong management key succeeded", w.name)
			}
			slotsKept(t, w.name+" with a wrong management key", before, c, 0)
		}
	})
}

// replaceFile replaces path with a new regular file holding content with
// mode perm.
func replaceFile(t *testing.T, path, content string, perm os.FileMode) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

// TestPIVFakeRegistry (03-12f): in a pivfake build keystore.Open("piv",
// ...) opens the process-wide fake card of the serial in the options, which
// refuses a second open while it is open, and the exported FakePIN,
// FakeManagementKeyHex and FakeCardGenerated serve a command-level test.
func TestPIVFakeRegistry(t *testing.T) {
	const serial = 1203001 // this test's own card: the registry is process-wide
	opts := map[string]string{
		"pin-file":      writeSecret(t, "pin", FakePIN+"\n", 0o600),
		"mgmt-key-file": writeSecret(t, "mgmt-key", FakeManagementKeyHex+"\n", 0o600),
		"serial":        fmt.Sprint(serial),
	}
	be, err := keystore.Open("piv", opts)
	if err != nil {
		t.Fatalf("keystore.Open(piv) on the fake card: %v", err)
	}
	d, ok := be.(keystore.Describer)
	if !ok || !strings.Contains(d.Describe(), "firmware 5.7.0") {
		_ = be.Close()
		t.Fatalf("the backend does not describe the fake card's firmware 5.7.0 (%v)", ok)
	}
	if second, err := keystore.Open("piv", opts); err == nil || !strings.Contains(err.Error(), "in use") {
		if second != nil {
			_ = second.Close()
		}
		_ = be.Close()
		t.Fatalf("a second open of the card in use: got %v, want a refusal naming the card in use", err)
	}
	if err := be.Close(); err != nil {
		t.Fatal(err)
	}
	be, err = keystore.Open("piv", opts)
	if err != nil {
		t.Fatalf("reopen after Close: %v", err)
	}
	defer func() { _ = be.Close() }()
	p, ok := be.(keystore.Provisioner)
	if !ok {
		t.Fatal("the piv backend is not a Provisioner")
	}
	if _, err := p.Provision(allRoles); err != nil {
		t.Fatalf("Provision on the fake card: %v", err)
	}
	if got, want := FakeCardGenerated(serial), []uint32{0x82, 0x83, 0x84, 0x85, 0x86}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("FakeCardGenerated = %x, want %x", got, want)
	}
}
