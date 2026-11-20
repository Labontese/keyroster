//go:build piv && pivfake

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
	"sync"

	ykpiv "github.com/go-piv/piv-go/v2/piv"
)

// This file is test code: an in-memory fake PIV card, compiled only with
// the pivfake build tag (03-12f) and never into a release binary (piv.yml's
// release guard proves that). The piv package's tests use it directly; in a
// pivfake build, init points the backend's openCard hook at a process-wide
// registry of fake cards, one per serial, so a test at command level opens
// the piv backend through keystore.Open on a fake card.

const (
	testPIN = "40961758"
)

var (
	testMgmtKey = bytes.Repeat([]byte{0x5a, 0xc3}, 12) // 24 bytes, not the default
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
//
// Its PIN retry counter follows piv-go against a YubiKey as documented, not
// as observed on a card: a wrong PIN takes one retry and returns
// ykpiv.AuthErr with the retries left, the right PIN resets the counter, a
// counter at zero blocks the PIN (the right PIN no longer helps), and
// reading the counter in a logged-in session is an error (piv-go's Retries
// sends an empty VERIFY, which then succeeds).
type fakeCard struct {
	major, minor, patch int
	mgmtKey             []byte
	pin                 string
	slots               map[uint32]*fakeSlot
	infoErr             map[uint32]error // injected KeyInfo failures
	loggedIn            bool
	pinAttempts         int
	pinRetries          int   // PIN retries left; 0 means blocked
	retriesErr          error // injected PINRetries failure
	generateCalls       int
	generateAttempts    int                       // GenerateKey calls, counted before the management-key check
	generated           []uint32                  // the slot ids GenerateKey generated into, in order
	genFail             map[uint32]fakeGenFailure // injected GenerateKey failures per slot
	infoCalls           int                       // KeyInfo calls
	signs               int
	closed              bool
}

// fakePINRetries is the fake card's PIN retry limit, the YubiKey default.
const fakePINRetries = 3

func (f *fakeCard) VerifyPIN(pin string) error {
	f.pinAttempts++
	if f.pinRetries == 0 {
		f.loggedIn = false
		return fmt.Errorf("fake card: PIN blocked: %w", ykpiv.AuthErr{Retries: 0})
	}
	if pin != f.pin {
		f.loggedIn = false
		f.pinRetries--
		return fmt.Errorf("fake card: wrong PIN: %w", ykpiv.AuthErr{Retries: f.pinRetries})
	}
	f.pinRetries = fakePINRetries
	f.loggedIn = true
	return nil
}

func (f *fakeCard) PINRetries() (int, error) {
	if f.retriesErr != nil {
		return 0, f.retriesErr
	}
	if f.loggedIn {
		return 0, errors.New("fake card: expected error code from empty pin")
	}
	return f.pinRetries, nil
}

func newFakeCard(major, minor, patch int) *fakeCard {
	return &fakeCard{major: major, minor: minor, patch: patch, mgmtKey: testMgmtKey, pin: testPIN, pinRetries: fakePINRetries, slots: map[uint32]*fakeSlot{}}
}

func (f *fakeCard) Version() (int, int, int) { return f.major, f.minor, f.patch }

func (f *fakeCard) KeyInfo(slot ykpiv.Slot) (ykpiv.KeyInfo, error) {
	f.infoCalls++
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
	f.generateAttempts++
	if !bytes.Equal(mgmtKey, f.mgmtKey) {
		return nil, errors.New("fake card: management key authentication failed")
	}
	if key.PINPolicy != ykpiv.PINPolicyOnce || key.TouchPolicy != ykpiv.TouchPolicyNever {
		return nil, fmt.Errorf("fake card: unexpected policies %v/%v", key.PINPolicy, key.TouchPolicy)
	}
	if f.genFail[slot.Key] == genFailBefore {
		return nil, fmt.Errorf("fake card: generate in slot %s failed (injected)", slot)
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
	f.generated = append(f.generated, slot.Key)
	if f.genFail[slot.Key] == genFailAfterReplace {
		return nil, fmt.Errorf("fake card: the answer for slot %s was lost after the card replaced its key (injected)", slot)
	}
	return priv.Public(), nil
}

// fakeGenFailure is an injected GenerateKey failure of one slot.
type fakeGenFailure int

const (
	// genFailBefore fails before the card acts: the slot is unchanged.
	genFailBefore fakeGenFailure = iota + 1
	// genFailAfterReplace replaces the slot's key and then fails, as a
	// card that acted and whose answer was lost.
	genFailAfterReplace
)

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

// Close ends the card session, so a reopened card is no longer logged in.
func (f *fakeCard) Close() error {
	f.closed = true
	f.loggedIn = false
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

// FakePIN is the PIN of every fake card. It exists only in a pivfake
// build, so that a test at command level can write a pin-file the fake
// accepts.
const FakePIN = testPIN

// FakeManagementKeyHex is the management key of every fake card, in hex.
// It exists only in a pivfake build, so that a test at command level can
// write an mgmt-key-file the fake accepts.
var FakeManagementKeyHex = hex.EncodeToString(testMgmtKey)

// FakeCardGenerated returns a copy of the slot ids the fake card of
// serial generated keys into, in order; nil for a card not yet opened. It
// exists only in a pivfake build.
func FakeCardGenerated(serial uint32) []uint32 {
	fakeRegistry.mu.Lock()
	defer fakeRegistry.mu.Unlock()
	c := fakeRegistry.cards[serial]
	if c == nil {
		return nil
	}
	return append([]uint32(nil), c.generated...)
}

// fakeRegistry holds the process-wide fake cards of a pivfake build, one
// per serial (serial 0 is the card of an option without serial). A card is
// created on first use at firmware 5.7.0 and never removed, so a reopen
// finds the keys an earlier session generated. Its mutex guards the
// registry only: the cards keep no lock of their own (see fakeCard).
var fakeRegistry = struct {
	mu    sync.Mutex
	cards map[uint32]*fakeCard
	inUse map[uint32]*fakeSession // the open session of each card
}{cards: map[uint32]*fakeCard{}, inUse: map[uint32]*fakeSession{}}

// init points the backend's opener at the registry: in a pivfake build
// keystore.Open("piv", ...) opens a fake card and never reaches piv-go.
func init() { openCard = openFakeCard }

// fakeSession is one open session on a registered fake card. Like the
// PC/SC transaction piv-go holds until Close (yubikey.go), it keeps every
// other session of the card out while it is open.
type fakeSession struct {
	*fakeCard
	serial uint32
}

// openFakeCard opens a session on the fake card of serial, creating the
// card on first use. It refuses while an earlier session of that card is
// still open.
func openFakeCard(serial uint32) (card, error) {
	fakeRegistry.mu.Lock()
	defer fakeRegistry.mu.Unlock()
	if fakeRegistry.inUse[serial] != nil {
		return nil, fmt.Errorf("fake card %d is in use by another session", serial)
	}
	c := fakeRegistry.cards[serial]
	if c == nil {
		c = newFakeCard(5, 7, 0)
		fakeRegistry.cards[serial] = c
	}
	s := &fakeSession{fakeCard: c, serial: serial}
	fakeRegistry.inUse[serial] = s
	return s, nil
}

// Close ends the session: it logs the card out, as fakeCard's Close does,
// and releases the card. Only the session that holds the card releases
// it, so a second Close of an ended session cannot end a later session.
func (s *fakeSession) Close() error {
	fakeRegistry.mu.Lock()
	defer fakeRegistry.mu.Unlock()
	if fakeRegistry.inUse[s.serial] != s {
		return nil
	}
	delete(fakeRegistry.inUse, s.serial)
	return s.fakeCard.Close()
}
