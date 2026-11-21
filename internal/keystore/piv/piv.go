//go:build piv

// Package piv is the YubiKey PIV keystore backend, registered as "piv"
// (KEY-05). It is built only with the piv build tag; on Linux piv-go then
// links pcsc-lite through cgo, so default builds (CGO_ENABLED=0, no tags)
// contain neither this package nor piv-go (D-12).
//
// The CA, ops and log keys are generated on the card, one per retired
// key-management slot, so the standard slots 9a-9e stay free for other
// uses:
//
//	user 0x82, host 0x83, machine 0x84, ops 0x85, log 0x86
//
// The algorithm is Ed25519 on firmware 5.7.0 or newer and ECDSA P-256 on
// older firmware (D-09). Firmware older than 5.3.0 is refused, because the
// backend reads each slot's public key and origin through the GET METADATA
// command that 5.3.0 introduced. Keys use PIN policy once and touch policy
// never, so the unattended signer can sign after one PIN verification per
// card session. The backend verifies the PIN when it opens the card and
// refuses to open on a wrong PIN, so a wrong PIN costs one PIN retry per
// signer start rather than one per signing request. Before it sends the
// PIN it reads the card's retry counter and refuses, without trying, when
// fewer than two retries are left, so automatic starts never spend the last
// one. Both refusals wrap keystore.ErrCredentialRefused, on which
// keyroster-signer exits with a status its systemd unit does not restart
// on (D-CR-01).
//
// CA key generations (03-12f). Generation 1 of a role is the role's slot
// above. Every later generation of every role (ops and log included) takes
// a slot from the shared pool 0x87 to 0x95, 15 slots: the first one that no
// generation row records, chosen by the rows and never by whether the slot
// is empty. The row records the slot as its location, two lowercase hex
// digits ("87" to "95", as piv-go's Slot.String writes it), and the slot is
// never reused, even after its key is removed. When every slot is recorded,
// prepare refuses piv_no_free_slot. A candidate slot that already holds a
// key that no row records (a lost prepare, a restored signer.db, a key put
// there by hand) is refused with ErrSlotOccupied and never overwritten, so
// every later PIV prepare stops there until the slot is emptied
// (docs/backends/piv.md). KeyAt, Holds and RemoveGeneration read only the
// slot the row records, and Holds and RemoveGeneration compare the key in
// it, never its occupancy. The backend never overwrites a slot, with one
// exception: RemoveGeneration (retire-key) overwrites the draining
// generation's own slot with a throwaway key generated on the card, on
// every firmware, once the slot's key has the draining fingerprint. piv-go
// v2.6.0 has no delete command, so the slot stays occupied by the
// throwaway key.
//
// Options:
//
//	pin-file       file holding the PIV PIN (required)
//	mgmt-key-file  file holding the PIV management key in hex, read only
//	               when a key is generated or overwritten: by ca-init,
//	               ca-rotate prepare and ca-rotate retire-key
//	serial         serial number of the YubiKey to use (default: the only
//	               attached YubiKey)
//
// Both secret files must be regular files with mode 0600 or stricter. The
// PIN file is read when the backend opens. The management-key file is
// read and checked at the start of each card write, used for that write and
// not kept; every other command (serve, install-bundle, doctor) opens and
// signs without it, so the file can stay off the host between ceremonies.
// The default PIN and the default management key are refused, and so are
// keys that were imported into the card rather than generated on it. Both
// the card's identity (a reader name containing "yubikey") and a key's
// origin are what the card reports; slot attestation is not checked, so
// custody piv is card-reported, not proven (D-WR-04, docs/backends/piv.md).
//
// What CI verifies: everything in this file, through the card interface
// with an in-memory fake card (fake.go, compiled only with the pivfake
// tag). What CI does not verify: yubikey.go (the piv-go calls against a
// real card through pcscd) and piv-go's own signing code, and on a real
// card the generation slots, an overwrite and its effect on the old key.
// Those run first in the Phase 6 needs-hardware review
// (docs/security/needs-hardware.md).
package piv

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	ykpiv "github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
)

// Errors of the PIV backend.
var (
	// ErrKeyNotPresent means the role's slot is empty or holds another key
	// than the pinned one. The backend never falls back to another key.
	ErrKeyNotPresent = errors.New("keystore piv: pinned CA key not present on the card")
	// ErrSlotOccupied means Provision or ProvisionGeneration found a key in
	// a target slot; it generates nothing and overwrites nothing. The one
	// write over an occupied slot is RemoveGeneration's, of the draining
	// generation's own slot after its key matched (03-12f).
	ErrSlotOccupied = errors.New("keystore piv: slot already holds a key")
	// ErrNoFreeSlot means every generation slot from 0x87 to 0x95 is
	// recorded by a generation row: a later generation gets no slot, and
	// nothing is generated (03-12f).
	ErrNoFreeSlot = errors.New("piv_no_free_slot")
	// ErrBadLocation means a generation's location does not resolve to a
	// slot that generation may use (03-12f).
	ErrBadLocation = errors.New("keystore piv: the generation's location names no slot it may use")
	// ErrSlotHoldsAnotherKey means a generation's recorded slot holds
	// another key than the generation's, so it is not overwritten (03-12f).
	ErrSlotHoldsAnotherKey = errors.New("keystore piv: the slot holds another key")
)

// The backend's CA key generations (03-12f).
var (
	_ keystore.GenerationBackend     = (*backend)(nil)
	_ keystore.GenerationProvisioner = (*backend)(nil)
	_ keystore.GenerationHolder      = (*backend)(nil)
	_ keystore.GenerationRemover     = (*backend)(nil)
)

// minPINRetries is the fewest PIN retries the card must have left before
// the backend sends it the PIN. Below that it refuses without trying, so
// automatic starts never spend the card's last retry: a blocked PIN needs
// the PUK, and a blocked PUK means a PIV reset, which destroys the CA keys.
const minPINRetries = 2

// slots maps each role to its retired key-management slot.
var slots = map[keystore.Role]uint32{
	keystore.RoleUser:    0x82,
	keystore.RoleHost:    0x83,
	keystore.RoleMachine: 0x84,
	keystore.RoleOps:     0x85,
	keystore.RoleLog:     0x86,
}

// The pool of generation slots that every role's generations 2 and later
// share (03-12f).
const (
	firstGenerationSlot = 0x87
	lastGenerationSlot  = 0x95
)

func init() { keystore.Register("piv", open) }

// openCard opens the card that open hands to the backend: a real YubiKey
// through piv-go. It is the only seam a pivfake build repoints, to the
// in-memory fake card of fake.go (03-12f); a release build never assigns
// it.
var openCard = openYubiKey

// config is the parsed and checked backend options.
type config struct {
	pin         string
	mgmtKeyFile string // "": no card write is possible; read only at a card write
	serial      uint32 // 0: the only attached YubiKey
}

type backend struct {
	mu   sync.Mutex // serialises every card call: provisioning, metadata, signatures
	card card       // used only under mu
	cfg  config
	ver  [3]int
}

// open checks the options and the PIN file before it touches the card.
func open(opts map[string]string) (keystore.Backend, error) {
	cfg, err := parseOptions(opts)
	if err != nil {
		return nil, err
	}
	c, err := openCard(cfg.serial)
	if err != nil {
		return nil, err
	}
	return newBackend(c, cfg)
}

// newWithCard opens the backend on c, with the same option checks as open.
// The tests use it with a fake card.
func newWithCard(c card, opts map[string]string) (*backend, error) {
	cfg, err := parseOptions(opts)
	if err != nil {
		return nil, err
	}
	return newBackend(c, cfg)
}

// newBackend takes ownership of c; it closes c when it refuses the card.
//
// It verifies the PIN once, here. piv-go checks a PIN only when a key
// signs, so without this a wrong PIN would surface at every signing request
// and each request would use up one of the card's PIN retries: a few
// requests would block the PIN. Verified at open, a wrong PIN costs one
// retry per signer start and the signer refuses to start; with PIN policy
// once, the logged-in session then signs without further PIN checks.
//
// A start loop (a service manager restarting a signer that keeps failing)
// would still spend one retry per start, so it first reads the retry
// counter and refuses to try the PIN with fewer than minPINRetries left. An
// unreadable counter is a refusal too. Every failed VERIFY is treated as a
// spent retry, whatever the error, because the card may have counted it.
func newBackend(c card, cfg config) (*backend, error) {
	major, minor, patch := c.Version()
	b := &backend{card: c, cfg: cfg, ver: [3]int{major, minor, patch}}
	if !b.atLeast(5, 3, 0) {
		_ = c.Close()
		return nil, fmt.Errorf("keystore piv: firmware %d.%d.%d is older than 5.3.0, which the backend needs to read slot metadata", major, minor, patch)
	}
	left, err := c.PINRetries()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("keystore piv: read the card's PIN retry counter (the PIN was not tried): %w", err)
	}
	if left < minPINRetries {
		_ = c.Close()
		return nil, fmt.Errorf("keystore piv: only %d PIN retries left on the card, and the signer does not try the PIN with fewer than %d left; fix pin-file, then check the PIN by hand (docs/backends/piv.md): %w",
			left, minPINRetries, keystore.ErrCredentialRefused)
	}
	if err := c.VerifyPIN(cfg.pin); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("keystore piv: the card refused the PIN in pin-file (%w); fix pin-file before starting again: %w",
			err, keystore.ErrCredentialRefused)
	}
	return b, nil
}

// parseOptions checks the options and reads the PIN file. It keeps the
// mgmt-key-file path only: the file is read at a card write (03-12f).
func parseOptions(opts map[string]string) (config, error) {
	var cfg config
	if err := keystore.CheckOptions(opts, "serial", "pin-file", "mgmt-key-file"); err != nil {
		return cfg, err
	}
	pinFile := opts["pin-file"]
	if pinFile == "" {
		return cfg, errors.New("keystore piv: option pin-file is required")
	}
	pin, err := readSecretFile(pinFile)
	if err != nil {
		return cfg, err
	}
	cfg.pin = strings.TrimRight(string(pin), "\r\n")
	switch {
	case len(cfg.pin) < 6 || len(cfg.pin) > 8:
		return cfg, errors.New("keystore piv: the PIN in pin-file must be 6 to 8 characters")
	case cfg.pin == ykpiv.DefaultPIN:
		return cfg, errors.New("keystore piv: the card's default PIN is refused; change it first (docs/backends/piv.md)")
	}
	cfg.mgmtKeyFile = opts["mgmt-key-file"]
	if s := opts["serial"]; s != "" {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return cfg, fmt.Errorf("keystore piv: serial %q is not a card serial number", s)
		}
		cfg.serial = uint32(n)
	}
	return cfg, nil
}

// managementKey reads and checks the management key of the mgmt-key-file
// option for one card write (03-12f). The caller uses it for that write
// and does not keep it.
func (b *backend) managementKey() ([]byte, error) {
	return readManagementKey(b.cfg.mgmtKeyFile)
}

// readManagementKey reads the management key from path, with the checks a
// secret file gets (a regular file, not a link, no group or other
// permissions), and refuses a key that is not 16, 24 or 32 bytes of hex or
// is the card's default. Every refusal reads "keystore piv: mgmt-key-file
// <path>: <cause>".
func readManagementKey(path string) ([]byte, error) {
	key, err := checkManagementKey(path)
	if err != nil {
		return nil, fmt.Errorf("keystore piv: mgmt-key-file %s: %w", path, err)
	}
	return key, nil
}

func checkManagementKey(path string) ([]byte, error) {
	raw, err := checkSecretFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("must hold the management key in hex: %w", err)
	}
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, fmt.Errorf("the management key is %d bytes, want 16, 24 or 32", len(key))
	}
	if bytes.Equal(key, ykpiv.DefaultManagementKey) {
		return nil, errors.New("the card's default management key is refused; change it first (docs/backends/piv.md)")
	}
	return key, nil
}

func (b *backend) atLeast(major, minor, patch int) bool {
	v := b.ver
	if v[0] != major {
		return v[0] > major
	}
	if v[1] != minor {
		return v[1] > minor
	}
	return v[2] >= patch
}

// algorithm is the key algorithm for this card's firmware (D-09).
func (b *backend) algorithm() (ykpiv.Algorithm, string) {
	if b.atLeast(5, 7, 0) {
		return ykpiv.AlgorithmEd25519, ssh.KeyAlgoED25519
	}
	return ykpiv.AlgorithmEC256, ssh.KeyAlgoECDSA256
}

// Describe names the firmware and the algorithm it gets.
func (b *backend) Describe() string {
	_, alg := b.algorithm()
	return fmt.Sprintf("YubiKey PIV firmware %d.%d.%d → %s keys, custody %s", b.ver[0], b.ver[1], b.ver[2], alg, keystore.CustodyPIV)
}

func slotFor(role keystore.Role) (ykpiv.Slot, error) {
	id, ok := slots[role]
	if !ok {
		return ykpiv.Slot{}, fmt.Errorf("keystore piv: unknown role %q", role)
	}
	s, ok := ykpiv.RetiredKeyManagementSlot(id)
	if !ok {
		return ykpiv.Slot{}, fmt.Errorf("keystore piv: no slot %#x", id)
	}
	return s, nil
}

// parseLocation returns the generation slot a location names: exactly one
// of the 15 strings "87" to "95" (lowercase hex, as piv-go's Slot.String
// writes the slot). Every other string, "0x87", "8A", " 87", "86" and "96"
// among them, is ErrBadLocation.
func parseLocation(location string) (ykpiv.Slot, error) {
	for id := uint32(firstGenerationSlot); id <= lastGenerationSlot; id++ {
		if location != fmt.Sprintf("%x", id) {
			continue
		}
		s, ok := ykpiv.RetiredKeyManagementSlot(id)
		if !ok {
			return ykpiv.Slot{}, fmt.Errorf("keystore piv: no slot %#x", id)
		}
		return s, nil
	}
	return ykpiv.Slot{}, fmt.Errorf("%w (location %q)", ErrBadLocation, location)
}

// generationSlot resolves the slot of generation of role from the
// generation row's location. Generation 1 is the role's own slot and takes
// no location; generation 2 or later is the generation slot its location
// names, never the role's slot. Anything else is ErrBadLocation.
func generationSlot(role keystore.Role, generation uint32, location string) (ykpiv.Slot, error) {
	own, err := slotFor(role)
	if err != nil {
		return ykpiv.Slot{}, err
	}
	switch generation {
	case 0:
		return ykpiv.Slot{}, fmt.Errorf("%w: role %s has no generation 0", ErrBadLocation, role)
	case 1:
		if location != "" {
			return ykpiv.Slot{}, fmt.Errorf("%w: generation 1 of role %s is in slot %s and takes no location, got %q", ErrBadLocation, role, own, location)
		}
		return own, nil
	}
	s, err := parseLocation(location)
	if err != nil {
		return ykpiv.Slot{}, fmt.Errorf("generation %d of role %s: %w", generation, role, err)
	}
	return s, nil
}

// occupied reports whether slot holds a key. Only an error wrapping
// ykpiv.ErrNotFound means empty; any other error is returned, so an
// unreadable slot is never mistaken for an empty one.
func (b *backend) occupied(slot ykpiv.Slot) (bool, error) {
	_, err := b.card.KeyInfo(slot)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, ykpiv.ErrNotFound):
		return false, nil
	default:
		return false, fmt.Errorf("keystore piv: read slot %s: %w", slot, err)
	}
}

// slotKey returns the public key in slot, or nil for an empty slot. Only an
// error wrapping ykpiv.ErrNotFound means empty; any other error is
// returned. The caller holds mu.
func (b *backend) slotKey(slot ykpiv.Slot) (ssh.PublicKey, error) {
	info, err := b.card.KeyInfo(slot)
	if errors.Is(err, ykpiv.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keystore piv: read slot %s: %w", slot, err)
	}
	pub, err := ssh.NewPublicKey(info.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keystore piv: slot %s: %w", slot, err)
	}
	return pub, nil
}

// Provision generates one key per role in the role's slot, with PIN policy
// once and touch policy never. It checks every target slot first and
// refuses, generating nothing, if any slot already holds a key or cannot be
// read. If generation fails part-way, the slots already filled stay
// occupied, so a retry is refused; recovering then means resetting the
// card's PIV application (docs/backends/piv.md).
func (b *backend) Provision(roles []keystore.Role) (map[keystore.Role]ssh.PublicKey, error) {
	if len(roles) == 0 {
		return nil, errors.New("keystore piv: no roles to provision")
	}
	if b.cfg.mgmtKeyFile == "" {
		return nil, errors.New("keystore piv: provisioning needs option mgmt-key-file")
	}
	mgmtKey, err := b.managementKey()
	if err != nil {
		return nil, err
	}
	targets := make(map[keystore.Role]ykpiv.Slot, len(roles))
	for _, role := range roles {
		if _, dup := targets[role]; dup {
			return nil, fmt.Errorf("keystore piv: role %s given twice", role)
		}
		s, err := slotFor(role)
		if err != nil {
			return nil, err
		}
		targets[role] = s
	}
	alg, sshAlg := b.algorithm()

	b.mu.Lock()
	defer b.mu.Unlock()
	for _, role := range roles {
		used, err := b.occupied(targets[role])
		if err != nil {
			return nil, err
		}
		if used {
			return nil, fmt.Errorf("%w: slot %s (role %s); nothing was generated", ErrSlotOccupied, targets[role], role)
		}
	}
	pubs := make(map[keystore.Role]ssh.PublicKey, len(roles))
	for _, role := range roles {
		cpub, err := b.card.GenerateKey(mgmtKey, targets[role], ykpiv.Key{
			Algorithm:   alg,
			PINPolicy:   ykpiv.PINPolicyOnce,
			TouchPolicy: ykpiv.TouchPolicyNever,
		})
		if err != nil {
			return nil, fmt.Errorf("keystore piv: generate the %s key in slot %s: %w", role, targets[role], err)
		}
		pub, err := ssh.NewPublicKey(cpub)
		if err != nil {
			return nil, fmt.Errorf("keystore piv: %s key: %w", role, err)
		}
		if pub.Type() != sshAlg {
			return nil, fmt.Errorf("keystore piv: the card generated a %s key for role %s, want %s", pub.Type(), role, sshAlg)
		}
		pubs[role] = pub
	}
	return pubs, nil
}

// ProvisionGeneration generates the key of generation (2 or later) of role
// in the first generation slot that no entry of used names (03-12f): used
// holds the location of every stored generation row of every role, so the
// slot is chosen by the rows, never by occupancy, and never reused. Every
// entry of used must be a generation slot's location and none may repeat.
// Before any card write it refuses: generation 1 or 0, a missing
// mgmt-key-file option, a malformed or repeated entry of used, no free slot
// (ErrNoFreeSlot), a candidate slot that already holds a key
// (ErrSlotOccupied: a key that no row records is never skipped and never
// overwritten) or cannot be read, and a management-key file it refuses. It
// returns the slot as the location to record.
func (b *backend) ProvisionGeneration(role keystore.Role, generation uint32, used []string) (ssh.PublicKey, string, error) {
	if generation < 2 {
		return nil, "", fmt.Errorf("keystore piv: generation %d of role %s is not a later generation (generation 1 is ca-init's)", generation, role)
	}
	if _, err := slotFor(role); err != nil {
		return nil, "", err
	}
	if b.cfg.mgmtKeyFile == "" {
		return nil, "", errors.New("keystore piv: creating a generation's key needs option mgmt-key-file (pass --backend-opt mgmt-key-file=FILE)")
	}
	recorded := make(map[uint32]bool, len(used))
	for _, loc := range used {
		s, err := parseLocation(loc)
		if err == nil && recorded[s.Key] {
			err = errors.New("two generation rows record it")
		}
		if err != nil {
			return nil, "", fmt.Errorf("keystore piv: the generation rows' location %q is refused (edited rows?); nothing was generated: %w", loc, err)
		}
		recorded[s.Key] = true
	}
	var candidate uint32
	for id := uint32(firstGenerationSlot); id <= lastGenerationSlot; id++ {
		if !recorded[id] {
			candidate = id
			break
		}
	}
	if candidate == 0 {
		return nil, "", fmt.Errorf("%w: every generation slot from 0x87 to 0x95 is recorded by a generation row; nothing was generated", ErrNoFreeSlot)
	}
	slot, ok := ykpiv.RetiredKeyManagementSlot(candidate)
	if !ok {
		return nil, "", fmt.Errorf("keystore piv: no slot %#x", candidate)
	}
	alg, sshAlg := b.algorithm()

	b.mu.Lock()
	defer b.mu.Unlock()
	occ, err := b.occupied(slot)
	if err != nil {
		return nil, "", err
	}
	if occ {
		return nil, "", fmt.Errorf("%w: slot %s (generation %d of role %s); nothing was generated; no generation row records the key in this slot, and every later PIV prepare stops here until the slot is emptied (docs/backends/piv.md)",
			ErrSlotOccupied, slot, generation, role)
	}
	mgmtKey, err := b.managementKey()
	if err != nil {
		return nil, "", err
	}
	cpub, err := b.card.GenerateKey(mgmtKey, slot, ykpiv.Key{
		Algorithm:   alg,
		PINPolicy:   ykpiv.PINPolicyOnce,
		TouchPolicy: ykpiv.TouchPolicyNever,
	})
	if err != nil {
		return nil, "", fmt.Errorf("keystore piv: generate the key of generation %d of role %s in slot %s: %w", generation, role, slot, err)
	}
	pub, err := ssh.NewPublicKey(cpub)
	if err != nil {
		return nil, "", fmt.Errorf("keystore piv: generation %d of role %s: %w", generation, role, err)
	}
	if pub.Type() != sshAlg {
		return nil, "", fmt.Errorf("keystore piv: the card generated a %s key for generation %d of role %s, want %s", pub.Type(), generation, role, sshAlg)
	}
	return pub, slot.String(), nil
}

// Key reads the public key in role's slot, checks that it was generated on
// the card and has the pinned fingerprint, and returns a CAKey that signs on
// the card. It is generation 1 of role; KeyAt opens a later generation.
func (b *backend) Key(role keystore.Role, fingerprint string) (keystore.CAKey, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("keystore piv: no pinned fingerprint for role %s", role)
	}
	slot, err := slotFor(role)
	if err != nil {
		return nil, err
	}
	return b.keyInSlot(role, slot, fingerprint)
}

// KeyAt returns the key of generation of role with fingerprint, from the
// slot the generation row's location names (03-12f): generation 1 with no
// location is Key; a later generation opens only at its recorded slot and
// never at the role's own slot.
func (b *backend) KeyAt(role keystore.Role, generation uint32, fingerprint, location string) (keystore.CAKey, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("keystore piv: no pinned fingerprint for generation %d of role %s", generation, role)
	}
	slot, err := generationSlot(role, generation, location)
	if err != nil {
		return nil, err
	}
	return b.keyInSlot(role, slot, fingerprint)
}

// keyInSlot opens the key in slot for role: it checks that the card
// generated it and that it has fingerprint, and returns a CAKey that signs
// on the card.
func (b *backend) keyInSlot(role keystore.Role, slot ykpiv.Slot, fingerprint string) (keystore.CAKey, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	info, err := b.card.KeyInfo(slot)
	if errors.Is(err, ykpiv.ErrNotFound) {
		return nil, fmt.Errorf("%w (role %s, slot %s is empty)", ErrKeyNotPresent, role, slot)
	}
	if err != nil {
		return nil, fmt.Errorf("keystore piv: read slot %s: %w", slot, err)
	}
	if info.Origin != ykpiv.OriginGenerated {
		return nil, fmt.Errorf("keystore piv: the key in slot %s (role %s) was not generated on the card", slot, role)
	}
	pub, err := ssh.NewPublicKey(info.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keystore piv: slot %s: %w", slot, err)
	}
	if ssh.FingerprintSHA256(pub) != fingerprint {
		return nil, fmt.Errorf("%w (role %s)", ErrKeyNotPresent, role)
	}
	if err := cert.CheckCAKey(pub); err != nil {
		return nil, fmt.Errorf("keystore piv: key for role %s: %w", role, err)
	}
	priv, err := b.card.PrivateKey(slot, info.PublicKey, ykpiv.KeyAuth{PIN: b.cfg.pin, PINPolicy: info.PINPolicy})
	if err != nil {
		return nil, fmt.Errorf("keystore piv: key for role %s: %w", role, err)
	}
	cs, ok := priv.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("keystore piv: key for role %s cannot sign", role)
	}
	s, err := ssh.NewSignerFromSigner(lockedSigner{mu: &b.mu, Signer: cs})
	if err != nil {
		return nil, fmt.Errorf("keystore piv: key for role %s: %w", role, err)
	}
	return &caKey{Signer: s, alg: pub.Type()}, nil
}

// Holds reports whether the slot that generation of role records still
// holds the key with fingerprint (03-12f). It reads that slot only and
// compares the key: an empty slot or another key (a throwaway after
// RemoveGeneration) is not held. A location that does not resolve, or a
// slot that cannot be read, is held, with the error: an unknown answer
// never lets a draining key pass as removed.
func (b *backend) Holds(role keystore.Role, generation uint32, fingerprint, location string) (bool, error) {
	slot, err := generationSlot(role, generation, location)
	if err != nil {
		return true, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	pub, err := b.slotKey(slot)
	if err != nil {
		return true, err // could not tell: held
	}
	return pub != nil && ssh.FingerprintSHA256(pub) == fingerprint, nil
}

// RemoveGeneration removes the key of generation of role by overwriting
// its recorded slot with a throwaway key generated on the card (03-12f;
// piv-go v2.6.0 has no delete command, so this is done on every firmware).
// This is the backend's only write over an occupied slot, and it happens
// only after the slot's key has the draining fingerprint: an empty slot is
// done with no write, and another key is refused with
// ErrSlotHoldsAnotherKey and left alone. The management key is read only
// then, right before the write. After the write the slot must hold another
// key or none.
func (b *backend) RemoveGeneration(role keystore.Role, generation uint32, fingerprint, location string) error {
	slot, err := generationSlot(role, generation, location)
	if err != nil {
		return err
	}
	alg, _ := b.algorithm()
	b.mu.Lock()
	defer b.mu.Unlock()
	pub, err := b.slotKey(slot)
	if err != nil {
		return err
	}
	if pub == nil {
		return nil // the slot is empty: no key to remove, nothing written
	}
	if ssh.FingerprintSHA256(pub) != fingerprint {
		return fmt.Errorf("%w: slot %s (generation %d of role %s)", ErrSlotHoldsAnotherKey, slot, generation, role)
	}
	if b.cfg.mgmtKeyFile == "" {
		return errors.New("keystore piv: removing a generation's key needs option mgmt-key-file (pass --backend-opt mgmt-key-file=FILE)")
	}
	mgmtKey, err := b.managementKey()
	if err != nil {
		return err
	}
	if _, err := b.card.GenerateKey(mgmtKey, slot, ykpiv.Key{
		Algorithm:   alg,
		PINPolicy:   ykpiv.PINPolicyOnce,
		TouchPolicy: ykpiv.TouchPolicyNever,
	}); err != nil {
		return fmt.Errorf("keystore piv: overwrite slot %s (generation %d of role %s) with a throwaway key: %w", slot, generation, role, err)
	}
	after, err := b.slotKey(slot)
	if err != nil {
		return fmt.Errorf("keystore piv: after the overwrite: %w", err)
	}
	if after != nil && ssh.FingerprintSHA256(after) == fingerprint {
		return fmt.Errorf("keystore piv: slot %s still holds the key of generation %d of role %s after the overwrite", slot, generation, role)
	}
	return nil
}

func (b *backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.card.Close()
}

// lockedSigner runs every card signature under the backend's mutex.
type lockedSigner struct {
	mu *sync.Mutex
	crypto.Signer
}

func (l lockedSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.Signer.Sign(rand, digest, opts)
}

// caKey is a card-held CA key.
type caKey struct {
	ssh.Signer
	alg string
}

func (k *caKey) Custody() keystore.Custody { return keystore.CustodyPIV }

func (k *caKey) Algorithm() string { return k.alg }

// readSecretFile reads a regular file (not a symlink) that has no group or
// other permissions.
func readSecretFile(path string) ([]byte, error) {
	data, err := checkSecretFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore piv: %w", err)
	}
	return data, nil
}

// checkSecretFile is readSecretFile without the package prefix on its
// errors, for a caller that names the option itself.
func checkSecretFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %04o, want 0600 or stricter", path, fi.Mode().Perm())
	}
	return os.ReadFile(path) //nolint:gosec // G304: the operator names the secret file in the backend options
}
