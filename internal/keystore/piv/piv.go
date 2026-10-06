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
// signer start rather than one per signing request.
//
// Options:
//
//	pin-file       file holding the PIV PIN (required)
//	mgmt-key-file  file holding the PIV management key in hex (needed only
//	               to provision keys)
//	serial         serial number of the YubiKey to use (default: the only
//	               attached YubiKey)
//
// Both secret files must be regular files with mode 0600 or stricter. The
// default PIN and the default management key are refused, and so are keys
// that were imported into the card rather than generated on it.
//
// What CI verifies: everything in this file, through the card interface
// with an in-memory fake card. What CI does not verify: yubikey.go (the
// piv-go calls against a real card through pcscd) and piv-go's own signing
// code. Those run first in the Phase 6 needs-hardware review
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
	// ErrSlotOccupied means Provision found a key in a target slot; it
	// generates nothing and overwrites nothing.
	ErrSlotOccupied = errors.New("keystore piv: slot already holds a key")
)

// slots maps each role to its retired key-management slot.
var slots = map[keystore.Role]uint32{
	keystore.RoleUser:    0x82,
	keystore.RoleHost:    0x83,
	keystore.RoleMachine: 0x84,
	keystore.RoleOps:     0x85,
	keystore.RoleLog:     0x86,
}

func init() { keystore.Register("piv", open) }

// config is the parsed and checked backend options.
type config struct {
	pin     string
	mgmtKey []byte // nil: provisioning is not possible
	serial  uint32 // 0: the only attached YubiKey
}

type backend struct {
	mu   sync.Mutex // serialises every card call: provisioning, metadata, signatures
	card card       // used only under mu
	cfg  config
	ver  [3]int
}

// open checks the options and secret files before it touches the card.
func open(opts map[string]string) (keystore.Backend, error) {
	cfg, err := parseOptions(opts)
	if err != nil {
		return nil, err
	}
	c, err := openYubiKey(cfg.serial)
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
func newBackend(c card, cfg config) (*backend, error) {
	major, minor, patch := c.Version()
	b := &backend{card: c, cfg: cfg, ver: [3]int{major, minor, patch}}
	if !b.atLeast(5, 3, 0) {
		_ = c.Close()
		return nil, fmt.Errorf("keystore piv: firmware %d.%d.%d is older than 5.3.0, which the backend needs to read slot metadata", major, minor, patch)
	}
	if err := c.VerifyPIN(cfg.pin); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("keystore piv: the card refused the PIN in pin-file (each failure uses one of the card's PIN retries; fix pin-file before starting again): %w", err)
	}
	return b, nil
}

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
	if f := opts["mgmt-key-file"]; f != "" {
		raw, err := readSecretFile(f)
		if err != nil {
			return cfg, err
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return cfg, fmt.Errorf("keystore piv: mgmt-key-file must hold the management key in hex: %w", err)
		}
		switch len(key) {
		case 16, 24, 32:
		default:
			return cfg, fmt.Errorf("keystore piv: management key is %d bytes, want 16, 24 or 32", len(key))
		}
		if bytes.Equal(key, ykpiv.DefaultManagementKey) {
			return cfg, errors.New("keystore piv: the card's default management key is refused; change it first (docs/backends/piv.md)")
		}
		cfg.mgmtKey = key
	}
	if s := opts["serial"]; s != "" {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n == 0 {
			return cfg, fmt.Errorf("keystore piv: serial %q is not a card serial number", s)
		}
		cfg.serial = uint32(n)
	}
	return cfg, nil
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
	if b.cfg.mgmtKey == nil {
		return nil, errors.New("keystore piv: provisioning needs option mgmt-key-file")
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
		cpub, err := b.card.GenerateKey(b.cfg.mgmtKey, targets[role], ykpiv.Key{
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

// Key reads the public key in role's slot, checks that it was generated on
// the card and has the pinned fingerprint, and returns a CAKey that signs on
// the card.
func (b *backend) Key(role keystore.Role, fingerprint string) (keystore.CAKey, error) {
	if fingerprint == "" {
		return nil, fmt.Errorf("keystore piv: no pinned fingerprint for role %s", role)
	}
	slot, err := slotFor(role)
	if err != nil {
		return nil, err
	}
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
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("keystore piv: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("keystore piv: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("keystore piv: %s has mode %04o, want 0600 or stricter", path, fi.Mode().Perm())
	}
	return os.ReadFile(path) //nolint:gosec // G304: the operator names the secret file in the backend options
}
