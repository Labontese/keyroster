//go:build piv

package piv

import (
	"crypto"
	"errors"
	"fmt"
	"strings"

	ykpiv "github.com/go-piv/piv-go/v2/piv"
)

// NOT EXERCISED IN CI. This adapter is the only code that talks to a real
// YubiKey (through pcscd). CI has no card, so the tests replace it with a
// fake; it is first run on real hardware in the Phase 6 needs-hardware
// review (docs/security/needs-hardware.md). Keep it a thin pass-through to
// piv-go: every branch here is unverified.

// yubiKey adapts *ykpiv.YubiKey to card.
type yubiKey struct{ yk *ykpiv.YubiKey }

// openYubiKey opens the YubiKey with the given serial or, when serial is
// zero, the only attached YubiKey. piv-go holds a PC/SC transaction on the
// card until Close, so no other process can use the card meanwhile.
func openYubiKey(serial uint32) (card, error) {
	readers, err := ykpiv.Cards()
	if err != nil {
		return nil, fmt.Errorf("keystore piv: list smart cards: %w", err)
	}
	var names []string
	for _, r := range readers {
		if strings.Contains(strings.ToLower(r), "yubikey") {
			names = append(names, r)
		}
	}
	if serial == 0 {
		if len(names) != 1 {
			return nil, fmt.Errorf("keystore piv: %d YubiKeys attached; attach exactly one or set option serial", len(names))
		}
		yk, err := ykpiv.Open(names[0])
		if err != nil {
			return nil, fmt.Errorf("keystore piv: open %s: %w", names[0], err)
		}
		return &yubiKey{yk: yk}, nil
	}
	var errs []error
	for _, n := range names {
		yk, err := ykpiv.Open(n)
		if err != nil {
			errs = append(errs, fmt.Errorf("open %s: %w", n, err))
			continue
		}
		s, err := yk.Serial()
		if err == nil && s == serial {
			return &yubiKey{yk: yk}, nil
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("serial of %s: %w", n, err))
		}
		_ = yk.Close()
	}
	return nil, fmt.Errorf("keystore piv: no attached YubiKey has serial %d: %w", serial, errors.Join(errs...))
}

func (y *yubiKey) Version() (major, minor, patch int) {
	v := y.yk.Version()
	return v.Major, v.Minor, v.Patch
}

func (y *yubiKey) KeyInfo(slot ykpiv.Slot) (ykpiv.KeyInfo, error) {
	return y.yk.KeyInfo(slot)
}

func (y *yubiKey) GenerateKey(mgmtKey []byte, slot ykpiv.Slot, key ykpiv.Key) (crypto.PublicKey, error) {
	return y.yk.GenerateKey(mgmtKey, slot, key)
}

func (y *yubiKey) PrivateKey(slot ykpiv.Slot, pub crypto.PublicKey, auth ykpiv.KeyAuth) (crypto.PrivateKey, error) {
	return y.yk.PrivateKey(slot, pub, auth)
}

func (y *yubiKey) Close() error { return y.yk.Close() }
