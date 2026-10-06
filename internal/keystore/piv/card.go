//go:build piv

package piv

import (
	"crypto"

	ykpiv "github.com/go-piv/piv-go/v2/piv"
)

// card is the part of a PIV card the backend uses. The YubiKey adapter
// (yubikey.go) implements it with piv-go; the tests implement it with an
// in-memory fake. The backend calls it only under its mutex.
type card interface {
	// Version is the PIV applet's firmware version.
	Version() (major, minor, patch int)
	// KeyInfo returns the slot's metadata, including its public key and
	// whether the key was generated on the card. An empty slot is an error
	// that wraps ykpiv.ErrNotFound.
	KeyInfo(slot ykpiv.Slot) (ykpiv.KeyInfo, error)
	// GenerateKey creates a key in slot, authenticating with the
	// management key, and returns its public key. Like a real card, it
	// replaces a key the slot already holds.
	GenerateKey(mgmtKey []byte, slot ykpiv.Slot, key ykpiv.Key) (crypto.PublicKey, error)
	// PrivateKey returns a handle that signs with the key in slot.
	PrivateKey(slot ykpiv.Slot, pub crypto.PublicKey, auth ykpiv.KeyAuth) (crypto.PrivateKey, error)
	Close() error
}
