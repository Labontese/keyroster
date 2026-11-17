package krl

import (
	"errors"
	"math"

	"golang.org/x/crypto/ssh"
)

// DrainEntry is the certificate with the largest ValidBefore that the log
// records for one CA key (03-12e): its ValidBefore, the index of the leaf
// that records it, its serial and its key ID.
type DrainEntry struct {
	ValidBefore, Leaf, Serial uint64
	KeyID                     string
}

// DrainMax is the drain accumulator (03-12e): per CA key, the logged
// certificate with the largest ValidBefore, in constant memory per key. It
// takes certificates that internal/tlog parsed from verified leaves; the
// signer's install and keyroster audit verify both feed it, and neither
// ever reads the issuance table. It is revocation-blind (owner decision
// 2026-11-17): a revoked certificate still counts.
type DrainMax struct{ m map[string]DrainEntry }

// NewDrainMax returns an empty accumulator.
func NewDrainMax() *DrainMax { return &DrainMax{m: map[string]DrainEntry{}} }

// Add records the certificate c of leaf under its signature key. A nil
// certificate and one without a signature key are errors, never skipped.
// On a tie of ValidBefore the earliest leaf keeps the entry.
func (d *DrainMax) Add(leaf uint64, c *ssh.Certificate) error {
	if c == nil {
		return errors.New("krl: drain: no certificate")
	}
	if c.SignatureKey == nil {
		return errors.New("krl: drain: the certificate has no signature key")
	}
	k := string(c.SignatureKey.Marshal())
	if cur, ok := d.m[k]; ok && cur.ValidBefore >= c.ValidBefore {
		return nil
	}
	d.m[k] = DrainEntry{ValidBefore: c.ValidBefore, Leaf: leaf, Serial: c.Serial, KeyID: c.KeyId}
	return nil
}

// For returns the entry of the CA key caKey (its SSH wire encoding), and
// false when the accumulator holds no certificate of it. On a nil
// accumulator it returns the zero entry and false, so a caller that was
// handed none must refuse on its own (the signer's drain_scan_missing),
// and never panics.
func (d *DrainMax) For(caKey []byte) (DrainEntry, bool) {
	if d == nil {
		return DrainEntry{}, false
	}
	e, ok := d.m[string(caKey)]
	return e, ok
}

// DrainBindingHolds reports whether a switch whose trusted_until is
// trustedUntil leaves no certificate valid before maxValidBefore live
// (03-12e): !EntryLive(maxValidBefore, trustedUntil), so trustedUntil must
// be at least maxValidBefore plus PruneMargin. It is the one binding rule
// the signer's install and keyroster audit verify both apply.
func DrainBindingHolds(maxValidBefore, trustedUntil uint64) bool {
	return !EntryLive(maxValidBefore, trustedUntil)
}

// EarliestTrustedUntil is the earliest trusted_until for which
// DrainBindingHolds(validBefore, trusted_until) holds: validBefore plus
// PruneMargin, and false when that sum saturates (a certificate that never
// expires) (03-12e).
func EarliestTrustedUntil(validBefore uint64) (uint64, bool) {
	if validBefore > math.MaxUint64-PruneMargin {
		return 0, false
	}
	return validBefore + PruneMargin, true
}
