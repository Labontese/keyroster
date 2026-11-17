package krl

import "golang.org/x/crypto/ssh"

// DrainEntry is the certificate with the largest ValidBefore that the log
// records for one CA key (03-12e): its ValidBefore, the index of the leaf
// that records it, its serial and its key ID.
type DrainEntry struct {
	ValidBefore, Leaf, Serial uint64
	KeyID                     string
}

// DrainMax is the drain accumulator (03-12e): per CA key, the logged
// certificate with the largest ValidBefore.
type DrainMax struct{ m map[string]DrainEntry }

// NewDrainMax returns an empty accumulator.
func NewDrainMax() *DrainMax { return &DrainMax{m: map[string]DrainEntry{}} }

// Add records the certificate c of leaf.
func (d *DrainMax) Add(_ uint64, _ *ssh.Certificate) error { return nil }

// For returns the entry of the CA key caKey (its SSH wire encoding).
func (d *DrainMax) For(_ []byte) (DrainEntry, bool) { return DrainEntry{}, false }

// EarliestTrustedUntil is the earliest trusted_until that leaves a
// certificate valid before validBefore no longer live.
func EarliestTrustedUntil(_ uint64) (uint64, bool) { return 0, false }
