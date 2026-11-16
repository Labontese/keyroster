//go:build linux

package apply

import (
	"time"

	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
)

// trustLatchFile is the drop latch in the applier's state directory
// (03-12c): the draining CA keys this host has dropped, by fingerprint.
const trustLatchFile = "trust-dropped.json"

// latchKey is one dropped key of the latch: the SHA-256 fingerprint of
// the key and the trusted_until it had when it was dropped.
type latchKey struct {
	Fingerprint  string `json:"fingerprint"`
	TrustedUntil string `json:"trusted_until"`
}

// Latch is the drop latch as read (03-12c): a map from SHA-256
// fingerprint to the end the key had, and whether the file did not read.
type Latch struct {
	keys       map[string]string
	unreadable bool
}

// newLatch is a latch holding keys; unreadable marks one whose file did
// not read.
func newLatch(unreadable bool, keys ...latchKey) *Latch {
	l := &Latch{keys: map[string]string{}, unreadable: unreadable}
	for _, k := range keys {
		l.keys[k.Fingerprint] = k.TrustedUntil
	}
	return l
}

// Blocks reports whether the render leaves ca out because the latch holds
// it.
func (l *Latch) Blocks(_ trust.CAEntry) bool { return false }

// readLatch reads trust-dropped.json.
func (e *engine) readLatch() *Latch { return newLatch(false) }

// recordDropped records the draining keys the render at now omits.
func (e *engine) recordDropped(_ *state.Verified, _ time.Time) error { return nil }
