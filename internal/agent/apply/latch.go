//go:build linux

package apply

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
)

// trustLatchFile is the drop latch in the applier's state directory
// (03-12c): the draining CA keys this host has dropped, by fingerprint.
// The agent never takes a dropped key back, whatever its clock says later,
// after a rollback or after reset-directory.
const trustLatchFile = "trust-dropped.json"

// maxTrustLatch bounds the latch file: 64 KiB.
const maxTrustLatch = 64 << 10

// latchKey is one dropped key of the latch: the SHA-256 fingerprint of
// the key and the trusted_until it had when it was dropped.
type latchKey struct {
	Fingerprint  string `json:"fingerprint"`
	TrustedUntil string `json:"trusted_until"`
}

// latchDoc is the latch file: strict canonical JSON, keys sorted by
// fingerprint.
type latchDoc struct {
	Version int        `json:"version"`
	Keys    []latchKey `json:"keys"`
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

// caFingerprint is the SHA-256 fingerprint of ca's key.
func caFingerprint(ca trust.CAEntry) (string, bool) {
	pub, err := trust.ParseKey(ca.Key)
	if err != nil {
		return "", false
	}
	return ssh.FingerprintSHA256(pub), true
}

// holds reports whether the latch names the key with fingerprint f.
func (l *Latch) holds(f string) bool {
	if l == nil {
		return false
	}
	_, ok := l.keys[f]
	return ok
}

// Blocks reports whether the render leaves ca out because of the latch:
// never for a nil latch or an entry that is not draining; for every
// draining entry when the latch does not read (fail closed); otherwise
// exactly when the latch holds ca's key. It compares keys, never ends, so
// a later rotation's key is not blocked by an earlier one's end.
func (l *Latch) Blocks(ca trust.CAEntry) bool {
	if l == nil || ca.State != "draining" {
		return false
	}
	if l.unreadable {
		return true
	}
	f, ok := caFingerprint(ca)
	return ok && l.holds(f)
}

// encode is the latch file's bytes.
func (l *Latch) encode() ([]byte, error) {
	keys := make([]latchKey, 0, len(l.keys))
	for f, end := range l.keys {
		keys = append(keys, latchKey{Fingerprint: f, TrustedUntil: end})
	}
	slices.SortFunc(keys, func(a, b latchKey) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	return trust.CanonicalJSON(latchDoc{Version: 1, Keys: keys})
}

// parseLatch reads the latch file's bytes: strict canonical JSON of
// version 1, every fingerprint SHA-256, every end in trust.TimeFormat and
// the keys sorted by fingerprint without a repeat.
func parseLatch(b []byte) (*Latch, error) {
	var d latchDoc
	if err := trust.DecodeStrict(b, &d); err != nil {
		return nil, err
	}
	if d.Version != 1 {
		return nil, fmt.Errorf("version %d, want 1", d.Version)
	}
	for i, k := range d.Keys {
		if !strings.HasPrefix(k.Fingerprint, "SHA256:") {
			return nil, fmt.Errorf("key %d: fingerprint %q lacks the SHA256: prefix", i, k.Fingerprint)
		}
		if err := trust.CheckTimestamp(k.TrustedUntil); err != nil {
			return nil, fmt.Errorf("key %d: trusted_until: %w", i, err)
		}
		if i > 0 && d.Keys[i-1].Fingerprint >= k.Fingerprint {
			return nil, fmt.Errorf("key %d: the keys are not sorted by fingerprint", i)
		}
	}
	return newLatch(false, d.Keys...), nil
}

// readLatch is the drop latch, read once per engine from the state
// directory without following a symlink (spool.ReadFileAtInfo): a missing
// file is an empty latch; a file that does not read, is not a 0600
// regular file of the effective uid, is above 64 KiB or does not parse is
// unreadable, logged once, and blocks every draining entry. It only reads.
func (e *engine) readLatch() *Latch {
	if e.latch != nil {
		return e.latch
	}
	why := ""
	if e.stateFd < 0 {
		why = "the state directory is not open"
	} else {
		b, info, err := spool.ReadFileAtInfo(e.stateFd, trustLatchFile, maxTrustLatch)
		switch {
		case errors.Is(err, unix.ENOENT):
			e.latch = newLatch(false)
			return e.latch
		case err != nil:
			why = err.Error()
		case info.Mode != 0o600 || int(info.UID) != os.Geteuid():
			why = fmt.Sprintf("not a 0600 file of uid %d", os.Geteuid())
		default:
			l, err := parseLatch(b)
			if err == nil {
				e.latch = l
				return e.latch
			}
			why = err.Error()
		}
	}
	e.logf("WARNING %s does not read (%s); no draining CA key is rendered", trustLatchFile, why)
	e.latch = newLatch(true)
	return e.latch
}

// recordDropped latches the draining user and machine keys that the
// render at now omits because their end has passed (03-12c), before
// anything lands: the write is atomic and synced (e.writeState), so the
// latch is on disk before the marker, the generation or the swap, and a
// failed write fails the apply. It writes nothing in a dry run, for a
// bundle without a draining entry, when every such key is latched
// already, or when the latch does not read (an unreadable latch is never
// overwritten or removed). The host role's draining keys are not latched:
// no file of the agent holds them. The record is never pruned, because a
// drained key stays draining in every later bundle.
func (e *engine) recordDropped(v *state.Verified, now time.Time) error {
	if e.cfg.DryRun || v == nil || v.Bundle == nil || !hasDraining(v.Bundle) {
		return nil
	}
	l := e.readLatch()
	if l.unreadable {
		return nil
	}
	next := newLatch(false)
	maps.Copy(next.keys, l.keys)
	var added []latchKey
	for _, ca := range v.Bundle.CAs {
		if ca.State != "draining" || (ca.Role != trust.RoleUser && ca.Role != trust.RoleMachine) || ca.TrustedAt(now) || trust.CheckTimestamp(ca.TrustedUntil) != nil {
			continue
		}
		f, ok := caFingerprint(ca)
		if !ok || next.holds(f) {
			continue
		}
		next.keys[f] = ca.TrustedUntil
		added = append(added, latchKey{Fingerprint: f, TrustedUntil: ca.TrustedUntil})
	}
	if len(added) == 0 {
		return nil
	}
	b, err := next.encode()
	if err != nil {
		return err
	}
	if len(b) > maxTrustLatch {
		return fmt.Errorf("%s would be %d bytes, above %d", trustLatchFile, len(b), maxTrustLatch)
	}
	if err := e.writeState(trustLatchFile, b); err != nil {
		return fmt.Errorf("writing %s: %w", trustLatchFile, err)
	}
	e.latch = next
	for _, k := range added {
		e.logf("latched draining CA key %s (ended %s)", k.Fingerprint, k.TrustedUntil)
	}
	return nil
}
