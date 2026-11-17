package signer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// The refusals of a switch install (03-12e), each an ErrBundleInstall.
var (
	ErrDrainWindowTooShort        = fmt.Errorf("%w: drain_window_too_short", ErrBundleInstall)
	ErrDrainWindowTooLong         = fmt.Errorf("%w: drain_window_too_long", ErrBundleInstall)
	ErrInstallPreviousRequired    = fmt.Errorf("%w: install_previous_required", ErrBundleInstall)
	ErrInstallPreviousInvalid     = fmt.Errorf("%w: install_previous_invalid", ErrBundleInstall)
	ErrInstallPreviousNotExtended = fmt.Errorf("%w: install_previous_not_extended", ErrBundleInstall)
	ErrDrainScanMissing           = fmt.Errorf("%w: drain_scan_missing", ErrBundleInstall)
)

// DrainNote is what a switch install bound for one newly draining CA
// entry (03-12e): its role, generation and trusted_until, and the logged
// certificate of its key with the largest ValidBefore (Recorded false when
// the log records none).
type DrainNote struct {
	Role         string
	Generation   uint32
	TrustedUntil string
	Max          krl.DrainEntry
	Recorded     bool
}

// InstallBundleWithPrevious verifies a trust bundle and its policy and
// installs them (KEY-07), as InstallBundle documents, and binds a switch
// (03-12e). previous, when not nil, is the checkpoint note of an
// export-log file kept off the box: it must verify with the log key, cover
// at least one entry and be extended by this log, whether or not the
// install is a switch. An install is a switch when the bundle has a
// draining CA entry that the installed bundle does not have as draining;
// a switch needs previous, and each newly draining entry's trusted_until
// must leave no certificate of its key that the verified log records live
// (krl.DrainBindingHolds), else the install is refused
// drain_window_too_short with that certificate and the earliest acceptable
// trusted_until named. The scan of the log that the binding reads is the
// one the install's own log walk performs; the issuance table is never
// read. On any refusal nothing is written. It returns one DrainNote per
// newly draining entry.
func InstallBundleWithPrevious(ctx context.Context, db *signerdb.DB, be keystore.Backend, pins []string, threshold int,
	bundle, bundleSigs, policy, policySigs []byte, clock serial.Clock, previous []byte) (*trust.Bundle, []DrainNote, error) {
	if db == nil || be == nil {
		return nil, nil, errors.New("signer: InstallBundle needs a state database and a keystore backend")
	}
	if clock == nil {
		clock = time.Now
	}
	// The one clock read of an install: the issued_at bound, InstalledAt
	// and the leaf time (03-12).
	now := clock()
	caKeys, err := db.CAKeys(ctx)
	if errors.Is(err, signerdb.ErrNotInitialised) {
		return nil, nil, ErrNotInitialised
	}
	if err != nil {
		return nil, nil, err
	}
	gens, err := db.CAGenerations(ctx)
	if err != nil {
		return nil, nil, err
	}
	// One budget for install and Status: refuse, before any verification
	// or write, a bundle and policy whose Status reply would not fit
	// wire.MaxStatusFrame, so every installed trust state can be reported.
	// The directory fields are fixed-size, so zero values size them.
	if _, err := statusResponse(caKeys, 0, bundle, bundleSigs, policy, policySigs, statusDirectory{}).Marshal(); err != nil {
		if errors.Is(err, wire.ErrStatusTooLarge) {
			return nil, nil, fmt.Errorf("%w: the bundle, policy and signatures make the Status reply too large: %w", ErrBundleInstall, err)
		}
		return nil, nil, fmt.Errorf("%w: %w", ErrBundleInstall, err)
	}
	logKey, err := openRoleKey(be, caKeys, "log")
	if err != nil {
		return nil, nil, err
	}
	// The install's log walk feeds the drain scan, and checks previous
	// once it knows the log's size (03-12e).
	opts := rebuildOptions{drain: true}
	if previous != nil {
		cp, err := openPrevious(logKey, previous)
		if err != nil {
			return nil, nil, err
		}
		opts.previous = &cp
	}
	lw, err := newLogWriterWith(ctx, db, logKey, clock, opts)
	if err != nil {
		return nil, nil, err
	}
	var (
		b         *trust.Bundle
		p         *trust.Policy
		installed *trust.Bundle
	)
	latest, err := db.LatestBundle(ctx)
	if err == nil || errors.Is(err, signerdb.ErrNoBundle) {
		// A successor is verified against the installed record, so that
		// record must be the one the verified log carries.
		if cerr := checkBundleLogged(latest, lw.loaded.last); cerr != nil {
			return nil, nil, cerr
		}
	}
	switch {
	case errors.Is(err, signerdb.ErrNoBundle):
		b, p, err = trust.VerifyGenesisBundle(bundle, bundleSigs, policy, policySigs, pins, threshold)
	case err != nil:
		return nil, nil, err
	case len(pins) != 0 || threshold != 0:
		return nil, nil, fmt.Errorf("%w: bundle version %d is installed; a successor is verified against it, so --pin and --threshold apply to the genesis bundle only", ErrBundleInstall, latest.Version)
	default:
		installed, err = trust.ParseBundle(latest.Bundle)
		if err != nil {
			return nil, nil, fmt.Errorf("installed bundle: %w", err)
		}
		b, p, err = trust.VerifySuccessor(installed, latest.Bundle, latest.Policy, bundle, bundleSigs, policy, policySigs)
		if err == nil && b.Version <= latest.Version {
			err = fmt.Errorf("%w: version %d is not above the installed version %d", ErrBundleInstall, b.Version, latest.Version)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if err := checkIssuedNotAhead(b, now); err != nil {
		return nil, nil, err
	}
	if err := checkBundleKeys(b, caKeys, gens); err != nil {
		return nil, nil, err
	}
	if err := checkPolicyAdmins(b, p, gens); err != nil {
		return nil, nil, err
	}
	// The verifiers above saw the roots of b and of the installed bundle
	// only; no root of an earlier bundle may be an admin either.
	if err := lw.loaded.checkAdmins(p); err != nil {
		return nil, nil, err
	}
	if b.Log.Origin != tlog.Origin(logKey.PublicKey()) {
		return nil, nil, fmt.Errorf("%w: log origin %q is not the log key's %q", ErrBundleKeys, b.Log.Origin, tlog.Origin(logKey.PublicKey()))
	}
	// The switch's fences, before anything is written (03-12e).
	notes, err := checkSwitchInstall(lw, installed, b, previous != nil)
	if err != nil {
		return nil, nil, err
	}
	enc, err := (&tlog.BundleInstallBody{
		BundleVersion: b.Version, Bundle: bundle, BundleSigs: bundleSigs, Policy: policy, PolicySigs: policySigs,
	}).Encode()
	if err != nil {
		return nil, nil, err
	}
	err = lw.logTx(ctx, func(tx *sql.Tx) error {
		if err := db.InsertBundle(tx, signerdb.StoredBundle{
			Version: b.Version, Bundle: bundle, BundleSigs: bundleSigs, Policy: policy, PolicySigs: policySigs, InstalledAt: now,
		}); err != nil {
			return err
		}
		_, err := lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindBundleInstall, Body: enc})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return b, notes, nil
}

// openPrevious opens previous, the checkpoint note of an export-log file,
// with the log key: it must verify and cover at least one entry, since a
// checkpoint of the empty log is extended by every log and proves nothing
// (03-12e). That the log extends it is the install's log walk's check.
func openPrevious(logKey keystore.CAKey, previous []byte) (tlog.Checkpoint, error) {
	pub := logKey.PublicKey()
	v, err := tlog.NewNoteVerifier(tlog.Origin(pub), pub)
	if err != nil {
		return tlog.Checkpoint{}, fmt.Errorf("signer: log key: %w", err)
	}
	cp, err := tlog.OpenCheckpoint(previous, v)
	if err != nil {
		return tlog.Checkpoint{}, fmt.Errorf("%w: the checkpoint in --previous does not verify with this log's key: %w", ErrInstallPreviousInvalid, err)
	}
	if cp.Size == 0 {
		return tlog.Checkpoint{}, fmt.Errorf("%w: the checkpoint in --previous covers 0 entries", ErrInstallPreviousInvalid)
	}
	return cp, nil
}

// checkSwitchInstall applies the fences of a switch to the install of b
// over installed (nil for a genesis install) by lw, the log writer whose
// walk fed the drain scan (03-12e). It refuses drain_scan_missing first
// when lw carries no scan, whatever b is, so a path that did not ask for
// the scan cannot pass by omission. A newly draining entry is one that b
// has as draining and installed does not, by role and generation; an
// entry that was already draining is not bound again, because its end
// never changes. A switch needs previous (install_previous_required), and
// for each newly draining entry the largest ValidBefore that the scan
// recorded for its key must leave no certificate live at its
// trusted_until (krl.DrainBindingHolds), else drain_window_too_short. It
// returns one DrainNote per newly draining entry.
func checkSwitchInstall(lw *Signer, installed, b *trust.Bundle, havePrevious bool) ([]DrainNote, error) {
	if lw == nil || lw.loaded.drain == nil {
		return nil, fmt.Errorf("%w: the install was handed no scan of the log", ErrDrainScanMissing)
	}
	newly := newlyDraining(installed, b)
	if len(newly) == 0 {
		return nil, nil
	}
	if !havePrevious {
		return nil, fmt.Errorf("%w: a switch install needs --previous, an export-log file of this log kept off the box", ErrInstallPreviousRequired)
	}
	notes := make([]DrainNote, 0, len(newly))
	for _, ca := range newly {
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: CA %s generation %d: %w", ErrBundleInstall, ca.Role, ca.Generation, err)
		}
		tu, err := unixSeconds(ca.TrustedUntil)
		if err != nil {
			return nil, fmt.Errorf("%w: CA %s generation %d: trusted_until: %w", ErrBundleInstall, ca.Role, ca.Generation, err)
		}
		m, ok := lw.loaded.drain.For(pub.Marshal())
		if ok && !krl.DrainBindingHolds(m.ValidBefore, tu) {
			return nil, fmt.Errorf("%w: the switch of CA %s ends trust at %s, but the log records a certificate of generation %d valid until %s (serial %d, key ID %s, leaf %d); the earliest acceptable trusted_until is %s",
				ErrDrainWindowTooShort, ca.Role, ca.TrustedUntil, ca.Generation, drainTime(m.ValidBefore), m.Serial, m.KeyID, m.Leaf, earliestTrustedUntil(m.ValidBefore))
		}
		notes = append(notes, DrainNote{Role: ca.Role, Generation: ca.Generation, TrustedUntil: ca.TrustedUntil, Max: m, Recorded: ok})
	}
	return notes, nil
}

// newlyDraining returns the draining entries of b that installed (nil for
// none) does not have as draining, by role and generation (03-12e).
func newlyDraining(installed, b *trust.Bundle) []trust.CAEntry {
	var out []trust.CAEntry
	for _, ca := range b.CAs {
		if ca.State != "draining" {
			continue
		}
		was := false
		if installed != nil {
			for _, old := range installed.CAs {
				if old.Role == ca.Role && old.Generation == ca.Generation && old.State == "draining" {
					was = true
					break
				}
			}
		}
		if !was {
			out = append(out, ca)
		}
	}
	return out
}

// unixSeconds is the Unix seconds of a TimeFormat time; a time before 1970
// is an error, never converted to a wrapped uint64 (03-12e).
func unixSeconds(s string) (uint64, error) {
	t, err := time.Parse(trust.TimeFormat, s)
	if err != nil {
		return 0, err
	}
	if t.Unix() < 0 {
		return 0, fmt.Errorf("%s is before 1970", s)
	}
	return uint64(t.Unix()), nil //nolint:gosec // G115: not before 1970, checked above
}

// maxTimeFormat is the last second TimeFormat renders, 9999-12-31T23:59:59Z.
const maxTimeFormat = 253402300799

// drainTime renders Unix seconds u for a refusal or a drain line: in
// trust.TimeFormat when that format can render it, as "forever" for
// ssh.CertTimeInfinity and as the decimal seconds otherwise, so a
// ValidBefore at or above 2^63 is never rendered as a negative time
// (03-12e).
func drainTime(u uint64) string {
	switch {
	case u <= maxTimeFormat:
		return time.Unix(int64(u), 0).UTC().Format(trust.TimeFormat)
	case u == math.MaxUint64:
		return "forever"
	}
	return fmt.Sprintf("%d s after 1970", u)
}

// earliestTrustedUntil renders krl.EarliestTrustedUntil(validBefore) for
// the drain_window_too_short refusal (03-12e).
func earliestTrustedUntil(validBefore uint64) string {
	e, ok := krl.EarliestTrustedUntil(validBefore)
	if !ok {
		return "none (that certificate never expires)"
	}
	return drainTime(e)
}

// drainFeed is the signer's one call into tlog.LeafCertificates (03-12e):
// it adds every certificate leaf l (index idx) records to acc. A
// certificate that cannot be read fails the log walk with errLogMismatch,
// never skipped.
func drainFeed(acc *krl.DrainMax, idx uint64, l tlog.Leaf) error {
	certs, err := tlog.LeafCertificates(l)
	if err == nil {
		for _, c := range certs {
			if err = acc.Add(idx, c); err != nil {
				break
			}
		}
	}
	if err != nil {
		return fmt.Errorf("%w: drain scan: leaf %d (%s): %w", errLogMismatch, idx, l.Kind, err)
	}
	return nil
}
