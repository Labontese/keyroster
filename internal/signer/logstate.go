package signer

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"

	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/note"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
)

// errLogMismatch means the stored leaves do not reproduce the latest signed
// checkpoint (or do not decode), or contradict the tables written with
// them (checkLogCovers): the state database was modified outside the
// signer, or restored inconsistently. The signer refuses to start.
var errLogMismatch = errors.New("signer: log state mismatch")

// logState is the signer's in-memory view of the audit log. Every field is
// guarded by Signer.mu.
type logState struct {
	origin string
	// cpSigner signs checkpoints with the log key. It is an interface so
	// that tests in this package can inject a failing signer; production
	// code sets it only in initLog.
	cpSigner   note.Signer
	cpVerifier note.Verifier

	tree       *tlog.Log // committed state
	lastMicros uint64    // timestamp of the last committed leaf
	// loaded is what the install leaves of the log record, as last
	// loaded from the database. New and InstallBundle compare its last
	// bundle_install body with the stored trust bundle record and check
	// the policy against its root sets; loadDirectory compares its last
	// directory_install body with the stored directory.
	loaded loggedInstalls

	// pending is the state after the appends of the open transaction. It
	// replaces tree only after COMMIT succeeded.
	pending       *tlog.Log
	pendingMicros uint64
	// pendingRevoked is loaded.revoked plus the entries of the revoke
	// and revocation_recovery leaves appended in the open transaction,
	// nil while it appended none. It replaces loaded.revoked only after COMMIT succeeded.
	pendingRevoked loggedRevocations

	// broken is set when a failed commit left the in-memory state unknown
	// and it could not be reloaded; every later append fails with it.
	broken error
}

// initLog builds the checkpoint signer and verifier for the log key and
// rebuilds the log from the database.
func (s *Signer) initLog(ctx context.Context) error {
	pub := s.logKey.PublicKey()
	s.origin = tlog.Origin(pub)
	cpSigner, err := tlog.NewNoteSigner(s.origin, s.logKey)
	if err != nil {
		return fmt.Errorf("signer: log key: %w", err)
	}
	cpVerifier, err := tlog.NewNoteVerifier(s.origin, pub)
	if err != nil {
		return fmt.Errorf("signer: log key: %w", err)
	}
	s.cpSigner, s.cpVerifier = cpSigner, cpVerifier
	return s.loadLog(ctx)
}

// loadLog replaces the in-memory log with the one rebuilt from the
// database.
func (s *Signer) loadLog(ctx context.Context) error {
	tree, last, installs, err := s.rebuildLog(ctx)
	if err != nil {
		return err
	}
	s.tree, s.lastMicros, s.loaded, s.broken = tree, last, installs, nil
	return nil
}

// rebuildLog recomputes the tree from the stored leaf bytes (not only the
// stored hashes) and requires the latest checkpoint to verify with the log
// key and to match the recomputed size and root. It also returns what the
// bundle_install leaves record.
func (s *Signer) rebuildLog(ctx context.Context) (*tlog.Log, uint64, loggedInstalls, error) {
	return rebuildLogFrom(ctx, s.db, s.cpVerifier)
}

// loggedInstalls is what the install leaves of a log record: the body of
// the last bundle_install leaf (nil when there is none), the root set of
// every logged trust bundle, in log order, the body of the last
// directory_install leaf and the body of the last krl_publish leaf (each
// nil when there is none).
type loggedInstalls struct {
	last          []byte
	roots         [][]trust.RootKey
	lastDirectory []byte
	// lastKRLPublish is the body of the last krl_publish leaf (nil when
	// there is none); loadKRL compares the stored KRL state with it.
	lastKRLPublish []byte
	// revoked is the exact multiset of the entries of the revoke and
	// revocation_recovery leaves.
	// Unlike the other fields it follows the committed log: logTx adds
	// the entries of every revoke leaf that COMMITs (pendingRevoked), and
	// publishKRLLocked compares the revocation rows with it before the
	// ops key signs a KRL built from them.
	revoked loggedRevocations
}

// add records the bundle_install leaf idx with body.
func (li *loggedInstalls) add(idx uint64, body []byte) error {
	b, err := tlog.DecodeBundleInstallBody(body)
	if err != nil {
		return fmt.Errorf("%w: leaf %d: bundle_install body does not decode", errLogMismatch, idx)
	}
	bundle, err := trust.ParseBundle(b.Bundle)
	if err != nil {
		return fmt.Errorf("%w: leaf %d: the logged trust bundle does not parse: %w", errLogMismatch, idx, err)
	}
	li.last = body
	li.roots = append(li.roots, bundle.Root.Keys)
	return nil
}

// addDirectory records the directory_install leaf idx with body.
func (li *loggedInstalls) addDirectory(idx uint64, body []byte) error {
	if _, err := tlog.DecodeDirectoryInstallBody(body); err != nil {
		return fmt.Errorf("%w: leaf %d: directory_install body does not decode", errLogMismatch, idx)
	}
	li.lastDirectory = body
	return nil
}

// checkAdmins refuses a policy that names a root of any logged trust
// bundle as an admin. trust.VerifySuccessor checks only the roots of the
// bundle it verifies and of its predecessor, but a root retired earlier
// may still exist, and a root never authorizes issuance (KEY-07).
func (li *loggedInstalls) checkAdmins(p *trust.Policy) error {
	if err := trust.CheckAdminsNotRoots(p, li.roots...); err != nil {
		return fmt.Errorf("%w (a root of a trust bundle the log records, retired or not)", err)
	}
	return nil
}

// checkBundleLogged requires the stored trust bundle record (nil when none
// is stored) to be exactly what install, the body of the last
// bundle_install leaf of the verified log (nil when there is none),
// records: the same version and byte-identical bundle, policy and
// signatures. The log is anchored in the log key's signed checkpoint, the
// trust_bundle table is not, so a record written to the database outside
// install-bundle (a tampered backup, an offline edit) is refused instead of
// trusted.
func checkBundleLogged(stored *signerdb.StoredBundle, install []byte) error {
	switch {
	case stored == nil && install == nil:
		return nil
	case stored == nil:
		return fmt.Errorf("%w: the log records an installed trust bundle, but the state database holds none", errLogMismatch)
	case install == nil:
		return fmt.Errorf("%w: trust bundle version %d is stored, but the log records no bundle_install entry", errLogMismatch, stored.Version)
	}
	body, err := tlog.DecodeBundleInstallBody(install)
	if err != nil {
		return fmt.Errorf("%w: last bundle_install entry: %w", errLogMismatch, err)
	}
	if body.BundleVersion != stored.Version || !bytes.Equal(body.Bundle, stored.Bundle) || !bytes.Equal(body.BundleSigs, stored.BundleSigs) ||
		!bytes.Equal(body.Policy, stored.Policy) || !bytes.Equal(body.PolicySigs, stored.PolicySigs) {
		return fmt.Errorf("%w: the stored trust bundle (version %d) is not the one the last bundle_install entry records (version %d)",
			errLogMismatch, stored.Version, body.BundleVersion)
	}
	return nil
}

// checkDirectoryLogged requires the latest stored directory (nil when
// none is stored) to be exactly what install, the body of the last
// directory_install leaf of the verified log (nil when there is none),
// records: the same version and policy version and byte-identical
// document and signatures (T-02-14). The directory table is not anchored
// in the signed checkpoint, so a row overwritten, deleted or written
// outside InstallDirectory, with the log left as it is, is refused
// instead of trusted. It cannot catch the log rolled back together with
// the table to an earlier signed prefix, or a whole older database
// restored: the older directory is then exactly what the shorter log
// records (the C-WR-01 residual, see checkLogCovers).
func checkDirectoryLogged(stored *signerdb.StoredDirectory, install []byte) error {
	switch {
	case stored == nil && install == nil:
		return nil
	case stored == nil:
		return fmt.Errorf("%w: the log's last directory_install entry records an installed directory, but the state database holds none", errLogMismatch)
	case install == nil:
		return fmt.Errorf("%w: directory version %d is stored, but the log records no directory_install entry", errLogMismatch, stored.Version)
	}
	body, err := tlog.DecodeDirectoryInstallBody(install)
	if err != nil {
		return fmt.Errorf("%w: last directory_install entry: %w", errLogMismatch, err)
	}
	if body.Version != stored.Version || body.PolicyVersion != stored.PolicyVersion ||
		!bytes.Equal(body.Directory, stored.Doc) || !bytes.Equal(body.Sigs, stored.Sigs) {
		return fmt.Errorf("%w: the stored directory (version %d) is not the one the last directory_install entry records (version %d)",
			errLogMismatch, stored.Version, body.Version)
	}
	return nil
}

// CheckLog runs the start-up log check of serve without starting a signer:
// the stored leaves must decode, match their stored hashes and reproduce the
// latest checkpoint, which must verify with logKey (the recorded log key),
// and agree with the tables that commit with them (checkLogCovers, and the
// revocation rows with the revoke leaves: loggedRevocations.check). It only
// reads db. keyroster-signer doctor uses it; an error wraps the
// reason.
func CheckLog(ctx context.Context, db *signerdb.DB, logKey ssh.PublicKey) error {
	v, err := tlog.NewNoteVerifier(tlog.Origin(logKey), logKey)
	if err != nil {
		return fmt.Errorf("signer: log key: %w", err)
	}
	_, _, _, err = rebuildLogFrom(ctx, db, v)
	return err
}

// CheckTrust runs the start-up trust checks of serve that need no
// keystore backend, on one snapshot of db (it only reads): the installed
// trust bundle record must be consistent (version, policy hash), list
// exactly the recorded ca-init keys with no root among them (so the bundle's
// log key is the recorded one), name no online key or root as a policy
// admin, nor a root of any trust bundle the log records, carry a usable
// profile for every CA role and the recorded log key's origin, and be
// byte-identical to the body of the last bundle_install entry of the log.
// With no bundle installed, the log must record none. The latest stored
// directory must likewise be the one the last directory_install entry
// records (checkDirectoryLogged), and the published KRL state the one the
// last krl_publish entry records (checkKRLLogged), as serve requires at
// start.
// keyroster-signer doctor uses it; an error wraps the reason.
//
// It cannot catch a database rewritten consistently with keys and roots of
// the rewriter's choosing: it has neither the backend's keys nor the
// operator's root pins. serve refuses such a database only while the
// rewriter cannot also place their keys in the backend (with the agent
// backend, whoever can use the agent socket can); the check that holds is
// keyroster audit verify --pin.
func CheckTrust(ctx context.Context, db *signerdb.DB) error {
	var installs loggedInstalls
	snap, err := db.ReadLogWithHashes(ctx, func(idx uint64, leaf, _ []byte) error {
		l, err := tlog.DecodeLeaf(leaf)
		if err != nil {
			return fmt.Errorf("%w: leaf %d does not decode", errLogMismatch, idx)
		}
		switch l.Kind {
		case tlog.KindBundleInstall:
			return installs.add(idx, l.Body)
		case tlog.KindDirectoryInstall:
			return installs.addDirectory(idx, l.Body)
		case tlog.KindKRLPublish:
			installs.lastKRLPublish = l.Body
		}
		return nil
	})
	if err != nil {
		return err
	}
	if snap.CAKeys == nil {
		return ErrNotInitialised
	}
	if snap.Bundle != nil {
		ts, err := checkStoredTrust(snap.CAKeys, snap.Bundle)
		if err != nil {
			return err
		}
		if err := installs.checkAdmins(ts.policy); err != nil {
			return err
		}
	}
	if err := checkBundleLogged(snap.Bundle, installs.last); err != nil {
		return err
	}
	if err := checkDirectoryLogged(snap.Directory, installs.lastDirectory); err != nil {
		return err
	}
	return checkKRLLogged(snap.KRL, installs.lastKRLPublish)
}

// rebuildLogFrom is rebuildLog over db with the checkpoint verifier v. It
// reads the leaves, their stored hashes, the latest checkpoint and the
// tables checkLogCovers compares with them from one snapshot
// (signerdb.ReadLogWithHashes), so a leaf the signer appends meanwhile
// cannot make a healthy log look inconsistent (doctor runs against a live
// signer).
func rebuildLogFrom(ctx context.Context, db *signerdb.DB, v note.Verifier) (*tlog.Log, uint64, loggedInstalls, error) {
	var (
		last     uint64
		hashes   [][]byte
		installs loggedInstalls
		issued   issuedSummary
		revoked  = loggedRevocations{}
	)
	// ReadLogWithHashes yields idx = 0, 1, 2, ... without gaps.
	snap, err := db.ReadLogWithHashes(ctx, func(idx uint64, leaf, hash []byte) error {
		l, err := tlog.DecodeLeaf(leaf)
		if err != nil {
			return fmt.Errorf("%w: leaf %d does not decode", errLogMismatch, idx)
		}
		if l.Index != idx {
			return fmt.Errorf("%w: leaf %d records index %d", errLogMismatch, idx, l.Index)
		}
		if l.TimeMicros < last {
			return fmt.Errorf("%w: leaf %d is older than its predecessor", errLogMismatch, idx)
		}
		if !bytes.Equal(tlog.HashLeaf(leaf), hash) {
			return fmt.Errorf("%w: leaf %d does not match its stored hash", errLogMismatch, idx)
		}
		switch l.Kind {
		case tlog.KindBundleInstall:
			if err := installs.add(idx, l.Body); err != nil {
				return err
			}
		case tlog.KindDirectoryInstall:
			if err := installs.addDirectory(idx, l.Body); err != nil {
				return err
			}
		case tlog.KindIssue:
			b, err := tlog.DecodeIssueBody(l.Body)
			if err != nil {
				return fmt.Errorf("%w: leaf %d: issue body does not decode", errLogMismatch, idx)
			}
			issued.count++
			issued.lastSerial = b.Serial
		case tlog.KindLoginIssue:
			// A login certificate shares the issuance table and the serial
			// sequence with the admin path, so it counts the same way.
			b, err := tlog.DecodeLoginIssueBody(l.Body)
			if err != nil {
				return fmt.Errorf("%w: leaf %d: login_issue body does not decode", errLogMismatch, idx)
			}
			issued.count++
			issued.lastSerial = b.Serial
		case tlog.KindRevoke:
			// A revocation issues nothing: it must not change issued.
			b, err := tlog.DecodeRevokeBody(l.Body)
			if err != nil {
				return fmt.Errorf("%w: leaf %d: revoke body does not decode", errLogMismatch, idx)
			}
			if err := revoked.add(idx, b.Entries); err != nil {
				return err
			}
		case tlog.KindRevocationRecovery:
			// A recovery (03-06b) writes one revocation row per listed
			// entry and issues nothing, like a revocation.
			b, err := tlog.DecodeRecoveryBody(l.Body)
			if err != nil {
				return fmt.Errorf("%w: leaf %d: revocation_recovery body does not decode", errLogMismatch, idx)
			}
			if err := revoked.add(idx, b.Entries); err != nil {
				return err
			}
		case tlog.KindKRLPublish:
			if _, err := tlog.DecodeKRLPublishBody(l.Body); err != nil {
				return fmt.Errorf("%w: leaf %d: krl_publish body does not decode", errLogMismatch, idx)
			}
			installs.lastKRLPublish = l.Body
		case tlog.KindHostForget:
			// A forget (03-08c) issues and revokes nothing: it counts
			// nothing, but its body must decode.
			if _, err := tlog.DecodeHostForgetBody(l.Body); err != nil {
				return fmt.Errorf("%w: leaf %d: host_forget body does not decode", errLogMismatch, idx)
			}
		}
		last = l.TimeMicros
		hashes = append(hashes, hash)
		return nil
	})
	if err != nil {
		if errors.Is(err, errLogMismatch) {
			return nil, 0, loggedInstalls{}, err
		}
		return nil, 0, loggedInstalls{}, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		return nil, 0, loggedInstalls{}, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	if snap.Checkpoint == nil {
		if tree.Size() != 0 {
			return nil, 0, loggedInstalls{}, fmt.Errorf("%w: %d leaves but no checkpoint", errLogMismatch, tree.Size())
		}
		if err := checkLogCovers(snap, 0, issued); err != nil {
			return nil, 0, loggedInstalls{}, err
		}
		if err := revoked.check(snap.Revocations); err != nil {
			return nil, 0, loggedInstalls{}, err
		}
		installs.revoked = revoked
		return tree, 0, installs, nil
	}
	root, err := tree.Root()
	if err != nil {
		return nil, 0, loggedInstalls{}, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	cp, err := tlog.OpenCheckpoint(snap.Checkpoint, v)
	if err != nil {
		return nil, 0, loggedInstalls{}, fmt.Errorf("%w: latest checkpoint: %w", errLogMismatch, err)
	}
	if cp.Size != snap.Size || cp.Size != tree.Size() || !bytes.Equal(cp.Root, root) {
		return nil, 0, loggedInstalls{}, fmt.Errorf("%w: checkpoint size %d does not match the %d stored leaves and their root", errLogMismatch, cp.Size, tree.Size())
	}
	if err := checkLogCovers(snap, tree.Size(), issued); err != nil {
		return nil, 0, loggedInstalls{}, err
	}
	if err := revoked.check(snap.Revocations); err != nil {
		return nil, 0, loggedInstalls{}, err
	}
	installs.revoked = revoked
	return tree, last, installs, nil
}

// errRevocationsNotLogged is the revocations_not_logged start-up refusal.
var errRevocationsNotLogged = fmt.Errorf("%w: revocations_not_logged", errLogMismatch)

// loggedRevocations counts the entries of the revoke leaves of a log by
// revocationKey: what the revocation row written with each entry holds.
type loggedRevocations map[string]int

// revocationKey ties a revocation row to the entry of the revoke leaf it
// was written with: the leaf index, kind, CA key, serial, key ID, key and
// valid_before in microseconds (validBeforeMicros).
func revocationKey(leaf uint64, kind string, caKey []byte, serial uint64, keyID string, key []byte, validBeforeMicros uint64) string {
	return fmt.Sprintf("%d|%s|%x|%d|%q|%x|%d", leaf, kind, caKey, serial, keyID, key, validBeforeMicros)
}

// revocationKinds maps a revoked entry kind to the revocation row kind.
var revocationKinds = map[uint8]string{
	tlog.RevokedSerial: signerdb.RevocationSerial,
	tlog.RevokedKeyID:  signerdb.RevocationKeyID,
	tlog.RevokedKey:    signerdb.RevocationKey,
}

// add records the entries of the revoke leaf idx.
func (lr loggedRevocations) add(idx uint64, entries []tlog.RevokedEntry) error {
	for _, e := range entries {
		kind, ok := revocationKinds[e.Kind]
		if !ok {
			return fmt.Errorf("%w: leaf %d: revoked entry kind %d", errLogMismatch, idx, e.Kind)
		}
		lr[revocationKey(idx, kind, e.CAKey, e.Serial, e.KeyID, e.Key, validBeforeMicros(e.ValidBeforeSeconds))]++
	}
	return nil
}

// check requires the revocation rows (read from the same snapshot as the
// leaves) to be exactly the logged entries, one row per entry. The
// revocation table is not anchored in the signed checkpoint, but every KRL
// is rebuilt from it (publishKRLLocked): a row deleted outside the signer
// would be left out of the next KRL the ops key signs, which un-revokes
// that certificate on every host that installs it, and a row written
// outside the signer would be published with no revoke leaf recording it.
// Both are refused (revocations_not_logged), at start, by doctor and,
// against the entries the signer appended itself, at every publish
// (publishKRLLocked). Like checkLogCovers, it cannot catch the table
// rolled back together with the log to an earlier signed prefix. It
// does not modify lr.
func (lr loggedRevocations) check(rows []signerdb.Revocation) error {
	n := 0
	for _, c := range lr {
		n += c
	}
	left := maps.Clone(lr)
	if n != len(rows) {
		return fmt.Errorf("%w: the log records %d revoked entries, the state database %d revocation rows (rows deleted or written outside the signer?)",
			errRevocationsNotLogged, n, len(rows))
	}
	for _, r := range rows {
		k := revocationKey(r.LeafIndex, r.Kind, r.CAKey, r.Serial, r.KeyID, r.Key, r.ValidBeforeMicros)
		if left[k] == 0 {
			return fmt.Errorf("%w: revocation row %d is not an entry of revoke leaf %d", errRevocationsNotLogged, r.ID, r.LeafIndex)
		}
		left[k]--
	}
	return nil
}

// issuedSummary is what the issue and login_issue leaves of a log record
// about issuance, in log order: both kinds write an issuance row and raise
// the one serial high-water mark.
type issuedSummary struct {
	count      uint64 // issue and login_issue leaves
	lastSerial uint64 // serial of the last one, 0 when there is none
}

// checkLogCovers compares a log of size entries whose issue and
// login_issue leaves sum up to issued with the tables that commit in the same transactions as its
// leaves (snap, read from the same snapshot): ca-init writes the CA keys
// with the first leaf, and every issuance writes its issuance row and the
// serial high-water mark with its issue or login_issue leaf, and nothing
// deletes them. So the log is empty exactly when no CA keys are recorded,
// it has one issue or login_issue leaf per issuance row, and the last one
// carries the high-water mark. This catches the log tables alone rolled back to an earlier
// signed prefix, or wiped. It cannot catch the whole database restored
// from an older copy, those tables rolled back with the log, or trailing
// entries without issuance cut off: refusals, clock_regression, and
// bundle_install and directory_install entries together with their
// trust_bundle and directory rows, which brings back the older policy and
// directory. Only an earlier checkpoint kept outside the database
// (keyroster audit verify --previous) shows those (C-WR-01, Phase 4).
func checkLogCovers(snap *signerdb.LogSnapshot, size uint64, issued issuedSummary) error {
	switch {
	case snap.CAKeys != nil && size == 0:
		return fmt.Errorf("%w: CA keys are recorded, but the log is empty (wiped?)", errLogMismatch)
	case snap.CAKeys == nil && size != 0:
		return fmt.Errorf("%w: the log has %d entries, but no CA keys are recorded", errLogMismatch, size)
	case issued.count != snap.Issuances || issued.lastSerial != snap.LastSerial:
		return fmt.Errorf("%w: the log records %d issued certificates (issue and login_issue leaves) up to serial %d, the state database %d issuance rows and serial high-water mark %d (log or tables rolled back or modified?)",
			errLogMismatch, issued.count, issued.lastSerial, snap.Issuances, snap.LastSerial)
	}
	return nil
}

// appendLocked appends leaf (its Index is assigned here, and its time is
// raised to the previous leaf's if the clock went back) to the pending
// state of the open transaction tx: it writes the leaf and a checkpoint for
// the new size, signed with the log key, inside tx. The caller holds s.mu
// and runs tx through logTx, which publishes the pending state only after
// COMMIT.
func (s *Signer) appendLocked(_ context.Context, tx *sql.Tx, leaf tlog.Leaf) (uint64, error) {
	if s.broken != nil {
		return 0, s.broken
	}
	if s.pending == nil {
		s.pending, s.pendingMicros = s.tree.Clone(), s.lastMicros
	}
	leaf.Index = s.pending.Size()
	leaf.TimeMicros = max(leaf.TimeMicros, s.pendingMicros)
	enc, err := tlog.MarshalLeaf(leaf)
	if err != nil {
		return 0, err
	}
	hash := tlog.HashLeaf(enc)
	if err := s.pending.Append(hash); err != nil {
		return 0, err
	}
	root, err := s.pending.Root()
	if err != nil {
		return 0, err
	}
	signed, err := tlog.SignCheckpoint(tlog.Checkpoint{Origin: s.origin, Size: s.pending.Size(), Root: root}, s.cpSigner)
	if err != nil {
		return 0, err
	}
	if err := s.db.AppendLeaf(tx, leaf.Index, enc, hash); err != nil {
		return 0, err
	}
	if err := s.db.PutCheckpoint(tx, s.pending.Size(), signed); err != nil {
		return 0, err
	}
	entries, revokes, err := revokedEntriesOf(leaf)
	if err != nil {
		return 0, err
	}
	if revokes {
		if s.pendingRevoked == nil {
			s.pendingRevoked = maps.Clone(s.loaded.revoked)
			if s.pendingRevoked == nil {
				s.pendingRevoked = loggedRevocations{}
			}
		}
		if err := s.pendingRevoked.add(leaf.Index, entries); err != nil {
			return 0, err
		}
	}
	s.pendingMicros = leaf.TimeMicros
	return leaf.Index, nil
}

// revokedEntriesOf returns the revoked entries of a revoke or
// revocation_recovery leaf, and ok false for a leaf of any other kind.
func revokedEntriesOf(leaf tlog.Leaf) ([]tlog.RevokedEntry, bool, error) {
	switch leaf.Kind {
	case tlog.KindRevoke:
		b, err := tlog.DecodeRevokeBody(leaf.Body)
		if err != nil {
			return nil, false, err
		}
		return b.Entries, true, nil
	case tlog.KindRevocationRecovery:
		b, err := tlog.DecodeRecoveryBody(leaf.Body)
		if err != nil {
			return nil, false, err
		}
		return b.Entries, true, nil
	}
	return nil, false, nil
}

// logTx runs fn in one transaction (the caller holds s.mu). Leaves that fn
// appends through appendLocked join the in-memory log only after COMMIT
// succeeded; on any error they are discarded, and the state is reloaded
// from the database in case a failed commit reached the disk anyway.
func (s *Signer) logTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if s.broken != nil {
		return s.broken
	}
	s.pending, s.pendingRevoked = nil, nil
	err := s.db.WithTx(ctx, fn)
	next, nextMicros, nextRevoked := s.pending, s.pendingMicros, s.pendingRevoked
	s.pending, s.pendingRevoked = nil, nil
	if err == nil {
		if next != nil {
			s.tree, s.lastMicros = next, nextMicros
		}
		if nextRevoked != nil {
			s.loaded.revoked = nextRevoked
		}
		return nil
	}
	if next != nil {
		rerr := s.loadLog(context.WithoutCancel(ctx))
		if rerr == nil {
			// A COMMIT that reached the disk may have published a KRL:
			// serve the state the reloaded log records, not the one
			// cached before the transaction.
			rerr = s.loadKRL(context.WithoutCancel(ctx))
		}
		if rerr != nil {
			s.broken = fmt.Errorf("signer: audit log state unknown after a failed transaction: %w", rerr)
			s.log.Error("audit log unavailable", "error", rerr.Error())
		}
	}
	if errors.Is(err, errRevocationsNotLogged) && s.broken == nil {
		// publishKRLLocked found the revocation table changed while the
		// signer runs. The rows are not anchored in the log, so no reload
		// can tell which side is right: stop, as at start.
		s.broken = fmt.Errorf("signer: revocation table changed outside the signer: %w", err)
		s.log.Error("audit log unavailable", "error", err.Error())
	}
	return err
}
