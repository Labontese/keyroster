package signer

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/note"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
)

// errLogMismatch means the stored leaves do not reproduce the latest signed
// checkpoint (or do not decode): the state database was modified outside
// the signer, or restored inconsistently. The signer refuses to start.
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
	// loadedInstall is the body of the last bundle_install leaf of the log
	// as last loaded from the database (nil when it had none). New and
	// InstallBundle compare it with the stored trust bundle record.
	loadedInstall []byte

	// pending is the state after the appends of the open transaction. It
	// replaces tree only after COMMIT succeeded.
	pending       *tlog.Log
	pendingMicros uint64

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
	tree, last, install, err := s.rebuildLog(ctx)
	if err != nil {
		return err
	}
	s.tree, s.lastMicros, s.loadedInstall, s.broken = tree, last, install, nil
	return nil
}

// rebuildLog recomputes the tree from the stored leaf bytes (not only the
// stored hashes) and requires the latest checkpoint to verify with the log
// key and to match the recomputed size and root. It also returns the body
// of the last bundle_install leaf, or nil.
func (s *Signer) rebuildLog(ctx context.Context) (*tlog.Log, uint64, []byte, error) {
	return rebuildLogFrom(ctx, s.db, s.cpVerifier)
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

// CheckLog runs the start-up log check of serve without starting a signer:
// the stored leaves must decode, match their stored hashes and reproduce the
// latest checkpoint, which must verify with logKey (the recorded log key).
// It only reads db. keyroster-signer doctor uses it; an error wraps the
// reason.
func CheckLog(ctx context.Context, db *signerdb.DB, logKey ssh.PublicKey) error {
	v, err := tlog.NewNoteVerifier(tlog.Origin(logKey), logKey)
	if err != nil {
		return fmt.Errorf("signer: log key: %w", err)
	}
	_, _, _, err = rebuildLogFrom(ctx, db, v)
	return err
}

// rebuildLogFrom is rebuildLog over db with the checkpoint verifier v. It
// reads the leaves, their stored hashes and the latest checkpoint from one
// snapshot (signerdb.ReadLogWithHashes), so a leaf the signer appends
// meanwhile cannot make a healthy log look inconsistent (doctor runs
// against a live signer).
func rebuildLogFrom(ctx context.Context, db *signerdb.DB, v note.Verifier) (*tlog.Log, uint64, []byte, error) {
	var (
		last    uint64
		hashes  [][]byte
		install []byte
	)
	// ReadLogWithHashes yields idx = 0, 1, 2, ... without gaps.
	msg, size, err := db.ReadLogWithHashes(ctx, func(idx uint64, leaf, hash []byte) error {
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
		if l.Kind == tlog.KindBundleInstall {
			install = l.Body
		}
		last = l.TimeMicros
		hashes = append(hashes, hash)
		return nil
	})
	noCheckpoint := errors.Is(err, signerdb.ErrNoCheckpoint)
	if err != nil && !noCheckpoint {
		if errors.Is(err, errLogMismatch) {
			return nil, 0, nil, err
		}
		return nil, 0, nil, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	if noCheckpoint {
		if tree.Size() != 0 {
			return nil, 0, nil, fmt.Errorf("%w: %d leaves but no checkpoint", errLogMismatch, tree.Size())
		}
		return tree, 0, nil, nil
	}
	root, err := tree.Root()
	if err != nil {
		return nil, 0, nil, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	cp, err := tlog.OpenCheckpoint(msg, v)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("%w: latest checkpoint: %w", errLogMismatch, err)
	}
	if cp.Size != size || cp.Size != tree.Size() || !bytes.Equal(cp.Root, root) {
		return nil, 0, nil, fmt.Errorf("%w: checkpoint size %d does not match the %d stored leaves and their root", errLogMismatch, cp.Size, tree.Size())
	}
	return tree, last, install, nil
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
	s.pendingMicros = leaf.TimeMicros
	return leaf.Index, nil
}

// logTx runs fn in one transaction (the caller holds s.mu). Leaves that fn
// appends through appendLocked join the in-memory log only after COMMIT
// succeeded; on any error they are discarded, and the state is reloaded
// from the database in case a failed commit reached the disk anyway.
func (s *Signer) logTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	if s.broken != nil {
		return s.broken
	}
	s.pending = nil
	err := s.db.WithTx(ctx, fn)
	next, nextMicros := s.pending, s.pendingMicros
	s.pending = nil
	if err == nil {
		if next != nil {
			s.tree, s.lastMicros = next, nextMicros
		}
		return nil
	}
	if next != nil {
		if rerr := s.loadLog(context.WithoutCancel(ctx)); rerr != nil {
			s.broken = fmt.Errorf("signer: audit log state unknown after a failed transaction: %w", rerr)
			s.log.Error("audit log unavailable", "error", rerr.Error())
		}
	}
	return err
}
