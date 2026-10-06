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
	tree, last, err := s.rebuildLog(ctx)
	if err != nil {
		return err
	}
	s.tree, s.lastMicros, s.broken = tree, last, nil
	return nil
}

// rebuildLog recomputes the tree from the stored leaf bytes (not only the
// stored hashes) and requires the latest checkpoint to verify with the log
// key and to match the recomputed size and root.
func (s *Signer) rebuildLog(ctx context.Context) (*tlog.Log, uint64, error) {
	return rebuildLogFrom(ctx, s.db, s.cpVerifier)
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
	_, _, err = rebuildLogFrom(ctx, db, v)
	return err
}

// rebuildLogFrom is rebuildLog over db with the checkpoint verifier v.
func rebuildLogFrom(ctx context.Context, db *signerdb.DB, v note.Verifier) (*tlog.Log, uint64, error) {
	hashes, err := db.LeafHashes(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	var (
		last  uint64
		count int
	)
	// ForEachLeaf yields idx = 0, 1, 2, ... without gaps, so count == idx.
	err = db.ForEachLeaf(ctx, func(idx uint64, leaf []byte) error {
		if count >= len(hashes) {
			return fmt.Errorf("%w: leaf %d has no stored hash", errLogMismatch, idx)
		}
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
		if !bytes.Equal(tlog.HashLeaf(leaf), hashes[count]) {
			return fmt.Errorf("%w: leaf %d does not match its stored hash", errLogMismatch, idx)
		}
		last = l.TimeMicros
		count++
		return nil
	})
	if err != nil {
		if errors.Is(err, errLogMismatch) {
			return nil, 0, err
		}
		return nil, 0, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	if count != len(hashes) {
		return nil, 0, fmt.Errorf("%w: %d leaves, %d hashes", errLogMismatch, count, len(hashes))
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	root, err := tree.Root()
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	msg, size, err := db.LatestCheckpoint(ctx)
	if errors.Is(err, signerdb.ErrNoCheckpoint) {
		if tree.Size() != 0 {
			return nil, 0, fmt.Errorf("%w: %d leaves but no checkpoint", errLogMismatch, tree.Size())
		}
		return tree, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %w", errLogMismatch, err)
	}
	cp, err := tlog.OpenCheckpoint(msg, v)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: latest checkpoint: %w", errLogMismatch, err)
	}
	if cp.Size != size || cp.Size != tree.Size() || !bytes.Equal(cp.Root, root) {
		return nil, 0, fmt.Errorf("%w: checkpoint size %d does not match the %d stored leaves and their root", errLogMismatch, cp.Size, tree.Size())
	}
	return tree, last, nil
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
