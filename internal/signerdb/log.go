package signerdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// ErrNoCheckpoint means the log has no checkpoint yet (no leaf was ever
// appended).
var ErrNoCheckpoint = errors.New("signerdb: the log has no checkpoint")

// AppendLeaf stores leaf idx inside tx. The log has no gaps: idx must be
// exactly the next index (0 for an empty log, else one above the highest
// stored index).
func (d *DB) AppendLeaf(tx *sql.Tx, idx uint64, leaf, hash []byte) error {
	i, err := toInt64(idx)
	if err != nil {
		return err
	}
	if len(leaf) == 0 || len(hash) != 32 {
		return errors.New("signerdb: incomplete log leaf")
	}
	var next int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(idx) + 1, 0) FROM log_leaf`).Scan(&next); err != nil {
		return fmt.Errorf("signerdb: read log size: %w", err)
	}
	if next != i {
		return fmt.Errorf("signerdb: log leaf %d is not the next index %d", i, next)
	}
	if _, err := tx.Exec(`INSERT INTO log_leaf (idx, leaf, leaf_hash) VALUES (?, ?, ?)`, i, leaf, hash); err != nil {
		return fmt.Errorf("signerdb: insert log leaf: %w", err)
	}
	return nil
}

// PutCheckpoint stores the signed checkpoint for log size inside tx.
func (d *DB) PutCheckpoint(tx *sql.Tx, size uint64, note []byte) error {
	s, err := toInt64(size)
	if err != nil {
		return err
	}
	if s == 0 || len(note) == 0 {
		return errors.New("signerdb: incomplete checkpoint")
	}
	if _, err := tx.Exec(`INSERT INTO checkpoint (size, note) VALUES (?, ?)`, s, note); err != nil {
		return fmt.Errorf("signerdb: insert checkpoint: %w", err)
	}
	return nil
}

// LeafHashes returns the stored leaf hashes in index order.
func (d *DB) LeafHashes(ctx context.Context) ([][]byte, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT idx, leaf_hash FROM log_leaf ORDER BY idx`)
	if err != nil {
		return nil, fmt.Errorf("signerdb: read leaf hashes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out [][]byte
	for rows.Next() {
		var (
			idx  int64
			hash []byte
		)
		if err := rows.Scan(&idx, &hash); err != nil {
			return nil, fmt.Errorf("signerdb: read leaf hashes: %w", err)
		}
		if idx != int64(len(out)) {
			return nil, fmt.Errorf("signerdb: log leaf %d missing", len(out))
		}
		out = append(out, hash)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("signerdb: read leaf hashes: %w", err)
	}
	return out, nil
}

// LatestCheckpoint returns the checkpoint with the largest size, or
// ErrNoCheckpoint.
func (d *DB) LatestCheckpoint(ctx context.Context) ([]byte, uint64, error) {
	return latestCheckpoint(ctx, d.db)
}

// ForEachLeaf calls fn for every leaf in index order and stops at the first
// error.
func (d *DB) ForEachLeaf(ctx context.Context, fn func(idx uint64, leaf []byte) error) error {
	return forEachLeaf(ctx, d.db, -1, fn)
}

// ReadLog reads a consistent snapshot of the log in one read transaction:
// the latest checkpoint, and every leaf below its size, in index order.
func (d *DB) ReadLog(ctx context.Context, fn func(idx uint64, leaf []byte) error) (note []byte, size uint64, err error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("signerdb: begin read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	note, size, err = latestCheckpoint(ctx, tx)
	if err != nil {
		return nil, 0, err
	}
	n, err := toInt64(size)
	if err != nil {
		return nil, 0, err
	}
	if err := forEachLeaf(ctx, tx, n, fn); err != nil {
		return nil, 0, err
	}
	return note, size, nil
}

// ReadLogWithHashes reads the whole log from one consistent snapshot, in
// one read transaction: it calls fn for every leaf with its stored hash, in
// index order, and then returns the latest checkpoint, or ErrNoCheckpoint
// when there is none (fn has then seen every leaf). Appends committed
// meanwhile are not seen, so the leaves, hashes and checkpoint always
// belong together.
func (d *DB) ReadLogWithHashes(ctx context.Context, fn func(idx uint64, leaf, hash []byte) error) (note []byte, size uint64, err error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, 0, fmt.Errorf("signerdb: begin read: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT idx, leaf, leaf_hash FROM log_leaf ORDER BY idx`)
	if err != nil {
		return nil, 0, fmt.Errorf("signerdb: read log leaves: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var want int64
	for rows.Next() {
		var (
			idx        int64
			leaf, hash []byte
		)
		if err := rows.Scan(&idx, &leaf, &hash); err != nil {
			return nil, 0, fmt.Errorf("signerdb: read log leaves: %w", err)
		}
		if idx != want {
			return nil, 0, fmt.Errorf("signerdb: log leaf %d missing", want)
		}
		want++
		if err := fn(uint64(idx), leaf, hash); err != nil { //nolint:gosec // G115: idx == want-1 >= 0
			return nil, 0, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("signerdb: read log leaves: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, 0, fmt.Errorf("signerdb: read log leaves: %w", err)
	}
	return latestCheckpoint(ctx, tx)
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func latestCheckpoint(ctx context.Context, q queryer) ([]byte, uint64, error) {
	var (
		size int64
		note []byte
	)
	err := q.QueryRowContext(ctx, `SELECT size, note FROM checkpoint ORDER BY size DESC LIMIT 1`).Scan(&size, &note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrNoCheckpoint
	}
	if err != nil {
		return nil, 0, fmt.Errorf("signerdb: read checkpoint: %w", err)
	}
	if size <= 0 {
		return nil, 0, errors.New("signerdb: invalid checkpoint size")
	}
	return note, uint64(size), nil //nolint:gosec // G115: size > 0, checked above
}

// forEachLeaf iterates leaves in index order; limit >= 0 stops below that
// index and requires exactly limit leaves.
func forEachLeaf(ctx context.Context, q queryer, limit int64, fn func(idx uint64, leaf []byte) error) error {
	query, args := `SELECT idx, leaf FROM log_leaf ORDER BY idx`, []any(nil)
	if limit >= 0 {
		query, args = `SELECT idx, leaf FROM log_leaf WHERE idx < ? ORDER BY idx`, []any{limit}
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("signerdb: read log leaves: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var want int64
	for rows.Next() {
		var (
			idx  int64
			leaf []byte
		)
		if err := rows.Scan(&idx, &leaf); err != nil {
			return fmt.Errorf("signerdb: read log leaves: %w", err)
		}
		if idx != want {
			return fmt.Errorf("signerdb: log leaf %d missing", want)
		}
		want++
		if err := fn(uint64(idx), leaf); err != nil { //nolint:gosec // G115: idx >= 0 (CHECK constraint, and idx == want >= 0)
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("signerdb: read log leaves: %w", err)
	}
	if limit >= 0 && want != limit {
		return fmt.Errorf("signerdb: log has %d leaves below checkpoint size %d", want, limit)
	}
	return nil
}

// OpenReadOnly opens an existing database read-only (SQLite mode=ro,
// query_only), for export. It applies no migrations and refuses a schema
// version other than the one this binary writes.
func OpenReadOnly(path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("signerdb: empty database path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("signerdb: %w", err)
	}
	// A file: URI (path escaped by url.URL) so that SQLite applies
	// mode=ro; the driver strips the parameters of a plain file name.
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a Windows drive path: file:///C:/...
	}
	u := url.URL{Scheme: "file", Path: p}
	sqlDB, err := sql.Open("sqlite", u.String()+"?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		return nil, fmt.Errorf("signerdb: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	d := &DB{db: sqlDB}
	ms, err := loadMigrations()
	if err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	var version int
	if err := sqlDB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("signerdb: open %s read-only: %w", path, err)
	}
	if version != len(ms) {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("signerdb: %s has schema version %d, this binary reads %d", path, version, len(ms))
	}
	return d, nil
}
