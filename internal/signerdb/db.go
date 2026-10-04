// Package signerdb is keyroster-signer's state database: the serial
// high-water mark and the issuance index, in one SQLite file that only the
// signer writes. Later plans add the Merkle log tables through new
// migrations, so a state change and its audit entry commit together.
package signerdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver
)

// DB is an open signer state database.
type DB struct {
	db *sql.DB
}

// dsnParams: WAL with synchronous=FULL (a committed issuance survives power
// loss), foreign keys on, a 5 s busy timeout, and BEGIN IMMEDIATE for every
// transaction so the write lock is taken up front.
const dsnParams = "_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"

// Open opens (creating with mode 0600 if needed) the database at path and
// applies the embedded migrations.
func Open(path string) (*DB, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("signerdb: unusable database path %q", path)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the path is the operator's state directory
	if err != nil {
		return nil, fmt.Errorf("signerdb: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("signerdb: %w", err)
	}
	sqlDB, err := sql.Open("sqlite", path+"?"+dsnParams)
	if err != nil {
		return nil, fmt.Errorf("signerdb: %w", err)
	}
	// One connection: the signer is the only writer and serializes
	// issuance, and a single connection keeps every read on the state the
	// last commit left.
	sqlDB.SetMaxOpenConns(1)
	d := &DB{db: sqlDB}
	if err := d.migrate(context.Background()); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return d, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// WithTx runs fn in one BEGIN IMMEDIATE transaction and commits when fn
// returns nil; otherwise it rolls back and returns fn's error.
func (d *DB) WithTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("signerdb: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			return errors.Join(err, fmt.Errorf("signerdb: rollback: %w", rbErr))
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("signerdb: commit: %w", err)
	}
	return nil
}

// LastSerial returns the serial high-water mark.
func (d *DB) LastSerial(ctx context.Context) (uint64, error) {
	var last int64
	if err := d.db.QueryRowContext(ctx, `SELECT last_serial FROM serial_state WHERE id = 1`).Scan(&last); err != nil {
		return 0, fmt.Errorf("signerdb: read serial high-water mark: %w", err)
	}
	if last < 0 {
		return 0, errors.New("signerdb: negative serial high-water mark")
	}
	return uint64(last), nil //nolint:gosec // G115: last >= 0, checked above
}

// SetLastSerial raises the high-water mark to serial inside tx. It refuses
// to lower it or to set it to the same value.
func (d *DB) SetLastSerial(tx *sql.Tx, serial uint64) error {
	s, err := toInt64(serial)
	if err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE serial_state SET last_serial = ? WHERE id = 1 AND last_serial < ?`, s, s)
	if err != nil {
		return fmt.Errorf("signerdb: update serial high-water mark: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("signerdb: update serial high-water mark: %w", err)
	}
	if n != 1 {
		return errors.New("signerdb: serial high-water mark would not increase")
	}
	return nil
}

func toInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("signerdb: value %d does not fit SQLite INTEGER", v)
	}
	return int64(v), nil //nolint:gosec // G115: v <= math.MaxInt64, checked above
}
