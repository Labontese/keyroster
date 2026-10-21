// Package serverdb is keyroster-server's state database: pending accounts
// with their invites, and the nonces of admin API requests already used.
// It is one SQLite file that only the server writes.
//
// Nothing in it is authority. A pending account cannot sign in or obtain a
// certificate; only the admin-signed directory the signer has installed
// binds a credential to a user (D-03, AUTH-01). A server compromise can
// rewrite this file and gains nothing that the signer would honour.
package serverdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	// ErrExists means a pending account with that name already exists.
	ErrExists = errors.New("serverdb: pending account already exists")
	// ErrNotFound means no row matched.
	ErrNotFound = errors.New("serverdb: not found")
	// ErrNonceUsed means an admin nonce was already used: a replay.
	ErrNonceUsed = errors.New("serverdb: admin nonce already used")
)

// DB is an open server state database.
type DB struct {
	db *sql.DB
}

// dsnParams: WAL with synchronous=FULL, a 5 s busy timeout, and BEGIN
// IMMEDIATE for every transaction so the write lock is taken up front.
const dsnParams = "_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)&_txlock=immediate"

// Open opens (creating with mode 0600 if needed) the database at path and
// applies the embedded migrations. A database whose schema is newer than
// this binary knows is refused.
func Open(path string) (*DB, error) {
	if path == "" || strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("serverdb: unusable database path %q", path)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the path is the operator's state directory
	if err != nil {
		return nil, fmt.Errorf("serverdb: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("serverdb: %w", err)
	}
	sqlDB, err := sql.Open("sqlite", path+"?"+dsnParams)
	if err != nil {
		return nil, fmt.Errorf("serverdb: %w", err)
	}
	// One connection: every statement runs in order on the state the
	// last commit left, and concurrent writers (two reinvites, two adds)
	// are serialized.
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

// PendingUser is one pending account and its current invite.
type PendingUser struct {
	Name          string
	UserHandle    []byte // WebAuthn user handle, 32 random bytes
	InviteHash    []byte // SHA-256 of the invite token
	InviteExpires time.Time
	Created       time.Time
	CreatedBy     string // the admin who created it
}

// CreatePendingUser inserts u. A pending account with the same name returns
// ErrExists (the pending_users.name primary key); any other conflict, such
// as an equal user handle or invite hash, is a plain error.
func (d *DB) CreatePendingUser(ctx context.Context, u PendingUser) error {
	if u.Name == "" || len(u.UserHandle) == 0 || len(u.InviteHash) == 0 || u.InviteExpires.IsZero() || u.Created.IsZero() || u.CreatedBy == "" {
		return errors.New("serverdb: incomplete pending account")
	}
	_, err := d.db.ExecContext(ctx, `INSERT INTO pending_users (name, user_handle, invite_hash, invite_expires_us, created_us, created_by) VALUES (?, ?, ?, ?, ?, ?)`,
		u.Name, u.UserHandle, u.InviteHash, u.InviteExpires.UnixMicro(), u.Created.UnixMicro(), u.CreatedBy)
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY {
			return ErrExists
		}
		return fmt.Errorf("serverdb: insert pending account: %w", err)
	}
	return nil
}

// ReplaceInvite gives the pending account name a new invite: inviteHash
// and expiresUS replace the old ones in place, and the user handle stays.
// The old token stops matching at once. It is last-writer-wins: the single
// connection serializes concurrent reinvites, so exactly one token stays
// valid. No pending account with that name returns ErrNotFound.
func (d *DB) ReplaceInvite(ctx context.Context, name string, inviteHash []byte, expiresUS int64) error {
	if len(inviteHash) == 0 {
		return errors.New("serverdb: empty invite hash")
	}
	res, err := d.db.ExecContext(ctx, `UPDATE pending_users SET invite_hash = ?, invite_expires_us = ? WHERE name = ?`, inviteHash, expiresUS, name)
	if err != nil {
		return fmt.Errorf("serverdb: replace invite: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("serverdb: replace invite: %w", err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}

// PendingUser returns the pending account name, or ErrNotFound.
func (d *DB) PendingUser(ctx context.Context, name string) (*PendingUser, error) {
	return d.pendingUser(ctx, `SELECT name, user_handle, invite_hash, invite_expires_us, created_us, created_by FROM pending_users WHERE name = ?`, name)
}

// PendingUserByInvite returns the pending account whose invite hash is
// hash and whose invite has not expired at now, or ErrNotFound.
//
// Under migration 0001 no invite can be used yet. 02-08 adds the
// invite_used_us column and extends this lookup to require an unused
// invite as well.
func (d *DB) PendingUserByInvite(ctx context.Context, hash []byte, now time.Time) (*PendingUser, error) {
	return d.pendingUser(ctx, `SELECT name, user_handle, invite_hash, invite_expires_us, created_us, created_by FROM pending_users WHERE invite_hash = ? AND invite_expires_us > ?`,
		hash, now.UnixMicro())
}

func (d *DB) pendingUser(ctx context.Context, query string, args ...any) (*PendingUser, error) {
	var (
		u                  PendingUser
		expires, createdUS int64
	)
	err := d.db.QueryRowContext(ctx, query, args...).Scan(&u.Name, &u.UserHandle, &u.InviteHash, &expires, &createdUS, &u.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("serverdb: read pending account: %w", err)
	}
	u.InviteExpires = time.UnixMicro(expires).UTC()
	u.Created = time.UnixMicro(createdUS).UTC()
	return &u, nil
}

// UseNonce records the admin nonce as used until expires. In the same
// transaction it first deletes every row that expired at or before now.
// A nonce already recorded returns ErrNonceUsed: the request is a replay.
func (d *DB) UseNonce(ctx context.Context, nonce string, expires, now time.Time) error {
	if nonce == "" {
		return errors.New("serverdb: empty nonce")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM admin_nonces WHERE expires_us <= ?`, now.UnixMicro()); err != nil {
		return fmt.Errorf("serverdb: purge nonces: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_nonces (nonce, expires_us) VALUES (?, ?)`, nonce, expires.UnixMicro()); err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY {
			return ErrNonceUsed
		}
		return fmt.Errorf("serverdb: record nonce: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}
