// Package serverdb is keyroster-server's state database: pending accounts
// with their invites, the nonces of admin API requests already used, and
// web sign-in challenges and sessions. It is one SQLite file that only the
// server writes.
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
	// ErrExpired means the row was found but had expired; it is gone now.
	ErrExpired = errors.New("serverdb: expired")
	// ErrTooManySessions means the invite already has MaxOpenSessions
	// unexpired registration sessions.
	ErrTooManySessions = errors.New("serverdb: too many open registration sessions for this invite")
	// ErrInviteNotValid means the invite is not current: used, expired or
	// replaced by a reinvite.
	ErrInviteNotValid = errors.New("serverdb: invite not valid")
	// ErrDuplicateCredential means the credential ID is already pending,
	// or the user already has a pending credential.
	ErrDuplicateCredential = errors.New("serverdb: credential already pending")
)

// MaxOpenSessions is the most unexpired registration sessions one invite
// may hold at a time.
const MaxOpenSessions = 16

// DB is an open server state database.
type DB struct {
	db *sql.DB
	// afterPendingInvite, when a test sets it, runs inside PendingState
	// between the read of the invite and the read of the credentials. It
	// is nil outside tests.
	afterPendingInvite func()
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
// The old token stops matching at once. In the same transaction it marks
// the new invite unused, deletes every registration session of the old
// invite and deletes the account's pending credential: an unapproved
// passkey registered through a replaced invite is discarded, and the user
// registers again under the new one (02-08-F7, 02-07-F5). It is
// last-writer-wins: the single connection serializes concurrent
// reinvites, so exactly one token stays valid. No pending account with
// that name returns ErrNotFound.
func (d *DB) ReplaceInvite(ctx context.Context, name string, inviteHash []byte, expiresUS int64) error {
	if len(inviteHash) == 0 {
		return errors.New("serverdb: empty invite hash")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var old []byte
	err = tx.QueryRowContext(ctx, `SELECT invite_hash FROM pending_users WHERE name = ?`, name).Scan(&old)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("serverdb: replace invite: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM registration_sessions WHERE invite_hash = ?`, old); err != nil {
		return fmt.Errorf("serverdb: replace invite: drop sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pending_credentials WHERE user_name = ?`, name); err != nil {
		return fmt.Errorf("serverdb: replace invite: drop pending credential: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pending_users SET invite_hash = ?, invite_expires_us = ?, invite_used_us = NULL WHERE name = ?`, inviteHash, expiresUS, name); err != nil {
		return fmt.Errorf("serverdb: replace invite: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}

// PendingUser returns the pending account name, or ErrNotFound.
func (d *DB) PendingUser(ctx context.Context, name string) (*PendingUser, error) {
	return d.pendingUser(ctx, `SELECT name, user_handle, invite_hash, invite_expires_us, created_us, created_by FROM pending_users WHERE name = ?`, name)
}

// PendingUserByInvite returns the pending account whose invite hash is
// hash, whose invite has not expired at now and has not registered a
// credential yet, or ErrNotFound. It is the one invite lookup: the invite
// page and the registration begin both use it, so a used, expired,
// replaced or unknown invite gets the same answer everywhere.
func (d *DB) PendingUserByInvite(ctx context.Context, hash []byte, now time.Time) (*PendingUser, error) {
	return d.pendingUser(ctx, `SELECT name, user_handle, invite_hash, invite_expires_us, created_us, created_by FROM pending_users WHERE invite_hash = ? AND invite_expires_us > ? AND invite_used_us IS NULL`,
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

// CreateRegistrationSession stores session, the registration session data
// the server itself produced for one begun ceremony, under the invite hash
// and the ceremony's challenge until expiresUS. In one transaction it
// first deletes every session that expired at or before nowUS, then
// refuses with ErrTooManySessions when the invite already holds
// MaxOpenSessions sessions, and otherwise inserts.
func (d *DB) CreateRegistrationSession(ctx context.Context, inviteHash []byte, challenge string, session []byte, expiresUS, nowUS int64) error {
	if len(inviteHash) == 0 || challenge == "" || len(session) == 0 {
		return errors.New("serverdb: incomplete registration session")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM registration_sessions WHERE expires_us <= ?`, nowUS); err != nil {
		return fmt.Errorf("serverdb: purge registration sessions: %w", err)
	}
	var open int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM registration_sessions WHERE invite_hash = ?`, inviteHash).Scan(&open); err != nil {
		return fmt.Errorf("serverdb: count registration sessions: %w", err)
	}
	if open >= MaxOpenSessions {
		return ErrTooManySessions
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO registration_sessions (invite_hash, challenge, session, expires_us) VALUES (?, ?, ?, ?)`,
		inviteHash, challenge, session, expiresUS); err != nil {
		return fmt.Errorf("serverdb: insert registration session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}

// ConsumeRegistrationSession deletes the session stored under the invite
// hash and challenge and returns its data, in one statement (DELETE ...
// RETURNING), so a session is used at most once even when two finishes
// race. No such session is ErrNotFound; one that expired at or before
// nowUS is ErrExpired (and is gone as well).
func (d *DB) ConsumeRegistrationSession(ctx context.Context, inviteHash []byte, challenge string, nowUS int64) ([]byte, error) {
	var (
		session []byte
		expires int64
	)
	err := d.db.QueryRowContext(ctx, `DELETE FROM registration_sessions WHERE invite_hash = ? AND challenge = ? RETURNING session, expires_us`,
		inviteHash, challenge).Scan(&session, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("serverdb: consume registration session: %w", err)
	}
	if expires <= nowUS {
		return nil, ErrExpired
	}
	return session, nil
}

// PendingCredential is a credential registered through an invite and not
// yet bound by an admin-signed directory.
type PendingCredential struct {
	ID             string // unpadded base64url of the credential ID
	UserName       string
	Alg            int64  // COSE algorithm
	SPKI           []byte // public key, SPKI DER
	BackupEligible bool
	BackedUp       bool
	Registered     time.Time
}

// BindPendingCredential records cred as the credential the invite with
// inviteHash registered, in one transaction:
//
//  1. UPDATE pending_users SET invite_used_us ... WHERE invite_hash = ? AND
//     invite_used_us IS NULL AND invite_expires_us > ? RETURNING name. No
//     row means the invite was used, expired or replaced by a reinvite:
//     ErrInviteNotValid, nothing written. When cred.UserName is set, the
//     returned name must equal it.
//  2. INSERT INTO pending_credentials for that name. An ID already pending
//     or a user who already has a pending credential is
//     ErrDuplicateCredential, and the transaction rolls back.
func (d *DB) BindPendingCredential(ctx context.Context, inviteHash []byte, nowUS int64, cred PendingCredential) error {
	if len(inviteHash) == 0 || cred.ID == "" || len(cred.SPKI) == 0 {
		return errors.New("serverdb: incomplete pending credential")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var name string
	err = tx.QueryRowContext(ctx, `UPDATE pending_users SET invite_used_us = ? WHERE invite_hash = ? AND invite_used_us IS NULL AND invite_expires_us > ? RETURNING name`,
		nowUS, inviteHash, nowUS).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrInviteNotValid
	}
	if err != nil {
		return fmt.Errorf("serverdb: use invite: %w", err)
	}
	if cred.UserName != "" && cred.UserName != name {
		return ErrInviteNotValid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO pending_credentials (id, user_name, alg, spki, backup_eligible, backed_up, registered_us) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		cred.ID, name, cred.Alg, cred.SPKI, boolInt(cred.BackupEligible), boolInt(cred.BackedUp), nowUS)
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && (se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY || se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE) {
			return ErrDuplicateCredential
		}
		return fmt.Errorf("serverdb: insert pending credential: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}

// PendingCredentialExists reports whether a pending credential has the
// canonical ID id.
func (d *DB) PendingCredentialExists(ctx context.Context, id string) (bool, error) {
	var one int
	err := d.db.QueryRowContext(ctx, `SELECT 1 FROM pending_credentials WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("serverdb: read pending credential: %w", err)
	}
	return true, nil
}

// PendingCredentials returns the pending credentials of the account name,
// oldest first (at most one under the one-per-user index).
func (d *DB) PendingCredentials(ctx context.Context, name string) ([]PendingCredential, error) {
	return pendingCredentials(ctx, d.db, name)
}

// queryer is the read method *sql.DB and *sql.Tx share.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func pendingCredentials(ctx context.Context, q queryer, name string) ([]PendingCredential, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, user_name, alg, spki, backup_eligible, backed_up, registered_us FROM pending_credentials WHERE user_name = ? ORDER BY registered_us, id`, name)
	if err != nil {
		return nil, fmt.Errorf("serverdb: read pending credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PendingCredential
	for rows.Next() {
		var (
			c      PendingCredential
			be, bs int
			reg    int64
		)
		if err := rows.Scan(&c.ID, &c.UserName, &c.Alg, &c.SPKI, &be, &bs, &reg); err != nil {
			return nil, fmt.Errorf("serverdb: read pending credentials: %w", err)
		}
		c.BackupEligible, c.BackedUp = be == 1, bs == 1
		c.Registered = time.UnixMicro(reg).UTC()
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("serverdb: read pending credentials: %w", err)
	}
	return out, nil
}

// InviteUsed reports whether the current invite of the account name has
// registered a credential.
func (d *DB) InviteUsed(ctx context.Context, name string) (bool, error) {
	var used sql.NullInt64
	err := d.db.QueryRowContext(ctx, `SELECT invite_used_us FROM pending_users WHERE name = ?`, name).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("serverdb: read pending account: %w", err)
	}
	return used.Valid, nil
}

// PendingState is one consistent read of a pending account: the account
// with its current invite, whether that invite has registered a
// credential, and the account's pending credentials.
type PendingState struct {
	User        PendingUser
	InviteUsed  bool
	Credentials []PendingCredential
}

// PendingState reads the pending account name, whether its current
// invite is used and its pending credentials in one transaction, so a
// write that commits meanwhile (a reinvite, a registration) is seen whole
// or not at all. BindPendingCredential and ReplaceInvite each change the
// invite and the credential together, so a used invite comes with its
// credential and an unused one with none (02-08 pre-merge review). No
// pending account returns ErrNotFound.
func (d *DB) PendingState(ctx context.Context, name string) (*PendingState, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var (
		st                 PendingState
		expires, createdUS int64
		used               sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `SELECT name, user_handle, invite_hash, invite_expires_us, created_us, created_by, invite_used_us FROM pending_users WHERE name = ?`, name).
		Scan(&st.User.Name, &st.User.UserHandle, &st.User.InviteHash, &expires, &createdUS, &st.User.CreatedBy, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("serverdb: read pending account: %w", err)
	}
	st.User.InviteExpires = time.UnixMicro(expires).UTC()
	st.User.Created = time.UnixMicro(createdUS).UTC()
	st.InviteUsed = used.Valid
	if d.afterPendingInvite != nil {
		d.afterPendingInvite()
	}
	if st.Credentials, err = pendingCredentials(ctx, tx, name); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("serverdb: commit: %w", err)
	}
	return &st, nil
}

// PendingCredentialByID returns the pending credential with the canonical
// ID id (its ID, user name, algorithm and key; not its flags or time), or
// ErrNotFound when no pending credential has it.
func (d *DB) PendingCredentialByID(ctx context.Context, id string) (*PendingCredential, error) {
	pc := PendingCredential{ID: id}
	err := d.db.QueryRowContext(ctx, `SELECT user_name, alg, spki FROM pending_credentials WHERE id = ?`, id).Scan(&pc.UserName, &pc.Alg, &pc.SPKI)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("serverdb: read pending credential: %w", err)
	}
	return &pc, nil
}

// Binding is one credential an installed directory version binds: its
// canonical ID, the user that holds it in that version, and its COSE
// algorithm and key (SPKI DER).
type Binding struct {
	ID   string
	User string
	Alg  int64
	SPKI []byte
}

// DeleteBound removes, in one transaction, the pending state that an
// installed directory version has made obsolete. bound is every binding
// of that version, not only the ones the install added, so a pending row
// left behind by an earlier install (whose cleanup failed, or whose
// signer answer was lost) goes with the next accepted install (02-09-R2-F4).
//
//  1. For each binding it deletes the pending credential whose ID, user
//     name, algorithm and key all equal the binding's. A pending
//     credential of another user, or with another key, under the same ID
//     is never touched.
//  2. For each user whose pending credential it deleted, it deletes the
//     pending account, with its registration sessions, only when the
//     account has no pending credential left and its invite is not open:
//     used, or expired at nowUS. An open invite (unused and unexpired,
//     such as a directory user's invite for one more passkey) stays.
//
// The invariant of BindPendingCredential and ReplaceInvite holds after it:
// an account's invite is used exactly when it has its one pending
// credential. Deleting a used account's credential deletes the account.
func (d *DB) DeleteBound(ctx context.Context, bound []Binding, nowUS int64) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	emptied := map[string]bool{}
	for _, b := range bound {
		res, err := tx.ExecContext(ctx, `DELETE FROM pending_credentials WHERE id = ? AND user_name = ? AND alg = ? AND spki = ?`, b.ID, b.User, b.Alg, b.SPKI)
		if err != nil {
			return fmt.Errorf("serverdb: delete bound credential: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return fmt.Errorf("serverdb: delete bound credential: %w", err)
		} else if n > 0 {
			emptied[b.User] = true
		}
	}
	for name := range emptied {
		var hash []byte
		err := tx.QueryRowContext(ctx, `SELECT invite_hash FROM pending_users WHERE name = ?
			AND NOT EXISTS (SELECT 1 FROM pending_credentials WHERE user_name = ?)
			AND (invite_used_us IS NOT NULL OR invite_expires_us <= ?)`, name, name, nowUS).Scan(&hash)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("serverdb: read emptied pending account: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM registration_sessions WHERE invite_hash = ?`, hash); err != nil {
			return fmt.Errorf("serverdb: delete emptied account's sessions: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM pending_users WHERE name = ?`, name); err != nil {
			return fmt.Errorf("serverdb: delete emptied pending account: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}

// PendingSummary is one pending account as keyroster user list shows it.
type PendingSummary struct {
	Name          string
	InviteExpires time.Time
	InviteUsed    bool
	Credentials   int
}

// ListPending returns every pending account, sorted by name, with its
// invite's expiry, whether the invite is used and how many pending
// credentials it holds, read in one statement.
func (d *DB) ListPending(ctx context.Context) ([]PendingSummary, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT u.name, u.invite_expires_us, u.invite_used_us,
		(SELECT COUNT(*) FROM pending_credentials c WHERE c.user_name = u.name)
		FROM pending_users u ORDER BY u.name`)
	if err != nil {
		return nil, fmt.Errorf("serverdb: list pending accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []PendingSummary
	for rows.Next() {
		var (
			p       PendingSummary
			expires int64
			used    sql.NullInt64
		)
		if err := rows.Scan(&p.Name, &expires, &used, &p.Credentials); err != nil {
			return nil, fmt.Errorf("serverdb: list pending accounts: %w", err)
		}
		p.InviteExpires = time.UnixMicro(expires).UTC()
		p.InviteUsed = used.Valid
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("serverdb: list pending accounts: %w", err)
	}
	return out, nil
}

// CreateChallenge stores a begun web sign-in ceremony: the challenge
// bytes for user under id until expiresUS. In the same transaction it
// first deletes every challenge that expired at or before nowUS, so the
// table holds only live ceremonies (the sign-in rate limits bound how many
// there are).
func (d *DB) CreateChallenge(ctx context.Context, id, user string, challenge []byte, expiresUS, nowUS int64) error {
	if id == "" || user == "" || len(challenge) == 0 {
		return errors.New("serverdb: incomplete sign-in challenge")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM web_challenges WHERE expires_us <= ?`, nowUS); err != nil {
		return fmt.Errorf("serverdb: purge sign-in challenges: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO web_challenges (id, user_name, challenge, expires_us) VALUES (?, ?, ?, ?)`,
		id, user, challenge, expiresUS); err != nil {
		return fmt.Errorf("serverdb: insert sign-in challenge: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}

// TakeChallenge deletes the challenge stored under id and returns its user
// and bytes, in one statement (DELETE ... RETURNING), so a challenge is
// used at most once even when two finishes race. An absent challenge and
// one that expired at or before now are both ErrNotFound; either way the
// row is gone afterwards.
func (d *DB) TakeChallenge(ctx context.Context, id string, now time.Time) (user string, challenge []byte, err error) {
	var expires int64
	err = d.db.QueryRowContext(ctx, `DELETE FROM web_challenges WHERE id = ? RETURNING user_name, challenge, expires_us`, id).
		Scan(&user, &challenge, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("serverdb: take sign-in challenge: %w", err)
	}
	if expires <= now.UnixMicro() {
		return "", nil, ErrNotFound
	}
	return user, challenge, nil
}

// CreateSession stores a new web session: the SHA-256 of its ID (never
// the ID), the user and the credential whose assertion opened it, created
// and last seen at now. In the same transaction it first deletes every
// session already past idle or absolute at now, the limits TouchSession
// enforces, so expired rows do not accumulate.
func (d *DB) CreateSession(ctx context.Context, idHash []byte, user string, credID []byte, now time.Time, idle, absolute time.Duration) error {
	if len(idHash) == 0 || user == "" || len(credID) == 0 {
		return errors.New("serverdb: incomplete session")
	}
	nowUS := now.UnixMicro()
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE :now - last_seen_us > :idle OR :now - created_us > :absolute`,
		sql.Named("now", nowUS), sql.Named("idle", idle.Microseconds()), sql.Named("absolute", absolute.Microseconds())); err != nil {
		return fmt.Errorf("serverdb: purge sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions (id_hash, user_name, cred_id, created_us, last_seen_us) VALUES (?, ?, ?, ?, ?)`,
		idHash, user, credID, nowUS, nowUS); err != nil {
		return fmt.Errorf("serverdb: insert session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}

// TouchSession extends the session with ID hash idHash to now and returns
// its user and the credential that opened it, in one conditional
// statement: the row is updated only while it is within idle of its last
// use and within absolute of its creation, both at now (02-10-F5). The
// last-seen time never moves backwards. When no row matches, the row (if
// any) is deleted and the answer is ErrNotFound, so an expired session is
// never extended or revived, not even by a later call with an earlier now.
func (d *DB) TouchSession(ctx context.Context, idHash []byte, now time.Time, idle, absolute time.Duration) (user string, credID []byte, err error) {
	hash := sql.Named("hash", idHash)
	err = d.db.QueryRowContext(ctx, `UPDATE sessions SET last_seen_us = max(last_seen_us, :now) WHERE id_hash = :hash AND :now - last_seen_us <= :idle AND :now - created_us <= :absolute RETURNING user_name, cred_id`,
		hash, sql.Named("now", now.UnixMicro()), sql.Named("idle", idle.Microseconds()), sql.Named("absolute", absolute.Microseconds())).
		Scan(&user, &credID)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := d.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = :hash`, hash); err != nil {
			return "", nil, fmt.Errorf("serverdb: delete expired session: %w", err)
		}
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("serverdb: touch session: %w", err)
	}
	return user, credID, nil
}

// DeleteSession deletes the session with ID hash idHash and returns the
// user it belonged to. No such session returns ErrNotFound.
func (d *DB) DeleteSession(ctx context.Context, idHash []byte) (user string, err error) {
	err = d.db.QueryRowContext(ctx, `DELETE FROM sessions WHERE id_hash = ? RETURNING user_name`, idHash).Scan(&user)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("serverdb: delete session: %w", err)
	}
	return user, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// The states of a CLI login session (02-12).
const (
	LoginPending  = "pending"
	LoginApproved = "approved"
	LoginRedeemed = "redeemed"
)

// LoginSession is one keyroster login begun through the browser-loopback
// flow (02-12). Request is the CLI's LoginIssueRequest without evidence;
// Created is that request's CreatedAt, from which the handlers derive
// every deadline. CodeHash, CodeExpires and Assertion are set only once
// the passkey approved the session. Nothing in a row is authority.
type LoginSession struct {
	ID            string
	User          string
	Request       []byte
	CodeChallenge string
	State         string
	RedirectPort  int
	Status        string
	Assertion     []byte
	CodeHash      []byte
	CodeExpires   time.Time // zero until approved
	Created       time.Time
	Expires       time.Time
}

// CreateLogin stores a new pending login session. In the same transaction
// it first deletes every redeemed session (the signer's log is the record,
// and a deleted row cannot be redeemed again) and every session past its
// expiry whose code, if it has one, has expired too. An approved session
// whose code is still valid survives its own expiry until the code
// expires. With the login rate limits the table holds a few minutes of
// begins at most (02-12-F12).
func (d *DB) CreateLogin(ctx context.Context, l LoginSession, now time.Time) error {
	if l.ID == "" || l.User == "" || len(l.Request) == 0 || l.CodeChallenge == "" || l.State == "" || l.Created.IsZero() || l.Expires.IsZero() {
		return errors.New("serverdb: incomplete login session")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_sessions WHERE status = 'redeemed' OR (expires_us < :now AND (code_expires_us IS NULL OR code_expires_us < :now))`,
		sql.Named("now", now.UnixMicro())); err != nil {
		return fmt.Errorf("serverdb: purge login sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO login_sessions (id, user_name, request, code_challenge, state, redirect_port, status, created_us, expires_us) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
		l.ID, l.User, l.Request, l.CodeChallenge, l.State, l.RedirectPort, l.Created.UnixMicro(), l.Expires.UnixMicro()); err != nil {
		return fmt.Errorf("serverdb: insert login session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}

// Login returns the login session id whatever its expiry fields say: each
// handler applies its own deadline. No such row is ErrNotFound.
func (d *DB) Login(ctx context.Context, id string) (*LoginSession, error) {
	var (
		l           LoginSession
		codeExpires sql.NullInt64
		created     int64
		expires     int64
	)
	err := d.db.QueryRowContext(ctx, `SELECT id, user_name, request, code_challenge, state, redirect_port, status, assertion, code_hash, code_expires_us, created_us, expires_us FROM login_sessions WHERE id = ?`, id).
		Scan(&l.ID, &l.User, &l.Request, &l.CodeChallenge, &l.State, &l.RedirectPort, &l.Status, &l.Assertion, &l.CodeHash, &codeExpires, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("serverdb: read login session: %w", err)
	}
	if codeExpires.Valid {
		l.CodeExpires = time.UnixMicro(codeExpires.Int64)
	}
	l.Created, l.Expires = time.UnixMicro(created), time.UnixMicro(expires)
	return &l, nil
}

// ApproveLogin marks the login session id approved: it stores the
// assertion blob, the SHA-256 of the new single-use code and the code's
// expiry. Only a pending session whose expiry is not before now changes;
// any other is ErrNotFound and nothing is written.
func (d *DB) ApproveLogin(ctx context.Context, id string, assertion, codeHash []byte, codeExpires, now time.Time) error {
	if len(assertion) == 0 || len(codeHash) == 0 || codeExpires.IsZero() {
		return errors.New("serverdb: incomplete login approval")
	}
	res, err := d.db.ExecContext(ctx, `UPDATE login_sessions SET status = 'approved', assertion = ?, code_hash = ?, code_expires_us = ? WHERE id = ? AND status = 'pending' AND expires_us >= ?`,
		assertion, codeHash, codeExpires.UnixMicro(), id, now.UnixMicro())
	if err != nil {
		return fmt.Errorf("serverdb: approve login session: %w", err)
	}
	return oneRow(res)
}

// RedeemLogin burns the code of the login session id: one conditional
// UPDATE moves an approved session whose code hash is codeHash and whose
// code has not expired at now to redeemed. It is the single atomic step
// that makes a code single-use: of two concurrent redeems one changes the
// row and the other gets ErrNotFound.
func (d *DB) RedeemLogin(ctx context.Context, id string, codeHash []byte, now time.Time) error {
	res, err := d.db.ExecContext(ctx, `UPDATE login_sessions SET status = 'redeemed' WHERE id = ? AND status = 'approved' AND code_hash = ? AND code_expires_us >= ?`,
		id, codeHash, now.UnixMicro())
	if err != nil {
		return fmt.Errorf("serverdb: redeem login session: %w", err)
	}
	return oneRow(res)
}

// oneRow requires res to have changed exactly one row; none is
// ErrNotFound.
func oneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("serverdb: rows affected: %w", err)
	}
	switch n {
	case 1:
		return nil
	case 0:
		return ErrNotFound
	default:
		return fmt.Errorf("serverdb: %d rows changed, want 1", n)
	}
}
