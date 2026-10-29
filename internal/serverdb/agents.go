package serverdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Refusals of a join token use and of an enrollment (03-07).
var (
	// ErrTokenUnknown is a join token the server never minted.
	ErrTokenUnknown = errors.New("token_unknown")
	// ErrTokenUsed is a join token that already enrolled an agent.
	ErrTokenUsed = errors.New("token_used")
	// ErrTokenExpired is a join token presented at or after its expiry.
	ErrTokenExpired = errors.New("token_expired")
	// ErrIdentityInUse is an agent identity that is enrolled already.
	ErrIdentityInUse = errors.New("identity_in_use")
	// ErrHostKeysInUse is a host key another enrolled agent holds.
	ErrHostKeysInUse = errors.New("host_keys_in_use")
	// ErrTokenExists is a token hash minted before (a random collision).
	ErrTokenExists = errors.New("serverdb: join token exists")
)

// CreateJoinToken stores a minted join token: only the SHA-256 of its raw
// bytes (32 bytes), the host name the admin expects, who minted it and
// its expiry (microseconds, a whole second).
func (d *DB) CreateJoinToken(ctx context.Context, tokenHash []byte, expectedName, createdBy string, expiresUS int64) error {
	if len(tokenHash) != 32 || expectedName == "" || createdBy == "" {
		return errors.New("serverdb: incomplete join token")
	}
	_, err := d.db.ExecContext(ctx, `INSERT INTO join_tokens (token_hash, expected_name, expires_at_us, created_by) VALUES (?, ?, ?, ?)`,
		tokenHash, expectedName, expiresUS, createdBy)
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY {
			return ErrTokenExists
		}
		return fmt.Errorf("serverdb: create join token: %w", err)
	}
	return nil
}

// JoinTokenUsed reports whether the join token tokenHash has been used
// (false for an unknown token). Tests read it.
func (d *DB) JoinTokenUsed(ctx context.Context, tokenHash []byte) (bool, error) {
	var used sql.NullInt64
	err := d.db.QueryRowContext(ctx, `SELECT used_at_us FROM join_tokens WHERE token_hash = ?`, tokenHash).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("serverdb: join token: %w", err)
	}
	return used.Valid, nil
}

// CountJoinTokens returns how many join tokens exist. Tests read it.
func (d *DB) CountJoinTokens(ctx context.Context) (int, error) {
	var n int
	if err := d.db.QueryRowContext(ctx, `SELECT count(*) FROM join_tokens`).Scan(&n); err != nil {
		return 0, fmt.Errorf("serverdb: count join tokens: %w", err)
	}
	return n, nil
}

// Agent is one enrolled agent. HostKeys are sorted trust.FormatKey
// strings, Facts the facts' JSON as the agent sent them, TokenSHA256 the
// SHA-256 of the join token that enrolled it.
type Agent struct {
	ID                 int64
	IdentitySPKISHA256 []byte
	TokenSHA256        []byte
	ExpectedName       string
	HostKeys           []string
	Facts              string
	EnrolledAtUS       int64
	LastSeenUS         int64 // 0: never seen after enrollment
	// ApprovedAtUS is when the agent first got signed state while the
	// directory approved it (0: never). An agent approved once keeps
	// getting state after its host entry goes (PR #71 review D-R1).
	ApprovedAtUS int64
	// RemovedDirVersion is, for an agent approved once, the first
	// directory version it requested state under that no longer approves
	// it (0: none since it was last approved; 03-08).
	RemovedDirVersion uint64
	// ClockOffsetS is the clock offset of the newest heartbeat that
	// authenticated and parsed, stored or refused (ClockOffsetKnown false:
	// none yet), and SeqRegressedAtUS when a seq below the stored one was
	// last refused and logged (0: never; owner decision D-R2).
	ClockOffsetS     int64
	ClockOffsetKnown bool
	SeqRegressedAtUS int64
	// IdentityRotatedAtUS is when the identity last rotated (0: never),
	// IdentityRotations how often it has (owner decision D-R1).
	IdentityRotatedAtUS int64
	IdentityRotations   int64
	// RemovalConfirmedVersion and RemovalConfirmedSHA256 are the directory
	// version and the raw SHA-256 of its document whose application, in
	// the host's own heartbeat, confirmed the removal at RemovedDirVersion
	// (0 and nil: none recorded; 03-08b, RecordRemovalConfirmed).
	RemovalConfirmedVersion uint64
	RemovalConfirmedSHA256  []byte
}

// EnrollAgent uses the join token tokenHash and records a as an enrolled
// agent, in one transaction, at nowUS (a whole second). It refuses, and
// then changes nothing (the token stays unused):
//   - ErrTokenUnknown, ErrTokenUsed and ErrTokenExpired (expires_at_us at
//     or before nowUS);
//   - ErrIdentityInUse when another agent has a's identity;
//   - ErrHostKeysInUse when another agent holds one of a's host keys.
//
// The token is used by one conditional UPDATE (unused, unexpired), so two
// enrollments with one token cannot both pass. a.ExpectedName is set from
// the token, and the agent's ID is returned.
func (d *DB) EnrollAgent(ctx context.Context, tokenHash []byte, a Agent, nowUS int64) (*Agent, error) {
	if len(a.IdentitySPKISHA256) != 32 || len(a.HostKeys) == 0 {
		return nil, errors.New("serverdb: incomplete agent")
	}
	keys, err := json.Marshal(a.HostKeys)
	if err != nil {
		return nil, err
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var (
		name    string
		expires int64
		used    sql.NullInt64
	)
	err = tx.QueryRowContext(ctx, `SELECT expected_name, expires_at_us, used_at_us FROM join_tokens WHERE token_hash = ?`, tokenHash).Scan(&name, &expires, &used)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrTokenUnknown
	case err != nil:
		return nil, fmt.Errorf("serverdb: join token: %w", err)
	case used.Valid:
		return nil, ErrTokenUsed
	case expires <= nowUS:
		return nil, ErrTokenExpired
	}
	var one int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM agents WHERE identity_spki_sha256 = ?`, a.IdentitySPKISHA256).Scan(&one)
	if err == nil {
		return nil, ErrIdentityInUse
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("serverdb: agent identity: %w", err)
	}
	others, err := listAgents(ctx, tx)
	if err != nil {
		return nil, err
	}
	for _, o := range others {
		for _, k := range a.HostKeys {
			if slices.Contains(o.HostKeys, k) {
				return nil, ErrHostKeysInUse
			}
		}
	}
	if err := tx.QueryRowContext(ctx, `UPDATE join_tokens SET used_at_us = ? WHERE token_hash = ? AND used_at_us IS NULL AND expires_at_us > ? RETURNING expected_name`,
		nowUS, tokenHash, nowUS).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTokenUsed
		}
		return nil, fmt.Errorf("serverdb: use join token: %w", err)
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO agents (identity_spki_sha256, token_hash, expected_name, host_keys, facts, enrolled_at_us) VALUES (?, ?, ?, ?, ?, ?)`,
		a.IdentitySPKISHA256, tokenHash, name, string(keys), a.Facts, nowUS)
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return nil, ErrIdentityInUse
		}
		return nil, fmt.Errorf("serverdb: record agent: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("serverdb: agent id: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("serverdb: commit: %w", err)
	}
	out := a
	out.ID, out.ExpectedName, out.EnrolledAtUS, out.TokenSHA256 = id, name, nowUS, slices.Clone(tokenHash)
	return &out, nil
}

// ListAgents returns every enrolled agent, by ID.
func (d *DB) ListAgents(ctx context.Context) ([]Agent, error) { return listAgents(ctx, d.db) }

func listAgents(ctx context.Context, q queryer) ([]Agent, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("serverdb: list agents: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("serverdb: list agents: %w", err)
	}
	return out, nil
}

// AgentBySPKI returns the agent whose identity SPKI hash is spki, or
// ErrNotFound.
func (d *DB) AgentBySPKI(ctx context.Context, spki []byte) (*Agent, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE identity_spki_sha256 = ?`, spki)
	if err != nil {
		return nil, fmt.Errorf("serverdb: agent: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("serverdb: agent: %w", err)
		}
		return nil, ErrNotFound
	}
	return scanAgent(rows)
}

// AgentKey names one enrollment of an agents row: its row ID, its
// identity SPKI hash and the SHA-256 of the join token that enrolled it.
// Every agents-row writer matches all three (03-08b): SQLite reuses the
// highest row ID, and the runbook's same-machine re-enrollment keeps the
// identity, so only the token tells a new enrollment from a forgotten one
// (PR #74 pre-merge review, finding 8). Each join token enrolls at most
// one row, and an identity rotation keeps the token (RotateAgentIdentity
// changes only the identity), so a request of a forgotten agent never
// writes a row that reused its ID and its identity.
type AgentKey struct {
	ID          int64
	SPKI        []byte
	TokenSHA256 []byte
}

// Key is a's AgentKey.
func (a *Agent) Key() AgentKey {
	return AgentKey{ID: a.ID, SPKI: a.IdentitySPKISHA256, TokenSHA256: a.TokenSHA256}
}

// agentKeyWhere is the WHERE terms of an AgentKey, bound by its args.
const agentKeyWhere = `id = ? AND identity_spki_sha256 = ? AND token_hash = ?`

func (k AgentKey) args() []any { return []any{k.ID, k.SPKI, k.TokenSHA256} }

// keyArgs is first, then k's arguments.
func keyArgs(k AgentKey, first ...any) []any { return append(first, k.args()...) }

// TouchAgent sets the last_seen_us of the agents row k to nowUS. It is
// ErrNotFound when no row matches k (03-08b, AgentKey).
func (d *DB) TouchAgent(ctx context.Context, k AgentKey, nowUS int64) error {
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET last_seen_us = ? WHERE `+agentKeyWhere, keyArgs(k, nowUS)...)
	if err != nil {
		return fmt.Errorf("serverdb: touch agent: %w", err)
	}
	return oneRow(res)
}

// MarkAgentApproved records nowUS as the first approved state answer of
// the agents row k; a later call keeps the first time (PR #71 review
// D-R1). It is ErrNotFound when no row matches k (03-08b).
func (d *DB) MarkAgentApproved(ctx context.Context, k AgentKey, nowUS int64) error {
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET approved_at_us = ? WHERE `+agentKeyWhere+` AND approved_at_us IS NULL`, keyArgs(k, nowUS)...)
	if err != nil {
		return fmt.Errorf("serverdb: mark agent approved: %w", err)
	}
	if err := oneRow(res); !errors.Is(err, ErrNotFound) {
		return err
	}
	// Nothing changed: the row is gone, or it was approved already.
	return agentExists(ctx, d.db, k)
}

// ForgetFacts are what the admin saw of an agent in keyroster host
// pending, which a forget names and DeleteAgentIf re-checks (03-08b):
// whether the directory approved it once, its removal version (0: none)
// and its recorded removal confirmation (ConfirmedVersion 0 and
// ConfirmedSHA256 nil: none; the SHA-256 is raw, 32 bytes), and when it
// enrolled (EnrolledAtUS, 03-08c): a forget is bound to the one enrollment
// the admin saw, so it never deletes a later enrollment of the same
// identity with the same facts.
type ForgetFacts struct {
	ApprovedOnce     bool
	RemovalVersion   uint64
	ConfirmedVersion uint64
	ConfirmedSHA256  []byte
	EnrolledAtUS     int64
}

// ForgetFacts are a's ForgetFacts as the row holds them.
func (a *Agent) ForgetFacts() ForgetFacts {
	return ForgetFacts{ApprovedOnce: a.ApprovedAtUS != 0, RemovalVersion: a.RemovedDirVersion,
		ConfirmedVersion: a.RemovalConfirmedVersion, ConfirmedSHA256: a.RemovalConfirmedSHA256, EnrolledAtUS: a.EnrolledAtUS}
}

// nullVersion binds a version, NULL for 0 (IS ? then matches a NULL
// column; a bound 0 never would).
func nullVersion(v uint64) (any, error) {
	switch {
	case v == 0:
		return nil, nil
	case v > math.MaxInt64:
		return nil, errors.New("serverdb: directory version above int64")
	}
	return int64(v), nil //nolint:gosec // G115: checked above
}

// nullBlob binds b, NULL for an empty b (an empty blob is not NULL).
func nullBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// DeleteAgentIf removes the agents row k (AgentKey: a re-enrollment of
// the same identity into the reused row ID is another row), and its
// heartbeat, which frees its identity and host keys for a new enrollment
// (keyroster host forget; PR #71 review D-R1), but only while the row's
// approval, removal version, recorded confirmation and enrollment time
// still equal facts (03-08b, plan check item 1; 03-08c). The heartbeat and the row are deleted in
// one transaction, the row by one statement that re-checks every fact;
// when it deletes no row (the row is gone, its identity rotated, or a fact
// changed after the caller checked it) nothing is deleted and the answer
// is ErrNotFound. foreign_keys is off, so the heartbeat is deleted here.
//
// With a non-nil hbCheck, the row's stored heartbeat body (nil when none is
// stored) is read in the same transaction, before anything is deleted, and
// a non-nil error from hbCheck refuses the delete with that error: the
// server refuses a forget while the host reports a swap it has not
// finished (03-08c). The transaction holds the database's one connection
// from its start (_txlock=immediate), so no heartbeat is stored between
// the check and the delete.
func (d *DB) DeleteAgentIf(ctx context.Context, k AgentKey, facts ForgetFacts, hbCheck func(body []byte) error) error {
	removal, err := nullVersion(facts.RemovalVersion)
	if err != nil {
		return err
	}
	confirmed, err := nullVersion(facts.ConfirmedVersion)
	if err != nil {
		return err
	}
	if (confirmed == nil) != (len(facts.ConfirmedSHA256) == 0) {
		return errors.New("serverdb: a confirmation needs both its version and its SHA-256")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if hbCheck != nil {
		var body []byte
		err := tx.QueryRowContext(ctx, `SELECT body FROM heartbeats WHERE agent_id = (SELECT id FROM agents WHERE `+agentKeyWhere+`)`, k.args()...).Scan(&body)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			body = nil
		case err != nil:
			return fmt.Errorf("serverdb: heartbeat: %w", err)
		}
		if err := hbCheck(body); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM heartbeats WHERE agent_id = ?`, k.ID); err != nil {
		return fmt.Errorf("serverdb: delete heartbeat: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM agents WHERE `+agentKeyWhere+` AND removed_dir_version IS ?
AND removal_confirmed_version IS ? AND removal_confirmed_sha256 IS ? AND (approved_at_us IS NULL) = ? AND enrolled_at_us = ?`,
		append(k.args(), removal, confirmed, nullBlob(facts.ConfirmedSHA256), !facts.ApprovedOnce, facts.EnrolledAtUS)...)
	if err != nil {
		return fmt.Errorf("serverdb: delete agent: %w", err)
	}
	if err := oneRow(res); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serverdb: commit: %w", err)
	}
	return nil
}

// RecordRemovalConfirmed records {version, sha256} (sha256 raw, 32 bytes)
// as the confirmation of the removal at removedVersion of the agents row k
// (03-08b), decided from the row's stored heartbeat with seq hbSeq. It
// records only while that removal version is still the recorded one, no
// confirmation is, and the stored heartbeat is still the one with hbSeq:
// a removal cleared or re-recorded since the caller read the row, or a
// newer heartbeat stored meanwhile (which may show principals again,
// owner decision D-R1), records nothing, and the next heartbeat or host
// pending runs the rule again. It reports whether it recorded;
// ErrNotFound when no row matches k.
func (d *DB) RecordRemovalConfirmed(ctx context.Context, k AgentKey, hbSeq int64, removedVersion, version uint64, sha256 []byte) (bool, error) {
	if removedVersion == 0 || version < removedVersion || version > math.MaxInt64 || len(sha256) != 32 || hbSeq < 1 {
		return false, errors.New("serverdb: incomplete removal confirmation")
	}
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET removal_confirmed_version = ?, removal_confirmed_sha256 = ?
WHERE `+agentKeyWhere+` AND removed_dir_version = ? AND removal_confirmed_version IS NULL AND `+storedSeqIs,
		append(keyArgs(k, int64(version), sha256), int64(removedVersion), hbSeq)...) //nolint:gosec // G115: removedVersion <= version <= MaxInt64, checked above
	if err != nil {
		return false, fmt.Errorf("serverdb: record removal confirmation: %w", err)
	}
	return changedOrExists(ctx, d.db, res, k)
}

// storedSeqIs is the condition that the agents row's stored heartbeat has
// the seq it binds (a decision made from that heartbeat still stands).
const storedSeqIs = `(SELECT seq FROM heartbeats WHERE agent_id = agents.id) = ?`

// ClearRemovalConfirmed clears the recorded removal confirmation of the
// agents row k (owner decision D-R1, PR #74 review fix round 1), decided
// from the row's stored heartbeat with seq hbSeq, which shows principals
// again: the host resumed service, so its forget needs --host-gone again
// until a later heartbeat confirms a removal anew. The removal version
// stays. It clears only while a confirmation is recorded and the stored
// heartbeat is still the one with hbSeq, and reports whether it cleared;
// ErrNotFound when no row matches k.
func (d *DB) ClearRemovalConfirmed(ctx context.Context, k AgentKey, hbSeq int64) (bool, error) {
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET removal_confirmed_version = NULL, removal_confirmed_sha256 = NULL
WHERE `+agentKeyWhere+` AND removal_confirmed_version IS NOT NULL AND `+storedSeqIs, append(k.args(), hbSeq)...)
	if err != nil {
		return false, fmt.Errorf("serverdb: clear removal confirmation: %w", err)
	}
	return changedOrExists(ctx, d.db, res, k)
}

// changedOrExists reports whether res changed the agents row k: true when
// it did, false when it did not and the row exists, ErrNotFound when no
// row matches k.
func changedOrExists(ctx context.Context, q rowQueryer, res sql.Result, k AgentKey) (bool, error) {
	if err := oneRow(res); !errors.Is(err, ErrNotFound) {
		return err == nil, err
	}
	if err := agentExists(ctx, q, k); err != nil {
		return false, err
	}
	return false, nil
}

// rowQueryer is a *sql.DB or a *sql.Tx.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// agentExists is ErrNotFound unless the agents row k exists.
func agentExists(ctx context.Context, q rowQueryer, k AgentKey) error {
	var one int
	err := q.QueryRowContext(ctx, `SELECT 1 FROM agents WHERE `+agentKeyWhere, k.args()...).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("serverdb: agent: %w", err)
	}
	return nil
}

// SetAgentRemovedVersion records version as the first directory version
// that no longer approves the agents row k, unless one is recorded
// already. A version of 0 clears it and its recorded confirmation (a
// directory entry holds the agent's keys again). It is ErrNotFound when
// no row matches k (03-08b, AgentKey).
func (d *DB) SetAgentRemovedVersion(ctx context.Context, k AgentKey, version uint64) error {
	if version > math.MaxInt64 {
		return errors.New("serverdb: directory version above int64")
	}
	var (
		res sql.Result
		err error
	)
	if version == 0 {
		res, err = d.db.ExecContext(ctx, `UPDATE agents SET removed_dir_version = NULL, removal_confirmed_version = NULL, removal_confirmed_sha256 = NULL
WHERE `+agentKeyWhere, k.args()...)
	} else {
		res, err = d.db.ExecContext(ctx, `UPDATE agents SET removed_dir_version = ? WHERE `+agentKeyWhere+` AND removed_dir_version IS NULL`,
			keyArgs(k, int64(version))...) //nolint:gosec // G115: checked above
	}
	if err != nil {
		return fmt.Errorf("serverdb: agent removal version: %w", err)
	}
	if err := oneRow(res); !errors.Is(err, ErrNotFound) {
		return err
	}
	// Nothing changed: the row is gone, or a removal is recorded already.
	return agentExists(ctx, d.db, k)
}

// RotationEvery is how often one agents row may rotate its identity (PR
// #72 review C10, C15): a row cannot churn identities.
const RotationEvery = time.Hour

// ErrRotationTooSoon is a rotation less than RotationEvery after the
// row's last one.
var ErrRotationTooSoon = errors.New("identity_rotation_too_soon")

// RotateAgentIdentity replaces the identity SPKI hash k.SPKI of the
// agents row k by newSPKI (03-08, AGENT-02) and records the rotation at
// nowUS (identity_rotated_at_us, identity_rotations; owner decision
// D-R1), in one conditional UPDATE that leaves token_hash as it is
// (AgentKey). It is ErrRotationTooSoon within RotationEvery of the row's
// last rotation, ErrNotFound when no row matches k (a concurrent
// rotation, or the row was forgotten), ErrIdentityInUse when another
// agent holds newSPKI.
func (d *DB) RotateAgentIdentity(ctx context.Context, k AgentKey, newSPKI []byte, nowUS int64) error {
	if len(newSPKI) != 32 {
		return errors.New("serverdb: incomplete identity")
	}
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET identity_spki_sha256 = ?, identity_rotated_at_us = ?, identity_rotations = identity_rotations + 1
WHERE `+agentKeyWhere+` AND (identity_rotated_at_us IS NULL OR identity_rotated_at_us <= ?)`,
		append(keyArgs(k, newSPKI, nowUS), nowUS-RotationEvery.Microseconds())...)
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return ErrIdentityInUse
		}
		return fmt.Errorf("serverdb: rotate agent identity: %w", err)
	}
	if err := oneRow(res); !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := agentExists(ctx, d.db, k); err != nil {
		return err
	}
	return ErrRotationTooSoon
}

// ErrStaleHeartbeat is a heartbeat whose seq is not above the stored one,
// and ErrSeqRegressed (which is ErrStaleHeartbeat too) one whose seq is
// below it.
var (
	ErrStaleHeartbeat = errors.New("stale_heartbeat")
	ErrSeqRegressed   = fmt.Errorf("%w: seq below the stored one", ErrStaleHeartbeat)
)

// seqRegressedLogEvery is how often a host that keeps sending a seq below
// the stored one is logged (D-R2).
const seqRegressedLogEvery = int64(time.Hour / time.Microsecond)

// Heartbeat is one stored heartbeat.
type Heartbeat struct {
	AgentID      int64
	Seq          int64
	Body         []byte
	ReceivedAtUS int64
}

// StoreHeartbeat stores body as the heartbeat of the agents row k when seq
// is above the stored one, or none is stored, in one transaction that
// first checks that the row k still exists (AgentKey): a
// request the row was forgotten (or rotated) under while its body arrived
// never writes a heartbeat that a later agent reusing the ID would inherit
// (ErrNotFound; PR #72 review C1). Every write names k itself as well
// (03-08c), the heartbeat through its agents row, so none of them relies
// on that first check to miss a row that reused the ID. foreign_keys is
// off, so 0006's ON DELETE CASCADE does nothing; DeleteAgentIf deletes the
// row itself.
//
// The clock offset is recorded whatever the seq (owner decision D-R2). An
// equal seq changes nothing else and is ErrStaleHeartbeat; a lower one is
// ErrSeqRegressed and records seq_regressed_at_us when it is a new episode
// (nothing recorded since the stored heartbeat arrived) or an hour has
// passed since the last record: logIt then tells the caller to log it, so
// a host that keeps sending lower seqs is logged once an hour.
func (d *DB) StoreHeartbeat(ctx context.Context, k AgentKey, seq int64, body []byte, offsetS, nowUS int64) (logIt bool, err error) {
	id := k.ID
	if seq < 1 || len(body) == 0 || len(k.SPKI) != 32 {
		return false, errors.New("serverdb: incomplete heartbeat")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := agentExists(ctx, tx, k); err != nil {
		return false, err
	}
	res, err := tx.ExecContext(ctx, `UPDATE agents SET clock_offset_s = ? WHERE `+agentKeyWhere, keyArgs(k, offsetS)...)
	if err != nil {
		return false, fmt.Errorf("serverdb: clock offset: %w", err)
	}
	if err := oneRow(res); err != nil {
		return false, err
	}
	var stored, receivedUS int64
	err = tx.QueryRowContext(ctx, `SELECT seq, received_at_us FROM heartbeats WHERE agent_id = ?`, id).Scan(&stored, &receivedUS)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, fmt.Errorf("serverdb: heartbeat: %w", err)
	case seq == stored:
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("serverdb: commit: %w", err)
		}
		return false, ErrStaleHeartbeat
	case seq < stored:
		res, err := tx.ExecContext(ctx, `UPDATE agents SET seq_regressed_at_us = ? WHERE `+agentKeyWhere+`
AND (seq_regressed_at_us IS NULL OR seq_regressed_at_us <= ? OR seq_regressed_at_us <= ?)`, append(keyArgs(k, nowUS), receivedUS, nowUS-seqRegressedLogEvery)...)
		if err != nil {
			return false, fmt.Errorf("serverdb: seq regressed: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return false, fmt.Errorf("serverdb: rows affected: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return false, fmt.Errorf("serverdb: commit: %w", err)
		}
		return n == 1, ErrSeqRegressed
	}
	// The row's ID comes from the agents row k, so the heartbeat is stored
	// only for that row (the WHERE also keeps SQLite's upsert parse
	// unambiguous).
	res, err = tx.ExecContext(ctx, `INSERT INTO heartbeats (agent_id, seq, body, received_at_us) SELECT id, ?, ?, ? FROM agents WHERE `+agentKeyWhere+`
ON CONFLICT (agent_id) DO UPDATE SET seq = excluded.seq, body = excluded.body, received_at_us = excluded.received_at_us`, keyArgs(k, seq, body, nowUS)...)
	if err != nil {
		return false, fmt.Errorf("serverdb: store heartbeat: %w", err)
	}
	if err := oneRow(res); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("serverdb: commit: %w", err)
	}
	return false, nil
}

// RecordClockOffset records offsetS as the clock offset of the agents row
// k (else ErrNotFound, AgentKey): a heartbeat refused before
// StoreHeartbeat (heartbeat_seq_future) still shows its host's clock
// (D-R2).
func (d *DB) RecordClockOffset(ctx context.Context, k AgentKey, offsetS int64) error {
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET clock_offset_s = ? WHERE `+agentKeyWhere, keyArgs(k, offsetS)...)
	if err != nil {
		return fmt.Errorf("serverdb: clock offset: %w", err)
	}
	return oneRow(res)
}

// Heartbeats returns every stored heartbeat, by agent ID.
func (d *DB) Heartbeats(ctx context.Context) (map[int64]Heartbeat, error) {
	return heartbeats(ctx, d.db)
}

// AgentsAndHeartbeats is ListAgents and Heartbeats read in one
// transaction, so an agent's row and its stored heartbeat are from the
// same moment: a request that marks the agent approved and stores its
// first heartbeat meanwhile (requireAgent, then StoreHeartbeat) is seen
// whole or not at all (PR #74 pre-merge review fix round 2), and a
// heartbeat is never paired with another agent's row under a reused ID.
// The transaction holds the only connection, so nothing in it may use
// d.db.
func (d *DB) AgentsAndHeartbeats(ctx context.Context) ([]Agent, map[int64]Heartbeat, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	agents, err := listAgents(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	if d.afterListAgents != nil {
		d.afterListAgents()
	}
	hbs, err := heartbeats(ctx, tx)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("serverdb: commit: %w", err)
	}
	return agents, hbs, nil
}

func heartbeats(ctx context.Context, q queryer) (map[int64]Heartbeat, error) {
	rows, err := q.QueryContext(ctx, `SELECT agent_id, seq, body, received_at_us FROM heartbeats`)
	if err != nil {
		return nil, fmt.Errorf("serverdb: heartbeats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[int64]Heartbeat{}
	for rows.Next() {
		var h Heartbeat
		if err := rows.Scan(&h.AgentID, &h.Seq, &h.Body, &h.ReceivedAtUS); err != nil {
			return nil, fmt.Errorf("serverdb: heartbeat: %w", err)
		}
		out[h.AgentID] = h
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("serverdb: heartbeats: %w", err)
	}
	return out, nil
}

// agentColumns are the columns scanAgent reads, in its order.
const agentColumns = `id, identity_spki_sha256, token_hash, expected_name, host_keys, facts, enrolled_at_us, last_seen_us, approved_at_us, removed_dir_version,
clock_offset_s, seq_regressed_at_us, identity_rotated_at_us, identity_rotations, removal_confirmed_version, removal_confirmed_sha256`

func scanAgent(rows *sql.Rows) (*Agent, error) {
	var (
		a                       Agent
		keys                    string
		seen, approved, removed sql.NullInt64
		offset, regressed       sql.NullInt64
		rotated, confirmed      sql.NullInt64
	)
	if err := rows.Scan(&a.ID, &a.IdentitySPKISHA256, &a.TokenSHA256, &a.ExpectedName, &keys, &a.Facts, &a.EnrolledAtUS, &seen, &approved, &removed,
		&offset, &regressed, &rotated, &a.IdentityRotations, &confirmed, &a.RemovalConfirmedSHA256); err != nil {
		return nil, fmt.Errorf("serverdb: agent: %w", err)
	}
	if err := json.Unmarshal([]byte(keys), &a.HostKeys); err != nil {
		return nil, fmt.Errorf("serverdb: agent %d host keys: %w", a.ID, err)
	}
	a.LastSeenUS, a.ApprovedAtUS = seen.Int64, approved.Int64
	a.ClockOffsetS, a.ClockOffsetKnown, a.SeqRegressedAtUS = offset.Int64, offset.Valid, regressed.Int64
	a.IdentityRotatedAtUS = rotated.Int64
	if removed.Valid && removed.Int64 > 0 {
		a.RemovedDirVersion = uint64(removed.Int64)
	}
	if confirmed.Valid && confirmed.Int64 > 0 {
		a.RemovalConfirmedVersion = uint64(confirmed.Int64)
	} else {
		a.RemovalConfirmedSHA256 = nil
	}
	return &a, nil
}
