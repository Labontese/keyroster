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

// TouchAgent sets the agent's last_seen_us to nowUS.
func (d *DB) TouchAgent(ctx context.Context, id, nowUS int64) error {
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET last_seen_us = ? WHERE id = ?`, nowUS, id)
	if err != nil {
		return fmt.Errorf("serverdb: touch agent: %w", err)
	}
	return oneRow(res)
}

// MarkAgentApproved records nowUS as the agent's first approved state
// answer; a later call keeps the first time (PR #71 review D-R1).
func (d *DB) MarkAgentApproved(ctx context.Context, id, nowUS int64) error {
	if _, err := d.db.ExecContext(ctx, `UPDATE agents SET approved_at_us = ? WHERE id = ? AND approved_at_us IS NULL`, nowUS, id); err != nil {
		return fmt.Errorf("serverdb: mark agent approved: %w", err)
	}
	return nil
}

// DeleteAgent removes the agent row id and its heartbeat, which frees its
// identity and host keys for a new enrollment (keyroster host forget; PR
// #71 review D-R1). It is ErrNotFound when no such row exists.
func (d *DB) DeleteAgent(ctx context.Context, id int64) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM heartbeats WHERE agent_id = ?`, id); err != nil {
		return fmt.Errorf("serverdb: delete heartbeat: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM agents WHERE id = ?`, id)
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

// SetAgentRemovedVersion records version as the first directory version
// that no longer approves the agent, unless one is recorded already. A
// version of 0 clears it (a directory approves the agent again).
func (d *DB) SetAgentRemovedVersion(ctx context.Context, id int64, version uint64) error {
	if version > math.MaxInt64 {
		return errors.New("serverdb: directory version above int64")
	}
	var err error
	if version == 0 {
		_, err = d.db.ExecContext(ctx, `UPDATE agents SET removed_dir_version = NULL WHERE id = ?`, id)
	} else {
		_, err = d.db.ExecContext(ctx, `UPDATE agents SET removed_dir_version = ? WHERE id = ? AND removed_dir_version IS NULL`, int64(version), id) //nolint:gosec // G115: checked above
	}
	if err != nil {
		return fmt.Errorf("serverdb: agent removal version: %w", err)
	}
	return nil
}

// RotateAgentIdentity replaces agent id's identity SPKI hash oldSPKI by
// newSPKI (03-08, AGENT-02) and records the rotation at nowUS
// (identity_rotated_at_us, identity_rotations; owner decision D-R1). It
// is ErrNotFound when the row no longer holds oldSPKI (a concurrent
// rotation), ErrIdentityInUse when another agent holds newSPKI.
func (d *DB) RotateAgentIdentity(ctx context.Context, id int64, oldSPKI, newSPKI []byte, nowUS int64) error {
	if len(newSPKI) != 32 {
		return errors.New("serverdb: incomplete identity")
	}
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET identity_spki_sha256 = ?, identity_rotated_at_us = ?, identity_rotations = identity_rotations + 1
WHERE id = ? AND identity_spki_sha256 = ?`, newSPKI, nowUS, id, oldSPKI)
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return ErrIdentityInUse
		}
		return fmt.Errorf("serverdb: rotate agent identity: %w", err)
	}
	return oneRow(res)
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

// StoreHeartbeat stores body as agent id's heartbeat when seq is above
// the stored one, or none is stored, in one transaction that first checks
// that the agents row id still exists and still has the identity spki: a
// request the row was forgotten (or rotated) under while its body arrived
// never writes a heartbeat that a later agent reusing the ID would inherit
// (ErrNotFound; PR #72 review C1). foreign_keys is off, so 0006's ON
// DELETE CASCADE does nothing; DeleteAgent deletes the row itself.
//
// The clock offset is recorded whatever the seq (owner decision D-R2). An
// equal seq changes nothing else and is ErrStaleHeartbeat; a lower one is
// ErrSeqRegressed and records seq_regressed_at_us when it is a new episode
// (nothing recorded since the stored heartbeat arrived) or an hour has
// passed since the last record: logIt then tells the caller to log it, so
// a host that keeps sending lower seqs is logged once an hour.
func (d *DB) StoreHeartbeat(ctx context.Context, id int64, spki []byte, seq int64, body []byte, offsetS, nowUS int64) (logIt bool, err error) {
	if seq < 1 || len(body) == 0 || len(spki) != 32 {
		return false, errors.New("serverdb: incomplete heartbeat")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("serverdb: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := agentLive(ctx, tx, id, spki); err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agents SET clock_offset_s = ? WHERE id = ?`, offsetS, id); err != nil {
		return false, fmt.Errorf("serverdb: clock offset: %w", err)
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
		res, err := tx.ExecContext(ctx, `UPDATE agents SET seq_regressed_at_us = ? WHERE id = ?
AND (seq_regressed_at_us IS NULL OR seq_regressed_at_us <= ? OR seq_regressed_at_us <= ?)`, nowUS, id, receivedUS, nowUS-seqRegressedLogEvery)
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO heartbeats (agent_id, seq, body, received_at_us) VALUES (?, ?, ?, ?)
ON CONFLICT (agent_id) DO UPDATE SET seq = excluded.seq, body = excluded.body, received_at_us = excluded.received_at_us`, id, seq, body, nowUS); err != nil {
		return false, fmt.Errorf("serverdb: store heartbeat: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("serverdb: commit: %w", err)
	}
	return false, nil
}

// RecordClockOffset records offsetS as agent id's clock offset, when the
// row still has the identity spki (else ErrNotFound): a heartbeat refused
// before StoreHeartbeat (heartbeat_seq_future) still shows its host's
// clock (D-R2).
func (d *DB) RecordClockOffset(ctx context.Context, id int64, spki []byte, offsetS int64) error {
	res, err := d.db.ExecContext(ctx, `UPDATE agents SET clock_offset_s = ? WHERE id = ? AND identity_spki_sha256 = ?`, offsetS, id, spki)
	if err != nil {
		return fmt.Errorf("serverdb: clock offset: %w", err)
	}
	return oneRow(res)
}

// agentLive is ErrNotFound unless the agents row id exists with the
// identity spki.
func agentLive(ctx context.Context, tx *sql.Tx, id int64, spki []byte) error {
	var one int
	err := tx.QueryRowContext(ctx, `SELECT 1 FROM agents WHERE id = ? AND identity_spki_sha256 = ?`, id, spki).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("serverdb: agent: %w", err)
	}
	return nil
}

// Heartbeats returns every stored heartbeat, by agent ID.
func (d *DB) Heartbeats(ctx context.Context) (map[int64]Heartbeat, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT agent_id, seq, body, received_at_us FROM heartbeats`)
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
clock_offset_s, seq_regressed_at_us, identity_rotated_at_us, identity_rotations`

func scanAgent(rows *sql.Rows) (*Agent, error) {
	var (
		a                       Agent
		keys                    string
		seen, approved, removed sql.NullInt64
		offset, regressed       sql.NullInt64
		rotated                 sql.NullInt64
	)
	if err := rows.Scan(&a.ID, &a.IdentitySPKISHA256, &a.TokenSHA256, &a.ExpectedName, &keys, &a.Facts, &a.EnrolledAtUS, &seen, &approved, &removed,
		&offset, &regressed, &rotated, &a.IdentityRotations); err != nil {
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
	return &a, nil
}
