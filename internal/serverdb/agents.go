package serverdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

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

// DeleteAgent removes the agent row id, which frees its identity and host
// keys for a new enrollment (keyroster host forget; PR #71 review D-R1).
// It is ErrNotFound when no such row exists.
func (d *DB) DeleteAgent(ctx context.Context, id int64) error {
	res, err := d.db.ExecContext(ctx, `DELETE FROM agents WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("serverdb: delete agent: %w", err)
	}
	return oneRow(res)
}

// agentColumns are the columns scanAgent reads, in its order.
const agentColumns = `id, identity_spki_sha256, token_hash, expected_name, host_keys, facts, enrolled_at_us, last_seen_us, approved_at_us`

func scanAgent(rows *sql.Rows) (*Agent, error) {
	var (
		a              Agent
		keys           string
		seen, approved sql.NullInt64
	)
	if err := rows.Scan(&a.ID, &a.IdentitySPKISHA256, &a.TokenSHA256, &a.ExpectedName, &keys, &a.Facts, &a.EnrolledAtUS, &seen, &approved); err != nil {
		return nil, fmt.Errorf("serverdb: agent: %w", err)
	}
	if err := json.Unmarshal([]byte(keys), &a.HostKeys); err != nil {
		return nil, fmt.Errorf("serverdb: agent %d host keys: %w", a.ID, err)
	}
	a.LastSeenUS, a.ApprovedAtUS = seen.Int64, approved.Int64
	return &a, nil
}
