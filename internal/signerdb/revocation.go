package signerdb

import (
	"bytes"
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
)

// Revocation kinds, as the revocation table stores them.
const (
	RevocationSerial = "serial"
	RevocationKeyID  = "key_id"
	RevocationKey    = "key"
)

// Revocation is one revoked entry. For RevocationSerial, CAKey (SSH wire
// format) and Serial name the certificate; for RevocationKeyID, CAKey and
// KeyID; for RevocationKey, Key (SSH wire format) names the key.
// ValidBeforeMicros is the revoked certificate's valid_before in
// microseconds (0 when not known, and for a key).
type Revocation struct {
	ID                int64
	Kind              string
	CAKey             []byte
	Serial            uint64
	KeyID             string
	Key               []byte
	ValidBeforeMicros uint64
	RequestID         [16]byte
	LeafIndex         uint64
	RevokedAt         time.Time
}

// KRLState is the published KRL in force: its version, bytes, canonical
// manifest and the ops key's detached signature over the manifest.
type KRLState struct {
	Version     uint64
	KRL         []byte
	Manifest    []byte
	Sig         []byte
	PublishedAt time.Time
}

// InsertRevocation records r inside tx. Each kind carries exactly its own
// fields: a serial row CAKey and Serial, a key_id row CAKey and KeyID, a
// key row Key; ValidBeforeMicros 0 is stored as NULL (not known), and a
// key row has none.
func (d *DB) InsertRevocation(tx *sql.Tx, r Revocation) error {
	ok := !r.RevokedAt.IsZero()
	switch r.Kind {
	case RevocationSerial:
		ok = ok && len(r.CAKey) > 0 && r.Serial != 0 && r.KeyID == "" && len(r.Key) == 0
	case RevocationKeyID:
		ok = ok && len(r.CAKey) > 0 && r.Serial == 0 && r.KeyID != "" && len(r.Key) == 0
	case RevocationKey:
		ok = ok && len(r.CAKey) == 0 && r.Serial == 0 && r.KeyID == "" && len(r.Key) > 0 && r.ValidBeforeMicros == 0
	default:
		ok = false
	}
	if !ok {
		return errors.New("signerdb: incomplete revocation record")
	}
	leaf, err := toInt64(r.LeafIndex)
	if err != nil {
		return err
	}
	var serial, validBefore, caKey, keyID, key any
	if r.Serial != 0 {
		s, err := toInt64(r.Serial)
		if err != nil {
			return err
		}
		serial = s
	}
	if r.ValidBeforeMicros != 0 {
		vb, err := toInt64(r.ValidBeforeMicros)
		if err != nil {
			return err
		}
		validBefore = vb
	}
	if len(r.CAKey) > 0 {
		caKey = r.CAKey
	}
	if r.KeyID != "" {
		keyID = r.KeyID
	}
	if len(r.Key) > 0 {
		key = r.Key
	}
	if _, err := tx.Exec(`INSERT INTO revocation (kind, ca_key, serial, key_id, key, valid_before_us, request_id, leaf_index, revoked_at_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Kind, caKey, serial, keyID, key, validBefore, r.RequestID[:], leaf, r.RevokedAt.UnixMicro()); err != nil {
		return fmt.Errorf("signerdb: insert revocation: %w", err)
	}
	return nil
}

// LiveCert is a certificate the signer issued that is live at a
// subject revocation's resolution time.
type LiveCert struct {
	Serial      uint64
	CAKey       []byte // the certificate's signature key, SSH wire format
	ValidBefore uint64 // whole seconds
	KeyID       string
}

// LiveIssuanceForSubjectTx returns, inside tx, every certificate issued
// under CA role role (as the issuance table stores it) whose key ID names
// subject (a kr1 or kr2 key ID with that sub field, confirmed with
// cert.ParseKeyID) and that is live at at (whole seconds) by
// krl.EntryLive, in ascending serial order. The prefix is compared
// exactly (substr), never with LIKE, in which "_" would match any
// character. There is no issue-time cutoff: the TTL cap comes from the
// policy, and a successor policy with a shorter cap must not hide an
// older, longer-lived certificate. It does not consult the revocation
// table: a certificate an earlier revocation already lists is returned
// again (re-listing).
func (d *DB) LiveIssuanceForSubjectTx(ctx context.Context, tx *sql.Tx, role, subject string, at uint64) ([]LiveCert, error) {
	var out []LiveCert
	for _, prefix := range []string{"kr1/ca=" + role + "/sub=" + subject + "/", "kr2/ca=" + role + "/sub=" + subject + "/"} {
		rows, err := tx.QueryContext(ctx, `SELECT serial, key_id, cert FROM issuance WHERE ca_role = ? AND substr(key_id, 1, length(?)) = ? ORDER BY serial`,
			role, prefix, prefix)
		if err != nil {
			return nil, fmt.Errorf("signerdb: read issuance by subject: %w", err)
		}
		for rows.Next() {
			var (
				serial int64
				keyID  string
				blob   []byte
			)
			if err := rows.Scan(&serial, &keyID, &blob); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("signerdb: read issuance by subject: %w", err)
			}
			kid, err := cert.ParseKeyID(keyID)
			if err != nil || kid.CA != role || kid.Subject != subject || serial <= 0 || kid.Serial != uint64(serial) {
				_ = rows.Close()
				return nil, errors.New("signerdb: invalid issuance record")
			}
			c, err := parseIssuedCert(blob)
			if err != nil || c.Serial != uint64(serial) || c.KeyId != keyID {
				_ = rows.Close()
				return nil, errors.New("signerdb: invalid issuance record")
			}
			if !krl.EntryLive(c.ValidBefore, at) {
				continue
			}
			out = append(out, LiveCert{Serial: c.Serial, CAKey: c.SignatureKey.Marshal(), ValidBefore: c.ValidBefore, KeyID: keyID})
		}
		if err := rows.Close(); err != nil {
			return nil, fmt.Errorf("signerdb: read issuance by subject: %w", err)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("signerdb: read issuance by subject: %w", err)
		}
	}
	slices.SortFunc(out, func(a, b LiveCert) int { return cmp.Compare(a.Serial, b.Serial) })
	return out, nil
}

// KeyIDValidBeforeTx returns, inside tx, the latest ValidBefore (whole
// seconds) of the certificates with key ID keyID signed by caKey (SSH wire
// format), or 0 when the signer issued none.
func (d *DB) KeyIDValidBeforeTx(ctx context.Context, tx *sql.Tx, keyID string, caKey []byte) (uint64, error) {
	rows, err := tx.QueryContext(ctx, `SELECT cert FROM issuance WHERE key_id = ?`, keyID)
	if err != nil {
		return 0, fmt.Errorf("signerdb: read issuance by key ID: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var vb uint64
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return 0, fmt.Errorf("signerdb: read issuance by key ID: %w", err)
		}
		c, err := parseIssuedCert(blob)
		if err != nil {
			return 0, errors.New("signerdb: invalid issuance record")
		}
		if bytes.Equal(c.SignatureKey.Marshal(), caKey) {
			vb = max(vb, c.ValidBefore)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("signerdb: read issuance by key ID: %w", err)
	}
	return vb, nil
}

// parseIssuedCert parses a stored certificate.
func parseIssuedCert(blob []byte) (*ssh.Certificate, error) {
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, err
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok || c.SignatureKey == nil {
		return nil, errors.New("signerdb: the stored key is not a certificate")
	}
	return c, nil
}

// InsertRevokeRequestTx records an accepted revoke request inside tx. A
// request ID recorded before returns ErrDuplicateRequest (the PRIMARY KEY
// is the backstop behind RevokeRequestUsed).
func (d *DB) InsertRevokeRequestTx(tx *sql.Tx, id [16]byte, leafIndex uint64) error {
	leaf, err := toInt64(leafIndex)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO revoke_request (request_id, leaf_index) VALUES (?, ?)`, id[:], leaf); err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && (se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY || se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE) {
			return ErrDuplicateRequest
		}
		return fmt.Errorf("signerdb: insert revoke request: %w", err)
	}
	return nil
}

// RevokeRequestUsed reports whether a revoke request with ID id was
// accepted before.
func (d *DB) RevokeRequestUsed(ctx context.Context, id [16]byte) (bool, error) {
	var one int
	err := d.db.QueryRowContext(ctx, `SELECT 1 FROM revoke_request WHERE request_id = ?`, id[:]).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("signerdb: read revoke request: %w", err)
	}
	return true, nil
}

// RevocationsTx returns every revocation row inside tx, in id order.
func (d *DB) RevocationsTx(ctx context.Context, tx *sql.Tx) ([]Revocation, error) {
	return revocations(ctx, tx)
}

func revocations(ctx context.Context, q queryer) ([]Revocation, error) {
	rows, err := q.QueryContext(ctx, `SELECT id, kind, ca_key, serial, key_id, key, valid_before_us, request_id, leaf_index, revoked_at_us FROM revocation ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("signerdb: read revocations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Revocation
	for rows.Next() {
		var (
			r                   Revocation
			serial, validBefore sql.NullInt64
			keyID               sql.NullString
			reqID               []byte
			leaf, at            int64
		)
		if err := rows.Scan(&r.ID, &r.Kind, &r.CAKey, &serial, &keyID, &r.Key, &validBefore, &reqID, &leaf, &at); err != nil {
			return nil, fmt.Errorf("signerdb: read revocation: %w", err)
		}
		if len(reqID) != len(r.RequestID) || leaf < 0 || (serial.Valid && serial.Int64 <= 0) || (validBefore.Valid && validBefore.Int64 < 0) {
			return nil, errors.New("signerdb: invalid revocation record")
		}
		copy(r.RequestID[:], reqID)
		r.Serial = uint64(serial.Int64)                 //nolint:gosec // G115: > 0 or 0 (NULL), checked above
		r.ValidBeforeMicros = uint64(validBefore.Int64) //nolint:gosec // G115: >= 0 or 0 (NULL), checked above
		r.KeyID = keyID.String
		r.LeafIndex = uint64(leaf) //nolint:gosec // G115: leaf >= 0, checked above
		r.RevokedAt = time.UnixMicro(at)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("signerdb: read revocations: %w", err)
	}
	return out, nil
}

// PutKRLStateTx stores st as the KRL in force inside tx, replacing the
// previous one. Versions must strictly increase.
func (d *DB) PutKRLStateTx(tx *sql.Tx, st KRLState) error {
	v, err := toInt64(st.Version)
	if err != nil {
		return err
	}
	if v < 1 || len(st.KRL) == 0 || len(st.Manifest) == 0 || len(st.Sig) == 0 || st.PublishedAt.IsZero() {
		return errors.New("signerdb: incomplete KRL state")
	}
	prev, err := krlState(context.Background(), tx)
	if err != nil {
		return err
	}
	if prev != nil && st.Version <= prev.Version {
		return fmt.Errorf("signerdb: KRL version %d is not above the published version %d", st.Version, prev.Version)
	}
	if _, err := tx.Exec(`INSERT INTO krl_state (id, version, krl, manifest, sig, published_at_us) VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET version = excluded.version, krl = excluded.krl, manifest = excluded.manifest,
		sig = excluded.sig, published_at_us = excluded.published_at_us`,
		v, st.KRL, st.Manifest, st.Sig, st.PublishedAt.UnixMicro()); err != nil {
		return fmt.Errorf("signerdb: write KRL state: %w", err)
	}
	return nil
}

// KRLState returns the published KRL in force, or nil and no error when
// none is published.
func (d *DB) KRLState(ctx context.Context) (*KRLState, error) {
	return krlState(ctx, d.db)
}

// KRLStateTx is KRLState inside tx.
func (d *DB) KRLStateTx(ctx context.Context, tx *sql.Tx) (*KRLState, error) {
	return krlState(ctx, tx)
}

func krlState(ctx context.Context, q queryer) (*KRLState, error) {
	var (
		st      KRLState
		version int64
		at      int64
	)
	err := q.QueryRowContext(ctx, `SELECT version, krl, manifest, sig, published_at_us FROM krl_state WHERE id = 1`).
		Scan(&version, &st.KRL, &st.Manifest, &st.Sig, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // nothing published
	}
	if err != nil {
		return nil, fmt.Errorf("signerdb: read KRL state: %w", err)
	}
	if version < 1 {
		return nil, errors.New("signerdb: invalid KRL state")
	}
	st.Version = uint64(version) //nolint:gosec // G115: version >= 1, checked above
	st.PublishedAt = time.UnixMicro(at)
	return &st, nil
}

// IssuanceBySerialTx returns the issuance with serial inside tx, or nil and
// no error when none has that serial.
func (d *DB) IssuanceBySerialTx(ctx context.Context, tx *sql.Tx, serial uint64) (*Issuance, error) {
	s, err := toInt64(serial)
	if err != nil {
		return nil, nil //nolint:nilerr // a serial above int64 cannot be stored, so no issuance has it
	}
	var (
		is    Issuance
		reqID []byte
		at    int64
		got   int64
	)
	err = tx.QueryRowContext(ctx, `SELECT serial, request_id, ca_role, key_id, cert, issued_at_us FROM issuance WHERE serial = ?`, s).
		Scan(&got, &reqID, &is.CARole, &is.KeyID, &is.Cert, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("signerdb: read issuance: %w", err)
	}
	if got <= 0 || len(reqID) != len(is.RequestID) {
		return nil, errors.New("signerdb: invalid issuance record")
	}
	is.Serial = uint64(got) //nolint:gosec // G115: got > 0, checked above
	copy(is.RequestID[:], reqID)
	is.IssuedAt = time.UnixMicro(at)
	return &is, nil
}
