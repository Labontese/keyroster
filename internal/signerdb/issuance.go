package signerdb

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// ErrDuplicateRequest means the request id was already used for an
// issuance.
var ErrDuplicateRequest = errors.New("signerdb: duplicate request id")

// Issuance is one issued certificate.
type Issuance struct {
	Serial    uint64
	RequestID [16]byte
	CARole    string
	KeyID     string
	Cert      []byte // SSH wire format
	IssuedAt  time.Time
}

// InsertIssuance records is inside tx. A reused request id returns
// ErrDuplicateRequest.
func (d *DB) InsertIssuance(tx *sql.Tx, is Issuance) error {
	serial, err := toInt64(is.Serial)
	if err != nil {
		return err
	}
	if serial == 0 || len(is.Cert) == 0 || is.CARole == "" || is.KeyID == "" || is.IssuedAt.IsZero() {
		return errors.New("signerdb: incomplete issuance record")
	}
	_, err = tx.Exec(`INSERT INTO issuance (serial, request_id, ca_role, key_id, cert, issued_at_us) VALUES (?, ?, ?, ?, ?, ?)`,
		serial, is.RequestID[:], is.CARole, is.KeyID, is.Cert, is.IssuedAt.UnixMicro())
	if err != nil {
		var se *sqlite.Error
		if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
			return ErrDuplicateRequest
		}
		return fmt.Errorf("signerdb: insert issuance: %w", err)
	}
	return nil
}
