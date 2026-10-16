package signerdb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// StoredDirectory is one installed directory version: its canonical bytes,
// the admins' signatures and the policy version it was verified under.
type StoredDirectory struct {
	Version       uint64
	Doc           []byte
	Sigs          []byte
	PolicyVersion uint64
	InstalledAt   time.Time
}

// InsertDirectory stores an installed directory inside tx. Versions must
// strictly increase.
func (d *DB) InsertDirectory(tx *sql.Tx, dir StoredDirectory) error {
	v, err := toInt64(dir.Version)
	if err != nil {
		return err
	}
	pol, err := toInt64(dir.PolicyVersion)
	if err != nil {
		return err
	}
	if v < 1 || len(dir.Doc) == 0 || len(dir.Sigs) == 0 || dir.InstalledAt.IsZero() {
		return errors.New("signerdb: incomplete directory record")
	}
	latest, err := latestDirectoryVersion(context.Background(), tx)
	if err != nil {
		return err
	}
	if dir.Version <= latest {
		return fmt.Errorf("signerdb: directory version %d is not above the installed version %d", dir.Version, latest)
	}
	if _, err := tx.Exec(`INSERT INTO directory (version, doc, sigs, policy_version, installed_at_us) VALUES (?, ?, ?, ?, ?)`,
		v, dir.Doc, dir.Sigs, pol, dir.InstalledAt.UnixMicro()); err != nil {
		return fmt.Errorf("signerdb: insert directory: %w", err)
	}
	return nil
}

// LatestDirectory returns the installed directory with the highest
// version, or nil and no error when none is installed.
func (d *DB) LatestDirectory(ctx context.Context) (*StoredDirectory, error) {
	var (
		dir     StoredDirectory
		version int64
		pol     int64
		at      int64
	)
	err := d.db.QueryRowContext(ctx, `SELECT version, doc, sigs, policy_version, installed_at_us FROM directory ORDER BY version DESC LIMIT 1`).
		Scan(&version, &dir.Doc, &dir.Sigs, &pol, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil // no directory installed
	}
	if err != nil {
		return nil, fmt.Errorf("signerdb: read directory: %w", err)
	}
	if version < 1 || pol < 0 {
		return nil, errors.New("signerdb: invalid directory record")
	}
	dir.Version = uint64(version)   //nolint:gosec // G115: version >= 1, checked above
	dir.PolicyVersion = uint64(pol) //nolint:gosec // G115: pol >= 0, checked above
	dir.InstalledAt = time.UnixMicro(at)
	return &dir, nil
}

// LatestDirectoryVersionTx returns the highest installed directory version
// inside tx (0 when none is installed), so that a check against it holds
// until tx commits.
func (d *DB) LatestDirectoryVersionTx(ctx context.Context, tx *sql.Tx) (uint64, error) {
	return latestDirectoryVersion(ctx, tx)
}

func latestDirectoryVersion(ctx context.Context, q queryer) (uint64, error) {
	var v int64
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM directory`).Scan(&v); err != nil {
		return 0, fmt.Errorf("signerdb: read directory version: %w", err)
	}
	if v < 0 {
		return 0, errors.New("signerdb: invalid directory version")
	}
	return uint64(v), nil //nolint:gosec // G115: v >= 0, checked above
}
