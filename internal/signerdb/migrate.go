package signerdb

import (
	"context"
	"embed"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

// loadMigrations returns the embedded migrations ordered by version. Their
// names must be NNNN_description.sql with versions 1, 2, 3, ... and no gaps.
func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("signerdb: read migrations: %w", err)
	}
	var ms []migration
	for _, e := range entries {
		name := e.Name()
		prefix, _, ok := strings.Cut(name, "_")
		if !ok || len(prefix) != 4 {
			return nil, fmt.Errorf("signerdb: bad migration name %q", name)
		}
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("signerdb: bad migration name %q", name)
		}
		body, err := migrationFS.ReadFile(path.Join("migrations", name))
		if err != nil {
			return nil, fmt.Errorf("signerdb: read migration %q: %w", name, err)
		}
		ms = append(ms, migration{version: v, name: name, sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("signerdb: migration %q out of sequence (want version %d)", m.name, i+1)
		}
	}
	return ms, nil
}

// migrate applies every migration above PRAGMA user_version, each in its own
// transaction together with the user_version bump. A database whose version
// is newer than this binary knows is refused.
func (d *DB) migrate(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	var current int
	if err := d.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("signerdb: read schema version: %w", err)
	}
	if current > len(ms) {
		return fmt.Errorf("signerdb: database schema version %d is newer than this binary supports (%d)", current, len(ms))
	}
	for _, m := range ms[current:] {
		tx, err := d.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("signerdb: begin migration %q: %w", m.name, err)
		}
		if _, err := tx.ExecContext(ctx, m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("signerdb: apply migration %q: %w", m.name, err)
		}
		// PRAGMA takes no bound parameters; m.version is an int parsed
		// from an embedded file name.
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("signerdb: set schema version %d: %w", m.version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("signerdb: commit migration %q: %w", m.name, err)
		}
	}
	return nil
}
