package signerdb

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

func openTemp(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signer.db")
	d, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d, path
}

func userVersion(t *testing.T, d *DB) int {
	t.Helper()
	var v int
	if err := d.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func countIssuance(t *testing.T, d *DB) int {
	t.Helper()
	var n int
	if err := d.db.QueryRow(`SELECT count(*) FROM issuance`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func issuance(serial uint64, reqByte byte) Issuance {
	is := Issuance{
		Serial:   serial,
		CARole:   "user",
		KeyID:    "kr1/ca=user/sub=u:alice/req=00000000000000000000000000000000/pol=0/ser=1",
		Cert:     []byte("cert"),
		IssuedAt: time.Now(),
	}
	for i := range is.RequestID {
		is.RequestID[i] = reqByte
	}
	return is
}

func insert(d *DB, is Issuance) error {
	return d.WithTx(context.Background(), func(tx *sql.Tx) error { return d.InsertIssuance(tx, is) })
}

// sqliteCode returns the extended SQLite result code carried by err, or 0.
func sqliteCode(err error) int {
	var se *sqlite.Error
	if errors.As(err, &se) {
		return se.Code()
	}
	return 0
}

func TestMigrations(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil || len(ms) == 0 {
		t.Fatalf("loadMigrations = %d migrations, %v", len(ms), err)
	}

	t.Run("fresh_db_migrated_once", func(t *testing.T) {
		d, _ := openTemp(t)
		if got := userVersion(t, d); got != len(ms) {
			t.Fatalf("user_version = %d, want %d", got, len(ms))
		}
		last, err := d.LastSerial(context.Background())
		if err != nil || last != 0 {
			t.Fatalf("LastSerial on a fresh DB = %d, %v; want 0", last, err)
		}
	})
	t.Run("reopen_idempotent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "signer.db")
		d, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := insert(d, issuance(7, 1)); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		d, err = Open(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		defer func() { _ = d.Close() }()
		if got := userVersion(t, d); got != len(ms) {
			t.Fatalf("user_version after reopen = %d, want %d", got, len(ms))
		}
		if got := countIssuance(t, d); got != 1 {
			t.Fatalf("issuance rows after reopen = %d, want 1", got)
		}
		var rows int
		if err := d.db.QueryRow(`SELECT count(*) FROM serial_state`).Scan(&rows); err != nil || rows != 1 {
			t.Fatalf("serial_state rows = %d, %v; want exactly 1 (migration ran twice?)", rows, err)
		}
	})
	t.Run("newer_schema", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "signer.db")
		d, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.db.Exec(`PRAGMA user_version = 99`); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		d, err = Open(path)
		if err == nil {
			_ = d.Close()
			t.Fatal("Open accepted a database with a newer schema version")
		}
		if !strings.Contains(err.Error(), "schema version 99 is newer than this binary supports") {
			t.Fatalf("Open error = %v, want the newer-schema refusal", err)
		}
	})
	t.Run("unusable_path", func(t *testing.T) {
		for _, p := range []string{"", "a?mode=memory", "a#b"} {
			if _, err := Open(p); err == nil || !strings.Contains(err.Error(), "unusable database path") {
				t.Fatalf("Open(%q) error = %v, want the unusable-path refusal", p, err)
			}
		}
	})
}

func TestDBFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX file modes; CI checks this on Linux")
	}
	_, path := openTemp(t)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("database file mode = %#o, want 0600", got)
	}
}

func TestIssuanceConstraints(t *testing.T) {
	t.Run("duplicate_request_id", func(t *testing.T) {
		d, _ := openTemp(t)
		if err := insert(d, issuance(10, 5)); err != nil {
			t.Fatal(err)
		}
		if err := insert(d, issuance(11, 5)); !errors.Is(err, ErrDuplicateRequest) {
			t.Fatalf("second insert with the same request id: error = %v, want ErrDuplicateRequest", err)
		}
		if got := countIssuance(t, d); got != 1 {
			t.Fatalf("issuance rows = %d, want 1", got)
		}
	})
	t.Run("duplicate_serial", func(t *testing.T) {
		d, _ := openTemp(t)
		if err := insert(d, issuance(10, 5)); err != nil {
			t.Fatal(err)
		}
		err := insert(d, issuance(10, 6))
		if errors.Is(err, ErrDuplicateRequest) || sqliteCode(err) != sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY {
			t.Fatalf("second insert with the same serial: error = %v (code %d), want a PRIMARY KEY violation", err, sqliteCode(err))
		}
	})
	t.Run("serial_zero_refused", func(t *testing.T) {
		d, _ := openTemp(t)
		if err := insert(d, issuance(0, 5)); err == nil || !strings.Contains(err.Error(), "incomplete issuance record") {
			t.Fatalf("InsertIssuance(serial 0) error = %v, want the incomplete-record refusal", err)
		}
	})
	rawInsert := func(d *DB, serial int64, reqID []byte) error {
		return d.WithTx(context.Background(), func(tx *sql.Tx) error {
			_, err := tx.Exec(`INSERT INTO issuance (serial, request_id, ca_role, key_id, cert, issued_at_us) VALUES (?, ?, 'user', 'k', x'00', 1)`, serial, reqID)
			return err
		})
	}
	t.Run("serial_zero_check_constraint", func(t *testing.T) {
		d, _ := openTemp(t)
		if err := rawInsert(d, 0, make([]byte, 16)); sqliteCode(err) != sqlite3.SQLITE_CONSTRAINT_CHECK {
			t.Fatalf("raw insert of serial 0: error = %v (code %d), want a CHECK violation", err, sqliteCode(err))
		}
	})
	t.Run("request_id_15_bytes_check_constraint", func(t *testing.T) {
		d, _ := openTemp(t)
		if err := rawInsert(d, 1, make([]byte, 15)); sqliteCode(err) != sqlite3.SQLITE_CONSTRAINT_CHECK {
			t.Fatalf("raw insert of a 15-byte request id: error = %v (code %d), want a CHECK violation", err, sqliteCode(err))
		}
	})
	t.Run("request_id_16_bytes_accepted", func(t *testing.T) {
		d, _ := openTemp(t)
		if err := rawInsert(d, 1, make([]byte, 16)); err != nil {
			t.Fatalf("raw insert of a valid row: %v", err)
		}
	})
}

func TestSetLastSerial(t *testing.T) {
	d, _ := openTemp(t)
	set := func(s uint64) error {
		return d.WithTx(context.Background(), func(tx *sql.Tx) error { return d.SetLastSerial(tx, s) })
	}
	if err := set(100); err != nil {
		t.Fatalf("raise to 100: %v", err)
	}
	for _, tc := range []struct {
		name    string
		serial  uint64
		wantMsg string
	}{
		{"same_value", 100, "would not increase"},
		{"lower_value", 99, "would not increase"},
		{"above_int64", 1 << 63, "does not fit SQLite INTEGER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := set(tc.serial); err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("SetLastSerial(%d) error = %v, want %q", tc.serial, err, tc.wantMsg)
			}
			last, err := d.LastSerial(context.Background())
			if err != nil || last != 100 {
				t.Fatalf("LastSerial = %d, %v; want 100 unchanged", last, err)
			}
		})
	}
	// A failed transaction leaves no partial issuance behind.
	t.Run("rollback_on_error", func(t *testing.T) {
		err := d.WithTx(context.Background(), func(tx *sql.Tx) error {
			if err := d.InsertIssuance(tx, issuance(200, 9)); err != nil {
				return err
			}
			return d.SetLastSerial(tx, 50) // lower: refused
		})
		if err == nil || !strings.Contains(err.Error(), "would not increase") {
			t.Fatalf("WithTx error = %v, want the high-water-mark refusal", err)
		}
		if got := countIssuance(t, d); got != 0 {
			t.Fatalf("issuance rows after a rolled-back transaction = %d, want 0", got)
		}
	})
}

func hash32(b byte) []byte {
	h := make([]byte, 32)
	h[0] = b
	return h
}

func TestLogTables(t *testing.T) {
	d, path := openTemp(t)
	ctx := context.Background()
	if _, _, err := d.LatestCheckpoint(ctx); !errors.Is(err, ErrNoCheckpoint) {
		t.Fatalf("LatestCheckpoint on an empty log: %v, want ErrNoCheckpoint", err)
	}
	appendLeaf := func(idx uint64, leaf, hash []byte, cp []byte) error {
		return d.WithTx(ctx, func(tx *sql.Tx) error {
			if err := d.AppendLeaf(tx, idx, leaf, hash); err != nil {
				return err
			}
			if cp != nil {
				return d.PutCheckpoint(tx, idx+1, cp)
			}
			return nil
		})
	}
	if err := appendLeaf(1, []byte("gap"), hash32(1), nil); err == nil {
		t.Fatal("AppendLeaf accepted index 1 on an empty log")
	}
	if err := appendLeaf(0, []byte("short hash"), make([]byte, 31), nil); err == nil {
		t.Fatal("AppendLeaf accepted a 31-byte hash")
	}
	if err := appendLeaf(0, []byte("leaf0"), hash32(0), []byte("cp1")); err != nil {
		t.Fatal(err)
	}
	if err := appendLeaf(0, []byte("again"), hash32(9), nil); err == nil {
		t.Fatal("AppendLeaf accepted index 0 twice")
	}
	if err := appendLeaf(1, []byte("leaf1"), hash32(1), []byte("cp2")); err != nil {
		t.Fatal(err)
	}
	// A leaf without its checkpoint (never written by the signer, but a
	// reader must still stop at the checkpoint size).
	if err := appendLeaf(2, []byte("leaf2"), hash32(2), nil); err != nil {
		t.Fatal(err)
	}
	hashes, err := d.LeafHashes(ctx)
	if err != nil || len(hashes) != 3 || hashes[2][0] != 2 {
		t.Fatalf("LeafHashes = %d hashes, %v", len(hashes), err)
	}
	note, size, err := d.LatestCheckpoint(ctx)
	if err != nil || size != 2 || string(note) != "cp2" {
		t.Fatalf("LatestCheckpoint = %q, %d, %v", note, size, err)
	}
	var seen []string
	if err := d.ForEachLeaf(ctx, func(idx uint64, leaf []byte) error { seen = append(seen, string(leaf)); return nil }); err != nil || len(seen) != 3 {
		t.Fatalf("ForEachLeaf = %q, %v", seen, err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("OpenReadOnly: %v", err)
	}
	defer func() { _ = ro.Close() }()
	seen = nil
	note, size, err = ro.ReadLog(ctx, func(idx uint64, leaf []byte) error { seen = append(seen, string(leaf)); return nil })
	if err != nil || size != 2 || string(note) != "cp2" || strings.Join(seen, ",") != "leaf0,leaf1" {
		t.Fatalf("ReadLog = %q, %d, %q, %v; want the two checkpointed leaves", note, size, seen, err)
	}
	if err := appendLeafRO(ro); err == nil {
		t.Fatal("a read-only database accepted a write")
	}
}

func appendLeafRO(d *DB) error {
	return d.WithTx(context.Background(), func(tx *sql.Tx) error { return d.AppendLeaf(tx, 3, []byte("x"), hash32(3)) })
}

func TestOpenReadOnlyRefuses(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.db")
	if _, err := OpenReadOnly(missing); err == nil {
		t.Fatal("OpenReadOnly opened a missing database")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenReadOnly created %s", missing)
	}
}
