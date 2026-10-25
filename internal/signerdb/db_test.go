package signerdb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
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
	// upgrade_from_v3 builds a populated Phase 1 database (schema version 3,
	// the first three migrations applied by direct SQL) and opens it: the
	// 0004 directory migration applies, the directory table is empty, and
	// the Phase 1 rows read back unchanged (T-02-78; the 02-13 homelab
	// signer takes exactly this path).
	t.Run("upgrade_from_v3", func(t *testing.T) {
		if len(ms) < 4 || ms[3].name != "0004_directory.sql" {
			t.Fatalf("want migration 4 to be 0004_directory.sql, have %d migrations", len(ms))
		}
		path := filepath.Join(t.TempDir(), "signer.db")
		raw, err := sql.Open("sqlite", path+"?"+dsnParams)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms[:3] {
			if _, err := raw.Exec(m.sql); err != nil {
				t.Fatalf("apply %s: %v", m.name, err)
			}
			if _, err := raw.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
				t.Fatal(err)
			}
		}
		reqID := bytes.Repeat([]byte{0x42}, 16)
		if _, err := raw.Exec(`INSERT INTO issuance (serial, request_id, ca_role, key_id, cert, issued_at_us) VALUES (?, ?, ?, ?, ?, ?)`,
			1700000000000001, reqID, "user", "kr1/key", []byte("cert"), 1700000000000002); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`INSERT INTO trust_bundle (version, bundle, bundle_sigs, policy, policy_sigs, installed_at_us) VALUES (?, ?, ?, ?, ?, ?)`,
			1, []byte("bundle"), []byte("bsigs"), []byte("policy"), []byte("psigs"), 1700000000000003); err != nil {
			t.Fatal(err)
		}
		var v int
		if err := raw.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil || v != 3 {
			t.Fatalf("Phase 1 database user_version = %d, %v; want 3", v, err)
		}
		if err := raw.Close(); err != nil {
			t.Fatal(err)
		}

		d, err := Open(path)
		if err != nil {
			t.Fatalf("Open of a version 3 database: %v", err)
		}
		defer func() { _ = d.Close() }()
		if got := userVersion(t, d); got != len(ms) {
			t.Fatalf("user_version after the upgrade = %d, want %d", got, len(ms))
		}
		var dirs int
		if err := d.db.QueryRow(`SELECT count(*) FROM directory`).Scan(&dirs); err != nil || dirs != 0 {
			t.Fatalf("directory rows after the upgrade = %d, %v; want an empty directory table", dirs, err)
		}
		if got, err := d.LatestDirectory(context.Background()); err != nil || got != nil {
			t.Fatalf("LatestDirectory after the upgrade = %+v, %v; want none", got, err)
		}
		var (
			serial          int64
			gotReq, gotCert []byte
			role, keyID     string
		)
		if err := d.db.QueryRow(`SELECT serial, request_id, ca_role, key_id, cert FROM issuance`).Scan(&serial, &gotReq, &role, &keyID, &gotCert); err != nil ||
			serial != 1700000000000001 || !bytes.Equal(gotReq, reqID) || role != "user" || keyID != "kr1/key" || string(gotCert) != "cert" {
			t.Fatalf("issuance row after the upgrade: %d %x %s %s %q, %v", serial, gotReq, role, keyID, gotCert, err)
		}
		b, err := d.LatestBundle(context.Background())
		if err != nil || b.Version != 1 || string(b.Bundle) != "bundle" || string(b.BundleSigs) != "bsigs" ||
			string(b.Policy) != "policy" || string(b.PolicySigs) != "psigs" || b.InstalledAt.UnixMicro() != 1700000000000003 {
			t.Fatalf("trust_bundle row after the upgrade: %+v, %v", b, err)
		}
	})
	// upgrade_from_v4 builds a populated Phase 2 database (schema version
	// 4, migrations 1-4 by direct SQL) and opens it: the 0005 revocation
	// migration applies, its three tables are empty, and the Phase 2 rows
	// read back unchanged (03-01; the homelab signer takes this path).
	t.Run("upgrade_from_v4", func(t *testing.T) {
		if len(ms) < 5 || ms[4].name != "0005_revocation.sql" {
			t.Fatalf("want migration 5 to be 0005_revocation.sql, have %d migrations", len(ms))
		}
		path := filepath.Join(t.TempDir(), "signer.db")
		raw, err := sql.Open("sqlite", path+"?"+dsnParams)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms[:4] {
			if _, err := raw.Exec(m.sql); err != nil {
				t.Fatalf("apply %s: %v", m.name, err)
			}
			if _, err := raw.Exec(fmt.Sprintf("PRAGMA user_version = %d", m.version)); err != nil {
				t.Fatal(err)
			}
		}
		reqID := bytes.Repeat([]byte{0x43}, 16)
		if _, err := raw.Exec(`INSERT INTO issuance (serial, request_id, ca_role, key_id, cert, issued_at_us) VALUES (?, ?, ?, ?, ?, ?)`,
			1700000000000001, reqID, "user", "kr2/key", []byte("cert"), 1700000000000002); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`INSERT INTO directory (version, doc, sigs, policy_version, installed_at_us) VALUES (?, ?, ?, ?, ?)`,
			1, []byte("doc"), []byte("sigs"), 1, 1700000000000004); err != nil {
			t.Fatal(err)
		}
		if err := raw.Close(); err != nil {
			t.Fatal(err)
		}
		d, err := Open(path)
		if err != nil {
			t.Fatalf("Open of a version 4 database: %v", err)
		}
		defer func() { _ = d.Close() }()
		if got := userVersion(t, d); got != len(ms) {
			t.Fatalf("user_version after the upgrade = %d, want %d", got, len(ms))
		}
		for _, table := range []string{"revocation", "krl_state", "revoke_request"} {
			var n int
			if err := d.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil || n != 0 { //nolint:gosec // G202: a constant table name
				t.Fatalf("%s rows after the upgrade = %d, %v; want an empty table", table, n, err)
			}
		}
		if st, err := d.KRLState(context.Background()); err != nil || st != nil {
			t.Fatalf("KRLState after the upgrade = %+v, %v; want none", st, err)
		}
		var (
			serial      int64
			gotReq      []byte
			role, keyID string
		)
		if err := d.db.QueryRow(`SELECT serial, request_id, ca_role, key_id FROM issuance`).Scan(&serial, &gotReq, &role, &keyID); err != nil ||
			serial != 1700000000000001 || !bytes.Equal(gotReq, reqID) || role != "user" || keyID != "kr2/key" {
			t.Fatalf("issuance row after the upgrade: %d %x %s %s, %v", serial, gotReq, role, keyID, err)
		}
		dir, err := d.LatestDirectory(context.Background())
		if err != nil || dir == nil || dir.Version != 1 || string(dir.Doc) != "doc" || string(dir.Sigs) != "sigs" {
			t.Fatalf("directory row after the upgrade: %+v, %v", dir, err)
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
	if err := d.ForEachLeaf(ctx, func(_ uint64, leaf []byte) error { seen = append(seen, string(leaf)); return nil }); err != nil || len(seen) != 3 {
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
	note, size, err = ro.ReadLog(ctx, func(_ uint64, leaf []byte) error { seen = append(seen, string(leaf)); return nil })
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

// TestDurabilityPragmas pins assumption A7: the signer database runs in WAL
// mode with synchronous=FULL, which SQLite documents as durable (ACID) in
// WAL mode, so a committed issuance and its log leaf survive power loss.
func TestDurabilityPragmas(t *testing.T) {
	d, _ := openTemp(t)
	var mode string
	var sync int
	if err := d.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := d.db.QueryRow(`PRAGMA synchronous`).Scan(&sync); err != nil {
		t.Fatal(err)
	}
	if mode != "wal" || sync != 2 {
		t.Fatalf("journal_mode=%s synchronous=%d, want wal and 2 (FULL)", mode, sync)
	}
}

// TestReadLogWithHashesSnapshot (A-WR-06, C-WR-02): ReadLogWithHashes
// serves the leaves, their hashes, the latest checkpoint, the CA keys, the
// latest trust bundle, the issuance row count and the serial high-water
// mark from one snapshot (C-WR-01 adds the last two). Rows committed by another
// connection while it reads are not seen, so the result is always
// consistent (doctor against a live signer).
func TestReadLogWithHashesSnapshot(t *testing.T) {
	ctx := context.Background()
	writer, path := openTemp(t)
	// appendOne takes the index as a byte so that the leaf and hash bytes
	// need no narrowing conversion; the log index is the widened value.
	appendOne := func(b byte) error {
		idx := uint64(b)
		return writer.WithTx(ctx, func(tx *sql.Tx) error {
			if err := writer.AppendLeaf(tx, idx, []byte{b, 'l'}, hash32(b)); err != nil {
				return err
			}
			return writer.PutCheckpoint(tx, idx+1, []byte{'c', b + 1})
		})
	}
	for i := range byte(3) {
		if err := appendOne(i); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	var seen []uint64
	snap, err := reader.ReadLogWithHashes(ctx, func(idx uint64, leaf, hash []byte) error {
		if idx == 0 {
			// Commit leaf 3 and its checkpoint, the CA keys and a trust
			// bundle mid-read.
			if err := appendOne(3); err != nil {
				return err
			}
			if err := writer.WithTx(ctx, func(tx *sql.Tx) error {
				keys := make([]CAKey, 0, len(CARoles))
				for i, role := range CARoles {
					keys = append(keys, CAKey{Role: role, PublicKey: []byte{'k', byte(i)}, Alg: "a", Custody: "c"})
				}
				if err := writer.SaveCAKeys(tx, keys); err != nil {
					return err
				}
				if err := writer.InsertIssuance(tx, issuance(77, 1)); err != nil {
					return err
				}
				if err := writer.SetLastSerial(tx, 77); err != nil {
					return err
				}
				return writer.InsertBundle(tx, StoredBundle{Version: 1, Bundle: []byte("b"), BundleSigs: []byte("s"),
					Policy: []byte("p"), PolicySigs: []byte("t"), InstalledAt: time.Now()})
			}); err != nil {
				return err
			}
		}
		if uint64(leaf[0]) != idx || uint64(hash[0]) != idx {
			t.Errorf("leaf %d: got leaf %x, hash %x", idx, leaf, hash)
		}
		seen = append(seen, idx)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 || snap.Size != 3 || string(snap.Checkpoint) != string([]byte{'c', 3}) {
		t.Fatalf("snapshot read %d leaves and checkpoint size %d (%x); want 3 leaves and checkpoint 3", len(seen), snap.Size, snap.Checkpoint)
	}
	if snap.CAKeys != nil || snap.Bundle != nil || snap.Issuances != 0 || snap.LastSerial != 0 {
		t.Fatalf("snapshot saw rows committed after it began: %+v", snap)
	}
	// The concurrent append did commit; the next read sees it.
	seen = nil
	if snap, err = reader.ReadLogWithHashes(ctx, func(idx uint64, _, _ []byte) error {
		seen = append(seen, idx)
		return nil
	}); err != nil || len(seen) != 4 || snap.Size != 4 {
		t.Fatalf("second read: %d leaves, %+v, %v; want 4 leaves and checkpoint 4", len(seen), snap, err)
	}
	if len(snap.CAKeys) != len(CARoles) || snap.Bundle == nil || snap.Bundle.Version != 1 || snap.Issuances != 1 || snap.LastSerial != 77 {
		t.Fatalf("second read: %+v; want the five keys, bundle version 1, one issuance row and high-water mark 77", snap)
	}

	t.Run("empty_log", func(t *testing.T) {
		empty, _ := openTemp(t)
		calls := 0
		snap, err := empty.ReadLogWithHashes(ctx, func(uint64, []byte, []byte) error { calls++; return nil })
		if err != nil || calls != 0 || snap.Checkpoint != nil || snap.Size != 0 {
			t.Fatalf("empty log: %d calls, %+v, %v; want 0 calls and no checkpoint", calls, snap, err)
		}
	})
}

// TestRevocationTables: a revoke request ID is recorded once (the PRIMARY
// KEY returns ErrDuplicateRequest), revocations read back in id order,
// and the KRL state only moves to a higher version.
func TestRevocationTables(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	id := [16]byte{1, 2, 3}
	now := time.UnixMicro(1700000000000000)
	err := d.WithTx(ctx, func(tx *sql.Tx) error {
		for i, serial := range []uint64{9, 5} {
			if err := d.InsertRevocation(tx, Revocation{Kind: RevocationSerial, CAKey: []byte("ca"), Serial: serial,
				ValidBeforeMicros: 1700000600000000, RequestID: id, LeafIndex: uint64(i), RevokedAt: now}); err != nil {
				return err
			}
		}
		if err := d.InsertRevokeRequestTx(tx, id, 1); err != nil {
			return err
		}
		return d.PutKRLStateTx(tx, KRLState{Version: 1, KRL: []byte("k1"), Manifest: []byte("m1"), Sig: []byte("s1"), PublishedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	if used, err := d.RevokeRequestUsed(ctx, id); err != nil || !used {
		t.Fatalf("RevokeRequestUsed = %v, %v", used, err)
	}
	if used, err := d.RevokeRequestUsed(ctx, [16]byte{9}); err != nil || used {
		t.Fatalf("RevokeRequestUsed(another id) = %v, %v", used, err)
	}
	err = d.WithTx(ctx, func(tx *sql.Tx) error {
		if err := d.InsertRevokeRequestTx(tx, id, 2); !errors.Is(err, ErrDuplicateRequest) {
			t.Errorf("a second InsertRevokeRequestTx: %v, want ErrDuplicateRequest", err)
		}
		return errors.New("roll back")
	})
	if err == nil {
		t.Fatal("the rolled-back transaction committed")
	}
	err = d.WithTx(ctx, func(tx *sql.Tx) error {
		revs, err := d.RevocationsTx(ctx, tx)
		if err != nil {
			return err
		}
		if len(revs) != 2 || revs[0].Serial != 9 || revs[1].Serial != 5 || revs[0].ValidBeforeMicros != 1700000600000000 || revs[0].RequestID != id {
			t.Errorf("RevocationsTx = %+v", revs)
		}
		if err := d.PutKRLStateTx(tx, KRLState{Version: 1, KRL: []byte("k"), Manifest: []byte("m"), Sig: []byte("s"), PublishedAt: now}); err == nil {
			t.Error("PutKRLStateTx accepted the same version again")
		}
		if err := d.InsertRevocation(tx, Revocation{Kind: RevocationKeyID, KeyID: "k", RequestID: id, RevokedAt: now}); err == nil {
			t.Error("InsertRevocation accepted a key_id row, which this version does not write")
		}
		return d.PutKRLStateTx(tx, KRLState{Version: 2, KRL: []byte("k2"), Manifest: []byte("m2"), Sig: []byte("s2"), PublishedAt: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := d.KRLState(ctx)
	if err != nil || st == nil || st.Version != 2 || string(st.KRL) != "k2" || string(st.Manifest) != "m2" || string(st.Sig) != "s2" {
		t.Fatalf("KRLState = %+v, %v", st, err)
	}
}
