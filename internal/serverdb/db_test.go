package serverdb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var tNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func openTemp(t *testing.T) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.db")
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

func count(t *testing.T, d *DB, table string) int {
	t.Helper()
	var n int
	if err := d.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil { //nolint:gosec // G202: a constant table name from the test
		t.Fatal(err)
	}
	return n
}

// pending returns a complete pending account for name; b fills the user
// handle and the invite hash.
func pending(name string, b byte) PendingUser {
	return PendingUser{
		Name:          name,
		UserHandle:    bytes.Repeat([]byte{b}, 32),
		InviteHash:    bytes.Repeat([]byte{b ^ 0xff}, 32),
		InviteExpires: tNow.Add(24 * time.Hour),
		Created:       tNow,
		CreatedBy:     "admin",
	}
}

func TestOpen(t *testing.T) {
	t.Run("migration_applies_once", func(t *testing.T) {
		d, path := openTemp(t)
		if v := userVersion(t, d); v != 2 {
			t.Fatalf("user_version = %d, want 2", v)
		}
		if err := d.CreatePendingUser(context.Background(), pending("alice", 1)); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		d2, err := Open(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		defer func() { _ = d2.Close() }()
		if v := userVersion(t, d2); v != 2 {
			t.Fatalf("user_version after reopen = %d, want 2", v)
		}
		if n := count(t, d2, "pending_users"); n != 1 {
			t.Fatalf("%d pending accounts after reopen, want the 1 written before", n)
		}
	})
	t.Run("newer_schema_refused", func(t *testing.T) {
		d, path := openTemp(t)
		if _, err := d.db.Exec(`PRAGMA user_version = 99`); err != nil {
			t.Fatal(err)
		}
		if err := d.Close(); err != nil {
			t.Fatal(err)
		}
		if d2, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer than this binary supports") {
			if d2 != nil {
				_ = d2.Close()
			}
			t.Fatalf("Open of a version 99 database: %v, want the newer-schema refusal", err)
		}
	})
	t.Run("file_mode_0600", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("file modes are a no-op on Windows")
		}
		_, path := openTemp(t)
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	})
	t.Run("unusable_path_refused", func(t *testing.T) {
		if _, err := Open(filepath.Join(t.TempDir(), "x.db?mode=ro")); err == nil {
			t.Fatal("a path with '?' was accepted")
		}
	})
}

// TestCreatePendingUserConflict: a second account with the same name is
// ErrExists and leaves the first row as it was; a conflict on another
// unique column is a plain error (02-07-R2-F17).
func TestCreatePendingUserConflict(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	first := pending("erin", 1)
	if err := d.CreatePendingUser(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := d.CreatePendingUser(ctx, pending("erin", 2)); !errors.Is(err, ErrExists) {
		t.Fatalf("second CreatePendingUser(erin) = %v, want ErrExists", err)
	}
	got, err := d.PendingUser(ctx, "erin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.UserHandle, first.UserHandle) || !bytes.Equal(got.InviteHash, first.InviteHash) {
		t.Fatalf("erin's row changed: %+v, want %+v", got, first)
	}
	// Control: a new name with erin's invite hash conflicts on another
	// column, which is not ErrExists.
	dup := pending("frank", 3)
	dup.InviteHash = first.InviteHash
	if err := d.CreatePendingUser(ctx, dup); err == nil || errors.Is(err, ErrExists) {
		t.Fatalf("CreatePendingUser with a used invite hash = %v, want a plain error", err)
	}
	if n := count(t, d, "pending_users"); n != 1 {
		t.Fatalf("%d pending accounts, want 1", n)
	}
}

func TestPendingUserInvite(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	u := pending("alice", 1)
	if err := d.CreatePendingUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	t.Run("found_until_expiry", func(t *testing.T) {
		got, err := d.PendingUserByInvite(ctx, u.InviteHash, u.InviteExpires.Add(-time.Microsecond))
		if err != nil || got.Name != "alice" || !got.InviteExpires.Equal(u.InviteExpires) || got.CreatedBy != "admin" {
			t.Fatalf("PendingUserByInvite before expiry = %+v, %v", got, err)
		}
		if _, err := d.PendingUserByInvite(ctx, u.InviteHash, u.InviteExpires); !errors.Is(err, ErrNotFound) {
			t.Fatalf("PendingUserByInvite at expiry = %v, want ErrNotFound", err)
		}
	})
	t.Run("replace_invite_keeps_handle", func(t *testing.T) {
		newHash := bytes.Repeat([]byte{7}, 32)
		if err := d.ReplaceInvite(ctx, "alice", newHash, tNow.Add(48*time.Hour).UnixMicro()); err != nil {
			t.Fatal(err)
		}
		if _, err := d.PendingUserByInvite(ctx, u.InviteHash, tNow); !errors.Is(err, ErrNotFound) {
			t.Fatalf("the replaced invite still matches: %v", err)
		}
		got, err := d.PendingUserByInvite(ctx, newHash, tNow)
		if err != nil || !bytes.Equal(got.UserHandle, u.UserHandle) {
			t.Fatalf("the new invite = %+v, %v; want alice with the same user handle", got, err)
		}
	})
	t.Run("replace_invite_unknown_name", func(t *testing.T) {
		if err := d.ReplaceInvite(ctx, "nobody", bytes.Repeat([]byte{8}, 32), tNow.UnixMicro()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("ReplaceInvite(nobody) = %v, want ErrNotFound", err)
		}
	})
	t.Run("unknown_name", func(t *testing.T) {
		if _, err := d.PendingUser(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("PendingUser(nobody) = %v, want ErrNotFound", err)
		}
	})
}

func TestUseNonce(t *testing.T) {
	ctx := context.Background()
	t.Run("replay_refused", func(t *testing.T) {
		d, _ := openTemp(t)
		if err := d.UseNonce(ctx, "n1", tNow.Add(time.Minute), tNow); err != nil {
			t.Fatal(err)
		}
		if err := d.UseNonce(ctx, "n1", tNow.Add(time.Minute), tNow); !errors.Is(err, ErrNonceUsed) {
			t.Fatalf("second UseNonce(n1) = %v, want ErrNonceUsed", err)
		}
	})
	t.Run("deletes_expired_rows", func(t *testing.T) {
		d, _ := openTemp(t)
		for i, n := range []string{"old1", "old2", "young"} {
			exp := tNow.Add(time.Duration(i+1) * time.Second)
			if n == "young" {
				exp = tNow.Add(time.Hour)
			}
			if err := d.UseNonce(ctx, n, exp, tNow); err != nil {
				t.Fatal(err)
			}
		}
		// At tNow+2s, old1 (expires +1s) and old2 (expires +2s) are gone.
		if err := d.UseNonce(ctx, "fresh", tNow.Add(time.Hour), tNow.Add(2*time.Second)); err != nil {
			t.Fatal(err)
		}
		if n := count(t, d, "admin_nonces"); n != 2 {
			t.Fatalf("%d nonce rows after the purge, want 2 (young, fresh)", n)
		}
		if err := d.UseNonce(ctx, "young", tNow.Add(time.Hour), tNow.Add(2*time.Second)); !errors.Is(err, ErrNonceUsed) {
			t.Fatalf("UseNonce(young) = %v, want ErrNonceUsed: an unexpired row must survive the purge", err)
		}
	})
}
