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
		if v := userVersion(t, d); v != 3 {
			t.Fatalf("user_version = %d, want 3", v)
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
		if v := userVersion(t, d2); v != 3 {
			t.Fatalf("user_version after reopen = %d, want 3", v)
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

// TestBindPendingCredential (pre-merge review, T-02-97): the conditional
// UPDATE and the one-per-user index make an invite register exactly one
// credential, deterministically, without the handler's earlier invite
// lookup in front of them.
func TestBindPendingCredential(t *testing.T) {
	ctx := context.Background()
	cred := func(id string) PendingCredential {
		return PendingCredential{ID: id, Alg: -7, SPKI: []byte{0x30, 0x01}, BackupEligible: true}
	}
	usedAt := func(t *testing.T, d *DB, name string) any {
		t.Helper()
		var v any
		if err := d.db.QueryRow(`SELECT invite_used_us FROM pending_users WHERE name = ?`, name).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	setup := func(t *testing.T) (*DB, PendingUser) {
		t.Helper()
		d, _ := openTemp(t)
		u := pending("alice", 1)
		if err := d.CreatePendingUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		return d, u
	}
	t.Run("second_bind_on_one_invite_refused", func(t *testing.T) {
		d, u := setup(t)
		if err := d.BindPendingCredential(ctx, u.InviteHash, tNow.UnixMicro(), cred("first")); err != nil {
			t.Fatal(err)
		}
		before := usedAt(t, d, "alice")
		err := d.BindPendingCredential(ctx, u.InviteHash, tNow.Add(time.Second).UnixMicro(), cred("second"))
		if !errors.Is(err, ErrInviteNotValid) || count(t, d, "pending_credentials") != 1 || usedAt(t, d, "alice") != before {
			t.Fatalf("second bind = %v, %d credentials, used %v (was %v); want ErrInviteNotValid, 1 and unchanged",
				err, count(t, d, "pending_credentials"), usedAt(t, d, "alice"), before)
		}
	})
	t.Run("replaced_invite_refused", func(t *testing.T) {
		d, u := setup(t)
		if err := d.ReplaceInvite(ctx, "alice", bytes.Repeat([]byte{7}, 32), tNow.Add(48*time.Hour).UnixMicro()); err != nil {
			t.Fatal(err)
		}
		if err := d.BindPendingCredential(ctx, u.InviteHash, tNow.UnixMicro(), cred("x")); !errors.Is(err, ErrInviteNotValid) || count(t, d, "pending_credentials") != 0 {
			t.Fatalf("bind on the replaced invite = %v, want ErrInviteNotValid and nothing written", err)
		}
	})
	t.Run("at_expiry_refused", func(t *testing.T) {
		d, u := setup(t)
		if err := d.BindPendingCredential(ctx, u.InviteHash, u.InviteExpires.UnixMicro(), cred("x")); !errors.Is(err, ErrInviteNotValid) || usedAt(t, d, "alice") != nil {
			t.Fatalf("bind at the expiry = %v (used %v), want ErrInviteNotValid and the invite unused", err, usedAt(t, d, "alice"))
		}
		if err := d.BindPendingCredential(ctx, u.InviteHash, u.InviteExpires.UnixMicro()-1, cred("x")); err != nil {
			t.Fatalf("bind a microsecond before the expiry = %v", err)
		}
	})
	t.Run("credential_id_of_another_user_refused", func(t *testing.T) {
		d, u := setup(t)
		b := pending("bob", 2)
		if err := d.CreatePendingUser(ctx, b); err != nil {
			t.Fatal(err)
		}
		if err := d.BindPendingCredential(ctx, u.InviteHash, tNow.UnixMicro(), cred("same")); err != nil {
			t.Fatal(err)
		}
		if err := d.BindPendingCredential(ctx, b.InviteHash, tNow.UnixMicro(), cred("same")); !errors.Is(err, ErrDuplicateCredential) || usedAt(t, d, "bob") != nil {
			t.Fatalf("bob binding alice's credential ID = %v (used %v), want ErrDuplicateCredential and bob's invite unused", err, usedAt(t, d, "bob"))
		}
	})
	t.Run("one_credential_per_user", func(t *testing.T) {
		d, u := setup(t)
		if err := d.BindPendingCredential(ctx, u.InviteHash, tNow.UnixMicro(), cred("first")); err != nil {
			t.Fatal(err)
		}
		// Only the unique index stands in the way: the invite is made
		// unused again without dropping the credential, which ReplaceInvite
		// would do.
		if _, err := d.db.Exec(`UPDATE pending_users SET invite_used_us = NULL WHERE name = 'alice'`); err != nil {
			t.Fatal(err)
		}
		if err := d.BindPendingCredential(ctx, u.InviteHash, tNow.UnixMicro(), cred("second")); !errors.Is(err, ErrDuplicateCredential) ||
			count(t, d, "pending_credentials") != 1 || usedAt(t, d, "alice") != nil {
			t.Fatalf("second credential for alice = %v, %d credentials, used %v; want ErrDuplicateCredential, 1 and the UPDATE rolled back",
				err, count(t, d, "pending_credentials"), usedAt(t, d, "alice"))
		}
	})
}

// TestPendingState (pre-merge review): PendingState reads the invite and
// the credentials in one transaction, so a write that commits while it
// reads is seen whole or not at all. The hook starts the write between
// the two reads and returns once the write has either committed (the
// reads are not isolated) or is waiting for the one connection the
// snapshot holds. Both are events, not timings.
func TestPendingState(t *testing.T) {
	ctx := context.Background()
	cred := PendingCredential{ID: "first", Alg: -7, SPKI: []byte{0x30, 0x01}, BackupEligible: true}
	oldExpires, newExpires := tNow.Add(24*time.Hour), tNow.Add(48*time.Hour)
	for _, tc := range []struct {
		name string
		// registered: carol's invite registered cred before the read.
		registered bool
		write      func(d *DB, u PendingUser) error
		// What PendingState must see during the write (the state before
		// it) and after it.
		beforeUsed, afterUsed       bool
		beforeExpires, afterExpires time.Time
	}{
		// The finding's scenario: admin B's reinvite lands while admin A
		// reads a used invite with its credential.
		{"reinvite_during_read", true, func(d *DB, _ PendingUser) error {
			return d.ReplaceInvite(ctx, "carol", bytes.Repeat([]byte{7}, 32), newExpires.UnixMicro())
		}, true, false, oldExpires, newExpires},
		{"registration_during_read", false, func(d *DB, u PendingUser) error {
			return d.BindPendingCredential(ctx, u.InviteHash, tNow.UnixMicro(), cred)
		}, false, true, oldExpires, oldExpires},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := openTemp(t)
			u := pending("carol", 1)
			if err := d.CreatePendingUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			if tc.registered {
				if err := d.BindPendingCredential(ctx, u.InviteHash, tNow.UnixMicro(), cred); err != nil {
					t.Fatal(err)
				}
			}
			check := func(what string, st *PendingState, used bool, expires time.Time) {
				t.Helper()
				if st.User.Name != "carol" || st.InviteUsed != used || len(st.Credentials) != boolInt(used) || !st.User.InviteExpires.Equal(expires) {
					t.Fatalf("%s: used %v with %d credentials, expires %s; want used %v with %d, expires %s",
						what, st.InviteUsed, len(st.Credentials), st.User.InviteExpires, used, boolInt(used), expires)
				}
			}
			written := make(chan error, 1)
			ran := false
			d.afterPendingInvite = func() {
				ran = true
				waits := d.db.Stats().WaitCount
				go func() { written <- tc.write(d, u) }()
				deadline := time.Now().Add(10 * time.Second)
				for len(written) == 0 && d.db.Stats().WaitCount == waits {
					if time.Now().After(deadline) {
						t.Error("the write neither committed nor waited for the connection")
						return
					}
					time.Sleep(time.Millisecond)
				}
			}
			st, err := d.PendingState(ctx, "carol")
			d.afterPendingInvite = nil
			if err != nil || !ran {
				t.Fatalf("PendingState = %v (hook ran: %v)", err, ran)
			}
			if err := <-written; err != nil {
				t.Fatalf("the write during the read = %v", err)
			}
			check("read during the write", st, tc.beforeUsed, tc.beforeExpires)
			after, err := d.PendingState(ctx, "carol")
			if err != nil {
				t.Fatal(err)
			}
			check("read after the write", after, tc.afterUsed, tc.afterExpires)
		})
	}
	t.Run("not_found", func(t *testing.T) {
		d, _ := openTemp(t)
		if _, err := d.PendingState(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("PendingState(nobody) = %v, want ErrNotFound", err)
		}
	})
}

// TestDeleteBound: DeleteBound removes the pending credentials an
// installed version binds to that same user, then each emptied account
// whose invite is not open, and nothing else (02-09-F6, 02-09-R2-F4).
func TestDeleteBound(t *testing.T) {
	ctx := context.Background()
	cred := func(id string) PendingCredential {
		return PendingCredential{ID: id, Alg: -7, SPKI: []byte{0x30, 0x01}}
	}
	// bound is the binding of cred(id)'s key to user.
	bound := func(id, user string) Binding {
		return Binding{ID: id, User: user, Alg: -7, SPKI: []byte{0x30, 0x01}}
	}
	setup := func(t *testing.T, names ...string) *DB {
		t.Helper()
		d, _ := openTemp(t)
		for i, n := range names {
			u := pending(n, byte(i+1))
			if err := d.CreatePendingUser(ctx, u); err != nil {
				t.Fatal(err)
			}
			if err := d.BindPendingCredential(ctx, u.InviteHash, tNow.UnixMicro(), cred(n+"-cred")); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	t.Run("bound_credential_and_used_account_deleted", func(t *testing.T) {
		d := setup(t, "dave", "carol")
		if err := d.DeleteBound(ctx, []Binding{bound("dave-cred", "dave"), bound("frank-cred", "frank")}, tNow.UnixMicro()); err != nil {
			t.Fatal(err)
		}
		if _, err := d.PendingUser(ctx, "dave"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("dave's account after DeleteBound: %v, want ErrNotFound", err)
		}
		if st, err := d.PendingState(ctx, "carol"); err != nil || len(st.Credentials) != 1 || !st.InviteUsed {
			t.Fatalf("carol after DeleteBound: %+v, %v; want unchanged", st, err)
		}
	})
	t.Run("same_id_other_user_untouched", func(t *testing.T) {
		d := setup(t, "erin")
		if err := d.DeleteBound(ctx, []Binding{bound("erin-cred", "frank")}, tNow.UnixMicro()); err != nil {
			t.Fatal(err)
		}
		if st, err := d.PendingState(ctx, "erin"); err != nil || len(st.Credentials) != 1 {
			t.Fatalf("erin after a binding of her credential ID to frank: %+v, %v; want unchanged", st, err)
		}
	})
	t.Run("same_id_other_key_untouched", func(t *testing.T) {
		// A binding of the pending ID to another key (a proposal written
		// before a reinvite whose new passkey reused the ID) deletes nothing
		// (pre-merge review, 02-09).
		d := setup(t, "dave")
		for _, b := range []Binding{
			{ID: "dave-cred", User: "dave", Alg: -7, SPKI: []byte{0x30, 0x02}},
			{ID: "dave-cred", User: "dave", Alg: -8, SPKI: []byte{0x30, 0x01}},
		} {
			if err := d.DeleteBound(ctx, []Binding{b}, tNow.UnixMicro()); err != nil {
				t.Fatal(err)
			}
			if st, err := d.PendingState(ctx, "dave"); err != nil || len(st.Credentials) != 1 {
				t.Fatalf("dave after a binding of his credential ID to another key (%+v): %+v, %v; want unchanged", b, st, err)
			}
		}
		pc, err := d.PendingCredentialByID(ctx, "dave-cred")
		if err != nil || pc.UserName != "dave" || pc.Alg != -7 || !bytes.Equal(pc.SPKI, []byte{0x30, 0x01}) {
			t.Fatalf("PendingCredentialByID(dave-cred) = %+v, %v; want dave's row", pc, err)
		}
		if _, err := d.PendingCredentialByID(ctx, "nobody-cred"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("PendingCredentialByID(nobody-cred) = %v, want ErrNotFound", err)
		}
	})
	t.Run("open_invite_kept", func(t *testing.T) {
		// A state BindPendingCredential never leaves (a credential under an
		// open invite), forced by SQL to reach the open-invite rule.
		d := setup(t, "alice")
		if _, err := d.db.Exec(`UPDATE pending_users SET invite_used_us = NULL WHERE name = 'alice'`); err != nil {
			t.Fatal(err)
		}
		if err := d.DeleteBound(ctx, []Binding{bound("alice-cred", "alice")}, tNow.UnixMicro()); err != nil {
			t.Fatal(err)
		}
		if st, err := d.PendingState(ctx, "alice"); err != nil || len(st.Credentials) != 0 || st.InviteUsed {
			t.Fatalf("alice after DeleteBound: %+v, %v; want her account with its open invite and no credential", st, err)
		}
		// Expired, the same invite no longer keeps the account.
		if _, err := d.db.Exec(`INSERT INTO pending_credentials (id, user_name, alg, spki, backup_eligible, backed_up, registered_us) VALUES ('alice-2', 'alice', -7, x'3001', 0, 0, 0)`); err != nil {
			t.Fatal(err)
		}
		if err := d.DeleteBound(ctx, []Binding{bound("alice-2", "alice")}, tNow.Add(25*time.Hour).UnixMicro()); err != nil {
			t.Fatal(err)
		}
		if _, err := d.PendingUser(ctx, "alice"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("alice's account after DeleteBound past the expiry: %v, want ErrNotFound", err)
		}
	})
}
