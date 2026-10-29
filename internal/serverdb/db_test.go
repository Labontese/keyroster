package serverdb

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
		if v := userVersion(t, d); v != 7 {
			t.Fatalf("user_version = %d, want 7", v)
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
		if v := userVersion(t, d2); v != 7 {
			t.Fatalf("user_version after reopen = %d, want 7", v)
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

// TestWebSignInRows: sign-in challenges and sessions are purged once
// expired, so the tables hold only live rows; a challenge is taken once.
func TestWebSignInRows(t *testing.T) {
	ctx := context.Background()
	t.Run("challenge_taken_once_and_purged", func(t *testing.T) {
		d, _ := openTemp(t)
		ch := bytes.Repeat([]byte{7}, 32)
		if err := d.CreateChallenge(ctx, "old", "alice", ch, tNow.Add(time.Minute).UnixMicro(), tNow.UnixMicro()); err != nil {
			t.Fatal(err)
		}
		if err := d.CreateChallenge(ctx, "live", "bob", ch, tNow.Add(3*time.Minute).UnixMicro(), tNow.UnixMicro()); err != nil {
			t.Fatal(err)
		}
		// A begin two minutes later purges the expired one.
		if err := d.CreateChallenge(ctx, "new", "carol", ch, tNow.Add(4*time.Minute).UnixMicro(), tNow.Add(2*time.Minute).UnixMicro()); err != nil {
			t.Fatal(err)
		}
		if n := count(t, d, "web_challenges"); n != 2 {
			t.Fatalf("%d challenge rows, want 2 (live, new)", n)
		}
		user, got, err := d.TakeChallenge(ctx, "live", tNow.Add(2*time.Minute))
		if err != nil || user != "bob" || !bytes.Equal(got, ch) {
			t.Fatalf("TakeChallenge = %q %x %v", user, got, err)
		}
		if _, _, err := d.TakeChallenge(ctx, "live", tNow.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second TakeChallenge: %v, want ErrNotFound", err)
		}
		if _, _, err := d.TakeChallenge(ctx, "new", tNow.Add(4*time.Minute)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("TakeChallenge at the expiry: %v, want ErrNotFound", err)
		}
		if n := count(t, d, "web_challenges"); n != 0 {
			t.Fatalf("%d challenge rows, want 0", n)
		}
	})
	t.Run("expired_sessions_purged", func(t *testing.T) {
		d, _ := openTemp(t)
		cred := []byte{1}
		if err := d.CreateSession(ctx, []byte("idle"), "alice", cred, tNow, time.Hour, 12*time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := d.CreateSession(ctx, []byte("busy"), "alice", cred, tNow, time.Hour, 12*time.Hour); err != nil {
			t.Fatal(err)
		}
		for h := time.Duration(1); h <= 12; h++ {
			if _, _, err := d.TouchSession(ctx, []byte("busy"), tNow.Add(h*time.Hour-time.Minute), time.Hour, 12*time.Hour); err != nil {
				t.Fatalf("touch at %v: %v", h*time.Hour-time.Minute, err)
			}
		}
		if err := d.CreateSession(ctx, []byte("fresh"), "bob", cred, tNow.Add(12*time.Hour+time.Second), time.Hour, 12*time.Hour); err != nil {
			t.Fatal(err)
		}
		if n := count(t, d, "sessions"); n != 1 {
			t.Fatalf("%d session rows, want 1 (fresh): idle and absolute expiry purge", n)
		}
		if _, err := d.DeleteSession(ctx, []byte("fresh")); err != nil {
			t.Fatal(err)
		}
		if _, err := d.DeleteSession(ctx, []byte("fresh")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("second DeleteSession: %v, want ErrNotFound", err)
		}
	})
}

// enrollTestAgent mints a join token for name and enrolls an agent with
// the identity SPKI hash spki (32 bytes of b) and the host key key, at
// nowUS.
func enrollTestAgent(t *testing.T, d *DB, b byte, name, key string, nowUS int64) *Agent {
	t.Helper()
	return enrollTestAgentToken(t, d, b, b, name, key, nowUS)
}

// storeTestHB stores a heartbeat with seq seq for the agents row k.
func storeTestHB(t *testing.T, d *DB, k AgentKey, seq int64) {
	t.Helper()
	if _, err := d.StoreHeartbeat(context.Background(), k, seq, []byte("{}"), 0, tNow.UnixMicro()); err != nil {
		t.Fatalf("store heartbeat %d: %v", seq, err)
	}
}

// enrollTestAgentToken is enrollTestAgent with the identity of b and the
// join token of tok (32 bytes of each).
func enrollTestAgentToken(t *testing.T, d *DB, b, tok byte, name, key string, nowUS int64) *Agent {
	t.Helper()
	ctx := context.Background()
	token := bytes.Repeat([]byte{tok}, 32)
	if err := d.CreateJoinToken(ctx, token, name, "admin", nowUS+3600_000_000); err != nil {
		t.Fatal(err)
	}
	a, err := d.EnrollAgent(ctx, token, Agent{IdentitySPKISHA256: bytes.Repeat([]byte{b}, 32), HostKeys: []string{key}, Facts: "{}"}, nowUS)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestAgentWritesKeyedByToken is the PR #74 pre-merge review's finding 8
// (03-08b fix round 1): agent A is deleted and the same identity
// re-enrolls with a new join token into A's reused row ID (the runbook's
// same-machine order), so B has A's ID and A's identity. Every agents-row
// writer called with A's key (its token) is ErrNotFound and leaves B's
// row, and its heartbeat, as they were. B is fresh (never approved, no
// removal) for the writers that only change such a row, and approved and
// removed, unconfirmed, for the others.
func TestAgentWritesKeyedByToken(t *testing.T) {
	ctx := context.Background()
	nowUS := tNow.UnixMicro()
	sum := bytes.Repeat([]byte{0xcd}, 32)
	reused := func(t *testing.T, approvedRemoved, confirmed bool) (*DB, AgentKey, *Agent) {
		t.Helper()
		d, _ := openTemp(t)
		enrollTestAgent(t, d, 0x01, "web0", "key-0", nowUS)
		a := enrollTestAgent(t, d, 0x0a, "web1", "key-a", nowUS)
		if err := d.DeleteAgentIf(ctx, a.Key(), ForgetFacts{}); err != nil {
			t.Fatalf("delete A: %v", err)
		}
		b := enrollTestAgentToken(t, d, 0x0a, 0x1a, "web1", "key-a", nowUS)
		if b.ID != a.ID || !bytes.Equal(b.IdentitySPKISHA256, a.IdentitySPKISHA256) || bytes.Equal(b.TokenSHA256, a.TokenSHA256) {
			t.Fatalf("B %d %x %x; the test needs A's row ID %d and identity with another token", b.ID, b.IdentitySPKISHA256, b.TokenSHA256, a.ID)
		}
		if approvedRemoved {
			if err := d.MarkAgentApproved(ctx, b.Key(), nowUS+1); err != nil {
				t.Fatal(err)
			}
			if err := d.SetAgentRemovedVersion(ctx, b.Key(), 5); err != nil {
				t.Fatal(err)
			}
			storeTestHB(t, d, b.Key(), 1)
		}
		if confirmed {
			if ok, err := d.RecordRemovalConfirmed(ctx, b.Key(), 1, 5, 6, sum); err != nil || !ok {
				t.Fatalf("record B's confirmation: %t %v", ok, err)
			}
		}
		before, err := d.AgentBySPKI(ctx, b.IdentitySPKISHA256)
		if err != nil {
			t.Fatal(err)
		}
		return d, a.Key(), before
	}
	type write struct {
		name  string
		write func(d *DB, k AgentKey, before *Agent) error
	}
	check := func(t *testing.T, approvedRemoved, confirmed bool, writes []write) {
		t.Helper()
		for _, w := range writes {
			d, k, before := reused(t, approvedRemoved, confirmed)
			hbsBefore, err := d.Heartbeats(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.write(d, k, before); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s with A's key: %v, want ErrNotFound", w.name, err)
			}
			after, err := d.AgentBySPKI(ctx, before.IdentitySPKISHA256)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Errorf("%s with A's key changed B's row:\n%+v\nwas\n%+v (%v)", w.name, after, before, err)
			}
			if hbs, err := d.Heartbeats(ctx); err != nil || !reflect.DeepEqual(hbs, hbsBefore) {
				t.Errorf("%s with A's key changed B's heartbeat: %v, was %v (%v)", w.name, hbs, hbsBefore, err)
			}
		}
	}
	t.Run("fresh", func(t *testing.T) {
		check(t, false, false, []write{
			{"TouchAgent", func(d *DB, k AgentKey, _ *Agent) error { return d.TouchAgent(ctx, k, nowUS+9) }},
			{"MarkAgentApproved", func(d *DB, k AgentKey, _ *Agent) error { return d.MarkAgentApproved(ctx, k, nowUS+9) }},
			{"SetAgentRemovedVersion_record", func(d *DB, k AgentKey, _ *Agent) error { return d.SetAgentRemovedVersion(ctx, k, 9) }},
			{"DeleteAgentIf", func(d *DB, k AgentKey, b *Agent) error { return d.DeleteAgentIf(ctx, k, b.ForgetFacts()) }},
			{"StoreHeartbeat", func(d *DB, k AgentKey, _ *Agent) error {
				_, err := d.StoreHeartbeat(ctx, k, 1, []byte("{}"), 7, nowUS+9)
				return err
			}},
			{"RecordClockOffset", func(d *DB, k AgentKey, _ *Agent) error { return d.RecordClockOffset(ctx, k, 7) }},
			{"RotateAgentIdentity", func(d *DB, k AgentKey, _ *Agent) error {
				return d.RotateAgentIdentity(ctx, k, bytes.Repeat([]byte{0x2a}, 32), nowUS+9)
			}},
		})
	})
	t.Run("approved_removed", func(t *testing.T) {
		check(t, true, false, []write{
			{"SetAgentRemovedVersion_clear", func(d *DB, k AgentKey, _ *Agent) error { return d.SetAgentRemovedVersion(ctx, k, 0) }},
			{"RecordRemovalConfirmed", func(d *DB, k AgentKey, _ *Agent) error {
				_, err := d.RecordRemovalConfirmed(ctx, k, 1, 5, 6, sum)
				return err
			}},
			{"DeleteAgentIf", func(d *DB, k AgentKey, b *Agent) error { return d.DeleteAgentIf(ctx, k, b.ForgetFacts()) }},
			{"StoreHeartbeat", func(d *DB, k AgentKey, _ *Agent) error {
				_, err := d.StoreHeartbeat(ctx, k, 2, []byte("{}"), 7, nowUS+9)
				return err
			}},
		})
	})
	t.Run("confirmed", func(t *testing.T) {
		check(t, true, true, []write{
			{"ClearRemovalConfirmed", func(d *DB, k AgentKey, _ *Agent) error {
				_, err := d.ClearRemovalConfirmed(ctx, k, 1)
				return err
			}},
			{"DeleteAgentIf", func(d *DB, k AgentKey, b *Agent) error { return d.DeleteAgentIf(ctx, k, b.ForgetFacts()) }},
		})
	})
	t.Run("seq_regressed", func(t *testing.T) {
		// StoreHeartbeat's seq_regressed write (03-08c): B's stored
		// heartbeat has seq 3, and A's request carries 2.
		d, k, b := reused(t, true, false)
		storeTestHB(t, d, b.Key(), 3)
		before, err := d.AgentBySPKI(ctx, b.IdentitySPKISHA256)
		if err != nil {
			t.Fatal(err)
		}
		hbsBefore, err := d.Heartbeats(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.StoreHeartbeat(ctx, k, 2, []byte("{}"), 7, nowUS+9); !errors.Is(err, ErrNotFound) {
			t.Errorf("StoreHeartbeat below B's seq with A's key: %v, want ErrNotFound", err)
		}
		after, err := d.AgentBySPKI(ctx, b.IdentitySPKISHA256)
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Errorf("StoreHeartbeat below B's seq with A's key changed B's row:\n%+v\nwas\n%+v (%v)", after, before, err)
		}
		if hbs, err := d.Heartbeats(ctx); err != nil || !reflect.DeepEqual(hbs, hbsBefore) {
			t.Errorf("StoreHeartbeat below B's seq with A's key changed B's heartbeat: %v, was %v (%v)", hbs, hbsBefore, err)
		}
	})
}

// TestAgentWritesKeyedByIdentity is PR #72 fix-round carry-over (a)
// (03-08b): agent A is deleted and B enrolls into A's reused row ID; every
// agents-row writer called with A's ID and A's identity is ErrNotFound
// and leaves B's row as it was, column for column.
func TestAgentWritesKeyedByIdentity(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	nowUS := tNow.UnixMicro()
	enrollTestAgent(t, d, 0x01, "web0", "key-0", nowUS)
	a := enrollTestAgent(t, d, 0x0a, "web1", "key-a", nowUS)
	if err := d.DeleteAgentIf(ctx, a.Key(), ForgetFacts{}); err != nil {
		t.Fatalf("delete A: %v", err)
	}
	b := enrollTestAgent(t, d, 0x0b, "web1", "key-b", nowUS)
	if b.ID != a.ID {
		t.Fatalf("B got row ID %d; the test needs A's %d (SQLite reuses the highest row ID)", b.ID, a.ID)
	}
	// B approved, removed at v5 and confirmed at v6, seen.
	sum := bytes.Repeat([]byte{0xcd}, 32)
	if err := d.MarkAgentApproved(ctx, b.Key(), nowUS+1); err != nil {
		t.Fatal(err)
	}
	if err := d.SetAgentRemovedVersion(ctx, b.Key(), 5); err != nil {
		t.Fatal(err)
	}
	storeTestHB(t, d, b.Key(), 1)
	if ok, err := d.RecordRemovalConfirmed(ctx, b.Key(), 1, 5, 6, sum); err != nil || !ok {
		t.Fatalf("record B's confirmation: %t %v", ok, err)
	}
	if err := d.TouchAgent(ctx, b.Key(), nowUS+2); err != nil {
		t.Fatal(err)
	}
	before, err := d.AgentBySPKI(ctx, b.IdentitySPKISHA256)
	if err != nil {
		t.Fatal(err)
	}
	if before.ApprovedAtUS != nowUS+1 || before.RemovedDirVersion != 5 || before.RemovalConfirmedVersion != 6 || !bytes.Equal(before.RemovalConfirmedSHA256, sum) || before.LastSeenUS != nowUS+2 {
		t.Fatalf("B before the writes: %+v", before)
	}
	for _, w := range []struct {
		name  string
		write func() error
	}{
		{"TouchAgent", func() error { return d.TouchAgent(ctx, a.Key(), nowUS+9) }},
		{"MarkAgentApproved", func() error { return d.MarkAgentApproved(ctx, a.Key(), nowUS+9) }},
		{"SetAgentRemovedVersion_clear", func() error { return d.SetAgentRemovedVersion(ctx, a.Key(), 0) }},
		{"SetAgentRemovedVersion_record", func() error { return d.SetAgentRemovedVersion(ctx, a.Key(), 9) }},
		{"RecordRemovalConfirmed", func() error {
			_, err := d.RecordRemovalConfirmed(ctx, a.Key(), 1, 5, 9, sum)
			return err
		}},
		{"ClearRemovalConfirmed", func() error {
			_, err := d.ClearRemovalConfirmed(ctx, a.Key(), 1)
			return err
		}},
		{"DeleteAgentIf", func() error { return d.DeleteAgentIf(ctx, a.Key(), before.ForgetFacts()) }},
	} {
		if err := w.write(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s with A's ID and identity: %v, want ErrNotFound", w.name, err)
		}
		after, err := d.AgentBySPKI(ctx, b.IdentitySPKISHA256)
		if err != nil || !reflect.DeepEqual(after, before) {
			t.Fatalf("%s with A's ID and identity changed B's row:\n%+v\nwas\n%+v (%v)", w.name, after, before, err)
		}
	}
	t.Run("fresh_row", func(t *testing.T) {
		// B never approved and with no removal: the conditional writers
		// would change its row if they matched by ID alone.
		d, _ := openTemp(t)
		a := enrollTestAgent(t, d, 0x0a, "web1", "key-a", nowUS)
		if err := d.DeleteAgentIf(ctx, a.Key(), ForgetFacts{}); err != nil {
			t.Fatal(err)
		}
		b := enrollTestAgent(t, d, 0x0b, "web1", "key-b", nowUS)
		if b.ID != a.ID {
			t.Fatalf("B got row ID %d; the test needs A's %d", b.ID, a.ID)
		}
		before, err := d.AgentBySPKI(ctx, b.IdentitySPKISHA256)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range []struct {
			name  string
			write func() error
		}{
			{"TouchAgent", func() error { return d.TouchAgent(ctx, a.Key(), nowUS+9) }},
			{"MarkAgentApproved", func() error { return d.MarkAgentApproved(ctx, a.Key(), nowUS+9) }},
			{"SetAgentRemovedVersion_record", func() error { return d.SetAgentRemovedVersion(ctx, a.Key(), 9) }},
			{"SetAgentRemovedVersion_clear", func() error { return d.SetAgentRemovedVersion(ctx, a.Key(), 0) }},
			{"DeleteAgentIf", func() error { return d.DeleteAgentIf(ctx, a.Key(), before.ForgetFacts()) }},
		} {
			if err := w.write(); !errors.Is(err, ErrNotFound) {
				t.Errorf("%s with A's ID and identity: %v, want ErrNotFound", w.name, err)
			}
			after, err := d.AgentBySPKI(ctx, b.IdentitySPKISHA256)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatalf("%s with A's ID and identity changed B's fresh row:\n%+v\nwas\n%+v (%v)", w.name, after, before, err)
			}
		}
	})
	t.Run("approved_again_keeps_the_first_time", func(t *testing.T) {
		if err := d.MarkAgentApproved(ctx, b.Key(), nowUS+50); err != nil {
			t.Fatalf("MarkAgentApproved on an approved row: %v", err)
		}
		if got, _ := d.AgentBySPKI(ctx, b.IdentitySPKISHA256); got.ApprovedAtUS != nowUS+1 {
			t.Fatalf("approved_at_us %d, want the first time %d", got.ApprovedAtUS, nowUS+1)
		}
		if err := d.SetAgentRemovedVersion(ctx, b.Key(), 7); err != nil {
			t.Fatalf("SetAgentRemovedVersion with one recorded: %v", err)
		}
		if got, _ := d.AgentBySPKI(ctx, b.IdentitySPKISHA256); got.RemovedDirVersion != 5 {
			t.Fatalf("removed_dir_version %d, want the first 5", got.RemovedDirVersion)
		}
	})
}

// TestDeleteAgentIf (03-08b, plan check item 1): the delete matches only
// while every fact equals the row, NULLs included: a never-approved row,
// a row without a confirmation and a confirmed one.
func TestDeleteAgentIf(t *testing.T) {
	ctx := context.Background()
	sum := bytes.Repeat([]byte{0xcd}, 32)
	nowUS := tNow.UnixMicro()
	t.Run("never_approved", func(t *testing.T) {
		d, _ := openTemp(t)
		a := enrollTestAgent(t, d, 0x0a, "web1", "key-a", nowUS)
		if err := d.DeleteAgentIf(ctx, a.Key(), ForgetFacts{ApprovedOnce: true}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("approved_once true for a never-approved row: %v", err)
		}
		if err := d.DeleteAgentIf(ctx, a.Key(), ForgetFacts{}); err != nil {
			t.Fatalf("the row's own facts: %v", err)
		}
	})
	t.Run("removed_unconfirmed_then_confirmed", func(t *testing.T) {
		d, _ := openTemp(t)
		a := enrollTestAgent(t, d, 0x0a, "web1", "key-a", nowUS)
		if err := d.MarkAgentApproved(ctx, a.Key(), nowUS); err != nil {
			t.Fatal(err)
		}
		if err := d.SetAgentRemovedVersion(ctx, a.Key(), 3); err != nil {
			t.Fatal(err)
		}
		for _, f := range []ForgetFacts{
			{ApprovedOnce: true},
			{ApprovedOnce: false, RemovalVersion: 3},
			{ApprovedOnce: true, RemovalVersion: 4},
			{ApprovedOnce: true, RemovalVersion: 3, ConfirmedVersion: 3, ConfirmedSHA256: sum},
		} {
			if err := d.DeleteAgentIf(ctx, a.Key(), f); !errors.Is(err, ErrNotFound) {
				t.Fatalf("facts %+v the row does not hold: %v", f, err)
			}
		}
		storeTestHB(t, d, a.Key(), 1)
		if ok, err := d.RecordRemovalConfirmed(ctx, a.Key(), 1, 3, 4, sum); err != nil || !ok {
			t.Fatalf("record: %t %v", ok, err)
		}
		if ok, err := d.RecordRemovalConfirmed(ctx, a.Key(), 1, 3, 5, sum); err != nil || ok {
			t.Fatalf("a second record: %t %v, want nothing recorded", ok, err)
		}
		other := bytes.Repeat([]byte{0xab}, 32)
		for _, f := range []ForgetFacts{
			{ApprovedOnce: true, RemovalVersion: 3},
			{ApprovedOnce: true, RemovalVersion: 3, ConfirmedVersion: 4, ConfirmedSHA256: other},
			{ApprovedOnce: true, RemovalVersion: 3, ConfirmedVersion: 5, ConfirmedSHA256: sum},
		} {
			if err := d.DeleteAgentIf(ctx, a.Key(), f); !errors.Is(err, ErrNotFound) {
				t.Fatalf("facts %+v the row does not hold: %v", f, err)
			}
		}
		if err := d.DeleteAgentIf(ctx, a.Key(), ForgetFacts{ApprovedOnce: true, RemovalVersion: 3, ConfirmedVersion: 4, ConfirmedSHA256: sum}); err != nil {
			t.Fatalf("the row's own facts: %v", err)
		}
		if _, err := d.AgentBySPKI(ctx, a.IdentitySPKISHA256); !errors.Is(err, ErrNotFound) {
			t.Fatalf("the row after the delete: %v", err)
		}
	})
}

// TestRemovalConfirmation is serverdb's half of carry-over (b) (03-08b):
// RecordRemovalConfirmed records only for the removal version the caller
// read.
func TestRemovalConfirmation(t *testing.T) {
	ctx := context.Background()
	sum := bytes.Repeat([]byte{0xcd}, 32)
	nowUS := tNow.UnixMicro()
	t.Run("removal_changed_before_record", func(t *testing.T) {
		// The caller read removal version 3; the removal was cleared and
		// recorded again at 5 before its write. Nothing is recorded.
		d, _ := openTemp(t)
		a := enrollTestAgent(t, d, 0x0a, "web1", "key-a", nowUS)
		if err := d.MarkAgentApproved(ctx, a.Key(), nowUS); err != nil {
			t.Fatal(err)
		}
		for _, v := range []uint64{3, 0, 5} {
			if err := d.SetAgentRemovedVersion(ctx, a.Key(), v); err != nil {
				t.Fatal(err)
			}
		}
		storeTestHB(t, d, a.Key(), 1)
		if ok, err := d.RecordRemovalConfirmed(ctx, a.Key(), 1, 3, 4, sum); err != nil || ok {
			t.Fatalf("a confirmation of the old removal: %t %v, want nothing recorded", ok, err)
		}
		if got, _ := d.AgentBySPKI(ctx, a.IdentitySPKISHA256); got.RemovedDirVersion != 5 || got.RemovalConfirmedVersion != 0 {
			t.Fatalf("removed_dir_version %d, confirmed %d; want 5, none", got.RemovedDirVersion, got.RemovalConfirmedVersion)
		}
	})
	// Owner decision D-R1 (PR #74 review fix round 1): a confirmation is
	// recorded or cleared only from the heartbeat that is still stored.
	removed := func(t *testing.T) (*DB, *Agent) {
		t.Helper()
		d, _ := openTemp(t)
		a := enrollTestAgent(t, d, 0x0a, "web1", "key-a", nowUS)
		if err := d.MarkAgentApproved(ctx, a.Key(), nowUS); err != nil {
			t.Fatal(err)
		}
		if err := d.SetAgentRemovedVersion(ctx, a.Key(), 3); err != nil {
			t.Fatal(err)
		}
		storeTestHB(t, d, a.Key(), 1)
		return d, a
	}
	confirmedAt := func(t *testing.T, d *DB, a *Agent) uint64 {
		t.Helper()
		got, err := d.AgentBySPKI(ctx, a.IdentitySPKISHA256)
		if err != nil || got.RemovedDirVersion != 3 {
			t.Fatalf("the row: %+v %v", got, err)
		}
		return got.RemovalConfirmedVersion
	}
	t.Run("heartbeat_changed_before_record", func(t *testing.T) {
		// The caller decided from heartbeat 1; heartbeat 2 (which may show
		// principals again) was stored before its write.
		d, a := removed(t)
		storeTestHB(t, d, a.Key(), 2)
		if ok, err := d.RecordRemovalConfirmed(ctx, a.Key(), 1, 3, 4, sum); err != nil || ok {
			t.Fatalf("a confirmation from a replaced heartbeat: %t %v, want nothing recorded", ok, err)
		}
		if v := confirmedAt(t, d, a); v != 0 {
			t.Fatalf("confirmed v%d, want none", v)
		}
	})
	t.Run("cleared_only_from_the_stored_heartbeat", func(t *testing.T) {
		d, a := removed(t)
		if ok, err := d.RecordRemovalConfirmed(ctx, a.Key(), 1, 3, 4, sum); err != nil || !ok {
			t.Fatalf("record: %t %v", ok, err)
		}
		storeTestHB(t, d, a.Key(), 2)
		if ok, err := d.ClearRemovalConfirmed(ctx, a.Key(), 1); err != nil || ok {
			t.Fatalf("a clear from a replaced heartbeat: %t %v, want nothing cleared", ok, err)
		}
		if v := confirmedAt(t, d, a); v != 4 {
			t.Fatalf("confirmed v%d, want 4", v)
		}
		if ok, err := d.ClearRemovalConfirmed(ctx, a.Key(), 2); err != nil || !ok {
			t.Fatalf("a clear from the stored heartbeat: %t %v", ok, err)
		}
		if v := confirmedAt(t, d, a); v != 0 {
			t.Fatalf("confirmed v%d after the clear, want none (the removal version stays)", v)
		}
		if ok, err := d.ClearRemovalConfirmed(ctx, a.Key(), 2); err != nil || ok {
			t.Fatalf("a second clear: %t %v, want nothing cleared", ok, err)
		}
		if ok, err := d.RecordRemovalConfirmed(ctx, a.Key(), 2, 3, 5, sum); err != nil || !ok {
			t.Fatalf("a new confirmation after the clear: %t %v", ok, err)
		}
	})
}

// TestAgentsAndHeartbeatsOneRead is PR #74 pre-merge review fix round 2,
// fix 2: host status reads the agents and their heartbeats as one
// snapshot. A request that marks the agent approved and stores its first
// heartbeat while the read runs (between the two reads, the hook) is seen
// whole or not at all: never a row with approved_at_us unset next to a
// stored heartbeat, which keyroster host status refuses.
func TestAgentsAndHeartbeatsOneRead(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	a := enrollTestAgent(t, d, 0x0a, "web1", "key-a", tNow.UnixMicro())
	written := make(chan error, 1)
	ran := false
	d.afterListAgents = func() {
		ran = true
		waits := d.db.Stats().WaitCount
		go func() {
			if err := d.MarkAgentApproved(ctx, a.Key(), tNow.UnixMicro()); err != nil {
				written <- err
				return
			}
			_, err := d.StoreHeartbeat(ctx, a.Key(), 1, []byte("{}"), 0, tNow.UnixMicro())
			written <- err
		}()
		deadline := time.Now().Add(10 * time.Second)
		for len(written) == 0 && d.db.Stats().WaitCount == waits {
			if time.Now().After(deadline) {
				t.Error("the write neither committed nor waited for the connection")
				return
			}
			time.Sleep(time.Millisecond)
		}
	}
	agents, hbs, err := d.AgentsAndHeartbeats(ctx)
	d.afterListAgents = nil
	if err != nil || !ran {
		t.Fatalf("AgentsAndHeartbeats = %v (hook ran: %v)", err, ran)
	}
	if err := <-written; err != nil {
		t.Fatalf("the request during the read = %v", err)
	}
	check := func(what string, agents []Agent, hbs map[int64]Heartbeat, approved bool) {
		t.Helper()
		if len(agents) != 1 {
			t.Fatalf("%s: %d agents, want 1", what, len(agents))
		}
		_, hasHB := hbs[a.ID]
		if (agents[0].ApprovedAtUS != 0) != approved || hasHB != approved {
			t.Fatalf("%s: approved_at_us %d, heartbeat stored %v; want approved and a heartbeat both %v", what, agents[0].ApprovedAtUS, hasHB, approved)
		}
	}
	check("read during the request", agents, hbs, false)
	agents, hbs, err = d.AgentsAndHeartbeats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check("read after the request", agents, hbs, true)
}
