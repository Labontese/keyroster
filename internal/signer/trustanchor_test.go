package signer

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"testing"

	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
)

// attackerPolicy is a policy at version that names one fresh key, not one
// of the fixture's admins, as the only admin with quorum 1.
func attackerPolicy(t *testing.T, fx *Fixture, version uint64, prev string) *trust.Policy {
	t.Helper()
	_, attacker := NewEd25519Key(t)
	p := fx.Policy()
	p.Version, p.Prev = version, prev
	p.AdminQuorum = 1
	p.Admins = []trust.AdminKey{{Name: "mallory", Key: trust.FormatKey(attacker.PublicKey())}}
	return p
}

// TestStoredBundleMustMatchLog (A-WR-01): the signer takes its trust state
// from the trust_bundle table only when the verified log's last
// bundle_install entry records exactly that row. A row written to the
// database outside install-bundle (internally consistent, but never
// root-verified and never logged) stops serve from starting and
// install-bundle from building on it.
func TestStoredBundleMustMatchLog(t *testing.T) {
	ctx := context.Background()
	exec := func(t *testing.T, e *installEnv, query string, args ...any) {
		t.Helper()
		if err := e.db.WithTx(ctx, func(tx *sql.Tx) error {
			_, err := tx.Exec(query, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	canon := func(t *testing.T, doc interface{ Canonical() ([]byte, error) }) []byte {
		t.Helper()
		b, err := doc.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := map[string]func(t *testing.T, e *installEnv){
		// A version 2 row whose bundle chains to the installed one and
		// whose policy matches its hash and passes every start-up check,
		// but which no root signed and no bundle_install entry records.
		"unlogged_successor_row": func(t *testing.T, e *installEnv) {
			pol := attackerPolicy(t, e.fx, 2, trust.SHA256Hex(canon(t, e.fx.Policy())))
			b := successor(t, e.genesis(t), pol)
			exec(t, e, `INSERT INTO trust_bundle (version, bundle, bundle_sigs, policy, policy_sigs, installed_at_us) VALUES (2, ?, 'x', ?, 'x', 1)`,
				canon(t, b), canon(t, pol))
		},
		"installed_policy_replaced": func(t *testing.T, e *installEnv) {
			pol := attackerPolicy(t, e.fx, 1, trust.GenesisPrev)
			b := e.genesis(t)
			b.PolicySHA256 = trust.SHA256Hex(canon(t, pol))
			exec(t, e, `UPDATE trust_bundle SET bundle = ?, policy = ? WHERE version = 1`, canon(t, b), canon(t, pol))
		},
		"installed_signatures_replaced": func(t *testing.T, e *installEnv) {
			exec(t, e, `UPDATE trust_bundle SET policy_sigs = 'x' WHERE version = 1`)
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			e := newInstallEnv(t, NewFixture(t, 1, 1))
			e.installGenesis(t)
			cfg := Config{Backend: e.be, DB: e.db, AllowUIDs: []uint32{1}, Logger: slog.New(slog.DiscardHandler)}
			if _, err := New(cfg); err != nil {
				t.Fatalf("control before tampering: %v", err)
			}
			if err := CheckTrust(ctx, e.db); err != nil {
				t.Fatalf("CheckTrust before tampering: %v", err)
			}
			tamper(t, e)
			if _, err := New(cfg); !errors.Is(err, errLogMismatch) {
				t.Fatalf("New with a trust_bundle row the log does not record = %v, want errLogMismatch", err)
			}
			// doctor runs the same check (A-WR-01 via C-WR-02).
			if err := CheckTrust(ctx, e.db); !errors.Is(err, errLogMismatch) {
				t.Fatalf("CheckTrust with a trust_bundle row the log does not record = %v, want errLogMismatch", err)
			}
			pol := policyV2(t, e.fx)
			next := successor(t, e.genesis(t), pol)
			leaves := leafCount(t, e.db)
			if _, err := e.install(nil, 0, docs4(t, next, pol, e.fx.Root)); !errors.Is(err, errLogMismatch) {
				t.Fatalf("InstallBundle on a trust_bundle row the log does not record = %v, want errLogMismatch", err)
			}
			if n := leafCount(t, e.db); n != leaves {
				t.Fatalf("%d leaves after the refused install, want %d", n, leaves)
			}
		})
	}

	t.Run("installed_rows_deleted", func(t *testing.T) {
		e := newInstallEnv(t, NewFixture(t, 1, 1))
		e.installGenesis(t)
		exec(t, e, `DELETE FROM trust_bundle`)
		// Without a stored row install-bundle would take a genesis bundle;
		// the log already records one, so it refuses.
		_, err := e.install([]string{e.fx.RootPin()}, 1, docs4(t, e.fx.GenesisBundle(t, e.cas, e.fx.Policy()), e.fx.Policy(), e.fx.Root))
		if !errors.Is(err, errLogMismatch) {
			t.Fatalf("genesis install over a logged bundle = %v, want errLogMismatch", err)
		}
		if err := CheckTrust(ctx, e.db); !errors.Is(err, errLogMismatch) {
			t.Fatalf("CheckTrust with the logged bundle's row deleted = %v, want errLogMismatch", err)
		}
	})
}

// TestCheckTrustLogKeySwapped (C-WR-02): someone who can write signer.db
// replaces the recorded log key with their own and re-signs the latest
// checkpoint with it. The log then checks out against the recorded key
// (what doctor's log check used alone), but the installed bundle names
// another log key, so CheckTrust, as serve, refuses it.
func TestCheckTrustLogKeySwapped(t *testing.T) {
	ctx := context.Background()
	e := newInstallEnv(t, NewFixture(t, 1, 1))
	e.installGenesis(t)
	if err := CheckTrust(ctx, e.db); err != nil {
		t.Fatalf("control: %v", err)
	}
	_, attacker := NewEd25519Key(t)
	hashes, err := e.db.LeafHashes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := tree.Root()
	if err != nil {
		t.Fatal(err)
	}
	origin := tlog.Origin(attacker.PublicKey())
	ns, err := tlog.NewNoteSigner(origin, attacker)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := tlog.SignCheckpoint(tlog.Checkpoint{Origin: origin, Size: tree.Size(), Root: root}, ns)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.db.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE ca_keys SET pubkey = ? WHERE role = 'log'`, attacker.PublicKey().Marshal()); err != nil {
			return err
		}
		_, err := tx.Exec(`UPDATE checkpoint SET note = ? WHERE size = ?`, signed, tree.Size())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := CheckLog(ctx, e.db, attacker.PublicKey()); err != nil {
		t.Fatalf("CheckLog against the swapped key = %v; the tampering must pass the log check alone for this test to mean anything", err)
	}
	if err := CheckTrust(ctx, e.db); !errors.Is(err, ErrBundleKeys) {
		t.Fatalf("CheckTrust with the recorded log key swapped = %v, want ErrBundleKeys", err)
	}
}

// TestCheckTrustBeforeCAInit: CheckTrust on a database without CA keys
// refuses with ErrNotInitialised instead of reporting the trust state as
// sound.
func TestCheckTrustBeforeCAInit(t *testing.T) {
	if err := CheckTrust(context.Background(), newStateDB(t)); !errors.Is(err, ErrNotInitialised) {
		t.Fatalf("CheckTrust before ca-init = %v, want ErrNotInitialised", err)
	}
}
