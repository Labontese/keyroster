package signer

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestPrepareGeneration (03-12): PrepareGeneration records the next CA key
// generation of user, host or machine as a row and a ca_generation entry
// in one transaction, refuses a key equal to anything it must differ
// from, a role, a backend or a custody it cannot rotate, and checks the
// log before it creates any key.
func TestPrepareGeneration(t *testing.T) {
	ctx := context.Background()
	// unchanged requires a refusal to have written nothing.
	unchanged := func(t *testing.T, e *genEnv, leaves, rows int) {
		t.Helper()
		if n := e.leaves(t); n != leaves {
			t.Fatalf("%d leaves after the refusal, want %d", n, leaves)
		}
		if n := len(e.gens(t)); n != rows {
			t.Fatalf("%d generation rows after the refusal, want %d", n, rows)
		}
	}
	// refusedWith prepares role with fp, which must be refused with want
	// and write nothing.
	refusedWith := func(t *testing.T, e *genEnv, role keystore.Role, fp string, want error) error {
		t.Helper()
		leaves, rows := e.leaves(t), len(e.gens(t))
		_, err := e.prepare(role, fp)
		if !errors.Is(err, want) {
			t.Fatalf("PrepareGeneration = %v, want %v", err, want)
		}
		unchanged(t, e, leaves, rows)
		return err
	}
	fpOf := func(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }
	// held adds s to the backend and returns its fingerprint.
	held := func(e *genEnv, s ssh.Signer) string {
		e.be.keys[fpOf(s)] = s
		return fpOf(s)
	}

	t.Run("agent_backend_needs_key", func(t *testing.T) {
		fx := NewFixture(t, 1, 1)
		db := newStateDB(t)
		be := newMemBackend(fx)
		fx.Bootstrap(t, db, be, nil)
		_, err := PrepareGeneration(ctx, db, be, keystore.RoleUser, "", nil)
		if !errors.Is(err, ErrKeySelection) || !strings.Contains(err.Error(), "--key") {
			t.Fatalf("PrepareGeneration without --key on a backend that creates no key = %v", err)
		}
	})
	t.Run("provisioner_creates_next_generation", func(t *testing.T) {
		e := newGenEnv(t)
		for want := uint32(2); want <= 4; want++ {
			leaves, rows := e.leaves(t), len(e.gens(t))
			g := e.mustPrepare(t, keystore.RoleUser)
			if g.Generation != want || g.Role != "user" || g.Custody != "software" || g.Alg != ssh.KeyAlgoED25519 {
				t.Fatalf("generation %+v, want user generation %d", g, want)
			}
			if n := e.leaves(t); n != leaves+1 {
				t.Fatalf("%d leaves after prepare, want %d", n, leaves+1)
			}
			if n := len(e.gens(t)); n != rows+1 {
				t.Fatalf("%d generation rows after prepare, want %d", n, rows+1)
			}
			l := lastLeaf(t, e.db)
			body, err := tlog.DecodeCAGenerationBody(l.Body)
			if l.Kind != tlog.KindCAGeneration || err != nil || body.Role != g.Role || body.Generation != g.Generation ||
				string(body.PublicKey) != string(g.PublicKey) || body.Alg != g.Alg || body.Custody != g.Custody {
				t.Fatalf("the last leaf %s %+v does not record %+v (%v)", l.Kind, body, g, err)
			}
		}
	})
	t.Run("key_equal_stored_refused", func(t *testing.T) {
		e := newGenEnv(t)
		err := refusedWith(t, e, keystore.RoleUser, fpOf(e.fx.Roles[keystore.RoleHost]), ErrKeySelection)
		if !strings.Contains(err.Error(), "stored generation") {
			t.Fatalf("the refusal does not name the stored generation: %v", err)
		}
	})
	t.Run("key_equal_admin_refused", func(t *testing.T) {
		e := newGenEnv(t)
		err := refusedWith(t, e, keystore.RoleUser, held(e, e.fx.Admins[0]), ErrBundleKeys)
		if !strings.Contains(err.Error(), "admin") {
			t.Fatalf("the refusal does not name the admin: %v", err)
		}
	})
	t.Run("key_equal_root_refused", func(t *testing.T) {
		e := newGenEnv(t)
		err := refusedWith(t, e, keystore.RoleUser, held(e, e.fx.Root), ErrBundleKeys)
		if !strings.Contains(err.Error(), "root key") {
			t.Fatalf("the refusal does not name the root: %v", err)
		}
	})
	t.Run("key_equal_earlier_root_refused", func(t *testing.T) {
		e := newGenEnv(t)
		r2 := newEd25519(t)
		// v2 replaces the root R with R2; R and R2 both sign it.
		if _, err := e.install(editedSuccessor(t, e.db, func(b *trust.Bundle) {
			b.Root.Keys = []trust.RootKey{{Key: trust.FormatKey(r2.PublicKey()), Custody: "software"}}
		}, nil, e.fx.Root, r2)); err != nil {
			t.Fatalf("root rotation: %v", err)
		}
		b, _ := installedDocs(t, e.db)
		if len(b.Root.Keys) != 1 || b.Root.Keys[0].Key != trust.FormatKey(r2.PublicKey()) {
			t.Fatal("the installed bundle still names R")
		}
		err := refusedWith(t, e, keystore.RoleUser, held(e, e.fx.Root), ErrBundleKeys)
		if !strings.Contains(err.Error(), "root key") {
			t.Fatalf("the refusal does not name the root: %v", err)
		}
	})
	t.Run("key_equal_bundle_key_refused", func(t *testing.T) {
		e := newGenEnv(t)
		leaves, rows := e.leaves(t), len(e.gens(t))
		if _, err := e.prepare(keystore.RoleUser, fpOf(e.fx.Roles[keystore.RoleOps])); !errors.Is(err, ErrKeySelection) && !errors.Is(err, ErrBundleKeys) {
			t.Fatalf("PrepareGeneration with the ops key = %v", err)
		}
		unchanged(t, e, leaves, rows)
	})
	t.Run("refusal_before_provision_leaves_no_file", func(t *testing.T) {
		e := newGenEnv(t)
		delete(e.be.keys, fpOf(e.fx.Roles[keystore.RoleLog]))
		leaves, rows := e.leaves(t), len(e.gens(t))
		if _, err := e.prepare(keystore.RoleUser, ""); err == nil {
			t.Fatal("PrepareGeneration without the log key succeeded")
		}
		unchanged(t, e, leaves, rows)
		if n := e.be.provisionCount(); n != 0 {
			t.Fatalf("the backend was asked to create %d keys before the log key was open", n)
		}
	})
	t.Run("refusal_by_log_check_before_provision_leaves_no_file", func(t *testing.T) {
		e := newGenEnv(t)
		e.exec(t, `UPDATE checkpoint SET note = x'00' WHERE size = (SELECT max(size) FROM checkpoint)`)
		leaves, rows := e.leaves(t), len(e.gens(t))
		if _, err := e.prepare(keystore.RoleUser, ""); !errors.Is(err, errLogMismatch) {
			t.Fatalf("PrepareGeneration over an altered checkpoint = %v, want errLogMismatch", err)
		}
		unchanged(t, e, leaves, rows)
		if n := e.be.provisionCount(); n != 0 {
			t.Fatalf("the backend was asked to create %d keys before the log was checked", n)
		}
	})
	// PR #102 review (I2): the stored bundle and policy are the inputs of
	// the distinctness check, so a trust_bundle row the log does not
	// record is refused before any key is selected or created.
	t.Run("unlogged_policy_row_refused", func(t *testing.T) {
		e := newGenEnv(t)
		admin := held(e, e.fx.Admins[0])
		// The installed policy with admin 0's key replaced, so that the
		// row no longer names it: the row is edited and the log is left
		// as it is.
		_, p := installedDocs(t, e.db)
		p.Admins[0].Key = trust.FormatKey(newEd25519(t).PublicKey())
		pol, err := p.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		e.exec(t, `UPDATE trust_bundle SET policy = ? WHERE version = (SELECT max(version) FROM trust_bundle)`, pol)
		refusedWith(t, e, keystore.RoleUser, admin, errLogMismatch)
		refusedWith(t, e, keystore.RoleUser, "", errLogMismatch)
		if n := e.be.provisionCount(); n != 0 {
			t.Fatalf("the backend was asked to create %d keys over an unlogged policy row", n)
		}
	})
	t.Run("bundle_row_without_install_leaf_refused", func(t *testing.T) {
		fx := NewFixture(t, 1, 1)
		e := &genEnv{fx: fx, dbPath: filepath.Join(t.TempDir(), "signer.db"), be: newGenBackend(fx)}
		db, err := signerdb.Open(e.dbPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		e.db = db
		cas, err := InitCA(ctx, db, e.be, "test", map[string]string{}, fx.Selection(), nil)
		if err != nil {
			t.Fatal(err)
		}
		// The signed genesis documents, stored by SQL: the log records no
		// bundle_install entry.
		b, bs, p, ps := SignDocs(t, fx.GenesisBundle(t, cas, fx.Policy()), fx.Policy(), fx.Root)
		e.exec(t, `INSERT INTO trust_bundle (version, bundle, bundle_sigs, policy, policy_sigs, installed_at_us) VALUES (1, ?, ?, ?, ?, 1)`, b, bs, p, ps)
		refusedWith(t, e, keystore.RoleUser, "", errLogMismatch)
		refusedWith(t, e, keystore.RoleUser, held(e, fx.Admins[0]), errLogMismatch)
		if n := e.be.provisionCount(); n != 0 {
			t.Fatalf("the backend was asked to create %d keys over a bundle row without a bundle_install entry", n)
		}
	})
	t.Run("location_persisted_and_passed", func(t *testing.T) {
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		if g.Location != "loc-user-g2" {
			t.Fatalf("PrepareGeneration returned location %q", g.Location)
		}
		gens := e.gens(t)
		if i := slices.IndexFunc(gens, func(r signerdb.CAGeneration) bool { return r.Role == "user" && r.Generation == 2 }); i < 0 || gens[i].Location != "loc-user-g2" {
			t.Fatalf("the stored row does not hold the location: %+v", gens)
		}
		e.mustPrepare(t, keystore.RoleHost)
		e.be.mu.Lock()
		defer e.be.mu.Unlock()
		if len(e.be.used) != 2 || len(e.be.used[0]) != 0 || !slices.Equal(e.be.used[1], []string{"loc-user-g2"}) {
			t.Fatalf("the used locations of the two provisioning calls are %q", e.be.used)
		}
	})
	t.Run("row_and_leaf_one_transaction", func(t *testing.T) {
		e := newGenEnv(t)
		lw, err := newLogWriter(ctx, e.db, memKey{e.fx.Roles[keystore.RoleLog]}, nil)
		if err != nil {
			t.Fatal(err)
		}
		leaves, rows := e.leaves(t), len(e.gens(t))
		lw.cpSigner = failingSigner{lw.cpSigner}
		if _, err := prepareGeneration(ctx, lw, e.db, e.be, keystore.RoleUser, "", time.Now); err == nil {
			t.Fatal("prepareGeneration succeeded although the checkpoint was not signed")
		}
		unchanged(t, e, leaves, rows)
		if lw.broken != nil || lw.tree.Size() != uint64(leaves) { //nolint:gosec // G115: a leaf count
			t.Fatalf("the writer did not reload: broken %v, size %d, want %d", lw.broken, lw.tree.Size(), leaves)
		}
	})
	t.Run("tpm_and_piv_refused_until_supported", func(t *testing.T) {
		for _, name := range []string{"tpm", "piv"} {
			err := CheckRotationBackend(name)
			if !errors.Is(err, ErrRotationBackend) || !strings.Contains(err.Error(), "03-12f") || !strings.HasPrefix(err.Error(), "rotation_not_supported_on_backend") {
				t.Fatalf("CheckRotationBackend(%s) = %v", name, err)
			}
		}
		for _, name := range []string{"agent", "software"} {
			if err := CheckRotationBackend(name); err != nil {
				t.Fatalf("CheckRotationBackend(%s) = %v", name, err)
			}
		}
		for _, name := range []string{"pkcs11-agent", "", "foo"} {
			if err := CheckRotationBackend(name); !errors.Is(err, ErrRotationBackend) {
				t.Fatalf("CheckRotationBackend(%q) = %v", name, err)
			}
		}
	})
	for _, role := range []keystore.Role{keystore.RoleOps, keystore.RoleLog, "foo"} {
		name := "role_" + string(role) + "_refused"
		if role == "foo" {
			name = "role_unknown_refused"
		}
		t.Run(name, func(t *testing.T) {
			e := newGenEnv(t)
			err := refusedWith(t, e, role, "", ErrRotationRole)
			if !strings.HasPrefix(err.Error(), "rotation_role_not_supported") {
				t.Fatalf("the refusal does not start with its name: %v", err)
			}
			if n := e.be.provisionCount(); n != 0 {
				t.Fatalf("the backend was asked to create %d keys", n)
			}
		})
	}
	t.Run("custody_mismatch_refused", func(t *testing.T) {
		e := newGenEnv(t)
		other := newEd25519(t)
		held(e, other)
		leaves, rows := e.leaves(t), len(e.gens(t))
		// Only the new key reports custody agent; generation 1 is software.
		be := oneCustodyBackend{memBackend: e.be.memBackend, fp: fpOf(other), custody: keystore.CustodyAgent}
		_, err := PrepareGeneration(ctx, e.db, be, keystore.RoleUser, fpOf(other), nil)
		if !errors.Is(err, ErrRotationCustody) || !strings.HasPrefix(err.Error(), "rotation_custody_mismatch") {
			t.Fatalf("PrepareGeneration with a key of another custody = %v, want rotation_custody_mismatch", err)
		}
		unchanged(t, e, leaves, rows)
	})
	t.Run("no_bundle_refused", func(t *testing.T) {
		e := newInstallEnv(t, NewFixture(t, 1, 1))
		if _, err := PrepareGeneration(ctx, e.db, e.be, keystore.RoleUser, "", nil); !errors.Is(err, ErrNoTrustBundle) {
			t.Fatalf("PrepareGeneration before any bundle = %v, want ErrNoTrustBundle", err)
		}
	})
}

// oneCustodyBackend reports custody for the key with fingerprint fp only.
type oneCustodyBackend struct {
	*memBackend
	fp      string
	custody keystore.Custody
}

func (b oneCustodyBackend) Key(role keystore.Role, fp string) (keystore.CAKey, error) {
	k, err := b.memBackend.Key(role, fp)
	if err != nil || fp != b.fp {
		return k, err
	}
	return keyringKey{k, b.custody}, nil
}
