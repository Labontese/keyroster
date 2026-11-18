package signer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/keystore"
	_ "github.com/Labontese/keyroster/internal/keystore/agent" // registers the "agent" backend
	"github.com/Labontese/keyroster/internal/keystore/software"
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
		_ = refusedWith(t, e, keystore.RoleUser, admin, errLogMismatch)
		_ = refusedWith(t, e, keystore.RoleUser, "", errLogMismatch)
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
		_ = refusedWith(t, e, keystore.RoleUser, "", errLogMismatch)
		_ = refusedWith(t, e, keystore.RoleUser, held(e, fx.Admins[0]), errLogMismatch)
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

// offline runs fn on one handle of k's state database with the signer
// stopped, and does not start it again (03-12e): a draining key may still
// be held, which a start would refuse.
func (k *swKit) offline(t *testing.T, fn func(db *signerdb.DB)) {
	t.Helper()
	k.e.close()
	db, err := signerdb.Open(k.e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	fn(db)
}

// start tries to start k's signer on be, as serve does, and returns New's
// error; on success the env holds the new signer (03-12e).
func (k *swKit) start(t *testing.T, be keystore.Backend) error {
	t.Helper()
	k.e.close()
	db, err := signerdb.Open(k.e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sdb, err := signerdb.OpenReadOnly(k.e.dbPath)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	s, err := New(Config{Backend: be, Clock: k.clk.Now, DB: db, StatusDB: sdb, AllowUIDs: []uint32{1000}})
	if err != nil {
		_ = sdb.Close()
		_ = db.Close()
		return err
	}
	k.e.db, k.e.sdb, k.e.s = db, sdb, s
	return nil
}

// heldSwitch is drainEnv with the switch of roles (allowance 0) installed
// behind the log's checkpoint, the signer stopped and every draining key
// still held, as right after install-bundle and before retire-key
// (03-12e).
func heldSwitch(t *testing.T, roles ...string) (*swKit, time.Time) {
	t.Helper()
	k, at := drainEnv(t)
	k.at(t, at.Add(10*time.Second))
	k.installHeld(t, k.switchDocs(t, at, 0, roles...))
	return k, at
}

// installHeld installs the switch d at the clock behind the log's
// checkpoint with the signer stopped, which stays stopped, and removes no
// key (03-12e).
func (k *swKit) installHeld(t *testing.T, d [4][]byte) {
	t.Helper()
	k.offline(t, func(db *signerdb.DB) {
		cp, _, err := db.LatestCheckpoint(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := InstallBundleWithPrevious(context.Background(), db, k.gb, nil, 0, d[0], d[1], d[2], d[3], k.clk.Now, cp); err != nil {
			t.Fatalf("the switch install: %v", err)
		}
	})
}

// retire runs RetireKeys for role over k's state database and backend with
// the signer stopped (03-12e).
func (k *swKit) retire(t *testing.T, role keystore.Role) (*RetireResult, error) {
	t.Helper()
	var (
		res *RetireResult
		err error
	)
	k.offline(t, func(db *signerdb.DB) {
		res, err = RetireKeys(context.Background(), db, k.gb, role)
	})
	return res, err
}

// fpGen is the fingerprint of generation of role in k's state database.
func (k *swKit) fpGen(t *testing.T, role keystore.Role, generation uint32) string {
	t.Helper()
	db, err := signerdb.Open(k.e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	gens, err := db.CAGenerations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range gens {
		if g.Role == string(role) && g.Generation == generation {
			return fingerprintOfWire(g.PublicKey)
		}
	}
	t.Fatalf("no generation %d of %s is stored", generation, role)
	return ""
}

// outcomes renders a RetireResult's generations as "<g> <outcome>" for a
// comparison; a nil result is "no result".
func outcomes(res *RetireResult) string {
	if res == nil {
		return "no result"
	}
	var parts []string
	for _, g := range res.Generations {
		parts = append(parts, fmt.Sprintf("%d %s", g.Generation, g.Outcome))
	}
	return strings.Join(parts, ", ")
}

// TestRetireKey (03-12e, RK-01 to RK-08 and RK-10, the library): after a
// switch, RetireKeys proves the bundle and the active key before it
// removes anything, then removes every draining generation of the named
// role and nothing else, and reports a key it could not remove as still
// held.
func TestRetireKey(t *testing.T) {
	t.Run("active_unusable_refused_nothing_removed", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		fp1 := k.fpGen(t, keystore.RoleUser, 1)
		k.gb.drop(t, keystore.RoleUser, 2)
		res, err := k.retire(t, keystore.RoleUser)
		if err == nil || !strings.Contains(err.Error(), "active_key_unusable") {
			t.Fatalf("RetireKeys with the active key gone = %s, %v; want active_key_unusable", outcomes(res), err)
		}
		if !k.gb.held(fp1) {
			t.Fatal("the draining generation 1 was removed although the active key does not sign")
		}
	})
	t.Run("no_draining_entry_refused", func(t *testing.T) {
		k, _ := drainEnv(t)
		res, err := k.retire(t, keystore.RoleUser)
		if err == nil || !strings.Contains(err.Error(), "no_draining_entry") {
			t.Fatalf("RetireKeys without a switch = %s, %v; want no_draining_entry", outcomes(res), err)
		}
	})
	t.Run("removes_every_draining_generation", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser, trust.RoleHost)
		u1, u2, h1 := k.fpGen(t, keystore.RoleUser, 1), k.fpGen(t, keystore.RoleUser, 2), k.fpGen(t, keystore.RoleHost, 1)
		res, err := k.retire(t, keystore.RoleUser)
		if err != nil || outcomes(res) != "1 removed" || res.Generations[0].Fingerprint != u1 {
			t.Fatalf("RetireKeys(user) = %s, %v; want generation 1 (%s) removed", outcomes(res), err, u1)
		}
		if k.gb.held(u1) || !k.gb.held(u2) || !k.gb.held(h1) {
			t.Fatalf("after retiring the user CA: user 1 held %v, user 2 held %v, host 1 held %v; want false, true, true", k.gb.held(u1), k.gb.held(u2), k.gb.held(h1))
		}
		if err := k.start(t, k.gb); err == nil || !strings.Contains(err.Error(), "of the host CA") {
			t.Fatalf("start with the host key still held: %v, want the refusal naming the host CA", err)
		}
		if res, err := k.retire(t, keystore.RoleHost); err != nil || outcomes(res) != "1 removed" {
			t.Fatalf("RetireKeys(host) = %s, %v; want generation 1 removed", outcomes(res), err)
		}
		if err := k.start(t, k.gb); err != nil {
			t.Fatalf("start after both roles were retired: %v", err)
		}
	})
	t.Run("two_draining_generations", func(t *testing.T) {
		// The first switch (its key dropped by the install's stand-in), a
		// ceremony for generation 3, the second switch with generation 2
		// still held, and generation 1 loaded into the backend again, as an
		// agent or pkcs11 reload would.
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		if _, err := k.install(t, k.switchDocs(t, at, 0, trust.RoleUser), true); err != nil {
			t.Fatalf("the first switch: %v", err)
		}
		at2 := k.ceremonyTime(t)
		k.ceremony1(t, at2, keystore.RoleUser)
		k.at(t, at2.Add(10*time.Second))
		k.installHeld(t, k.switchDocs(t, at2, 0, trust.RoleUser))
		u1, u2, u3 := k.fpGen(t, keystore.RoleUser, 1), k.fpGen(t, keystore.RoleUser, 2), k.fpGen(t, keystore.RoleUser, 3)
		k.gb.mu.Lock()
		k.gb.keys[u1] = k.e.fx.Roles[keystore.RoleUser]
		k.gb.mu.Unlock()
		res, err := k.retire(t, keystore.RoleUser)
		if err != nil || outcomes(res) != "1 removed, 2 removed" {
			t.Fatalf("RetireKeys = %s, %v; want generations 1 and 2 removed", outcomes(res), err)
		}
		if k.gb.held(u1) || k.gb.held(u2) || !k.gb.held(u3) {
			t.Fatalf("after retire-key: generation 1 held %v, 2 held %v, 3 held %v; want false, false, true", k.gb.held(u1), k.gb.held(u2), k.gb.held(u3))
		}
	})
	t.Run("unsupported_role_refused", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		for _, role := range []keystore.Role{keystore.RoleOps, keystore.RoleLog, "admin"} {
			if res, err := k.retire(t, role); err == nil || !strings.Contains(err.Error(), "rotation_role_not_supported") {
				t.Fatalf("RetireKeys(%s) = %s, %v; want rotation_role_not_supported", role, outcomes(res), err)
			}
		}
	})
	t.Run("removal_error_is_incomplete", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		fp1 := k.fpGen(t, keystore.RoleUser, 1)
		k.gb.removeErr = errors.New("injected removal failure")
		res, err := k.retire(t, keystore.RoleUser)
		if err == nil || !strings.Contains(err.Error(), "retire_key_incomplete: 1 draining generation(s) of role user are still held") {
			t.Fatalf("RetireKeys with a failing removal = %s, %v; want retire_key_incomplete", outcomes(res), err)
		}
		if outcomes(res) != "1 not removed" || !strings.Contains(res.Generations[0].Detail, "injected removal failure") {
			t.Fatalf("the result %s does not report generation 1 not removed with the failure", outcomes(res))
		}
		if !k.gb.held(fp1) {
			t.Fatal("generation 1 is gone although its removal failed")
		}
	})
	t.Run("bundle_not_the_logged_one_refused_nothing_removed", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		fp1 := k.fpGen(t, keystore.RoleUser, 1)
		k.e.exec(t, `UPDATE trust_bundle SET bundle_sigs = bundle_sigs || x'0a' WHERE version = (SELECT max(version) FROM trust_bundle)`)
		res, err := k.retire(t, keystore.RoleUser)
		if err == nil || !strings.Contains(err.Error(), "is not the one the last bundle_install entry records") {
			t.Fatalf("RetireKeys over an edited bundle row = %s, %v; want the log refusal", outcomes(res), err)
		}
		if !k.gb.held(fp1) {
			t.Fatal("generation 1 was removed although the stored bundle is not the logged one")
		}
	})
}

// TestRetireTargets (03-12e, RK-10, pure): each draining entry of the
// named role is paired with its stored generation row; an entry no row
// matches, or one that names the active entry's generation, is refused.
func TestRetireTargets(t *testing.T) {
	k1, k2, k3, k4 := newEd25519(t).PublicKey(), newEd25519(t).PublicKey(), newEd25519(t).PublicKey(), newEd25519(t).PublicKey()
	entry := func(role, state string, gen uint32, k ssh.PublicKey) trust.CAEntry {
		e := trust.CAEntry{Role: role, Key: trust.FormatKey(k), Alg: k.Type(), Custody: "agent", State: state, Generation: gen}
		if state == "draining" {
			e.TrustedUntil = "2026-12-01T00:00:00Z"
		}
		return e
	}
	gens := []signerdb.CAGeneration{
		{Role: "user", Generation: 1, PublicKey: k1.Marshal()},
		{Role: "user", Generation: 2, PublicKey: k2.Marshal()},
		{Role: "host", Generation: 1, PublicKey: k3.Marshal()},
	}
	t.Run("draining_of_the_role_only", func(t *testing.T) {
		b := &trust.Bundle{CAs: []trust.CAEntry{entry("user", "active", 2, k2), entry("user", "draining", 1, k1), entry("host", "draining", 1, k3)}}
		got, err := retireTargets(b, gens, "user")
		if err != nil || len(got) != 1 || got[0].Gen.Role != "user" || got[0].Gen.Generation != 1 || got[0].Entry.State != "draining" {
			t.Fatalf("retireTargets(user) = %+v, %v; want the user generation 1 row only", got, err)
		}
	})
	t.Run("unmatched_draining_entry_refused", func(t *testing.T) {
		for _, d := range []trust.CAEntry{entry("user", "draining", 1, k4), entry("user", "draining", 3, k1), entry("user", "draining", 1, k3)} {
			b := &trust.Bundle{CAs: []trust.CAEntry{entry("user", "active", 2, k2), d}}
			if got, err := retireTargets(b, gens, "user"); err == nil || !strings.Contains(err.Error(), "draining_generation_unknown") {
				t.Fatalf("retireTargets with the draining entry %+v = %+v, %v; want draining_generation_unknown", d, got, err)
			}
		}
	})
	t.Run("draining_names_the_active_generation_refused", func(t *testing.T) {
		b := &trust.Bundle{CAs: []trust.CAEntry{entry("user", "active", 2, k2), entry("user", "draining", 2, k2)}}
		if got, err := retireTargets(b, gens, "user"); err == nil || !strings.Contains(err.Error(), "draining_names_the_active_generation") {
			t.Fatalf("retireTargets with a draining entry of the active generation = %+v, %v; want draining_names_the_active_generation", got, err)
		}
	})
}

// softwareHolds is a genBackend whose Holds is the software backend's
// file check (software.GenerationHeld) over a state directory (03-12e).
type softwareHolds struct {
	*genBackend
	stateDir string
}

func (b softwareHolds) Holds(role keystore.Role, generation uint32, _, _ string) (bool, error) {
	return software.GenerationHeld(b.stateDir, role, generation)
}

// agentHolds is a genBackend whose Holds is a real agent backend's
// (03-12e).
type agentHolds struct {
	*genBackend
	agent keystore.Backend
}

func (b agentHolds) Holds(role keystore.Role, generation uint32, fp, location string) (bool, error) {
	return b.agent.(keystore.GenerationHolder).Holds(role, generation, fp, location)
}

// keysOnly opens keys through a genBackend and cannot say whether it
// holds one: it implements no keystore.GenerationHolder (03-12e).
type keysOnly struct{ g *genBackend }

func (b keysOnly) Key(role keystore.Role, fp string) (keystore.CAKey, error) {
	return b.g.Key(role, fp)
}

func (b keysOnly) KeyAt(role keystore.Role, generation uint32, fp, location string) (keystore.CAKey, error) {
	return b.g.KeyAt(role, generation, fp, location)
}

func (b keysOnly) Close() error { return nil }

// serveTestAgent serves keyring on a Unix socket in a short temporary
// directory until the test ends and returns the socket path.
func serveTestAgent(t *testing.T, keyring sshagent.Agent) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "krsa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sshagent.ServeAgent(keyring, c)
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		wg.Wait()
	})
	return filepath.Join(dir, "agent.sock")
}

// TestServeRefusesWhileBackendHoldsDrainingKey (03-12e, SR-01 to SR-07):
// signer.New in its serving configuration refuses draining_key_still_usable
// while the backend holds the key of a draining entry of the installed
// bundle in any role, or cannot say whether it does; it starts once the
// key is gone, or when no entry drains; the switch install itself runs
// while the old key is held.
func TestServeRefusesWhileBackendHoldsDrainingKey(t *testing.T) {
	refused := func(t *testing.T, err error, want ...string) {
		t.Helper()
		if !errors.Is(err, ErrDrainingKeyUsable) {
			t.Fatalf("start = %v, want draining_key_still_usable", err)
		}
		for _, w := range append(want, "; run keyroster-signer ca-rotate retire-key") {
			if !strings.Contains(err.Error(), w) {
				t.Fatalf("the refusal %q does not hold %q", err, w)
			}
		}
	}
	t.Run("software_file_held", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		fp1 := k.fpGen(t, keystore.RoleUser, 1)
		k.gb.drop(t, keystore.RoleUser, 1)
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "software"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "software", "user.age"), []byte("generation 1"), 0o600); err != nil {
			t.Fatal(err)
		}
		be := softwareHolds{genBackend: k.gb, stateDir: dir}
		refused(t, k.start(t, be), "the backend still holds generation 1 of the user CA ("+fp1+"), which the installed bundle drains")
		if err := os.Remove(filepath.Join(dir, "software", "user.age")); err != nil {
			t.Fatal(err)
		}
		if err := k.start(t, be); err != nil {
			t.Fatalf("start once user.age is gone: %v", err)
		}
	})
	t.Run("agent_holds", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		fp1 := k.fpGen(t, keystore.RoleUser, 1)
		k.gb.drop(t, keystore.RoleUser, 1)
		keyring := sshagent.NewKeyring()
		if err := keyring.Add(sshagent.AddedKey{PrivateKey: k.e.fx.RolePriv[keystore.RoleUser]}); err != nil {
			t.Fatal(err)
		}
		ab, err := keystore.Open("agent", map[string]string{"socket": serveTestAgent(t, keyring)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ab.Close() })
		be := agentHolds{genBackend: k.gb, agent: ab}
		refused(t, k.start(t, be), "the backend still holds generation 1 of the user CA ("+fp1+")")
		if err := keyring.RemoveAll(); err != nil {
			t.Fatal(err)
		}
		if err := k.start(t, be); err != nil {
			t.Fatalf("start once the agent no longer lists the key: %v", err)
		}
	})
	t.Run("unknown_backend_is_held", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		k.gb.drop(t, keystore.RoleUser, 1)
		err := k.start(t, keysOnly{g: k.gb})
		refused(t, err, "generation 1 of the user CA", "cannot tell whether the backend holds it")
		if !errors.Is(err, keystore.ErrHoldsUnsupported) {
			t.Fatalf("the refusal %q does not carry ErrHoldsUnsupported", err)
		}
	})
	t.Run("holds_error_refuses", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		k.gb.drop(t, keystore.RoleUser, 1)
		k.gb.holdsErr = errors.New("injected holds failure")
		refused(t, k.start(t, k.gb), "cannot tell whether the backend holds it: injected holds failure")
	})
	t.Run("any_role", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleHost)
		refused(t, k.start(t, k.gb), "the backend still holds generation 1 of the host CA ("+k.fpGen(t, keystore.RoleHost, 1)+")")
	})
	t.Run("not_held_passes", func(t *testing.T) {
		k, _ := heldSwitch(t, trust.RoleUser)
		k.gb.drop(t, keystore.RoleUser, 1)
		if err := k.start(t, k.gb); err != nil {
			t.Fatalf("start with the draining key gone: %v", err)
		}
	})
	t.Run("no_draining_entry_passes", func(t *testing.T) {
		k, _ := drainEnv(t)
		if err := k.start(t, k.gb); err != nil {
			t.Fatalf("start with no draining entry: %v", err)
		}
	})
	t.Run("install_runs_while_the_old_key_is_held", func(t *testing.T) {
		k, at := drainEnv(t)
		k.at(t, at.Add(10*time.Second))
		fp1 := k.fpGen(t, keystore.RoleUser, 1)
		if !k.gb.held(fp1) {
			t.Fatal("the backend does not hold generation 1 before the switch")
		}
		k.installHeld(t, k.switchDocs(t, at, 0, trust.RoleUser))
		if !k.gb.held(fp1) {
			t.Fatal("the switch install removed generation 1")
		}
	})
}
