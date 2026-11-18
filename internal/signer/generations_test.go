package signer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// genBackend is a memBackend that creates later CA key generations
// (keystore.GenerationProvisioner) and opens keys by generation
// (keystore.GenerationBackend), so that this package's tests exercise the
// provisioner path and the location's round trip without the software
// backend (03-12). It counts its provisioning calls and records the used
// argument of each one and the location every KeyAt call receives.
//
// It also says whether it holds a generation and removes one
// (keystore.GenerationHolder and GenerationRemover, 03-12e). What it holds
// is, by definition, what its KeyAt can open, and drop and
// RemoveGeneration remove a key from that same map, so the double can
// never report a key as not held while it still signs with it. holdsErr
// and removeErr, when set, make Holds and RemoveGeneration fail.
type genBackend struct {
	*memBackend
	fx         *Fixture // generation 1 of each role is fx's role key
	mu         sync.Mutex
	provisions int
	used       [][]string
	locations  []string
	created    map[string]string // "role/N" of each generation it created, to its fingerprint
	holdsErr   error
	removeErr  error
}

func newGenBackend(fx *Fixture) *genBackend {
	return &genBackend{memBackend: newMemBackend(fx), fx: fx}
}

// ProvisionGeneration generates an Ed25519 key, holds it, and returns it
// with the location loc-<role>-g<N>.
func (b *genBackend) ProvisionGeneration(role keystore.Role, generation uint32, used []string) (ssh.PublicKey, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.provisions++
	b.used = append(b.used, slices.Clone(used))
	b.keys[ssh.FingerprintSHA256(s.PublicKey())] = s
	if b.created == nil {
		b.created = map[string]string{}
	}
	b.created[fmt.Sprintf("%s/%d", role, generation)] = ssh.FingerprintSHA256(s.PublicKey())
	return s.PublicKey(), fmt.Sprintf("loc-%s-g%d", role, generation), nil
}

// Holds reports whether the key with fp is in the map KeyAt opens from,
// or fails with holdsErr (03-12e).
func (b *genBackend) Holds(_ keystore.Role, _ uint32, fp, _ string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.holdsErr != nil {
		return true, b.holdsErr
	}
	_, ok := b.keys[fp]
	return ok, nil
}

// RemoveGeneration removes the key with fp, or fails with removeErr
// (03-12e).
func (b *genBackend) RemoveGeneration(_ keystore.Role, _ uint32, fp, _ string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.removeErr != nil {
		return b.removeErr
	}
	delete(b.keys, fp)
	return nil
}

// drop removes the key of generation of role, as the runbook's removal
// step does after a switch install (03-12e): generation 1 is the
// fixture's role key, a later one a key this double created. A generation
// it cannot map fails the test, so a missed stand-in names itself.
func (b *genBackend) drop(t testing.TB, role keystore.Role, generation uint32) {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	fp, ok := b.created[fmt.Sprintf("%s/%d", role, generation)]
	if generation == 1 && b.fx != nil {
		if s, has := b.fx.Roles[role]; has {
			fp, ok = ssh.FingerprintSHA256(s.PublicKey()), true
		}
	}
	if !ok {
		t.Fatalf("drop: the double cannot map generation %d of %s to a key", generation, role)
	}
	delete(b.keys, fp)
}

// held reports, for a test, whether the double holds the key with fp.
func (b *genBackend) held(fp string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.keys[fp]
	return ok
}

// KeyAt records location and selects by fingerprint, as memBackend does.
func (b *genBackend) KeyAt(role keystore.Role, _ uint32, fp, location string) (keystore.CAKey, error) {
	b.mu.Lock()
	b.locations = append(b.locations, location)
	b.mu.Unlock()
	return b.Key(role, fp)
}

func (b *genBackend) provisionCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.provisions
}

// genEnv is a bootstrapped state (ca-init and a genesis bundle) whose
// backend is a genBackend.
type genEnv struct {
	fx     *Fixture
	dbPath string
	db     *signerdb.DB
	be     *genBackend
}

func newGenEnv(t *testing.T) *genEnv {
	t.Helper()
	fx := NewFixture(t, 1, 1)
	e := &genEnv{fx: fx, dbPath: filepath.Join(t.TempDir(), "signer.db"), be: newGenBackend(fx)}
	db, err := signerdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	fx.Bootstrap(t, db, e.be, nil)
	return e
}

func (e *genEnv) prepare(role keystore.Role, fp string) (signerdb.CAGeneration, error) {
	return PrepareGeneration(context.Background(), e.db, e.be, role, fp, nil)
}

func (e *genEnv) mustPrepare(t *testing.T, role keystore.Role) signerdb.CAGeneration {
	t.Helper()
	g, err := e.prepare(role, "")
	if err != nil {
		t.Fatalf("PrepareGeneration(%s): %v", role, err)
	}
	return g
}

// exec runs one SQL statement on the state database, as an edit outside
// the signer would.
func (e *genEnv) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	raw, err := sql.Open("sqlite", e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	if _, err := raw.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func (e *genEnv) gens(t *testing.T) []signerdb.CAGeneration {
	t.Helper()
	gens, err := e.db.CAGenerations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return gens
}

func (e *genEnv) leaves(t *testing.T) int { t.Helper(); return leafCount(t, e.db) }

// install installs docs as a successor (no pins).
func (e *genEnv) install(docs [4][]byte) (*trust.Bundle, error) {
	return InstallBundle(context.Background(), e.db, e.be, nil, 0, docs[0], docs[1], docs[2], docs[3], nil)
}

// start starts a signer over the state, as serve does.
func (e *genEnv) start() (*Signer, error) {
	return New(Config{Backend: e.be, DB: e.db, AllowUIDs: []uint32{1000}})
}

// logKey returns the log public key.
func (e *genEnv) logKey() ssh.PublicKey { return e.fx.Roles[keystore.RoleLog].PublicKey() }

// newKeyWire returns the SSH wire encoding of a fresh Ed25519 key.
func newKeyWire(t *testing.T) []byte { t.Helper(); return newEd25519(t).PublicKey().Marshal() }

// caEntry returns a pointer to b's CA entry for role.
func caEntry(t *testing.T, b *trust.Bundle, role string) *trust.CAEntry {
	t.Helper()
	for i := range b.CAs {
		if b.CAs[i].Role == role {
			return &b.CAs[i]
		}
	}
	t.Fatalf("no CA %s entry", role)
	return nil
}

func formatWire(t *testing.T, pub []byte) string {
	t.Helper()
	k, err := ssh.ParsePublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(k)
}

// mustRefusedInstall installs docs, requires the refusal want, and requires
// that nothing was written: no leaf and no bundle row (03-12b). It returns
// the refusal.
func mustRefusedInstall(t *testing.T, e *genEnv, docs [4][]byte, want error) error {
	t.Helper()
	leaves := e.leaves(t)
	v, err := e.db.LatestBundleVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, ierr := e.install(docs)
	if !errors.Is(ierr, want) {
		t.Fatalf("install = %v, want %v", ierr, want)
	}
	t.Logf("refusal: %v", ierr)
	if n := e.leaves(t); n != leaves {
		t.Fatalf("%d leaves after the refusal, want %d", n, leaves)
	}
	if got, _ := e.db.LatestBundleVersion(context.Background()); got != v {
		t.Fatalf("bundle version %d after the refusal, want %d", got, v)
	}
	return ierr
}

// checkKeys runs checkBundleKeys on the bundle of docs (or on b when docs
// is the zero value) against e's stored ca_keys and generation rows: the
// signer's own rule, apart from the chain rule that InstallBundle runs
// first (03-12b).
func (e *genEnv) checkKeys(t *testing.T, docs [4][]byte, b *trust.Bundle) error {
	t.Helper()
	if b == nil {
		var err error
		if b, err = trust.ParseBundle(docs[0]); err != nil {
			t.Fatal(err)
		}
	}
	caKeys, err := e.db.CAKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return checkBundleKeys(b, caKeys, e.gens(t))
}

// nextEntry is the next entry of the stored generation g of its role.
func nextEntry(t *testing.T, g signerdb.CAGeneration) trust.CAEntry {
	t.Helper()
	return trust.CAEntry{Role: g.Role, Key: formatWire(t, g.PublicKey), Alg: g.Alg, Custody: g.Custody, State: "next", Generation: g.Generation}
}

// insertCA inserts e into b's CA entries after the last entry of its role.
func insertCA(b *trust.Bundle, e trust.CAEntry) {
	at := 0
	for i, c := range b.CAs {
		if c.Role == e.Role {
			at = i + 1
		}
	}
	b.CAs = slices.Insert(b.CAs, at, e)
}

// TestCheckBundleKeysGenerations (03-12, 03-12b, 03-12e): an install accepts
// exactly one active CA entry per role, equal in key, algorithm and custody
// to a stored generation of its role whose number it carries, and a next,
// retired or draining entry only when it equals a stored generation of its
// role, whatever the backend holds; it refuses a root or a policy admin
// equal to any stored generation, prepared ones included. An edit of the
// active entry is refused by the chain rule first (03-12b), so those cases
// also call checkBundleKeys directly.
func TestCheckBundleKeysGenerations(t *testing.T) {
	refused := func(t *testing.T, e *genEnv, docs [4][]byte) {
		t.Helper()
		_ = mustRefusedInstall(t, e, docs, ErrBundleKeys)
	}
	t.Run("next_stored_accepted", func(t *testing.T) {
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		b, err := e.install(editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, nextEntry(t, g)) }, nil, e.fx.Root))
		if err != nil || b.Version != 2 {
			t.Fatalf("a successor adding the stored generation 2 as next: %v, %v", b, err)
		}
		if _, err := e.start(); err != nil {
			t.Fatalf("start after the successor: %v", err)
		}
	})
	t.Run("active_later_generation_ok", func(t *testing.T) {
		// Since the switch (03-12e) the active entry may be any stored
		// generation; replacing the active key in place is still the chain
		// rule's to refuse.
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		docs := editedSuccessor(t, e.db, func(b *trust.Bundle) {
			ca := caEntry(t, b, "user")
			ca.Key, ca.Generation = formatWire(t, g.PublicKey), 2
		}, nil, e.fx.Root)
		if err := e.checkKeys(t, docs, nil); err != nil {
			t.Fatalf("checkBundleKeys with the stored generation 2 active = %v, want nil", err)
		}
		_ = mustRefusedInstall(t, e, docs, trust.ErrVersionChain)
	})
	t.Run("active_not_stored_refused", func(t *testing.T) {
		// An active entry whose key no stored generation holds.
		e := newGenEnv(t)
		e.mustPrepare(t, keystore.RoleUser)
		docs := editedSuccessor(t, e.db, func(b *trust.Bundle) {
			caEntry(t, b, "user").Key = trust.FormatKey(newEd25519(t).PublicKey())
		}, nil, e.fx.Root)
		if err := e.checkKeys(t, docs, nil); !errors.Is(err, ErrBundleKeys) {
			t.Fatalf("checkBundleKeys with a foreign active key = %v, want ErrBundleKeys", err)
		}
	})
	t.Run("generation_field_mismatch_refused", func(t *testing.T) {
		e := newGenEnv(t)
		e.mustPrepare(t, keystore.RoleUser)
		docs := editedSuccessor(t, e.db, func(b *trust.Bundle) { caEntry(t, b, "user").Generation = 2 }, nil, e.fx.Root)
		if err := e.checkKeys(t, docs, nil); !errors.Is(err, ErrBundleKeys) || !strings.Contains(err.Error(), "carries generation 2") {
			t.Fatalf("checkBundleKeys = %v, want ErrBundleKeys naming the generation field", err)
		}
		_ = mustRefusedInstall(t, e, docs, trust.ErrVersionChain)
	})
	t.Run("next_not_stored_refused", func(t *testing.T) {
		// A next entry whose key no generation row holds: the chain rule
		// accepts the addition, and checkBundleKeys refuses it.
		e := newGenEnv(t)
		foreign := trust.CAEntry{Role: "user", Key: trust.FormatKey(newEd25519(t).PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "next", Generation: 2}
		docs := editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, foreign) }, nil, e.fx.Root)
		if err := e.checkKeys(t, docs, nil); !errors.Is(err, ErrBundleKeys) || !strings.Contains(err.Error(), "no stored generation") {
			t.Fatalf("checkBundleKeys = %v, want ErrBundleKeys naming no stored generation", err)
		}
		_ = mustRefusedInstall(t, e, docs, ErrBundleKeys)
	})
	t.Run("next_stored_wrong_generation_refused", func(t *testing.T) {
		// The stored generation 2 key listed under generation 3.
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		wrong := nextEntry(t, g)
		wrong.Generation = 3
		docs := editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, wrong) }, nil, e.fx.Root)
		if err := e.checkKeys(t, docs, nil); !errors.Is(err, ErrBundleKeys) || !strings.Contains(err.Error(), "generation 3 is no stored generation") {
			t.Fatalf("checkBundleKeys = %v, want ErrBundleKeys naming generation 3", err)
		}
		_ = mustRefusedInstall(t, e, docs, ErrBundleKeys)
	})
	t.Run("retired_accepted", func(t *testing.T) {
		// Direct: the chain rule refuses a new retired entry, so only an
		// aborted next one reaches the signer this way.
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		retired := nextEntry(t, g)
		retired.State = "retired"
		docs := editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, retired) }, nil, e.fx.Root)
		if err := e.checkKeys(t, docs, nil); err != nil {
			t.Fatalf("checkBundleKeys with the stored generation 2 retired = %v, want nil", err)
		}
	})
	t.Run("retired_not_stored_refused", func(t *testing.T) {
		e := newGenEnv(t)
		foreign := trust.CAEntry{Role: "user", Key: trust.FormatKey(newEd25519(t).PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "retired", Generation: 2}
		docs := editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, foreign) }, nil, e.fx.Root)
		if err := e.checkKeys(t, docs, nil); !errors.Is(err, ErrBundleKeys) || !strings.Contains(err.Error(), "is retired but generation 2 is no stored generation") {
			t.Fatalf("checkBundleKeys = %v, want ErrBundleKeys naming the retired entry", err)
		}
	})
	t.Run("draining_stored_generation_ok", func(t *testing.T) {
		// A direct call with an unvalidated bundle struct: a draining entry
		// that is a stored generation of its role is accepted, whatever the
		// backend holds (03-12e).
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		b, _ := installedDocs(t, e.db)
		draining := nextEntry(t, g)
		draining.State = "draining"
		insertCA(b, draining)
		if err := e.checkKeys(t, [4][]byte{}, b); err != nil {
			t.Fatalf("checkBundleKeys with the stored generation 2 draining = %v, want nil", err)
		}
	})
	t.Run("draining_parsed_bundle_stored_ok", func(t *testing.T) {
		// A bundle with a draining entry parses (version 2 or above, with a
		// trusted_until, 03-12c); the signer accepts it when the entry is a
		// stored generation of its role (03-12e).
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		b, _ := installedDocs(t, e.db)
		draining := nextEntry(t, g)
		draining.State, draining.TrustedUntil = "draining", "2026-12-01T00:00:00Z"
		insertCA(b, draining)
		b.Version, b.Prev = 2, trust.SHA256Hex([]byte("an earlier bundle"))
		doc, err := trust.CanonicalJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := trust.ParseBundle(doc)
		if err != nil {
			t.Fatalf("a version 2 bundle with a draining entry does not parse: %v", err)
		}
		if err := e.checkKeys(t, [4][]byte{}, parsed); err != nil {
			t.Fatalf("checkBundleKeys with a parsed draining entry of the stored generation 2 = %v, want nil", err)
		}
	})
	t.Run("draining_not_stored_refused", func(t *testing.T) {
		// A draining entry whose key no stored generation holds (03-12e).
		e := newGenEnv(t)
		b, _ := installedDocs(t, e.db)
		insertCA(b, trust.CAEntry{Role: "user", Key: trust.FormatKey(newEd25519(t).PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "agent",
			State: "draining", Generation: 2, TrustedUntil: "2026-12-01T00:00:00Z"})
		want := "CA user is draining but generation 2 is no stored generation of that key"
		if err := e.checkKeys(t, [4][]byte{}, b); !errors.Is(err, ErrBundleKeys) || !strings.Contains(err.Error(), want) {
			t.Fatalf("checkBundleKeys with a foreign draining entry = %v, want ErrBundleKeys naming %q", err, want)
		}
	})
	t.Run("draining_successor_refused_by_the_chain_rule", func(t *testing.T) {
		// A root-signed successor that adds a draining entry is refused by
		// the chain rule before the signer's own rule, and nothing is
		// written.
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		docs := editedSuccessor(t, e.db, func(b *trust.Bundle) {
			draining := nextEntry(t, g)
			draining.State, draining.TrustedUntil = "draining", "2026-12-01T00:00:00Z"
			insertCA(b, draining)
		}, nil, e.fx.Root)
		if err := mustRefusedInstall(t, e, docs, trust.ErrVersionChain); !strings.Contains(err.Error(), "a new entry must be next") {
			t.Fatalf("the refusal %q does not name the chain rule's reason", err)
		}
	})
	t.Run("admin_equal_stored_generation_refused", func(t *testing.T) {
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleHost)
		refused(t, e, editedSuccessor(t, e.db, nil, func(p *trust.Policy) {
			p.Admins = append(p.Admins, trust.AdminKey{Name: "prepared", Key: formatWire(t, g.PublicKey)})
		}, e.fx.Root))
	})
	t.Run("root_equal_stored_generation_refused", func(t *testing.T) {
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleMachine)
		refused(t, e, editedSuccessor(t, e.db, func(b *trust.Bundle) {
			b.Root.Keys = append(b.Root.Keys, trust.RootKey{Key: formatWire(t, g.PublicKey), Custody: "software"})
		}, nil, e.fx.Root))
	})
	t.Run("generation_1_active_accepted", func(t *testing.T) {
		e := newGenEnv(t)
		e.mustPrepare(t, keystore.RoleUser)
		if b, err := e.install(editedSuccessor(t, e.db, nil, nil, e.fx.Root)); err != nil || b.Version != 2 {
			t.Fatalf("an unchanged successor: %v, %v", b, err)
		}
		if _, err := e.start(); err != nil {
			t.Fatalf("start after the successor: %v", err)
		}
	})
}

// retireEntry returns an edit that retires the CA entry of role at gen.
func retireEntry(t *testing.T, role string, gen uint32) func(*trust.Bundle) {
	return func(b *trust.Bundle) {
		for i := range b.CAs {
			if b.CAs[i].Role == role && b.CAs[i].Generation == gen {
				b.CAs[i].State = "retired"
				return
			}
		}
		t.Fatalf("no CA %s generation %d", role, gen)
	}
}

// TestInstallNextBundle (03-12b): the signer installs and restarts on
// ceremony 1 (generation 1 active, generation 2 next), on its abort and on
// a later generation 3 added after the abort, and refuses a second next
// entry, a next entry that is no stored generation and an admin equal to
// a next key, writing nothing.
func TestInstallNextBundle(t *testing.T) {
	// withNext is e after a successor that adds the stored generation 2
	// of user as next.
	withNext := func(t *testing.T) (*genEnv, signerdb.CAGeneration) {
		t.Helper()
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		if b, err := e.install(editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, nextEntry(t, g)) }, nil, e.fx.Root)); err != nil || b.Version != 2 {
			t.Fatalf("the successor adding generation 2 as next: %v, %v", b, err)
		}
		return e, g
	}
	started := func(t *testing.T, e *genEnv) {
		t.Helper()
		if _, err := e.start(); err != nil {
			t.Fatalf("start: %v", err)
		}
	}
	t.Run("g1_active_plus_g2_next_installs", func(t *testing.T) {
		e, g := withNext(t)
		b, _ := installedDocs(t, e.db)
		if got := trust.IssuingCAs(b, "user"); len(got) != 2 || got[0].Generation != 1 || got[1] != nextEntry(t, g) {
			t.Fatalf("the installed bundle's user CAs %+v, want generation 1 active and 2 next", got)
		}
		started(t, e)
	})
	t.Run("abort_bundle_installs", func(t *testing.T) {
		e, _ := withNext(t)
		if b, err := e.install(editedSuccessor(t, e.db, retireEntry(t, "user", 2), nil, e.fx.Root)); err != nil || b.Version != 3 {
			t.Fatalf("the abort: %v, %v", b, err)
		}
		started(t, e)
	})
	t.Run("abort_then_g3_next_installs", func(t *testing.T) {
		e, _ := withNext(t)
		if _, err := e.install(editedSuccessor(t, e.db, retireEntry(t, "user", 2), nil, e.fx.Root)); err != nil {
			t.Fatalf("the abort: %v", err)
		}
		g3 := e.mustPrepare(t, keystore.RoleUser)
		if g3.Generation != 3 {
			t.Fatalf("the prepare after the abort made generation %d, want 3", g3.Generation)
		}
		if b, err := e.install(editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, nextEntry(t, g3)) }, nil, e.fx.Root)); err != nil || b.Version != 4 {
			t.Fatalf("generation 3 as next after the abort: %v, %v", b, err)
		}
		started(t, e)
	})
	t.Run("second_next_while_one_is_next_refused", func(t *testing.T) {
		// 03-12c: Validate refuses a second next entry of a role when the
		// bundle is parsed, before the chain rule runs.
		e, _ := withNext(t)
		g3 := e.mustPrepare(t, keystore.RoleUser)
		err := mustRefusedInstall(t, e, editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, nextEntry(t, g3)) }, nil, e.fx.Root), trust.ErrInvalid)
		if !strings.Contains(err.Error(), "more than one next entry") {
			t.Fatalf("the refusal %q does not hold Validate's text", err)
		}
	})
	t.Run("next_not_a_stored_generation_refused", func(t *testing.T) {
		e := newGenEnv(t)
		foreign := trust.CAEntry{Role: "user", Key: trust.FormatKey(newEd25519(t).PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "next", Generation: 2}
		_ = mustRefusedInstall(t, e, editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, foreign) }, nil, e.fx.Root), ErrBundleKeys)
	})
	t.Run("admin_equal_next_key_refused", func(t *testing.T) {
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		next := nextEntry(t, g)
		err := mustRefusedInstall(t, e, editedSuccessor(t, e.db, func(b *trust.Bundle) { insertCA(b, next) }, func(p *trust.Policy) {
			p.Admins = append(p.Admins, trust.AdminKey{Name: "nextadmin", Key: next.Key})
		}, e.fx.Root), ErrBundleKeys)
		if !strings.Contains(err.Error(), "nextadmin") {
			t.Fatalf("the refusal %q does not name the admin", err)
		}
	})
}

// TestSuccessorForeignCAKeyRefused (03-12, a duty of 03-14b): a root-signed
// successor that replaces a CA key with a foreign one is refused by the
// chain rule through InstallBundle (03-12b), naming the role, and nothing
// is written; checkBundleKeys, called directly, refuses the same bundle
// too.
func TestSuccessorForeignCAKeyRefused(t *testing.T) {
	for _, role := range []string{"user", "host", "machine"} {
		t.Run(role, func(t *testing.T) {
			e := newGenEnv(t)
			foreign := trust.FormatKey(newEd25519(t).PublicKey())
			docs := editedSuccessor(t, e.db, func(b *trust.Bundle) { caEntry(t, b, role).Key = foreign }, nil, e.fx.Root)
			if err := e.checkKeys(t, docs, nil); !errors.Is(err, ErrBundleKeys) {
				t.Fatalf("checkBundleKeys with a foreign %s CA key = %v, want ErrBundleKeys", role, err)
			}
			err := mustRefusedInstall(t, e, docs, trust.ErrVersionChain)
			if !strings.Contains(err.Error(), "CA "+role+" generation 1") {
				t.Fatalf("a successor with a foreign %s CA key = %v, want ErrVersionChain naming CA %s generation 1", role, err, role)
			}
			if v, _ := e.db.LatestBundleVersion(context.Background()); v != 1 {
				t.Fatalf("bundle version %d after the refusal, want 1", v)
			}
		})
	}
}

// TestCheckStoredTrust (03-12): an edit of one ca_keys row is refused at
// start (loadTrust) and by CheckTrust, which doctor runs. d15f044's
// checkBundleKeys already refuses each edit; once it reads the generation
// rows, checkStoredTrust's comparison of ca_keys with generation 1 keeps
// the refusal for the CA roles.
func TestCheckStoredTrust(t *testing.T) {
	t.Run("ca_keys_key_edited_refused", func(t *testing.T) {
		for _, role := range signerdb.CARoles {
			e := newGenEnv(t)
			e.exec(t, `UPDATE ca_keys SET pubkey = ? WHERE role = ?`, newKeyWire(t), role)
			_, err := e.start()
			if !errors.Is(err, ErrBundleKeys) || !strings.Contains(err.Error(), role) {
				t.Fatalf("start after an edit of the %s ca_keys key = %v, want ErrBundleKeys naming %s", role, err, role)
			}
		}
	})
	t.Run("ca_keys_alg_edited_refused", func(t *testing.T) {
		e := newGenEnv(t)
		e.exec(t, `UPDATE ca_keys SET alg = 'ecdsa-sha2-nistp256' WHERE role = 'user'`)
		if _, err := e.start(); !errors.Is(err, ErrBundleKeys) {
			t.Fatalf("start after an edit of the user ca_keys algorithm = %v, want ErrBundleKeys", err)
		}
	})
	t.Run("ca_keys_custody_edited_refused", func(t *testing.T) {
		e := newGenEnv(t)
		e.exec(t, `UPDATE ca_keys SET custody = 'agent' WHERE role = 'user'`)
		if _, err := e.start(); !errors.Is(err, ErrBundleKeys) {
			t.Fatalf("start after an edit of the user ca_keys custody = %v, want ErrBundleKeys", err)
		}
	})
	t.Run("ca_keys_edit_refused_by_check_trust", func(t *testing.T) {
		e := newGenEnv(t)
		e.exec(t, `UPDATE ca_keys SET pubkey = ? WHERE role = 'user'`, newKeyWire(t))
		if err := CheckTrust(context.Background(), e.db); !errors.Is(err, ErrBundleKeys) {
			t.Fatalf("CheckTrust after an edit of the user ca_keys key = %v, want ErrBundleKeys", err)
		}
	})
	t.Run("ca_keys_match_generation_1_ok", func(t *testing.T) {
		e := newGenEnv(t)
		if _, err := e.start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		if err := CheckTrust(context.Background(), e.db); err != nil {
			t.Fatalf("CheckTrust: %v", err)
		}
	})
}

// TestGenerationsLogged (03-12): the stored generation rows must be
// exactly the ca_init keys plus the logged ca_generation entries, in both
// directions, at start and in doctor's CheckLog and CheckTrust
// (generations_not_logged).
func TestGenerationsLogged(t *testing.T) {
	ctx := context.Background()
	t.Run("matching_rows_ok", func(t *testing.T) {
		e := newGenEnv(t)
		e.mustPrepare(t, keystore.RoleUser)
		e.mustPrepare(t, keystore.RoleHost)
		if _, err := e.start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		if err := CheckTrust(ctx, e.db); err != nil {
			t.Fatalf("CheckTrust: %v", err)
		}
		if err := CheckLog(ctx, e.db, e.logKey()); err != nil {
			t.Fatalf("CheckLog: %v", err)
		}
	})
	extraRow := func(t *testing.T, e *genEnv) {
		t.Helper()
		e.exec(t, `INSERT INTO ca_key_generations (role, generation, pubkey, alg, custody, location, created_at_us) VALUES ('host', 2, ?, 'ssh-ed25519', 'software', '', 1)`, newKeyWire(t))
	}
	t.Run("row_without_leaf_refused_at_start", func(t *testing.T) {
		e := newGenEnv(t)
		extraRow(t, e)
		if _, err := e.start(); !errors.Is(err, errGenerationsNotLogged) {
			t.Fatalf("start with a generation row no entry logs = %v, want generations_not_logged", err)
		}
	})
	t.Run("leaf_without_row_refused_at_start", func(t *testing.T) {
		e := newGenEnv(t)
		e.mustPrepare(t, keystore.RoleUser)
		e.exec(t, `DELETE FROM ca_key_generations WHERE role = 'user' AND generation = 2`)
		if _, err := e.start(); !errors.Is(err, errGenerationsNotLogged) {
			t.Fatalf("start with a logged generation and no row = %v, want generations_not_logged", err)
		}
	})
	t.Run("row_altered_refused", func(t *testing.T) {
		e := newGenEnv(t)
		e.mustPrepare(t, keystore.RoleUser)
		e.exec(t, `UPDATE ca_key_generations SET alg = 'ecdsa-sha2-nistp256' WHERE role = 'user' AND generation = 2`)
		if _, err := e.start(); !errors.Is(err, errGenerationsNotLogged) {
			t.Fatalf("start with an altered generation row = %v, want generations_not_logged", err)
		}
	})
	t.Run("refused_by_check_trust", func(t *testing.T) {
		e := newGenEnv(t)
		extraRow(t, e)
		if err := CheckTrust(ctx, e.db); !errors.Is(err, errGenerationsNotLogged) {
			t.Fatalf("CheckTrust = %v, want generations_not_logged", err)
		}
	})
	t.Run("refused_by_check_log", func(t *testing.T) {
		e := newGenEnv(t)
		extraRow(t, e)
		if err := CheckLog(ctx, e.db, e.logKey()); !errors.Is(err, errGenerationsNotLogged) {
			t.Fatalf("CheckLog = %v, want generations_not_logged", err)
		}
	})
}

// TestSignerRestartAfterPrepare (03-12): after a prepare the signer starts
// again on generation 1: doctor's CheckTrust passes, Status reports the
// generation-1 fingerprints, an admin issue request is signed by the
// generation-1 CA and the prepared key signs nothing; loadTrust hands each
// active row's location to KeyAt.
func TestSignerRestartAfterPrepare(t *testing.T) {
	ctx := context.Background()
	e := newGenEnv(t)
	prepared := map[string]signerdb.CAGeneration{}
	for _, role := range []keystore.Role{keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine} {
		prepared[string(role)] = e.mustPrepare(t, role)
	}
	sdb, err := signerdb.OpenReadOnly(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	s, err := New(Config{Backend: e.be, DB: e.db, StatusDB: sdb, AllowUIDs: []uint32{1000}})
	if err != nil {
		t.Fatalf("restart after prepare: %v", err)
	}
	if err := CheckTrust(ctx, e.db); err != nil {
		t.Fatalf("CheckTrust: %v", err)
	}
	st, err := s.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range st.Keys {
		role := keystore.Role(k.Role)
		if want := ssh.FingerprintSHA256(e.fx.Roles[role].PublicKey()); k.Fingerprint != want {
			t.Fatalf("Status reports %s %s, want generation 1 %s", k.Role, k.Fingerprint, want)
		}
	}
	req := &wire.IssueRequest{
		CARole: wire.CARoleUser, SubjectKey: newEd25519(t).PublicKey().Marshal(), Subject: "u:alice",
		Principals: []string{"alice"}, ValidForSeconds: 600, CreatedAt: uint64(time.Now().Unix()), //nolint:gosec // G115: after 1970
		InstallationID: e.fx.InstallationID,
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	req.Evidence = SignRequest(t, req, e.fx.Admins...)
	resp, err := s.Issue(ctx, Peer{UID: 1000}, req)
	if err != nil {
		t.Fatalf("Issue after the restart: %v", err)
	}
	pk, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	c := pk.(*ssh.Certificate)
	if !bytes.Equal(c.SignatureKey.Marshal(), e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()) {
		t.Fatalf("the certificate is signed by %s, want the generation-1 user CA", ssh.FingerprintSHA256(c.SignatureKey))
	}
	for role, g := range prepared {
		if bytes.Equal(c.SignatureKey.Marshal(), g.PublicKey) {
			t.Fatalf("the prepared %s key signed the certificate", role)
		}
	}
	t.Run("restart_passes_the_rows_location", func(t *testing.T) {
		e := newGenEnv(t)
		e.mustPrepare(t, keystore.RoleUser)
		e.exec(t, `UPDATE ca_key_generations SET location = 'loc-genesis-user' WHERE role = 'user' AND generation = 1`)
		e.be.mu.Lock()
		e.be.locations = nil
		e.be.mu.Unlock()
		if _, err := e.start(); err != nil {
			t.Fatalf("restart: %v", err)
		}
		e.be.mu.Lock()
		defer e.be.mu.Unlock()
		if !slices.Contains(e.be.locations, "loc-genesis-user") {
			t.Fatalf("KeyAt received the locations %q at restart, want the user row's loc-genesis-user", e.be.locations)
		}
	})
}

// lastLeaf returns the last leaf of db.
func lastLeaf(t *testing.T, db *signerdb.DB) tlog.Leaf {
	t.Helper()
	var last tlog.Leaf
	if err := db.ForEachLeaf(context.Background(), func(_ uint64, raw []byte) error {
		var err error
		last, err = tlog.DecodeLeaf(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return last
}
