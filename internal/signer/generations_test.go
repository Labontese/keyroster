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
type genBackend struct {
	*memBackend
	mu         sync.Mutex
	provisions int
	used       [][]string
	locations  []string
}

func newGenBackend(fx *Fixture) *genBackend { return &genBackend{memBackend: newMemBackend(fx)} }

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
	return s.PublicKey(), fmt.Sprintf("loc-%s-g%d", role, generation), nil
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

// TestCheckBundleKeysGenerations (03-12): an install accepts exactly one
// active CA entry per role, equal in key, algorithm, custody and generation
// to the role's stored generation 1, and refuses a root or a policy admin
// equal to any stored generation, prepared ones included. 03-12b rewrites
// non_active_entry_refused and 03-12e active_not_generation_1_refused.
func TestCheckBundleKeysGenerations(t *testing.T) {
	refused := func(t *testing.T, e *genEnv, docs [4][]byte) {
		t.Helper()
		leaves := e.leaves(t)
		v, err := e.db.LatestBundleVersion(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.install(docs); err == nil {
			t.Fatal("the successor was installed")
		} else {
			t.Logf("refusal: %v", err)
		}
		if n := e.leaves(t); n != leaves {
			t.Fatalf("%d leaves after the refusal, want %d", n, leaves)
		}
		if got, _ := e.db.LatestBundleVersion(context.Background()); got != v {
			t.Fatalf("bundle version %d after the refusal, want %d", got, v)
		}
	}
	t.Run("non_active_entry_refused", func(t *testing.T) {
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		refused(t, e, editedSuccessor(t, e.db, func(b *trust.Bundle) {
			b.CAs = append(b.CAs, trust.CAEntry{Role: "user", Key: formatWire(t, g.PublicKey), Alg: g.Alg, Custody: g.Custody, State: "next", Generation: 2})
		}, nil, e.fx.Root))
	})
	t.Run("active_not_generation_1_refused", func(t *testing.T) {
		e := newGenEnv(t)
		g := e.mustPrepare(t, keystore.RoleUser)
		refused(t, e, editedSuccessor(t, e.db, func(b *trust.Bundle) {
			ca := caEntry(t, b, "user")
			ca.Key, ca.Generation = formatWire(t, g.PublicKey), 2
		}, nil, e.fx.Root))
	})
	t.Run("generation_field_mismatch_refused", func(t *testing.T) {
		e := newGenEnv(t)
		e.mustPrepare(t, keystore.RoleUser)
		refused(t, e, editedSuccessor(t, e.db, func(b *trust.Bundle) { caEntry(t, b, "user").Generation = 2 }, nil, e.fx.Root))
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

// TestSuccessorForeignCAKeyRefused (03-12, a duty of 03-14b): a root-signed
// successor that replaces a CA key with a foreign one is refused by
// checkBundleKeys through InstallBundle (the chain rule has no CA rule
// yet), and nothing is written.
func TestSuccessorForeignCAKeyRefused(t *testing.T) {
	for _, role := range []string{"user", "host", "machine"} {
		t.Run(role, func(t *testing.T) {
			e := newGenEnv(t)
			leaves := e.leaves(t)
			foreign := trust.FormatKey(newEd25519(t).PublicKey())
			_, err := e.install(editedSuccessor(t, e.db, func(b *trust.Bundle) { caEntry(t, b, role).Key = foreign }, nil, e.fx.Root))
			if !errors.Is(err, ErrBundleKeys) {
				t.Fatalf("a successor with a foreign %s CA key = %v, want ErrBundleKeys", role, err)
			}
			if n := e.leaves(t); n != leaves {
				t.Fatalf("%d leaves after the refusal, want %d", n, leaves)
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
