package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// keyringBackend serves an in-memory agent.NewKeyring() as a keystore
// backend. It returns whatever entry has the fingerprint, certificates and
// RSA or P-384 keys included, so the checks under test are InitCA's own.
type keyringBackend struct {
	kr      sshagent.Agent
	custody keystore.Custody
}

type keyringKey struct {
	ssh.Signer
	custody keystore.Custody
}

func (k keyringKey) Custody() keystore.Custody { return k.custody }
func (k keyringKey) Algorithm() string         { return k.PublicKey().Type() }

func (b *keyringBackend) Key(_ keystore.Role, fp string) (keystore.CAKey, error) {
	signers, err := b.kr.Signers()
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		if ssh.FingerprintSHA256(s.PublicKey()) == fp {
			return keyringKey{s, b.custody}, nil
		}
	}
	return nil, errors.New("pinned CA key not present")
}

func (b *keyringBackend) Close() error { return nil }

// newKeyringBackend holds the fixture's role keys and extra private keys.
func newKeyringBackend(t *testing.T, fx *Fixture, extra ...sshagent.AddedKey) *keyringBackend {
	t.Helper()
	kr := sshagent.NewKeyring()
	for _, k := range fx.RolePriv {
		if err := kr.Add(sshagent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range extra {
		if err := kr.Add(k); err != nil {
			t.Fatal(err)
		}
	}
	return &keyringBackend{kr: kr, custody: keystore.CustodyAgent}
}

// provisioningBackend creates keys in place: it returns the fixture's role
// keys, or for dupRole the key of the role before it.
type provisioningBackend struct {
	*keyringBackend
	fx      *Fixture
	dupRole keystore.Role
}

func (b *provisioningBackend) Provision(roles []keystore.Role) (map[keystore.Role]ssh.PublicKey, error) {
	out := map[keystore.Role]ssh.PublicKey{}
	for i, r := range roles {
		src := r
		if r == b.dupRole && i > 0 {
			src = roles[i-1]
		}
		out[r] = b.fx.Roles[src].PublicKey()
	}
	return out, nil
}

func newStateDB(t *testing.T) *signerdb.DB {
	t.Helper()
	db, err := signerdb.Open(filepath.Join(t.TempDir(), "signer.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func leafCount(t *testing.T, db *signerdb.DB) int {
	t.Helper()
	hashes, err := db.LeafHashes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return len(hashes)
}

// wantUninitialised requires that nothing of ca-init reached db.
func wantUninitialised(t *testing.T, db *signerdb.DB) {
	t.Helper()
	ctx := context.Background()
	if _, err := db.CAKeys(ctx); !errors.Is(err, signerdb.ErrNotInitialised) {
		t.Errorf("CAKeys after the refusal: %v, want ErrNotInitialised", err)
	}
	if _, _, err := db.BackendConfig(ctx); !errors.Is(err, signerdb.ErrNotInitialised) {
		t.Errorf("BackendConfig after the refusal: %v, want ErrNotInitialised", err)
	}
	if n := leafCount(t, db); n != 0 {
		t.Errorf("%d log leaves after the refusal, want 0", n)
	}
}

// TestInitCARefusals (CA-01, CA-07, D-09): ca-init refuses every key set
// that is not five distinct usable keys, and writes nothing when it does.
func TestInitCARefusals(t *testing.T) {
	ctx := context.Background()
	fx := NewFixture(t, 1, 1)

	t.Run("duplicate_key_across_roles", func(t *testing.T) {
		for i, a := range initRoles {
			for _, b := range initRoles[i+1:] {
				t.Run(string(a)+"_"+string(b), func(t *testing.T) {
					db, sel := newStateDB(t), fx.Selection()
					sel[b] = sel[a]
					_, err := InitCA(ctx, db, newMemBackend(fx), "test", nil, sel, nil)
					if !errors.Is(err, ErrKeySelection) || !strings.Contains(err.Error(), "same key") {
						t.Fatalf("InitCA = %v, want the same-key refusal", err)
					}
					wantUninitialised(t, db)
				})
			}
		}
	})
	t.Run("missing_role", func(t *testing.T) {
		for _, role := range initRoles {
			t.Run(string(role), func(t *testing.T) {
				db, sel := newStateDB(t), fx.Selection()
				delete(sel, role)
				if _, err := InitCA(ctx, db, newMemBackend(fx), "test", nil, sel, nil); !errors.Is(err, ErrKeySelection) {
					t.Fatalf("InitCA = %v, want ErrKeySelection", err)
				}
				wantUninitialised(t, db)
			})
		}
	})
	t.Run("certificate_key", func(t *testing.T) {
		_, issuer := NewEd25519Key(t)
		c, err := cert.Build(cert.Request{
			Profile: cert.DefaultUserProfile(), Subject: fx.Roles[keystore.RoleUser].PublicKey(), Principals: []string{"x"},
			Now: time.Now(), ValidFor: time.Hour, Serial: 1,
			KeyID: cert.KeyID{CA: "user", Subject: "x", Request: strings.Repeat("0", 32), Serial: 1},
		}, issuer, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		be := newKeyringBackend(t, fx, sshagent.AddedKey{PrivateKey: fx.RolePriv[keystore.RoleUser], Certificate: c})
		db, sel := newStateDB(t), fx.Selection()
		sel[keystore.RoleUser] = ssh.FingerprintSHA256(c)
		if _, err := InitCA(ctx, db, be, "agent", nil, sel, nil); !errors.Is(err, cert.ErrCertificateKey) {
			t.Fatalf("InitCA with a certificate entry as the user CA = %v, want ErrCertificateKey", err)
		}
		wantUninitialised(t, db)
	})
	for _, alg := range []struct {
		name string
		key  func() (any, error)
	}{
		{"rsa_3072_key", func() (any, error) { return rsa.GenerateKey(rand.Reader, 3072) }},
		{"p384_key", func() (any, error) { return ecdsa.GenerateKey(elliptic.P384(), rand.Reader) }},
	} {
		t.Run(alg.name, func(t *testing.T) {
			priv, err := alg.key()
			if err != nil {
				t.Fatal(err)
			}
			s, err := ssh.NewSignerFromKey(priv)
			if err != nil {
				t.Fatal(err)
			}
			be := newKeyringBackend(t, fx, sshagent.AddedKey{PrivateKey: priv})
			for _, role := range []keystore.Role{keystore.RoleHost, keystore.RoleLog} {
				db, sel := newStateDB(t), fx.Selection()
				sel[role] = ssh.FingerprintSHA256(s.PublicKey())
				if _, err := InitCA(ctx, db, be, "agent", nil, sel, nil); !errors.Is(err, cert.ErrCAKeyAlgorithm) {
					t.Fatalf("InitCA with a %s %s key = %v, want ErrCAKeyAlgorithm", s.PublicKey().Type(), role, err)
				}
				wantUninitialised(t, db)
			}
		})
	}
	t.Run("unknown_role", func(t *testing.T) {
		db, sel := newStateDB(t), fx.Selection()
		sel["admin"] = sel[keystore.RoleUser]
		if _, err := InitCA(ctx, db, newMemBackend(fx), "test", nil, sel, nil); !errors.Is(err, ErrKeySelection) {
			t.Fatalf("InitCA = %v, want ErrKeySelection", err)
		}
		wantUninitialised(t, db)
	})
	t.Run("key_not_in_backend", func(t *testing.T) {
		db, sel := newStateDB(t), fx.Selection()
		_, other := NewEd25519Key(t)
		sel[keystore.RoleOps] = ssh.FingerprintSHA256(other.PublicKey())
		if _, err := InitCA(ctx, db, newMemBackend(fx), "test", nil, sel, nil); !errors.Is(err, ErrKeySelection) {
			t.Fatalf("InitCA = %v, want ErrKeySelection", err)
		}
		wantUninitialised(t, db)
	})
	t.Run("second_ca_init", func(t *testing.T) {
		db := newStateDB(t)
		if _, err := InitCA(ctx, db, newMemBackend(fx), "test", nil, fx.Selection(), nil); err != nil {
			t.Fatal(err)
		}
		other := NewFixture(t, 1, 1)
		if _, err := InitCA(ctx, db, newMemBackend(other), "test", nil, other.Selection(), nil); !errors.Is(err, ErrAlreadyInitialised) {
			t.Fatalf("second InitCA = %v, want ErrAlreadyInitialised", err)
		}
		if n := leafCount(t, db); n != 1 {
			t.Fatalf("%d leaves after the refused second ca-init, want the first ca_init only", n)
		}
	})
	t.Run("no_selection_without_provisioner", func(t *testing.T) {
		db := newStateDB(t)
		if _, err := InitCA(ctx, db, newMemBackend(fx), "test", nil, nil, nil); !errors.Is(err, ErrKeySelection) {
			t.Fatalf("InitCA = %v, want ErrKeySelection", err)
		}
		wantUninitialised(t, db)
	})
	t.Run("provisioner_same_key_twice", func(t *testing.T) {
		db := newStateDB(t)
		be := &provisioningBackend{keyringBackend: newKeyringBackend(t, fx), fx: fx, dupRole: keystore.RoleLog}
		if _, err := InitCA(ctx, db, be, "prov", nil, nil, nil); !errors.Is(err, ErrKeySelection) {
			t.Fatalf("InitCA = %v, want ErrKeySelection", err)
		}
		wantUninitialised(t, db)
	})
	t.Run("provisioner_creates_keys", func(t *testing.T) {
		db := newStateDB(t)
		be := &provisioningBackend{keyringBackend: newKeyringBackend(t, fx), fx: fx}
		cas, err := InitCA(ctx, db, be, "prov", nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if k, _ := cas.Key("log"); k.Key != trust.FormatKey(fx.Roles[keystore.RoleLog].PublicKey()) || k.Custody != "agent" {
			t.Fatalf("provisioned log key %+v", k)
		}
	})
}

// TestInitCAOrdering (CA-01 ordering): ca-pubkeys.json and the ca_init
// entry list the roles in the fixed order user, host, machine, ops, log,
// and the canonical document is byte-identical across runs.
func TestInitCAOrdering(t *testing.T) {
	fx := NewFixture(t, 1, 1)
	var docs [][]byte
	for range 2 {
		db := newStateDB(t)
		cas, err := InitCA(context.Background(), db, newMemBackend(fx), "test", map[string]string{"b": "2", "a": "1"}, fx.Selection(), nil)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := cas.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, doc)
		for i, k := range cas.Keys {
			if k.Role != trust.CAPubKeyRoles[i] {
				t.Fatalf("ca-pubkeys entry %d is %s, want %s", i, k.Role, trust.CAPubKeyRoles[i])
			}
		}
		var body *tlog.CAInitBody
		err = db.ForEachLeaf(context.Background(), func(_ uint64, raw []byte) error {
			l, err := tlog.DecodeLeaf(raw)
			if err != nil {
				return err
			}
			body, err = tlog.DecodeCAInitBody(l.Body)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		for i, k := range body.Keys {
			if k.Role != string(initRoles[i]) || k.Alg != ssh.KeyAlgoED25519 || k.Custody != "software" {
				t.Fatalf("ca_init key %d = %s/%s/%s", i, k.Role, k.Alg, k.Custody)
			}
		}
		name, opts, err := db.BackendConfig(context.Background())
		if err != nil || name != "test" || opts["a"] != "1" || opts["b"] != "2" {
			t.Fatalf("backend config %q %v %v", name, opts, err)
		}
	}
	if string(docs[0]) != string(docs[1]) {
		t.Fatalf("ca-pubkeys differs across runs:\n%s\n%s", docs[0], docs[1])
	}
}

// installEnv is an initialised state with a fixture.
type installEnv struct {
	fx  *Fixture
	db  *signerdb.DB
	be  *memBackend
	cas *trust.CAPubKeys
}

func newInstallEnv(t *testing.T, fx *Fixture) *installEnv {
	t.Helper()
	e := &installEnv{fx: fx, db: newStateDB(t), be: newMemBackend(fx)}
	var err error
	if e.cas, err = InitCA(context.Background(), e.db, e.be, "test", nil, fx.Selection(), nil); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *installEnv) install(pins []string, threshold int, docs [4][]byte) (*trust.Bundle, error) {
	return InstallBundle(context.Background(), e.db, e.be, pins, threshold, docs[0], docs[1], docs[2], docs[3], nil)
}

func docs4(t *testing.T, b *trust.Bundle, p *trust.Policy, signers ...ssh.Signer) [4][]byte {
	t.Helper()
	bd, bs, pd, ps := SignDocs(t, b, p, signers...)
	return [4][]byte{bd, bs, pd, ps}
}

// successor returns version prev.Version+1 of prev for pol: same roots,
// prev hash chained, issued a second later.
func successor(t *testing.T, prev *trust.Bundle, pol *trust.Policy) *trust.Bundle {
	t.Helper()
	pc, err := prev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	pd, err := pol.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	next := *prev
	next.Version = prev.Version + 1
	next.Prev = trust.SHA256Hex(pc)
	issued, err := time.Parse(trust.TimeFormat, prev.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	next.IssuedAt = issued.Add(time.Second).Format(trust.TimeFormat)
	next.PolicySHA256 = trust.SHA256Hex(pd)
	return &next
}

// policyV2 is the fixture policy at version 2, chained to version 1.
func policyV2(t *testing.T, fx *Fixture) *trust.Policy {
	t.Helper()
	v1, err := fx.Policy().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	p := fx.Policy()
	p.Version, p.Prev = 2, trust.SHA256Hex(v1)
	p.CAProfiles[0].MaxTTLSeconds = 8 * 3600
	return p
}

// TestInstallBundleRefusals (KEY-07, T-01-37, T-01-38): install-bundle
// refuses every bundle that is not anchored on the pinned roots (genesis)
// or the installed bundle (successor), or whose keys are not exactly the
// ca-init keys; a refusal stores nothing and logs no bundle_install entry.
func TestInstallBundleRefusals(t *testing.T) {
	type input struct {
		pins      []string
		threshold int
		docs      [4][]byte
	}
	fp := func(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }
	cases := []struct {
		name         string
		genesisFirst bool
		prepare      func(t *testing.T, e *installEnv) input
		want         error
	}{
		{"unpinned_root", false, func(t *testing.T, e *installEnv) input {
			_, other := NewEd25519Key(t)
			return input{[]string{fp(other)}, 1, docs4(t, e.fx.GenesisBundle(t, e.cas, e.fx.Policy()), e.fx.Policy(), e.fx.Root)}
		}, trust.ErrPins},
		{"self_signed_bundle", false, func(t *testing.T, e *installEnv) input {
			_, fresh := NewEd25519Key(t)
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.Root.Keys = []trust.RootKey{{Key: trust.FormatKey(fresh.PublicKey()), Custody: "software"}}
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, b, e.fx.Policy(), fresh)}
		}, trust.ErrPins},
		{"pins_differ_from_root_set", false, func(t *testing.T, e *installEnv) input {
			_, r2 := NewEd25519Key(t)
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.Root.Keys = append(b.Root.Keys, trust.RootKey{Key: trust.FormatKey(r2.PublicKey()), Custody: "software"})
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, b, e.fx.Policy(), e.fx.Root, r2)}
		}, trust.ErrPins},
		{"threshold_not_met", false, func(t *testing.T, e *installEnv) input {
			_, r2 := NewEd25519Key(t)
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.Root.Keys = append(b.Root.Keys, trust.RootKey{Key: trust.FormatKey(r2.PublicKey()), Custody: "software"})
			b.Root.Threshold = 2
			return input{[]string{e.fx.RootPin(), fp(r2)}, 2, docs4(t, b, e.fx.Policy(), e.fx.Root)}
		}, trust.ErrThreshold},
		{"bundle_swap", false, func(t *testing.T, e *installEnv) input {
			_, other := NewEd25519Key(t)
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.CAs[0].Key = trust.FormatKey(other.PublicKey())
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, b, e.fx.Policy(), e.fx.Root)}
		}, ErrBundleKeys},
		{"bundle_swap_roles_exchanged", false, func(t *testing.T, e *installEnv) input {
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.CAs[0].Key, b.CAs[1].Key = b.CAs[1].Key, b.CAs[0].Key // user and host CA swapped
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, b, e.fx.Policy(), e.fx.Root)}
		}, ErrBundleKeys},
		{"ops_key_swap", false, func(t *testing.T, e *installEnv) input {
			_, other := NewEd25519Key(t)
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.OpsKey.Key = trust.FormatKey(other.PublicKey())
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, b, e.fx.Policy(), e.fx.Root)}
		}, ErrBundleKeys},
		{"log_key_swap", false, func(t *testing.T, e *installEnv) input {
			_, other := NewEd25519Key(t)
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.Log.Key, b.Log.Origin = trust.FormatKey(other.PublicKey()), tlog.Origin(other.PublicKey())
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, b, e.fx.Policy(), e.fx.Root)}
		}, ErrBundleKeys},
		{"custody_differs", false, func(t *testing.T, e *installEnv) input {
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.CAs[1].Custody = "tpm"
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, b, e.fx.Policy(), e.fx.Root)}
		}, ErrBundleKeys},
		{"root_as_ca", false, func(t *testing.T, e *installEnv) input {
			userCA := e.fx.Roles[keystore.RoleUser]
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.Root.Keys = []trust.RootKey{{Key: trust.FormatKey(userCA.PublicKey()), Custody: "software"}}
			return input{[]string{fp(userCA)}, 1, docs4(t, b, e.fx.Policy(), userCA)}
		}, trust.ErrKeyIsRoot},
		{"root_as_log_key", false, func(t *testing.T, e *installEnv) input {
			logKey := e.fx.Roles[keystore.RoleLog]
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			b.Root.Keys = []trust.RootKey{{Key: trust.FormatKey(logKey.PublicKey()), Custody: "software"}}
			return input{[]string{fp(logKey)}, 1, docs4(t, b, e.fx.Policy(), logKey)}
		}, trust.ErrKeyIsRoot},
		{"policy_hash_mismatch", false, func(t *testing.T, e *installEnv) input {
			other := e.fx.Policy()
			other.CAProfiles[0].MaxTTLSeconds = 24 * 3600
			b := e.fx.GenesisBundle(t, e.cas, e.fx.Policy())
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, b, other, e.fx.Root)}
		}, trust.ErrPolicyHash},
		{"admin_is_online_key", false, func(t *testing.T, e *installEnv) input {
			pol := e.fx.Policy()
			pol.Admins[0].Key = trust.FormatKey(e.fx.Roles[keystore.RoleUser].PublicKey())
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, e.fx.GenesisBundle(t, e.cas, pol), pol, e.fx.Root)}
		}, ErrBundleKeys},
		// B-CR-01 (KEY-07): a root never authorizes issuance.
		{"admin_is_root", false, func(t *testing.T, e *installEnv) input {
			pol := e.fx.Policy()
			pol.Admins[0].Key = trust.FormatKey(e.fx.Root.PublicKey())
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, e.fx.GenesisBundle(t, e.cas, pol), pol, e.fx.Root)}
		}, trust.ErrKeyIsRoot},
		{"successor_admin_is_root", true, func(t *testing.T, e *installEnv) input {
			pol := policyV2(t, e.fx)
			pol.Admins = append(pol.Admins, trust.AdminKey{Name: "root", Key: trust.FormatKey(e.fx.Root.PublicKey())})
			return input{nil, 0, docs4(t, successor(t, e.genesis(t), pol), pol, e.fx.Root)}
		}, trust.ErrKeyIsRoot},
		{"version_not_increasing", true, func(t *testing.T, e *installEnv) input {
			return input{nil, 0, docs4(t, e.fx.GenesisBundle(t, e.cas, e.fx.Policy()), e.fx.Policy(), e.fx.Root)}
		}, trust.ErrVersionChain},
		{"successor_not_signed_by_previous", true, func(t *testing.T, e *installEnv) input {
			_, r2 := NewEd25519Key(t)
			pol := policyV2(t, e.fx)
			next := successor(t, e.genesis(t), pol)
			next.Root.Keys = []trust.RootKey{{Key: trust.FormatKey(r2.PublicKey()), Custody: "software"}}
			return input{nil, 0, docs4(t, next, pol, r2)}
		}, trust.ErrThreshold},
		// A-WR-02: a changed policy under the version in force (pol=1 would
		// name two policies) and one that does not chain to it.
		{"successor_policy_same_version", true, func(t *testing.T, e *installEnv) input {
			pol := e.fx.Policy()
			pol.CAProfiles[0].MaxTTLSeconds = 8 * 3600
			return input{nil, 0, docs4(t, successor(t, e.genesis(t), pol), pol, e.fx.Root)}
		}, trust.ErrVersionChain},
		{"successor_policy_unchained", true, func(t *testing.T, e *installEnv) input {
			pol := policyV2(t, e.fx)
			pol.Prev = trust.SHA256Hex([]byte("another policy"))
			return input{nil, 0, docs4(t, successor(t, e.genesis(t), pol), pol, e.fx.Root)}
		}, trust.ErrVersionChain},
		{"successor_with_pins", true, func(t *testing.T, e *installEnv) input {
			pol := policyV2(t, e.fx)
			return input{[]string{e.fx.RootPin()}, 1, docs4(t, successor(t, e.genesis(t), pol), pol, e.fx.Root)}
		}, ErrBundleInstall},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newInstallEnv(t, NewFixture(t, 1, 1))
			wantVersion := uint64(0)
			if tc.genesisFirst {
				e.installGenesis(t)
				wantVersion = 1
			}
			in := tc.prepare(t, e)
			leaves := leafCount(t, e.db)
			b, err := e.install(in.pins, in.threshold, in.docs)
			if err == nil || !errors.Is(err, tc.want) {
				var installed uint64
				if b != nil {
					installed = b.Version
				}
				t.Fatalf("InstallBundle = version %d, error %v; want %v", installed, err, tc.want)
			}
			if n := leafCount(t, e.db); n != leaves {
				t.Fatalf("%d leaves after the refusal, want %d (no bundle_install entry)", n, leaves)
			}
			latest, lerr := e.db.LatestBundle(context.Background())
			switch {
			case wantVersion == 0 && !errors.Is(lerr, signerdb.ErrNoBundle):
				t.Fatalf("LatestBundle after a refused genesis: %v, %v", latest, lerr)
			case wantVersion != 0 && (lerr != nil || latest.Version != wantVersion):
				t.Fatalf("LatestBundle after the refusal: %v, %v; want version %d", latest, lerr, wantVersion)
			}
		})
	}

	t.Run("not_initialised", func(t *testing.T) {
		fx := NewFixture(t, 1, 1)
		db := newStateDB(t)
		_, err := InstallBundle(context.Background(), db, newMemBackend(fx), []string{fx.RootPin()}, 1,
			[]byte("{}"), []byte("x"), []byte("{}"), []byte("x"), nil)
		if !errors.Is(err, ErrNotInitialised) {
			t.Fatalf("InstallBundle before ca-init = %v, want ErrNotInitialised", err)
		}
	})
	t.Run("valid_successor_accepted", func(t *testing.T) {
		e := newInstallEnv(t, NewFixture(t, 1, 1))
		e.installGenesis(t)
		pol := policyV2(t, e.fx)
		in := docs4(t, successor(t, e.genesis(t), pol), pol, e.fx.Root)
		b, err := e.install(nil, 0, in)
		if err != nil || b.Version != 2 {
			t.Fatalf("successor: %v, %v", b, err)
		}
		var last tlog.Leaf
		if err := e.db.ForEachLeaf(context.Background(), func(_ uint64, raw []byte) error {
			last, err = tlog.DecodeLeaf(raw)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		body, err := tlog.DecodeBundleInstallBody(last.Body)
		if last.Kind != tlog.KindBundleInstall || err != nil || body.BundleVersion != 2 ||
			string(body.Bundle) != string(in[0]) || string(body.BundleSigs) != string(in[1]) ||
			string(body.Policy) != string(in[2]) || string(body.PolicySigs) != string(in[3]) {
			t.Fatalf("last leaf %s does not record the installed documents (%v)", last.Kind, err)
		}
	})
}

// genesis returns the installed genesis bundle.
func (e *installEnv) genesis(t *testing.T) *trust.Bundle {
	t.Helper()
	sb, err := e.db.LatestBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(sb.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *installEnv) installGenesis(t *testing.T) {
	t.Helper()
	if _, err := e.install([]string{e.fx.RootPin()}, 1, docs4(t, e.fx.GenesisBundle(t, e.cas, e.fx.Policy()), e.fx.Policy(), e.fx.Root)); err != nil {
		t.Fatal(err)
	}
}

// custodyBackend reports custody for every key of an inner backend.
type custodyBackend struct {
	*memBackend
	custody keystore.Custody
}

func (b custodyBackend) Key(role keystore.Role, fp string) (keystore.CAKey, error) {
	k, err := b.memBackend.Key(role, fp)
	if err != nil {
		return nil, err
	}
	return keyringKey{k, b.custody}, nil
}

// TestStartRefusesCustodyMismatch (KEY-01): serve may override backend
// options, but the keys it then reaches must still carry the custody the
// root-signed bundle records.
func TestStartRefusesCustodyMismatch(t *testing.T) {
	fx := NewFixture(t, 1, 1)
	db := newStateDB(t)
	be := newMemBackend(fx) // custody software
	fx.Bootstrap(t, db, be, nil)
	t.Run("custody_mismatch_at_start", func(t *testing.T) {
		_, err := New(Config{Backend: custodyBackend{be, keystore.CustodyAgent}, DB: db, AllowUIDs: []uint32{1}})
		if !errors.Is(err, ErrBundleKeys) || !strings.Contains(err.Error(), "custody") {
			t.Fatalf("New with keys reporting another custody = %v, want ErrBundleKeys naming custody", err)
		}
	})
	t.Run("control_same_custody", func(t *testing.T) {
		if _, err := New(Config{Backend: be, DB: db, AllowUIDs: []uint32{1}}); err != nil {
			t.Fatal(err)
		}
	})
}

// TestStartRefusesRootAsAdmin (B-CR-01, KEY-07): a stored record whose
// policy lists a root as an admin, as an install-bundle without the check
// could have written, is refused at start, not served.
func TestStartRefusesRootAsAdmin(t *testing.T) {
	ctx := context.Background()
	fx := NewFixture(t, 1, 1)
	db := newStateDB(t)
	be := newMemBackend(fx)
	cas, err := InitCA(ctx, db, be, "test", map[string]string{}, fx.Selection(), nil)
	if err != nil {
		t.Fatal(err)
	}
	pol := fx.Policy()
	pol.Admins[0].Key = trust.FormatKey(fx.Root.PublicKey())
	bd, bs, pd, ps := SignDocs(t, fx.GenesisBundle(t, cas, pol), pol, fx.Root)

	// Write the rows and the log entry InstallBundle writes, without its
	// verification.
	caKeys, err := db.CAKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	logKey, err := openRoleKey(be, caKeys, "log")
	if err != nil {
		t.Fatal(err)
	}
	lw, err := newLogWriter(ctx, db, logKey, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := (&tlog.BundleInstallBody{BundleVersion: 1, Bundle: bd, BundleSigs: bs, Policy: pd, PolicySigs: ps}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := lw.logTx(ctx, func(tx *sql.Tx) error {
		if err := db.InsertBundle(tx, signerdb.StoredBundle{Version: 1, Bundle: bd, BundleSigs: bs, Policy: pd, PolicySigs: ps, InstalledAt: now}); err != nil {
			return err
		}
		_, err := lw.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindBundleInstall, Body: enc})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := New(Config{Backend: be, DB: db, AllowUIDs: []uint32{1}}); !errors.Is(err, trust.ErrKeyIsRoot) {
		t.Fatalf("New with a root as policy admin = %v, want trust.ErrKeyIsRoot", err)
	}
	// doctor runs the same check (B-CR-01 via C-WR-02).
	if err := CheckTrust(ctx, db); !errors.Is(err, trust.ErrKeyIsRoot) {
		t.Fatalf("CheckTrust with a root as policy admin = %v, want trust.ErrKeyIsRoot", err)
	}
}

// TestProfiles (CA-04, CA-05): every certificate follows its role's policy
// profile: the validity cap, the default extensions (user and machine:
// exactly permit-pty), extras only when the profile allows them, and host
// certificates without extensions.
func TestProfiles(t *testing.T) {
	fx := NewFixture(t, 1, 1)
	fx.PolicyEdit = func(p *trust.Policy) {
		p.CAProfiles[0].AllowedExtensions = []string{"permit-agent-forwarding", "permit-port-forwarding"}
	}
	e := newLogEnvFx(t, fx)
	issue := func(t *testing.T, edit func(r *wire.IssueRequest)) (*ssh.Certificate, error) {
		t.Helper()
		req := e.request()
		edit(req)
		req.Evidence = SignRequest(t, req, fx.Admins...)
		resp, err := e.s.Issue(context.Background(), Peer{UID: 1000}, req)
		if err != nil {
			return nil, err
		}
		pk, err := ssh.ParsePublicKey(resp.Cert)
		if err != nil {
			t.Fatal(err)
		}
		return pk.(*ssh.Certificate), nil
	}
	wantRefusal := func(t *testing.T, err error, reason string) {
		t.Helper()
		var r *refusal
		if !errors.As(err, &r) || r.reason != reason {
			t.Fatalf("err = %v, want %s", err, reason)
		}
	}
	extensions := func(c *ssh.Certificate) string {
		var names []string
		for k := range c.Extensions {
			names = append(names, k)
		}
		slices.Sort(names)
		return strings.Join(names, ",")
	}

	for _, tc := range []struct {
		role     wire.CARole
		maxTTL   uint32
		certType uint32
		ext      string
	}{
		{wire.CARoleUser, 12 * 3600, ssh.UserCert, "permit-pty"},
		{wire.CARoleHost, 720 * 3600, ssh.HostCert, ""},
		{wire.CARoleMachine, 24 * 3600, ssh.UserCert, "permit-pty"},
	} {
		t.Run(tc.role.String()+"_defaults", func(t *testing.T) {
			c, err := issue(t, func(r *wire.IssueRequest) { r.CARole, r.ValidForSeconds = tc.role, tc.maxTTL })
			if err != nil {
				t.Fatal(err)
			}
			if c.CertType != tc.certType || extensions(c) != tc.ext || len(c.CriticalOptions) != 0 {
				t.Fatalf("type %d, extensions %q, critical %v; want %d, %q, none", c.CertType, extensions(c), c.CriticalOptions, tc.certType, tc.ext)
			}
			if !strings.Contains(c.KeyId, "/pol=1/") {
				t.Fatalf("key ID %q lacks pol=1", c.KeyId)
			}
		})
		t.Run(tc.role.String()+"_ttl_above_role_max", func(t *testing.T) {
			_, err := issue(t, func(r *wire.IssueRequest) { r.CARole, r.ValidForSeconds = tc.role, tc.maxTTL+1 })
			wantRefusal(t, err, "bad_validity")
		})
	}
	t.Run("extension_allowed_by_role", func(t *testing.T) {
		c, err := issue(t, func(r *wire.IssueRequest) { r.Extensions = []string{"permit-port-forwarding"} })
		if err != nil {
			t.Fatal(err)
		}
		if got := extensions(c); got != "permit-port-forwarding,permit-pty" {
			t.Fatalf("extensions %q, want permit-port-forwarding,permit-pty", got)
		}
	})
	t.Run("extension_not_allowed_by_role", func(t *testing.T) {
		_, err := issue(t, func(r *wire.IssueRequest) { r.Extensions = []string{"permit-X11-forwarding"} })
		wantRefusal(t, err, "extension_not_allowed")
	})
	t.Run("extension_allowed_for_user_not_machine", func(t *testing.T) {
		_, err := issue(t, func(r *wire.IssueRequest) {
			r.CARole, r.Extensions = wire.CARoleMachine, []string{"permit-port-forwarding"}
		})
		wantRefusal(t, err, "extension_not_allowed")
	})
	t.Run("host_extension_refused", func(t *testing.T) {
		_, err := issue(t, func(r *wire.IssueRequest) { r.CARole, r.Extensions = wire.CARoleHost, []string{"permit-pty"} })
		wantRefusal(t, err, "extension_not_allowed")
	})
	t.Run("default_extension_requested_again", func(t *testing.T) {
		_, err := issue(t, func(r *wire.IssueRequest) { r.Extensions = []string{"permit-pty"} })
		wantRefusal(t, err, "extension_not_allowed")
	})
	t.Run("duplicate_extension", func(t *testing.T) {
		_, err := issue(t, func(r *wire.IssueRequest) {
			r.Extensions = []string{"permit-port-forwarding", "permit-port-forwarding"}
		})
		wantRefusal(t, err, "duplicate_extension")
	})
	t.Run("profile_for_unknown_role", func(t *testing.T) {
		if _, err := profileFor("admin", fx.Policy()); err == nil {
			t.Fatal("profileFor accepted an unknown role")
		}
	})
}
