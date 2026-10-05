package signer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// Fixture is a complete software trust setup for tests in this package and
// in signer_test: five role keys, one root key and the admin keys, all
// Ed25519 and generated fresh. Tests use real SSHSIG signatures throughout;
// nothing here shortcuts verification.
type Fixture struct {
	RolePriv  map[keystore.Role]ed25519.PrivateKey
	Roles     map[keystore.Role]ssh.Signer
	Root      ssh.Signer
	AdminPriv []ed25519.PrivateKey
	Admins    []ssh.Signer
	Quorum    uint32
}

// NewFixture generates the keys; quorum is the policy's admin quorum.
func NewFixture(t testing.TB, admins int, quorum uint32) *Fixture {
	t.Helper()
	f := &Fixture{RolePriv: map[keystore.Role]ed25519.PrivateKey{}, Roles: map[keystore.Role]ssh.Signer{}, Quorum: quorum}
	for _, role := range initRoles {
		f.RolePriv[role], f.Roles[role] = NewEd25519Key(t)
	}
	_, f.Root = NewEd25519Key(t)
	for range admins {
		priv, s := NewEd25519Key(t)
		f.AdminPriv = append(f.AdminPriv, priv)
		f.Admins = append(f.Admins, s)
	}
	return f
}

// NewEd25519Key returns a fresh Ed25519 key and its signer.
func NewEd25519Key(t testing.TB) (ed25519.PrivateKey, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, s
}

// Selection returns the role fingerprints for InitCA.
func (f *Fixture) Selection() map[keystore.Role]string {
	sel := map[keystore.Role]string{}
	for role, s := range f.Roles {
		sel[role] = ssh.FingerprintSHA256(s.PublicKey())
	}
	return sel
}

// RootPin returns the root key's fingerprint.
func (f *Fixture) RootPin() string { return ssh.FingerprintSHA256(f.Root.PublicKey()) }

// Policy returns the genesis policy: the fixture's admins and quorum, user
// certificates up to 12 h with permit-pty, host certificates up to 720 h
// without extensions, machine certificates up to 24 h with permit-pty.
func (f *Fixture) Policy() *trust.Policy {
	p := &trust.Policy{Version: 1, Prev: trust.GenesisPrev, AdminQuorum: f.Quorum, Admins: []trust.AdminKey{}}
	for i, a := range f.Admins {
		p.Admins = append(p.Admins, trust.AdminKey{Name: "admin" + string(rune('a'+i)), Key: trust.FormatKey(a.PublicKey())})
	}
	for _, prof := range []struct {
		role string
		ttl  uint64
		ext  []string
	}{{trust.RoleUser, 12 * 3600, []string{"permit-pty"}}, {trust.RoleHost, 720 * 3600, []string{}}, {trust.RoleMachine, 24 * 3600, []string{"permit-pty"}}} {
		p.CAProfiles = append(p.CAProfiles, trust.CAProfile{Role: prof.role, MaxTTLSeconds: prof.ttl,
			DefaultExtensions: prof.ext, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}})
	}
	return p
}

// GenesisBundle returns the version 1 bundle for cas (as InitCA returned
// them), the fixture's root at threshold 1, and pol.
func (f *Fixture) GenesisBundle(t testing.TB, cas *trust.CAPubKeys, pol *trust.Policy) *trust.Bundle {
	t.Helper()
	polDoc, err := pol.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b := &trust.Bundle{
		Version: 1, Prev: trust.GenesisPrev, IssuedAt: time.Now().UTC().Truncate(time.Second).Format(trust.TimeFormat),
		Root:         trust.RootSet{Keys: []trust.RootKey{{Key: trust.FormatKey(f.Root.PublicKey()), Custody: "software"}}, Threshold: 1},
		CAs:          []trust.CAEntry{},
		PolicySHA256: trust.SHA256Hex(polDoc),
	}
	for _, role := range []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine} {
		k, _ := cas.Key(role)
		b.CAs = append(b.CAs, trust.CAEntry{Role: role, Key: k.Key, Alg: k.Alg, Custody: k.Custody, State: "active", Generation: 1})
	}
	ops, _ := cas.Key("ops")
	b.OpsKey = trust.KeyEntry{Key: ops.Key, Alg: ops.Alg, Custody: ops.Custody}
	lg, _ := cas.Key("log")
	logPub, err := trust.ParseKey(lg.Key)
	if err != nil {
		t.Fatal(err)
	}
	b.Log = trust.LogEntry{Key: lg.Key, Alg: lg.Alg, Custody: lg.Custody, Origin: tlog.Origin(logPub)}
	return b
}

// SignDocs returns the canonical bundle and policy with detached SSHSIG
// signatures by every signer under the bundle and policy namespaces.
func SignDocs(t testing.TB, b *trust.Bundle, pol *trust.Policy, signers ...ssh.Signer) (bundle, bundleSigs, policy, policySigs []byte) {
	t.Helper()
	var err error
	if bundle, err = b.Canonical(); err != nil {
		t.Fatal(err)
	}
	if policy, err = pol.Canonical(); err != nil {
		t.Fatal(err)
	}
	for _, s := range signers {
		bs, err := sshsig.Sign(rand.Reader, s, trust.NamespaceBundle, bundle)
		if err != nil {
			t.Fatal(err)
		}
		ps, err := sshsig.Sign(rand.Reader, s, trust.NamespacePolicy, policy)
		if err != nil {
			t.Fatal(err)
		}
		bundleSigs, policySigs = append(bundleSigs, bs...), append(policySigs, ps...)
	}
	return bundle, bundleSigs, policy, policySigs
}

// Bootstrap runs InitCA with the fixture's keys from be and installs the
// root-signed genesis bundle and policy, as ca-init and install-bundle do.
// It returns the keys InitCA reported.
func (f *Fixture) Bootstrap(t testing.TB, db *signerdb.DB, be keystore.Backend, clock serial.Clock) *trust.CAPubKeys {
	t.Helper()
	ctx := context.Background()
	cas, err := InitCA(ctx, db, be, "test", map[string]string{}, f.Selection(), clock)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	b, bs, p, ps := SignDocs(t, f.GenesisBundle(t, cas, f.Policy()), f.Policy(), f.Root)
	if _, err := InstallBundle(ctx, db, be, []string{f.RootPin()}, 1, b, bs, p, ps, clock); err != nil {
		t.Fatalf("InstallBundle: %v", err)
	}
	return cas
}

// SignRequest returns req's admin-sshsig/v1 evidence by each signer.
func SignRequest(t testing.TB, req *wire.IssueRequest, signers ...ssh.Signer) []wire.Evidence {
	t.Helper()
	var ev []wire.Evidence
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, wire.AdminSSHSIGNamespace, req.SigningBytes())
		if err != nil {
			t.Fatal(err)
		}
		ev = append(ev, wire.Evidence{Type: wire.EvidenceAdminSSHSIG, Blob: sig})
	}
	return ev
}
