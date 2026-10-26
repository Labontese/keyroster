//go:build e2edistro && linux

package distro

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// The signed world of the distro tests: the same documents and signing
// code as internal/agent/apply's harness and the e2e suite, made inside
// the container (the state directory and pins must belong to its root,
// and the directory names the container's own sshd host key). Keys come
// from fixed seeds.
const installation = "0123456789abcdef0123456789abcdef"

func seedKey(t testing.TB, n byte) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// world is one installation: roots, CAs, ops and admin keys, the genesis
// bundle and policy, and the directory versions published so far.
type world struct {
	t                                  testing.TB
	root, admin, user, host, mach, ops ssh.Signer
	log                                ssh.Signer
	bundle                             *trust.Bundle
	bundleDoc, bundleSigs              []byte
	policyDoc, policySigs              []byte
	dirs                               []spool.Doc
}

func newWorld(t testing.TB, popHosts bool) *world {
	t.Helper()
	w := &world{t: t, root: seedKey(t, 1), admin: seedKey(t, 2), user: seedKey(t, 3), host: seedKey(t, 4), mach: seedKey(t, 5), ops: seedKey(t, 6), log: seedKey(t, 7)}
	key := func(s ssh.Signer) string { return trust.FormatKey(s.PublicKey()) }
	policy := &trust.Policy{
		Version: 1, Prev: trust.GenesisPrev, AdminQuorum: 1,
		Admins: []trust.AdminKey{{Name: "alice", Key: key(w.admin)}},
		CAProfiles: []trust.CAProfile{
			{Role: trust.RoleUser, MaxTTLSeconds: 43200, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleHost, MaxTTLSeconds: 2592000, DefaultExtensions: []string{}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleMachine, MaxTTLSeconds: 86400, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
		},
	}
	if popHosts {
		policy.PoP = &trust.PoPPolicy{Hosts: true}
	}
	w.policyDoc = w.canonical(policy)
	w.policySigs = w.sign(w.root, trust.NamespacePolicy, w.policyDoc)
	ca := func(role string, s ssh.Signer) trust.CAEntry {
		return trust.CAEntry{Role: role, Key: key(s), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "active", Generation: 1}
	}
	w.bundle = &trust.Bundle{
		Version: 1, Prev: trust.GenesisPrev, IssuedAt: "2026-10-01T00:00:00Z",
		Root:           trust.RootSet{Keys: []trust.RootKey{{Key: key(w.root), Custody: "software"}}, Threshold: 1},
		CAs:            []trust.CAEntry{ca(trust.RoleUser, w.user), ca(trust.RoleHost, w.host), ca(trust.RoleMachine, w.mach)},
		OpsKey:         trust.KeyEntry{Key: key(w.ops), Alg: ssh.KeyAlgoED25519, Custody: "software"},
		Log:            trust.LogEntry{Key: key(w.log), Alg: ssh.KeyAlgoED25519, Custody: "software", Origin: trust.LogOrigin(w.log.PublicKey())},
		PolicySHA256:   trust.SHA256Hex(w.policyDoc),
		InstallationID: installation,
	}
	w.bundleDoc = w.canonical(w.bundle)
	if _, err := trust.ParseBundle(w.bundleDoc); err != nil {
		t.Fatalf("world bundle: %v", err)
	}
	w.bundleSigs = w.sign(w.root, trust.NamespaceBundle, w.bundleDoc)
	return w
}

func (w *world) canonical(v any) []byte {
	w.t.Helper()
	b, err := trust.CanonicalJSON(v)
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

func (w *world) sign(s ssh.Signer, namespace string, doc []byte) []byte {
	w.t.Helper()
	sig, err := sshsig.Sign(rand.Reader, s, namespace, doc)
	if err != nil {
		w.t.Fatal(err)
	}
	return sig
}

func (w *world) pins() *state.Pins {
	return &state.Pins{TrustPins: []string{ssh.FingerprintSHA256(w.root.PublicKey())}, Threshold: 1, InstallationID: installation}
}

// publish signs the next directory version: role ops grants principals,
// host group lab maps account to ops, and host web1 has hostKey.
func (w *world) publish(account string, hostKey ssh.PublicKey, principals ...string) spool.Doc {
	w.t.Helper()
	d := &directory.Directory{Version: 1, Prev: trust.GenesisPrev, Users: []directory.User{}, Groups: []directory.Group{},
		Roles:          []directory.Role{{Name: "ops", Principals: principals, MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{}, Groups: []string{}}},
		HostGroups:     []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: account, Roles: []string{"ops"}}}}},
		Hosts:          []directory.Host{{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(hostKey)}, Principals: []string{"web1"}, Status: directory.StatusActive}},
		InstallationID: installation,
	}
	if n := len(w.dirs); n > 0 {
		prev := w.dirs[n-1].Body
		p, err := directory.Parse(prev)
		if err != nil {
			w.t.Fatal(err)
		}
		d.Version, d.Prev = p.Version+1, trust.SHA256Hex(prev)
	}
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := directory.Parse(doc); err != nil {
		w.t.Fatalf("world directory: %v", err)
	}
	sd := spool.Doc{Body: doc, Sigs: w.sign(w.admin, directory.Namespace, doc)}
	w.dirs = append(w.dirs, sd)
	return sd
}

// spoolState is the genesis bundle and policy and every directory version
// published.
func (w *world) spoolState() spool.State {
	s := spool.State{
		Bundles:     map[uint64]spool.Doc{1: {Body: w.bundleDoc, Sigs: w.bundleSigs}},
		Policies:    map[uint64]spool.Doc{1: {Body: w.policyDoc, Sigs: w.policySigs}},
		Directories: map[uint64]spool.Doc{},
		KRLs:        map[uint64]spool.KRLFiles{},
	}
	for i, d := range w.dirs {
		s.Directories[uint64(i+1)] = d //nolint:gosec // G115: a small test index
	}
	return s
}

// lastDirectory is the newest published directory, parsed.
func (w *world) lastDirectory() *directory.Directory {
	w.t.Helper()
	d, err := directory.Parse(w.dirs[len(w.dirs)-1].Body)
	if err != nil {
		w.t.Fatal(err)
	}
	return d
}

// caLine is the Phase 2 runbook's keyroster_user_ca.pub: the active user
// CA key with keyroster host ca-key's comment.
func (w *world) caLine() string {
	return fmt.Sprintf("%s keyroster user CA (bundle v%d)\n", trust.FormatKey(w.user.PublicKey()), w.bundle.Version)
}

// userCert is a signer holding a fresh key and a user certificate for it
// from the world's user CA, through internal/cert.Build (the signer's one
// SignCert call site), with principals.
func (w *world) userCert(serial uint64, principals ...string) ssh.Signer {
	w.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		w.t.Fatal(err)
	}
	subject, err := ssh.NewPublicKey(pub)
	if err != nil {
		w.t.Fatal(err)
	}
	kid := cert.KeyID{CA: "user", Subject: "alice", Request: strings.Repeat(fmt.Sprintf("%02x", byte(serial)), 16), Policy: 1, Serial: serial}
	c, err := cert.Build(cert.Request{Profile: cert.DefaultUserProfile(), Subject: subject, Principals: principals,
		Now: time.Now().Add(-time.Minute), ValidFor: time.Hour, KeyID: kid, Serial: serial}, w.user, rand.Reader)
	if err != nil {
		w.t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		w.t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(c, key)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}
