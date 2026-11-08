//go:build linux

package apply

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	probecert "github.com/Labontese/keyroster/internal/agent/probe"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	certpkg "github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestMain fixes the umask: readTrusted refuses a configuration file or
// directory writable by group or others (PR #68 review D-R3), so the
// fixtures' modes must not depend on the caller's umask.
func TestMain(m *testing.M) {
	unix.Umask(0o022)
	os.Exit(m.Run())
}

// Test fixture keys: deterministic Ed25519 keys from a seed byte.
func seedKey(t testing.TB, n byte) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const testInstallation = "0123456789abcdef0123456789abcdef"

// fixture is a signed world: root, CA, ops and admin keys, a genesis
// bundle and policy bound to testInstallation, and helpers that sign
// directories and KRLs the way the signer does.
type fixture struct {
	t                                  testing.TB
	root, admin, user, host, mach, ops ssh.Signer
	log                                ssh.Signer
	bundle                             *trust.Bundle
	policy                             *trust.Policy
	bundleDoc, bundleSigs              []byte
	policyDoc, policySigs              []byte
	krlVersion                         uint64
	// krlHostSerials are host-CA serials every later KRL also revokes
	// (03-09).
	krlHostSerials []uint64
	// krlMachSerials are machine-CA serials every later KRL also revokes:
	// negative probe certificates (03-10b).
	krlMachSerials []uint64
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{t: t, root: seedKey(t, 1), admin: seedKey(t, 2), user: seedKey(t, 3), host: seedKey(t, 4), mach: seedKey(t, 5), ops: seedKey(t, 6), log: seedKey(t, 7), krlVersion: 1793000000}
	key := func(s ssh.Signer) string { return trust.FormatKey(s.PublicKey()) }
	f.policy = &trust.Policy{
		Version: 1, Prev: trust.GenesisPrev, AdminQuorum: 1,
		Admins: []trust.AdminKey{{Name: "alice", Key: key(f.admin)}},
		CAProfiles: []trust.CAProfile{
			{Role: trust.RoleUser, MaxTTLSeconds: 43200, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleHost, MaxTTLSeconds: 2592000, DefaultExtensions: []string{}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleMachine, MaxTTLSeconds: 86400, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
		},
		PoP: &trust.PoPPolicy{Hosts: true},
	}
	f.policyDoc = mustCanonical(t, f.policy)
	f.policySigs = f.rootSign(trust.NamespacePolicy, f.policyDoc)
	ca := func(role string, s ssh.Signer) trust.CAEntry {
		return trust.CAEntry{Role: role, Key: key(s), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "active", Generation: 1}
	}
	f.bundle = &trust.Bundle{
		Version: 1, Prev: trust.GenesisPrev, IssuedAt: "2026-10-01T00:00:00Z",
		Root:           trust.RootSet{Keys: []trust.RootKey{{Key: key(f.root), Custody: "software"}}, Threshold: 1},
		CAs:            []trust.CAEntry{ca(trust.RoleUser, f.user), ca(trust.RoleHost, f.host), ca(trust.RoleMachine, f.mach)},
		OpsKey:         trust.KeyEntry{Key: key(f.ops), Alg: ssh.KeyAlgoED25519, Custody: "software"},
		Log:            trust.LogEntry{Key: key(f.log), Alg: ssh.KeyAlgoED25519, Custody: "software", Origin: trust.LogOrigin(f.log.PublicKey())},
		PolicySHA256:   trust.SHA256Hex(f.policyDoc),
		InstallationID: testInstallation,
	}
	f.bundleDoc = mustCanonical(t, f.bundle)
	if _, err := trust.ParseBundle(f.bundleDoc); err != nil {
		t.Fatalf("fixture bundle: %v", err)
	}
	f.bundleSigs = f.rootSign(trust.NamespaceBundle, f.bundleDoc)
	return f
}

func mustCanonical(t testing.TB, v any) []byte {
	t.Helper()
	b, err := trust.CanonicalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) rootSign(namespace string, doc []byte) []byte {
	sig, err := sshsig.Sign(rand.Reader, f.root, namespace, doc)
	if err != nil {
		f.t.Fatal(err)
	}
	return sig
}

func (f *fixture) pins() *state.Pins {
	return &state.Pins{TrustPins: []string{ssh.FingerprintSHA256(f.root.PublicKey())}, Threshold: 1, InstallationID: testInstallation}
}

// dirSpec describes one directory version of the tests: the principals of
// role ops, the accounts of host group lab mapped to it, and host web1
// with the given host keys and status.
type dirSpec struct {
	principals []string
	accounts   []string
	hostKeys   []ssh.PublicKey
	status     string
	install    string // installation ID; "" means testInstallation
	extraHost  *directory.Host
	// bulkRoles adds that many roles of 32 principals of 128 characters
	// each, mapped to every account (a valid directory whose principals
	// files exceed the generation read cap).
	bulkRoles int
	// signer signs the directory; nil is the fixture's admin.
	signer ssh.Signer
	// noHost leaves host web1 out of the directory.
	noHost bool
	// bare are more accounts of host group lab, mapped to no role: their
	// principals files hold the header alone.
	bare []string
}

// directory signs one version after prev (nil: version 1).
func (f *fixture) directory(prev []byte, s dirSpec) spool.Doc {
	f.t.Helper()
	if s.status == "" {
		s.status = directory.StatusActive
	}
	if s.install == "" {
		s.install = testInstallation
	}
	var keys []string
	for _, k := range s.hostKeys {
		keys = append(keys, trust.FormatKey(k))
	}
	roles := []directory.Role{{Name: "ops", Principals: s.principals, MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{}, Groups: []string{}}}
	names := []string{"ops"}
	for i := range s.bulkRoles {
		r := directory.Role{Name: fmt.Sprintf("bulk%02d", i), MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{}, Groups: []string{}}
		for j := range directory.MaxRolePrincipals {
			p := fmt.Sprintf("bulk%02d-%02d-", i, j)
			r.Principals = append(r.Principals, p+strings.Repeat("x", 128-len(p)))
		}
		roles = append(roles, r)
		names = append(names, r.Name)
	}
	var accounts []directory.AccountMap
	for _, a := range s.accounts {
		accounts = append(accounts, directory.AccountMap{Account: a, Roles: names})
	}
	for _, a := range s.bare {
		accounts = append(accounts, directory.AccountMap{Account: a, Roles: []string{}})
	}
	d := &directory.Directory{Version: 1, Prev: trust.GenesisPrev, Users: []directory.User{}, Groups: []directory.Group{},
		Roles:          roles,
		HostGroups:     []directory.HostGroup{{Name: "lab", Accounts: accounts}},
		Hosts:          []directory.Host{{Name: "web1", HostGroup: "lab", Keys: keys, Principals: []string{"web1"}, Status: s.status}},
		InstallationID: s.install,
	}
	if s.noHost {
		d.Hosts = nil
	}
	if s.extraHost != nil {
		d.Hosts = append(d.Hosts, *s.extraHost)
	}
	if prev != nil {
		p, err := directory.Parse(prev)
		if err != nil {
			f.t.Fatal(err)
		}
		d.Version, d.Prev = p.Version+1, trust.SHA256Hex(prev)
	}
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := directory.Parse(doc); err != nil {
		f.t.Fatalf("test directory: %v", err)
	}
	signer := f.admin
	if s.signer != nil {
		signer = s.signer
	}
	sig, err := sshsig.Sign(rand.Reader, signer, directory.Namespace, doc)
	if err != nil {
		f.t.Fatal(err)
	}
	return spool.Doc{Body: doc, Sigs: sig}
}

// krl publishes the next KRL version revoking serials of the user CA and
// keys explicitly, signed by the ops key for installation id ("" means
// testInstallation).
func (f *fixture) krl(serials []uint64, keys []ssh.PublicKey, id string) (uint64, spool.KRLFiles) {
	f.t.Helper()
	return f.krlWithHeader(serials, keys, id, 0)
}

// krlWithHeader is krl with the KRL's own header krl_version set to header
// instead of the manifest's version (0: the same).
func (f *fixture) krlWithHeader(serials []uint64, keys []ssh.PublicKey, id string, header uint64) (uint64, spool.KRLFiles) {
	f.t.Helper()
	if id == "" {
		id = testInstallation
	}
	f.krlVersion++
	if header == 0 {
		header = f.krlVersion
	}
	set := krl.Set{Keys: keys}
	if len(serials) > 0 {
		set.Certs = []krl.CertSection{{CAKey: f.user.PublicKey(), Serials: serials}}
	}
	if len(f.krlHostSerials) > 0 {
		set.Certs = append(set.Certs, krl.CertSection{CAKey: f.host.PublicKey(), Serials: f.krlHostSerials})
	}
	if len(f.krlMachSerials) > 0 {
		set.Certs = append(set.Certs, krl.CertSection{CAKey: f.mach.PublicKey(), Serials: f.krlMachSerials})
	}
	b, err := krl.Encode(set, header, time.Unix(int64(f.krlVersion), 0)) //nolint:gosec // G115: a test version
	if err != nil {
		f.t.Fatal(err)
	}
	m := &krl.Manifest{InstallationID: id, KRLVersion: f.krlVersion, KRLSHA256: krl.SHA256Hex(b), IssuedAt: "2026-10-01T00:00:00Z", BundleVersion: 1, LogIndex: 3}
	doc, err := m.Canonical()
	if err != nil {
		f.t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, f.ops, krl.Namespace, doc)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.krlVersion, spool.KRLFiles{KRL: b, Manifest: doc, Sig: sig}
}

// genesis is a spool state with the genesis bundle and policy.
func (f *fixture) genesis() spool.State {
	return spool.State{
		Bundles:     map[uint64]spool.Doc{1: {Body: f.bundleDoc, Sigs: f.bundleSigs}},
		Policies:    map[uint64]spool.Doc{1: {Body: f.policyDoc, Sigs: f.policySigs}},
		Directories: map[uint64]spool.Doc{},
		KRLs:        map[uint64]spool.KRLFiles{},
	}
}

// fakeClock is CLOCK_MONOTONIC and wall time that only Sleep advances.
type fakeClock struct {
	mu      sync.Mutex
	boot    string
	elapsed time.Duration
	wall    time.Time
	onSleep func(d time.Duration)
}

func newFakeClock() *fakeClock {
	return &fakeClock{boot: "boot-1", elapsed: time.Hour, wall: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Monotonic() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.elapsed
}

func (c *fakeClock) BootID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.boot
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

func (c *fakeClock) Sleep(_ context.Context, d time.Duration) error {
	c.advance(d)
	c.mu.Lock()
	hook := c.onSleep
	c.mu.Unlock()
	if hook != nil {
		hook(d)
	}
	return nil
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.elapsed += d
	c.wall = c.wall.Add(d)
}

// fakeSSHD is an in-process SSH server on a loopback port, with the
// host's key, that completes key exchange and nothing else; stall makes
// it accept and never answer, stop closes it.
//
// It models sshd's host certificates (03-09) as documented and as
// upstream servconf.c and sshd.c behave (UNVERIFIED against real sshd
// beyond the e2e's two algorithms): at every reload, never at a write, it
// re-reads the drop-in on disk and the files its HostCertificate lines
// name, and serves, for each certificate algorithm, the certificate of
// the first host key in HostKey order that has one of that type; a key
// without one is served plainly, the first key of each plain algorithm.
type fakeSSHD struct {
	ln       net.Listener
	port     int
	keyPath  string // private key path as sshd -T names it; keyPath.pub holds the public key
	pub      ssh.PublicKey
	mu       sync.Mutex
	stall    bool
	accepted int
	dir      string
	// keys are the host keys in HostKey order, the first keyPath's; cfg
	// is what the server serves now; forced, set by serveCert, is served
	// for its algorithm whatever the drop-in names; reloadDelay delays
	// what a reload serves.
	keys        []fakeHostKey
	cfg         *ssh.ServerConfig
	forced      *ssh.Certificate
	reloadDelay time.Duration
	served      []*ssh.Certificate // the certificates the last reload loaded
}

// fakeHostKey is one host key of the fake sshd: its private key path and
// signer.
type fakeHostKey struct {
	path   string
	signer ssh.Signer
}

func startFakeSSHD(t *testing.T) *fakeSSHD {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s := &fakeSSHD{ln: ln, port: ln.Addr().(*net.TCPAddr).Port, keyPath: filepath.Join(dir, "ssh_host_ed25519_key"), pub: signer.PublicKey()}
	// sshd skips a HostKey whose private key is missing, and so does
	// hostKeys: the fixture writes both halves, the private key in
	// OpenSSH format (enrollment signs with it, 03-07).
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.keyPath+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	s.dir, s.cfg = dir, cfg
	s.keys = []fakeHostKey{{path: s.keyPath, signer: signer}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.accepted++
			stall := s.stall
			cfg := s.cfg
			s.mu.Unlock()
			go func() {
				defer func() { _ = c.Close() }()
				if stall {
					time.Sleep(5 * time.Second)
					return
				}
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeSSHD) setStall(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stall = v
}

func (s *fakeSSHD) stop() { _ = s.ln.Close() }

// addHostKey writes a new host key of kind (ed25519, ecdsa or rsa) beside
// the first, both halves, appends it to the HostKey order and returns its
// signer and path. sshd -T lists it only through fakeRunner.extraHostKeys.
func (s *fakeSSHD) addHostKey(t *testing.T, kind string) (ssh.Signer, string) {
	t.Helper()
	priv := cachedHostKey(t, kind, len(s.keys))
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	path := filepath.Join(s.dir, fmt.Sprintf("ssh_host_%s_key_%d", kind, len(s.keys)))
	s.keys = append(s.keys, fakeHostKey{path: path, signer: signer})
	s.mu.Unlock()
	block, err := ssh.MarshalPrivateKey(priv.(crypto.PrivateKey), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return signer, path
}

// hostKeyCache holds the extra host keys, generated once per kind and
// position (an RSA key under -race is slow; every host may share them).
var hostKeyCache sync.Map

func cachedHostKey(t *testing.T, kind string, pos int) any {
	t.Helper()
	key := fmt.Sprintf("%s/%d", kind, pos)
	if v, ok := hostKeyCache.Load(key); ok {
		return v
	}
	var priv any
	var err error
	switch kind {
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("host key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	v, _ := hostKeyCache.LoadOrStore(key, priv)
	return v
}

// reload is sshd's reload (SIGHUP): it reads the drop-in on disk (none
// with noInclude) and the certificate files its HostCertificate lines
// name, and serves them, after reloadDelay when one is set.
func (s *fakeSSHD) reload(l Layout, noInclude bool) {
	var certs []*ssh.Certificate
	if b, err := os.ReadFile(l.DropIn()); err == nil && !noInclude {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) != 2 || strings.ToLower(f[0]) != "hostcertificate" {
				continue
			}
			raw, err := os.ReadFile(f[1]) //nolint:gosec // a path the drop-in names
			if err != nil {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
			if c, ok := pub.(*ssh.Certificate); err == nil && ok {
				certs = append(certs, c)
			}
		}
	}
	s.mu.Lock()
	delay := s.reloadDelay
	s.mu.Unlock()
	apply := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.served = certs
		s.cfg = s.buildLocked(certs)
	}
	if delay > 0 {
		time.AfterFunc(delay, apply)
		return
	}
	apply()
}

// serveCert makes the fake serve c for its algorithm from now on,
// whatever the drop-in names (a wrong certificate, 03-09); nil undoes it.
func (s *fakeSSHD) serveCert(c *ssh.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forced = c
	s.cfg = s.buildLocked(s.served)
}

// buildLocked is the server configuration for certs: per certificate
// algorithm the first key in HostKey order with a certificate of that
// type (forced first), then each key's plain algorithm, first key first.
func (s *fakeSSHD) buildLocked(certs []*ssh.Certificate) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	have := map[string]bool{}
	signerFor := func(c *ssh.Certificate) ssh.Signer {
		for _, k := range s.keys {
			if bytes.Equal(k.signer.PublicKey().Marshal(), c.Key.Marshal()) {
				return k.signer
			}
		}
		return nil
	}
	if f := s.forced; f != nil {
		if k := signerFor(f); k != nil {
			if cs, err := ssh.NewCertSigner(f, k); err == nil {
				cfg.AddHostKey(cs)
				have[f.Type()] = true
			}
		}
	}
	for _, k := range s.keys {
		for _, c := range certs {
			if !bytes.Equal(c.Key.Marshal(), k.signer.PublicKey().Marshal()) || have[c.Type()] {
				continue
			}
			if cs, err := ssh.NewCertSigner(c, k.signer); err == nil {
				cfg.AddHostKey(cs)
				have[c.Type()] = true
			}
		}
	}
	for _, k := range s.keys {
		if t := k.signer.PublicKey().Type(); !have[t] {
			cfg.AddHostKey(k.signer)
			have[t] = true
		}
	}
	return cfg
}

// fakeRunner answers the applier's exec sites by binary and flags,
// running nothing.
type fakeRunner struct {
	mu          sync.Mutex
	h           *testHost
	calls       []string
	reloads     int
	grace       string // logingracetime sshd -T reports
	listen      []string
	sshdTestErr string
	// rejectDropIn makes sshd -t and sshd -T fail, as a real sshd does
	// for a configuration line it refuses, while the drop-in on disk
	// makes it true (PR #68 carry-over).
	rejectDropIn func(dropIn []byte) bool
	rejectCA     func(line string) bool
	onQuery      func()
	queryCode    int
	// extraHostKeys are more HostKey paths sshd -T lists.
	extraHostKeys []string
	// before are trust settings read before the Include (they win over
	// any drop-in), after those read after it (a drop-in wins over them).
	// noInclude makes sshd read no drop-in at all. match overrides
	// settings for sshd -T -C user=<account> (a Match block). extra is
	// more sshd -T lines (allowusers, denygroups, ...), and extraFor the
	// same for sshd -T -C user=<account>.
	before, after map[string]string
	noInclude     bool
	match         map[string]map[string]string
	extra         string
	extraFor      map[string]string
	// dumps counts sshd -T runs, by -C spec ("" for none).
	dumps map[string]int
	// onReload runs at every reload command (rc-service, systemctl), with
	// the runner's lock held.
	onReload func(call string)
	// hostCertBefore and hostCertAfter are HostCertificate values read
	// before and after the drop-in (03-09); hostKeyAlgorithms is sshd -T's
	// hostkeyalgorithms ("" for every certificate and plain algorithm).
	hostCertBefore, hostCertAfter []string
	hostKeyAlgorithms             string
}

// defaultHostKeyAlgorithms is every certificate and plain host key
// algorithm the fake serves.
var defaultHostKeyAlgorithms = strings.Join([]string{
	ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}, ",")

func (r *fakeRunner) Run(_ context.Context, cmd execsite.Cmd) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	args := cmd.Args()[1:]
	call := filepath.Base(cmd.Path()) + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if b, err := os.ReadFile(r.h.l.DropIn()); err == nil && r.rejectDropIn != nil && r.rejectDropIn(b) &&
		cmd.Path() == r.h.cfg.SSHD && len(args) >= 1 && (args[0] == "-t" || args[0] == "-T") {
		return Result{Code: 255, Stderr: []byte(r.h.l.DropIn() + " line 9: invalid quotes")}, nil
	}
	switch {
	case cmd.Path() == r.h.cfg.SSHD && len(args) == 1 && args[0] == "-V":
		return Result{Stderr: []byte("OpenSSH_10.5p1, OpenSSL 3.5.0 8 Apr 2025\n")}, nil
	case cmd.Path() == r.h.cfg.SSHD && len(args) >= 1 && args[0] == "-t":
		// The configuration fails only with the agent's drop-in in it.
		if _, err := os.Stat(r.h.l.DropIn()); r.sshdTestErr != "" && err == nil {
			return Result{Code: 1, Stderr: []byte(r.sshdTestErr)}, nil
		}
		return Result{}, nil
	case cmd.Path() == r.h.cfg.SSHD && len(args) >= 1 && args[0] == "-T":
		spec := ""
		if len(args) == 5 && args[3] == "-C" {
			spec = args[4]
		}
		if r.dumps == nil {
			r.dumps = map[string]int{}
		}
		r.dumps[spec]++
		return Result{Stdout: []byte(r.dumpFor(spec))}, nil
	case cmd.Path() == r.h.cfg.SSHKeygen && len(args) == 3 && args[0] == "-l":
		b, err := os.ReadFile(args[2])
		if err != nil {
			return Result{Code: 255}, nil
		}
		line := strings.TrimSpace(string(b))
		if r.rejectCA != nil && r.rejectCA(line) {
			return Result{Code: 255, Stderr: []byte("not a public key file")}, nil
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey(b); err != nil {
			return Result{Code: 255, Stderr: []byte("not a public key file")}, nil
		}
		return Result{Stdout: []byte("256 SHA256:x (ED25519)\n")}, nil
	case cmd.Path() == r.h.cfg.SSHKeygen && len(args) == 4 && args[0] == "-Q":
		if r.onQuery != nil {
			r.onQuery()
		}
		if r.queryCode != 0 {
			return Result{Code: r.queryCode, Stderr: []byte("KRL load failed")}, nil
		}
		b, err := os.ReadFile(args[2])
		if err != nil {
			return Result{Code: 255}, nil
		}
		if _, err := krl.Parse(b); err != nil {
			return Result{Code: 255, Stderr: []byte("invalid KRL")}, nil
		}
		return Result{Stdout: []byte(args[3] + ": ok\n")}, nil
	case filepath.Base(cmd.Path()) == "rc-service" || filepath.Base(cmd.Path()) == "systemctl":
		r.reloads++
		// The fake sshd re-reads its host certificates at every reload,
		// before any per-test hook (03-09).
		r.h.sshd.reload(r.h.l, r.noInclude)
		if r.onReload != nil {
			r.onReload(call)
		}
		return Result{}, nil
	}
	return Result{Code: 127}, fmt.Errorf("fake runner: unexpected command %s", call)
}

func (r *fakeRunner) dump() string { return r.dumpFor("") }

// dumpFor is sshd -T, with -C spec when spec is not empty: the trust
// settings come from before, then the drop-in on disk (any file there
// that names them, the agent's or a trial), then after, then "none"; a
// Match override for the spec's user wins.
func (r *fakeRunner) dumpFor(spec string) string {
	user := ""
	for _, kv := range strings.Split(spec, ",") {
		if v, ok := strings.CutPrefix(kv, "user="); ok {
			user = v
		}
	}
	dropIn, derr := os.ReadFile(r.h.l.DropIn())
	value := func(k string) string {
		if v, ok := r.match[user][k]; ok && user != "" {
			return v
		}
		if v, ok := r.before[k]; ok {
			return v
		}
		if derr == nil && !r.noInclude {
			for _, l := range strings.Split(string(dropIn), "\n") {
				if f := strings.Fields(l); len(f) == 2 && strings.ToLower(f[0]) == k {
					return f[1]
				}
			}
		}
		if v, ok := r.after[k]; ok {
			return v
		}
		return "none"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "port %d\n", r.h.sshd.port)
	listen := r.listen
	if listen == nil {
		listen = []string{"127.0.0.1:" + strconv.Itoa(r.h.sshd.port)}
	}
	for _, l := range listen {
		fmt.Fprintf(&b, "listenaddress %s\n", l)
	}
	fmt.Fprintf(&b, "hostkey %s\npidfile /nonexistent/sshd.pid\nlogingracetime %s\n", r.h.sshd.keyPath, r.grace)
	for _, k := range r.extraHostKeys {
		fmt.Fprintf(&b, "hostkey %s\n", k)
	}
	for _, k := range append(slices.Clone(trustKeywords), principalsCommand, principalsCommandUser) {
		fmt.Fprintf(&b, "%s %s\n", k, value(k))
	}
	// One hostcertificate line per value, before-files, drop-in, after-files
	// (03-09), and hostkeyalgorithms.
	certs := slices.Clone(r.hostCertBefore)
	if derr == nil && !r.noInclude {
		for _, l := range strings.Split(string(dropIn), "\n") {
			if f := strings.Fields(l); len(f) == 2 && strings.ToLower(f[0]) == "hostcertificate" {
				certs = append(certs, f[1])
			}
		}
	}
	certs = append(certs, r.hostCertAfter...)
	for _, c := range certs {
		fmt.Fprintf(&b, "hostcertificate %s\n", c)
	}
	algs := r.hostKeyAlgorithms
	if algs == "" {
		algs = defaultHostKeyAlgorithms
	}
	fmt.Fprintf(&b, "hostkeyalgorithms %s\n", algs)
	b.WriteString(r.extra)
	if user != "" {
		b.WriteString(r.extraFor[user])
	}
	return b.String()
}

// testHost is one host under test: its layout, spool, fake sshd, fake
// runner and fake clock, and the fixture whose state it applies.
type testHost struct {
	t     *testing.T
	f     *fixture
	l     Layout
	spool string
	sshd  *fakeSSHD
	run   *fakeRunner
	clock *fakeClock
	cfg   Config
	dirs  []spool.Doc
	state spool.State
	// probeMu guards queries, the probe queries sshdProbe answered
	// (03-10b).
	probeMu sync.Mutex
	queries []ProbeTarget
}

func newTestHost(t *testing.T, f *fixture) *testHost {
	t.Helper()
	return newTestHostIn(t, f, t.TempDir())
}

// newTestHostIn is newTestHost with its layout under base.
func newTestHostIn(t *testing.T, f *fixture, base string) *testHost {
	t.Helper()
	h := &testHost{t: t, f: f, l: Layout{Root: filepath.Join(base, "root"), StateDir: filepath.Join(base, "state")}, spool: filepath.Join(base, "spool"), clock: newFakeClock()}
	for _, d := range []string{h.l.Root, h.l.StateDir, h.spool} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(h.l.DropInDir(), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	fd, err := spool.OpenDir(h.l.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.WritePins(h.l, fd, f.pins()); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	h.sshd = startFakeSSHD(t)
	h.run = &fakeRunner{h: h, grace: "120"}
	// The binaries exist (the preflight checks them) but never run: the
	// fake runner answers by path. sshd_config is the host's own file.
	bin := filepath.Join(base, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	for _, b := range []string{"sshd", "ssh-keygen"} {
		if err := os.WriteFile(filepath.Join(bin, b), []byte("#!/bin/false\n"), 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	sshdConfig := filepath.Join(h.l.Root, "etc", "ssh", "sshd_config")
	if err := os.WriteFile(sshdConfig, []byte("Include "+filepath.Join(h.l.DropInDir(), "*.conf")+"\n"), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	h.cfg = Config{Spool: h.spool, SSHD: filepath.Join(bin, "sshd"), SSHDConfig: sshdConfig, SSHKeygen: filepath.Join(bin, "ssh-keygen"),
		Reload: "openrc", SelfTestTimeout: 2 * time.Second, Clock: h.clock, Exec: h.run}
	// 03-10b: the probe self-test is off for every existing apply test, so
	// no generation gains a probe file and no widening is gated; the probe
	// tests switch it on again.
	h.cfg.probeOff = true
	h.state = f.genesis()
	return h
}

// spec is the default directory spec for this host: account deploy
// mapped to ops with principals.
func (h *testHost) spec(principals ...string) dirSpec {
	return dirSpec{principals: principals, accounts: []string{"deploy"}, hostKeys: []ssh.PublicKey{h.sshd.pub}}
}

// publishDir signs the next directory version and offers it.
func (h *testHost) publishDir(s dirSpec) spool.Doc {
	h.t.Helper()
	var prev []byte
	if len(h.dirs) > 0 {
		prev = h.dirs[len(h.dirs)-1].Body
	}
	d := h.f.directory(prev, s)
	h.dirs = append(h.dirs, d)
	h.state.Directories[uint64(len(h.dirs))] = d
	return d
}

// publishKRL offers the next KRL version.
func (h *testHost) publishKRL(serials ...uint64) {
	h.t.Helper()
	v, files := h.f.krl(serials, nil, "")
	h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
}

// write puts the offered state into the spool.
func (h *testHost) write() {
	h.t.Helper()
	if err := spool.Write(h.spool, h.state); err != nil {
		h.t.Fatal(err)
	}
}

func (h *testHost) apply() (*Report, error) {
	h.t.Helper()
	h.write()
	return Apply(context.Background(), h.cfg, h.l)
}

func (h *testHost) mustApply() *Report {
	h.t.Helper()
	r, err := h.apply()
	if err != nil {
		h.t.Fatalf("apply: %v (report %+v)", err, r)
	}
	return r
}

// link returns the generation a link names (0: none).
func (h *testHost) link(path string) uint64 {
	h.t.Helper()
	target, err := os.Readlink(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		h.t.Fatal(err)
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(target, "gen/"), 10, 64)
	if err != nil {
		h.t.Fatalf("link %s = %q", path, target)
	}
	return n
}

func (h *testHost) current() uint64  { return h.link(h.l.Current()) }
func (h *testHost) lastGood() uint64 { return h.link(h.l.LastGood()) }

// file reads a file of the generation current names.
func (h *testHost) file(name string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.l.Current(), name)) //nolint:gosec // test fixture
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

// principals is the non-comment lines of current's principals file for
// account.
func (h *testHost) principals(account string) []string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.l.Current(), PrincipalsDir, account)) //nolint:gosec // test fixture
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, l := range lines(b) {
		if k, ok := principalLine(l); ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// installed brings the host to a first generation: directory version 1
// with principals, no KRL yet.
func (h *testHost) installed(principals ...string) *Report {
	h.t.Helper()
	h.publishDir(h.spec(principals...))
	r := h.mustApply()
	if h.current() == 0 || h.lastGood() != h.current() {
		h.t.Fatalf("after the first install current %d, last-good %d", h.current(), h.lastGood())
	}
	return r
}

// probeLogin is the probe account of the gate tests (03-10b): the default
// name, a uid that is not 0 and the nologin shell.
const probeLogin = certpkg.ReservedAccountName + ":x:990:990::/nonexistent:/usr/sbin/nologin"

// gateOn switches h's probe self-test on (03-10b) and writes the passwd
// fixture with the probe account and an executable nologin under the root.
func (h *testHost) gateOn() {
	h.t.Helper()
	h.cfg.probeOff = false
	h.cfg.SelfTestTimeout = time.Second
	h.writePasswd("root:x:0:0:root:/root:/bin/bash\n" + probeLogin + "\n")
	h.writeRootFile("usr/sbin/nologin", []byte("#!/bin/false\n"), 0o755)
	h.cfg.probeQuery = h.sshdProbe
}

// sshdProbe answers a probe query as sshd does against the generation
// current names (03-10b): accepted when the certificate's principal is in
// the account's principals file, its CA key is in user_ca_keys and the KRL
// does not revoke its serial; refused otherwise. It records the query.
func (h *testHost) sshdProbe(_ context.Context, t ProbeTarget, c *ssh.Certificate, _ time.Time) (ProbeOutcome, error) {
	h.probeMu.Lock()
	h.queries = append(h.queries, t)
	h.probeMu.Unlock()
	g, _, err := h.engine().readCurrent()
	if err != nil || g == nil {
		return ProbeInconclusive, fmt.Errorf("no current generation: %w", err)
	}
	if len(c.ValidPrincipals) != 1 || !lineSet(g.Files[PrincipalsDir+"/"+t.Account], principalLine)[c.ValidPrincipals[0]] ||
		!slices.ContainsFunc(genCAKeys(g), func(k ssh.PublicKey) bool { return bytes.Equal(k.Marshal(), c.SignatureKey.Marshal()) }) {
		return ProbeRefused, nil
	}
	if k := genKRL(g); k != nil && k.RevokesSerial(c.SignatureKey.Marshal(), c.Serial) {
		return ProbeRefused, nil
	}
	return ProbeAccepted, nil
}

// probeQueries is the probe queries sshdProbe answered so far.
func (h *testHost) probeQueries() []ProbeTarget {
	h.probeMu.Lock()
	defer h.probeMu.Unlock()
	return slices.Clone(h.queries)
}

// writePasswd writes <root>/etc/passwd.
func (h *testHost) writePasswd(content string) {
	h.t.Helper()
	h.writeRootFile("etc/passwd", []byte(content), 0o644)
}

// writeRootFile writes name below the layout root with mode.
func (h *testHost) writeRootFile(name string, b []byte, mode os.FileMode) {
	h.t.Helper()
	p := filepath.Join(h.l.Root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // test fixture
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, b, mode); err != nil {
		h.t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		h.t.Fatal(err)
	}
}

// probeSerial numbers the probe certificates the fixture signs.
var probeSerial atomic.Uint64

// signProbeFor signs a probe certificate for the host named host (web1,
// or a name the entry had before a rename: PR #91 review F1) with the
// fixture's machine CA, as the signer does: certprofile.ProbeProfile, the
// kr3 key ID of the probe subject, the probe principal and options,
// backdated five minutes by cert.Build, valid for lifetime from the fake
// clock's now.
func (h *testHost) signProbeFor(host string, lifetime time.Duration, ca ssh.Signer) *ssh.Certificate {
	h.t.Helper()
	prof, err := certprofile.ProbeProfile(h.f.policy)
	if err != nil {
		h.t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		h.t.Fatal(err)
	}
	serial := 1_795_000_000_000_000 + probeSerial.Add(1)
	c, err := certpkg.Build(certpkg.Request{
		Profile: prof, Subject: key, Principals: []string{certpkg.ReservedPrincipalPrefix + host}, Now: h.clock.Now(),
		ValidFor: lifetime, Serial: serial,
		KeyID:           certpkg.KeyID{V3: true, CA: "machine", Subject: "probe." + host, Request: strings.Repeat("ab", 16), Policy: 1, Directory: 1, Serial: serial},
		CriticalOptions: certprofile.ProbeCriticalOptions()}, ca, rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// seedPair signs a probe pair with the machine CA (lifetime from now) and
// stores it as <state>/probe.json's committed pair (next when next is
// set), through the engine's writer. It returns the pair.
func (h *testHost) seedPair(lifetime time.Duration, next bool) probecert.Pair {
	h.t.Helper()
	return h.storePair(probecert.Pair{Positive: h.probeCert(lifetime, h.f.mach), Negative: h.probeCert(lifetime, h.f.mach)}, next)
}

// probeCert is a signed probe certificate as probe.json keeps it.
func (h *testHost) probeCert(lifetime time.Duration, ca ssh.Signer) *probecert.Cert {
	h.t.Helper()
	return h.probeCertFor("web1", lifetime, ca)
}

// probeCertFor is probeCert for the host named host.
func (h *testHost) probeCertFor(host string, lifetime time.Duration, ca ssh.Signer) *probecert.Cert {
	h.t.Helper()
	c := h.signProbeFor(host, lifetime, ca)
	return probecert.NewCert(c, c.ValidAfter+300+uint64(lifetime/time.Second)*2/3) //nolint:gosec // G115: a positive test lifetime
}

// storePair writes p as probe.json's committed (or next) pair, keeping the
// rest of the record.
func (h *testHost) storePair(p probecert.Pair, next bool) probecert.Pair {
	h.t.Helper()
	e := h.engine()
	e.locked = true
	rec := e.readProbeRecord()
	if next {
		rec.Next = p
	} else {
		rec.Committed = p
	}
	if err := e.saveProbeRecord(rec); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// listMach makes every later KRL of the fixture list serials under the
// machine CA key (negative probe certificates) and offers the next one.
func (h *testHost) listMach(serials ...uint64) {
	h.t.Helper()
	h.f.krlMachSerials = append(h.f.krlMachSerials, serials...)
	h.publishKRL()
}
