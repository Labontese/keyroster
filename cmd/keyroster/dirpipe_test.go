package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/adminauth"
	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// countingAgent is an in-memory ssh-agent that counts the sign requests
// that sign a directory version: SSHSIG signed data under
// directory.Namespace. Every admin API request is a sign request too
// (keyroster/admin-api/v1), so counting every request could never show
// that a refused directory signature reached no agent.
type countingAgent struct {
	agent.ExtendedAgent
	mu   sync.Mutex
	dirs int
}

func (c *countingAgent) note(data []byte) {
	if sshsigNamespace(data) == directory.Namespace {
		c.mu.Lock()
		c.dirs++
		c.mu.Unlock()
	}
}

func (c *countingAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	c.note(data)
	return c.ExtendedAgent.Sign(key, data)
}

func (c *countingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	c.note(data)
	return c.ExtendedAgent.SignWithFlags(key, data, flags)
}

// dirSigns returns the number of directory signatures asked for so far.
func (c *countingAgent) dirSigns() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dirs
}

// sshsigNamespace returns the namespace of SSHSIG signed data ("SSHSIG",
// then the namespace as an SSH string), or "" for any other data.
func sshsigNamespace(data []byte) string {
	rest, ok := bytes.CutPrefix(data, []byte("SSHSIG"))
	if !ok || len(rest) < 4 {
		return ""
	}
	n := int64(binary.BigEndian.Uint32(rest))
	if n > int64(len(rest))-4 {
		return ""
	}
	return string(rest[4 : 4+n])
}

// useCountingKeyring routes the CLI's ssh-agent connection to a counting
// in-memory keyring holding keys.
func useCountingKeyring(t *testing.T, keys ...ed25519.PrivateKey) *countingAgent {
	t.Helper()
	keyring, ok := agent.NewKeyring().(agent.ExtendedAgent)
	if !ok {
		t.Fatal("the keyring is not an ExtendedAgent")
	}
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	c := &countingAgent{ExtendedAgent: keyring}
	prev := dialAgent
	dialAgent = func() (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_ = agent.ServeAgent(c, server)
			_ = server.Close()
		}()
		return client, nil
	}
	t.Cleanup(func() { dialAgent = prev })
	return c
}

// useTerminal sets what confirmSign sees: whether stdin is a terminal,
// and the line typed.
func useTerminal(t *testing.T, tty bool, input string) {
	t.Helper()
	prevTTY, prevIn := stdinIsTerminal, ceremonyInput
	stdinIsTerminal = func() bool { return tty }
	ceremonyInput = strings.NewReader(input)
	t.Cleanup(func() { stdinIsTerminal, ceremonyInput = prevTTY, prevIn })
}

// dirEnv is a fake keyroster-server for the directory commands: a TLS
// server under a test root that serves a root-signed trust document whose
// policy has n admins at quorum q, verifies admin requests against them,
// serves the installed directory and pending passkeys, and installs a
// posted version by the signer's rules (chain and quorum) unless post is
// set. The saved config pins it, and a counting keyring holds every
// admin key.
type dirEnv struct {
	keys    []ed25519.PrivateKey
	signers []ssh.Signer
	fps     []string
	pol     *trust.Policy
	agent   *countingAgent
	cfg     *Config
	// bundle is the root-signed genesis bundle served, and ops a signer
	// for its ops key (signs KRL manifests).
	bundle *trust.Bundle
	ops    ssh.Signer
	// root is the genesis root's private key, for re-signing the bundle
	// (resignBundle).
	root ed25519.PrivateKey

	mu       sync.Mutex
	custody  string // the Keyroster-Custody header of every answer
	trustDoc []byte
	doc      []byte // the installed directory, nil for none
	sigs     []byte
	served   *serverclient.DirectoryAnswer // served instead of doc when set
	pending  map[string]serverclient.PendingAnswer
	pendingN map[string]int // pending accounts for GET users
	override map[string]func(w http.ResponseWriter)
	post     func(w http.ResponseWriter, req serverclient.InstallDirectoryRequest)
	posts    int
	leaf     uint64
	// revokeBody is the body of the last POST AdminRevokePath.
	revokeBody []byte
	// calls is every admin POST, in order, as "POST <path>".
	calls []string
}

const agentCustody = "user=agent, host=agent, machine=agent, ops=agent, log=agent"

func newDirEnv(t *testing.T, admins int, quorum int) *dirEnv {
	t.Helper()
	return newDirEnvPolicy(t, admins, quorum, nil)
}

// newDirEnvPolicy is newDirEnv with the genesis policy changed by edit
// (nil: unchanged) before the root signs it.
func newDirEnvPolicy(t *testing.T, admins int, quorum int, edit func(p *trust.Policy)) *dirEnv {
	t.Helper()
	e := &dirEnv{custody: agentCustody, pending: map[string]serverclient.PendingAnswer{}, pendingN: map[string]int{}, override: map[string]func(http.ResponseWriter){}}
	g := newCeremony(t, 1)
	g.policy = filepath.Join(g.dir, "dir-policy.json")
	args := []string{"root", "genesis-policy", "--admin-quorum", strconv.Itoa(quorum), "--webauthn-rp-id", inviteRPID, "--out", g.policy}
	for i := range admins {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(g.dir, fmt.Sprintf("admin%d.pub", i))
		writeTestFile(t, file, ssh.MarshalAuthorizedKey(s.PublicKey()))
		args = append(args, "--admin", fmt.Sprintf("admin%d=%s", i, file))
		e.keys, e.signers, e.fps = append(e.keys, k), append(e.signers, s), append(e.fps, ssh.FingerprintSHA256(s.PublicKey()))
	}
	if code, _, stderr := run(t, args...); code != 0 {
		t.Fatalf("genesis-policy exit %d: %s", code, stderr)
	}
	if edit != nil {
		p, err := trust.ParsePolicy(readTestFile(t, g.policy))
		if err != nil {
			t.Fatal(err)
		}
		edit(p)
		doc, err := p.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, g.policy, doc)
	}
	e.root = g.rootKeys[0]
	useKeyring(t, g.rootKeys...)
	typeHashPrefix(t, g.out)
	if code, _, stderr := g.sign(t, "1", 0); code != 0 {
		t.Fatalf("root sign: exit %d: %s", code, stderr)
	}
	read := func(name string) []byte { return readTestFile(t, filepath.Join(g.out, name)) }
	pol, err := trust.ParsePolicy(read("policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.pol = pol
	if e.bundle, err = trust.ParseBundle(read("bundle.json")); err != nil {
		t.Fatal(err)
	}
	if e.ops, err = ssh.NewSignerFromKey(g.caKeys["ops"]); err != nil {
		t.Fatal(err)
	}
	e.trustDoc, err = json.Marshal(serverclient.TrustResponse{
		Bundle: read("bundle.json"), BundleSigs: read("bundle.json.sigs"),
		Policy: read("policy.json"), PolicySigs: read("policy.json.sigs"), BundleVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	rootFP := g.fingerprint(t, 0)

	root, rootKey := initTestRoot(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	url := serveTLS(t, tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: leafKey}, http.HandlerFunc(e.handle))
	e.cfg = &Config{
		Server:         url,
		TLSRootsPEM:    []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))},
		TLSPins:        []string{serverclient.PinOf(root)},
		TrustPins:      []string{rootFP},
		TrustThreshold: 1,
		User:           "admin",
		AdminKey:       e.fps[0],
	}
	useConfigDir(t)
	if _, err := saveConfig(e.cfg, false); err != nil {
		t.Fatal(err)
	}
	e.agent = useCountingKeyring(t, e.keys...)
	useTerminal(t, false, "")
	return e
}

func (e *dirEnv) handle(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	custody := e.custody
	e.mu.Unlock()
	w.Header().Set(serverclient.CustodyHeader, custody)
	if r.URL.Path == serverclient.TrustPath {
		e.mu.Lock()
		doc := e.trustDoc
		e.mu.Unlock()
		_, _ = w.Write(doc)
		return
	}
	if r.URL.Path == serverclient.KRLPath {
		// Public, like the trust document: override "GET "+KRLPath
		// serves a KRL, otherwise none is published.
		e.mu.Lock()
		f := e.override[r.Method+" "+r.URL.Path]
		e.mu.Unlock()
		if f != nil {
			f(w)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"`+serverclient.KRLErrNone+`"}`)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	_, _, digest, err := adminauth.Verify(r.Header, "https://"+r.Host, r.Method, r.RequestURI, time.Now(), e.pol.Admins)
	if err == nil {
		err = adminauth.CheckBody(digest, body)
	}
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"admin authentication failed"}`)
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.Method == http.MethodPost && r.URL.Path == serverclient.AdminRevokePath {
		e.revokeBody = body
	}
	if r.Method == http.MethodPost {
		e.calls = append(e.calls, r.Method+" "+r.URL.Path)
	}
	if f := e.override[r.Method+" "+r.URL.Path]; f != nil {
		f(w)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == serverclient.AdminDirectoryPath:
		ans := serverclient.DirectoryAnswer{}
		if e.doc != nil {
			ans = serverclient.DirectoryAnswer{Version: docVersion(e.doc), Directory: e.doc, Sigs: e.sigs, Authorized: true}
		}
		if e.served != nil {
			ans = *e.served
		}
		_ = json.NewEncoder(w).Encode(ans)
	case r.Method == http.MethodPost && r.URL.Path == serverclient.AdminDirectoryPath:
		e.posts++
		var req serverclient.InstallDirectoryRequest
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if e.post != nil {
			e.post(w, req)
			return
		}
		e.install(w, req)
	case r.Method == http.MethodGet && r.URL.Path == serverclient.AdminUsersPath:
		ans := serverclient.UsersAnswer{Users: []serverclient.DirectoryUser{}, Pending: []serverclient.PendingAccount{}}
		for name, n := range e.pendingN {
			ans.Pending = append(ans.Pending, serverclient.PendingAccount{Name: name, InviteExpiresAt: "2026-10-22T10:00:00Z", InviteUsed: n == 1, Credentials: n})
		}
		_ = json.NewEncoder(w).Encode(ans)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pending"):
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, serverclient.AdminUsersPath+"/"), "/pending")
		ans, ok := e.pending[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"not pending"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(ans)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// install applies the signer's rules to a posted version: the admin
// quorum of the policy, then the chain.
func (e *dirEnv) install(w http.ResponseWriter, req serverclient.InstallDirectoryRequest) {
	refuse := func(code int, msg string) {
		w.WriteHeader(code)
		_, _ = io.WriteString(w, `{"error":"`+msg+`"}`)
	}
	if _, err := directory.VerifySignatures(req.Directory, req.Sigs, e.pol); err != nil {
		refuse(http.StatusForbidden, "directory_quorum_not_met")
		return
	}
	want, cur := trust.GenesisPrev, uint64(0)
	if e.doc != nil {
		want, cur = trust.SHA256Hex(e.doc), docVersion(e.doc)
	}
	d, err := directory.Parse(req.Directory)
	if err != nil {
		refuse(http.StatusBadRequest, "directory_invalid")
		return
	}
	if d.Version != cur+1 || d.Prev != want {
		refuse(http.StatusConflict, "directory_version_chain")
		return
	}
	e.doc, e.sigs = req.Directory, req.Sigs
	e.leaf++
	_ = json.NewEncoder(w).Encode(serverclient.InstallDirectoryAnswer{Version: d.Version, SHA256: trust.SHA256Hex(req.Directory), LeafIndex: e.leaf})
}

func docVersion(doc []byte) uint64 {
	var v struct {
		Version uint64 `json:"version"`
	}
	_ = json.Unmarshal(doc, &v)
	return v.Version
}

// sign returns the armored signatures over doc by the admins idx.
func (e *dirEnv) sign(t *testing.T, doc []byte, idx ...int) []byte {
	t.Helper()
	var out []byte
	for _, i := range idx {
		sig, err := sshsig.Sign(rand.Reader, e.signers[i], directory.Namespace, doc)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sig...)
	}
	return out
}

// installDirect makes doc the installed directory, signed by the first
// quorum admins.
func (e *dirEnv) installDirect(t *testing.T, doc []byte) {
	t.Helper()
	idx := make([]int, e.pol.AdminQuorum)
	for i := range idx {
		idx[i] = i
	}
	sigs := e.sign(t, doc, idx...)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.doc, e.sigs = doc, sigs
}

// installed returns the installed directory and the number of posts.
func (e *dirEnv) installed() ([]byte, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.doc, e.posts
}

// setPending makes entries name's pending passkeys under a used invite.
func (e *dirEnv) setPending(name string, entries ...serverclient.PendingCredential) {
	e.mu.Lock()
	defer e.mu.Unlock()
	state := serverclient.InviteUsed
	if len(entries) == 0 {
		state = serverclient.InviteOpen
	}
	e.pending[name] = serverclient.PendingAnswer{Invite: serverclient.PendingInvite{State: state, ExpiresAt: "2026-10-22T10:00:00Z"},
		Credentials: append([]serverclient.PendingCredential{}, entries...)}
	e.pendingN[name] = len(entries)
}

// buildDir returns the canonical successor of prev (nil: genesis) after
// mutate.
func buildDir(t *testing.T, prev []byte, mutate func(d *directory.Directory)) []byte {
	t.Helper()
	d := &directory.Directory{Version: 1, Prev: trust.GenesisPrev}
	if prev != nil {
		p, err := directory.Parse(prev)
		if err != nil {
			t.Fatal(err)
		}
		d = p
		d.Version, d.Prev = p.Version+1, trust.SHA256Hex(prev)
	}
	mutate(d)
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Parse(doc); err != nil {
		t.Fatalf("test directory does not parse: %v", err)
	}
	return doc
}

// boundTo returns mutate followed by binding the directory to installation
// id, as every edit binds a new version to the root-verified bundle's.
func boundTo(id string, mutate func(d *directory.Directory)) func(d *directory.Directory) {
	return func(d *directory.Directory) {
		mutate(d)
		d.InstallationID = id
	}
}

// credOf is the directory credential of a pending entry.
func credOf(c serverclient.PendingCredential) directory.Credential {
	return directory.Credential{ID: c.ID, Alg: c.Alg, SPKI: c.SPKI, BackupEligible: c.BackupEligible, BackedUp: c.BackedUp}
}

// addUser returns a mutation that adds name, active, with creds.
func addUser(name string, creds ...directory.Credential) func(d *directory.Directory) {
	return func(d *directory.Directory) {
		d.Users = append(d.Users, directory.User{Name: name, Status: directory.StatusActive, Credentials: creds})
	}
}

// writeProposalDir writes a proposal directory holding doc and sigs.
func writeProposalDir(t *testing.T, doc, sigs []byte) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, proposalDoc), doc)
	writeTestFile(t, filepath.Join(dir, proposalSigs), sigs)
	return dir
}

// requireNotSigned fails if any directory signature reached the agent or
// any version was posted.
func requireNotSigned(t *testing.T, e *dirEnv, posts int) {
	t.Helper()
	if n := e.agent.dirSigns(); n != 0 {
		t.Fatalf("the agent got %d directory sign requests, want 0", n)
	}
	if _, p := e.installed(); p != posts {
		t.Fatalf("%d install posts, want %d", p, posts)
	}
}

func TestDirectoryPipeline(t *testing.T) {
	t.Run("fetch_no_directory_installed", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		s, err := openAdminSession("", io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		vd, err := fetchVerifiedDirectory(context.Background(), s)
		if err != nil || vd == nil || vd.Version != 0 || vd.Dir != nil || vd.Doc != nil || vd.Sigs != nil || vd.SHA256 != "" || len(vd.Signers) != 0 || vd.Policy == nil {
			t.Fatalf("fetchVerifiedDirectory with nothing installed = %+v, %v; want version 0, nil Dir, empty SHA256 and the policy", vd, err)
		}
		if code, stdout, stderr := run(t, "directory", "show"); code != 0 || stdout != "The server serves no directory.\n" {
			t.Fatalf("directory show: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		// Control: with version 1 installed.
		entry, _ := pendingEntry(t, webauthn.AlgES256)
		v1 := buildDir(t, nil, addUser("alice", credOf(entry)))
		e.installDirect(t, v1)
		vd, err = fetchVerifiedDirectory(context.Background(), s)
		if err != nil || vd.Version != 1 || vd.Dir == nil || vd.SHA256 != trust.SHA256Hex(v1) || len(vd.Signers) != 1 || vd.Signers[0] != e.fps[0] {
			t.Fatalf("fetchVerifiedDirectory with version 1 = %+v, %v", vd, err)
		}
		// show prints what the server serves and says that installation is
		// the server's word (pre-merge review, 02-09: owner decision F1).
		if code, stdout, stderr := run(t, "directory", "show"); code != 0 ||
			!strings.HasPrefix(stdout, "The admin-signed directory the server serves: version 1, signatures verified against the root-signed policy version 1\n"+serverServesNote) ||
			strings.Contains(strings.ToLower(stdout), "installed directory") || strings.Contains(stdout, "verified installed") ||
			!strings.Contains(stdout, "user alice (active)") || !strings.Contains(stdout, "admin0 "+e.fps[0]) {
			t.Fatalf("directory show: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})

	t.Run("fake_base_refused", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		alice, _ := pendingEntry(t, webauthn.AlgES256)
		v1 := buildDir(t, nil, addUser("alice", credOf(alice)))
		_, other, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		nonAdmin, err := ssh.NewSignerFromKey(other)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sshsig.Sign(rand.Reader, nonAdmin, directory.Namespace, v1)
		if err != nil {
			t.Fatal(err)
		}
		e.mu.Lock()
		e.doc, e.sigs = v1, sig // signed by a key that is not a policy admin
		e.mu.Unlock()
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", bob)
		code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 1 || !strings.Contains(stderr, "not signed by the policy admins") {
			t.Fatalf("approve on a fake base: exit %d, stderr %q", code, stderr)
		}
		requireNotSigned(t, e, 0)
	})

	t.Run("unpinned_bundle_refused", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		other := make([]byte, 32)
		if _, err := rand.Read(other); err != nil {
			t.Fatal(err)
		}
		e.cfg.TrustPins = []string{"SHA256:" + base64.RawStdEncoding.EncodeToString(other)}
		if _, err := saveConfig(e.cfg, true); err != nil {
			t.Fatal(err)
		}
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", bob)
		code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 1 || !strings.Contains(stderr, "do not match the --root-pin set") {
			t.Fatalf("approve against a bundle of an unpinned root: exit %d, stderr %q", code, stderr)
		}
		requireNotSigned(t, e, 0)
	})

	t.Run("duplicate_credential_across_users_not_signed", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		alice, _ := pendingEntry(t, webauthn.AlgES256)
		e.installDirect(t, buildDir(t, nil, addUser("alice", credOf(alice))))
		// bob's pending passkey carries alice's credential ID (the pending
		// store refuses this; a fake server can send it).
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		bob.ID = alice.ID
		e.setPending("bob", bob)
		code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 1 || !strings.Contains(stderr, "would not be valid") || !strings.Contains(stderr, "bound more than once") {
			t.Fatalf("approve of a credential bound to alice: exit %d, stderr %q", code, stderr)
		}
		requireNotSigned(t, e, 0)
	})

	t.Run("no_pending_credential", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		_, fp := pendingEntry(t, webauthn.AlgES256)
		code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 1 || !strings.Contains(stderr, "no pending credential for bob") {
			t.Fatalf("approve of a name with no pending enrollment: exit %d, stderr %q", code, stderr)
		}
		e.setPending("bob") // an open invite, no passkey yet
		code, _, stderr = run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 1 || !strings.Contains(stderr, "no pending credential for bob") {
			t.Fatalf("approve of an open invite: exit %d, stderr %q", code, stderr)
		}
		requireNotSigned(t, e, 0)
	})

	t.Run("unknown_fingerprint", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", bob)
		_, other := pendingEntry(t, webauthn.AlgES256)
		code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", other, "--yes")
		if code != 1 || !strings.Contains(stderr, "no pending credential with fingerprint "+other) {
			t.Fatalf("approve with an unknown fingerprint: exit %d, stderr %q", code, stderr)
		}
		requireNotSigned(t, e, 0)
	})

	t.Run("active_user_without_credential_not_signed", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.installDirect(t, buildDir(t, nil, func(d *directory.Directory) {
			d.Users = append(d.Users, directory.User{Name: "carol", Status: directory.StatusDisabled, Credentials: []directory.Credential{}})
		}))
		code, _, stderr := run(t, "user", "enable", "carol", "--yes")
		if code != 1 || !strings.Contains(stderr, "has no credential") {
			t.Fatalf("enable of a user with no credential: exit %d, stderr %q", code, stderr)
		}
		requireNotSigned(t, e, 0)
	})

	t.Run("approve_disable_enable_round_trip", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", bob)
		code, stdout, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 0 || !strings.Contains(stdout, "+ user bob (active)") || !strings.Contains(stdout, "+ credential bob "+fp+" ES256") {
			t.Fatalf("approve: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		v1, _ := e.installed()
		// The install is reported as the server's word, never as a fact the
		// CLI checked (pre-merge review, 02-09: owner decision F1).
		if !strings.Contains(stdout, "The server reports directory version 1 installed (SHA-256 "+trust.SHA256Hex(v1)+", log leaf 1).\n"+
			"That is the server's word: the signer's audit log is the proof (keyroster audit verify on a log exported on the signer host must print \"directory installs 1\").\n") ||
			strings.Contains(stdout, "Installed directory") {
			t.Fatalf("approve output does not report the install as the server's word, with the version's own SHA-256:\n%s", stdout)
		}
		if code, stdout, stderr := run(t, "user", "disable", "bob", "--yes"); code != 0 || !strings.Contains(stdout, "~ user bob active -> disabled") {
			t.Fatalf("disable: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, _, stderr := run(t, "user", "disable", "bob", "--yes"); code != 1 || !strings.Contains(stderr, "bob is already disabled") {
			t.Fatalf("second disable: exit %d, stderr %q", code, stderr)
		}
		if code, stdout, stderr := run(t, "user", "enable", "bob", "--yes"); code != 0 || !strings.Contains(stdout, "~ user bob disabled -> active") {
			t.Fatalf("enable: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		doc, posts := e.installed()
		if docVersion(doc) != 3 || posts != 3 || e.agent.dirSigns() != 3 {
			t.Fatalf("after approve, disable, enable: version %d, %d posts, %d directory signatures; want 3 each", docVersion(doc), posts, e.agent.dirSigns())
		}
		if code, stdout, stderr := run(t, "user", "list"); code != 0 || !strings.Contains(stdout, "bob") || !strings.Contains(stdout, "passkey "+fp+" ES256") ||
			!strings.HasPrefix(stdout, "The admin-signed directory the server serves: version 3, signatures verified against the root-signed policy.\n"+serverServesNote) {
			t.Fatalf("user list: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})

	t.Run("approve_appends_passkey_to_directory_user", func(t *testing.T) {
		// One more passkey for a user already in the directory (the
		// reinvite flow) is added next to the bound one, never in its place
		// (pre-merge review, 02-09).
		e := newDirEnv(t, 1, 1)
		c1, fp1 := pendingEntry(t, webauthn.AlgES256)
		e.installDirect(t, buildDir(t, nil, addUser("bob", credOf(c1))))
		c2, fp2 := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", c2)
		code, stdout, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp2, "--yes")
		if code != 0 || !strings.Contains(stdout, "+ credential bob "+fp2+" ES256") || strings.Contains(stdout, "- credential") ||
			strings.Contains(stdout, "+ user bob") || strings.Contains(stdout, fp1) {
			t.Fatalf("approve of bob's second passkey: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		doc, _ := e.installed()
		d, err := directory.Parse(doc)
		if err != nil || d.Version != 2 || len(d.Users) != 1 || len(d.Users[0].Credentials) != 2 {
			t.Fatalf("installed after the approve: %+v, %v; want version 2 with bob holding two passkeys", d, err)
		}
		for _, c := range []serverclient.PendingCredential{c1, c2} {
			if !slices.Contains(d.Users[0].Credentials, credOf(c)) {
				t.Fatalf("bob does not hold credential %s after the approve: %+v", c.ID, d.Users[0].Credentials)
			}
		}
	})

	t.Run("directory_sign_refuses_non_admin_sig", func(t *testing.T) {
		e := newDirEnv(t, 2, 2)
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		doc := buildDir(t, nil, boundTo(e.bundle.InstallationID, addUser("bob", credOf(bob))))
		_, other, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		nonAdmin, err := ssh.NewSignerFromKey(other)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sshsig.Sign(rand.Reader, nonAdmin, directory.Namespace, doc)
		if err != nil {
			t.Fatal(err)
		}
		dir := writeProposalDir(t, doc, sig)
		code, _, stderr := run(t, "directory", "sign", dir, "--yes", "--admin-key", e.fps[1])
		if code != 1 || !strings.Contains(stderr, "not an admin of the root-signed policy") {
			t.Fatalf("sign of a proposal with a non-admin signature: exit %d, stderr %q", code, stderr)
		}
		requireNotSigned(t, e, 0)
		if got := readTestFile(t, filepath.Join(dir, proposalSigs)); !bytes.Equal(got, sig) {
			t.Fatal("directory.json.sigs changed")
		}
	})

	t.Run("directory_sign_refuses_tampered_doc", func(t *testing.T) {
		e := newDirEnv(t, 2, 2)
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		doc := buildDir(t, nil, boundTo(e.bundle.InstallationID, addUser("bob", credOf(bob))))
		sig := e.sign(t, doc, 0)
		tampered := bytes.Replace(doc, []byte(`"name":"bob"`), []byte(`"name":"bod"`), 1)
		if bytes.Equal(tampered, doc) {
			t.Fatal("no byte changed")
		}
		dir := writeProposalDir(t, tampered, sig)
		code, _, stderr := run(t, "directory", "sign", dir, "--yes", "--admin-key", e.fps[1])
		if code != 1 || !strings.Contains(stderr, "does not verify over directory.json") {
			t.Fatalf("sign of a tampered proposal: exit %d, stderr %q", code, stderr)
		}
		requireNotSigned(t, e, 0)
	})

	staleSetup := func(t *testing.T) (*dirEnv, string) {
		t.Helper()
		e := newDirEnv(t, 2, 2)
		alice, _ := pendingEntry(t, webauthn.AlgES256)
		v1 := buildDir(t, nil, addUser("alice", credOf(alice)))
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		carol, _ := pendingEntry(t, webauthn.AlgES256)
		proposal := buildDir(t, v1, addUser("bob", credOf(bob))) // built on v1
		e.installDirect(t, buildDir(t, v1, addUser("carol", credOf(carol))))
		return e, writeProposalDir(t, proposal, e.sign(t, proposal, 0))
	}
	requireStale := func(t *testing.T, what string, code int, stderr string) {
		t.Helper()
		if code != 1 || !strings.Contains(stderr, "based on version 1, but the server serves version 2") ||
			!strings.Contains(stderr, "re-run the command that produced it") || strings.Contains(stderr, "re-run this command") {
			t.Fatalf("%s: exit %d, stderr %q", what, code, stderr)
		}
	}

	t.Run("stale_proposal_sign_message", func(t *testing.T) {
		e, dir := staleSetup(t)
		code, _, stderr := run(t, "directory", "sign", dir, "--yes", "--admin-key", e.fps[1])
		requireStale(t, "sign of a stale proposal", code, stderr)
		requireNotSigned(t, e, 0)
	})

	t.Run("stale_proposal_install_message", func(t *testing.T) {
		e, dir := staleSetup(t)
		code, _, stderr := run(t, "directory", "install", dir)
		requireStale(t, "install of a stale proposal", code, stderr)
		requireNotSigned(t, e, 0)
		// The pre-check passes, another admin's v2 lands, and the server
		// answers 409 directory_version_chain: the same advice, with the
		// version served now, not the one the pre-check read (pre-merge
		// review, 02-09).
		e2 := newDirEnv(t, 1, 1)
		alice, _ := pendingEntry(t, webauthn.AlgES256)
		v1 := buildDir(t, nil, addUser("alice", credOf(alice)))
		e2.installDirect(t, v1)
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		carol, _ := pendingEntry(t, webauthn.AlgES256)
		proposal := buildDir(t, v1, addUser("bob", credOf(bob)))
		other := buildDir(t, v1, addUser("carol", credOf(carol)))
		otherSigs := e2.sign(t, other, 0)
		e2.post = func(w http.ResponseWriter, _ serverclient.InstallDirectoryRequest) {
			e2.doc, e2.sigs = other, otherSigs // e2.mu is held
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"directory_version_chain"}`)
		}
		code, _, stderr = run(t, "directory", "install", writeProposalDir(t, proposal, e2.sign(t, proposal, 0)))
		requireStale(t, "install refused 409 directory_version_chain", code, stderr)
	})

	t.Run("proposal_already_served", func(t *testing.T) {
		// The signer installs the proposal and the server loses its answer
		// (503). A retry must not call the proposal stale: it is the
		// version the server serves (pre-merge review, 02-09).
		e := newDirEnv(t, 1, 1)
		alice, _ := pendingEntry(t, webauthn.AlgES256)
		v1 := buildDir(t, nil, addUser("alice", credOf(alice)))
		e.installDirect(t, v1)
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		proposal := buildDir(t, v1, addUser("bob", credOf(bob)))
		dir := writeProposalDir(t, proposal, e.sign(t, proposal, 0))
		e.post = func(w http.ResponseWriter, req serverclient.InstallDirectoryRequest) {
			e.doc, e.sigs = req.Directory, req.Sigs // e.mu is held
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"signer unavailable"}`)
		}
		if code, _, stderr := run(t, "directory", "install", dir); code != 1 || !strings.Contains(stderr, "cannot reach its signer") {
			t.Fatalf("install whose answer is lost: exit %d, stderr %q", code, stderr)
		}
		e.mu.Lock()
		e.post = nil
		e.mu.Unlock()
		served := "The server already serves proposal " + dir + " as directory version 2 (SHA-256 " + trust.SHA256Hex(proposal) + "); nothing to do."
		code, stdout, stderr := run(t, "directory", "install", dir)
		if code != 0 || !strings.Contains(stdout, served) || strings.Contains(stdout+stderr, "Discard") {
			t.Fatalf("install retried after the lost answer: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		code, _, stderr = run(t, "directory", "sign", dir, "--yes")
		if code != 1 || !strings.Contains(stderr, "is already the version the server serves") || strings.Contains(stderr, "Discard") ||
			strings.Contains(stderr, "re-run") {
			t.Fatalf("sign of the served proposal: exit %d, stderr %q", code, stderr)
		}
		if _, posts := e.installed(); posts != 1 || e.agent.dirSigns() != 0 {
			t.Fatalf("%d install posts and %d directory signatures, want 1 and 0", posts, e.agent.dirSigns())
		}
		// Another admin installs the same proposal between the pre-check
		// and the post: the 409 is reported as nothing to do as well.
		e2 := newDirEnv(t, 1, 1)
		e2.installDirect(t, v1)
		sigs := e2.sign(t, proposal, 0)
		e2.post = func(w http.ResponseWriter, _ serverclient.InstallDirectoryRequest) {
			e2.doc, e2.sigs = proposal, sigs // e2.mu is held
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"directory_version_chain"}`)
		}
		dir2 := writeProposalDir(t, proposal, sigs)
		code, stdout, stderr = run(t, "directory", "install", dir2)
		if code != 0 || !strings.Contains(stdout, "The server already serves proposal "+dir2+" as directory version 2") {
			t.Fatalf("install refused 409 after the same proposal landed: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})

	t.Run("discarded_credential_install_message", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.post = func(w http.ResponseWriter, _ serverclient.InstallDirectoryRequest) {
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":"credential_not_pending"}`)
		}
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		proposal := buildDir(t, nil, addUser("bob", credOf(bob)))
		code, _, stderr := run(t, "directory", "install", writeProposalDir(t, proposal, e.sign(t, proposal, 0)))
		if code != 1 || !strings.Contains(stderr, "no longer pending") || !strings.Contains(stderr, "Discard") ||
			!strings.Contains(stderr, "keyroster user approve") || strings.Contains(stderr, "re-run this command") {
			t.Fatalf("install of a proposal binding a discarded passkey: exit %d, stderr %q", code, stderr)
		}
		e.setPending("bob", bob)
		code, _, stderr = run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 1 || !strings.Contains(stderr, "no longer pending") || !strings.Contains(stderr, "keyroster user pending bob") ||
			strings.Contains(stderr, "re-run this command") {
			t.Fatalf("direct approve refused credential_not_pending: exit %d, stderr %q", code, stderr)
		}
	})

	t.Run("approve_without_fingerprint_exits_2", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		bob, fp := pendingEntry(t, webauthn.AlgEdDSA)
		e.setPending("bob", bob)
		code, stdout, stderr := run(t, "user", "approve", "bob")
		if code != 2 || !strings.Contains(stdout, "fingerprint  "+fp) || !strings.HasSuffix(strings.TrimSpace(stderr), "re-run with --fingerprint") ||
			strings.Contains(stderr, "usage:") {
			t.Fatalf("approve without --fingerprint: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		requireNotSigned(t, e, 0)
	})

	t.Run("quorum_two_writes_proposal", func(t *testing.T) {
		e := newDirEnv(t, 2, 2)
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", bob)
		out := filepath.Join(t.TempDir(), "proposal")
		code, stdout, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes", "--out", out)
		if code != 0 || !strings.Contains(stdout, "1 of 2 admin signatures") {
			t.Fatalf("approve at quorum 2: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if _, posts := e.installed(); posts != 0 || e.agent.dirSigns() != 1 {
			t.Fatalf("%d install posts and %d directory signatures at quorum 2, want 0 and 1", posts, e.agent.dirSigns())
		}
		code, _, stderr = run(t, "directory", "sign", out, "--yes", "--admin-key", e.fps[0])
		if code != 1 || !strings.Contains(stderr, "already holds a signature by "+e.fps[0]) {
			t.Fatalf("second signature by the same admin: exit %d, stderr %q", code, stderr)
		}
		if code, stdout, stderr = run(t, "directory", "sign", out, "--yes", "--admin-key", e.fps[1]); code != 0 || !strings.Contains(stdout, "2 of 2 admin signatures") {
			t.Fatalf("co-sign: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, stdout, stderr = run(t, "directory", "install", out); code != 0 || !strings.Contains(stdout, "The server reports directory version 1 installed") {
			t.Fatalf("install: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
}

// TestDirectorySignConfirm: directory sign asks before it signs, on a
// terminal, and refuses without one unless --yes is given; a refusal
// reaches no agent and leaves directory.json.sigs as it was (02-09-R2-F10).
func TestDirectorySignConfirm(t *testing.T) {
	setup := func(t *testing.T) (*dirEnv, string, []byte) {
		t.Helper()
		e := newDirEnv(t, 2, 2)
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		doc := buildDir(t, nil, boundTo(e.bundle.InstallationID, addUser("bob", credOf(bob))))
		sig := e.sign(t, doc, 0)
		return e, writeProposalDir(t, doc, sig), sig
	}
	t.Run("directory_sign_requires_yes_without_tty", func(t *testing.T) {
		e, dir, sig := setup(t)
		code, _, stderr := run(t, "directory", "sign", dir, "--admin-key", e.fps[1])
		if code != 1 || !strings.Contains(stderr, "stdin is not a terminal") {
			t.Fatalf("sign without --yes and without a terminal: exit %d, stderr %q", code, stderr)
		}
		if n := e.agent.dirSigns(); n != 0 {
			t.Fatalf("%d directory sign requests reached the agent, want 0", n)
		}
		if got := readTestFile(t, filepath.Join(dir, proposalSigs)); !bytes.Equal(got, sig) {
			t.Fatal("directory.json.sigs changed")
		}
		if code, _, stderr := run(t, "directory", "sign", dir, "--yes", "--admin-key", e.fps[1]); code != 0 || e.agent.dirSigns() != 1 {
			t.Fatalf("sign with --yes: exit %d, %d directory sign requests; stderr %q", code, e.agent.dirSigns(), stderr)
		}
		doc := readTestFile(t, filepath.Join(dir, proposalDoc))
		admins, err := checkProposalSigs(doc, readTestFile(t, filepath.Join(dir, proposalSigs)), e.pol)
		if err != nil || len(admins) != 2 {
			t.Fatalf("checkProposalSigs after the co-signature = %v, %v; want two admins", admins, err)
		}
	})
	t.Run("directory_sign_prompt_answers", func(t *testing.T) {
		e, dir, sig := setup(t)
		useTerminal(t, true, "n\n")
		code, stdout, stderr := run(t, "directory", "sign", dir, "--admin-key", e.fps[1])
		if code != 1 || !strings.Contains(stderr, "not confirmed") || !strings.Contains(stdout, "Sign directory version 1? [y/N]") || e.agent.dirSigns() != 0 {
			t.Fatalf("sign answered n: exit %d, %d sign requests, stdout %q, stderr %q", code, e.agent.dirSigns(), stdout, stderr)
		}
		requireDiffBeforePrompt(t, stdout, "+ user bob (active)", 1)
		if got := readTestFile(t, filepath.Join(dir, proposalSigs)); !bytes.Equal(got, sig) {
			t.Fatal("directory.json.sigs changed")
		}
		useTerminal(t, true, "Y\n")
		code, stdout, stderr = run(t, "directory", "sign", dir, "--admin-key", e.fps[1])
		if code != 0 || e.agent.dirSigns() != 1 {
			t.Fatalf("sign answered y: exit %d, %d sign requests, stderr %q", code, e.agent.dirSigns(), stderr)
		}
		requireDiffBeforePrompt(t, stdout, "+ user bob (active)", 1)
		if got := readTestFile(t, filepath.Join(dir, proposalSigs)); len(got) <= len(sig) {
			t.Fatal("no signature was appended")
		}
	})
}

// requireDiffBeforePrompt fails unless stdout shows diffLine before the
// confirmation prompt for version (T-02-43: nothing is signed unseen).
func requireDiffBeforePrompt(t *testing.T, stdout, diffLine string, version int) {
	t.Helper()
	d := strings.Index(stdout, diffLine)
	p := strings.Index(stdout, fmt.Sprintf("Sign directory version %d? [y/N]", version))
	if d < 0 || p < 0 || d > p {
		t.Fatalf("stdout does not show %q before the prompt (at %d and %d):\n%s", diffLine, d, p, stdout)
	}
}

// TestEditConfirm: every directory edit (user approve, disable, enable)
// asks before it signs, after the diff, on a terminal, and refuses
// without one unless --yes is given; a refusal reaches no agent and posts
// nothing (T-02-43; pre-merge review, 02-09).
func TestEditConfirm(t *testing.T) {
	setup := func(t *testing.T) (*dirEnv, string) {
		t.Helper()
		e := newDirEnv(t, 1, 1)
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", bob)
		return e, fp
	}
	t.Run("approve_requires_yes_without_tty", func(t *testing.T) {
		e, fp := setup(t)
		code, stdout, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp)
		if code != 1 || !strings.Contains(stderr, "stdin is not a terminal") || !strings.Contains(stdout, "+ user bob (active)") {
			t.Fatalf("approve without --yes and without a terminal: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		requireNotSigned(t, e, 0)
	})
	t.Run("approve_prompt_answered_n", func(t *testing.T) {
		e, fp := setup(t)
		useTerminal(t, true, "n\n")
		code, stdout, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp)
		if code != 1 || !strings.Contains(stderr, "not confirmed") {
			t.Fatalf("approve answered n: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		requireDiffBeforePrompt(t, stdout, "+ user bob (active)", 1)
		requireNotSigned(t, e, 0)
	})
	t.Run("approve_prompt_answered_y", func(t *testing.T) {
		e, fp := setup(t)
		useTerminal(t, true, "y\n")
		code, stdout, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp)
		if code != 0 {
			t.Fatalf("approve answered y: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		requireDiffBeforePrompt(t, stdout, "+ user bob (active)", 1)
		if _, posts := e.installed(); posts != 1 || e.agent.dirSigns() != 1 {
			t.Fatalf("approve answered y: %d install posts and %d directory signatures, want 1 each", posts, e.agent.dirSigns())
		}
	})
	t.Run("disable_and_enable_ask", func(t *testing.T) {
		e, fp := setup(t)
		if code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes"); code != 0 {
			t.Fatalf("approve --yes: exit %d, stderr %q", code, stderr)
		}
		if code, _, stderr := run(t, "user", "disable", "bob"); code != 1 || !strings.Contains(stderr, "stdin is not a terminal") {
			t.Fatalf("disable without --yes and without a terminal: exit %d, stderr %q", code, stderr)
		}
		useTerminal(t, true, "\n")
		code, stdout, stderr := run(t, "user", "disable", "bob")
		if code != 1 || !strings.Contains(stderr, "not confirmed") {
			t.Fatalf("disable answered with an empty line: exit %d, stderr %q", code, stderr)
		}
		requireDiffBeforePrompt(t, stdout, "~ user bob active -> disabled", 2)
		if _, posts := e.installed(); posts != 1 || e.agent.dirSigns() != 1 {
			t.Fatalf("after the refused disable: %d install posts and %d directory signatures, want 1 each (the approve)", posts, e.agent.dirSigns())
		}
		useTerminal(t, true, "yes\n")
		if code, stdout, stderr := run(t, "user", "disable", "bob"); code != 0 || e.agent.dirSigns() != 2 {
			t.Fatalf("disable answered yes: exit %d, %d directory signatures, stdout %q, stderr %q", code, e.agent.dirSigns(), stdout, stderr)
		}
		useTerminal(t, false, "")
		if code, _, stderr := run(t, "user", "enable", "bob"); code != 1 || !strings.Contains(stderr, "stdin is not a terminal") || e.agent.dirSigns() != 2 {
			t.Fatalf("enable without --yes and without a terminal: exit %d, %d directory signatures, stderr %q", code, e.agent.dirSigns(), stderr)
		}
	})
}

// TestDirectoryPeerText: text the server chooses in the new directory
// commands never reaches the admin, except as a PeerError excerpt, and
// the CLI's own words come last (T-02-93).
func TestDirectoryPeerText(t *testing.T) {
	padded := func(code int) func(w http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, mustJSON(t, serverclient.APIError{Error: paddedAdvice}))
		}
	}
	t.Run("approve_padded_404", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.override["GET "+serverclient.AdminPendingPath("bob")] = padded(http.StatusNotFound)
		_, fp := pendingEntry(t, webauthn.AlgES256)
		code, stdout, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 1 || stdout != "" {
			t.Fatalf("exit %d, stdout %q", code, stdout)
		}
		requirePeerTextContained(t, stderr, nil)
		requireNotSigned(t, e, 0)
	})
	t.Run("approve_padded_409_install", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.override["POST "+serverclient.AdminDirectoryPath] = padded(http.StatusConflict)
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", bob)
		code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		if code != 1 {
			t.Fatalf("exit %d", code)
		}
		requirePeerTextContained(t, stderr, nil)
	})
	t.Run("approve_forged_pending_fingerprint", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		bob.Fingerprint = attackerRootPin
		e.setPending("bob", bob)
		code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", attackerRootPin, "--yes")
		if code != 1 {
			t.Fatalf("exit %d", code)
		}
		requirePeerTextContained(t, strings.ReplaceAll(stderr, attackerRootPin, ""), errBadPendingAnswer)
		requireNotSigned(t, e, 0)
	})
	t.Run("list_forged_pending_name", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.override["GET "+serverclient.AdminUsersPath] = func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(serverclient.UsersAnswer{Pending: []serverclient.PendingAccount{
				{Name: paddedAdvice, InviteExpiresAt: "2026-10-22T10:00:00Z"},
			}})
		}
		code, stdout, stderr := run(t, "user", "list")
		if code != 1 || stdout != "" {
			t.Fatalf("exit %d, stdout %q", code, stdout)
		}
		requirePeerTextContained(t, stderr, errBadUsersAnswer)
	})
	t.Run("list_ignores_server_fingerprints", func(t *testing.T) {
		// The server's own view of the users is not printed: a fingerprint
		// there would be text the server chose (an attacker's root pin).
		e := newDirEnv(t, 1, 1)
		e.override["GET "+serverclient.AdminUsersPath] = func(w http.ResponseWriter) {
			_ = json.NewEncoder(w).Encode(serverclient.UsersAnswer{DirectoryVersion: 1, Users: []serverclient.DirectoryUser{
				{Name: "mallory", Status: "active", Credentials: []serverclient.UserCredential{{Fingerprint: attackerRootPin, Alg: webauthn.AlgEdDSA}}},
			}, Pending: []serverclient.PendingAccount{}})
		}
		code, stdout, stderr := run(t, "user", "list")
		if code != 0 || strings.Contains(stdout, attackerRootPin[7:]) || strings.Contains(stdout, "mallory") {
			t.Fatalf("exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})
	t.Run("show_escapes_extension_control_bytes", func(t *testing.T) {
		// An admin-signed directory whose role extension carries escape
		// sequences reaches the terminal escaped (pre-merge review, 02-09).
		e := newDirEnv(t, 1, 1)
		alice, _ := pendingEntry(t, webauthn.AlgES256)
		e.installDirect(t, buildDir(t, nil, func(d *directory.Directory) {
			addUser("alice", credOf(alice))(d)
			d.Roles = append(d.Roles, directory.Role{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600,
				Extensions: []string{"\x1b]0;owned\x07\x1b[2Kpermit-pty"}, Users: []string{"alice"}, Groups: []string{}})
		}))
		code, stdout, stderr := run(t, "directory", "show")
		if code != 0 || strings.ContainsAny(stdout, "\x1b\x07") || !strings.Contains(stdout, `extensions=["\x1b]0;owned\a\x1b[2Kpermit-pty"]`) {
			t.Fatalf("directory show of an extension with escape sequences: exit %d, stderr %q, stdout %q", code, stderr, stdout)
		}
	})
	t.Run("install_answer_mismatch", func(t *testing.T) {
		e := newDirEnv(t, 1, 1)
		e.post = func(w http.ResponseWriter, _ serverclient.InstallDirectoryRequest) {
			_ = json.NewEncoder(w).Encode(serverclient.InstallDirectoryAnswer{Version: 1, SHA256: strings.Repeat("ab", 32), LeafIndex: 1})
		}
		bob, _ := pendingEntry(t, webauthn.AlgES256)
		proposal := buildDir(t, nil, addUser("bob", credOf(bob)))
		code, stdout, stderr := run(t, "directory", "install", writeProposalDir(t, proposal, e.sign(t, proposal, 0)))
		if code != 1 || strings.Contains(stdout+stderr, strings.Repeat("ab", 32)) {
			t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		requirePeerTextContained(t, stderr, errBadInstallAnswer)
	})
	t.Run("software_custody_banner_once", func(t *testing.T) {
		// KEY-06: one Client per command, so approve's several requests
		// print the evaluation-only banner once.
		e := newDirEnv(t, 1, 1)
		bob, fp := pendingEntry(t, webauthn.AlgES256)
		e.setPending("bob", bob)
		e.mu.Lock()
		e.custody = "user=software, host=software, machine=software, ops=software, log=software"
		e.mu.Unlock()
		code, _, stderr := run(t, "user", "approve", "bob", "--fingerprint", fp, "--yes")
		banner := custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"})
		if code != 0 || strings.Count(stderr, banner) != 1 {
			t.Fatalf("approve with software custody: exit %d, stderr:\n%s\nwant the banner once", code, stderr)
		}
	})
}

// TestDirectorySignInstallation (pre-merge review, 03-04): directory sign
// co-signs only a proposal bound to the root-verified bundle's
// installation, the signer's install rule (directory.CheckInstallation,
// D-04). A proposal for another installation, or for none while the bundle
// has an ID, is refused before the agent is asked, with directory.json.sigs
// unchanged.
func TestDirectorySignInstallation(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   func(e *dirEnv) string
		want string
	}{
		{"other_installation", func(*dirEnv) string { return "ffffffffffffffffffffffffffffffff" }, "is bound to installation ffffffffffffffffffffffffffffffff, but the root-verified trust bundle names "},
		{"no_installation", func(*dirEnv) string { return "" }, "is bound to installation none, but the root-verified trust bundle names "},
		{"this_installation", func(e *dirEnv) string { return e.bundle.InstallationID }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newDirEnv(t, 2, 2)
			bob, _ := pendingEntry(t, webauthn.AlgES256)
			doc := buildDir(t, nil, boundTo(tc.id(e), addUser("bob", credOf(bob))))
			sig := e.sign(t, doc, 0)
			dir := writeProposalDir(t, doc, sig)
			code, stdout, stderr := run(t, "directory", "sign", dir, "--yes", "--admin-key", e.fps[1])
			if tc.want == "" {
				if code != 0 || e.agent.dirSigns() != 1 || !strings.Contains(stdout, "2 of 2 admin signatures") {
					t.Fatalf("sign of a proposal for this installation: exit %d, %d sign requests, stdout %q, stderr %q", code, e.agent.dirSigns(), stdout, stderr)
				}
				return
			}
			if code != 1 || !strings.Contains(stderr, tc.want+e.bundle.InstallationID) || !strings.Contains(stderr, "Nothing was signed") {
				t.Fatalf("sign of a proposal for installation %q: exit %d, stdout %q, stderr %q", tc.id(e), code, stdout, stderr)
			}
			requireNotSigned(t, e, 0)
			if got := readTestFile(t, filepath.Join(dir, proposalSigs)); !bytes.Equal(got, sig) {
				t.Fatal("directory.json.sigs changed")
			}
		})
	}
}
