//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// rotateState is a state directory initialised by ca-init with the agent
// backend (03-12): five generated role keys held by an in-process
// ssh-agent, whose keyring stays reachable so that a test can add the key
// of a later CA generation.
type rotateState struct {
	dir     string
	db      string
	sock    string
	keyring agent.Agent
	privs   map[string]ed25519.PrivateKey // each key addKey added, by fingerprint (03-12e)
}

// startTestAgent serves an in-process ssh-agent on a Unix socket in a short
// temporary directory (socket paths are limited to 108 bytes).
func startTestAgent(t *testing.T) (string, agent.Agent) {
	t.Helper()
	sockDir, err := os.MkdirTemp("", "krrot")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	keyring := agent.NewKeyring()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = agent.ServeAgent(keyring, c)
			}()
		}
	}()
	return sock, keyring
}

// newRotateState runs ca-init (in process) with the agent backend and five
// generated Ed25519 keys. No bundle is installed.
func newRotateState(t *testing.T) *rotateState {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("doctor refuses to run as root; run the tests as a normal user")
	}
	sock, keyring := startTestAgent(t)
	st := &rotateState{sock: sock, keyring: keyring}
	args := []string{"ca-init", "--backend", "agent", "--backend-opt", "socket=" + sock}
	for _, role := range []string{"user", "host", "machine", "ops", "log"} {
		args = append(args, "--key", role+"="+st.addKey(t))
	}
	st.dir = filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(st.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st.db = filepath.Join(st.dir, "signer.db")
	args = append(args, "--state-dir", st.dir)
	if code, out := runSigner(t, args...); code != 0 {
		t.Fatalf("ca-init exited %d:\n%s", code, out)
	}
	return st
}

// addKey adds one generated Ed25519 key to the agent and returns its
// fingerprint.
func (st *rotateState) addKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	fp := ssh.FingerprintSHA256(s.PublicKey())
	if st.privs == nil {
		st.privs = map[string]ed25519.PrivateKey{}
	}
	st.privs[fp] = priv
	return fp
}

// caPubKeys reads the ca-pubkeys.json that ca-init wrote.
func (st *rotateState) caPubKeys(t *testing.T) *trust.CAPubKeys {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(st.dir, "ca-pubkeys.json"))
	if err != nil {
		t.Fatal(err)
	}
	cas, err := trust.ParseCAPubKeys(data)
	if err != nil {
		t.Fatal(err)
	}
	return cas
}

// count runs one SELECT count(*) on the state database.
func (st *rotateState) count(t *testing.T, query string, args ...any) int {
	t.Helper()
	db, err := sql.Open("sqlite", st.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// genesisDocs is a root-signed genesis bundle and policy written to a
// temporary directory, with the in-memory root that signed them.
type genesisDocs struct {
	bundle, policy string // paths; the signatures are FILE.sigs
	rootFP         string
	root           ssh.Signer
	admin          ssh.Signer
	b              *trust.Bundle
	p              *trust.Policy
}

// genesisFiles builds, as internal/signer's fixture does (GenesisBundle and
// SignDocs, which this package cannot import), a genesis bundle and policy
// for st's keys: one generated Ed25519 root at threshold 1 that is never
// written to disk, one generated admin, the profiles user 43200 s, host
// 2592000 s and machine 86400 s, issued now.
func genesisFiles(t *testing.T, st *rotateState) genesisDocs {
	t.Helper()
	g := genesisDocs{root: newTestSigner(t), admin: newTestSigner(t)}
	g.rootFP = ssh.FingerprintSHA256(g.root.PublicKey())
	g.p = &trust.Policy{Version: 1, Prev: trust.GenesisPrev, AdminQuorum: 1,
		Admins: []trust.AdminKey{{Name: "admina", Key: trust.FormatKey(g.admin.PublicKey())}}}
	for _, prof := range []struct {
		role string
		ttl  uint64
		ext  []string
	}{{trust.RoleUser, 43200, []string{"permit-pty"}}, {trust.RoleHost, 2592000, []string{}}, {trust.RoleMachine, 86400, []string{"permit-pty"}}} {
		g.p.CAProfiles = append(g.p.CAProfiles, trust.CAProfile{Role: prof.role, MaxTTLSeconds: prof.ttl,
			DefaultExtensions: prof.ext, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}})
	}
	polDoc, err := g.p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	cas := st.caPubKeys(t)
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	g.b = &trust.Bundle{
		Version: 1, Prev: trust.GenesisPrev, IssuedAt: time.Now().UTC().Truncate(time.Second).Format(trust.TimeFormat),
		Root:           trust.RootSet{Keys: []trust.RootKey{{Key: trust.FormatKey(g.root.PublicKey()), Custody: "software"}}, Threshold: 1},
		CAs:            []trust.CAEntry{},
		PolicySHA256:   trust.SHA256Hex(polDoc),
		InstallationID: hex.EncodeToString(id),
	}
	for _, role := range []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine} {
		k, _ := cas.Key(role)
		g.b.CAs = append(g.b.CAs, trust.CAEntry{Role: role, Key: k.Key, Alg: k.Alg, Custody: k.Custody, State: "active", Generation: 1})
	}
	ops, _ := cas.Key("ops")
	g.b.OpsKey = trust.KeyEntry{Key: ops.Key, Alg: ops.Alg, Custody: ops.Custody}
	lg, _ := cas.Key("log")
	logPub, err := trust.ParseKey(lg.Key)
	if err != nil {
		t.Fatal(err)
	}
	g.b.Log = trust.LogEntry{Key: lg.Key, Alg: lg.Alg, Custody: lg.Custody, Origin: tlog.Origin(logPub)}
	g.bundle, g.policy = writeSignedDocs(t, g.b, g.p, g.root)
	return g
}

// writeSignedDocs writes b and p, each with its detached signatures by
// signers, to a new temporary directory and returns the two paths.
func writeSignedDocs(t *testing.T, b *trust.Bundle, p *trust.Policy, signers ...ssh.Signer) (string, string) {
	t.Helper()
	bundle, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	var bundleSigs, policySigs []byte
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
	dir := t.TempDir()
	bp, pp := filepath.Join(dir, "bundle.json"), filepath.Join(dir, "policy.json")
	for path, data := range map[string][]byte{bp: bundle, bp + ".sigs": bundleSigs, pp: policy, pp + ".sigs": policySigs} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return bp, pp
}

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// install runs install-bundle for g's genesis documents, which must succeed.
func install(t *testing.T, st *rotateState, g genesisDocs) {
	t.Helper()
	if code, out := runSigner(t, "install-bundle", "--state-dir", st.dir, "--bundle", g.bundle, "--policy", g.policy,
		"--pin", g.rootFP, "--threshold", "1"); code != 0 {
		t.Fatalf("install-bundle exited %d:\n%s", code, out)
	}
}

// startSigner opens the database and the stored backend as serve does and
// starts a signer on them, which is the restart. It takes no state lock,
// because nothing else runs.
func startSigner(t *testing.T, st *rotateState) *signer.Signer {
	t.Helper()
	ctx := context.Background()
	db, err := signerdb.Open(st.db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, be, err := openStoredBackend(ctx, db, nil, st.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = be.Close() })
	s, err := signer.New(signer.Config{Backend: be, DB: db, AllowUIDs: []uint32{uint32(os.Getuid())}}) //nolint:gosec // G115: a uid
	if err != nil {
		t.Fatalf("signer.New: %v", err)
	}
	return s
}

// exportAndVerify runs export-log and verifies the export under rootFP at
// threshold 1. It returns the report, the export's text and Verify's error.
func exportAndVerify(t *testing.T, st *rotateState, rootFP string) (*audit.Report, string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "export.jsonl")
	if code, msg := runSigner(t, "export-log", "--state-dir", st.dir, "--out", out); code != 0 {
		t.Fatalf("export-log exited %d:\n%s", code, msg)
	}
	data, err := os.ReadFile(out) //nolint:gosec // G304: the test's own export file
	if err != nil {
		t.Fatal(err)
	}
	rep, err := audit.Verify(bytes.NewReader(data), audit.Options{Pins: []string{rootFP}, Threshold: 1})
	return rep, string(data), err
}

// TestCARotatePrepareTracer (03-12): ca-rotate prepare on the agent backend
// records generation 2 of the user CA as a row and a ca_generation entry,
// the signer restarts on generation 1, doctor and audit verify accept the
// state, and the same key is refused a second time.
func TestCARotatePrepareTracer(t *testing.T) {
	st := newRotateState(t)
	g := genesisFiles(t, st)
	install(t, st, g)

	fp := st.addKey(t)
	outFile := filepath.Join(t.TempDir(), "user-g2.json")
	code, out := runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", fp, "--out", outFile)
	if code != 0 {
		t.Fatalf("ca-rotate prepare exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "role user generation 2 "+fp) {
		t.Fatalf("prepare output lacks the generation line:\n%s", out)
	}
	data, err := os.ReadFile(outFile) //nolint:gosec // G304: the test's own prepare file
	if err != nil {
		t.Fatal(err)
	}
	var pf struct {
		Role       string `json:"role"`
		Generation uint32 `json:"generation"`
		Key        string `json:"key"`
		Alg        string `json:"alg"`
		Custody    string `json:"custody"`
	}
	if err := trust.DecodeStrict(data, &pf); err != nil {
		t.Fatalf("prepare file %q: %v", data, err)
	}
	pub, err := trust.ParseKey(pf.Key)
	if err != nil {
		t.Fatal(err)
	}
	if pf.Role != "user" || pf.Generation != 2 || ssh.FingerprintSHA256(pub) != fp || pf.Alg != ssh.KeyAlgoED25519 || pf.Custody != "agent" {
		t.Fatalf("prepare file = %+v, want user generation 2 %s ssh-ed25519 agent", pf, fp)
	}

	if code, out := runSigner(t, "doctor", "--state-dir", st.dir); code != 0 {
		t.Fatalf("doctor after prepare exited %d:\n%s", code, out)
	}

	s := startSigner(t, st)
	userCA, _ := st.caPubKeys(t).Key(trust.RoleUser)
	if got := trust.FormatKey(s.CAPublicKey(wire.CARoleUser)); got != userCA.Key {
		t.Fatalf("the restarted signer serves user CA %s, want generation 1 %s", got, userCA.Key)
	}

	rep, export, err := exportAndVerify(t, st, g.rootFP)
	if err != nil {
		t.Fatalf("audit verify of the export: %v", err)
	}
	if rep.Counts[tlog.Kind(14)] != 1 {
		t.Fatalf("the report counts %d entries of kind 14, want 1", rep.Counts[tlog.Kind(14)])
	}
	if n := strings.Count(export, `"kind":"ca_generation"`); n != 1 {
		t.Fatalf("%d export lines carry kind ca_generation, want 1", n)
	}

	code, out = runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", fp,
		"--out", filepath.Join(t.TempDir(), "again.json"))
	if code != 1 || !strings.Contains(out, "stored generation") {
		t.Fatalf("a second prepare with the same key exited %d:\n%s", code, out)
	}
	if n := st.count(t, "SELECT count(*) FROM ca_key_generations WHERE role='user'"); n != 2 {
		t.Fatalf("ca_key_generations holds %d user rows, want 2", n)
	}
}

// signs requires key to sign and its public key to verify the signature.
func signs(t *testing.T, key keystore.CAKey) {
	t.Helper()
	data := []byte("keyroster 03-12 generation check")
	sig, err := key.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.PublicKey().Verify(data, sig); err != nil {
		t.Fatal(err)
	}
}

// TestSignerRestartMixedBundle (03-12): after ca-rotate prepare the signer
// restarts, and the stored backend opens both generations of the user CA
// by generation and fingerprint and refuses each generation's number with
// the other's fingerprint. The software case is the one test of this
// package that runs scrypt at the production work factor: its
// generation-1 files are written at a low work factor, and the
// generation-2 file that prepare creates is at the production one.
func TestSignerRestartMixedBundle(t *testing.T) {
	check := func(t *testing.T, st *rotateState, fp1, fp2 string) {
		t.Helper()
		startSigner(t, st)
		ctx := context.Background()
		db, err := signerdb.Open(st.db)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		_, be, err := openStoredBackend(ctx, db, nil, st.dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = be.Close() })
		for _, k := range []struct {
			gen uint32
			fp  string
		}{{1, fp1}, {2, fp2}} {
			key, err := keystore.KeyFor(be, keystore.RoleUser, k.gen, k.fp, "")
			if err != nil {
				t.Fatalf("KeyFor generation %d: %v", k.gen, err)
			}
			if got := ssh.FingerprintSHA256(key.PublicKey()); got != k.fp {
				t.Fatalf("KeyFor generation %d returned %s, want %s", k.gen, got, k.fp)
			}
			signs(t, key)
		}
		if _, isGen := be.(keystore.GenerationBackend); isGen {
			if _, err := keystore.KeyFor(be, keystore.RoleUser, 2, fp1, ""); err == nil {
				t.Fatal("generation 2 opened generation 1's key")
			}
			if _, err := keystore.KeyFor(be, keystore.RoleUser, 1, fp2, ""); err == nil {
				t.Fatal("generation 1 opened generation 2's key")
			}
		}
	}
	t.Run("software", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("doctor refuses to run as root; run the tests as a normal user")
		}
		t.Setenv("CREDENTIALS_DIRECTORY", "")
		const passphrase = "abcdefghijklmnopqrstuvwx"
		pass := filepath.Join(t.TempDir(), "passphrase")
		if err := os.WriteFile(pass, []byte(passphrase), 0o600); err != nil {
			t.Fatal(err)
		}
		st := &rotateState{dir: filepath.Join(t.TempDir(), "state")}
		if err := os.Mkdir(st.dir, 0o700); err != nil {
			t.Fatal(err)
		}
		st.db = filepath.Join(st.dir, "signer.db")
		// The five generation-1 key files are written here at a low scrypt
		// work factor and selected with --key, so that ca-init, the
		// restart and the generation-1 opens stay cheap under -race; the
		// generation-2 file that prepare creates is the one at the
		// production work factor.
		args := []string{"ca-init", "--backend", "software", "--backend-opt", "passphrase-file=" + pass, "--state-dir", st.dir}
		for role, fp := range writeSoftwareKeys(t, st.dir, passphrase) {
			args = append(args, "--key", role+"="+fp)
		}
		if code, out := runSigner(t, args...); code != 0 {
			t.Fatalf("ca-init exited %d:\n%s", code, out)
		}
		g := genesisFiles(t, st)
		install(t, st, g)
		outFile := filepath.Join(t.TempDir(), "user-g2.json")
		code, out := runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--out", outFile)
		if code != 0 {
			t.Fatalf("ca-rotate prepare exited %d:\n%s", code, out)
		}
		user, _ := st.caPubKeys(t).Key(trust.RoleUser)
		pub1, err := trust.ParseKey(user.Key)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(outFile) //nolint:gosec // G304: the test's own prepare file
		if err != nil {
			t.Fatal(err)
		}
		var pf prepareFile
		if err := trust.DecodeStrict(data, &pf); err != nil {
			t.Fatal(err)
		}
		pub2, err := trust.ParseKey(pf.Key)
		if err != nil {
			t.Fatal(err)
		}
		if pf.Generation != 2 || pf.Custody != "software" {
			t.Fatalf("prepare file %+v", pf)
		}
		for _, name := range []string{"user.age", "user-g2.age"} {
			fi, err := os.Lstat(filepath.Join(st.dir, "software", name))
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
				t.Fatalf("%s: %v, %v; want a regular 0600 file", name, fi, err)
			}
		}
		check(t, st, ssh.FingerprintSHA256(pub1), ssh.FingerprintSHA256(pub2))
		// With generation 2 next in the bundle in force (03-12b): one more
		// production-factor decrypt of generation 2, no new key.
		installNext(t, st, g, genesisChain(t, g), pf)
		check(t, st, ssh.FingerprintSHA256(pub1), ssh.FingerprintSHA256(pub2))
	})
	t.Run("agent", func(t *testing.T) {
		st := newRotateState(t)
		g := genesisFiles(t, st)
		install(t, st, g)
		fp2, pf := prepareNext(t, st, "user")
		user, _ := st.caPubKeys(t).Key(trust.RoleUser)
		pub1, err := trust.ParseKey(user.Key)
		if err != nil {
			t.Fatal(err)
		}
		check(t, st, ssh.FingerprintSHA256(pub1), fp2)
		// With generation 2 next in the bundle in force (03-12b).
		installNext(t, st, g, genesisChain(t, g), pf)
		check(t, st, ssh.FingerprintSHA256(pub1), fp2)
	})
	// activeUser is the fingerprint of the active user CA entry of c.
	activeUser := func(t *testing.T, c chainDocs) string {
		t.Helper()
		pub, err := trust.ParseKey(trust.ActiveCA(c.b, trust.RoleUser).Key)
		if err != nil {
			t.Fatal(err)
		}
		return ssh.FingerprintSHA256(pub)
	}
	t.Run("switch_leg_issues_with_the_new_key", func(t *testing.T) {
		// 03-12e: after the switch install, the old key removed from the
		// in-process agent, retire-key and a restart, the signer issues
		// with generation 2.
		st, g, c, export := switchFlagState(t)
		if code, out := installSwitch(t, st, g, c, "--previous", export); code != 0 {
			t.Fatalf("install-bundle of the switch exited %d:\n%s", code, out)
		}
		user, _ := st.caPubKeys(t).Key(trust.RoleUser)
		pub1, err := trust.ParseKey(user.Key)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.keyring.Remove(pub1); err != nil {
			t.Fatal(err)
		}
		if code, out := retireKey(t, st, "user"); code != 0 {
			t.Fatalf("retire-key exited %d:\n%s", code, out)
		}
		s := startSigner(t, st)
		req := &wire.IssueRequest{CARole: wire.CARoleUser, SubjectKey: newTestSigner(t).PublicKey().Marshal(), Subject: "u:alice", Principals: []string{"alice"},
			ValidForSeconds: 600, CreatedAt: uint64(time.Now().Unix()), InstallationID: g.b.InstallationID} //nolint:gosec // G115: after 1970
		if _, err := rand.Read(req.RequestID[:]); err != nil {
			t.Fatal(err)
		}
		sig, err := sshsig.Sign(rand.Reader, g.admin, req.Namespace(), req.SigningBytes())
		if err != nil {
			t.Fatal(err)
		}
		req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: sig}}
		resp, err := s.Issue(context.Background(), signer.Peer{UID: uint32(os.Getuid())}, req) //nolint:gosec // G115: a uid
		if err != nil {
			t.Fatalf("issue after the switch: %v", err)
		}
		pub, err := ssh.ParsePublicKey(resp.Cert)
		if err != nil {
			t.Fatal(err)
		}
		crt, ok := pub.(*ssh.Certificate)
		if !ok {
			t.Fatalf("the response holds a %T, not a certificate", pub)
		}
		if got, want := ssh.FingerprintSHA256(crt.SignatureKey), activeUser(t, c); got != want {
			t.Fatalf("the certificate after the switch is signed by %s, want generation 2 (%s)", got, want)
		}
	})
	t.Run("unheld_active_generation_refuses_at_start", func(t *testing.T) {
		// 03-12e: after the switch install, with the old key gone and the
		// active generation 2 missing from the agent too, the start is
		// refused naming generation 2.
		st, g, c, export := switchFlagState(t)
		if code, out := installSwitch(t, st, g, c, "--previous", export); code != 0 {
			t.Fatalf("install-bundle of the switch exited %d:\n%s", code, out)
		}
		user, _ := st.caPubKeys(t).Key(trust.RoleUser)
		pub1, err := trust.ParseKey(user.Key)
		if err != nil {
			t.Fatal(err)
		}
		pub2, err := trust.ParseKey(trust.ActiveCA(c.b, trust.RoleUser).Key)
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []ssh.PublicKey{pub1, pub2} {
			if err := st.keyring.Remove(k); err != nil {
				t.Fatal(err)
			}
		}
		if err := startErr(t, st); err == nil || !strings.Contains(err.Error(), "bundle key for role user (generation 2)") {
			t.Fatalf("start without the active generation 2: %v, want the refusal naming generation 2", err)
		}
	})
}

// prepareNext adds a fresh key to st's agent and runs ca-rotate prepare
// for role with it, which must succeed; it returns the fingerprint and
// the prepare file, read strictly (03-12b).
func prepareNext(t *testing.T, st *rotateState, role string) (string, prepareFile) {
	t.Helper()
	fp := st.addKey(t)
	out := filepath.Join(t.TempDir(), role+"-next.json")
	if code, msg := runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", role, "--key", fp, "--out", out); code != 0 {
		t.Fatalf("ca-rotate prepare exited %d:\n%s", code, msg)
	}
	data, err := os.ReadFile(out) //nolint:gosec // G304: the test's own prepare file
	if err != nil {
		t.Fatal(err)
	}
	var pf prepareFile
	if err := trust.DecodeStrict(data, &pf); err != nil {
		t.Fatalf("prepare file %q: %v", data, err)
	}
	return fp, pf
}

// chainDocs is a bundle in force with its canonical bytes, and its policy.
type chainDocs struct {
	b      *trust.Bundle
	canon  []byte
	p      *trust.Policy
	polDoc []byte
}

// genesisChain is g's genesis bundle and policy as a chainDocs.
func genesisChain(t *testing.T, g genesisDocs) chainDocs {
	t.Helper()
	canon, err := g.b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	pol, err := g.p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return chainDocs{b: g.b, canon: canon, p: g.p, polDoc: pol}
}

// buildSuccessorDocs builds the successor of c under its policy with the
// CA changes next and retire (trust.BuildSuccessor), issued a second after
// c, and returns it as a chainDocs.
func buildSuccessorDocs(t *testing.T, c chainDocs, next []trust.CAEntry, retire []trust.CARef) chainDocs {
	t.Helper()
	issued, err := time.Parse(trust.TimeFormat, c.b.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.BuildSuccessor(c.b, c.canon, c.polDoc, trust.SuccessorOptions{
		Roots: c.b.Root.Keys, Threshold: 1, Policy: c.polDoc,
		IssuedAt: issued.Add(time.Second).Format(trust.TimeFormat), InstallationID: c.b.InstallationID,
		CANext: next, CARetire: retire,
	})
	if err != nil {
		t.Fatalf("BuildSuccessor: %v", err)
	}
	canon, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return chainDocs{b: b, canon: canon, p: c.p, polDoc: c.polDoc}
}

// installDocs signs c with root and runs install-bundle on it; it returns
// the exit code and the output.
func installDocs(t *testing.T, st *rotateState, c chainDocs, root ssh.Signer) (int, string) {
	t.Helper()
	bundle, policy := writeSignedDocs(t, c.b, c.p, root)
	return runSigner(t, "install-bundle", "--state-dir", st.dir, "--bundle", bundle, "--policy", policy)
}

// installNext builds the successor of c that adds the prepare file pf as a
// next entry, requires that the builder added it, installs it signed by g's
// root, which must succeed, and returns it (03-12b).
func installNext(t *testing.T, st *rotateState, g genesisDocs, c chainDocs, pf prepareFile) chainDocs {
	t.Helper()
	add := trust.CAEntry{Role: pf.Role, Key: pf.Key, Alg: pf.Alg, Custody: pf.Custody, State: "next", Generation: pf.Generation}
	next := buildSuccessorDocs(t, c, []trust.CAEntry{add}, nil)
	if len(next.b.CAs) != len(c.b.CAs)+1 || !slices.Contains(next.b.CAs, add) {
		t.Fatalf("BuildSuccessor ignored CANext: the successor lists %+v", next.b.CAs)
	}
	if code, out := installDocs(t, st, next, g.root); code != 0 {
		t.Fatalf("install-bundle of the successor adding %s generation %d as next exited %d:\n%s", pf.Role, pf.Generation, code, out)
	}
	return next
}

// TestCANextTracer (03-12b): ceremony 1 and abort end to end on one
// signer. A prepared user key is added as next by a root-signed successor,
// which installs; doctor passes, the signer restarts and still signs with
// generation 1, and the export verifies. A second next entry and a changed
// active key are refused by the chain rule with nothing written, and the
// abort installs and verifies.
func TestCANextTracer(t *testing.T) {
	st := newRotateState(t)
	g := genesisFiles(t, st)
	install(t, st, g)
	_, export0, err := exportAndVerify(t, st, g.rootFP)
	if err != nil {
		t.Fatalf("audit verify of the genesis export: %v", err)
	}
	installs0 := strings.Count(export0, `"kind":"bundle_install"`)

	fp, pf := prepareNext(t, st, "user")
	v1 := genesisChain(t, g)
	v2 := installNext(t, st, g, v1, pf)
	if len(v2.b.CAs) != 4 || v2.b.CAs[1].State != "next" || v2.b.CAs[1].Generation != 2 {
		t.Fatalf("BuildSuccessor ignored CANext: %+v", v2.b.CAs)
	}

	code, out := runSigner(t, "doctor", "--state-dir", st.dir)
	if code != 0 {
		t.Fatalf("doctor after the next install exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "next g2 "+fp) {
		t.Fatalf("doctor's generations line lacks next g2 %s:\n%s", fp, out)
	}
	userCA, _ := st.caPubKeys(t).Key(trust.RoleUser)
	if got := trust.FormatKey(startSigner(t, st).CAPublicKey(wire.CARoleUser)); got != userCA.Key {
		t.Fatalf("the restarted signer serves user CA %s, want generation 1 %s", got, userCA.Key)
	}
	if _, _, err := exportAndVerify(t, st, g.rootFP); err != nil {
		t.Fatalf("audit verify after the next install: %v", err)
	}

	// Edited on the bundle struct before signing: BuildSuccessor would
	// refuse both first.
	_, pf3 := prepareNext(t, st, "user")
	leaves := st.count(t, "SELECT count(*) FROM log_leaf")
	// 03-12c: a second next entry is refused by Validate when the bundle
	// is parsed, before the chain rule runs.
	for name, c := range map[string]struct {
		edit func(b *trust.Bundle)
		want []string
	}{
		"second_next": {edit: func(b *trust.Bundle) {
			b.CAs = slices.Insert(b.CAs, 2, trust.CAEntry{Role: pf3.Role, Key: pf3.Key, Alg: pf3.Alg, Custody: pf3.Custody, State: "next", Generation: pf3.Generation})
		}, want: []string{"more than one next entry"}},
		"active_changed": {edit: func(b *trust.Bundle) { b.CAs[0].Key = pf3.Key },
			want: []string{"trust: bundle version or prev hash breaks the chain", "CA user generation"}},
	} {
		bad := buildSuccessorDocs(t, v2, nil, nil)
		c.edit(bad.b)
		code, out := installDocs(t, st, bad, g.root)
		for _, w := range c.want {
			if code != 1 || !strings.Contains(out, w) {
				t.Fatalf("%s: install-bundle exited %d, want 1 and a refusal holding %q:\n%s", name, code, w, out)
			}
		}
		if v := st.count(t, "SELECT COALESCE(MAX(version), 0) FROM trust_bundle"); v != 2 {
			t.Fatalf("%s: installed bundle version %d after the refusal, want 2", name, v)
		}
		if n := st.count(t, "SELECT count(*) FROM log_leaf"); n != leaves {
			t.Fatalf("%s: %d leaves after the refusal, want %d", name, n, leaves)
		}
	}

	v3 := buildSuccessorDocs(t, v2, nil, []trust.CARef{{Role: "user", Generation: 2}})
	if code, out := installDocs(t, st, v3, g.root); code != 0 {
		t.Fatalf("install-bundle of the abort exited %d:\n%s", code, out)
	}
	if v3.b.CAs[1].State != "retired" {
		t.Fatalf("the abort successor lists %+v, want user generation 2 retired", v3.b.CAs)
	}
	startSigner(t, st)
	if code, out := runSigner(t, "doctor", "--state-dir", st.dir); code != 0 {
		t.Fatalf("doctor after the abort exited %d:\n%s", code, out)
	}
	_, export, err := exportAndVerify(t, st, g.rootFP)
	if err != nil {
		t.Fatalf("audit verify after the abort: %v", err)
	}
	if n := strings.Count(export, `"kind":"bundle_install"`); n != installs0+2 {
		t.Fatalf("the export holds %d bundle_install entries, want %d", n, installs0+2)
	}
}

// TestPrepareFileFormat (03-12) pins the prepare file's bytes, which the
// root ceremony of 03-12b reads: canonical JSON with the fields role,
// generation, key, alg and custody in that order and one trailing newline.
func TestPrepareFileFormat(t *testing.T) {
	t.Run("prepare_file_bytes_pinned", func(t *testing.T) {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = byte(i)
		}
		pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
		if err != nil {
			t.Fatal(err)
		}
		got, err := prepareFileBytes("user", 2, pub, "software")
		if err != nil {
			t.Fatal(err)
		}
		const want = `{"role":"user","generation":2,"key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4","alg":"ssh-ed25519","custody":"software"}` + "\n"
		if string(got) != want {
			t.Fatalf("prepare file bytes:\n got %q\nwant %q", got, want)
		}
	})
}

// writeSoftwareKeys writes the five generation-1 key files of the software
// backend into {stateDir}/software (0700, each file 0600) in the backend's
// format: an armored age file with one scrypt recipient for passphrase,
// holding the OpenSSH PEM of a generated Ed25519 key. The work factor is
// low, which the backend's decryption accepts, so that only keys the
// backend itself creates cost scrypt at the production work factor. It
// returns each role's fingerprint.
func writeSoftwareKeys(t *testing.T, stateDir, passphrase string) map[string]string {
	t.Helper()
	dir := filepath.Join(stateDir, "software")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fps := map[string]string{}
	for _, role := range []string{"user", "host", "machine", "ops", "log"} {
		fps[role] = writeSoftwareKey(t, filepath.Join(dir, role+".age"), passphrase)
	}
	return fps
}

// writeSoftwareKey writes one key file of the software backend at path, as
// writeSoftwareKeys does, and returns the key's fingerprint (03-12e: also
// a later generation's file, placed for a --key prepare).
func writeSoftwareKey(t *testing.T, path, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "keyroster test key")
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		t.Fatal(err)
	}
	recipient.SetWorkFactor(10)
	var out bytes.Buffer
	aw := armor.NewWriter(&out)
	w, err := age.Encrypt(aw, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pem.EncodeToMemory(block)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(s.PublicKey())
}

// switchFlagState is a state with ceremony 1 of the user CA installed
// (03-12e): it returns the state, the genesis documents, the root-signed
// switch successor that makes generation 2 active and generation 1
// draining (allowance 0, issued a second after ceremony 1) and an
// export-log file of the state as it is.
func switchFlagState(t *testing.T) (*rotateState, genesisDocs, chainDocs, string) {
	t.Helper()
	st := newRotateState(t)
	g := genesisFiles(t, st)
	install(t, st, g)
	_, pf := prepareNext(t, st, "user")
	v2 := installNext(t, st, g, genesisChain(t, g), pf)
	return st, g, userSwitch(t, v2), exportLog(t, st)
}

// userSwitch is the switch successor of c for the user CA (allowance 0,
// issued a second after c), built by trust.BuildSuccessor (03-12e).
func userSwitch(t *testing.T, c chainDocs) chainDocs {
	t.Helper()
	issued, err := time.Parse(trust.TimeFormat, c.b.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.BuildSuccessor(c.b, c.canon, c.polDoc, trust.SuccessorOptions{
		Roots: c.b.Root.Keys, Threshold: 1, Policy: c.polDoc,
		IssuedAt: issued.Add(time.Second).Format(trust.TimeFormat), InstallationID: c.b.InstallationID,
		CASwitch: []string{trust.RoleUser},
	})
	if err != nil {
		t.Fatalf("BuildSuccessor: %v", err)
	}
	canon, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return chainDocs{b: b, canon: canon, p: c.p, polDoc: c.polDoc}
}

// exportLog runs export-log on st and returns the export file (03-12e).
func exportLog(t *testing.T, st *rotateState) string {
	t.Helper()
	export := filepath.Join(t.TempDir(), "export.jsonl")
	if code, msg := runSigner(t, "export-log", "--state-dir", st.dir, "--out", export); code != 0 {
		t.Fatalf("export-log exited %d:\n%s", code, msg)
	}
	return export
}

// installSwitch runs install-bundle on the switch c, signed by g's root,
// with the extra arguments args.
func installSwitch(t *testing.T, st *rotateState, g genesisDocs, c chainDocs, args ...string) (int, string) {
	t.Helper()
	bundle, policy := writeSignedDocs(t, c.b, c.p, g.root)
	return runSigner(t, append([]string{"install-bundle", "--state-dir", st.dir, "--bundle", bundle, "--policy", policy}, args...)...)
}

// TestInstallBundlePreviousFlag (03-12e): install-bundle --previous reads
// the checkpoint from the last line of an export-log file (at most its
// last 1 MiB) and refuses a file without one; a switch without --previous
// is refused; the state lock's restore gate comes first; a switch install
// prints one drain line per newly draining entry.
func TestInstallBundlePreviousFlag(t *testing.T) {
	refused := func(t *testing.T, code int, out, want string) {
		t.Helper()
		if code == 0 || !strings.Contains(out, want) {
			t.Fatalf("install-bundle exited %d, want a refusal holding %q:\n%s", code, want, out)
		}
	}
	t.Run("export_file_last_line_is_the_checkpoint", func(t *testing.T) {
		st, g, c, export := switchFlagState(t)
		if code, out := installSwitch(t, st, g, c, "--previous", export); code != 0 || !strings.Contains(out, "installed bundle version 3") {
			t.Fatalf("install-bundle --previous of the export exited %d:\n%s", code, out)
		}
	})
	t.Run("no_checkpoint_line_refused", func(t *testing.T) {
		st, g, c, export := switchFlagState(t)
		data, err := os.ReadFile(export) //nolint:gosec // G304: the test's own export file
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.SplitAfter(strings.TrimRight(string(data), "\n"), "\n")
		f := filepath.Join(t.TempDir(), "leaves-only.jsonl")
		if err := os.WriteFile(f, []byte(strings.Join(lines[:len(lines)-1], "")), 0o600); err != nil { //nolint:gosec // G703: a fixed name in the test's temporary directory
			t.Fatal(err)
		}
		code, out := installSwitch(t, st, g, c, "--previous", f)
		refused(t, code, out, "install_previous_invalid")
	})
	t.Run("empty_file_refused", func(t *testing.T) {
		st, g, c, _ := switchFlagState(t)
		f := filepath.Join(t.TempDir(), "empty.jsonl")
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := installSwitch(t, st, g, c, "--previous", f)
		refused(t, code, out, "install_previous_invalid")
	})
	t.Run("oversize_last_line_refused", func(t *testing.T) {
		st, g, c, _ := switchFlagState(t)
		f := filepath.Join(t.TempDir(), "oversize.jsonl")
		if err := os.WriteFile(f, []byte(`{"checkpoint":"`+strings.Repeat("a", 1<<20)+`"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := installSwitch(t, st, g, c, "--previous", f)
		refused(t, code, out, "install_previous_invalid")
	})
	t.Run("refused_under_restore_marker", func(t *testing.T) {
		st, g, c, export := switchFlagState(t)
		if err := os.WriteFile(filepath.Join(st.dir, "restore-recovery-pending"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := installSwitch(t, st, g, c, "--previous", export)
		refused(t, code, out, "restore_recovery_pending")
	})
	t.Run("drain_line_printed", func(t *testing.T) {
		st, g, c, export := switchFlagState(t)
		var tu string
		for _, ca := range c.b.CAs {
			if ca.Role == trust.RoleUser && ca.State == "draining" {
				tu = ca.TrustedUntil
			}
		}
		code, out := installSwitch(t, st, g, c, "--previous", export)
		if want := "drain user generation 1 until " + tu + "; the last certificate the log records for it is valid until none recorded"; code != 0 || !strings.Contains(out, want) {
			t.Fatalf("install-bundle exited %d; want the line %q:\n%s", code, want, out)
		}
	})
	t.Run("switch_without_previous_refused_by_the_command", func(t *testing.T) {
		st, g, c, _ := switchFlagState(t)
		code, out := installSwitch(t, st, g, c)
		refused(t, code, out, "install_previous_required")
	})
}

// softwareSwitchState is a state directory initialised by ca-init with the
// software backend, with the user CA switched (03-12e): genesis, a
// generation-2 user key file placed at a low work factor and selected by
// ca-rotate prepare --key, ceremony 1, and the switch installed through
// install-bundle --previous. Every key file is at a low scrypt work
// factor, so no production-factor decrypt runs. It returns the state and
// the fingerprints of user generations 1 and 2.
func softwareSwitchState(t *testing.T) (*rotateState, string, string) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("doctor refuses to run as root; run the tests as a normal user")
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	const passphrase = "abcdefghijklmnopqrstuvwx"
	pass := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(pass, []byte(passphrase), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &rotateState{dir: filepath.Join(t.TempDir(), "state")}
	if err := os.Mkdir(st.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	st.db = filepath.Join(st.dir, "signer.db")
	fps := writeSoftwareKeys(t, st.dir, passphrase)
	args := []string{"ca-init", "--backend", "software", "--backend-opt", "passphrase-file=" + pass, "--state-dir", st.dir}
	for role, fp := range fps {
		args = append(args, "--key", role+"="+fp)
	}
	if code, out := runSigner(t, args...); code != 0 {
		t.Fatalf("ca-init exited %d:\n%s", code, out)
	}
	g := genesisFiles(t, st)
	install(t, st, g)
	fp2 := writeSoftwareKey(t, filepath.Join(st.dir, "software", "user-g2.age"), passphrase)
	outFile := filepath.Join(t.TempDir(), "user-g2.json")
	if code, out := runSigner(t, "ca-rotate", "prepare", "--state-dir", st.dir, "--role", "user", "--key", fp2, "--out", outFile); code != 0 {
		t.Fatalf("ca-rotate prepare exited %d:\n%s", code, out)
	}
	data, err := os.ReadFile(outFile) //nolint:gosec // G304: the test's own prepare file
	if err != nil {
		t.Fatal(err)
	}
	var pf prepareFile
	if err := trust.DecodeStrict(data, &pf); err != nil {
		t.Fatal(err)
	}
	v2 := installNext(t, st, g, genesisChain(t, g), pf)
	if code, out := installSwitch(t, st, g, userSwitch(t, v2), "--previous", exportLog(t, st)); code != 0 {
		t.Fatalf("install-bundle of the switch exited %d:\n%s", code, out)
	}
	return st, fps["user"], fp2
}

// agentSwitchState is switchFlagState with the switch installed through
// install-bundle --previous (03-12e). It returns the state and the
// fingerprint of user generation 1, whose key the agent still holds.
func agentSwitchState(t *testing.T) (*rotateState, string) {
	t.Helper()
	st, g, c, export := switchFlagState(t)
	if code, out := installSwitch(t, st, g, c, "--previous", export); code != 0 {
		t.Fatalf("install-bundle of the switch exited %d:\n%s", code, out)
	}
	user, _ := st.caPubKeys(t).Key(trust.RoleUser)
	pub, err := trust.ParseKey(user.Key)
	if err != nil {
		t.Fatal(err)
	}
	return st, ssh.FingerprintSHA256(pub)
}

// retireKey runs ca-rotate retire-key for role on st.
func retireKey(t *testing.T, st *rotateState, role string) (int, string) {
	t.Helper()
	return runSigner(t, "ca-rotate", "retire-key", "--state-dir", st.dir, "--role", role)
}

// startErr opens the state database and the stored backend as serve does
// and returns signer.New's error, closing what it opened (03-12e).
func startErr(t *testing.T, st *rotateState) error {
	t.Helper()
	ctx := context.Background()
	db, err := signerdb.Open(st.db)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	_, be, err := openStoredBackend(ctx, db, nil, st.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = be.Close() }()
	_, err = signer.New(signer.Config{Backend: be, DB: db, AllowUIDs: []uint32{uint32(os.Getuid())}}) //nolint:gosec // G115: a uid
	return err
}

// TestRetireKey (03-12e, RK-01 to RK-09, the command): ca-rotate
// retire-key removes the software backend's draining key file and nothing
// else, prints for the agent the ssh-add commands through the signer's own
// agent socket and checks again, and refuses under the restore marker,
// without a draining entry, when the active key does not sign, and on a
// backend that cannot hold a generation.
func TestRetireKey(t *testing.T) {
	refused := func(t *testing.T, code int, out, want string) {
		t.Helper()
		if code == 0 || !strings.Contains(out, want) {
			t.Fatalf("retire-key exited %d, want a refusal holding %q:\n%s", code, want, out)
		}
	}
	keyFiles := func(t *testing.T, st *rotateState) []string {
		t.Helper()
		m, err := filepath.Glob(filepath.Join(st.dir, "software", "*.age"))
		if err != nil {
			t.Fatal(err)
		}
		for i := range m {
			m[i] = filepath.Base(m[i])
		}
		slices.Sort(m)
		return m
	}
	t.Run("software_removes_draining_files_only", func(t *testing.T) {
		st, fp1, _ := softwareSwitchState(t)
		if err := startErr(t, st); err == nil || !strings.Contains(err.Error(), "draining_key_still_usable: the backend still holds generation 1 of the user CA ("+fp1+")") {
			t.Fatalf("serve before retire-key: %v, want draining_key_still_usable naming generation 1", err)
		}
		code, out := retireKey(t, st, "user")
		if code != 0 || !strings.Contains(out, "role user generation 1 "+fp1+": removed\n") || !strings.Contains(out, "retire-key: no draining key of role user is held\n") {
			t.Fatalf("retire-key exited %d:\n%s", code, out)
		}
		if got, want := strings.Join(keyFiles(t, st), " "), "host.age log.age machine.age ops.age user-g2.age"; got != want {
			t.Fatalf("key files after retire-key: %s, want %s", got, want)
		}
		if err := startErr(t, st); err != nil {
			t.Fatalf("serve after retire-key: %v", err)
		}
	})
	t.Run("agent_prints_command_and_rechecks", func(t *testing.T) {
		st, fp1 := agentSwitchState(t)
		// A certificate identity of the draining key, beside the plain key.
		priv1 := st.privs[fp1]
		pub1, err := ssh.NewPublicKey(priv1.Public())
		if err != nil {
			t.Fatal(err)
		}
		c := &ssh.Certificate{Key: pub1, CertType: ssh.UserCert, KeyId: "identity", ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
		if err := c.SignCert(rand.Reader, newTestSigner(t)); err != nil { //nolint:forbidigo // a certificate identity of a CA key in the test agent, which cert.Build cannot make
			t.Fatal(err)
		}
		if err := st.keyring.Add(agent.AddedKey{PrivateKey: priv1, Certificate: c}); err != nil {
			t.Fatal(err)
		}
		keyLine := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub1)), "\n")
		certLine := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(c)), "\n")
		head := "role user generation 1 " + fp1 + ": "
		code, out := retireKey(t, st, "user")
		want := head + "still held by the agent; write this public key line into retire-user-g1 and run: SSH_AUTH_SOCK=" + st.sock + " ssh-add -d retire-user-g1\n" +
			keyLine + "\n" +
			head + "write this certificate line into retire-user-g1-cert.pub and run: SSH_AUTH_SOCK=" + st.sock + " ssh-add -d retire-user-g1-cert.pub\n" +
			certLine + "\n" +
			"run retire-key again\n"
		if code != 1 || !strings.Contains(out, want) || !strings.Contains(out, "retire_key_incomplete: 1 draining generation(s) of role user are still held") {
			t.Fatalf("retire-key while the agent holds the key exited %d, want 1 with\n%s\ngot:\n%s", code, want, out)
		}
		// Remove exactly the printed identities through the printed socket.
		lines := strings.Split(out, "\n")
		var sock string
		var printed []string
		for i, l := range lines {
			if !strings.HasPrefix(l, head) || i+1 >= len(lines) {
				continue
			}
			_, after, ok := strings.Cut(l, "SSH_AUTH_SOCK=")
			if !ok {
				continue
			}
			sock, _, _ = strings.Cut(after, " ")
			printed = append(printed, lines[i+1])
		}
		if sock != st.sock || len(printed) != 2 {
			t.Fatalf("parsed socket %q and lines %q from the output", sock, printed)
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		client := agent.NewClient(conn)
		for i, l := range printed {
			k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
			if err != nil {
				t.Fatalf("printed line %q: %v", l, err)
			}
			if err := client.Remove(k); err != nil {
				t.Fatalf("remove %q through %s: %v", l, sock, err)
			}
			code, out := retireKey(t, st, "user")
			if i == 0 && (code != 1 || !strings.Contains(out, head+"write this certificate line")) {
				t.Fatalf("retire-key with only the certificate identity left exited %d:\n%s", code, out)
			}
			if i == 1 && (code != 0 || !strings.Contains(out, head+"not held\n") || !strings.Contains(out, "retire-key: no draining key of role user is held\n")) {
				t.Fatalf("retire-key after both identities were removed exited %d:\n%s", code, out)
			}
		}
	})
	t.Run("refused_under_restore_marker", func(t *testing.T) {
		st, _ := agentSwitchState(t)
		if err := os.WriteFile(filepath.Join(st.dir, "restore-recovery-pending"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		code, out := retireKey(t, st, "user")
		refused(t, code, out, "restore_recovery_pending")
	})
	t.Run("no_draining_entry_refused", func(t *testing.T) {
		st, _, _, _ := switchFlagState(t)
		code, out := retireKey(t, st, "user")
		refused(t, code, out, "no_draining_entry")
	})
	t.Run("active_unusable_refused_nothing_removed", func(t *testing.T) {
		st, _, _ := softwareSwitchState(t)
		if err := os.Remove(filepath.Join(st.dir, "software", "user-g2.age")); err != nil {
			t.Fatal(err)
		}
		code, out := retireKey(t, st, "user")
		refused(t, code, out, "active_key_unusable")
		if got, want := strings.Join(keyFiles(t, st), " "), "host.age log.age machine.age ops.age user.age"; got != want {
			t.Fatalf("key files after the refusal: %s, want %s", got, want)
		}
	})
	t.Run("second_run_is_a_no_op", func(t *testing.T) {
		st, fp1, _ := softwareSwitchState(t)
		if code, out := retireKey(t, st, "user"); code != 0 {
			t.Fatalf("the first retire-key exited %d:\n%s", code, out)
		}
		before := keyFiles(t, st)
		code, out := retireKey(t, st, "user")
		if code != 0 || !strings.Contains(out, "role user generation 1 "+fp1+": not held\n") || !strings.Contains(out, "retire-key: no draining key of role user is held\n") {
			t.Fatalf("the second retire-key exited %d:\n%s", code, out)
		}
		if after := keyFiles(t, st); !slices.Equal(before, after) {
			t.Fatalf("the second retire-key changed the key files: %v, then %v", before, after)
		}
	})
	t.Run("unsupported_backend_refused", func(t *testing.T) {
		st, _ := agentSwitchState(t)
		for _, name := range []string{"tpm", "piv"} {
			db, err := sql.Open("sqlite", st.db)
			if err != nil {
				t.Fatal(err)
			}
			_, err = db.Exec(`UPDATE backend_config SET name = ? WHERE id = 1`, name)
			_ = db.Close()
			if err != nil {
				t.Fatal(err)
			}
			code, out := retireKey(t, st, "user")
			refused(t, code, out, "rotation_not_supported_on_backend")
		}
	})
}
