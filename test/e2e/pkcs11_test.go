//go:build e2e_pkcs11

// PKCS#11 HSM path (KEY-03, D-11, D-12): the five online keys live in a
// SoftHSM2 token (the CI stand-in for a YubiHSM 2) and the root key in a
// second token (the stand-in for a PIV root). keyroster never loads a
// PKCS#11 module: each token is reached only through its own OpenSSH
// ssh-agent, which runs the vendor module in ssh-pkcs11-helper.
//
// Environment, besides KEYROSTER_OPENSSH_PREFIX (sshd, ssh, ssh-keygen):
//
//	KEYROSTER_SSH_AGENT       ssh-agent binary that holds the tokens; ssh-add
//	                          is taken from the same directory
//	KEYROSTER_PKCS11_KEYTYPE  p256 or ed25519 (Ed25519 needs ssh-agent 10.1+)
//
// softhsm2 and opensc (pkcs11-tool) must be installed; see
// scripts/softhsm-setup.sh.
package e2e

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/trust"
)

// pkcs11Labels maps each ca-init role to its key label in the CA token.
var pkcs11Labels = map[string]string{"user": "user-ca", "host": "host-ca", "machine": "machine-ca", "ops": "ops", "log": "log"}

// pkcs11Agent returns KEYROSTER_SSH_AGENT. Like the rest of e2e it fails,
// never skips, when unset.
func pkcs11Agent(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("KEYROSTER_SSH_AGENT")
	if bin == "" {
		t.Fatal("KEYROSTER_SSH_AGENT is not set; point it at the ssh-agent that should hold the PKCS#11 tokens (/usr/bin/ssh-agent or an OpenSSH 10.1+ build)")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("KEYROSTER_SSH_AGENT=%s: %v", bin, err)
	}
	return bin
}

// pkcs11KeyType returns KEYROSTER_PKCS11_KEYTYPE (p256 or ed25519).
func pkcs11KeyType(t *testing.T) string {
	t.Helper()
	kt := os.Getenv("KEYROSTER_PKCS11_KEYTYPE")
	if kt != "p256" && kt != "ed25519" {
		t.Fatalf("KEYROSTER_PKCS11_KEYTYPE=%q; want p256 or ed25519", kt)
	}
	return kt
}

// pkcs11Alg is the SSH key algorithm of a softhsm-setup.sh key type.
func pkcs11Alg(keytype string) string {
	if keytype == "ed25519" {
		return ssh.KeyAlgoED25519
	}
	return ssh.KeyAlgoECDSA256
}

// softHSM is the output of scripts/softhsm-setup.sh.
type softHSM struct {
	module   string // PKCS#11 module, symlinks resolved
	caConf   string // SOFTHSM2_CONF that sees only the keyroster-ca token
	rootConf string // SOFTHSM2_CONF that sees only the keyroster-root token
	askpass  string
	pin      string // read only to prove it never leaks
	output   string // the setup script's stdout and stderr
}

// newSoftHSM runs scripts/softhsm-setup.sh into a fresh directory.
func newSoftHSM(t *testing.T, keytype string) *softHSM {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "hsm")
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("bash", filepath.Join(root, "scripts", "softhsm-setup.sh"), dir, keytype) //nolint:gosec // G204: the repository's setup script
	cmd.Env = envWithout("SOFTHSM2_CONF")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("softhsm-setup.sh %s: %v\n%s%s", keytype, err, stdout.String(), stderr.String())
	}
	h := &softHSM{
		module:   strings.TrimSpace(stdout.String()),
		caConf:   filepath.Join(dir, "ca", "softhsm2.conf"),
		rootConf: filepath.Join(dir, "root", "softhsm2.conf"),
		askpass:  filepath.Join(dir, "askpass.sh"),
		output:   stdout.String() + stderr.String(),
	}
	for path, want := range map[string]os.FileMode{filepath.Join(dir, "pin"): 0o600, h.askpass: 0o700} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%s has mode %v, want %v", path, fi.Mode().Perm(), want)
		}
	}
	pin, err := os.ReadFile(filepath.Join(dir, "pin")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	h.pin = strings.TrimSpace(string(pin))
	if len(h.pin) < 16 {
		t.Fatalf("softhsm-setup.sh wrote a %d-character PIN, want a random one of at least 16", len(h.pin))
	}
	return h
}

// tokenAgent is a private ssh-agent with one SoftHSM2 token loaded.
type tokenAgent struct {
	sock    string
	pid     int
	log     *syncBuffer // the agent's stdout and stderr
	addOut  string      // ssh-add -s output
	addCode int
}

// startTokenAgent runs agentBin on a private socket with the module as its
// only allowed provider (-P) and SOFTHSM2_CONF=conf, then loads the token
// with ssh-add -s. The PIN reaches ssh-add only through SSH_ASKPASS.
func (h *softHSM) startTokenAgent(t *testing.T, agentBin, conf string) *tokenAgent {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "agent.sock")
	env := append(envWithout("SSH_AUTH_SOCK", "SOFTHSM2_CONF"), "SOFTHSM2_CONF="+conf)
	cmd, log, done := startDaemon(t, "pkcs11 ssh-agent", env, agentBin, "-D", "-a", sock, "-P", h.module)
	waitFor(t, "pkcs11 ssh-agent socket", done, log, func() bool { return isSocket(sock) })
	a := &tokenAgent{sock: sock, pid: cmd.Process.Pid, log: log}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	add := exec.CommandContext(ctx, filepath.Join(filepath.Dir(agentBin), "ssh-add"), "-s", h.module) //nolint:gosec // G204: OpenSSH under test
	add.Env = append(envWithout("SSH_AUTH_SOCK", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "DISPLAY", "SOFTHSM2_CONF"),
		"SSH_AUTH_SOCK="+sock, "SSH_ASKPASS="+h.askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=:0")
	out, err := add.CombinedOutput()
	a.addOut = string(out)
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("ssh-add -s: %v\n%s", err, out)
		}
		a.addCode = ee.ExitCode()
	}
	return a
}

// mustLoad fails the test unless ssh-add -s succeeded.
func (a *tokenAgent) mustLoad(t *testing.T) {
	t.Helper()
	if a.addCode != 0 {
		t.Fatalf("ssh-add -s exited %d:\n%s\n--- agent log ---\n%s", a.addCode, a.addOut, a.log.String())
	}
}

// tokenKeys lists the token's public keys by label with ssh-keygen -D,
// which reads only public objects (no PIN).
func (h *softHSM) tokenKeys(t *testing.T, conf string) map[string]ssh.PublicKey {
	t.Helper()
	cmd := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh-keygen"), "-D", h.module) //nolint:gosec // G204: OpenSSH under test
	cmd.Env = append(envWithout("SSH_AUTH_SOCK", "SOFTHSM2_CONF"), "SOFTHSM2_CONF="+conf)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ssh-keygen -D: %v\n%s", err, stderr.String())
	}
	keys := map[string]ssh.PublicKey{}
	for rest := out; len(bytes.TrimSpace(rest)) > 0; {
		pub, label, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			t.Fatalf("ssh-keygen -D output: %v\n%s", err, out)
		}
		if _, dup := keys[label]; dup {
			t.Fatalf("ssh-keygen -D lists label %q twice:\n%s", label, out)
		}
		keys[label] = pub
		rest = next
	}
	return keys
}

// agentFingerprints returns the fingerprints of every key the agent holds.
func agentFingerprints(t *testing.T, sock string) map[string]bool {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		t.Fatalf("list agent keys: %v", err)
	}
	fps := map[string]bool{}
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Marshal())
		if err != nil {
			t.Fatalf("agent key: %v", err)
		}
		fps[ssh.FingerprintSHA256(pub)] = true
	}
	return fps
}

// pkcs11Setup is a SoftHSM2 CA token and root token, each loaded into its
// own ssh-agent.
type pkcs11Setup struct {
	hsm     *softHSM
	keytype string
	ca      *tokenAgent
	root    *tokenAgent
	roleFPs map[string]string // role -> fingerprint of its token key
	rootFP  string
}

// newPKCS11Setup creates both tokens, loads each into its own agent and
// checks that neither agent holds the other token's keys.
func newPKCS11Setup(t *testing.T, agentBin, keytype string) *pkcs11Setup {
	t.Helper()
	h := newSoftHSM(t, keytype)
	s := &pkcs11Setup{hsm: h, keytype: keytype, roleFPs: map[string]string{}}
	s.ca = h.startTokenAgent(t, agentBin, h.caConf)
	s.ca.mustLoad(t)
	s.root = h.startTokenAgent(t, agentBin, h.rootConf)
	s.root.mustLoad(t)

	caKeys, rootKeys := h.tokenKeys(t, h.caConf), h.tokenKeys(t, h.rootConf)
	if len(caKeys) != len(pkcs11Labels) || len(rootKeys) != 1 {
		t.Fatalf("tokens hold %d CA and %d root keys, want %d and 1", len(caKeys), len(rootKeys), len(pkcs11Labels))
	}
	for _, role := range roleNames {
		pub, ok := caKeys[pkcs11Labels[role]]
		if !ok {
			t.Fatalf("CA token has no key labelled %q", pkcs11Labels[role])
		}
		if pub.Type() != pkcs11Alg(keytype) {
			t.Fatalf("token key %s is %s, want %s", pkcs11Labels[role], pub.Type(), pkcs11Alg(keytype))
		}
		s.roleFPs[role] = ssh.FingerprintSHA256(pub)
	}
	rootPub, ok := rootKeys["root"]
	if !ok {
		t.Fatal("root token has no key labelled root")
	}
	s.rootFP = ssh.FingerprintSHA256(rootPub)

	// T-01-47: the CA agent holds exactly the five CA keys and the root
	// agent exactly the root key.
	caHeld, rootHeld := agentFingerprints(t, s.ca.sock), agentFingerprints(t, s.root.sock)
	if len(caHeld) != len(roleNames) || len(rootHeld) != 1 || !rootHeld[s.rootFP] || caHeld[s.rootFP] {
		t.Fatalf("agent separation broken: CA agent holds %v, root agent holds %v", caHeld, rootHeld)
	}
	for role, fp := range s.roleFPs {
		if !caHeld[fp] || rootHeld[fp] {
			t.Fatalf("role %s key %s: in CA agent %v, in root agent %v", role, fp, caHeld[fp], rootHeld[fp])
		}
	}
	return s
}

// opts returns bootstrapSigner options for the PKCS#11-backed signer:
// backend agent with custody pkcs11-agent, roles pinned by fingerprint,
// and the token-held root declared custody=pkcs11.
func (s *pkcs11Setup) opts() bootstrapOpts {
	return bootstrapOpts{
		Backend:         "agent",
		BackendOpts:     map[string]string{"socket": s.ca.sock, "custody": "pkcs11-agent"},
		RoleKeys:        s.roleFPs,
		RootAgentSocket: s.root.sock,
		RootFingerprint: s.rootFP,
		RootCustody:     "pkcs11",
	}
}

// assertNoPINLeak fails when the PIN appears in any captured output or in
// the command line of any running process (agents, ssh-pkcs11-helper).
func (s *pkcs11Setup) assertNoPINLeak(t *testing.T, outputs ...string) {
	t.Helper()
	pin := s.hsm.pin
	named := map[string]string{
		"softhsm-setup.sh output": s.hsm.output,
		"CA agent log":            s.ca.log.String(),
		"root agent log":          s.root.log.String(),
		"CA ssh-add output":       s.ca.addOut,
		"root ssh-add output":     s.root.addOut,
	}
	for i, o := range outputs {
		named["output "+strconv.Itoa(i)] = o
	}
	for name, o := range named {
		if strings.Contains(o, pin) {
			t.Errorf("the PKCS#11 PIN appears in the %s", name)
		}
	}
	procs, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, p := range procs {
		b, err := os.ReadFile(p) //nolint:gosec // procfs
		if err != nil {
			continue // the process exited
		}
		checked++
		if bytes.Contains(b, []byte(pin)) {
			t.Errorf("the PKCS#11 PIN appears in the arguments of %s: %q", p, bytes.ReplaceAll(b, []byte{0}, []byte{' '}))
		}
	}
	if checked == 0 {
		t.Error("no /proc/*/cmdline was readable; the argument check proved nothing")
	}
}

// verifiedBundle verifies env's genesis bundle against the pinned root and
// returns it.
func verifiedBundle(t *testing.T, env *signerEnv) *trust.Bundle {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(env.BundleDir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b, _, err := trust.VerifyGenesisBundle(read("bundle.json"), read("bundle.json.sigs"),
		read("policy.json"), read("policy.json.sigs"), env.RootFingerprints, 1)
	if err != nil {
		t.Fatalf("verify genesis bundle: %v", err)
	}
	return b
}

// assertPKCS11Bundle checks that the verified bundle records custody
// pkcs11-agent and the token's algorithm for all five online keys, and
// custody pkcs11 for the root.
func assertPKCS11Bundle(t *testing.T, b *trust.Bundle, keytype string) {
	t.Helper()
	alg := pkcs11Alg(keytype)
	if len(b.CAs) != 3 {
		t.Fatalf("bundle lists %d CAs, want user, host and machine", len(b.CAs))
	}
	for _, ca := range b.CAs {
		if ca.Custody != "pkcs11-agent" || ca.Alg != alg {
			t.Errorf("bundle CA %s: custody %q alg %q, want pkcs11-agent %s", ca.Role, ca.Custody, ca.Alg, alg)
		}
	}
	if b.OpsKey.Custody != "pkcs11-agent" || b.OpsKey.Alg != alg {
		t.Errorf("bundle ops key: custody %q alg %q, want pkcs11-agent %s", b.OpsKey.Custody, b.OpsKey.Alg, alg)
	}
	if b.Log.Custody != "pkcs11-agent" || b.Log.Alg != alg {
		t.Errorf("bundle log key: custody %q alg %q, want pkcs11-agent %s", b.Log.Custody, b.Log.Alg, alg)
	}
	if len(b.Root.Keys) != 1 || b.Root.Keys[0].Custody != "pkcs11" || !strings.HasPrefix(b.Root.Keys[0].Key, alg+" ") {
		t.Errorf("bundle root = %+v, want one %s key with custody pkcs11", b.Root.Keys, alg)
	}
}

var pkcs11SigningCA = regexp.MustCompile(`(?m)^\s*Signing CA: \S+ (SHA256:\S+)`)

// pkcs11IssueAndLogin issues a user certificate through env and logs in
// with it on a fresh sshd that trusts env's user CA. It returns the issue
// output.
func pkcs11IssueAndLogin(t *testing.T, env *signerEnv, userCAFP string) string {
	t.Helper()
	login := currentUser(t)
	userKey := filepath.Join(t.TempDir(), "id_ed25519")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user", "-f", userKey)
	out := env.issue(t, "--pubkey", userKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	certFile := userKey + "-cert.pub"
	if m := pkcs11SigningCA.FindStringSubmatch(sshKeygen(t, "-L", "-f", certFile)); m == nil || m[1] != userCAFP {
		t.Fatalf("certificate not signed by the token's user CA %s (ssh-keygen -L match %q)", userCAFP, m)
	}
	port := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {login}}})
	if code, output := sshLogin(t, loginOptions{Port: port, Key: userKey, Cert: certFile, User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with the PKCS#11-signed certificate exited %d:\n%s", code, output)
	}
	return out
}

// pkcs11AuditVerify exports env's log and verifies it pinned to the root,
// expecting entries log entries and issued issuances. It returns the
// output of audit verify.
func pkcs11AuditVerify(t *testing.T, env *signerEnv, entries, issued int) string {
	t.Helper()
	export := env.exportLog(t)
	args := []string{"audit", "verify", "--threshold", "1"}
	for _, fp := range env.RootFingerprints {
		args = append(args, "--pin", fp)
	}
	code, out := keyrosterWithAgent(t, "", append(args, export)...)
	want := "OK: " + strconv.Itoa(entries) + " entries,"
	if code != 0 || !strings.HasPrefix(out, want) || !strings.Contains(out, "issued "+strconv.Itoa(issued)) {
		t.Fatalf("keyroster audit verify exited %d, want %q and issued %d:\n%s", code, want, issued, out)
	}
	return out
}

// runPKCS11FullFlow is the KEY-03 flow: ca-init over the PKCS#11 agent,
// root-signed genesis bundle (root in its own token), install-bundle,
// serve, an admin-signed ca issue, an sshd login and audit verify --pin.
func runPKCS11FullFlow(t *testing.T, agentBin, keytype string) {
	t.Helper()
	s := newPKCS11Setup(t, agentBin, keytype)
	env := bootstrapSigner(t, s.opts())

	assertPKCS11Bundle(t, verifiedBundle(t, env), keytype)
	issueOut := pkcs11IssueAndLogin(t, env, s.roleFPs["user"])
	// ca_init, bundle_install and the issuance.
	verifyOut := pkcs11AuditVerify(t, env, 3, 1)
	t.Logf("keyroster audit verify:\n%s", verifyOut)
	s.assertNoPINLeak(t, issueOut, verifyOut)

	// D-WR-03: custody pkcs11-agent is declared, not verified; doctor says
	// so and never reports it as hardware custody.
	code, out := env.signerCmd(t, "doctor", "--state-dir", env.StateDir)
	if code != 0 || !strings.Contains(out, "\nINFO pkcs11_custody_declared: keys user, host, machine, ops, log are declared custody pkcs11-agent") || strings.Contains(out, "OK custody:") {
		t.Fatalf("doctor exited %d; want 0, the pkcs11_custody_declared line and no OK custody line:\n%s", code, out)
	}
}

// TestPKCS11FullFlow runs the KEY-03 flow with KEYROSTER_PKCS11_KEYTYPE
// keys in KEYROSTER_SSH_AGENT.
func TestPKCS11FullFlow(t *testing.T) {
	runPKCS11FullFlow(t, pkcs11Agent(t), pkcs11KeyType(t))
}

// agentVersion returns the major and minor OpenSSH version of agentBin,
// read from the ssh client installed next to it.
func agentVersion(t *testing.T, agentBin string) (major, minor int) {
	t.Helper()
	out, err := exec.Command(filepath.Join(filepath.Dir(agentBin), "ssh"), "-V").CombinedOutput() //nolint:gosec // G204: OpenSSH under test
	if err != nil {
		t.Fatalf("ssh -V next to %s: %v\n%s", agentBin, err, out)
	}
	m := regexp.MustCompile(`OpenSSH_(\d+)\.(\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("ssh -V next to %s: no OpenSSH version in %q", agentBin, out)
	}
	major, _ = strconv.Atoi(m[1])
	minor, _ = strconv.Atoi(m[2])
	return major, minor
}

// TestPKCS11Ed25519 runs the KEY-03 flow with Ed25519 keys in the token
// when KEYROSTER_SSH_AGENT is OpenSSH 10.1 or newer. An older agent cannot
// use Ed25519 PKCS#11 keys (research Pitfall 2); there the test asserts
// that the agent refuses them, so the documented minimum stays true.
func TestPKCS11Ed25519(t *testing.T) {
	agentBin := pkcs11Agent(t)
	if major, minor := agentVersion(t, agentBin); major < 10 || (major == 10 && minor < 1) {
		h := newSoftHSM(t, "ed25519")
		a := h.startTokenAgent(t, agentBin, h.caConf)
		if held := agentFingerprints(t, a.sock); a.addCode == 0 || len(held) != 0 {
			t.Fatalf("ssh-agent %d.%d loaded Ed25519 PKCS#11 keys (ssh-add exit %d, %d keys); the 10.1 minimum in docs/backends/pkcs11.md is out of date",
				major, minor, a.addCode, len(held))
		}
		t.Logf("ssh-agent %d.%d refuses Ed25519 PKCS#11 keys as expected (needs 10.1+): %s", major, minor, strings.TrimSpace(a.addOut))
		return
	}
	runPKCS11FullFlow(t, agentBin, "ed25519")
}

// TestPKCS11RootSignsBundle: a root key held in its own PKCS#11 token (the
// PIV-root stand-in, D-11) signs the genesis bundle through ssh-agent, the
// verified bundle records custody pkcs11, and install-bundle refuses the
// same bundle and policy before the root's signatures exist.
func TestPKCS11RootSignsBundle(t *testing.T) {
	keytype := pkcs11KeyType(t)
	s := newPKCS11Setup(t, pkcs11Agent(t), keytype)
	opts := s.opts()
	env := initSigner(t, opts)
	env.signGenesis(t, opts)

	// The same bundle.json and policy.json with no signatures yet: what
	// root sign had written before it appended the root's signatures.
	unsigned := t.TempDir()
	for _, name := range []string{"bundle.json", "policy.json"} {
		data, err := os.ReadFile(filepath.Join(env.BundleDir, name)) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(unsigned, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(unsigned, name+".sigs"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"install-bundle", "--state-dir", env.StateDir, "--threshold", "1", "--pin", s.rootFP,
		"--bundle", filepath.Join(unsigned, "bundle.json"), "--policy", filepath.Join(unsigned, "policy.json")}
	code, out := env.signerCmd(t, args...)
	if code == 0 || !strings.Contains(out, "signature") {
		t.Fatalf("install-bundle without the root's signature exited %d, want a refusal about the missing signature:\n%s", code, out)
	}
	t.Logf("install-bundle without the root signature exited %d (expected):\n%s", code, out)

	// With the root's signatures the same documents install, which also
	// shows that the refused attempt installed nothing.
	if code, out := env.signerCmd(t, env.installArgs()...); code != 0 {
		t.Fatalf("install-bundle with the root's signature exited %d:\n%s", code, out)
	}
	assertPKCS11Bundle(t, verifiedBundle(t, env), keytype)
	env.serve(t)
	pkcs11IssueAndLogin(t, env, s.roleFPs["user"])
	pkcs11AuditVerify(t, env, 3, 1)
}

// TestPKCS11CAInitTwiceRefused: a second ca-init with the same PKCS#11 keys
// on an initialised state directory is refused and changes nothing (KEY-03
// idempotency): the same ca_keys rows, ca-pubkeys.json and audit log.
func TestPKCS11CAInitTwiceRefused(t *testing.T) {
	s := newPKCS11Setup(t, pkcs11Agent(t), pkcs11KeyType(t))
	// Without serve: a running serve holds the state directory lock, and
	// ca-init would then be refused by the lock before it reaches the
	// initialised-state check this test is about.
	env := prepareSigner(t, s.opts())

	caKeys := func() []signerdb.CAKey {
		t.Helper()
		db, err := signerdb.OpenReadOnly(filepath.Join(env.StateDir, "signer.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		keys, err := db.CAKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return keys
	}
	readFile := func(path string) []byte {
		t.Helper()
		b, err := os.ReadFile(path) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	keysBefore, pubBefore := caKeys(), readFile(env.CAPubkeys)
	logBefore := readFile(env.exportLog(t))

	args := []string{"ca-init", "--state-dir", env.StateDir, "--backend", "agent",
		"--backend-opt", "custody=pkcs11-agent", "--backend-opt", "socket=" + s.ca.sock}
	for _, role := range roleNames {
		args = append(args, "--key", role+"="+s.roleFPs[role])
	}
	// The default output, ca-pubkeys.json, already exists.
	if code, out := env.signerCmd(t, args...); code == 0 {
		t.Fatalf("second ca-init exited 0:\n%s", out)
	}
	// With a fresh output path the refusal comes from the initialised
	// state itself, and the output file is not left behind.
	fresh := filepath.Join(t.TempDir(), "ca-pubkeys.json")
	code, out := env.signerCmd(t, append(args, "--out", fresh)...)
	if code == 0 || !strings.Contains(out, "already initialised") {
		t.Fatalf("second ca-init with --out exited %d, want a refusal naming the initialised state:\n%s", code, out)
	}
	if _, err := os.Stat(fresh); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("refused ca-init left %s behind (stat: %v)", fresh, err)
	}

	keysAfter := caKeys()
	if len(keysAfter) != len(keysBefore) {
		t.Fatalf("ca_keys has %d rows after the refused ca-init, want %d", len(keysAfter), len(keysBefore))
	}
	for i := range keysBefore {
		b, a := keysBefore[i], keysAfter[i]
		if b.Role != a.Role || !bytes.Equal(b.PublicKey, a.PublicKey) || b.Alg != a.Alg || b.Custody != a.Custody {
			t.Fatalf("ca_keys row %d changed: %+v -> %+v", i, b, a)
		}
	}
	if !bytes.Equal(readFile(env.CAPubkeys), pubBefore) {
		t.Fatal("ca-pubkeys.json changed after the refused ca-init")
	}
	if !bytes.Equal(readFile(env.exportLog(t)), logBefore) {
		t.Fatal("the audit log changed after the refused ca-init")
	}
	// ca_init and bundle_install only.
	pkcs11AuditVerify(t, env, 2, 0)
}

// TestPKCS11ConcurrentIssue: eight admin-signed ca issue calls in parallel
// against the PKCS#11-backed signer each get a distinct, valid certificate
// (KEY-03 concurrency; the agent connection is used under one mutex).
func TestPKCS11ConcurrentIssue(t *testing.T) {
	const n = 8
	s := newPKCS11Setup(t, pkcs11Agent(t), pkcs11KeyType(t))
	env := bootstrapSigner(t, s.opts())
	login := currentUser(t)

	keys := make([]string, n)
	for i := range keys {
		keys[i] = filepath.Join(t.TempDir(), "id_ed25519")
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user"+strconv.Itoa(i), "-f", keys[i])
	}
	type result struct {
		code int
		out  string
		err  error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			// No t.Fatal off the test goroutine: collect, then check below.
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, keyrosterBin, "ca", "issue", "--socket", env.Socket, //nolint:gosec // G204: the binary under test
				"--admin-key", env.AdminFingerprint, "--pubkey", keys[i]+".pub",
				"--principal", login, "--subject", "u:"+login, "--ttl", "10m")
			cmd.Env = append(envWithout("SSH_AUTH_SOCK"), "SSH_AUTH_SOCK="+env.AdminAgent)
			out, err := cmd.CombinedOutput()
			r := result{out: string(out)}
			var ee *exec.ExitError
			switch {
			case errors.As(err, &ee):
				r.code = ee.ExitCode()
			case err != nil:
				r.err = err
			}
			results[i] = r
		})
	}
	wg.Wait()

	serials := map[string]int{}
	serialRE := regexp.MustCompile(`(?m)^\s*Serial: (\d+)$`)
	for i, r := range results {
		if r.err != nil || r.code != 0 {
			t.Fatalf("concurrent ca issue %d exited %d (%v):\n%s", i, r.code, r.err, r.out)
		}
		info := sshKeygen(t, "-L", "-f", keys[i]+"-cert.pub")
		if m := pkcs11SigningCA.FindStringSubmatch(info); m == nil || m[1] != s.roleFPs["user"] {
			t.Fatalf("certificate %d not signed by the token's user CA:\n%s", i, info)
		}
		m := serialRE.FindStringSubmatch(info)
		if m == nil {
			t.Fatalf("certificate %d: no serial in ssh-keygen -L:\n%s", i, info)
		}
		if j, dup := serials[m[1]]; dup {
			t.Fatalf("certificates %d and %d share serial %s", j, i, m[1])
		}
		serials[m[1]] = i
	}

	// Every certificate must be valid for sshd; eight logins are cheap, so
	// check them all.
	port := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {login}}})
	for i, key := range keys {
		if code, out := sshLogin(t, loginOptions{Port: port, Key: key, Cert: key + "-cert.pub", User: login, Command: "true"}); code != 0 {
			t.Fatalf("ssh login with concurrent certificate %d exited %d:\n%s", i, code, out)
		}
	}
	// ca_init, bundle_install and eight issuances.
	pkcs11AuditVerify(t, env, 2+n, n)
}
