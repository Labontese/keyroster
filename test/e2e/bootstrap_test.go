//go:build e2e || e2e_pkcs11 || e2e_tpm

package e2e

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/trust"
)

// bootstrapOpts configures bootstrapSigner. The zero value is the default
// setup: the agent backend with five generated Ed25519 role keys in a
// private ssh-agent, a generated Ed25519 root (custody software) in its own
// agent, and one generated admin key in a third agent.
type bootstrapOpts struct {
	// Backend is the keystore backend for ca-init (default "agent").
	Backend string
	// BackendOpts are its --backend-opt values. For the default agent
	// backend, socket defaults to a fresh agent holding generated keys.
	BackendOpts map[string]string
	// RoleKeys maps role (user, host, machine, ops, log) to the SHA256
	// fingerprint of an existing key in the backend. When empty and the
	// backend is not "agent", ca-init runs without --key so that a
	// Provisioner backend (TPM, PIV) creates the keys.
	RoleKeys map[string]string
	// RootAgentSocket, RootFingerprint and RootCustody name an existing
	// root key in an ssh-agent (for example a FIDO or PIV root). Empty
	// means a generated Ed25519 root with custody software.
	RootAgentSocket, RootFingerprint, RootCustody string
	// AdminQuorum is the genesis policy's admin quorum; that many admin
	// keys are generated (default 1).
	AdminQuorum int
}

// signerEnv is a running keyroster-signer under a root-signed genesis
// bundle, and everything a test needs to use and check it.
type signerEnv struct {
	Socket    string // signer socket
	StateDir  string
	CAPubkeys string // ca-pubkeys.json written by ca-init
	BundleDir string // bundle.json, policy.json and their .sigs

	RootFingerprints []string
	AdminAgent       string   // ssh-agent socket holding the admin keys
	AdminFingerprint string   // the first admin key
	AdminFPs         []string // every admin key, AdminFingerprint first

	// Public key files (OpenSSH .pub) of the online keys, from
	// ca-pubkeys.json.
	UserCAPub, HostCAPub, MachineCAPub, OpsPub, LogPub string
	// RoleAgent is the agent socket holding generated role keys, and
	// RoleKeyFiles their private key files ("" for a Provisioner backend
	// or caller-supplied keys).
	RoleAgent    string
	RoleKeyFiles map[string]string
}

// roleNames is the fixed role order of ca-init.
var roleNames = []string{"user", "host", "machine", "ops", "log"}

// newRoleKeys generates one Ed25519 key per role in dir, loads them into
// the agent at agentSock and returns the fingerprints and key files.
func newRoleKeys(t *testing.T, agentSock, dir string) (fps, files map[string]string) {
	t.Helper()
	fps, files = map[string]string{}, map[string]string{}
	for _, role := range roleNames {
		key := filepath.Join(dir, role+"_key")
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", role+"-key", "-f", key)
		sshAdd(t, agentSock, key)
		fps[role], files[role] = fingerprint(t, key+".pub"), key
	}
	return fps, files
}

// bootstrapSigner runs the full trust setup and starts the signer:
// keyroster-signer ca-init, keyroster root genesis-policy, keyroster root
// sign, keyroster-signer install-bundle --pin, and keyroster-signer serve.
func bootstrapSigner(t *testing.T, opts bootstrapOpts) *signerEnv {
	t.Helper()
	env := prepareSigner(t, opts)
	env.serve(t)
	return env
}

// prepareSigner is bootstrapSigner without serve.
func prepareSigner(t *testing.T, opts bootstrapOpts) *signerEnv {
	t.Helper()
	env := initSigner(t, opts)
	env.signGenesis(t, opts)
	if code, out := env.signerCmd(t, env.installArgs()...); code != 0 {
		t.Fatalf("install-bundle exited %d:\n%s", code, out)
	}
	return env
}

// initSigner creates the state directory and runs ca-init, generating keys
// as opts says. It does not install a bundle.
func initSigner(t *testing.T, opts bootstrapOpts) *signerEnv {
	t.Helper()
	base := shortTempDir(t)
	keys := t.TempDir()
	env := &signerEnv{
		Socket:    filepath.Join(base, "signer.sock"),
		StateDir:  filepath.Join(base, "state"),
		BundleDir: filepath.Join(keys, "bundle"),
	}
	if err := os.Mkdir(env.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	env.CAPubkeys = filepath.Join(env.StateDir, "ca-pubkeys.json")

	backend := opts.Backend
	if backend == "" {
		backend = "agent"
	}
	bopts := map[string]string{}
	for k, v := range opts.BackendOpts {
		bopts[k] = v
	}
	roleKeys := opts.RoleKeys
	if backend == "agent" && len(roleKeys) == 0 {
		if bopts["socket"] == "" {
			bopts["socket"] = startAgent(t)
		}
		env.RoleAgent = bopts["socket"]
		roleKeys, env.RoleKeyFiles = newRoleKeys(t, env.RoleAgent, keys)
	}
	args := []string{"ca-init", "--state-dir", env.StateDir, "--backend", backend}
	for _, k := range sortedKeys(bopts) {
		args = append(args, "--backend-opt", k+"="+bopts[k])
	}
	for _, role := range roleNames {
		if fp, ok := roleKeys[role]; ok {
			args = append(args, "--key", role+"="+fp)
		}
	}
	if code, out := env.signerCmd(t, args...); code != 0 {
		t.Fatalf("ca-init exited %d:\n%s", code, out)
	}
	data, err := os.ReadFile(env.CAPubkeys)
	if err != nil {
		t.Fatal(err)
	}
	cas, err := trust.ParseCAPubKeys(data)
	if err != nil {
		t.Fatalf("ca-pubkeys.json: %v", err)
	}
	for role, dst := range map[string]*string{"user": &env.UserCAPub, "host": &env.HostCAPub, "machine": &env.MachineCAPub, "ops": &env.OpsPub, "log": &env.LogPub} {
		k, _ := cas.Key(role)
		*dst = filepath.Join(keys, role+"_pub.pub")
		if err := os.WriteFile(*dst, []byte(k.Key+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

// signGenesis writes the genesis policy (with generated admin keys) and the
// root-signed genesis bundle into env.BundleDir.
func (e *signerEnv) signGenesis(t *testing.T, opts bootstrapOpts) {
	t.Helper()
	dir := filepath.Dir(e.BundleDir)

	quorum := max(opts.AdminQuorum, 1)
	e.AdminAgent = startAgent(t)
	policy := filepath.Join(dir, "genesis-policy.json")
	args := []string{"root", "genesis-policy", "--admin-quorum", strconv.Itoa(quorum), "--out", policy}
	for i := range quorum {
		name := "admin" + strconv.Itoa(i)
		key := filepath.Join(dir, name)
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key)
		sshAdd(t, e.AdminAgent, key)
		e.AdminFPs = append(e.AdminFPs, fingerprint(t, key+".pub"))
		args = append(args, "--admin", name+"="+key+".pub")
	}
	e.AdminFingerprint = e.AdminFPs[0]
	if code, out := keyrosterWithAgent(t, "", args...); code != 0 {
		t.Fatalf("root genesis-policy exited %d:\n%s", code, out)
	}

	rootSock, rootFP, custody := opts.RootAgentSocket, opts.RootFingerprint, opts.RootCustody
	if rootSock == "" {
		rootSock = startAgent(t)
		key := filepath.Join(dir, "root")
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "root", "-f", key)
		sshAdd(t, rootSock, key)
		rootFP, custody = fingerprint(t, key+".pub"), "software"
	}
	rootPub := agentKey(t, rootSock, rootFP)
	roots := filepath.Join(dir, "roots.pub")
	if err := os.WriteFile(roots, []byte(trust.FormatKey(rootPub)+" custody="+custody+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.RootFingerprints = []string{rootFP}

	sign := []string{"root", "sign", "--ca-pubkeys", e.CAPubkeys, "--policy", policy, "--roots", roots,
		"--threshold", "1", "--out-dir", e.BundleDir, "--agent-key", rootFP}
	// A first run with a wrong confirmation writes bundle.json and signs
	// nothing; the second confirms the real hash prefix.
	if code, out := keyrosterWithAgent(t, rootSock, append(sign, "--confirm", "00000000")...); code != 1 || !strings.Contains(out, "nothing was signed") {
		t.Fatalf("root sign with a wrong confirmation exited %d:\n%s", code, out)
	}
	bundle, err := os.ReadFile(filepath.Join(e.BundleDir, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	if code, out := keyrosterWithAgent(t, rootSock, append(sign, "--confirm", trust.SHA256Hex(bundle)[:8])...); code != 0 {
		t.Fatalf("root sign exited %d:\n%s", code, out)
	}
}

// installArgs returns the install-bundle arguments for env's genesis
// bundle, pinned to its roots.
func (e *signerEnv) installArgs() []string {
	args := []string{"install-bundle", "--state-dir", e.StateDir, "--threshold", "1",
		"--bundle", filepath.Join(e.BundleDir, "bundle.json"), "--policy", filepath.Join(e.BundleDir, "policy.json")}
	for _, fp := range e.RootFingerprints {
		args = append(args, "--pin", fp)
	}
	return args
}

// serve starts keyroster-signer serve on env's state and waits for its
// socket. The test's uid is the only allowed peer.
func (e *signerEnv) serve(t *testing.T) {
	t.Helper()
	_, log, done := startDaemon(t, "keyroster-signer", envWithout("SSH_AUTH_SOCK"), signerBin,
		"serve", "--state-dir", e.StateDir, "--socket", e.Socket, "--allow-uid", strconv.Itoa(os.Getuid()))
	waitFor(t, "signer socket", done, log, func() bool { return isSocket(e.Socket) })
}

// signerCmd runs keyroster-signer once and returns its exit code and
// combined output.
func (e *signerEnv) signerCmd(t *testing.T, args ...string) (int, string) {
	t.Helper()
	return runBin(t, signerBin, "", args...)
}

// runIssue runs keyroster ca issue against the signer, authorized by the
// first admin key from the admin agent, and returns its exit code and
// output.
func (e *signerEnv) runIssue(t *testing.T, args ...string) (int, string) {
	t.Helper()
	full := append([]string{"ca", "issue", "--socket", e.Socket, "--admin-key", e.AdminFingerprint}, args...)
	return keyrosterWithAgent(t, e.AdminAgent, full...)
}

// issue is runIssue that fails the test unless ca issue succeeds.
func (e *signerEnv) issue(t *testing.T, args ...string) string {
	t.Helper()
	code, out := e.runIssue(t, args...)
	if code != 0 {
		t.Fatalf("keyroster ca issue %v exited %d:\n%s", args, code, out)
	}
	return out
}

// exportLog runs keyroster-signer export-log on env's state and returns
// the export file.
func (e *signerEnv) exportLog(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "log.jsonl")
	if code, b := e.signerCmd(t, "export-log", "--state-dir", e.StateDir, "--out", out); code != 0 {
		t.Fatalf("keyroster-signer export-log exited %d:\n%s", code, b)
	}
	return out
}

// keyrosterWithAgent runs the keyroster CLI with SSH_AUTH_SOCK set to
// agentSock ("" for none).
func keyrosterWithAgent(t *testing.T, agentSock string, args ...string) (int, string) {
	t.Helper()
	return runBin(t, keyrosterBin, agentSock, args...)
}

// runBin runs bin with SSH_AUTH_SOCK set to agentSock ("" for none) and
// returns its exit code and combined output.
func runBin(t *testing.T, bin, agentSock string, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: the binaries under test
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	if agentSock != "" {
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+agentSock)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("%s %v: %v\n%s", filepath.Base(bin), args, err, out)
	}
	return 0, string(out)
}

// agentKey returns the public key with fingerprint fp from the agent at
// sock.
func agentKey(t *testing.T, sock, fp string) ssh.PublicKey {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Marshal())
		if err == nil && ssh.FingerprintSHA256(pub) == fp {
			return pub
		}
	}
	t.Fatalf("agent %s holds no key %s", sock, fp)
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
