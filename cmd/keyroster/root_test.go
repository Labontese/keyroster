package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// useKeyring routes the CLI's ssh-agent connection to an in-memory keyring
// served over net.Pipe, so the ceremony runs on every OS without a socket.
func useKeyring(t *testing.T, keys ...ed25519.PrivateKey) {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	prev := dialAgent
	dialAgent = func() (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_ = agent.ServeAgent(keyring, server)
			_ = server.Close()
		}()
		return client, nil
	}
	t.Cleanup(func() { dialAgent = prev })
}

// ceremony holds the input files of a root signing.
type ceremony struct {
	dir, caPubkeys, policy, roots, out string
	rootKeys                           []ed25519.PrivateKey
}

// newCeremony writes a genesis policy (via keyroster root genesis-policy),
// ca-pubkeys.json with fresh P-256 keys, and roots.pub with n fresh
// Ed25519 software roots.
func newCeremony(t *testing.T, n int) *ceremony {
	t.Helper()
	c := newCeremonyInputs(t)
	var roots bytes.Buffer
	for range n {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		roots.WriteString(trust.FormatKey(pub) + " custody=software\n")
		c.rootKeys = append(c.rootKeys, priv)
	}
	writeTestFile(t, c.roots, roots.Bytes())
	return c
}

// newCeremonyInputs writes the genesis policy and ca-pubkeys.json; roots.pub
// is left to the caller.
func newCeremonyInputs(t *testing.T) *ceremony {
	t.Helper()
	dir := t.TempDir()
	c := &ceremony{
		dir:       dir,
		caPubkeys: filepath.Join(dir, "ca-pubkeys.json"),
		policy:    filepath.Join(dir, "genesis-policy.json"),
		roots:     filepath.Join(dir, "roots.pub"),
		out:       filepath.Join(dir, "out"),
	}
	_, adminPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminPub, err := ssh.NewPublicKey(adminPriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	adminFile := filepath.Join(dir, "alice.pub")
	writeTestFile(t, adminFile, ssh.MarshalAuthorizedKey(adminPub))
	if code, _, stderr := run(t, "root", "genesis-policy", "--admin", "alice="+adminFile, "--out", c.policy); code != 0 {
		t.Fatalf("genesis-policy exit %d: %s", code, stderr)
	}

	cas := &trust.CAPubKeys{}
	for _, role := range trust.CAPubKeyRoles {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		cas.Keys = append(cas.Keys, trust.CAPubKey{Role: role, Key: trust.FormatKey(pub), Alg: pub.Type(), Custody: "tpm"})
	}
	data, err := cas.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, c.caPubkeys, data)
	return c
}

func (c *ceremony) fingerprint(t *testing.T, i int) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(c.rootKeys[i].Public())
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(pub)
}

func (c *ceremony) sign(t *testing.T, threshold string, root int, extra ...string) (int, string, string) {
	t.Helper()
	args := []string{"root", "sign", "--ca-pubkeys", c.caPubkeys, "--policy", c.policy, "--roots", c.roots,
		"--threshold", threshold, "--out-dir", c.out, "--agent-key", c.fingerprint(t, root)}
	return run(t, append(args, extra...)...)
}

func (c *ceremony) verify(t *testing.T, threshold string, pins ...string) (int, string, string) {
	t.Helper()
	args := []string{"trust", "verify", "--threshold", threshold,
		"--bundle", filepath.Join(c.out, "bundle.json"), "--policy", filepath.Join(c.out, "policy.json")}
	for _, p := range pins {
		args = append(args, "--pin", p)
	}
	return run(t, args...)
}

func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := dispatch(context.Background(), args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // G703: a path inside the test's TempDir
		t.Fatal(err)
	}
}

// TestRootSignTrustVerifyRoundTrip runs the whole ceremony in process:
// genesis-policy, root sign with an agent-held root (hash-prefix
// confirmation on stdin), trust verify against the pinned fingerprint, a
// one-byte tamper refused, and stock ssh-keygen accepting the signatures.
func TestRootSignTrustVerifyRoundTrip(t *testing.T) {
	c := newCeremony(t, 1)
	useKeyring(t, c.rootKeys...)
	fixed := time.Date(2026, 10, 5, 7, 0, 0, 0, time.UTC)
	prevNow := ceremonyNow
	ceremonyNow = func() time.Time { return fixed }
	t.Cleanup(func() { ceremonyNow = prevNow })

	// A wrong confirmation signs nothing but leaves the bundle to inspect.
	code, _, stderr := c.sign(t, "1", 0, "--confirm", "00000000")
	if code != 1 || !strings.Contains(stderr, "nothing was signed") {
		t.Fatalf("wrong confirmation: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(c.out, "bundle.json.sigs")); !os.IsNotExist(err) {
		t.Fatalf("a signature file exists after a refused confirmation (stat error %v)", err)
	}
	bundle, err := os.ReadFile(filepath.Join(c.out, "bundle.json")) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}
	if b, err := trust.ParseBundle(bundle); err != nil || b.IssuedAt != "2026-10-05T07:00:00Z" {
		t.Fatalf("bundle.json: %v (issued_at %v)", err, b)
	}
	hash := trust.SHA256Hex(bundle)

	// The operator types the hash prefix on stdin.
	prevIn := ceremonyInput
	ceremonyInput = strings.NewReader(hash[:8] + "\n")
	t.Cleanup(func() { ceremonyInput = prevIn })
	code, stdout, stderr := c.sign(t, "1", 0)
	if code != 0 {
		t.Fatalf("root sign exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "SOFTWARE ROOT:") {
		t.Fatalf("an --agent-key root labelled custody=software signed without the SOFTWARE ROOT banner:\n%s", stderr)
	}
	for _, want := range []string{"Bundle SHA-256: " + hash, "SOFTWARE ROOT", c.fingerprint(t, 0)} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("root sign output lacks %q:\n%s", want, stdout)
		}
	}

	// Signing twice with the same root is refused.
	if code, _, stderr := c.sign(t, "1", 0, "--confirm", hash[:8]); code != 1 || !strings.Contains(stderr, "already holds a signature") {
		t.Fatalf("second signature by the same root: exit %d, stderr %q", code, stderr)
	}

	code, stdout, stderr = c.verify(t, "1", c.fingerprint(t, 0))
	if code != 0 {
		t.Fatalf("trust verify exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "OK: signed by 1 of 1 pinned roots (threshold 1)") {
		t.Fatalf("trust verify output:\n%s", stdout)
	}

	// Stock ssh-keygen accepts both signatures under their namespaces.
	if keygen := sshKeygenOracle(t); keygen != "" {
		pub, err := ssh.NewPublicKey(c.rootKeys[0].Public())
		if err != nil {
			t.Fatal(err)
		}
		allowed := filepath.Join(c.dir, "allowed_signers")
		writeTestFile(t, allowed, append([]byte("root "), ssh.MarshalAuthorizedKey(pub)...))
		for _, doc := range []struct{ file, ns string }{{"bundle.json", trust.NamespaceBundle}, {"policy.json", trust.NamespacePolicy}} {
			msg, err := os.ReadFile(filepath.Join(c.out, doc.file)) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(keygen, "-Y", "verify", "-f", allowed, "-I", "root", "-n", doc.ns, "-s", filepath.Join(c.out, doc.file+".sigs")) //nolint:gosec // G204: test oracle
			cmd.Stdin = bytes.NewReader(msg)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("ssh-keygen -Y verify %s: %v\n%s", doc.file, err, out)
			}
		}
	}

	// One changed byte in bundle.json (a still-valid issued_at) breaks the
	// signature, and verification fails.
	tampered := bytes.Clone(bundle)
	i := bytes.Index(tampered, []byte("T07:00:00Z")) + len("T07:00:0")
	tampered[i] = '1'
	writeTestFile(t, filepath.Join(c.out, "bundle.json"), tampered)
	if code, _, stderr := c.verify(t, "1", c.fingerprint(t, 0)); code != 1 || !strings.Contains(stderr, "threshold not met") {
		t.Fatalf("trust verify of a tampered bundle: exit %d, want 1 for a missing signature (stderr %q)", code, stderr)
	}
}

// TestRootSignTwoOfTwoRoundTrip checks a threshold-2 ceremony: one root's
// signature is not enough, both are.
func TestRootSignTwoOfTwoRoundTrip(t *testing.T) {
	c := newCeremony(t, 2)
	useKeyring(t, c.rootKeys...)
	pins := []string{c.fingerprint(t, 0), c.fingerprint(t, 1)}

	code, _, stderr := c.sign(t, "2", 0, "--confirm", "00000000")
	if code != 1 {
		t.Fatalf("expected the wrong confirmation to fail: %s", stderr)
	}
	bundle, err := os.ReadFile(filepath.Join(c.out, "bundle.json")) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}
	prefix := trust.SHA256Hex(bundle)[:8]
	if code, _, stderr := c.sign(t, "2", 0, "--confirm", prefix); code != 0 {
		t.Fatalf("first root sign: exit %d: %s", code, stderr)
	}
	if code, _, stderr := c.verify(t, "2", pins...); code != 1 || !strings.Contains(stderr, "threshold not met") {
		t.Fatalf("verify with 1 of 2 signatures: exit %d, stderr %q", code, stderr)
	}
	if code, _, stderr := c.sign(t, "2", 1, "--confirm", prefix); code != 0 {
		t.Fatalf("second root sign: exit %d: %s", code, stderr)
	}
	code, stdout, stderr := c.verify(t, "2", pins...)
	if code != 0 || !strings.Contains(stdout, "OK: signed by 2 of 2 pinned roots (threshold 2)") {
		t.Fatalf("verify with 2 of 2 signatures: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// Pinning only one of the two roots does not match the bundle's root set.
	if code, _, stderr := c.verify(t, "1", pins[0]); code != 1 || !strings.Contains(stderr, "pinned root fingerprints do not match") {
		t.Fatalf("verify with a partial pin set: exit %d, stderr %q", code, stderr)
	}
}

// sshKeygenOracle returns ssh-keygen's path, or "" (test continues without
// the oracle step) when it is missing, unless KEYROSTER_REQUIRE_ORACLE=1
// (CI), where a missing oracle fails the test.
func sshKeygenOracle(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("ssh-keygen")
	if err != nil {
		if os.Getenv("KEYROSTER_REQUIRE_ORACLE") == "1" {
			t.Fatalf("ssh-keygen not found and KEYROSTER_REQUIRE_ORACLE=1: %v", err)
		}
		t.Logf("ssh-keygen not found; skipping the oracle step: %v", err)
		return ""
	}
	return p
}

// softwareRoot is a root created by keyroster root init.
type softwareRoot struct {
	path, pub, fingerprint, passphrase string
}

// passphraseFD returns, as a --passphrase-fd argument, the read end of a
// pipe that holds pass and a newline; the test owns and closes the pipe.
func passphraseFD(t *testing.T, pass string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if _, err := w.WriteString(pass + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return strconv.FormatUint(uint64(r.Fd()), 10)
}

// initSoftwareRoot runs keyroster root init with pass on a pipe and checks
// its outputs: an armored age file (mode 0600 outside Windows), a .pub
// labelled custody=software, the fingerprint on stdout and the SOFTWARE
// ROOT banner on stderr.
func initSoftwareRoot(t *testing.T, dir, name, pass string) softwareRoot {
	t.Helper()
	r := softwareRoot{path: filepath.Join(dir, name+".age"), passphrase: pass}
	r.pub = r.path + ".pub"
	code, stdout, stderr := run(t, "root", "init", "--out", r.path, "--passphrase-fd", passphraseFD(t, pass))
	if code != 0 {
		t.Fatalf("root init %s: exit %d: %s", name, code, stderr)
	}
	if !strings.HasPrefix(stderr, "SOFTWARE ROOT:") || !strings.Contains(stderr, "docs/runbooks/root-ceremony.md") {
		t.Fatalf("root init stderr lacks the SOFTWARE ROOT banner:\n%s", stderr)
	}
	enc, err := os.ReadFile(r.path) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(enc, []byte("-----BEGIN AGE ENCRYPTED FILE-----\n")) {
		t.Fatalf("%s does not start with the age armor header: %q", r.path, enc[:min(len(enc), 40)])
	}
	if bytes.Contains(enc, []byte("OPENSSH PRIVATE KEY")) {
		t.Fatalf("%s holds a plaintext private key", r.path)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(r.path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v, want 0600", r.path, st.Mode().Perm())
		}
	}
	pubLine, err := os.ReadFile(r.pub) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(pubLine), " custody=software\n") {
		t.Fatalf("%s = %q, want a key line ending in custody=software", r.pub, pubLine)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubLine)
	if err != nil {
		t.Fatal(err)
	}
	r.fingerprint = ssh.FingerprintSHA256(pub)
	if strings.TrimSpace(stdout) != r.fingerprint {
		t.Fatalf("root init stdout = %q, want the fingerprint %s", stdout, r.fingerprint)
	}
	return r
}

// typeHashPrefix answers the next confirmation prompt with the hash prefix
// of the bundle.json that root sign has written by the time it asks.
func typeHashPrefix(t *testing.T, outDir string) {
	t.Helper()
	prev := ceremonyInput
	ceremonyInput = &hashPrefixReader{path: filepath.Join(outDir, "bundle.json")}
	t.Cleanup(func() { ceremonyInput = prev })
}

type hashPrefixReader struct {
	path string
	r    io.Reader
}

func (h *hashPrefixReader) Read(p []byte) (int, error) {
	if h.r == nil {
		data, err := os.ReadFile(h.path) //nolint:gosec // G304: test file
		if err != nil {
			return 0, err
		}
		h.r = strings.NewReader(trust.SHA256Hex(data)[:8] + "\n")
	}
	return h.r.Read(p)
}

// signWithKey runs root sign --key with the root's passphrase on a pipe.
func (c *ceremony) signWithKey(t *testing.T, threshold string, r softwareRoot, extra ...string) (int, string, string) {
	t.Helper()
	typeHashPrefix(t, c.out)
	args := []string{"root", "sign", "--ca-pubkeys", c.caPubkeys, "--policy", c.policy, "--roots", c.roots,
		"--threshold", threshold, "--out-dir", c.out, "--key", r.path, "--passphrase-fd", passphraseFD(t, r.passphrase)}
	return run(t, append(args, extra...)...)
}

// writeRoots concatenates the roots' .pub files into the ceremony's
// roots.pub.
func (c *ceremony) writeRoots(t *testing.T, roots ...softwareRoot) {
	t.Helper()
	var all []byte
	for _, r := range roots {
		data, err := os.ReadFile(r.pub) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, data...)
	}
	writeTestFile(t, c.roots, all)
}

// TestSoftwareRoot runs the homelab ceremony end to end (D-10): two
// age-encrypted software roots from keyroster root init, root sign --key
// with root A at threshold 1, and trust verify pinning both roots. The
// subtests reuse the two roots (each scrypt run costs about a second, many
// more under the race detector) for the refusals and the 1-of-2 flow.
func TestSoftwareRoot(t *testing.T) {
	c := newCeremonyInputs(t)
	a := initSoftwareRoot(t, c.dir, "root-a", "correct horse battery staple A")
	b := initSoftwareRoot(t, c.dir, "root-b", "correct horse battery staple B")
	c.writeRoots(t, a, b)

	code, stdout, stderr := c.signWithKey(t, "1", a)
	if code != 0 {
		t.Fatalf("root sign --key: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stderr, "SOFTWARE ROOT:") {
		t.Fatalf("root sign --key printed no SOFTWARE ROOT banner:\n%s", stderr)
	}
	for _, want := range []string{a.fingerprint, b.fingerprint, "custody=software", "signed "} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("root sign output lacks %q:\n%s", want, stdout)
		}
	}
	code, stdout, stderr = c.verify(t, "1", a.fingerprint, b.fingerprint)
	if code != 0 {
		t.Fatalf("trust verify: exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "OK: signed by 1 of 2 pinned roots (threshold 1)") || !strings.Contains(stdout, "signed by root "+a.fingerprint) {
		t.Fatalf("trust verify output:\n%s", stdout)
	}

	sigsOf := func(t *testing.T, dir string) [2][]byte {
		t.Helper()
		var out [2][]byte
		for i, f := range []string{"bundle.json.sigs", "policy.json.sigs"} {
			data, err := os.ReadFile(filepath.Join(dir, f)) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			out[i] = data
		}
		return out
	}

	t.Run("wrong_passphrase", func(t *testing.T) {
		before := sigsOf(t, c.out)
		wrong := b
		wrong.passphrase = b.passphrase + "!"
		code, _, stderr := c.signWithKey(t, "1", wrong)
		if code != 1 || !strings.Contains(stderr, "nothing was signed") {
			t.Fatalf("wrong passphrase: exit %d, stderr %q", code, stderr)
		}
		if after := sigsOf(t, c.out); !bytes.Equal(after[0], before[0]) || !bytes.Equal(after[1], before[1]) {
			t.Fatal("a signature file changed after a wrong passphrase")
		}
	})

	t.Run("short_passphrase", func(t *testing.T) {
		path := filepath.Join(c.dir, "short.age")
		code, _, stderr := run(t, "root", "init", "--out", path, "--passphrase-fd", passphraseFD(t, strings.Repeat("x", 19)))
		if code != 1 || !strings.Contains(stderr, "at least 20") {
			t.Fatalf("19-character passphrase: exit %d, stderr %q", code, stderr)
		}
		for _, p := range []string{path, path + ".pub"} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatalf("%s exists after a refused init (stat error %v)", p, err)
			}
		}
	})

	t.Run("existing_output", func(t *testing.T) {
		before, err := os.ReadFile(a.path) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		code, _, stderr := run(t, "root", "init", "--out", a.path, "--passphrase-fd", passphraseFD(t, "a different passphrase entirely"))
		if code != 1 || !strings.Contains(stderr, "already exists") {
			t.Fatalf("init over an existing key: exit %d, stderr %q", code, stderr)
		}
		if after, err := os.ReadFile(a.path); err != nil || !bytes.Equal(after, before) { //nolint:gosec // G304: test file
			t.Fatalf("the existing key file changed (%v)", err)
		}
		// A leftover .pub alone also blocks init: the new key would get a
		// public key file that is not its own.
		orphan := filepath.Join(c.dir, "orphan.age")
		writeTestFile(t, orphan+".pub", []byte("left over\n"))
		if code, _, stderr := run(t, "root", "init", "--out", orphan, "--passphrase-fd", passphraseFD(t, "a different passphrase entirely")); code != 1 || !strings.Contains(stderr, "already exists") {
			t.Fatalf("init next to an existing .pub: exit %d, stderr %q", code, stderr)
		}
		if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
			t.Fatalf("%s was created (stat error %v)", orphan, err)
		}
	})

	t.Run("custody_mismatch", func(t *testing.T) {
		// roots.pub claims hardware custody for root A, whose key is in
		// fact the software file: --key refuses to sign under that label.
		for _, custody := range []string{"piv", "fido"} {
			m := newCeremonyInputs(t)
			apub, err := os.ReadFile(a.pub) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			bpub, err := os.ReadFile(b.pub) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, m.roots, append([]byte(strings.Replace(string(apub), "custody=software", "custody="+custody, 1)), bpub...))
			code, _, stderr := m.signWithKey(t, "1", a)
			if code != 1 || !strings.Contains(stderr, "custody") {
				t.Fatalf("--key for a root declared custody=%s: exit %d, stderr %q", custody, code, stderr)
			}
			if custody != "fido" && !strings.Contains(stderr, "false custody label") {
				t.Fatalf("custody=%s refused for the wrong reason: %q", custody, stderr)
			}
			if _, err := os.Stat(filepath.Join(m.out, "bundle.json.sigs")); !os.IsNotExist(err) {
				t.Fatalf("custody=%s: a signature file exists (stat error %v)", custody, err)
			}
		}
	})

	t.Run("key_and_agent_key", func(t *testing.T) {
		base := []string{"root", "sign", "--ca-pubkeys", c.caPubkeys, "--policy", c.policy, "--roots", c.roots, "--threshold", "1", "--out-dir", c.out}
		for name, extra := range map[string][]string{
			"both":         {"--key", a.path, "--agent-key", a.fingerprint},
			"neither":      {},
			"fd_for_agent": {"--agent-key", a.fingerprint, "--passphrase-fd", "0"},
		} {
			before := sigsOf(t, c.out)
			code, _, stderr := run(t, append(append([]string{}, base...), extra...)...)
			if code != 2 {
				t.Fatalf("%s: exit %d, want a usage error (stderr %q)", name, code, stderr)
			}
			if after := sigsOf(t, c.out); !bytes.Equal(after[0], before[0]) || !bytes.Equal(after[1], before[1]) {
				t.Fatalf("%s: a signature file changed", name)
			}
		}
		if code, _, _ := run(t, "root", "init", "--out", filepath.Join(c.dir, "x.age"), "--passphrase", "a passphrase on the command line"); code != 2 {
			t.Fatalf("root init accepted a --passphrase flag: exit %d", code)
		}
	})

	t.Run("two_roots_both_sign", func(t *testing.T) {
		// The ceremony signs with root B too, proving its medium and
		// passphrase now rather than in an emergency (D-10).
		if code, _, stderr := c.signWithKey(t, "1", b); code != 0 {
			t.Fatalf("root sign --key B: exit %d: %s", code, stderr)
		}
		code, stdout, stderr := c.verify(t, "1", a.fingerprint, b.fingerprint)
		if code != 0 || !strings.Contains(stdout, "OK: signed by 2 of 2 pinned roots (threshold 1)") {
			t.Fatalf("verify after both roots signed: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
		if code, _, stderr := c.signWithKey(t, "1", a); code != 1 || !strings.Contains(stderr, "already holds a signature") {
			t.Fatalf("second signature by root A: exit %d, stderr %q", code, stderr)
		}
	})

	t.Run("one_of_two_root_b_only", func(t *testing.T) {
		onlyB := *c
		onlyB.out = filepath.Join(c.dir, "out-b")
		if code, _, stderr := onlyB.signWithKey(t, "1", b); code != 0 {
			t.Fatalf("root sign --key B: exit %d: %s", code, stderr)
		}
		code, stdout, stderr := onlyB.verify(t, "1", a.fingerprint, b.fingerprint)
		if code != 0 || !strings.Contains(stdout, "OK: signed by 1 of 2 pinned roots (threshold 1)") || !strings.Contains(stdout, "signed by root "+b.fingerprint) {
			t.Fatalf("a bundle signed by root B alone: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}
	})

	t.Run("unrelated_root_ignored", func(t *testing.T) {
		_, thirdPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		third, err := ssh.NewSignerFromKey(thirdPriv)
		if err != nil {
			t.Fatal(err)
		}
		thirdSign := func(t *testing.T, dir string) {
			t.Helper()
			for _, doc := range []struct{ file, ns string }{{"bundle.json", trust.NamespaceBundle}, {"policy.json", trust.NamespacePolicy}} {
				msg, err := os.ReadFile(filepath.Join(dir, doc.file)) //nolint:gosec // G304: test file
				if err != nil {
					t.Fatal(err)
				}
				sig, err := sshsig.Sign(rand.Reader, third, doc.ns, msg)
				if err != nil {
					t.Fatal(err)
				}
				if err := appendSignature(filepath.Join(dir, doc.file+".sigs"), sig); err != nil {
					t.Fatal(err)
				}
			}
		}
		thirdFP := ssh.FingerprintSHA256(third.PublicKey())

		// Next to root B's signature, the third key's is reported and ignored.
		dirB := filepath.Join(c.dir, "out-b")
		thirdSign(t, dirB)
		code, stdout, stderr := c.verifyIn(t, dirB, "1", a.fingerprint, b.fingerprint)
		if code != 0 || !strings.Contains(stdout, "OK: signed by 1 of 2 pinned roots (threshold 1)") ||
			!strings.Contains(stdout, "ignored: bundle signature by non-pinned key "+thirdFP) {
			t.Fatalf("verify with an extra unrelated signature: exit %d, stdout %q, stderr %q", code, stdout, stderr)
		}

		// On its own, the third key's signature counts for nothing.
		dirC := filepath.Join(c.dir, "out-third")
		if err := os.MkdirAll(dirC, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"bundle.json", "policy.json"} {
			data, err := os.ReadFile(filepath.Join(dirB, f)) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(dirC, f), data)
		}
		thirdSign(t, dirC)
		if code, _, stderr := c.verifyIn(t, dirC, "1", a.fingerprint, b.fingerprint); code != 1 || !strings.Contains(stderr, "threshold not met") {
			t.Fatalf("verify with only an unrelated signature: exit %d, stderr %q", code, stderr)
		}
	})
}

// verifyIn runs trust verify on the bundle and policy in dir.
func (c *ceremony) verifyIn(t *testing.T, dir, threshold string, pins ...string) (int, string, string) {
	t.Helper()
	other := *c
	other.out = dir
	return other.verify(t, threshold, pins...)
}

// TestRootSignRefusesRootAsAdmin (B-CR-01, KEY-07): root sign refuses a
// policy that lists one of the roots as an admin, before it writes anything
// into --out-dir.
func TestRootSignRefusesRootAsAdmin(t *testing.T) {
	c := newCeremony(t, 1)
	useKeyring(t, c.rootKeys...)
	pub, err := ssh.NewPublicKey(c.rootKeys[0].Public())
	if err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(c.dir, "root.pub")
	writeTestFile(t, rootFile, ssh.MarshalAuthorizedKey(pub))
	c.policy = filepath.Join(c.dir, "root-admin-policy.json")
	if code, _, stderr := run(t, "root", "genesis-policy", "--admin", "root="+rootFile, "--out", c.policy); code != 0 {
		t.Fatalf("genesis-policy exit %d: %s", code, stderr)
	}
	code, _, stderr := c.sign(t, "1", 0, "--confirm", "00000000")
	if code != 1 || !strings.Contains(stderr, "policy admin key equals a root key") || !strings.Contains(stderr, "nothing was written or signed") {
		t.Fatalf("root sign of a root-as-admin policy: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(c.out); !os.IsNotExist(err) {
		t.Fatalf("--out-dir exists after the refusal (stat error %v)", err)
	}
}

// TestRootSignAppendsAfterMissingNewline (B-WR-02): a .sigs file whose last
// block lacks its newline still takes the next root's signature, and both
// signatures count.
func TestRootSignAppendsAfterMissingNewline(t *testing.T) {
	c := newCeremony(t, 2)
	useKeyring(t, c.rootKeys...)
	pins := []string{c.fingerprint(t, 0), c.fingerprint(t, 1)}
	if code, _, _ := c.sign(t, "2", 0, "--confirm", "00000000"); code != 1 {
		t.Fatal("expected the wrong confirmation to fail")
	}
	bundle, err := os.ReadFile(filepath.Join(c.out, "bundle.json")) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}
	prefix := trust.SHA256Hex(bundle)[:8]
	if code, _, stderr := c.sign(t, "2", 0, "--confirm", prefix); code != 0 {
		t.Fatalf("first root sign: exit %d: %s", code, stderr)
	}
	for _, f := range []string{"bundle.json.sigs", "policy.json.sigs"} {
		path := filepath.Join(c.out, f)
		data, err := os.ReadFile(path) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, path, bytes.TrimRight(data, "\n"))
	}
	if code, _, stderr := c.sign(t, "2", 1, "--confirm", prefix); code != 0 {
		t.Fatalf("second root sign: exit %d: %s", code, stderr)
	}
	if code, _, stderr := c.verify(t, "2", pins...); code != 0 {
		t.Fatalf("verify after appending to files without a final newline: exit %d, stderr %q", code, stderr)
	}
}

// TestAppendSignatureRefusesUnparseable (B-WR-02): appending to a file that
// does not parse as SSHSIG blocks is refused and the file is unchanged.
func TestAppendSignatureRefusesUnparseable(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, s, trust.NamespaceBundle, []byte("doc"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json.sigs")
	garbage := []byte("not a signature\n")
	writeTestFile(t, path, garbage)
	if err := appendSignature(path, sig); err == nil || !strings.Contains(err.Error(), "left unchanged") {
		t.Fatalf("appendSignature to an unparseable file = %v, want a refusal", err)
	}
	if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, garbage) { //nolint:gosec // G304: test file
		t.Fatalf("file changed after the refusal: %q, %v", data, err)
	}
}
