package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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
	if !strings.Contains(stdout, "OK: 1 of 1 pinned roots signed both documents (bundle 1, policy 1, threshold 1)") {
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
	if code != 0 || !strings.Contains(stdout, "OK: 2 of 2 pinned roots signed both documents (bundle 2, policy 2, threshold 2)") {
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
	if !strings.Contains(stdout, "OK: 1 of 2 pinned roots signed both documents (bundle 1, policy 1, threshold 1)") || !strings.Contains(stdout, "signed by root "+a.fingerprint) {
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
		if code != 0 || !strings.Contains(stdout, "OK: 2 of 2 pinned roots signed both documents (bundle 2, policy 2, threshold 1)") {
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
		if code != 0 || !strings.Contains(stdout, "OK: 1 of 2 pinned roots signed both documents (bundle 1, policy 1, threshold 1)") || !strings.Contains(stdout, "signed by root "+b.fingerprint) {
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
		if code != 0 || !strings.Contains(stdout, "OK: 1 of 2 pinned roots signed both documents (bundle 1, policy 1, threshold 1)") ||
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

// TestRootSignRerunAfterPartialFailure (B-WR-03): when only the bundle
// signature was written (the policy append failed), a rerun with the same
// root signs only the policy; a further rerun is refused. Signature files
// are replaced atomically, with no temporary file left behind.
func TestRootSignRerunAfterPartialFailure(t *testing.T) {
	c := newCeremony(t, 1)
	useKeyring(t, c.rootKeys...)
	fp := c.fingerprint(t, 0)
	if code, _, _ := c.sign(t, "1", 0, "--confirm", "00000000"); code != 1 {
		t.Fatal("expected the wrong confirmation to fail")
	}
	bundle, err := os.ReadFile(filepath.Join(c.out, "bundle.json")) //nolint:gosec // G304: test file
	if err != nil {
		t.Fatal(err)
	}
	prefix := trust.SHA256Hex(bundle)[:8]
	if code, _, stderr := c.sign(t, "1", 0, "--confirm", prefix); code != 0 {
		t.Fatalf("first root sign: exit %d: %s", code, stderr)
	}
	if err := os.Remove(filepath.Join(c.out, "policy.json.sigs")); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := c.sign(t, "1", 0, "--confirm", prefix)
	if code != 0 {
		t.Fatalf("rerun after a missing policy signature: exit %d: %s", code, stderr)
	}
	for _, want := range []string{
		filepath.Join(c.out, "bundle.json.sigs") + " already holds a signature by " + fp + "; not signing it again",
		"signed " + filepath.Join(c.out, "policy.json") + " with " + fp,
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("rerun output lacks %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "signed "+filepath.Join(c.out, "bundle.json")+" with") {
		t.Fatalf("rerun signed the bundle again:\n%s", stdout)
	}
	for _, f := range []string{"bundle.json.sigs", "policy.json.sigs"} {
		data, err := os.ReadFile(filepath.Join(c.out, f)) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		if sigs, err := sshsig.ParseAll(data); err != nil || len(sigs) != 1 {
			t.Fatalf("%s holds %d signatures (%v), want 1", f, len(sigs), err)
		}
		if runtime.GOOS != "windows" {
			if fi, err := os.Stat(filepath.Join(c.out, f)); err != nil || fi.Mode().Perm() != 0o644 {
				t.Fatalf("%s mode %v (%v), want 0644", f, fi.Mode().Perm(), err)
			}
		}
	}
	if code, _, stderr := c.verify(t, "1", fp); code != 0 {
		t.Fatalf("trust verify after the rerun: exit %d: %s", code, stderr)
	}

	if code, _, stderr := c.sign(t, "1", 0, "--confirm", prefix); code != 1 ||
		!strings.Contains(stderr, "already holds a signature") || !strings.Contains(stderr, "nothing to sign") {
		t.Fatalf("rerun with both documents signed: exit %d, stderr %q", code, stderr)
	}
	entries, err := os.ReadDir(c.out)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("temporary file %s left in --out-dir", e.Name())
		}
	}
}

// TestTrustVerifyReportsSignersPerDocument (B-WR-04): with pins {A, B, C}
// at threshold 2, A and B sign the bundle and B and C the policy. Each
// document meets the threshold, so verification passes, but only B signed
// both, and the report must say so rather than "2 of 3".
func TestTrustVerifyReportsSignersPerDocument(t *testing.T) {
	c := newCeremony(t, 3)
	useKeyring(t, c.rootKeys...)
	if code, _, _ := c.sign(t, "2", 0, "--confirm", "00000000"); code != 1 {
		t.Fatal("expected the wrong confirmation to fail")
	}
	signers := make([]ssh.Signer, len(c.rootKeys))
	for i, k := range c.rootKeys {
		s, err := ssh.NewSignerFromKey(k)
		if err != nil {
			t.Fatal(err)
		}
		signers[i] = s
	}
	for _, doc := range []struct {
		file, ns string
		by       []int
	}{{"bundle.json", trust.NamespaceBundle, []int{0, 1}}, {"policy.json", trust.NamespacePolicy, []int{1, 2}}} {
		msg, err := os.ReadFile(filepath.Join(c.out, doc.file)) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range doc.by {
			sig, err := sshsig.Sign(rand.Reader, signers[i], doc.ns, msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := appendSignature(filepath.Join(c.out, doc.file+".sigs"), sig); err != nil {
				t.Fatal(err)
			}
		}
	}
	a, b, cc := c.fingerprint(t, 0), c.fingerprint(t, 1), c.fingerprint(t, 2)
	code, stdout, stderr := c.verify(t, "2", a, b, cc)
	if code != 0 {
		t.Fatalf("trust verify: exit %d: %s", code, stderr)
	}
	for _, want := range []string{
		"signed by root " + b + "\n",
		"root " + a + " signed the bundle only\n",
		"root " + cc + " signed the policy only\n",
		"OK: 1 of 3 pinned roots signed both documents (bundle 2, policy 2, threshold 2)\n",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("trust verify output lacks %q:\n%s", want, stdout)
		}
	}
	for _, wrong := range []string{"signed by root " + a, "signed by root " + cc} {
		if strings.Contains(stdout, wrong) {
			t.Fatalf("trust verify reports %q, but that root signed one document only:\n%s", wrong, stdout)
		}
	}
}

// setCeremonyNow fixes the ceremony clock at ts until the test ends.
func setCeremonyNow(t *testing.T, ts string) {
	t.Helper()
	at, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		t.Fatal(err)
	}
	prev := ceremonyNow
	ceremonyNow = func() time.Time { return at }
	t.Cleanup(func() { ceremonyNow = prev })
}

// TestRootSignSuccessor (KEY-07, owner decision 1) runs root sign --prev in
// the homelab rotation shape: a genesis bundle by software roots A and B at
// threshold 1, signed by A, is succeeded by a bundle naming software roots
// C and D at threshold 1, which the previous root A and the new root C sign
// with --key. The subtests share the four roots (each scrypt run costs
// about a second); refusals that come before decryption cost none.
func TestRootSignSuccessor(t *testing.T) {
	g := newCeremonyInputs(t)
	a := initSoftwareRoot(t, g.dir, "root-a", "correct horse battery staple A")
	b := initSoftwareRoot(t, g.dir, "root-b", "correct horse battery staple B")
	g.writeRoots(t, a, b)
	setCeremonyNow(t, "2026-10-05T07:00:00Z")
	code, stdout, stderr := g.signWithKey(t, "1", a)
	if code != 0 {
		t.Fatalf("genesis root sign --key: exit %d: %s", code, stderr)
	}
	if strings.Contains(stdout, "Successor of") || strings.Contains(stdout, "signatures needed") {
		t.Fatalf("a genesis signing printed the successor header:\n%s", stdout)
	}
	c := initSoftwareRoot(t, g.dir, "root-c", "correct horse battery staple C")
	d := initSoftwareRoot(t, g.dir, "root-d", "correct horse battery staple D")
	newRoots := &ceremony{dir: g.dir, roots: filepath.Join(g.dir, "new-roots.pub")}
	newRoots.writeRoots(t, c, d)
	setCeremonyNow(t, "2026-10-06T07:00:00Z")
	prevPolicy := filepath.Join(g.out, "policy.json")

	// sign runs root sign --prev g.out into out with policy and threshold.
	// key nil signs with an --agent-key of fingerprint agentFP instead.
	sign := func(t *testing.T, out, policy, threshold string, key *softwareRoot, extra ...string) (int, string, string) {
		t.Helper()
		typeHashPrefix(t, out)
		args := []string{"root", "sign", "--prev", g.out, "--roots", newRoots.roots, "--threshold", threshold,
			"--policy", policy, "--out-dir", out}
		if key != nil {
			args = append(args, "--key", key.path, "--passphrase-fd", passphraseFD(t, key.passphrase))
		}
		return run(t, append(args, extra...)...)
	}
	verifyOut := func(t *testing.T, out string) error {
		t.Helper()
		read := func(dir, name string) []byte {
			data, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			return data
		}
		prevBundle := read(g.out, "bundle.json")
		prev, err := trust.ParseBundle(prevBundle)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = trust.VerifySuccessor(prev, prevBundle, read(g.out, "policy.json"),
			read(out, "bundle.json"), read(out, "bundle.json.sigs"), read(out, "policy.json"), read(out, "policy.json.sigs"))
		return err
	}
	mustNotExist := func(t *testing.T, path string) {
		t.Helper()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s exists after a refusal (stat error %v)", path, err)
		}
	}
	// policyV2 writes a policy chained to the genesis policy (version 2,
	// prev its SHA-256, a shorter user TTL), edited by edit, and returns
	// its path.
	policyV2 := func(t *testing.T, name string, edit func(p *trust.Policy)) string {
		t.Helper()
		v1, err := os.ReadFile(prevPolicy) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		p, err := trust.ParsePolicy(v1)
		if err != nil {
			t.Fatal(err)
		}
		p.CAProfiles[0].MaxTTLSeconds = 3600
		p.Version, p.Prev = 2, trust.SHA256Hex(v1)
		edit(p)
		data, err := p.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(g.dir, name)
		writeTestFile(t, path, data)
		return path
	}
	rootKey := func(t *testing.T, r softwareRoot) string {
		t.Helper()
		line, err := os.ReadFile(r.pub) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			t.Fatal(err)
		}
		return trust.FormatKey(pub)
	}
	// copyPrev copies the genesis bundle.json and policy.json into a new
	// directory, the named file transformed by edit, and returns it.
	copyPrev := func(t *testing.T, name string, edit func([]byte) []byte) string {
		t.Helper()
		dir, err := os.MkdirTemp(g.dir, "prev-")
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"bundle.json", "policy.json"} {
			data, err := os.ReadFile(filepath.Join(g.out, f)) //nolint:gosec // G304: test file
			if err != nil {
				t.Fatal(err)
			}
			if f == name {
				data = edit(data)
			}
			writeTestFile(t, filepath.Join(dir, f), data)
		}
		return dir
	}

	succ := filepath.Join(g.dir, "succ")
	t.Run("previous_root_signs_with_key", func(t *testing.T) {
		code, stdout, stderr := sign(t, succ, prevPolicy, "1", &a)
		if code != 0 {
			t.Fatalf("root sign --prev --key A: exit %d: %s", code, stderr)
		}
		prevBundle, err := os.ReadFile(filepath.Join(g.out, "bundle.json")) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"Successor of trust bundle v1, sha256 " + trust.SHA256Hex(prevBundle),
			"signatures needed: 1 of the 2 previous roots AND 1 of the 2 new roots, on both documents",
			"Trust bundle version 2",
			"signed " + filepath.Join(succ, "bundle.json") + " with " + a.fingerprint,
			"signed " + filepath.Join(succ, "policy.json") + " with " + a.fingerprint,
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("root sign --prev output lacks %q:\n%s", want, stdout)
			}
		}
		shown := false
		for _, line := range strings.Split(stdout, "\n") {
			shown = shown || (strings.Contains(line, a.fingerprint) && strings.Contains(line, "custody=software"))
		}
		if !shown || !strings.Contains(stderr, "SOFTWARE ROOT:") {
			t.Fatalf("previous root A not shown with custody=software, or no SOFTWARE ROOT banner:\n%s\n%s", stdout, stderr)
		}
		if err := verifyOut(t, succ); !errors.Is(err, trust.ErrThreshold) {
			t.Fatalf("VerifySuccessor with the previous root's signature only: err = %v, want %v", err, trust.ErrThreshold)
		}
	})

	t.Run("new_root_signs_with_key", func(t *testing.T) {
		if code, _, stderr := sign(t, succ, prevPolicy, "1", &c); code != 0 {
			t.Fatalf("root sign --prev --key C: exit %d: %s", code, stderr)
		}
		if err := verifyOut(t, succ); err != nil {
			t.Fatalf("VerifySuccessor after A and C signed: %v", err)
		}
	})

	t.Run("ca_pubkeys_refused", func(t *testing.T) {
		out := filepath.Join(g.dir, "out-ca")
		code, _, stderr := sign(t, out, prevPolicy, "1", nil, "--agent-key", a.fingerprint, "--ca-pubkeys", g.caPubkeys)
		if code != 2 || !strings.Contains(stderr, "--ca-pubkeys is refused with --prev") {
			t.Fatalf("--ca-pubkeys with --prev: exit %d, stderr %q", code, stderr)
		}
		mustNotExist(t, out)
	})

	t.Run("unknown_root_refused", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(g.dir, "out-unknown")
		code, _, stderr := sign(t, out, prevPolicy, "1", nil, "--agent-key", ssh.FingerprintSHA256(pub))
		if code != 1 || !strings.Contains(stderr, "not one of") || !strings.Contains(stderr, "previous bundle") {
			t.Fatalf("unknown signing root: exit %d, stderr %q", code, stderr)
		}
		mustNotExist(t, filepath.Join(out, "bundle.json.sigs"))
		mustNotExist(t, filepath.Join(out, "policy.json.sigs"))
	})

	t.Run("missing_flags_with_prev", func(t *testing.T) {
		code, _, stderr := run(t, "root", "sign", "--prev", g.out, "--threshold", "1", "--policy", prevPolicy,
			"--out-dir", filepath.Join(g.dir, "out-usage"), "--agent-key", a.fingerprint)
		if code != 2 || !strings.Contains(stderr, "with --prev, --policy, --roots, --threshold, --out-dir") {
			t.Fatalf("--prev without --roots: exit %d, stderr %q", code, stderr)
		}
	})

	t.Run("previous_root_custody_mismatch_refused", func(t *testing.T) {
		// The previous bundle labels A custody=piv: --key holds A in
		// software, so the label would be false, and the error names the
		// previous bundle as the label's source.
		prev := copyPrev(t, "bundle.json", func(data []byte) []byte {
			pb, err := trust.ParseBundle(data)
			if err != nil {
				t.Fatal(err)
			}
			for i, rk := range pb.Root.Keys {
				if rk.Key == rootKey(t, a) {
					pb.Root.Keys[i].Custody = "piv"
				}
			}
			out, err := pb.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			return out
		})
		out := filepath.Join(g.dir, "out-custody")
		code, _, stderr := sign(t, out, prevPolicy, "1", &a, "--prev", prev) // the later --prev wins
		if code != 1 || !strings.Contains(stderr, filepath.Join(prev, "bundle.json")+" declares custody=piv") || !strings.Contains(stderr, "false custody label") {
			t.Fatalf("previous root labelled piv signing with --key: exit %d, stderr %q", code, stderr)
		}
		mustNotExist(t, filepath.Join(out, "bundle.json.sigs"))
		mustNotExist(t, filepath.Join(out, "policy.json.sigs"))
	})

	for _, tc := range []struct {
		name string
		root softwareRoot
	}{{"admin_is_previous_root", a}, {"admin_is_new_root", c}} {
		t.Run(tc.name, func(t *testing.T) {
			policy := policyV2(t, tc.name+".json", func(p *trust.Policy) {
				p.Admins = append(p.Admins, trust.AdminKey{Name: "root", Key: rootKey(t, tc.root)})
			})
			out := filepath.Join(g.dir, "out-"+tc.name)
			code, _, stderr := sign(t, out, policy, "1", &a)
			if code != 1 || !strings.Contains(stderr, "policy admin key equals a root key") || !strings.Contains(stderr, "nothing was written or signed") {
				t.Fatalf("%s: exit %d, stderr %q", tc.name, code, stderr)
			}
			mustNotExist(t, out)
		})
	}

	t.Run("chained_policy_v2_accepted", func(t *testing.T) {
		policy := policyV2(t, "policy-v2.json", func(*trust.Policy) {})
		out := filepath.Join(g.dir, "out-chained")
		for _, r := range []*softwareRoot{&a, &c} {
			if code, _, stderr := sign(t, out, policy, "1", r); code != 0 {
				t.Fatalf("root sign --prev with a chained v2 policy by %s: exit %d: %s", r.path, code, stderr)
			}
		}
		if err := verifyOut(t, out); err != nil {
			t.Fatalf("VerifySuccessor with a chained v2 policy: %v", err)
		}
	})

	t.Run("unchained_policy_refused", func(t *testing.T) {
		policy := policyV2(t, "policy-unchained.json", func(p *trust.Policy) { p.Version, p.Prev = 1, trust.GenesisPrev })
		out := filepath.Join(g.dir, "out-unchained")
		code, _, stderr := sign(t, out, policy, "1", &a)
		if code != 1 || !strings.Contains(stderr, "a changed policy must be version 2") {
			t.Fatalf("unchained policy: exit %d, stderr %q", code, stderr)
		}
		mustNotExist(t, out)
	})

	t.Run("out_dir_equals_prev_refused", func(t *testing.T) {
		before, err := os.ReadDir(g.out)
		if err != nil {
			t.Fatal(err)
		}
		code, _, stderr := sign(t, g.out+string(filepath.Separator)+".", prevPolicy, "1", &a)
		if code != 1 || !strings.Contains(stderr, "is the --prev directory") {
			t.Fatalf("--out-dir equal to --prev: exit %d, stderr %q", code, stderr)
		}
		if after, err := os.ReadDir(g.out); err != nil || len(after) != len(before) {
			t.Fatalf("the --prev directory changed: %d entries, then %d (%v)", len(before), len(after), err)
		}
	})

	t.Run("prev_not_canonical_refused", func(t *testing.T) {
		prev := copyPrev(t, "bundle.json", func(b []byte) []byte { return append(b[:len(b)-1], ' ', '\n') })
		out := filepath.Join(g.dir, "out-noncanonical")
		args := []string{"root", "sign", "--prev", prev, "--roots", newRoots.roots, "--threshold", "1",
			"--policy", prevPolicy, "--out-dir", out, "--agent-key", a.fingerprint}
		if code, _, stderr := run(t, args...); code != 1 || !strings.Contains(stderr, "not canonical") {
			t.Fatalf("non-canonical previous bundle: exit %d, stderr %q", code, stderr)
		}
		mustNotExist(t, out)
	})

	t.Run("prev_policy_mismatch_refused", func(t *testing.T) {
		other := policyV2(t, "policy-other.json", func(*trust.Policy) {})
		otherData, err := os.ReadFile(other) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		prev := copyPrev(t, "policy.json", func([]byte) []byte { return otherData })
		out := filepath.Join(g.dir, "out-policy-mismatch")
		args := []string{"root", "sign", "--prev", prev, "--roots", newRoots.roots, "--threshold", "1",
			"--policy", prevPolicy, "--out-dir", out, "--agent-key", a.fingerprint}
		if code, _, stderr := run(t, args...); code != 1 || !strings.Contains(stderr, "not the previous bundle's policy") {
			t.Fatalf("previous policy.json not the bundle's policy: exit %d, stderr %q", code, stderr)
		}
		mustNotExist(t, out)
	})

	t.Run("clock_before_prev_refused", func(t *testing.T) {
		setCeremonyNow(t, "2026-10-05T06:59:59Z")
		out := filepath.Join(g.dir, "out-clock")
		code, _, stderr := sign(t, out, prevPolicy, "1", &a)
		if code != 1 || !strings.Contains(stderr, "2026-10-05T07:00:00Z") || !strings.Contains(stderr, "clock") {
			t.Fatalf("ceremony clock before the previous issued_at: exit %d, stderr %q", code, stderr)
		}
		mustNotExist(t, out)
	})

	t.Run("rerun_signs_only_missing", func(t *testing.T) {
		out := filepath.Join(g.dir, "out-rerun")
		if code, _, stderr := sign(t, out, prevPolicy, "1", &a); code != 0 {
			t.Fatalf("first signing by A: exit %d: %s", code, stderr)
		}
		if err := os.Remove(filepath.Join(out, "policy.json.sigs")); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := sign(t, out, prevPolicy, "1", &a)
		if code != 0 {
			t.Fatalf("rerun by A after a missing policy signature: exit %d: %s", code, stderr)
		}
		for _, want := range []string{
			filepath.Join(out, "bundle.json.sigs") + " already holds a signature by " + a.fingerprint,
			"signed " + filepath.Join(out, "policy.json") + " with " + a.fingerprint,
		} {
			if !strings.Contains(stdout, want) {
				t.Fatalf("rerun output lacks %q:\n%s", want, stdout)
			}
		}
		if strings.Contains(stdout, "signed "+filepath.Join(out, "bundle.json")+" with") {
			t.Fatalf("the rerun signed the bundle again:\n%s", stdout)
		}
		before, err := os.ReadFile(filepath.Join(out, "bundle.json")) //nolint:gosec // G304: test file
		if err != nil {
			t.Fatal(err)
		}
		code, _, stderr = sign(t, out, prevPolicy, "2", &a)
		if code != 1 || !strings.Contains(stderr, "does not match --prev, --roots, --threshold and --policy") {
			t.Fatalf("rerun with --threshold 2: exit %d, stderr %q", code, stderr)
		}
		if after, err := os.ReadFile(filepath.Join(out, "bundle.json")); err != nil || !bytes.Equal(after, before) { //nolint:gosec // G304: test file
			t.Fatalf("bundle.json changed after a refused rerun (%v)", err)
		}
	})
}
