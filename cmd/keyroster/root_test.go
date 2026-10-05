package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

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
	if err := os.WriteFile(path, data, 0o600); err != nil {
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
