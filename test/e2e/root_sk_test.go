//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestRootSK runs the root ceremony with a FIDO-style hardware root: an
// sk-ssh-ed25519@openssh.com key served by OpenSSH's test-only security-key
// provider sk-dummy.so through a real ssh-agent (the CI stand-in for a
// FIDO token, D-11). keyroster root sign signs through the agent, keyroster
// trust verify accepts the bundle against the pinned fingerprint, and stock
// ssh-keygen agrees in both directions.
func TestRootSK(t *testing.T) {
	prefix := opensshPrefix(t)
	provider := filepath.Join(prefix, "libexec", "sk-dummy.so")
	if _, err := os.Stat(provider); err != nil {
		t.Fatalf("%s missing (rebuild with scripts/build-openssh.sh): %v", provider, err)
	}
	// ssh-keygen and ssh-add find the provider through SSH_SK_PROVIDER.
	t.Setenv("SSH_SK_PROVIDER", provider)

	t.Run("fido_root_threshold_1", func(t *testing.T) {
		r := newRootCeremony(t, prefix)
		sk := r.newRoot(t, "root-sk", "ed25519-sk")
		r.writeRoots(t, sk)

		r.sign(t, "1", sk)
		out := r.verify(t, 0, "1", sk)
		if !strings.Contains(out, "OK: 1 of 1 pinned roots signed both documents (bundle 1, policy 1, threshold 1)") {
			t.Fatalf("trust verify output:\n%s", out)
		}
		b := r.bundle(t)
		if len(b.Root.Keys) != 1 || b.Root.Keys[0].Custody != "fido" || !strings.HasPrefix(b.Root.Keys[0].Key, ssh.KeyAlgoSKED25519+" ") {
			t.Fatalf("verified bundle root = %+v, want one %s key with custody fido", b.Root.Keys, ssh.KeyAlgoSKED25519)
		}
		r.keygenVerify(t, sk, "bundle.json", trust.NamespaceBundle)
		r.keygenVerify(t, sk, "policy.json", trust.NamespacePolicy)

		// The other direction: ssh-keygen -Y sign with the sk key, verified
		// by internal/sshsig.
		msg := filepath.Join(r.dir, "msg")
		if err := os.WriteFile(msg, []byte("keyroster sk oracle\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		sshKeygen(t, "-Y", "sign", "-f", sk.file, "-n", trust.NamespaceBundle, msg)
		armored, err := os.ReadFile(msg + ".sig") //nolint:gosec // test file
		if err != nil {
			t.Fatal(err)
		}
		sig, err := sshsig.Parse(armored)
		if err != nil {
			t.Fatalf("parse ssh-keygen sk signature: %v", err)
		}
		if sig.PublicKey().Type() != ssh.KeyAlgoSKED25519 {
			t.Fatalf("signature key type %s", sig.PublicKey().Type())
		}
		if err := sig.Verify(trust.NamespaceBundle, []byte("keyroster sk oracle\n")); err != nil {
			t.Fatalf("internal/sshsig refuses ssh-keygen's sk signature: %v", err)
		}
	})

	t.Run("fido_and_ed25519_roots_threshold_2", func(t *testing.T) {
		r := newRootCeremony(t, prefix)
		sk := r.newRoot(t, "root-sk", "ed25519-sk")
		ed := r.newRoot(t, "root-ed", "ed25519")
		r.writeRoots(t, sk, ed)

		r.sign(t, "2", sk)
		if out := r.verify(t, 1, "2", sk, ed); !strings.Contains(out, "threshold not met") {
			t.Fatalf("verify with 1 of 2 signatures: want a threshold failure, got:\n%s", out)
		}
		r.sign(t, "2", ed)
		out := r.verify(t, 0, "2", sk, ed)
		if !strings.Contains(out, "OK: 2 of 2 pinned roots signed both documents (bundle 2, policy 2, threshold 2)") {
			t.Fatalf("trust verify output:\n%s", out)
		}
		b := r.bundle(t)
		types := map[string]string{}
		for _, k := range b.Root.Keys {
			types[strings.Fields(k.Key)[0]] = k.Custody
		}
		if types[ssh.KeyAlgoSKED25519] != "fido" || types[ssh.KeyAlgoED25519] != "software" || b.Root.Threshold != 2 {
			t.Fatalf("verified bundle root = %+v", b.Root)
		}
	})
}

// rootCeremony is one root ceremony in a fresh directory with its own
// ssh-agent that may load keys through the prefix's providers.
type rootCeremony struct {
	prefix, dir, out, sock string
	caPubkeys, policy      string
	roots                  string
}

type rootKey struct {
	file, fingerprint string
	pub               ssh.PublicKey
}

func newRootCeremony(t *testing.T, prefix string) *rootCeremony {
	t.Helper()
	dir := t.TempDir()
	r := &rootCeremony{
		prefix:    prefix,
		dir:       dir,
		out:       filepath.Join(dir, "out"),
		caPubkeys: filepath.Join(dir, "ca-pubkeys.json"),
		policy:    filepath.Join(dir, "genesis-policy.json"),
		roots:     filepath.Join(dir, "roots.pub"),
	}
	// A private agent that accepts security-key providers from the prefix
	// only (as OpenSSH's regress suite does).
	r.sock = filepath.Join(shortTempDir(t), "agent.sock")
	_, log, done := startDaemon(t, "ssh-agent", envWithout("SSH_AUTH_SOCK"), filepath.Join(prefix, "bin", "ssh-agent"),
		"-D", "-a", r.sock, "-P", filepath.Join(prefix, "libexec", "*"))
	waitFor(t, "ssh-agent socket", done, log, func() bool { return isSocket(r.sock) })

	// Online keys from the CA host: fresh P-256 keys (D-09).
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
		cas.Keys = append(cas.Keys, trust.CAPubKey{Role: role, Key: trust.FormatKey(pub), Alg: pub.Type(), Custody: "vtpm"})
	}
	data, err := cas.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.caPubkeys, data, 0o600); err != nil {
		t.Fatal(err)
	}

	admin := filepath.Join(dir, "alice")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "alice", "-f", admin)
	if code, out := r.keyroster(t, "root", "genesis-policy", "--admin", "alice="+admin+".pub", "--out", r.policy); code != 0 {
		t.Fatalf("genesis-policy: exit %d\n%s", code, out)
	}
	return r
}

// newRoot creates a root key of keyType, loads it into the agent and
// returns it. For ed25519-sk the key handle lives in the sk-dummy provider.
func (r *rootCeremony) newRoot(t *testing.T, name, keyType string) rootKey {
	t.Helper()
	file := filepath.Join(r.dir, name)
	args := []string{"-q", "-t", keyType, "-N", "", "-C", name, "-f", file}
	if strings.HasSuffix(keyType, "-sk") {
		args = append(args, "-w", filepath.Join(r.prefix, "libexec", "sk-dummy.so"))
	}
	sshKeygen(t, args...)
	sshAdd(t, r.sock, file)
	data, err := os.ReadFile(file + ".pub") //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		t.Fatal(err)
	}
	return rootKey{file: file, fingerprint: fingerprint(t, file+".pub"), pub: pub}
}

func (r *rootCeremony) writeRoots(t *testing.T, keys ...rootKey) {
	t.Helper()
	var b strings.Builder
	for _, k := range keys {
		custody := "software"
		if strings.HasPrefix(k.pub.Type(), "sk-") {
			custody = "fido"
		}
		b.WriteString(trust.FormatKey(k.pub) + " custody=" + custody + "\n")
	}
	if err := os.WriteFile(r.roots, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// sign runs keyroster root sign with key through the agent, confirming the
// bundle hash prefix (a first run with a wrong prefix creates bundle.json
// and signs nothing).
func (r *rootCeremony) sign(t *testing.T, threshold string, key rootKey) {
	t.Helper()
	args := []string{"root", "sign", "--ca-pubkeys", r.caPubkeys, "--policy", r.policy, "--roots", r.roots,
		"--threshold", threshold, "--out-dir", r.out, "--agent-key", key.fingerprint}
	if _, err := os.Stat(filepath.Join(r.out, "bundle.json")); errors.Is(err, os.ErrNotExist) {
		if code, out := r.keyroster(t, append(args, "--confirm", "00000000")...); code != 1 || !strings.Contains(out, "nothing was signed") {
			t.Fatalf("root sign with a wrong confirmation: exit %d\n%s", code, out)
		}
	}
	bundle, err := os.ReadFile(filepath.Join(r.out, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	if code, out := r.keyroster(t, append(args, "--confirm", trust.SHA256Hex(bundle)[:8])...); code != 0 {
		t.Fatalf("root sign with %s: exit %d\n%s", key.fingerprint, code, out)
	}
}

// verify runs keyroster trust verify with the keys' fingerprints pinned and
// requires exit status want.
func (r *rootCeremony) verify(t *testing.T, want int, threshold string, pins ...rootKey) string {
	t.Helper()
	args := []string{"trust", "verify", "--threshold", threshold,
		"--bundle", filepath.Join(r.out, "bundle.json"), "--policy", filepath.Join(r.out, "policy.json")}
	for _, p := range pins {
		args = append(args, "--pin", p.fingerprint)
	}
	code, out := r.keyroster(t, args...)
	if code != want {
		t.Fatalf("trust verify: exit %d, want %d\n%s", code, want, out)
	}
	return out
}

func (r *rootCeremony) bundle(t *testing.T) *trust.Bundle {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.out, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// keygenVerify checks file's detached signature with ssh-keygen -Y verify.
func (r *rootCeremony) keygenVerify(t *testing.T, key rootKey, file, namespace string) {
	t.Helper()
	allowed := filepath.Join(r.dir, "allowed_signers")
	if err := os.WriteFile(allowed, append([]byte("root "), ssh.MarshalAuthorizedKey(key.pub)...), 0o600); err != nil {
		t.Fatal(err)
	}
	msg, err := os.ReadFile(filepath.Join(r.out, file)) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(r.prefix, "bin", "ssh-keygen"), "-Y", "verify", "-f", allowed, "-I", "root", //nolint:gosec // G204: test oracle
		"-n", namespace, "-s", filepath.Join(r.out, file+".sigs"))
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	cmd.Stdin = bytes.NewReader(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y verify %s: %v\n%s", file, err, out)
	}
}

// keyroster runs the CLI with the ceremony's agent as SSH_AUTH_SOCK.
func (r *rootCeremony) keyroster(t *testing.T, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, keyrosterBin, args...) //nolint:gosec // G204: the binary under test
	cmd.Env = append(envWithout("SSH_AUTH_SOCK"), "SSH_AUTH_SOCK="+r.sock)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("keyroster %v: %v\n%s", args, err, out)
	}
	return 0, string(out)
}
