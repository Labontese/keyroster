//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// softwareBannerPhrase is the first words of the evaluation-only banner
// (internal/custodytext). The tests of this plan and of the server grep
// for exactly this phrase.
const softwareBannerPhrase = "EVALUATION ONLY - SOFTWARE CA KEY"

// TestSoftwareCAEndToEnd (KEY-06): keyroster-signer ca-init --backend
// software creates the five online keys as age-encrypted files under the
// state directory; the root signs a bundle recording custody software; the
// signer serves on them; Status reports custody software for every key and
// exactly the installed bundle; keyroster ca issue prints the
// evaluation-only banner and gets a certificate that real sshd accepts;
// doctor warns software_key. Control: on the default agent backend ca
// issue prints no banner and Status reports custody agent.
func TestSoftwareCAEndToEnd(t *testing.T) {
	login := currentUser(t)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	passFile := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(passFile, []byte(base64.StdEncoding.EncodeToString(secret)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	env := prepareSigner(t, bootstrapOpts{Backend: "software", BackendOpts: map[string]string{"passphrase-file": passFile}})

	// ca-pubkeys.json and the verified bundle record custody software.
	data, err := os.ReadFile(env.CAPubkeys)
	if err != nil {
		t.Fatal(err)
	}
	cas, err := trust.ParseCAPubKeys(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas.Keys) != len(roleNames) {
		t.Fatalf("ca-pubkeys.json lists %d keys, want %d", len(cas.Keys), len(roleNames))
	}
	for _, k := range cas.Keys {
		if k.Custody != "software" || k.Alg != "ssh-ed25519" {
			t.Errorf("ca-pubkeys %s: custody %q alg %q, want software ssh-ed25519", k.Role, k.Custody, k.Alg)
		}
	}
	keyDir := filepath.Join(env.StateDir, "software")
	if fi, err := os.Lstat(keyDir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("key directory %s: %v, want a 0700 directory", keyDir, err)
	}
	for _, role := range roleNames {
		f := filepath.Join(keyDir, role+".age")
		fi, err := os.Lstat(f)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file %s: %v, want a regular 0600 file", f, err)
		}
		b, err := os.ReadFile(f) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(b, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) || bytes.Contains(b, []byte("PRIVATE KEY")) {
			t.Fatalf("key file %s is not an armored age file", f)
		}
	}

	// doctor states the software custody (before serve, which locks the
	// state directory).
	code, out := env.signerCmd(t, "doctor", "--state-dir", env.StateDir)
	if code != 0 {
		t.Fatalf("doctor exited %d, want 0:\n%s", code, out)
	}
	requireDoctorLine(t, out, "WARN software_key:")
	if strings.Contains(out, "FAIL ") || strings.Contains(out, "OK custody:") {
		t.Fatalf("doctor reported a FAIL or hardware custody for software keys:\n%s", out)
	}

	env.serve(t)

	// Status: custody software for every key, and exactly the installed
	// bundle and policy.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := signerclient.Status(ctx, env.Socket)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(st.Keys) != len(roleNames) {
		t.Fatalf("Status reports %d keys, want %d", len(st.Keys), len(roleNames))
	}
	for i, k := range st.Keys {
		want, _ := cas.Key(roleNames[i])
		if k.Role != roleNames[i] || k.Custody != "software" || k.Alg != "ssh-ed25519" || k.Fingerprint != fingerprintOfKey(t, want.Key) {
			t.Errorf("Status key %d = %+v, want role %s custody software ssh-ed25519 %s", i, k, roleNames[i], fingerprintOfKey(t, want.Key))
		}
	}
	bundle, err := os.ReadFile(filepath.Join(env.BundleDir, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := os.ReadFile(filepath.Join(env.BundleDir, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(st.Bundle) != sha256.Sum256(bundle) || !bytes.Equal(st.Policy, policy) || st.BundleVersion != 1 {
		t.Fatalf("Status reports bundle version %d, bundle SHA-256 %x, want version 1 and the installed bundle.json %x and policy.json",
			st.BundleVersion, sha256.Sum256(st.Bundle), sha256.Sum256(bundle))
	}
	if st.DirectoryVersion != 0 || st.DirectoryAuthorized {
		t.Fatalf("Status reports directory version %d authorized %v, want none", st.DirectoryVersion, st.DirectoryAuthorized)
	}

	// ca issue prints the banner and gets a certificate sshd accepts.
	userKey := filepath.Join(t.TempDir(), "id_ed25519")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user", "-f", userKey)
	out = env.issue(t, "--pubkey", userKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	t.Logf("keyroster ca issue (software custody), stderr:\n%s", out)
	frame := strings.Repeat("!", 76)
	banner := frame + "\n" + custodytext.SoftwareCABanner(roleNames) + "\n" + frame + "\n"
	if !strings.Contains(out, softwareBannerPhrase) || !strings.Contains(out, banner) || !strings.Contains(out, "or controls the signer host,") {
		t.Fatalf("ca issue on software custody did not print the framed, owner-approved banner naming all five keys:\n%s", out)
	}
	if strings.Index(out, softwareBannerPhrase) > strings.Index(out, "serial:") {
		t.Fatalf("the banner came after the issuance:\n%s", out)
	}
	if strings.Contains(out, strings.TrimSpace(string(mustRead(t, passFile)))) {
		t.Fatal("ca issue output contains the passphrase")
	}
	port := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {login}}})
	if code, out := sshLogin(t, loginOptions{Port: port, Key: userKey, Cert: userKey + "-cert.pub", User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with the software-signed certificate exited %d:\n%s", code, out)
	}

	// Control: the agent backend (bootstrap default) prints no banner.
	ctl := bootstrapSigner(t, bootstrapOpts{})
	cst, err := signerclient.Status(ctx, ctl.Socket)
	if err != nil {
		t.Fatalf("Status (agent control): %v", err)
	}
	for _, k := range cst.Keys {
		if k.Custody != "agent" {
			t.Errorf("Status (agent control) key %s custody %q, want agent", k.Role, k.Custody)
		}
	}
	ctlKey := filepath.Join(t.TempDir(), "id_ed25519")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user", "-f", ctlKey)
	out = ctl.issue(t, "--pubkey", ctlKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	if strings.Contains(out, softwareBannerPhrase) || strings.Contains(out, "!!!!") {
		t.Fatalf("ca issue on agent custody printed the software banner:\n%s", out)
	}
	if !strings.Contains(out, "serial:") {
		t.Fatalf("ca issue on agent custody did not issue:\n%s", out)
	}
}

// fingerprintOfKey returns the SHA256 fingerprint of an authorized-keys
// formatted public key.
func fingerprintOfKey(t *testing.T, key string) string {
	t.Helper()
	pub, err := trust.ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(pub)
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}
