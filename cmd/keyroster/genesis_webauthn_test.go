package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// TestRootGenesisPolicyWebAuthn covers the genesis-policy RP flags (D-09):
// the default origin, explicit origins written sorted, an origin without
// an RP ID refused, and an RP ID the policy rules refuse writes nothing.
func TestRootGenesisPolicyWebAuthn(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	admin := filepath.Join(dir, "alice.pub")
	writeTestFile(t, admin, ssh.MarshalAuthorizedKey(pub))
	genesis := func(name string, extra ...string) (int, string, string, string) {
		out := filepath.Join(dir, name)
		code, stdout, stderr := run(t, append([]string{"root", "genesis-policy", "--admin", "alice=" + admin, "--out", out}, extra...)...)
		return code, stdout, stderr, out
	}
	readPolicy := func(path string) *trust.Policy {
		t.Helper()
		data, err := os.ReadFile(path) //nolint:gosec // G304: a file inside the test's TempDir
		if err != nil {
			t.Fatal(err)
		}
		p, err := trust.ParsePolicy(data)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("default_origin", func(t *testing.T) {
		code, _, stderr, out := genesis("default.json", "--webauthn-rp-id", "keyroster.example.org")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		p := readPolicy(out)
		if p.WebAuthn == nil || p.WebAuthn.RPID != "keyroster.example.org" || !slices.Equal(p.WebAuthn.Origins, []string{"https://keyroster.example.org"}) {
			t.Fatalf("policy RP %+v, want keyroster.example.org with origin https://keyroster.example.org", p.WebAuthn)
		}
	})
	t.Run("origins_sorted", func(t *testing.T) {
		code, _, stderr, out := genesis("origins.json", "--webauthn-rp-id", "keyroster.example.org",
			"--webauthn-origin", "https://keyroster.example.org:8443", "--webauthn-origin", "https://keyroster.example.org")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		want := []string{"https://keyroster.example.org", "https://keyroster.example.org:8443"}
		if p := readPolicy(out); p.WebAuthn == nil || !slices.Equal(p.WebAuthn.Origins, want) {
			t.Fatalf("policy RP %+v, want origins %q", p.WebAuthn, want)
		}
	})
	t.Run("no_rp_id", func(t *testing.T) {
		code, _, stderr, out := genesis("no-rp.json", "--webauthn-origin", "https://keyroster.example.org")
		if code == 0 || !strings.Contains(stderr, "--webauthn-origin needs --webauthn-rp-id") {
			t.Fatalf("exit %d, stderr %q; want the missing RP ID refusal", code, stderr)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s written despite the refusal (stat %v)", out, err)
		}
	})
	t.Run("without_rp", func(t *testing.T) {
		code, _, stderr, out := genesis("plain.json")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if p := readPolicy(out); p.WebAuthn != nil {
			t.Fatalf("policy without the flags has RP %+v", p.WebAuthn)
		}
	})
	t.Run("ip_rp_id_refused", func(t *testing.T) {
		code, _, stderr, out := genesis("ip.json", "--webauthn-rp-id", "127.0.0.1")
		if code == 0 || !strings.Contains(stderr, "IP address") {
			t.Fatalf("exit %d, stderr %q; want the IP refusal", code, stderr)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s written despite the refusal (stat %v)", out, err)
		}
	})
}
