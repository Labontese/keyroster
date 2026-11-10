//go:build e2e && e2emachine

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
)

// TestMachineIdentityEndToEnd proves machine identities against real
// binaries and a real sshd (03-11b, D-15): an automation host that ran
// keyroster init without --user renews its machine certificate through
// keyroster-server's anonymous route by proof of possession of its own
// key, and logs in with it. It runs serial, in the e2e-probe job under the
// tag e2emachine, uses no helper of the tag e2eprobe and never sets
// genesisMachineMaxTTL (PD9). Its steps are ordered by design.
func TestMachineIdentityEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{PoPMachines: true})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
			time.Sleep(2 * time.Second)
			code, out, errOut = env.keyroster(t, admin, "", args...)
		}
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}
	// A role no user or group grants is checked against the user CA cap
	// until a machine carries it, then against the machine CA cap: add it
	// at 12 h, add the machine, then raise the role to 24 h.
	kr("role", "add", "deploy", "--max-ttl", "12h", "--yes")
	machineKey := newUserKey(t, "id_ci")
	kr("machine", "add", "ci", "--key", machineKey+".pub", "--role", "deploy", "--max-ttl", "24h", "--yes")
	kr("role", "update", "deploy", "--max-ttl", "24h", "--yes")

	// The automation host's own CLI: keyroster init without --user.
	host := newCLIEnv(t)
	initArgs := []string{"init", "--server", env.URL, "--tls-root-file", env.CA.RootPEM, "--tls-pin", env.CA.RootPin,
		"--root-pin", env.Signer.RootFingerprints[0], "--threshold", "1"}
	if code, stdout, stderr := runCLIIn(t, host, "", "", keyrosterBin, initArgs...); code != 0 {
		t.Fatalf("keyroster init without --user exited %d:\n%s\n%s", code, stdout, stderr)
	}
	renew := func(args ...string) (int, string, string) {
		t.Helper()
		return runCLIIn(t, host, "", "", keyrosterBin, append([]string{"machine", "renew"}, args...)...)
	}

	login := currentUser(t)
	krl := krlLayout(t)
	sshd := startSSHDWithKeys(t, sshdOptions{
		UserCAPub:  env.Signer.MachineCAPub,
		Principals: map[string][]string{login: {"role:deploy"}},
		Extra:      []string{"RevokedKeys " + filepath.Join(krl, "current", "revoked.krl")},
	}, "")
	certFile := filepath.Join(t.TempDir(), "ci-cert.pub")

	t.Run("renew_and_login", func(t *testing.T) {
		code, stdout, stderr := renew("ci", "--key", machineKey, "--out", certFile)
		if code != 0 {
			t.Fatalf("machine renew exited %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, stdout, stderr, env.Stderr.String())
		}
		data, err := os.ReadFile(certFile) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			t.Fatalf("CERTFILE: %v", err)
		}
		c, ok := pk.(*ssh.Certificate)
		if !ok {
			t.Fatalf("CERTFILE holds a %T", pk)
		}
		if life := c.ValidBefore - c.ValidAfter - 300; life != 24*3600 {
			t.Fatalf("lifetime %d s, want 24 h", life)
		}
		kid, err := cert.ParseKeyID(c.KeyId)
		if err != nil || !kid.V3 || kid.CA != "machine" || kid.Subject != "ci" {
			t.Fatalf("key ID %q (%v), want kr3 with ca=machine and sub=ci", c.KeyId, err)
		}
		sshExpect(t, 0, loginOptions{Port: sshd.port, Key: machineKey, Cert: certFile, User: login, Command: "true"})
	})
}
