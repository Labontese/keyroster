//go:build e2e && e2emachine

package e2e

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
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
	krlDir := krlLayout(t)
	sshd := startSSHDWithKeys(t, sshdOptions{
		UserCAPub:  env.Signer.MachineCAPub,
		Principals: map[string][]string{login: {"role:deploy"}},
		Extra:      []string{"RevokedKeys " + filepath.Join(krlDir, "current", "revoked.krl")},
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

	// exportCounts is the number of log entries of a fresh export and of
	// its machine_issue entries.
	exportCounts := func(t *testing.T) (all, machineIssues int) {
		t.Helper()
		for _, l := range exportLines(t, env.Signer.exportLog(t)) {
			all++
			if l.Kind == "machine_issue" {
				machineIssues++
			}
		}
		return all, machineIssues
	}
	// noFile fails t when path exists.
	noFile := func(t *testing.T, path string) {
		t.Helper()
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s exists after a refused renewal (stat: %v)", path, err)
		}
	}
	// servedKRL is the KRL the server serves, verified against the
	// root-pinned bundle.
	servedKRL := func(t *testing.T) []byte {
		t.Helper()
		client, bundle := revokeClient(t, env)
		doc, err := client.GetKRL(context.Background())
		if err != nil || doc == nil {
			t.Fatalf("GetKRL = %v, %v", doc, err)
		}
		if _, err := krl.VerifyManifest(doc.Manifest, doc.Sig, doc.KRL, bundle, env.Signer.InstallationID, 0); err != nil {
			t.Fatalf("VerifyManifest: %v", err)
		}
		return doc.KRL
	}
	identityDetails := []string{"unknown_machine", "machine_key_mismatch", "machine_pop_invalid"}

	t.Run("collapse_is_generic", func(t *testing.T) {
		otherKey := newUserKey(t, "id_other")
		for _, tc := range []struct {
			name, machine, key, reason string
		}{
			{"wrong_key", "ci", otherKey, "machine_key_mismatch"},
			{"unknown_name", "nosuch", machineKey, "unknown_machine"},
		} {
			out := filepath.Join(t.TempDir(), "cert.pub")
			before := env.Stderr.String()
			code, stdout, stderr := renew(tc.machine, "--key", tc.key, "--out", out)
			if code != 1 || !strings.Contains(stdout+stderr, "the server does not authenticate this renewal (machine_not_authenticated)") {
				t.Fatalf("%s: exit %d, want 1 with the machine_not_authenticated text:\nstdout:\n%s\nstderr:\n%s", tc.name, code, stdout, stderr)
			}
			for _, d := range identityDetails {
				if strings.Contains(stdout+stderr, d) {
					t.Fatalf("%s: the CLI output names %s:\n%s%s", tc.name, d, stdout, stderr)
				}
			}
			waitFor(t, "the server's log line for "+tc.name, nil, env.Stderr, func() bool {
				return strings.Contains(strings.TrimPrefix(env.Stderr.String(), before), "machine renew refused by the signer") &&
					strings.Contains(strings.TrimPrefix(env.Stderr.String(), before), tc.reason)
			})
			noFile(t, out)
		}
	})

	t.Run("if_due_sends_nothing", func(t *testing.T) {
		_, before := exportCounts(t)
		code, stdout, stderr := renew("ci", "--key", machineKey, "--out", certFile, "--if-due")
		if code != 0 || !strings.Contains(stdout, "not due:") {
			t.Fatalf("machine renew --if-due exited %d, want 0 and not due:\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if _, after := exportCounts(t); after != before {
			t.Fatalf("machine_issue entries %d before and %d after --if-due, want the same", before, after)
		}
	})

	t.Run("revoke_machine_refuses_login_and_renewal", func(t *testing.T) {
		kr("revoke", "machine", "ci", "--yes")
		swapKRL(t, krlDir, servedKRL(t))
		before := sshd.log.String()
		if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: machineKey, Cert: certFile, User: login, Command: "true"}); code == 0 {
			t.Fatalf("ci's certificate logged in after revoke machine:\n%s", out)
		}
		waitForLog(t, sshd, before, "revoked")
		out := filepath.Join(t.TempDir(), "cert3.pub")
		code, stdout, stderr := renew("ci", "--key", machineKey, "--out", out)
		if code != 1 || !strings.Contains(stdout+stderr, "(machine_disabled)") {
			t.Fatalf("machine renew after revoke machine exited %d, want 1 with machine_disabled:\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		noFile(t, out)
	})

	t.Run("keys_revokes_key_for_good", func(t *testing.T) {
		ci2Key := newUserKey(t, "id_ci2")
		kr("machine", "add", "ci2", "--key", ci2Key+".pub", "--role", "deploy", "--max-ttl", "24h", "--yes")
		kr("revoke", "machine", "ci2", "--keys", "--yes")
		if code, out := keygenQuery(t, writeKRL(t, servedKRL(t)), ci2Key+".pub"); code == 0 {
			t.Fatalf("ssh-keygen -Q reports ci2's key not revoked:\n%s", out)
		}
		out := filepath.Join(t.TempDir(), "cert4.pub")
		code, stdout, stderr := renew("ci2", "--key", ci2Key, "--out", out)
		if code != 1 || !strings.Contains(stdout+stderr, "(machine_key_revoked)") {
			t.Fatalf("machine renew ci2 exited %d, want 1 with machine_key_revoked:\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		noFile(t, out)
	})

	// The sk-dummy key of OpenSSH's test provider in a real ssh-agent, as
	// TestRootSK loads it: the CI stand-in for a security key (OQ-2 of
	// 03-11); a real token stays UNVERIFIED.
	skKey := filepath.Join(t.TempDir(), "id_ci3")
	t.Run("sk_through_agent", func(t *testing.T) {
		prefix := opensshPrefix(t)
		provider := filepath.Join(prefix, "libexec", "sk-dummy.so")
		if _, err := os.Stat(provider); err != nil {
			t.Fatalf("%s missing (rebuild with scripts/build-openssh.sh): %v", provider, err)
		}
		t.Setenv("SSH_SK_PROVIDER", provider)
		sock := filepath.Join(shortTempDir(t), "agent.sock")
		_, log, done := startDaemon(t, "ssh-agent", envWithout("SSH_AUTH_SOCK"), filepath.Join(prefix, "bin", "ssh-agent"),
			"-D", "-a", sock, "-P", filepath.Join(prefix, "libexec", "*"))
		waitFor(t, "ssh-agent socket", done, log, func() bool { return isSocket(sock) })
		sshKeygen(t, "-q", "-t", "ed25519-sk", "-N", "", "-C", "ci3", "-w", provider, "-f", skKey)
		sshAdd(t, sock, skKey)
		kr("machine", "add", "ci3", "--key", skKey+".pub", "--role", "deploy", "--max-ttl", "24h", "--yes")

		ci3Cert := filepath.Join(t.TempDir(), "ci3-cert.pub")
		code, stdout, stderr := runCLIIn(t, host, sock, "", keyrosterBin, "machine", "renew", "ci3", "--agent-key", fingerprint(t, skKey+".pub"), "--out", ci3Cert)
		if code != 0 {
			t.Fatalf("machine renew ci3 --agent-key exited %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, stdout, stderr, env.Stderr.String())
		}
		listing := sshKeygen(t, "-L", "-f", ci3Cert)
		if !strings.Contains(listing, "sk-ssh-ed25519-cert-v01@openssh.com") || !strings.Contains(listing, "sub=ci3") {
			t.Fatalf("ssh-keygen -L of ci3's certificate lacks the sk key or sub=ci3:\n%s", listing)
		}
	})

	t.Run("sk_key_file_named_error", func(t *testing.T) {
		before, _ := exportCounts(t)
		out := filepath.Join(t.TempDir(), "cert5.pub")
		code, stdout, stderr := renew("ci3", "--key", skKey, "--out", out)
		if code != 1 || !strings.Contains(stdout+stderr, "is a security key") || !strings.Contains(stdout+stderr, "--agent-key") {
			t.Fatalf("machine renew ci3 --key (an sk file) exited %d, want 1 with the named sk error:\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
		}
		if after, _ := exportCounts(t); after != before {
			t.Fatalf("%d log entries before and %d after, want the same (nothing sent)", before, after)
		}
		noFile(t, out)
	})

	t.Run("audit_verify_counts_machine_certificates", func(t *testing.T) {
		export := env.Signer.exportLog(t)
		code, out := auditVerify(t, env.Signer, export)
		if code != 0 || !strings.Contains(out, "\nmachine certificates: 2\n") {
			t.Fatalf("keyroster audit verify exited %d, want 0 with machine certificates: 2:\n%s", code, out)
		}
		n := 0
		for _, l := range exportLines(t, export) {
			if l.Kind == "machine_issue" {
				n++
			}
		}
		if n != 2 {
			t.Fatalf("the export holds %d machine_issue entries, want 2", n)
		}
	})
}
