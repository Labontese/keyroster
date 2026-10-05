//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// readPub returns the single key line of an OpenSSH .pub file.
func readPub(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

// strictLogin configures sshStrict.
type strictLogin struct {
	Port       int
	Key, Cert  string
	User       string
	KnownHosts string // the only known_hosts file the client reads
}

// sshStrict logs in with StrictHostKeyChecking=yes against the given
// known_hosts file only, so the host must prove itself through that file:
// there is no TOFU prompt (BatchMode) and nothing is added to the file. It
// runs with -v so the output shows which host key or certificate matched.
func sshStrict(t *testing.T, o strictLogin) (int, string) {
	t.Helper()
	args := []string{
		"-v", "-F", "none",
		"-i", o.Key,
		"-o", "CertificateFile=" + o.Cert,
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + o.KnownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-p", strconv.Itoa(o.Port),
		o.User + "@127.0.0.1", "echo host-ok",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(opensshPrefix(t), "bin", "ssh"), args...) //nolint:gosec // G204: the test OpenSSH
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("ssh: %v\n%s", err, out)
	}
	return 0, string(out)
}

// issueHostCert creates a host key in dir, has the signer's host CA certify
// it for 127.0.0.1 and localhost, and returns the key and certificate
// paths.
func issueHostCert(t *testing.T, env *signerEnv, dir string) (key, certFile string) {
	t.Helper()
	key = filepath.Join(dir, "ssh_host_kr_ed25519_key")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "kr-host", "-f", key)
	env.issue(t, "--ca", "host", "--pubkey", key+".pub",
		"--principal", "127.0.0.1", "--principal", "localhost", "--subject", "h:127.0.0.1", "--ttl", "1h")
	return key, key + "-cert.pub"
}

// TestHostCertificateNoTOFU (CA-01): a host certificate from the bundle's
// host CA lets a real ssh client with StrictHostKeyChecking=yes connect
// through a single @cert-authority known_hosts line, with no host-key
// prompt and nothing learned; the same client with an empty known_hosts, or
// with the user CA in the @cert-authority line, refuses the host. The
// exported log then verifies against the pinned root alone and counts the
// host issuance.
func TestHostCertificateNoTOFU(t *testing.T) {
	login := currentUser(t)
	env := bootstrapSigner(t, bootstrapOpts{})
	dir := t.TempDir()

	hostKey, hostCert := issueHostCert(t, env, dir)
	listing := sshKeygen(t, "-L", "-f", hostCert)
	info := parseCertInfo(t, listing)
	if !strings.Contains(listing, "host certificate") {
		t.Fatalf("ssh-keygen -L does not show a host certificate:\n%s", listing)
	}
	if info.signingCAFP != fingerprint(t, env.HostCAPub) {
		t.Fatalf("host certificate signed by %s, want the bundle's host CA %s", info.signingCAFP, fingerprint(t, env.HostCAPub))
	}
	if !strings.HasPrefix(info.keyID, "kr1/ca=host/") || !strings.Contains(info.keyID, "/pol=1/") {
		t.Fatalf("host certificate key ID %q, want kr1/ca=host/... with pol=1", info.keyID)
	}
	if strings.Join(info.principals, ",") != "127.0.0.1,localhost" {
		t.Fatalf("host certificate principals %v, want [127.0.0.1 localhost]", info.principals)
	}

	userKey := newUserKey(t, "id_no_tofu")
	env.issue(t, "--pubkey", userKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	port := startSSHD(t, sshdOptions{
		UserCAPub:  env.UserCAPub,
		Principals: map[string][]string{login: {login}},
		Extra:      []string{"HostKey " + hostKey, "HostCertificate " + hostCert},
	})
	hostPattern := "[127.0.0.1]:" + strconv.Itoa(port)
	writeKnownHosts := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	login1 := func(knownHosts string) (int, string) {
		return sshStrict(t, strictLogin{Port: port, Key: userKey, Cert: userKey + "-cert.pub", User: login, KnownHosts: knownHosts})
	}

	t.Run("cert_authority_line_logs_in", func(t *testing.T) {
		content := "@cert-authority " + hostPattern + " " + readPub(t, env.HostCAPub) + "\n"
		kh := writeKnownHosts("known_hosts", content)
		code, out := login1(kh)
		if code != 0 || !strings.Contains(out, "host-ok") {
			t.Fatalf("ssh with the host CA's @cert-authority line exited %d:\n%s", code, out)
		}
		if !strings.Contains(out, "matches the ED25519-CERT host certificate") {
			t.Fatalf("ssh did not authenticate the host by its certificate:\n%s", out)
		}
		for _, tofu := range []string{"authenticity of host", "Permanently added"} {
			if strings.Contains(out, tofu) {
				t.Fatalf("ssh output contains the TOFU message %q:\n%s", tofu, out)
			}
		}
		if after, err := os.ReadFile(kh); err != nil || string(after) != content { //nolint:gosec // test file
			t.Fatalf("known_hosts changed during login (TOFU learned a key): %q, %v", after, err)
		}
	})

	t.Run("empty_known_hosts_refuses", func(t *testing.T) {
		code, out := login1(writeKnownHosts("known_hosts_empty", ""))
		if code != 255 || !strings.Contains(out, "Host key verification failed") || strings.Contains(out, "host-ok") {
			t.Fatalf("ssh with an empty known_hosts exited %d, want 255 with Host key verification failed:\n%s", code, out)
		}
	})

	t.Run("user_ca_is_not_a_host_ca", func(t *testing.T) {
		kh := writeKnownHosts("known_hosts_user_ca", "@cert-authority "+hostPattern+" "+readPub(t, env.UserCAPub)+"\n")
		code, out := login1(kh)
		if code != 255 || !strings.Contains(out, "Host key verification failed") || strings.Contains(out, "host-ok") {
			t.Fatalf("ssh trusting the user CA as host CA exited %d, want 255 with Host key verification failed:\n%s", code, out)
		}
	})

	export := env.exportLog(t)
	code, out := auditVerify(t, env, export, "--json")
	if code != 0 {
		t.Fatalf("audit verify --pin exited %d:\n%s", code, out)
	}
	var res struct {
		Entries uint64         `json:"entries"`
		Issued  int            `json:"issued"`
		ByCA    map[string]int `json:"issued_by_ca"`
		Bundle  uint64         `json:"bundle_version"`
		LogKey  string         `json:"log_key"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("audit verify --json: %v\n%s", err, out)
	}
	if res.Entries != bootstrapLeaves+2 || res.Issued != 2 || res.ByCA["host"] != 1 || res.ByCA["user"] != 1 ||
		res.Bundle != 1 || res.LogKey != fingerprint(t, env.LogPub) {
		t.Fatalf("audit verify = %+v, want 4 entries with one host and one user issuance under bundle v1 and the bundle's log key", res)
	}
}
