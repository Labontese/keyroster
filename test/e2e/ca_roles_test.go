//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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

// caKeysFile writes the given CA public key files into one file, for
// TrustedUserCAKeys.
func caKeysFile(t *testing.T, pubs ...string) string {
	t.Helper()
	var b strings.Builder
	for _, p := range pubs {
		b.WriteString(readPub(t, p) + "\n")
	}
	path := filepath.Join(t.TempDir(), "trusted_user_ca_keys")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil { //nolint:gosec // public keys
		t.Fatal(err)
	}
	return path
}

// TestMachineCAIsSeparate (CA-01, CA-04): a machine-CA certificate is a
// user-type certificate under the machine profile, signed by the machine
// CA with key ID kr1/ca=machine/... and pol=1. An sshd whose
// TrustedUserCAKeys holds only the user CA rejects it; the same
// certificate logs in once the machine CA is added. Each refusal runs
// against its own sshd (PerSourcePenalties, see TestSSHDRejects).
func TestMachineCAIsSeparate(t *testing.T) {
	login := currentUser(t)
	env := bootstrapSigner(t, bootstrapOpts{})

	key := newUserKey(t, "id_machine")
	// 24 h is the genesis machine profile's cap and twice the user cap.
	env.issue(t, "--ca", "machine", "--pubkey", key+".pub", "--principal", login, "--subject", "m:backup", "--ttl", "24h")
	certFile := key + "-cert.pub"
	listing := sshKeygen(t, "-L", "-f", certFile)
	info := parseCertInfo(t, listing)
	if !strings.Contains(listing, "user certificate") {
		t.Fatalf("machine certificate is not a user-type certificate:\n%s", listing)
	}
	if !strings.HasPrefix(info.keyID, "kr1/ca=machine/") || !strings.Contains(info.keyID, "/pol=1/") {
		t.Fatalf("machine certificate key ID %q, want kr1/ca=machine/... with pol=1", info.keyID)
	}
	if info.signingCAFP != fingerprint(t, env.MachineCAPub) || info.signingCAFP == fingerprint(t, env.UserCAPub) {
		t.Fatalf("machine certificate signed by %s, want the machine CA %s", info.signingCAFP, fingerprint(t, env.MachineCAPub))
	}
	if code, out := env.runIssue(t, "--ca", "machine", "--pubkey", key+".pub", "--principal", login,
		"--subject", "m:backup", "--ttl", "25h", "--out", filepath.Join(t.TempDir(), "over-cap-cert.pub")); code != 1 || !strings.Contains(out, "bad_validity") {
		t.Fatalf("machine certificate above the machine profile cap: exited %d, want 1 with bad_validity:\n%s", code, out)
	}

	principals := map[string][]string{login: {login}}
	opts := func(port int) loginOptions {
		return loginOptions{Port: port, Key: key, Cert: certFile, User: login, Command: "true"}
	}
	t.Run("user_ca_only_rejects", func(t *testing.T) {
		port := startSSHD(t, sshdOptions{UserCAPub: caKeysFile(t, env.UserCAPub), Principals: principals})
		sshExpectDenied(t, opts(port))
	})
	t.Run("control_user_cert_on_user_ca_only", func(t *testing.T) {
		port := startSSHD(t, sshdOptions{UserCAPub: caKeysFile(t, env.UserCAPub), Principals: principals})
		userKey := newUserKey(t, "id_user_control")
		env.issue(t, "--pubkey", userKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
		sshExpect(t, 0, loginOptions{Port: port, Key: userKey, Cert: userKey + "-cert.pub", User: login, Command: "true"})
	})
	t.Run("machine_ca_added_accepts", func(t *testing.T) {
		port := startSSHD(t, sshdOptions{UserCAPub: caKeysFile(t, env.UserCAPub, env.MachineCAPub), Principals: principals})
		sshExpect(t, 0, opts(port))
	})

	export := env.exportLog(t)
	code, out := auditVerify(t, env, export, "--json")
	var res struct {
		ByCA map[string]int `json:"issued_by_ca"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &res) != nil || res.ByCA["machine"] != 1 {
		t.Fatalf("audit verify exited %d, want OK with one machine issuance:\n%s", code, out)
	}
}

// presentCert authenticates to sshd at port as user with the private key in
// keyFile and the certificate in certFile through golang.org/x/crypto/ssh,
// which, unlike the OpenSSH client, sends any certificate it is given. It
// returns nil when sshd accepted the certificate.
func presentCert(t *testing.T, port int, user, keyFile, certFile string) error {
	t.Helper()
	keyPEM, err := os.ReadFile(keyFile) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	certLine, err := os.ReadFile(certFile) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certLine)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("%s holds no certificate", certFile)
	}
	certSigner, err := ssh.NewCertSigner(c, signer)
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // G106: the test checks user authentication only
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return err
	}
	return client.Close()
}

// TestHostCAIsNotUserCA (CA-01, CA-05): a host-type certificate presented
// as a user certificate is rejected by sshd, even when the operator
// mistakenly lists the host CA in TrustedUserCAKeys and the principal
// matches, while a user certificate presented the same way on the same
// sshd logs in. The stock OpenSSH client does not even offer it.
func TestHostCAIsNotUserCA(t *testing.T) {
	login := currentUser(t)
	env := bootstrapSigner(t, bootstrapOpts{})

	key := newUserKey(t, "id_host_as_user")
	env.issue(t, "--ca", "host", "--pubkey", key+".pub", "--principal", login, "--subject", "h:"+login, "--ttl", "1h")
	certFile := key + "-cert.pub"
	if listing := sshKeygen(t, "-L", "-f", certFile); !strings.Contains(listing, "host certificate") {
		t.Fatalf("the host CA did not issue a host certificate:\n%s", listing)
	}
	userKey := newUserKey(t, "id_user_control")
	env.issue(t, "--pubkey", userKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")

	principals := map[string][]string{login: {login}}
	t.Run("host_ca_trusted_as_user_ca_still_rejects", func(t *testing.T) {
		port := startSSHD(t, sshdOptions{UserCAPub: caKeysFile(t, env.UserCAPub, env.HostCAPub), Principals: principals})
		if err := presentCert(t, port, login, userKey, userKey+"-cert.pub"); err != nil {
			t.Fatalf("control: the user certificate was refused: %v", err)
		}
		err := presentCert(t, port, login, key, certFile)
		if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatalf("sshd accepted a host certificate as user certificate (err = %v)", err)
		}
	})
	t.Run("user_ca_only_rejects", func(t *testing.T) {
		port := startSSHD(t, sshdOptions{UserCAPub: caKeysFile(t, env.UserCAPub), Principals: principals})
		err := presentCert(t, port, login, key, certFile)
		if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
			t.Fatalf("sshd accepted a host certificate as user certificate (err = %v)", err)
		}
	})
	t.Run("openssh_client_does_not_offer_it", func(t *testing.T) {
		port := startSSHD(t, sshdOptions{UserCAPub: caKeysFile(t, env.UserCAPub, env.HostCAPub), Principals: principals})
		code, out := sshLogin(t, loginOptions{Port: port, Key: key, Cert: certFile, User: login, Command: "true", Extra: []string{"-v"}})
		if code != 255 || !strings.Contains(out, "Permission denied") || !strings.Contains(out, "not a user certificate") {
			t.Fatalf("ssh with a host certificate exited %d, want 255 after ignoring it as not a user certificate:\n%s", code, out)
		}
	})
}
