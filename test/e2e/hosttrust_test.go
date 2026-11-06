//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// The three files keyroster login and keyroster known-hosts sync write in
// ~/.ssh (03-09b), and the state file in the CLI's config directory.
const (
	trustKnownHosts = "keyroster_known_hosts"
	trustKRL        = "keyroster_revoked_hosts.krl"
	trustSSHConfig  = "keyroster_ssh_config"
	trustStateFile  = "host-trust.json"
)

// trustManaged are the three managed file names in ~/.ssh.
var trustManaged = []string{trustKnownHosts, trustKRL, trustSSHConfig}

// trustCertAlgs offers the certificate first and the plain key after it,
// for every connection a test expects ssh to refuse: the client gets the
// certificate, and when no CA line covers the name it retries the plain
// key and refuses that (OpenSSH 10.x drops the retry when the plain
// algorithm is not offered; TestHostCertIssueAndServe/other_name_refused).
const trustCertAlgs = "ssh-ed25519-cert-v01@openssh.com,ssh-ed25519"

// revokedWord finds OpenSSH calling a key or certificate revoked; the
// managed file name keyroster_revoked_hosts.krl does not match it.
var revokedWord = regexp.MustCompile(`(?i)\brevoked\b`)

// requireRealHome returns the runner's real home (03-09b, QB-5): ssh
// expands ~ from the account database, never $HOME, so the CLIs must
// write the real ~/.ssh for ssh to read the files. It runs only in CI
// (GITHUB_ACTIONS=true) or with KEYROSTER_E2E_REAL_HOME=1, requires
// $HOME to be the account's home and none of the three managed files to
// exist, and removes them at cleanup (and ~/.ssh when this test created
// it and it is empty).
func requireRealHome(t *testing.T) string {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" && os.Getenv("KEYROSTER_E2E_REAL_HOME") != "1" {
		t.Fatal("this test writes the keyroster files in your real ~/.ssh; it runs in CI, or set KEYROSTER_E2E_REAL_HOME=1")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatalf("the account's home: %v", err)
	}
	if filepath.Clean(home) != filepath.Clean(u.HomeDir) {
		a, errA := os.Stat(home)
		b, errB := os.Stat(u.HomeDir)
		if errA != nil || errB != nil || !os.SameFile(a, b) {
			t.Fatalf("$HOME %s is not the account's home %s, which ssh reads", home, u.HomeDir)
		}
	}
	sshDir := filepath.Join(home, ".ssh")
	for _, name := range trustManaged {
		if _, err := os.Lstat(filepath.Join(sshDir, name)); err == nil {
			t.Fatalf("%s already exists; this test does not overwrite a real keyroster file", filepath.Join(sshDir, name))
		}
	}
	_, err = os.Lstat(sshDir)
	existed := err == nil
	t.Cleanup(func() {
		for _, name := range trustManaged {
			_ = os.Remove(filepath.Join(sshDir, name))
		}
		if !existed {
			_ = os.Remove(sshDir) // only when empty
		}
	})
	return home
}

// hostTrustKR is the keyroster CLI as admin, retrying while the server
// rate-limits; a failing call is reported with its stdout and stderr. It
// fails t, so each subtest builds its own.
func hostTrustKR(t *testing.T, env *serverEnv, admin *cliEnv) func(args ...string) string {
	t.Helper()
	return func(args ...string) string {
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
}

// writeTrustConfig writes a client configuration whose first line
// includes managed (the managed keyroster_ssh_config, or a copy of it),
// followed by the per-name blocks of D7 (QB-6: after the Include): web1
// and the unmanaged web2 at the host's sshd by HostKeyAlias; web2 brings
// its own strict trust options with an empty known_hosts file.
func writeTrustConfig(t *testing.T, managed string, port int) string {
	t.Helper()
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty_known_hosts")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	p := strconv.Itoa(port)
	cfg := "Include " + managed + "\n" +
		"Host web1\n\tHostName 127.0.0.1\n\tPort " + p + "\n\tHostKeyAlias web1\n" +
		"Host web2\n\tHostName 127.0.0.1\n\tPort " + p + "\n\tHostKeyAlias web2\n\tStrictHostKeyChecking yes\n" +
		"\tUserKnownHostsFile " + empty + "\n\tGlobalKnownHostsFile /dev/null\n"
	path := filepath.Join(dir, "ssh_config")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// trustedHostLogin runs ssh -F cfg -v to name as login from the loopback
// source src, with auth the identity options and extra more options. It
// sets none of the trust options: the managed block supplies them.
func trustedHostLogin(t *testing.T, cfg, login, name, src string, auth []string, extra ...string) (int, string) {
	t.Helper()
	args := []string{"-F", cfg, "-v"}
	args = append(args, auth...)
	args = append(args, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "BindAddress="+src)
	args = append(args, extra...)
	args = append(args, login+"@"+name, "true")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(opensshPrefix(t), "bin", "ssh"), args...)
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

// keyAuth are the identity options of a key file and its certificate.
func keyAuth(c agentCert) []string {
	return []string{"-i", c.key, "-o", "CertificateFile=" + c.cert, "-o", "IdentitiesOnly=yes"}
}

// wantNoPrompt fails when ssh printed a TOFU message.
func wantNoPrompt(t *testing.T, what, out string) {
	t.Helper()
	for _, tofu := range []string{"authenticity of host", "Permanently added"} {
		if strings.Contains(out, tofu) {
			t.Fatalf("%s: ssh printed the TOFU message %q:\n%s", what, tofu, out)
		}
	}
}

// caLines returns the @cert-authority lines of a known_hosts file: their
// host patterns and keys.
func caLines(t *testing.T, path string) (hosts [][]string, keys []ssh.PublicKey) {
	t.Helper()
	data := readFile(t, path)
	for _, l := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(l, "@cert-authority") {
			continue
		}
		marker, h, pub, _, _, err := ssh.ParseKnownHosts([]byte(l))
		if err != nil || marker != "cert-authority" {
			t.Fatalf("%s: line %q does not parse as @cert-authority: %v", path, l, err)
		}
		hosts, keys = append(hosts, h), append(keys, pub)
	}
	return hosts, keys
}

// configNames returns the names of the Host line of a managed
// keyroster_ssh_config.
func configNames(t *testing.T, path string) []string {
	t.Helper()
	for _, l := range strings.Split(string(readFile(t, path)), "\n") {
		if rest, ok := strings.CutPrefix(l, "Host "); ok {
			return strings.Fields(rest)
		}
	}
	return nil
}

// fileSnapshot is a file's bytes, or its absence.
type fileSnapshot struct {
	exists bool
	data   string
}

func snapshot(t *testing.T, path string) fileSnapshot {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // a test path
	if errors.Is(err, os.ErrNotExist) {
		return fileSnapshot{}
	}
	if err != nil {
		t.Fatal(err)
	}
	return fileSnapshot{exists: true, data: string(data)}
}

// copyManagedConfig writes a copy of the managed keyroster_ssh_config
// with its known-hosts paths (both) replaced by knownHosts and its
// RevokedHostKeys path by krlFile ("" keeps a path as it is).
func copyManagedConfig(t *testing.T, sshDir, knownHosts, krlFile string) string {
	t.Helper()
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimSuffix(string(readFile(t, filepath.Join(sshDir, trustSSHConfig))), "\n"), "\n") {
		key := strings.Fields(l)
		switch {
		case knownHosts != "" && len(key) == 2 && (key[0] == "UserKnownHostsFile" || key[0] == "GlobalKnownHostsFile"):
			l = "\t" + key[0] + " " + knownHosts
		case krlFile != "" && len(key) == 2 && key[0] == "RevokedHostKeys":
			l = "\tRevokedHostKeys " + krlFile
		}
		b.WriteString(l + "\n")
	}
	p := filepath.Join(t.TempDir(), "managed_copy")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// sshKeygenQ runs ssh-keygen -Q -f krlFile certFile and returns its exit
// code and output (1: revoked).
func sshKeygenQ(t *testing.T, krlFile, certFile string) (int, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh-keygen"), "-Q", "-f", krlFile, certFile)
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("ssh-keygen -Q: %v\n%s", err, out)
	}
	return 0, string(out)
}

// heartbeatDirectory is the directory version of name's last heartbeat.
func heartbeatDirectory(t *testing.T, kr func(args ...string) string, name string) uint64 {
	t.Helper()
	for _, row := range hostsStatusJSON(t, kr).Hosts {
		if row.Name == name && row.Heartbeat != nil {
			return row.Heartbeat.Status.Directory.Version
		}
	}
	return 0
}

// TestHostCertNoTOFU is 03-09b's tracer (REVOKE-04): an admin's
// keyroster known-hosts sync and a user's keyroster login write the
// CLI-managed files in the real ~/.ssh, and real ssh reaches an enrolled
// host by HostKeyAlias with no prompt; a name outside the managed block
// keeps the user's configuration; keyroster revoke host exits 0 while the
// agent is still served, and after a refresh the client refuses the host
// through the KRL alone and through the missing CA line alone.
func TestHostCertNoTOFU(t *testing.T) {
	home := requireRealHome(t)
	sshDir := filepath.Join(home, ".ssh")
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	admin.home = home
	kr := hostTrustKR(t, env, admin)
	eh := joinHostCert(t, env, kr, "web1")
	waitHostCerts(t, eh, 1, 120*time.Second, "no HostCertificate line within 120 s", nil)
	login := currentUser(t)
	c := issueAgentCert(t, env.Signer, "hc1", "role:ops")
	cfg := writeTrustConfig(t, "~/.ssh/"+trustSSHConfig, eh.sshd.port)
	certOnly := []string{"-o", "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com"}
	src := func(n byte) string { return net.IPv4(127, 0, 0, n).String() }
	sync := func(t *testing.T) string {
		t.Helper()
		out := hostTrustKR(t, env, admin)("known-hosts", "sync")
		if !strings.Contains(out, "Host trust refreshed (directory v") {
			t.Fatalf("known-hosts sync printed no refresh line:\n%s", out)
		}
		return out
	}
	wantWeb1 := func(t *testing.T, what string, auth []string) {
		t.Helper()
		code, out := trustedHostLogin(t, cfg, login, "web1", "127.0.0.1", auth, certOnly...)
		if code != 0 || !strings.Contains(out, "Server host certificate") {
			t.Fatalf("%s: ssh to web1 exited %d, want 0 with Server host certificate:\n%s", what, code, out)
		}
		wantNoPrompt(t, what, out)
	}
	// The managed known-hosts and KRL as they were before the revoke,
	// for the two single-cause refusals, in a directory that outlives the
	// subtest that copies them.
	var oldKnownHosts, oldKRL string
	keep := t.TempDir()

	t.Run("admin_sync_no_prompt", func(t *testing.T) {
		before := snapshot(t, filepath.Join(sshDir, "known_hosts"))
		out := sync(t)
		t.Logf("known-hosts sync:\n%s", out)
		for _, name := range trustManaged {
			if _, err := os.Stat(filepath.Join(sshDir, name)); err != nil {
				t.Fatalf("after sync: %v", err)
			}
		}
		if _, err := os.Stat(filepath.Join(admin.configHome, "keyroster", trustStateFile)); err != nil {
			t.Fatalf("after sync, the state file: %v", err)
		}
		hosts, keys := caLines(t, filepath.Join(sshDir, trustKnownHosts))
		hostCA := pubKey(t, readPub(t, env.Signer.HostCAPub))
		if len(hosts) != 1 || strings.Join(hosts[0], ",") != "web1" || string(keys[0].Marshal()) != string(hostCA.Marshal()) {
			t.Fatalf("%s holds CA lines for %v, want exactly @cert-authority web1 <the host CA>:\n%s", trustKnownHosts, hosts, readFile(t, filepath.Join(sshDir, trustKnownHosts)))
		}
		if names := configNames(t, filepath.Join(sshDir, trustSSHConfig)); strings.Join(names, " ") != "web1" {
			t.Fatalf("%s names %v, want web1:\n%s", trustSSHConfig, names, readFile(t, filepath.Join(sshDir, trustSSHConfig)))
		}
		wantWeb1(t, "web1 after the admin's sync", keyAuth(c))
		if after := snapshot(t, filepath.Join(sshDir, "known_hosts")); after != before {
			t.Fatalf("~/.ssh/known_hosts changed (before %+v, after %+v)", before, after)
		}
	})

	t.Run("name_outside_block_refused", func(t *testing.T) {
		// The positive control first, so the refusal is not vacuous.
		wantWeb1(t, "web1 (the control)", keyAuth(c))
		code, out := trustedHostLogin(t, cfg, login, "web2", src(2), keyAuth(c), "-o", "HostKeyAlgorithms="+trustCertAlgs)
		if code == 0 || !strings.Contains(out, "Host key verification failed") {
			t.Fatalf("ssh to web2 (outside the managed block) exited %d, want a refusal with Host key verification failed:\n%s", code, out)
		}
	})

	t.Run("user_login_writes_files", func(t *testing.T) {
		kr := hostTrustKR(t, env, admin)
		auth, fp := enroll(t, env, admin, "alice", webauthn.AlgES256)
		kr("user", "approve", "alice", "--fingerprint", fp, "--yes")
		kr("role", "grant", "ops", "--user", "alice", "--yes")
		// alice's own state is empty, so with the admin's files present
		// her first refresh would be refused (the damaged-state rule);
		// removing them also stands for a second machine.
		for _, name := range trustManaged {
			if err := os.Remove(filepath.Join(sshDir, name)); err != nil {
				t.Fatal(err)
			}
		}
		alice := newCLIEnv(t)
		if code, out, errOut := alice.run(t, env.initArgs()...); code != 0 {
			t.Fatalf("alice's keyroster init exited %d:\n%s\n%s", code, out, errOut)
		}
		alice.home = home
		sock := startAgent(t)
		_, out := loginOK(t, env, alice, auth, sock)
		if !strings.Contains(out, "Host trust refreshed (directory v") {
			t.Fatalf("keyroster login printed no host trust refresh line:\n%s", out)
		}
		for _, name := range trustManaged {
			if _, err := os.Stat(filepath.Join(sshDir, name)); err != nil {
				t.Fatalf("after alice's login: %v", err)
			}
		}
		if _, err := os.Stat(filepath.Join(alice.configHome, "keyroster", trustStateFile)); err != nil {
			t.Fatalf("after alice's login, her state file: %v", err)
		}
		code, sshOut := trustedHostLogin(t, cfg, login, "web1", "127.0.0.1", []string{"-o", "IdentityAgent=" + sock}, certOnly...)
		if code != 0 || !strings.Contains(sshOut, "Server host certificate") {
			t.Fatalf("alice's ssh to web1 through her agent exited %d, want 0 with Server host certificate:\n%s", code, sshOut)
		}
		wantNoPrompt(t, "alice's ssh to web1", sshOut)
	})

	t.Run("revoke_host_exit_0_agent_still_served", func(t *testing.T) {
		kr := hostTrustKR(t, env, admin)
		sync(t)
		wantWeb1(t, "web1 before the revoke (the control)", keyAuth(c))
		oldKnownHosts, oldKRL = filepath.Join(keep, "old_known_hosts"), filepath.Join(keep, "old_hosts.krl")
		copyFile(t, filepath.Join(sshDir, trustKnownHosts), oldKnownHosts, 0o600)
		copyFile(t, filepath.Join(sshDir, trustKRL), oldKRL, 0o600)
		before := hostsStatusJSON(t, kr).Current.Directory
		code, out, errOut := env.keyroster(t, admin, "", "revoke", "host", "web1", "--yes")
		t.Logf("keyroster revoke host web1:\n%s\n%s", out, errOut)
		if code != 0 || !strings.Contains(out, "agent keeps receiving state") {
			t.Fatalf("revoke host web1 exited %d, want 0 with the line that the agent keeps receiving state:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
		want := hostsStatusJSON(t, kr).Current.Directory
		if want <= before {
			t.Fatalf("revoke host left the directory at version %d (before: %d)", want, before)
		}
		for deadline := time.Now().Add(60 * time.Second); heartbeatDirectory(t, kr, "web1") < want; time.Sleep(500 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("web1's heartbeat did not reach directory v%d within 60 s\nfetch log:\n%s\nrun log:\n%s", want, eh.fetch.String(), eh.run.String())
			}
		}
		if strings.Contains(eh.fetch.String(), "not_approved") {
			t.Fatalf("the agent's fetch log names not_approved after the revoke:\n%s", eh.fetch.String())
		}
	})

	t.Run("refused_after_refresh", func(t *testing.T) {
		sync(t)
		certs := installedHostCerts(t, eh.agentHost)
		if len(certs) == 0 {
			t.Fatal("the agent installs no host certificate")
		}
		certFile := filepath.Join(t.TempDir(), "web1-cert.pub")
		if err := os.WriteFile(certFile, ssh.MarshalAuthorizedKey(certs[0]), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, out := sshKeygenQ(t, filepath.Join(sshDir, trustKRL), certFile); code != 1 {
			t.Fatalf("ssh-keygen -Q of the installed host certificate (serial %d) against the managed KRL exited %d, want 1 (revoked):\n%s", certs[0].Serial, code, out)
		}
		hosts, _ := caLines(t, filepath.Join(sshDir, trustKnownHosts))
		for _, h := range hosts {
			for _, n := range h {
				if n == "web1" {
					t.Fatalf("a CA line still lists web1 after the refresh: %v", hosts)
				}
			}
		}
		if names := configNames(t, filepath.Join(sshDir, trustSSHConfig)); !strings.Contains(" "+strings.Join(names, " ")+" ", " web1 ") {
			t.Fatalf("%s no longer names web1 (%v); the block must keep every name it saw", trustSSHConfig, names)
		}
		code, out := trustedHostLogin(t, cfg, login, "web1", src(3), keyAuth(c), "-o", "HostKeyAlgorithms="+trustCertAlgs)
		if code == 0 || !strings.Contains(out, "Host key verification failed") {
			t.Fatalf("ssh to the revoked web1 exited %d, want a refusal with Host key verification failed:\n%s", code, out)
		}
		wantNoPrompt(t, "ssh to the revoked web1", out)
	})

	t.Run("refused_through_krl_alone", func(t *testing.T) {
		if oldKnownHosts == "" {
			t.Fatal("revoke_host_exit_0_agent_still_served did not keep the old files")
		}
		// The control: the old CA line and the old KRL accept the host
		// key (user authentication fails: the disable emptied web1's
		// principals), so the refusal below is not vacuous.
		control := writeTrustConfig(t, copyManagedConfig(t, sshDir, oldKnownHosts, oldKRL), eh.sshd.port)
		_, out := trustedHostLogin(t, control, login, "web1", src(4), keyAuth(c), "-o", "HostKeyAlgorithms="+trustCertAlgs)
		if strings.Contains(out, "Host key verification failed") || !strings.Contains(out, "Server host certificate") {
			t.Fatalf("with the old CA line and the old KRL the host key was not accepted:\n%s", out)
		}
		t.Logf("control (old CA line, old KRL): the host key is accepted; user authentication: %v", strings.Contains(out, "Permission denied"))
		cfgKRL := writeTrustConfig(t, copyManagedConfig(t, sshDir, oldKnownHosts, ""), eh.sshd.port)
		code, out := trustedHostLogin(t, cfgKRL, login, "web1", src(5), keyAuth(c), "-o", "HostKeyAlgorithms="+trustCertAlgs)
		if code == 0 || !strings.Contains(out, "Host key verification failed") || !revokedWord.MatchString(out) {
			t.Fatalf("with the old CA line and the new KRL ssh exited %d, want Host key verification failed naming a revoked key:\n%s", code, out)
		}
	})

	t.Run("refused_through_missing_ca_line_alone", func(t *testing.T) {
		if oldKRL == "" {
			t.Fatal("revoke_host_exit_0_agent_still_served did not keep the old files")
		}
		cfgCA := writeTrustConfig(t, copyManagedConfig(t, sshDir, "", oldKRL), eh.sshd.port)
		code, out := trustedHostLogin(t, cfgCA, login, "web1", src(6), keyAuth(c), "-o", "HostKeyAlgorithms="+trustCertAlgs)
		if code == 0 || !strings.Contains(out, "Host key verification failed") || revokedWord.MatchString(out) {
			t.Fatalf("with the new known-hosts and the old KRL ssh exited %d, want Host key verification failed without a revoked key:\n%s", code, out)
		}
	})
}

// TestHostTrustLongLines is the OpenSSH oracle for the managed files'
// line shapes at their bounds and for the D7 block placement (03-09b,
// QB-1, QB-6).
func TestHostTrustLongLines(t *testing.T) {
	home := requireRealHome(t)
	env := startServerEnv(t, serverOpts{})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	admin.home = home
	kr := hostTrustKR(t, env, admin)
	kr("role", "add", "ops", "--max-ttl", "1h", "--yes")
	hostTrustLongLines(t, env, admin, home)
}

// longName is the i-th of the long test names: exactly 61 bytes, which
// the state file spends 64 bytes on, so they sort in index order.
func longName(i int) string { return fmt.Sprintf("h%060d", i) }

// hostTrustLongLines runs the long-line oracle against env, whose
// directory has one installed version and no host, as admin (whose home
// is the real home): (a) a state of 64,512 names of 61 bytes and one
// sync, then ssh -G reads the Host line whole; (b) one @cert-authority
// line of about 1 MiB of names, which ssh-keygen -F reads whole; (c) the
// D7 block after the Include leaves every other managed name strict, and
// the same block above the Include does not (OpenSSH reads an Include
// inside a non-matching Host block with NEVERMATCH).
func hostTrustLongLines(t *testing.T, env *serverEnv, admin *cliEnv, home string) {
	t.Helper()
	sshDir := filepath.Join(home, ".ssh")
	bundle, err := trust.ParseBundle(readFile(t, filepath.Join(env.Signer.BundleDir, "bundle.json")))
	if err != nil {
		t.Fatal(err)
	}
	const n = 64512
	names := make([]string, n)
	for i := range names {
		names[i] = longName(i)
	}
	state, err := json.Marshal(struct {
		Format           int      `json:"format"`
		InstallationID   string   `json:"installation_id"`
		BundleVersion    uint64   `json:"bundle_version"`
		OpsKey           string   `json:"ops_key"`
		DirectoryVersion uint64   `json:"directory_version"`
		DirectorySHA256  string   `json:"directory_sha256"`
		KRLVersion       uint64   `json:"krl_version"`
		Names            []string `json:"names"`
	}{1, bundle.InstallationID, bundle.Version, bundle.OpsKey.Key, 0, "", 0, names})
	if err != nil {
		t.Fatal(err)
	}
	state = append(state, '\n')
	if len(state) >= 5<<20 {
		t.Fatalf("the state is %d bytes, not below the 5 MiB read cap", len(state))
	}
	statePath := filepath.Join(admin.configHome, "keyroster", trustStateFile)
	if err := os.WriteFile(statePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("state: %d names of 61 bytes, %d bytes", n, len(state))

	t.Run("a_host_line_read_whole", func(t *testing.T) {
		out := hostTrustKR(t, env, admin)("known-hosts", "sync")
		t.Logf("known-hosts sync: %s", out)
		managed := filepath.Join(sshDir, trustSSHConfig)
		for _, name := range []string{names[0], names[n-1]} {
			if g := sshG(t, managed, name); !strings.Contains(g, "\nstricthostkeychecking true\n") {
				t.Fatalf("ssh -G -F %s %s does not print stricthostkeychecking true: the Host line of %d names was not read whole", managed, name, n)
			}
		}
	})

	t.Run("b_ca_line_read_whole", func(t *testing.T) {
		var list []string
		for size, i := 0, 0; size < 1<<20; i++ {
			list = append(list, longName(i))
			size += 62
		}
		kh := filepath.Join(t.TempDir(), "known_hosts")
		line := "@cert-authority " + strings.Join(list, ",") + " " + readPub(t, env.Signer.HostCAPub) + "\n"
		if err := os.WriteFile(kh, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{list[0], list[len(list)-1]} {
			cmd := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh-keygen"), "-F", name, "-f", kh)
			cmd.Env = envWithout("SSH_AUTH_SOCK")
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "found") {
				t.Fatalf("ssh-keygen -F %s in one @cert-authority line of %d bytes: %v\n%.300s", name, len(line), err, out)
			}
		}
	})

	t.Run("c_d7_block_after_include", func(t *testing.T) {
		first, last := names[0], names[n-1]
		block := "Host " + first + "\n\tPort 2222\n\tHostKeyAlias " + first + "\n"
		dir := t.TempDir()
		after := filepath.Join(dir, "after")
		above := filepath.Join(dir, "above")
		if err := os.WriteFile(after, []byte("Include ~/.ssh/"+trustSSHConfig+"\n"+block), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(above, []byte(block+"Include ~/.ssh/"+trustSSHConfig+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		g := sshG(t, after, last)
		if !strings.Contains(g, "\nstricthostkeychecking true\n") {
			t.Fatalf("with the D7 block after the Include, ssh -G %s does not print stricthostkeychecking true", last)
		}
		known := ""
		for _, l := range strings.Split(g, "\n") {
			if v, ok := strings.CutPrefix(l, "userknownhostsfile "); ok {
				known = v
			}
		}
		if !strings.HasSuffix(known, ".ssh/"+trustKnownHosts) {
			t.Fatalf("with the D7 block after the Include, ssh -G %s prints userknownhostsfile %q, want the managed file", last, known)
		}
		// The negative control: above the Include the block makes the
		// Include conditional on it, so the oracle cannot pass vacuously.
		if strings.Contains(sshG(t, above, last), "\nstricthostkeychecking true\n") {
			t.Fatalf("with the D7 block above the Include, ssh -G %s still prints stricthostkeychecking true: the oracle does not tell the placements apart", last)
		}
		if g := sshG(t, after, first); !strings.Contains(g, "\nport 2222\n") || !strings.Contains(g, "\nstricthostkeychecking true\n") {
			t.Fatalf("ssh -G %s with the D7 block does not print port 2222 and stricthostkeychecking true", first)
		}
	})
}

// sshG runs ssh -G -F cfg name and returns its output, with a leading
// newline so every line can be matched as "\n<line>\n".
func sshG(t *testing.T, cfg, name string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh"), "-G", "-F", cfg, name)
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		msg := ""
		if errors.As(err, &ee) {
			msg = string(ee.Stderr)
		}
		t.Fatalf("ssh -G -F %s %s: %v\n%.500s", cfg, name, err, msg)
	}
	return "\n" + string(out)
}
