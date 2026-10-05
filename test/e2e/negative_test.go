//go:build e2e

package e2e

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// caEnv is one bootstrapped signer and its user CA: the CA key file (for
// the ssh-keygen -s oracle), the CA public key file and the running
// signer.
type caEnv struct {
	*signerEnv
	caKey string // user CA private key file (ssh-keygen -s oracle only)
	caPub string // user CA public key file
}

// newCAEnv bootstraps a signer with generated role keys (ca-init, a
// root-signed genesis bundle, serve).
func newCAEnv(t *testing.T) *caEnv {
	t.Helper()
	env := bootstrapSigner(t, bootstrapOpts{})
	return &caEnv{signerEnv: env, caKey: env.RoleKeyFiles["user"], caPub: env.UserCAPub}
}

// newUserKey creates an Ed25519 user key in its own directory, so every
// certificate written next to it has a distinct path.
func newUserKey(t *testing.T, name string) string {
	t.Helper()
	key := filepath.Join(t.TempDir(), name)
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key)
	return key
}

// issueFor issues a certificate for key through the signer and returns its
// path (the CLI default, key-cert.pub).
func (e *caEnv) issueFor(t *testing.T, key string, principals ...string) string {
	t.Helper()
	args := []string{"--pubkey", key + ".pub", "--subject", "u:e2e", "--ttl", "10m"}
	for _, p := range principals {
		args = append(args, "--principal", p)
	}
	e.issue(t, args...)
	return key + "-cert.pub"
}

// oracleCert signs key with the CA key file through ssh-keygen -s (a test
// oracle, never product code) and returns the certificate path.
func (e *caEnv) oracleCert(t *testing.T, key, principal string, extra ...string) string {
	t.Helper()
	args := append([]string{"-q", "-s", e.caKey, "-I", "oracle", "-n", principal}, extra...)
	args = append(args, key+".pub")
	sshKeygen(t, args...)
	return key + "-cert.pub"
}

// sshExpectDenied asserts that ssh exits 255 with sshd's authentication
// refusal.
func sshExpectDenied(t *testing.T, opts loginOptions) {
	t.Helper()
	code, out := sshLogin(t, opts)
	if code != 255 || !strings.Contains(out, "Permission denied") {
		t.Fatalf("ssh exited %d, want 255 with \"Permission denied\":\n%s", code, out)
	}
}

// sshExpect asserts ssh's exit code.
func sshExpect(t *testing.T, want int, opts loginOptions) string {
	t.Helper()
	code, out := sshLogin(t, opts)
	if code != want {
		t.Fatalf("ssh %v %q exited %d, want %d:\n%s", opts.Extra, opts.Command, code, want, out)
	}
	return out
}

// TestSSHDRejects checks that real sshd refuses what the certificate or its
// configuration does not grant (CA-02, CA-05, CA-08). Each refusal changes
// one thing against a control that logs in, so a refusal cannot come from a
// broken setup. Certificates with other validity or extensions than the
// signer issues are crafted with ssh-keygen -s as a test oracle only.
func TestSSHDRejects(t *testing.T) {
	login := currentUser(t)
	ca := newCAEnv(t)
	// OpenSSH 9.8+ penalises a source address after repeated failed
	// authentications (PerSourcePenalties) and then drops its connections.
	// 9.5p1 does not know the option, so instead of turning it off, every
	// authentication refusal gets its own sshd with the default config.
	newSSHD := func() int {
		return startSSHD(t, sshdOptions{
			UserCAPub:  ca.caPub,
			Principals: map[string][]string{login: {login}},
		})
	}
	port := newSSHD() // shared by the cases that authenticate
	optsAt := func(p int, key, cert, command string, extra ...string) loginOptions {
		return loginOptions{Port: p, Key: key, Cert: cert, User: login, Command: command, Extra: extra}
	}
	opts := func(key, cert, command string, extra ...string) loginOptions {
		return optsAt(port, key, cert, command, extra...)
	}

	// The signer's certificate (extensions: permit-pty only) and an oracle
	// certificate with ssh-keygen's default extensions, which grant port
	// and agent forwarding. Forwarding cases run against both, so a refusal
	// is attributable to the signer's certificate, not to sshd_config.
	key := newUserKey(t, "id_signer")
	cert := ca.issueFor(t, key, login)
	permKey := newUserKey(t, "id_permissive")
	permCert := ca.oracleCert(t, permKey, login)

	t.Run("control_signer_cert_logs_in", func(t *testing.T) {
		sshExpect(t, 0, opts(key, cert, "true"))
	})

	t.Run("principal_not_listed", func(t *testing.T) {
		k := newUserKey(t, "id_other_principal")
		c := ca.issueFor(t, k, "not-listed")
		sshExpectDenied(t, optsAt(newSSHD(), k, c, "true"))
	})

	t.Run("ca_not_trusted", func(t *testing.T) {
		other := newCAEnv(t)
		k := newUserKey(t, "id_other_ca")
		c := other.issueFor(t, k, login)
		sshExpectDenied(t, optsAt(newSSHD(), k, c, "true"))
	})

	t.Run("expired", func(t *testing.T) {
		k := newUserKey(t, "id_expired")
		c := ca.oracleCert(t, k, login, "-V", "20200101:20200102")
		sshExpectDenied(t, optsAt(newSSHD(), k, c, "true"))
	})

	t.Run("not_yet_valid", func(t *testing.T) {
		k := newUserKey(t, "id_future")
		// A full day ahead, so the local-time interpretation of ssh-keygen
		// cannot make it valid in any time zone.
		from := time.Now().Add(24 * time.Hour).Format("20060102150405")
		to := time.Now().Add(48 * time.Hour).Format("20060102150405")
		c := ca.oracleCert(t, k, login, "-V", from+":"+to)
		sshExpectDenied(t, optsAt(newSSHD(), k, c, "true"))
	})

	// Local forwarding: -W opens a direct-tcpip channel to sshd's own port.
	t.Run("no_local_port_forwarding", func(t *testing.T) {
		out := sshExpect(t, 255, opts(key, cert, "", "-W", "127.0.0.1:"+strconv.Itoa(port)))
		if !strings.Contains(out, "administratively prohibited") {
			t.Fatalf("want sshd's \"administratively prohibited\" channel refusal:\n%s", out)
		}
	})
	t.Run("control_local_port_forwarding_with_permissive_cert", func(t *testing.T) {
		out := sshExpect(t, 0, opts(permKey, permCert, "", "-W", "127.0.0.1:"+strconv.Itoa(port)))
		if !strings.Contains(out, "SSH-2.0-OpenSSH") {
			t.Fatalf("want sshd's banner through the forwarded channel:\n%s", out)
		}
	})

	// Remote forwarding: sshd refuses the tcpip-forward request up front, so
	// ExitOnForwardFailure ends the session. (-L cannot be checked this way:
	// sshd refuses local forwards per channel, which no_local_port_forwarding
	// covers, and ssh rejects "-L 0:..." as a bad specification before it
	// connects, so that form would pass without reaching sshd.)
	t.Run("no_remote_port_forwarding", func(t *testing.T) {
		out := sshExpect(t, 255, opts(key, cert, "true",
			"-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:9"))
		if !strings.Contains(out, "remote port forwarding failed") {
			t.Fatalf("want \"remote port forwarding failed\":\n%s", out)
		}
	})
	t.Run("control_remote_port_forwarding_with_permissive_cert", func(t *testing.T) {
		sshExpect(t, 0, opts(permKey, permCert, "true",
			"-o", "ExitOnForwardFailure=yes", "-R", "0:127.0.0.1:9"))
	})

	// Agent forwarding: the client runs with a client agent in
	// SSH_AUTH_SOCK and -A; the remote shell must not get an SSH_AUTH_SOCK.
	clientAgent := startAgent(t)
	t.Run("no_agent_forwarding", func(t *testing.T) {
		code, out := sshWithAgent(t, clientAgent, opts(key, cert, `test -z "$SSH_AUTH_SOCK"`, "-A"))
		if code != 0 {
			t.Fatalf("remote SSH_AUTH_SOCK is set (ssh exited %d):\n%s", code, out)
		}
	})
	t.Run("control_agent_forwarding_with_permissive_cert", func(t *testing.T) {
		code, out := sshWithAgent(t, clientAgent, opts(permKey, permCert, `test -n "$SSH_AUTH_SOCK"`, "-A"))
		if code != 0 {
			t.Fatalf("agent not forwarded for a certificate with permit-agent-forwarding (ssh exited %d):\n%s", code, out)
		}
	})

	// PTY: permit-pty is the one extension the signer grants.
	t.Run("pty_allowed", func(t *testing.T) {
		out := sshExpect(t, 0, opts(key, cert, "test -t 0", "-tt"))
		if strings.Contains(out, "PTY allocation request failed") {
			t.Fatalf("sshd refused the PTY:\n%s", out)
		}
	})
	t.Run("control_no_pty_without_permit_pty", func(t *testing.T) {
		k := newUserKey(t, "id_no_pty")
		c := ca.oracleCert(t, k, login, "-O", "clear")
		code, out := sshLogin(t, opts(k, c, "test -t 0", "-tt"))
		if code == 0 || !strings.Contains(out, "PTY allocation request failed") {
			t.Fatalf("ssh exited %d, want non-zero with \"PTY allocation request failed\":\n%s", code, out)
		}
	})
}

// sshWithAgent runs ssh like sshLogin, but with SSH_AUTH_SOCK set to the
// client agent at agentSock, so -A has an agent to forward. (sshLogin clears
// SSH_AUTH_SOCK, and with -o ForwardAgent=<path> instead, ssh 10.5p1 sent
// no agent request in testing, which would make the refusal vacuous.)
func sshWithAgent(t *testing.T, agentSock string, opts loginOptions) (int, string) {
	t.Helper()
	args := []string{
		"-F", "none",
		"-i", opts.Key,
		"-o", "CertificateFile=" + opts.Cert,
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-p", strconv.Itoa(opts.Port),
	}
	args = append(args, opts.Extra...)
	args = append(args, opts.User+"@127.0.0.1", opts.Command)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(opensshPrefix(t), "bin", "ssh"), args...)
	cmd.Env = append(envWithout("SSH_AUTH_SOCK"), "SSH_AUTH_SOCK="+agentSock)
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

// runKeyroster runs the keyroster CLI and returns its exit code and output.
func runKeyroster(t *testing.T, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, keyrosterBin, args...)
	cmd.Env = envWithout("SSH_AUTH_SOCK")
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

// TestSignerRefuses checks refusals at the CLI and signer boundary (CA-02,
// CA-06, CA-07): each request exits non-zero with its specific reason,
// writes no certificate file, and the signer still serves the next valid
// request.
func TestSignerRefuses(t *testing.T) {
	login := currentUser(t)
	ca := newCAEnv(t)

	key := newUserKey(t, "id_ed25519")
	rsaKey := filepath.Join(t.TempDir(), "id_rsa2048")
	sshKeygen(t, "-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "rsa2048", "-f", rsaKey)
	certAsKey := ca.oracleCert(t, newUserKey(t, "id_certified"), login)

	cases := []struct {
		name     string
		pubkey   string
		args     []string
		wantCode int
		want     string
	}{
		{"no_principal", key + ".pub", nil, 2, "at least one --principal"},
		{"empty_principal", key + ".pub", []string{"--principal", ""}, 1, "bad_principal"},
		{"wildcard_principal", key + ".pub", []string{"--principal", "*"}, 1, "bad_principal"},
		{"comma_joined_principals", key + ".pub", []string{"--principal", "a,b"}, 1, "bad_principal"},
		{"whitespace_padded_principal", key + ".pub", []string{"--principal", " alice"}, 1, "bad_principal"},
		{"uppercase_principal", key + ".pub", []string{"--principal", "Alice"}, 1, "bad_principal"},
		{"certificate_as_pubkey", certAsKey, []string{"--principal", login}, 1, "bad_subject_key"},
		{"rsa_2048_pubkey", rsaKey + ".pub", []string{"--principal", login}, 1, "bad_subject_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "refused-cert.pub")
			defaultOut := strings.TrimSuffix(tc.pubkey, ".pub") + "-cert.pub"
			args := append([]string{"--pubkey", tc.pubkey, "--subject", "u:e2e", "--ttl", "10m", "--out", out}, tc.args...)
			code, output := ca.runIssue(t, args...)
			if code != tc.wantCode || !strings.Contains(output, tc.want) {
				t.Fatalf("keyroster ca issue exited %d, want %d with %q:\n%s", code, tc.wantCode, tc.want, output)
			}
			for _, p := range []string{out, defaultOut} {
				if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("certificate file %s exists after a refusal (stat: %v)", p, err)
				}
			}
			// The signer still serves the next valid request.
			next := newUserKey(t, "id_next")
			cert := ca.issueFor(t, next, login)
			if _, err := os.Stat(cert); err != nil {
				t.Fatalf("valid request after the refusal: %v", err)
			}
		})
	}

	// ca-init refuses a certificate held in the agent as a CA key (CA-07):
	// certificate entries are never CA keys, and nothing is initialised.
	t.Run("ca_init_certificate_as_user_ca", func(t *testing.T) {
		agent := startAgent(t)
		roleKeys, _ := newRoleKeys(t, agent, t.TempDir())
		certified := newUserKey(t, "id_agent_cert")
		agentCert := ca.oracleCert(t, certified, login)
		sshAdd(t, agent, certified) // loads the key and its -cert.pub
		roleKeys["user"] = fingerprint(t, agentCert)

		state := filepath.Join(shortTempDir(t), "state")
		if err := os.Mkdir(state, 0o700); err != nil {
			t.Fatal(err)
		}
		args := []string{"ca-init", "--state-dir", state, "--backend", "agent", "--backend-opt", "socket=" + agent}
		for _, role := range roleNames {
			args = append(args, "--key", role+"="+roleKeys[role])
		}
		code, output := runBin(t, signerBin, "", args...)
		if code == 0 || !strings.Contains(output, "pinned CA key not present") {
			t.Fatalf("ca-init with a certificate as the user CA exited %d, want the \"pinned CA key not present\" refusal:\n%s", code, output)
		}
		if _, err := os.Stat(filepath.Join(state, "ca-pubkeys.json")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("ca-init wrote ca-pubkeys.json although it refused (stat: %v)", err)
		}
		// Nothing was initialised: a correct ca-init on the same state works.
		roleKeys["user"] = fingerprint(t, certified+".pub")
		args = args[:len(args)-2*len(roleNames)]
		for _, role := range roleNames {
			args = append(args, "--key", role+"="+roleKeys[role])
		}
		if code, output := runBin(t, signerBin, "", args...); code != 0 {
			t.Fatalf("ca-init with the plain key after the refusal exited %d:\n%s", code, output)
		}
	})
}

// TestTrustRefuses (KEY-07, D-13) checks the trust boundary at the
// binaries: install-bundle refuses a genesis bundle whose root is not
// pinned and leaves the signer unable to start, and ca issue is refused
// without an admin key (by the CLI) and with a key the policy does not
// list (by the signer), writing no certificate either way.
func TestTrustRefuses(t *testing.T) {
	login := currentUser(t)

	t.Run("install_bundle_unpinned_root", func(t *testing.T) {
		env := initSigner(t, bootstrapOpts{})
		env.signGenesis(t, bootstrapOpts{})
		other := newUserKey(t, "not_the_root")
		args := env.installArgs()
		for i, a := range args {
			if a == "--pin" {
				args[i+1] = fingerprint(t, other+".pub")
			}
		}
		code, out := env.signerCmd(t, args...)
		if code == 0 || !strings.Contains(out, "pinned root fingerprints do not match") {
			t.Fatalf("install-bundle with an unpinned root exited %d, want the pin refusal:\n%s", code, out)
		}
		code, out = env.signerCmd(t, "serve", "--state-dir", env.StateDir, "--socket", env.Socket, "--allow-uid", strconv.Itoa(os.Getuid()))
		if code == 0 || !strings.Contains(out, "no trust bundle installed") {
			t.Fatalf("serve after the refused install exited %d, want \"no trust bundle installed\":\n%s", code, out)
		}
		// The correctly pinned install then succeeds.
		if code, out := env.signerCmd(t, env.installArgs()...); code != 0 {
			t.Fatalf("install-bundle with the right pin exited %d:\n%s", code, out)
		}
	})

	env := bootstrapSigner(t, bootstrapOpts{})
	key := newUserKey(t, "id_unauthorized")
	certFile := key + "-cert.pub"
	noCert := func(t *testing.T) {
		t.Helper()
		if _, err := os.Stat(certFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("certificate %s exists after a refusal (stat: %v)", certFile, err)
		}
	}
	t.Run("ca_issue_without_admin_key", func(t *testing.T) {
		code, out := keyrosterWithAgent(t, env.AdminAgent, "ca", "issue", "--socket", env.Socket,
			"--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
		if code != 2 || !strings.Contains(out, "--admin-key") {
			t.Fatalf("ca issue without --admin-key exited %d, want 2 naming --admin-key:\n%s", code, out)
		}
		noCert(t)
	})
	t.Run("ca_issue_with_non_admin_key", func(t *testing.T) {
		outsider := newUserKey(t, "outsider")
		sshAdd(t, env.AdminAgent, outsider)
		code, out := keyrosterWithAgent(t, env.AdminAgent, "ca", "issue", "--socket", env.Socket,
			"--admin-key", fingerprint(t, outsider+".pub"),
			"--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
		if code != 1 || !strings.Contains(out, "evidence_not_admin") {
			t.Fatalf("ca issue signed by a non-admin exited %d, want 1 with evidence_not_admin:\n%s", code, out)
		}
		noCert(t)
	})
	t.Run("control_admin_key", func(t *testing.T) {
		env.issue(t, "--pubkey", key+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
		if _, err := os.Stat(certFile); err != nil {
			t.Fatalf("admin-authorized request: %v", err)
		}
	})
}
