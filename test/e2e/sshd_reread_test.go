//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/krl"
)

// rereadEnv is one sshd whose trust files are read through a current
// link, as the agent's drop-in arranges: TrustedUserCAKeys,
// RevokedKeys and AuthorizedPrincipalsFile all under <dir>/current/, and
// AuthorizedKeysFile <dir>/ak/%u for plain keys.
type rereadEnv struct {
	dir  string
	sshd *sshdRun
	user string
	ca1  string // CA key files (private; .pub beside)
	ca2  string
}

func (r *rereadEnv) gen(t *testing.T, name string, caKeys string, krlBytes []byte, principals string) {
	t.Helper()
	g := filepath.Join(r.dir, "gen", name)
	if err := os.MkdirAll(filepath.Join(g, "principals"), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	for f, b := range map[string][]byte{"user_ca_keys": []byte(caKeys), "revoked.krl": krlBytes, "principals/" + r.user: []byte(principals)} {
		if err := os.WriteFile(filepath.Join(g, f), b, 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
}

// swap points current at target (relative) with rename(2), as the agent
// does, and sends sshd no signal.
func (r *rereadEnv) swap(t *testing.T, target string) {
	t.Helper()
	tmp := filepath.Join(r.dir, ".current.tmp")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(r.dir, "current")); err != nil {
		t.Fatal(err)
	}
}

func newRereadEnv(t *testing.T, extra ...string) *rereadEnv {
	t.Helper()
	r := &rereadEnv{dir: t.TempDir(), user: currentUser(t)}
	r.ca1, r.ca2 = filepath.Join(r.dir, "ca1"), filepath.Join(r.dir, "ca2")
	for _, k := range []string{r.ca1, r.ca2} {
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", k)
	}
	if err := os.MkdirAll(filepath.Join(r.dir, "ak"), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	r.gen(t, "1", readPub(t, r.ca1+".pub")+"\n", nil, "p\n")
	r.swap(t, "gen/1")
	opts := sshdOptions{Extra: append([]string{
		"RevokedKeys " + filepath.Join(r.dir, "current", "revoked.krl"),
		"LoginGraceTime 3",
	}, extra...)}
	opts.UserCAPub = filepath.Join(r.dir, "current", "user_ca_keys")
	// The harness template's AuthorizedPrincipalsFile is <its dir>/principals/%u;
	// replace it with the current link's.
	r.sshd = startRereadSSHD(t, opts, filepath.Join(r.dir, "ak", "%u"), filepath.Join(r.dir, "current", "principals", "%u"), "")
	return r
}

// startRereadSSHD is startSSHDWithKeys with the AuthorizedPrincipalsFile
// line pointed at principals.
func startRereadSSHD(t *testing.T, opts sshdOptions, authorizedKeys, principals, hostKey string) *sshdRun {
	t.Helper()
	prefix := opensshPrefix(t)
	dir := t.TempDir()
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "ssh_host_ed25519_key"))
	port := freePort(t)
	cfg := fmt.Sprintf(sshdConfigTemplate, port, dir, dir, opts.UserCAPub, dir)
	cfg = regexp.MustCompile(`(?m)^AuthorizedPrincipalsFile .*$`).ReplaceAllString(cfg, "AuthorizedPrincipalsFile "+principals)
	cfg = strings.Replace(cfg, "\nAuthorizedKeysFile none\n", "\nAuthorizedKeysFile "+authorizedKeys+"\n", 1)
	if hostKey != "" {
		cfg = regexp.MustCompile(`(?m)^HostKey .*$`).ReplaceAllLiteralString(cfg, "HostKey "+hostKey)
	}
	for _, l := range opts.Extra {
		cfg += l + "\n"
	}
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	sshd := filepath.Join(prefix, "sbin", "sshd")
	if out, err := exec.Command(sshd, "-t", "-f", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("sshd -t: %v\n%s\n%s", err, out, cfg)
	}
	_, log, done := startDaemon(t, "sshd", envWithout("SSH_AUTH_SOCK"), sshd, "-D", "-e", "-f", cfgPath)
	pidFile := filepath.Join(dir, "sshd.pid")
	waitFor(t, "sshd port", done, log, func() bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		_, err = os.Stat(pidFile)
		return err == nil
	})
	return &sshdRun{port: port, pidFile: pidFile, log: log}
}

// userCert signs a fresh user key with ca for principal at serial.
func (r *rereadEnv) userCert(t *testing.T, ca, principal string, serial int) agentCert {
	t.Helper()
	key := filepath.Join(t.TempDir(), "id")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", key)
	sshKeygen(t, "-q", "-s", ca, "-I", "reread", "-n", principal, "-z", strconv.Itoa(serial), "-V", "+10m", key+".pub")
	return agentCert{key: key, cert: key + "-cert.pub", serial: strconv.Itoa(serial)}
}

// plainKey is a key listed in the user's authorized_keys file.
func (r *rereadEnv) plainKey(t *testing.T) string {
	t.Helper()
	key := filepath.Join(t.TempDir(), "id_plain")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", key)
	if err := os.WriteFile(filepath.Join(r.dir, "ak", r.user), []byte(readPub(t, key+".pub")+"\n"), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return key
}

func (r *rereadEnv) certLogin(t *testing.T, c agentCert, src string) int {
	t.Helper()
	code, _ := sshLogin(t, loginOptions{Port: r.sshd.port, Key: c.key, Cert: c.cert, User: r.user, Command: "true", Extra: []string{"-o", "BindAddress=" + src}})
	return code
}

func (r *rereadEnv) plainLogin(t *testing.T, key, src string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(opensshPrefix(t), "bin", "ssh"), "-F", "none", "-i", key, "-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "BindAddress="+src,
		"-p", strconv.Itoa(r.sshd.port), r.user+"@127.0.0.1", "true")
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0
}

func (r *rereadEnv) want(t *testing.T, what string, code int, accepted bool) {
	t.Helper()
	if (code == 0) != accepted {
		t.Fatalf("%s: ssh exited %d, want accepted=%t\nsshd log:\n%s", what, code, accepted, r.sshd.log.String())
	}
}

func caPub(t *testing.T, ca string) ssh.PublicKey {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(readPub(t, ca+".pub")))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// TestSshdRereadsTrustFiles pins the sshd behaviour the agent's design
// rests on (03-RESEARCH "Does sshd re-read the files without reload?"),
// on both CI OpenSSH versions. sshd reads TrustedUserCAKeys, RevokedKeys
// and AuthorizedPrincipalsFile for each authentication, so with one sshd
// PID and no signal, swapping the current link changes the outcome for
// a revoked serial, a removed principal and a removed CA. A corrupt KRL,
// and a current naming a missing directory (no revoked.krl at all),
// refuse every public key, plain authorized_keys keys included; a
// zero-byte KRL revokes nothing. An unparsable line before the CA key
// fails the certificate login, the same line after it does not. A
// replaced HostCertificate is served at once by 9.5p1 and only after
// SIGHUP by 10.5p1 (recorded for 03-09). sshd closes a connection that
// sends its banner and nothing more after LoginGraceTime and within
// LoginGraceTime + 5 s, well inside the agent's widening wait of
// LoginGraceTime + 30 s (F1's premise). Every refusal comes from its
// own sshd and loopback source, so OpenSSH 10.x's PerSourcePenalties
// never penalise an accepted login.
func TestSshdRereadsTrustFiles(t *testing.T) {
	t.Run("revoked_serial", func(t *testing.T) {
		r := newRereadEnv(t)
		pid := r.sshd.pid(t)
		c := r.userCert(t, r.ca1, "p", 5)
		r.want(t, "before the swap", r.certLogin(t, c, "127.0.0.1"), true)
		k, err := krl.Encode(krl.Set{Certs: []krl.CertSection{{CAKey: caPub(t, r.ca1), Serials: []uint64{5}}}}, 1, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		r.gen(t, "2", readPub(t, r.ca1+".pub")+"\n", k, "p\n")
		r.swap(t, "gen/2")
		before := r.sshd.log.String()
		r.want(t, "after the swap to a KRL revoking serial 5", r.certLogin(t, c, "127.0.0.2"), false)
		waitForLog(t, r.sshd, before, logRevoked)
		if r.sshd.pid(t) != pid {
			t.Fatal("sshd PID changed")
		}
	})
	t.Run("removed_principal", func(t *testing.T) {
		r := newRereadEnv(t)
		pid := r.sshd.pid(t)
		c := r.userCert(t, r.ca1, "p", 6)
		r.want(t, "with the principal", r.certLogin(t, c, "127.0.0.1"), true)
		r.gen(t, "2", readPub(t, r.ca1+".pub")+"\n", nil, "other\n")
		r.swap(t, "gen/2")
		before := r.sshd.log.String()
		r.want(t, "without the principal", r.certLogin(t, c, "127.0.0.2"), false)
		waitForLog(t, r.sshd, before, logNoPrincipal)
		r.swap(t, "gen/1")
		r.want(t, "the principal restored", r.certLogin(t, c, "127.0.0.1"), true)
		if r.sshd.pid(t) != pid {
			t.Fatal("sshd PID changed")
		}
	})
	t.Run("removed_ca", func(t *testing.T) {
		r := newRereadEnv(t)
		pid := r.sshd.pid(t)
		c := r.userCert(t, r.ca1, "p", 7)
		r.want(t, "CA1 listed", r.certLogin(t, c, "127.0.0.1"), true)
		r.gen(t, "2", readPub(t, r.ca2+".pub")+"\n", nil, "p\n")
		r.swap(t, "gen/2")
		r.want(t, "CA1 no longer listed", r.certLogin(t, c, "127.0.0.2"), false)
		if r.sshd.pid(t) != pid {
			t.Fatal("sshd PID changed")
		}
	})
	t.Run("corrupt_krl_refuses_all", func(t *testing.T) {
		r := newRereadEnv(t)
		c := r.userCert(t, r.ca1, "p", 8)
		plain := r.plainKey(t)
		r.want(t, "certificate before", r.certLogin(t, c, "127.0.0.1"), true)
		r.want(t, "plain key before", r.plainLogin(t, plain, "127.0.0.1"), true)
		k, err := krl.Encode(krl.Set{}, 1, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		k = append(k, 0x7f, 0, 0, 0, 0) // a section of unknown type
		r.gen(t, "2", readPub(t, r.ca1+".pub")+"\n", k, "p\n")
		r.swap(t, "gen/2")
		r.want(t, "certificate under a corrupt KRL", r.certLogin(t, c, "127.0.0.2"), false)
		r.want(t, "plain key under a corrupt KRL", r.plainLogin(t, plain, "127.0.0.3"), false)
	})
	t.Run("missing_krl_refuses_all", func(t *testing.T) {
		// The premise of --recover-to-last-good's direct swap from a
		// missing current (checker iteration 3).
		r := newRereadEnv(t)
		c := r.userCert(t, r.ca1, "p", 9)
		plain := r.plainKey(t)
		r.want(t, "certificate before", r.certLogin(t, c, "127.0.0.1"), true)
		r.want(t, "plain key before", r.plainLogin(t, plain, "127.0.0.1"), true)
		r.swap(t, "gen/9")
		r.want(t, "certificate with current missing", r.certLogin(t, c, "127.0.0.2"), false)
		r.want(t, "plain key with current missing", r.plainLogin(t, plain, "127.0.0.3"), false)
	})
	t.Run("empty_krl_accepted", func(t *testing.T) {
		r := newRereadEnv(t)
		c := r.userCert(t, r.ca1, "p", 10)
		plain := r.plainKey(t)
		if fi, err := os.Stat(filepath.Join(r.dir, "current", "revoked.krl")); err != nil || fi.Size() != 0 {
			t.Fatalf("revoked.krl: %v, %v", fi, err)
		}
		r.want(t, "certificate under a zero-byte KRL", r.certLogin(t, c, "127.0.0.1"), true)
		r.want(t, "plain key under a zero-byte KRL", r.plainLogin(t, plain, "127.0.0.1"), true)
	})
	t.Run("garbage_ca_line", func(t *testing.T) {
		r := newRereadEnv(t)
		c := r.userCert(t, r.ca1, "p", 11)
		ca := readPub(t, r.ca1+".pub")
		r.gen(t, "2", ca+"\nnot-a-key AAAAgarbage\n", nil, "p\n")
		r.swap(t, "gen/2")
		r.want(t, "a garbage line after the CA key", r.certLogin(t, c, "127.0.0.1"), true)
		r.gen(t, "3", "not-a-key AAAAgarbage\n"+ca+"\n", nil, "p\n")
		r.swap(t, "gen/3")
		r.want(t, "a garbage line before the CA key", r.certLogin(t, c, "127.0.0.2"), false)
	})
	t.Run("host_certificate_needs_sighup", func(t *testing.T) {
		// Recorded for 03-09: sshd loads HostCertificate at start and on
		// SIGHUP only.
		dir := t.TempDir()
		hostCA := filepath.Join(dir, "host_ca")
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", hostCA)
		hostKey := filepath.Join(dir, "hk")
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", hostKey)
		sign := func(serial int) {
			sshKeygen(t, "-q", "-s", hostCA, "-h", "-I", "host", "-n", "127.0.0.1", "-z", strconv.Itoa(serial), "-V", "+1h", hostKey+".pub")
		}
		sign(1)
		s := startRereadSSHD(t, sshdOptions{UserCAPub: filepath.Join(dir, "none"), Extra: []string{"HostCertificate " + hostKey + "-cert.pub"}}, "none", filepath.Join(dir, "p", "%u"), hostKey)
		served := func() string {
			var out []byte
			var err error
			// ssh-keyscan now and then gets no answer from a freshly
			// re-executed sshd; a few tries settle it.
			for try := 0; try < 5; try++ {
				out, err = exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh-keyscan"), "-c", "-t", "ed25519", "-p", strconv.Itoa(s.port), "127.0.0.1").CombinedOutput()
				if err == nil && strings.Contains(string(out), "-cert-v01@openssh.com") {
					break
				}
				time.Sleep(300 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("ssh-keyscan -c: %v\n%s\nsshd log:\n%s", err, out, s.log.String())
			}
			f := filepath.Join(t.TempDir(), "cert.pub")
			for _, l := range strings.Split(string(out), "\n") {
				// ssh-keyscan -c prints "TYPE BASE64", without the host.
				fields := strings.Fields(l)
				for i := 0; i+1 < len(fields); i++ {
					if strings.HasSuffix(fields[i], "-cert-v01@openssh.com") {
						if err := os.WriteFile(f, []byte(fields[i]+" "+fields[i+1]+"\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			if _, err := os.Stat(f); err != nil {
				t.Fatalf("ssh-keyscan -c served no certificate:\n%s", out)
			}
			m := regexp.MustCompile(`Serial: ([0-9]+)`).FindStringSubmatch(sshKeygen(t, "-L", "-f", f))
			if m == nil {
				t.Fatalf("no serial in the served certificate:\n%s", out)
			}
			return m[1]
		}
		if got := served(); got != "1" {
			t.Fatalf("served serial %s, want 1", got)
		}
		sign(2)
		// Recorded for 03-09, version by version: 10.x loads host keys
		// and certificates in the listener, so the old certificate stays
		// until SIGHUP; 9.x re-executes sshd for every connection, which
		// reads the new file at once.
		want := "1"
		if opensshMajor(t) < 10 {
			want = "2"
		}
		got := served()
		t.Logf("OpenSSH %d: after replacing HostCertificate without SIGHUP, sshd serves serial %s", opensshMajor(t), got)
		if got != want {
			t.Fatalf("after replacing the file without SIGHUP sshd serves serial %s, want %s on OpenSSH %d", got, want, opensshMajor(t))
		}
		if err := syscall.Kill(s.pid(t), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for served() != "2" {
			if time.Now().After(deadline) {
				t.Fatal("after SIGHUP sshd still serves the old certificate")
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	t.Run("login_grace_bounds_auth_reads", func(t *testing.T) {
		// F1's premise is about reads, not closes: when does sshd stop
		// processing an authentication (and so reading the trust files)?
		// One offered LoginGraceTime + 1 s after connect is recorded, not
		// asserted: 10.5p1 was seen to accept it in 2 of 3 runs, 9.5p1
		// refused it. One offered after LoginGraceTime + 5 s must be
		// refused: sshd's own bound, well inside the agent's widening wait
		// of LoginGraceTime + 30 s (owner decision 2026-10-26, PR #67).
		r := newRereadEnv(t)
		c := r.userCert(t, r.ca1, "p", 12)
		for _, d := range []struct {
			delay time.Duration
			must  bool
		}{{4 * time.Second, false}, {8500 * time.Millisecond, true}} {
			err := delayedCertAuth(t, r, c, d.delay)
			t.Logf("OpenSSH %d: a certificate offered %v after connect (LoginGraceTime 3): accepted=%t (%v)", opensshMajor(t), d.delay, err == nil, err)
			if d.must && err == nil {
				t.Fatalf("sshd accepted an authentication %v after connect, beyond LoginGraceTime + 5 s", d.delay)
			}
		}
	})
	t.Run("login_grace_closes_preauth", func(t *testing.T) {
		r := newRereadEnv(t)
		conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.sshd.port)))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		start := time.Now()
		if _, err := conn.Write([]byte("SSH-2.0-keyroster-grace-test\r\n")); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		_, err = io.Copy(io.Discard, bufio.NewReader(conn))
		if err != nil {
			t.Fatalf("sshd did not close the connection: %v after %v", err, time.Since(start))
		}
		t.Logf("sshd closed the connection %v after the banner", time.Since(start))
		// The agent's widening wait is LoginGraceTime + 30 s; this bounds
		// sshd far tighter, at LoginGraceTime + 5 s. With LoginGraceTime 3,
		// 9.5p1 closed about 3.1 s after the banner and 10.5p1 from 3.2 s to
		// 6.6 s.
		if took := time.Since(start); took < 3*time.Second || took > (3+5)*time.Second {
			t.Fatalf("sshd closed the pre-authentication connection after %v, want after LoginGraceTime 3 and within LoginGraceTime + 5 s", took)
		}
	})
}

// opensshMajor is the major version of the test OpenSSH (ssh -V).
func opensshMajor(t *testing.T) int {
	t.Helper()
	out, err := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh"), "-V").CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -V: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`OpenSSH_([0-9]+)\.`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("ssh -V: %s", out)
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// delayedCertAuth connects to r's sshd and offers certificate c only
// delay after the TCP connection opened; nil means sshd accepted it.
func delayedCertAuth(t *testing.T, r *rereadEnv, c agentCert, delay time.Duration) error {
	t.Helper()
	keyBytes, err := os.ReadFile(c.key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := os.ReadFile(c.cert)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("%s is not a certificate", c.cert)
	}
	cs, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(r.sshd.port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(start.Add(delay + 10*time.Second))
	cfg := &ssh.ClientConfig{User: r.user, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Auth: []ssh.AuthMethod{ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		time.Sleep(time.Until(start.Add(delay)))
		return []ssh.Signer{cs}, nil
	})}}
	_, _, _, err = ssh.NewClientConn(conn, "127.0.0.1", cfg)
	return err
}
