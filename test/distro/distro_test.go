//go:build e2edistro && linux

// Package distro runs keyroster-agent against each supported
// distribution's own sshd, as root inside a container of that
// distribution (03-06, D-17). test/distro/run.sh builds the agent and this
// test binary on the host and runs them in the image; nothing here runs
// outside such a container.
package distro

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/apply"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/trust"
)

const (
	sshdBin    = "/usr/sbin/sshd"
	sshdConfig = "/etc/ssh/sshd_config"
	dropInDir  = "/etc/ssh/sshd_config.d"
	stateDir   = "/var/lib/keyroster-agent"
	spoolDir   = "/var/spool/keyroster-agent"
	account    = "deploy"
	pristine   = "/var/tmp/keyroster-pristine-etc-ssh"
	sshdLog    = "/var/log/keyroster-test-sshd.log"
)

var (
	agentBin string
	distro   string
	keygen   string
)

func TestMain(m *testing.M) {
	distro = os.Getenv("KEYROSTER_DISTRO")
	if os.Geteuid() != 0 || distro == "" {
		fmt.Fprintln(os.Stderr, "test/distro runs as root inside a distribution container: bash test/distro/run.sh <image>")
		os.Exit(1)
	}
	agentBin = os.Getenv("KEYROSTER_AGENT")
	for _, p := range []string{"/usr/bin/ssh-keygen", "/bin/ssh-keygen"} {
		if _, err := os.Stat(p); err == nil {
			keygen = p
			break
		}
	}
	if err := setup(); err != nil {
		fmt.Fprintln(os.Stderr, "distro setup:", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = stopSSHD()
	os.Exit(code)
}

// setup keeps a pristine copy of /etc/ssh (each test starts from it) and
// creates the managed account.
func setup() error {
	if agentBin == "" || keygen == "" {
		return errors.New("KEYROSTER_AGENT and ssh-keygen are required")
	}
	if err := os.MkdirAll("/run/sshd", 0o755); err != nil { //nolint:gosec // sshd's privilege separation directory
		return err
	}
	if out, err := exec.Command(keygen, "-A").CombinedOutput(); err != nil {
		return fmt.Errorf("ssh-keygen -A: %w: %s", err, out)
	}
	if _, err := os.Stat(pristine); errors.Is(err, os.ErrNotExist) {
		if out, err := exec.Command("cp", "-a", "/etc/ssh", pristine).CombinedOutput(); err != nil {
			return fmt.Errorf("cp -a /etc/ssh: %w: %s", err, out)
		}
	}
	if err := exec.Command("id", account).Run(); err != nil {
		cmd := exec.Command("useradd", "-m", "-s", "/bin/sh", account)
		if _, lerr := exec.LookPath("useradd"); lerr != nil {
			cmd = exec.Command("adduser", "-D", "-s", "/bin/sh", account) // busybox (Alpine)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create %s: %w: %s", account, err, out)
		}
	}
	// A locked password ("!") makes an sshd without PAM (Alpine) refuse
	// every login; "*" is no password and not locked.
	b, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.SplitN(l, ":", 3); len(f) == 3 && f[0] == account {
			l = f[0] + ":*:" + f[2]
		}
		out = append(out, l)
	}
	return os.WriteFile("/etc/shadow", []byte(strings.Join(out, "\n")), 0o640) //nolint:gosec // the container's shadow file
}

// host is the container's sshd host under test.
type host struct {
	t       *testing.T
	w       *world
	hostKey ssh.PublicKey
}

// hostEdit changes the pristine /etc/ssh before sshd starts: config edits
// sshd_config, files are extra files by path; noStart leaves sshd
// stopped (a configuration it cannot load or bind; preflight needs only
// sshd -T).
type hostEdit struct {
	config  func(string) string
	files   map[string]string
	noStart bool
}

// newHost restores the pristine /etc/ssh, applies edit, empties the
// agent's state and spool, and starts the distribution's sshd.
func newHost(t *testing.T, popHosts bool, edit hostEdit) *host {
	t.Helper()
	if err := stopSSHD(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/etc/ssh", stateDir, spoolDir} {
		if err := os.RemoveAll(p); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cp", "-a", pristine, "/etc/ssh").CombinedOutput(); err != nil {
		t.Fatalf("restore /etc/ssh: %v: %s", err, out)
	}
	if edit.config != nil {
		b, err := os.ReadFile(sshdConfig)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sshdConfig, []byte(edit.config(string(b))), 0o644); err != nil { //nolint:gosec // sshd_config
			t.Fatal(err)
		}
	}
	for p, content := range edit.files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // test layout
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil { //nolint:gosec // test layout
			t.Fatal(err)
		}
	}
	for _, d := range []string{stateDir, spoolDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h := &host{t: t, w: newWorld(t, popHosts)}
	b, err := os.ReadFile("/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		t.Fatal(err)
	}
	if h.hostKey, _, _, _, err = ssh.ParseAuthorizedKey(b); err != nil {
		t.Fatal(err)
	}
	if !edit.noStart {
		if err := startSSHD(); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if t.Failed() {
			if b, err := os.ReadFile(sshdLog); err == nil {
				t.Logf("sshd log:\n%s", b)
			}
		}
	})
	return h
}

// sshdT runs sshd -T, with -C spec when spec is not empty.
func sshdT(t *testing.T, spec string) apply.Dump {
	t.Helper()
	args := []string{"-T", "-f", sshdConfig}
	if spec != "" {
		args = append(args, "-C", spec)
	}
	out, err := exec.Command(sshdBin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("sshd %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return apply.ParseDump(out)
}

func startSSHD() error {
	_ = os.Remove(sshdLog)
	if out, err := exec.Command(sshdBin, "-f", sshdConfig, "-E", sshdLog).CombinedOutput(); err != nil {
		return fmt.Errorf("start sshd: %w: %s", err, out)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:22", time.Second); err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	b, _ := os.ReadFile(sshdLog)
	return fmt.Errorf("sshd did not listen on 127.0.0.1:22 within 15 s:\n%s", b)
}

// stopSSHD stops the sshd the PidFile names, if any, and waits for it.
func stopSSHD() error {
	for _, pf := range []string{"/run/sshd.pid", "/var/run/sshd.pid"} {
		b, err := os.ReadFile(pf) //nolint:gosec // G304: sshd's own PidFile paths
		if err != nil {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || pid <= 1 {
			continue
		}
		_ = syscall.Kill(pid, syscall.SIGTERM)
		for i := 0; i < 100; i++ {
			if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		_ = os.Remove(pf)
	}
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", "127.0.0.1:22", 200*time.Millisecond)
		if err != nil {
			return nil
		}
		_ = c.Close()
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("sshd still listens after SIGTERM")
}

// enroll writes pins.json and the spool as the fetcher and enrollment
// would (03-07): the genesis bundle and policy and every directory
// version published.
func (h *host) enroll() {
	h.t.Helper()
	fd, err := spool.OpenDir(stateDir)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := state.WritePins(apply.Layout{Root: "/", StateDir: stateDir}, fd, h.w.pins()); err != nil {
		h.t.Fatal(err)
	}
	h.writeSpool()
}

func (h *host) writeSpool() {
	h.t.Helper()
	if err := spool.Write(spoolDir, h.w.spoolState()); err != nil {
		h.t.Fatal(err)
	}
}

// agent runs keyroster-agent and returns its exit status, stdout and
// stderr.
func agent(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(agentBin, args...) //nolint:gosec // G204: the agent under test
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		t.Fatalf("run keyroster-agent %s: %v", strings.Join(args, " "), err)
	}
	t.Logf("keyroster-agent %s: exit %d\nstdout:\n%s\nstderr:\n%s", args[0], code, stdout.String(), stderr.String())
	return code, stdout.String(), stderr.String()
}

// service is the explicit sshd service flags: the containers run no
// service manager, so the reload strategy is signal (D-17: the matrix
// exercises the signal strategy only).
func service() []string {
	return []string{"--root", "/", "--sshd", sshdBin, "--sshd-config", sshdConfig, "--ssh-keygen", keygen}
}

func applyBase() []string {
	return append(append([]string{"apply", "--once", "--spool", spoolDir, "--state-dir", stateDir}, service()...), "--reload", "signal")
}

// applyArgs switch the probe self-test off (03-10b): the matrix's probe
// tests are 03-10c's, and run.sh builds the agent as the e2e test build.
func applyArgs() []string {
	return append(applyBase(), "--probe-self-test", "off")
}

// probeApplyArgs run the probe self-test as production does, for the
// probe account the matrix creates (03-10c); a first install is exempt
// from the probes, so it lands and writes the probe principals file.
func probeApplyArgs() []string {
	return append(applyBase(), "--probe-self-test", "required", "--probe-account", probeName)
}

func preflightArgs(withState bool) []string {
	args := append([]string{"preflight"}, service()...)
	if withState {
		args = append(args, "--state-dir", stateDir, "--spool", spoolDir)
	}
	return args
}

func checkArgs() []string {
	return append([]string{"check", "--state-dir", stateDir}, service()...)
}

// The probe account of the matrix (03-10c): the runbook's script creates
// it under a name of its own, passed in KEYROSTER_PROBE_NAME, so that the
// script's parameter and --probe-account are both exercised. probeSpec is
// sshd -T -C for it from the probe's source address.
const (
	probeName = "probe1"
	probeSpec = "user=" + probeName + ",host=127.0.0.2,addr=127.0.0.2,laddr=127.0.0.1,lport=22"
)

// probeSerial numbers the probe certificates the tests mint.
var probeSerial uint64 = 1000

// accountFiles are the account databases the probe tests change.
var accountFiles = []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"}

// snapshotAccounts restores the account databases byte for byte when t
// ends, so that the next test sees the image's accounts (deploy included)
// whatever useradd, usermod or the test did to them.
func snapshotAccounts(t *testing.T) {
	t.Helper()
	saved := map[string][]byte{}
	for _, p := range accountFiles {
		b, err := os.ReadFile(p) //nolint:gosec // G304: the container's account files
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		saved[p] = b
	}
	t.Cleanup(func() {
		for p, b := range saved {
			if err := os.WriteFile(p, b, 0o600); err != nil { // an existing file keeps its mode
				t.Errorf("restore %s: %v", p, err)
			}
		}
	})
}

// createProbeAccount runs the runbook's account script for the image's
// family (run-in.sh exports both variables) and restores the accounts at
// cleanup.
func createProbeAccount(t *testing.T) {
	t.Helper()
	snapshotAccounts(t)
	script, family := os.Getenv("KEYROSTER_PROBE_ACCOUNT_SH"), os.Getenv("KEYROSTER_FAMILY")
	if script == "" || family == "" {
		t.Fatal("KEYROSTER_PROBE_ACCOUNT_SH and KEYROSTER_FAMILY are required (run-in.sh exports them)")
	}
	cmd := exec.Command("sh", script, family) //nolint:gosec // G204: the runbook's script under test
	cmd.Env = append(os.Environ(), "KEYROSTER_PROBE_NAME="+probeName)
	out, err := cmd.CombinedOutput()
	t.Logf("sh %s %s:\n%s", script, family, out)
	if err != nil {
		t.Fatalf("sh %s %s: %v", script, family, err)
	}
}

// probeHost is a host for the probe tests: sshd started with edit, the
// directory published and enrolled, the probe account created by the
// runbook's script and a probes-on first install, so that current holds
// the probe principals file for web1 and the machine CA line.
func probeHost(t *testing.T, edit hostEdit) *host {
	t.Helper()
	h := newHost(t, true, edit)
	h.w.publish(account, h.hostKey, "role:ops")
	h.enroll()
	createProbeAccount(t)
	code, out, _ := agent(t, probeApplyArgs()...)
	if r := decode[apply.Report](t, out); code != 0 || r.SelfTest != "pass" {
		t.Fatalf("probes-on first install: exit %d, %+v", code, r)
	}
	b, err := os.ReadFile("/etc/ssh/keyroster/current/principals/" + probeName) //nolint:gosec // G304: the generation under test
	if err != nil || !strings.Contains(string(b), "\nkeyroster-probe:web1\n") {
		t.Fatalf("the probe principals file: %v %q", err, b)
	}
	return h
}

// probeCert is a probe certificate the test minted, with its key for a
// full login.
type probeCert struct {
	cert   *ssh.Certificate
	signer ssh.Signer
}

// mintProbe makes a certificate with the real probe certificate's shape
// (internal/signer/probeissue.go): the machine CA, the probe profile, a
// kr3 key ID ca=machine subject probe.web1, the one principal
// keyroster-probe:web1, the two critical options, no extension, 600 s.
func (w *world) mintProbe() probeCert {
	w.t.Helper()
	pol, err := trust.ParsePolicy(w.policyDoc)
	if err != nil {
		w.t.Fatal(err)
	}
	profile, err := certprofile.ProbeProfile(pol)
	if err != nil {
		w.t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		w.t.Fatal(err)
	}
	subject, err := ssh.NewPublicKey(pub)
	if err != nil {
		w.t.Fatal(err)
	}
	probeSerial++
	req := make([]byte, 16)
	if _, err := rand.Read(req); err != nil {
		w.t.Fatal(err)
	}
	kid := cert.KeyID{V3: true, CA: "machine", Subject: "probe.web1", Request: hex.EncodeToString(req), Policy: pol.Version,
		Directory: uint64(len(w.dirs)), Serial: probeSerial} //nolint:gosec // G115: a small test count
	c, err := cert.Build(cert.Request{Profile: profile, Subject: subject, Principals: []string{cert.ReservedPrincipalPrefix + "web1"},
		Now: time.Now(), ValidFor: 600 * time.Second, KeyID: kid, Serial: probeSerial, CriticalOptions: certprofile.ProbeCriticalOptions()}, w.mach, rand.Reader)
	if err != nil {
		w.t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		w.t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(c, key)
	if err != nil {
		w.t.Fatal(err)
	}
	return probeCert{cert: c, signer: s}
}

// writeProbeKRL builds a KRL that revokes serials of the machine CA with
// the image's own ssh-keygen and writes it over the revoked.krl of the
// generation current names (a test-only replacement; no drift check runs
// after it).
func (w *world) writeProbeKRL(t *testing.T, serials ...uint64) {
	t.Helper()
	dir := t.TempDir()
	ca, spec, file := filepath.Join(dir, "machine_ca.pub"), filepath.Join(dir, "krl.spec"), filepath.Join(dir, "revoked.krl")
	var lines strings.Builder
	for _, s := range serials {
		fmt.Fprintf(&lines, "serial: %d\n", s)
	}
	if err := os.WriteFile(ca, ssh.MarshalAuthorizedKey(w.mach.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spec, []byte(lines.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(keygen, "-k", "-f", file, "-s", ca, spec).CombinedOutput(); err != nil { //nolint:gosec // G204: the image's ssh-keygen
		t.Fatalf("ssh-keygen -k: %v: %s", err, out)
	}
	b, err := os.ReadFile(file) //nolint:gosec // G304: the test's own KRL
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/ssh/keyroster/current/revoked.krl", b, 0o644); err != nil { //nolint:gosec // the generation's KRL, read by sshd
		t.Fatal(err)
	}
}

// hostKeys are every host key of the container's sshd: the query offers
// no host key algorithm of its own, so sshd may answer with any of them.
func hostKeys(t *testing.T) []ssh.PublicKey {
	t.Helper()
	files, err := filepath.Glob("/etc/ssh/ssh_host_*_key.pub")
	if err != nil || len(files) == 0 {
		t.Fatalf("host keys: %v %v", files, err)
	}
	var keys []ssh.PublicKey
	for _, f := range files {
		b, err := os.ReadFile(f) //nolint:gosec // G304: the container's host keys
		if err != nil {
			t.Fatal(err)
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		keys = append(keys, k)
	}
	return keys
}

// probe is the production PK_OK query (apply.ProbeQuery) of c for the
// probe account from src.
func (h *host) probe(src string, c *ssh.Certificate) (apply.ProbeOutcome, error) {
	h.t.Helper()
	return apply.ProbeQuery(context.Background(), apply.ProbeTarget{Addr: "127.0.0.1:22", Source: src, Account: probeName, HostKeys: hostKeys(h.t)},
		c, time.Now().Add(10*time.Second))
}

// runAs logs in as the probe account from src with s and requests
// command: it returns the session's output and exit status, or the error
// of a login or session that did not end with an exit status.
func (h *host) runAs(src string, s ssh.Signer, command string) (string, int, error) {
	h.t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 10 * time.Second}
	conn, err := d.Dial("tcp", "127.0.0.1:22")
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	cfg := &ssh.ClientConfig{User: probeName, Auth: []ssh.AuthMethod{ssh.PublicKeys(s)},
		HostKeyCallback: ssh.FixedHostKey(h.hostKey), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}}
	cc, chans, reqs, err := ssh.NewClientConn(conn, "127.0.0.1:22", cfg)
	if err != nil {
		return "", 0, fmt.Errorf("login: %w", err)
	}
	c := ssh.NewClient(cc, chans, reqs)
	defer func() { _ = c.Close() }()
	sess, err := c.NewSession()
	if err != nil {
		return "", 0, fmt.Errorf("session: %w", err)
	}
	out, err := sess.CombinedOutput(command)
	var ee *ssh.ExitError
	switch {
	case err == nil:
		return string(out), 0, nil
	case errors.As(err, &ee):
		return string(out), ee.ExitStatus(), nil
	}
	return string(out), 0, fmt.Errorf("session: %w", err)
}

// login authenticates as account with signer over loopback; nil is a
// login sshd accepted.
func (h *host) login(signer ssh.Signer) error {
	cfg := &ssh.ClientConfig{
		User: account, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(h.hostKey), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		Timeout: 10 * time.Second,
	}
	c, err := ssh.Dial("tcp", "127.0.0.1:22", cfg)
	if err == nil {
		_ = c.Close()
	}
	return err
}

func decode[T any](t *testing.T, s string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("decode %T: %v\n%s", v, err, s)
	}
	return v
}

func codes(r apply.PreflightReport) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

// TestDistroApply: the distribution's packaged sshd with StrictModes yes,
// a clean preflight, apply --once with the signal strategy, and a
// certificate login through the symlinked generation (A2).
func TestDistroApply(t *testing.T) {
	h := newHost(t, true, hostEdit{})
	h.w.publish(account, h.hostKey, "role:ops")
	h.enroll()
	if got := sshdT(t, "").One("strictmodes"); got != "yes" {
		t.Fatalf("sshd -T strictmodes = %q, want yes (the packaged default)", got)
	}
	if code, out, _ := agent(t, preflightArgs(true)...); code != 0 {
		t.Fatalf("preflight exit %d, want 0: %v", code, codes(decode[apply.PreflightReport](t, out)))
	}
	code, out, _ := agent(t, applyArgs()...)
	r := decode[apply.Report](t, out)
	if code != 0 || r.SelfTest != "pass" || !r.Reloaded || r.Generation == 0 {
		t.Fatalf("apply --once: exit %d, %+v", code, r)
	}
	if fi, err := os.Lstat("/etc/ssh/keyroster/current"); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("current is not a symlink: %v %v", fi, err)
	}
	spec := "user=" + account + ",host=127.0.0.1,addr=127.0.0.1,laddr=127.0.0.1,lport=22"
	if d := sshdT(t, spec); d.One("authorizedprincipalsfile") != "/etc/ssh/keyroster/current/principals/%u" || d.One("strictmodes") != "yes" {
		t.Fatalf("sshd -T -C: authorizedprincipalsfile %q, strictmodes %q", d.One("authorizedprincipalsfile"), d.One("strictmodes"))
	}
	if err := h.login(h.w.userCert(1, "role:ops")); err != nil {
		t.Fatalf("certificate login with StrictModes yes through current: %v", err)
	}
	// The refusal last: OpenSSH 10.x PerSourcePenalties.
	if err := h.login(h.w.userCert(2, "role:other")); err == nil {
		t.Fatal("a certificate without the account's principal logged in")
	}
}

// TestDistroDrift: a later Match block that overrides
// AuthorizedPrincipalsFile for the managed account is drift; removing it
// clears it; so does a changed generation file.
func TestDistroDrift(t *testing.T) {
	h := newHost(t, true, hostEdit{})
	h.w.publish(account, h.hostKey, "role:ops")
	h.enroll()
	if code, out, _ := agent(t, applyArgs()...); code != 0 {
		t.Fatalf("apply --once: exit %d: %s", code, out)
	}
	if code, out, _ := agent(t, checkArgs()...); code != 0 {
		t.Fatalf("check on a fresh install: exit %d: %s", code, out)
	}
	override := filepath.Join(dropInDir, "99-test.conf")
	if err := os.WriteFile(override, []byte("Match User "+account+"\n    AuthorizedPrincipalsFile none\n"), 0o644); err != nil { //nolint:gosec // test drop-in
		t.Fatal(err)
	}
	code, out, _ := agent(t, checkArgs()...)
	r := decode[apply.DriftReport](t, out)
	found := false
	for _, s := range r.Settings {
		if s.Keyword == "authorizedprincipalsfile" && s.Account == account && s.Got == "none" {
			found = true
		}
	}
	if code != 3 || !found {
		t.Fatalf("check with a Match override: exit %d, %+v; want exit 3 naming authorizedprincipalsfile for %s", code, r, account)
	}
	// PR #68 review D-R3 (F16): an AuthorizedPrincipalsCommand in a Match
	// block for the managed account is drift, by its file and line and by
	// sshd -T -C.
	if err := os.WriteFile(override, []byte("Match User "+account+"\n    AuthorizedPrincipalsCommand /bin/false\n    AuthorizedPrincipalsCommandUser nobody\n"), 0o644); err != nil { //nolint:gosec // test drop-in
		t.Fatal(err)
	}
	code, out, _ = agent(t, checkArgs()...)
	r = decode[apply.DriftReport](t, out)
	foreign, command := false, false
	for _, f := range r.Foreign {
		foreign = foreign || f.File == override && f.Line == 2
	}
	for _, s := range r.Settings {
		command = command || s.Keyword == "authorizedprincipalscommand" && s.Account == account && s.Got == "/bin/false"
	}
	if code != 3 || !foreign || !command {
		t.Fatalf("check with a principals command for %s: exit %d, %+v", account, code, r)
	}
	if err := os.Remove(override); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := agent(t, checkArgs()...); code != 0 {
		t.Fatalf("check after removing the override: exit %d: %s", code, out)
	}
	file := fmt.Sprintf("/etc/ssh/keyroster/gen/%d/principals/%s", r.Generation, account)
	b, err := os.ReadFile(file) //nolint:gosec // G304: a file of the generation under test
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, append(append([]byte{}, b...), "role:hand-added\n"...), 0o644); err != nil { //nolint:gosec // drift under test
		t.Fatal(err)
	}
	code, out, _ = agent(t, checkArgs()...)
	if r := decode[apply.DriftReport](t, out); code != 3 || len(r.Files) != 1 || r.Files[0].File != file {
		t.Fatalf("check with a changed principals file: exit %d, %+v", code, r)
	}
	if err := os.WriteFile(file, b, 0o644); err != nil { //nolint:gosec // restore
		t.Fatal(err)
	}
}
