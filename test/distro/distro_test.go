//go:build e2edistro && linux

// Package distro runs keyroster-agent against each supported
// distribution's own sshd, as root inside a container of that
// distribution (03-06, D-17). test/distro/run.sh builds the agent and this
// test binary on the host and runs them in the image; nothing here runs
// outside such a container.
package distro

import (
	"bytes"
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
		return fmt.Errorf("ssh-keygen -A: %v: %s", err, out)
	}
	if _, err := os.Stat(pristine); errors.Is(err, os.ErrNotExist) {
		if out, err := exec.Command("cp", "-a", "/etc/ssh", pristine).CombinedOutput(); err != nil {
			return fmt.Errorf("cp -a /etc/ssh: %v: %s", err, out)
		}
	}
	if err := exec.Command("id", account).Run(); err != nil {
		cmd := exec.Command("useradd", "-m", "-s", "/bin/sh", account)
		if _, lerr := exec.LookPath("useradd"); lerr != nil {
			cmd = exec.Command("adduser", "-D", "-s", "/bin/sh", account) // busybox (Alpine)
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create %s: %v: %s", account, err, out)
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
// sshd_config, files are extra files by path.
type hostEdit struct {
	config func(string) string
	files  map[string]string
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
	if err := startSSHD(); err != nil {
		t.Fatal(err)
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
		return fmt.Errorf("start sshd: %v: %s", err, out)
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
		b, err := os.ReadFile(pf)
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

func applyArgs() []string {
	return append(append([]string{"apply", "--once", "--spool", spoolDir, "--state-dir", stateDir}, service()...), "--reload", "signal")
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
	if err := os.Remove(override); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := agent(t, checkArgs()...); code != 0 {
		t.Fatalf("check after removing the override: exit %d: %s", code, out)
	}
	file := fmt.Sprintf("/etc/ssh/keyroster/gen/%d/principals/%s", r.Generation, account)
	b, err := os.ReadFile(file)
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
