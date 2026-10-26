//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/apply"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// sshd log lines that name why a login was refused, taken from the
// 9.5p1 and 10.5p1 logs: a certificate the KRL revokes, and one that
// carries no principal of the account's AuthorizedPrincipalsFile.
const (
	logRevoked      = "revoked by file"
	logNoPrincipal  = "Certificate does not contain an authorized principal"
	agentLoginGrace = 3
)

var (
	agentBinOnce sync.Once
	agentBinPath string
	agentBinErr  error
)

// agentBin builds keyroster-agent once (harness_test.go's TestMain builds
// the other binaries; the agent is new in 03-05).
func agentBin(t *testing.T) string {
	t.Helper()
	agentBinOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			agentBinErr = err
			return
		}
		agentBinPath = filepath.Join(filepath.Dir(keyrosterBin), "keyroster-agent")
		cmd := exec.Command("go", "build", "-trimpath", "-o", agentBinPath, "./cmd/keyroster-agent")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			agentBinErr = fmt.Errorf("build keyroster-agent: %w\n%s", err, out)
		}
	})
	if agentBinErr != nil {
		t.Fatal(agentBinErr)
	}
	return agentBinPath
}

// includeSSHD is a test sshd whose configuration starts with an Include
// of <root>/etc/ssh/sshd_config.d/*.conf and sets no trust file of its
// own: everything it trusts comes from the agent's drop-in.
type includeSSHD struct {
	*sshdRun
	cfg     string
	hostKey string // the host key's .pub file
	cmd     *exec.Cmd
	done    <-chan struct{}
}

func startIncludeSSHD(t *testing.T, root string, extra ...string) *includeSSHD {
	t.Helper()
	prefix := opensshPrefix(t)
	dir := t.TempDir()
	key := filepath.Join(dir, "ssh_host_ed25519_key")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", key)
	port := freePort(t)
	cfg := fmt.Sprintf(`Include %s/*.conf
Port %d
ListenAddress 127.0.0.1
HostKey %s
PidFile %s/sshd.pid
StrictModes no
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthorizedKeysFile none
LogLevel VERBOSE
LoginGraceTime %d
`, filepath.Join(root, "etc", "ssh", "sshd_config.d"), port, key, dir, agentLoginGrace)
	for _, l := range extra {
		cfg += l + "\n"
	}
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	sshd := filepath.Join(prefix, "sbin", "sshd") // absolute: sshd re-execs itself
	if out, err := exec.Command(sshd, "-t", "-f", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("sshd -t: %v\n%s\n%s", err, out, cfg)
	}
	cmd, log, done := startDaemon(t, "sshd", envWithout("SSH_AUTH_SOCK"), sshd, "-D", "-e", "-f", cfgPath)
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
	return &includeSSHD{sshdRun: &sshdRun{port: port, pidFile: pidFile, log: log}, cfg: cfgPath, hostKey: key + ".pub", cmd: cmd, done: done}
}

// stop ends sshd and waits for it.
func (s *includeSSHD) stop(t *testing.T) {
	t.Helper()
	_ = s.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatal("sshd did not stop")
	}
}

// agentHost is one host driven by keyroster-agent from a signer's signed
// state: its root, state directory, spool and sshd.
type agentHost struct {
	signer               *signerEnv
	root, state, spoolDr string
	sshd                 *includeSSHD
}

func newAgentHost(t *testing.T, env *signerEnv, sshdExtra ...string) *agentHost {
	t.Helper()
	base := t.TempDir()
	h := &agentHost{signer: env, root: filepath.Join(base, "root"), state: filepath.Join(base, "state"), spoolDr: filepath.Join(base, "spool")}
	for _, d := range []string{h.root, h.state, h.spoolDr} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The host's own /etc/ssh/sshd_config.d: the agent writes its drop-in
	// there and creates no sshd configuration directory itself.
	if err := os.MkdirAll(filepath.Join(h.root, "etc", "ssh", "sshd_config.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.sshd = startIncludeSSHD(t, h.root, sshdExtra...)
	fd, err := spool.OpenDir(h.state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	pins := &state.Pins{TrustPins: env.RootFingerprints, Threshold: 1, InstallationID: env.InstallationID}
	if err := state.WritePins(apply.Layout{Root: h.root, StateDir: h.state}, fd, pins); err != nil {
		t.Fatal(err)
	}
	return h
}

// refreshSpool copies the signer's bundle, policy, directory and KRL into
// the spool, as the fetcher (03-07) will.
func (h *agentHost) refreshSpool(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	st, err := signerclient.Status(ctx, h.signer.Socket)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := trust.ParsePolicy(st.Policy)
	if err != nil {
		t.Fatal(err)
	}
	s := spool.State{
		Bundles:  map[uint64]spool.Doc{st.BundleVersion: {Body: st.Bundle, Sigs: st.BundleSigs}},
		Policies: map[uint64]spool.Doc{pol.Version: {Body: st.Policy, Sigs: st.PolicySigs}},
	}
	dir, err := signerclient.GetDirectory(ctx, h.signer.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if dir.Version > 0 {
		s.Directories = map[uint64]spool.Doc{dir.Version: {Body: dir.Directory, Sigs: dir.Sigs}}
	}
	k, err := signerclient.GetKRL(ctx, h.signer.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.KRL) > 0 {
		var m struct {
			Version uint64 `json:"krl_version"`
		}
		if err := json.Unmarshal(k.Manifest, &m); err != nil {
			t.Fatal(err)
		}
		s.KRLs = map[uint64]spool.KRLFiles{m.Version: {KRL: k.KRL, Manifest: k.Manifest, Sig: k.Sig}}
	}
	if err := spool.Write(h.spoolDr, s); err != nil {
		t.Fatal(err)
	}
}

func (h *agentHost) applyArgs(t *testing.T) []string {
	t.Helper()
	prefix := opensshPrefix(t)
	return []string{"apply", "--once", "--spool", h.spoolDr, "--state-dir", h.state, "--root", h.root,
		"--sshd", filepath.Join(prefix, "sbin", "sshd"), "--sshd-config", h.sshd.cfg,
		"--ssh-keygen", filepath.Join(prefix, "bin", "ssh-keygen"), "--reload", "signal"}
}

// agentRun is one keyroster-agent apply --once, started by start.
type agentRun struct {
	cmd            *exec.Cmd
	stdout, stderr strings.Builder
}

// start starts keyroster-agent apply --once; finish waits for it.
func (h *agentHost) start(t *testing.T) *agentRun {
	t.Helper()
	a := &agentRun{cmd: exec.Command(agentBin(t), h.applyArgs(t)...)}
	a.cmd.Env = envWithout("SSH_AUTH_SOCK")
	a.cmd.Stdout, a.cmd.Stderr = &a.stdout, &a.stderr
	if err := a.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return a
}

// finish waits for the run and returns its exit code, report and stderr.
func (a *agentRun) finish(t *testing.T) (int, apply.Report, string) {
	t.Helper()
	err := a.cmd.Wait()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	var r apply.Report
	if jerr := json.Unmarshal([]byte(a.stdout.String()), &r); jerr != nil {
		t.Fatalf("agent report: %v\nstdout:\n%s\nstderr:\n%s", jerr, a.stdout.String(), a.stderr.String())
	}
	t.Logf("keyroster-agent apply exit %d: generation=%d intermediate=%d reloaded=%t waited_ms=%d self_test=%q rollback=%t errors=%q",
		code, r.Generation, r.Intermediate, r.Reloaded, r.WaitedMS, r.SelfTest, r.Rollback, r.Errors)
	return code, r, a.stderr.String()
}

// apply runs keyroster-agent apply --once to the end.
func (h *agentHost) apply(t *testing.T) (int, apply.Report, string) {
	t.Helper()
	return h.start(t).finish(t)
}

// current returns the generation current names.
func (h *agentHost) current(t *testing.T) string {
	t.Helper()
	target, err := os.Readlink(filepath.Join(h.root, "etc", "ssh", "keyroster", "current"))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// agentDirectory builds an installation-bound directory: role ops with
// principals, host group lab mapping account to ops, and host web1 with
// the test sshd's host key.
func agentDirectory(t *testing.T, env *signerEnv, prev []byte, account, hostKeyPub string, principals ...string) []byte {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(readPub(t, hostKeyPub)))
	if err != nil {
		t.Fatal(err)
	}
	d := &directory.Directory{Version: 1, Prev: trust.GenesisPrev, Users: []directory.User{}, Groups: []directory.Group{},
		Roles:          []directory.Role{{Name: "ops", Principals: principals, MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{}, Groups: []string{}}},
		HostGroups:     []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: account, Roles: []string{"ops"}}}}},
		Hosts:          []directory.Host{{Name: "web1", HostGroup: "lab", Keys: []string{trust.FormatKey(key)}, Principals: []string{"web1"}, Status: directory.StatusActive}},
		InstallationID: env.InstallationID,
	}
	if prev != nil {
		p, err := directory.Parse(prev)
		if err != nil {
			t.Fatal(err)
		}
		d.Version, d.Prev = p.Version+1, trust.SHA256Hex(prev)
	}
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Parse(doc); err != nil {
		t.Fatalf("test directory: %v", err)
	}
	return doc
}

func installAgentDirectory(t *testing.T, env *signerEnv, doc []byte) {
	t.Helper()
	if _, err := signerclient.InstallDirectory(context.Background(), env.Socket, &wire.InstallDirectoryRequest{Directory: doc, Sigs: adminSign(t, env, directory.Namespace, doc)}); err != nil {
		t.Fatalf("install directory: %v", err)
	}
}

// revokeSerial revokes a user certificate's serial straight at the signer,
// authorized by the admin key (keyroster revoke serial does the same
// through keyroster-server).
func revokeSerial(t *testing.T, env *signerEnv, serial string) {
	t.Helper()
	n, err := strconv.ParseUint(serial, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	req := &wire.RevokeRequest{InstallationID: env.InstallationID, Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: n,
		CreatedAt: uint64(time.Now().Unix()), Reason: "e2e agent"} //nolint:gosec // G115: the clock is after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: adminSign(t, env, wire.RevokeSSHSIGNamespace, req.SigningBytes())}}
	if _, err := signerclient.Revoke(context.Background(), env.Socket, req); err != nil {
		t.Fatalf("revoke serial %s: %v", serial, err)
	}
}

// agentCert is one user certificate issued by the signer's admin path.
type agentCert struct{ key, cert, serial string }

func issueAgentCert(t *testing.T, env *signerEnv, name, principal string) agentCert {
	t.Helper()
	key := filepath.Join(t.TempDir(), "id_"+name)
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key)
	env.issue(t, "--pubkey", key+".pub", "--principal", principal, "--subject", "u:"+name, "--ttl", "10m")
	c := agentCert{key: key, cert: key + "-cert.pub"}
	c.serial = parseCertInfo(t, sshKeygen(t, "-L", "-f", c.cert)).serial
	return c
}

// loginFrom logs in with c from the loopback source address src (every
// refusal gets its own source, so OpenSSH 10.x's PerSourcePenalties never
// touch 127.0.0.1, which the accepted logins and the agent's self-test
// use).
func (h *agentHost) loginFrom(t *testing.T, c agentCert, user, src string) (int, string) {
	t.Helper()
	return sshLogin(t, loginOptions{Port: h.sshd.port, Key: c.key, Cert: c.cert, User: user, Command: "true", Extra: []string{"-o", "BindAddress=" + src}})
}

func (h *agentHost) wantAccepted(t *testing.T, what string, c agentCert, user string) {
	t.Helper()
	if code, out := h.loginFrom(t, c, user, "127.0.0.1"); code != 0 {
		t.Fatalf("%s: login exited %d, want 0:\n%s\nsshd log:\n%s", what, code, out, h.sshd.log.String())
	}
}

func (h *agentHost) wantRefused(t *testing.T, what string, c agentCert, user, src, logLine string) {
	t.Helper()
	before := h.sshd.log.String()
	if code, out := h.loginFrom(t, c, user, src); code == 0 {
		t.Fatalf("%s: login succeeded, want a refusal:\n%s", what, out)
	}
	waitForLog(t, h.sshd.sshdRun, before, logLine)
	t.Logf("%s: refused from %s (sshd: %q)", what, src, logLine)
}

// TestAgentApplyEndToEnd is 03-05's tracer: keyroster-agent apply --once
// drives a real sshd entirely from signed state. The signer's
// installation-bound bundle (policy with pop.hosts), a directory naming
// host web1 by the test sshd's host key, and its KRL go into the spool;
// the agent verifies them against pins.json, installs a first generation
// and the drop-in (one reload), and the certificate logs in. A
// revocation and a principal removal then each apply with no reload and
// one swap. A change that revokes certificate Y and adds principal q in
// one apply goes through the intermediate generation: while current names
// it, Y and a q-only certificate are both refused; after the final swap,
// LoginGraceTime 3 + 30 s later, Y is still refused and q is accepted. The
// sshd PID never changes after the first install. Finally, with sshd
// stopped, a new KRL fails its self-test and is rolled back to last-good.
func TestAgentApplyEndToEnd(t *testing.T) {
	env := bootstrapSigner(t, bootstrapOpts{PoPHosts: true})
	login := currentUser(t)
	h := newAgentHost(t, env)

	c1 := issueAgentCert(t, env, "c1", "role:ops")
	c2 := issueAgentCert(t, env, "c2", "role:ops")
	old := issueAgentCert(t, env, "old", "role:old")
	y := issueAgentCert(t, env, "y", "role:ops")
	q := issueAgentCert(t, env, "q", "role:q")
	z := issueAgentCert(t, env, "z", "role:ops")

	dir1 := agentDirectory(t, env, nil, login, h.sshd.hostKey, "role:old", "role:ops")
	installAgentDirectory(t, env, dir1)

	// 1. First install: generation, drop-in, one reload, self-test.
	h.refreshSpool(t)
	code, r, stderr := h.apply(t)
	if code != 0 || !r.Reloaded || r.Intermediate != 0 || r.SelfTest != "pass" || r.Rollback {
		t.Fatalf("first install: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	h.wantAccepted(t, "c1 after the first install", c1, login)
	pid := h.sshd.pid(t)

	// 2. Revoke c1: a revocation only, one narrowing swap, no reload.
	revokeSerial(t, env, c1.serial)
	h.refreshSpool(t)
	if code, r, stderr = h.apply(t); code != 0 || r.Reloaded || r.Intermediate != 0 || r.SelfTest != "pass" {
		t.Fatalf("revocation: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	h.wantAccepted(t, "c2 after c1's revocation", c2, login)
	h.wantRefused(t, "c1 after its revocation", c1, login, "127.0.0.2", logRevoked)

	// 3. A new directory version removes principal role:old.
	h.wantAccepted(t, "old before the removal", old, login)
	dir2 := agentDirectory(t, env, dir1, login, h.sshd.hostKey, "role:ops")
	installAgentDirectory(t, env, dir2)
	h.refreshSpool(t)
	if code, r, stderr = h.apply(t); code != 0 || r.Reloaded || r.Intermediate != 0 || r.SelfTest != "pass" {
		t.Fatalf("principal removal: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	h.wantRefused(t, "old after role:old was removed", old, login, "127.0.0.3", logNoPrincipal)

	// 4. Revoke y and add role:q in one spool update (the Codex
	// interleaving): the apply goes through the intermediate.
	h.wantAccepted(t, "y before its revocation", y, login)
	before := h.current(t)
	dir3 := agentDirectory(t, env, dir2, login, h.sshd.hostKey, "role:ops", "role:q")
	installAgentDirectory(t, env, dir3)
	revokeSerial(t, env, y.serial)
	h.refreshSpool(t)
	run := h.start(t)
	deadline := time.Now().Add(15 * time.Second)
	for h.current(t) == before {
		if time.Now().After(deadline) {
			t.Fatal("current never moved to the intermediate generation")
		}
		time.Sleep(20 * time.Millisecond)
	}
	mid := h.current(t)
	// The marker names that intermediate, and moves to step final right
	// after the swap: the next swap is the final one.
	for {
		pending, err := os.ReadFile(filepath.Join(h.state, "pending.json"))
		var m struct {
			Intermediate uint64 `json:"intermediate"`
			Step         string `json:"step"`
		}
		if err == nil && json.Unmarshal(pending, &m) == nil && "gen/"+strconv.FormatUint(m.Intermediate, 10) == mid && m.Step == "final" {
			break
		}
		if time.Now().After(deadline) || h.current(t) != mid {
			t.Fatalf("while current names %s, pending.json = %s (%v); want that intermediate at step final", mid, pending, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.wantRefused(t, "y while current names the intermediate", y, login, "127.0.0.4", logRevoked)
	h.wantRefused(t, "q while current names the intermediate", q, login, "127.0.0.5", logNoPrincipal)
	if h.current(t) != mid {
		t.Fatalf("current moved from the intermediate %s to %s before the wait ended", mid, h.current(t))
	}
	if code, r, stderr = run.finish(t); code != 0 || r.Intermediate == 0 || r.WaitedMS < int64(agentLoginGrace+30)*1000 || r.Reloaded || r.SelfTest != "pass" {
		t.Fatalf("mixed change: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	if got := h.current(t); got == mid || got == before {
		t.Fatalf("current names %s after the mixed apply, want the final generation", got)
	}
	h.wantAccepted(t, "q after the final swap", q, login)
	h.wantRefused(t, "y after the final swap", y, login, "127.0.0.6", logRevoked)
	if got := h.sshd.pid(t); got != pid {
		t.Fatalf("sshd PID %d, was %d: sshd was restarted", got, pid)
	}
	last := h.current(t)

	// 5. sshd stopped: a new KRL fails its self-test and the apply rolls
	// back. The KRL never rolls back (owner decision 2026-10-26, PR #67):
	// last-good stays, and current keeps last-good's CA keys and
	// principals with the new KRL.
	h.sshd.stop(t)
	revokeSerial(t, env, z.serial)
	h.refreshSpool(t)
	code, r, stderr = h.apply(t)
	if code == 0 || !r.Rollback || !strings.HasPrefix(r.SelfTest, "fail") {
		t.Fatalf("self-test failure: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	kr := filepath.Join(h.root, "etc", "ssh", "keyroster")
	if lg, err := os.Readlink(filepath.Join(kr, "last-good")); err != nil || lg != last {
		t.Fatalf("last-good names %q (%v) after the rollback, want %s", lg, err, last)
	}
	read := func(rel string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(kr, rel)) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, f := range []string{"user_ca_keys", "principals/" + login} {
		if !bytes.Equal(read(filepath.Join("current", f)), read(filepath.Join(last, f))) {
			t.Fatalf("current's %s after the rollback differs from last-good's", f)
		}
	}
	if bytes.Equal(read("current/revoked.krl"), read(filepath.Join(last, "revoked.krl"))) {
		t.Fatal("the rollback took the new KRL back")
	}
	if _, err := os.Stat(filepath.Join(h.state, "pending.json")); !os.IsNotExist(err) {
		t.Fatalf("pending.json after the rollback: %v", err)
	}
	if !regexp.MustCompile(`^gen/[0-9]+$`).MatchString(last) {
		t.Fatalf("current = %q", last)
	}
}
