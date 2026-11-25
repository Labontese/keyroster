//go:build e2e && e2erotation

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// caRotFailedLogin is the start of the sshd log line (LogLevel VERBOSE)
// for a refused publickey login of user from src, which a certificate
// signed by a CA key that TrustedUserCAKeys does not list gets (03-12b).
// sshd names that CA reason only at a debug level, so the generic line,
// from a source address of its own, is what can be matched; the 9.5p1 and
// 10.5p1 builds both print it.
func caRotFailedLogin(user, src string) string {
	return "Failed publickey for " + user + " from " + src + " port"
}

// caRotKeyLine is the trust.FormatKey line of the OpenSSH .pub file path.
func caRotKeyLine(t *testing.T, path string) string {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(readPub(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(pub)
}

// caRotUserCALines are the user CA lines of the live user_ca_keys of h, in
// file order: the file also lists the machine CA keys, which are dropped.
func caRotUserCALines(t *testing.T, h *agentHost, userCAs ...string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.root, "etc", "ssh", "keyroster", "current", "user_ca_keys")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		for _, u := range userCAs {
			if l == u {
				out = append(out, l)
			}
		}
	}
	return out
}

// caRotCeremony runs root sign --prev prevDir (its recorded SHA-256
// prevSHA) with the root in rootAgent and the CA flags ca, into out: first
// with a wrong confirmation, which signs nothing, then with the real hash
// prefix. It returns the display. Then trust verify --prev checks the
// signed successor against the pin.
func caRotCeremony(t *testing.T, rootAgent, rootFP, rootsPub, prevDir, prevSHA, out string, ca ...string) string {
	t.Helper()
	sign := append([]string{"root", "sign", "--prev", prevDir, "--prev-sha256", prevSHA, "--roots", rootsPub, "--threshold", "1",
		"--policy", filepath.Join(prevDir, "policy.json"), "--out-dir", out, "--agent-key", rootFP}, ca...)
	code, display := keyrosterWithAgent(t, rootAgent, append(sign, "--confirm", "00000000")...)
	if code != 1 || !strings.Contains(display, "nothing was signed") {
		t.Fatalf("root sign --prev %v with a wrong confirmation exited %d:\n%s", ca, code, display)
	}
	succ, err := os.ReadFile(filepath.Join(out, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	if code, msg := keyrosterWithAgent(t, rootAgent, append(sign, "--confirm", trust.SHA256Hex(succ)[:8])...); code != 0 {
		t.Fatalf("root sign --prev %v exited %d:\n%s", ca, code, msg)
	}
	code, verified := runKeyroster(t, "trust", "verify", "--prev", prevDir, "--prev-sha256", prevSHA, "--pin", rootFP, "--threshold", "1",
		"--bundle", filepath.Join(out, "bundle.json"), "--policy", filepath.Join(out, "policy.json"))
	if code != 0 || !strings.Contains(verified, "OK: successor of trust bundle") {
		t.Fatalf("trust verify --prev of %s exited %d:\n%s", out, code, verified)
	}
	return display + verified
}

// caRotInstall installs the successor in dir on env's stopped signer and
// starts serve again; it returns the new stop function.
func caRotInstall(t *testing.T, env *signerEnv, dir string, version string) func() {
	t.Helper()
	if code, out := env.signerCmd(t, "install-bundle", "--state-dir", env.StateDir,
		"--bundle", filepath.Join(dir, "bundle.json"), "--policy", filepath.Join(dir, "policy.json")); code != 0 ||
		!strings.Contains(out, "installed bundle version "+version) {
		t.Fatalf("install-bundle of %s exited %d:\n%s", dir, code, out)
	}
	return serveStoppable(t, env)
}

// TestCANextAndAbort (03-12b, D-14, KEY-08) runs ceremony 1 and its abort
// with the real binaries against an sshd that keyroster-agent drives: a
// prepared user CA key becomes next through a root ceremony, the host
// trusts it beside the active key after the widening wait, and an abort
// withdraws it at once, so a certificate it signed is refused. The
// exported log verifies across both (the e2e-rotation lane, 9.5p1 and
// 10.5p1).
func TestCANextAndAbort(t *testing.T) {
	login := currentUser(t)
	keys := t.TempDir()

	// 1. A root R in its own agent, the signer, a host, and c1.
	rAgent := startAgent(t)
	rKey := filepath.Join(keys, "r")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "r", "-f", rKey)
	sshAdd(t, rAgent, rKey)
	rFP := fingerprint(t, rKey+".pub")
	rootsPub := filepath.Join(keys, "roots.pub")
	if err := os.WriteFile(rootsPub, []byte(caRotKeyLine(t, rKey+".pub")+" custody=software\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := prepareSigner(t, bootstrapOpts{RootAgentSocket: rAgent, RootFingerprint: rFP, RootCustody: "software", PoPHosts: true})
	stop := serveStoppable(t, env)
	h := newAgentHost(t, env)
	installAgentDirectory(t, env, agentDirectory(t, env, nil, login, h.sshd.hostKey, "role:ops"))
	c1 := issueAgentCert(t, env, "c1", "role:ops")
	h.refreshSpool(t)
	if code, r, stderr := h.apply(t); code != 0 || !r.Reloaded || r.SelfTest != "pass" {
		t.Fatalf("first install: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	h.wantAccepted(t, "c1 after the first install", c1, login)
	gen1 := caRotKeyLine(t, env.UserCAPub)

	// 2. Prepare generation 2 of the user CA, with the signer stopped.
	stop()
	k2 := filepath.Join(keys, "user_g2")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user-g2", "-f", k2)
	sshAdd(t, env.RoleAgent, k2)
	fp2, line2 := fingerprint(t, k2+".pub"), caRotKeyLine(t, k2+".pub")
	prepared := filepath.Join(keys, "user-g2.json")
	if code, out := env.signerCmd(t, "ca-rotate", "prepare", "--state-dir", env.StateDir, "--role", "user", "--key", fp2, "--out", prepared); code != 0 ||
		!strings.Contains(out, "role user generation 2 "+fp2) {
		t.Fatalf("ca-rotate prepare exited %d:\n%s", code, out)
	}

	// 3. Ceremony 1. A wrong fingerprint is refused before anything is
	// written; the right one builds, signs and verifies.
	v1, err := os.ReadFile(filepath.Join(env.BundleDir, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(keys, "succ-wrong-fp")
	if code, out := keyrosterWithAgent(t, rAgent, "root", "sign", "--prev", env.BundleDir, "--prev-sha256", trust.SHA256Hex(v1),
		"--roots", rootsPub, "--threshold", "1", "--policy", filepath.Join(env.BundleDir, "policy.json"), "--out-dir", wrong,
		"--agent-key", rFP, "--ca-next", "user="+prepared, "--ca-next-fingerprint", "user="+rFP, "--confirm", "00000000"); code != 1 ||
		!strings.Contains(out, "ca_next_fingerprint_mismatch") {
		t.Fatalf("root sign with a wrong --ca-next-fingerprint exited %d:\n%s", code, out)
	}
	if _, err := os.Stat(wrong); !os.IsNotExist(err) {
		t.Fatalf("%s exists after the refused root sign (stat error %v)", wrong, err)
	}
	succ := filepath.Join(keys, "succ")
	out := caRotCeremony(t, rAgent, rFP, rootsPub, env.BundleDir, trust.SHA256Hex(v1), succ,
		"--ca-next", "user="+prepared, "--ca-next-fingerprint", "user="+fp2)
	for _, want := range []string{"CA user gen 2 " + fp2 + ": none -> next\n", "Root set: unchanged\n"} {
		if n := strings.Count(out, want); n != 2 {
			t.Fatalf("root sign and trust verify print %q %d times, want once each:\n%s", want, n, out)
		}
	}

	// 4. Install; 5. the host trusts both user CA keys after the widening
	// wait, with no reload. A CA line added alone is a pure widening: the
	// agent waits and swaps once, with no intermediate generation (that is
	// for a change that also narrows).
	stop = caRotInstall(t, env, succ, "2")
	h.refreshSpool(t)
	code, r, stderr := h.apply(t)
	if code != 0 || r.WaitedMS < int64(agentLoginGrace+30)*1000 || r.SelfTest != "pass" || r.Reloaded {
		t.Fatalf("the next CA: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	if got := caRotUserCALines(t, h, gen1, line2); len(got) != 2 || got[0] != gen1 || got[1] != line2 {
		t.Fatalf("live user CA lines %q, want generation 1 then generation 2", got)
	}
	h.wantAccepted(t, "c1 with the next CA trusted", c1, login)
	// A certificate signed directly with the next key (test-only: the
	// signer never signs with a next key).
	nk := filepath.Join(t.TempDir(), "id_next")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "next", "-f", nk)
	sshKeygen(t, "-q", "-s", k2, "-I", "e2e-next", "-n", "role:ops", "-V", "-5m:+10m", "-z", "4242", nk+".pub")
	byNext := agentCert{key: nk, cert: nk + "-cert.pub", serial: "4242"}
	h.wantAccepted(t, "a certificate by the next CA key", byNext, login)

	// 6. The abort, on the version-2 directory as --prev.
	stop()
	v2, err := os.ReadFile(filepath.Join(succ, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	abort := filepath.Join(keys, "abort")
	out = caRotCeremony(t, rAgent, rFP, rootsPub, succ, trust.SHA256Hex(v2), abort, "--ca-retire", "user:2")
	if n := strings.Count(out, "CA user gen 2 "+fp2+": next -> retired\n"); n != 2 {
		t.Fatalf("root sign and trust verify print the abort line %d times, want once each:\n%s", n, out)
	}
	_ = caRotInstall(t, env, abort, "3") // serve stops at the test's cleanup
	h.refreshSpool(t)
	code, r, stderr = h.apply(t)
	if code != 0 || r.Intermediate != 0 || r.Reloaded || r.SelfTest != "pass" || r.WaitedMS >= int64(agentLoginGrace)*1000 {
		t.Fatalf("the abort: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	if got := caRotUserCALines(t, h, gen1, line2); len(got) != 1 || got[0] != gen1 {
		t.Fatalf("live user CA lines %q after the abort, want generation 1 only", got)
	}
	h.wantAccepted(t, "c1 after the abort", c1, login)
	h.wantRefused(t, "the certificate by the aborted key", byNext, login, "127.0.0.2", caRotFailedLogin(login, "127.0.0.2"))

	// 7. The exported log verifies, and the bundle in force lists the
	// aborted entry as retired.
	if code, out := auditVerifyPins(t, env.RootFingerprints, env.exportLog(t), "--installation-id", env.InstallationID); code != 0 ||
		!strings.Contains(out, "trust bundle v3") {
		t.Fatalf("audit verify after the abort exited %d:\n%s", code, out)
	}
	st, err := signerclient.Status(context.Background(), env.Socket)
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(st.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.CAs) != 4 || b.CAs[1].Generation != 2 || b.CAs[1].State != "retired" || b.CAs[1].Key != line2 {
		t.Fatalf("the bundle in force lists %+v, want user generation 2 retired", b.CAs)
	}
}

// caRotTTL is the lifetime of every user certificate of
// TestCARotationNoFailedLogin, the genesis policy's user cap, and
// caRotAllowance its switch's --drain-allowance (03-12e2): the draining
// key is trusted until the switch's issued_at plus caRotTTL, 300 s of
// trust.DrainMargin and caRotAllowance, caRotDrain (420 s) in all.
const (
	caRotTTL       = 60 * time.Second
	caRotAllowance = 60 * time.Second
	caRotDrain     = caRotTTL + 300*time.Second + caRotAllowance
)

// loopIssue runs keyroster ca issue against sg's signer as
// signerEnv.runIssue does (the first admin key, --installation-id), for
// the public key pub with principal role:ops and --ttl 60s, writing the
// certificate to out, with a 5 s deadline. It returns the exit code, the
// output and an error, and never touches *testing.T, so the login loop's
// goroutines can call it (03-12e2).
func loopIssue(sg *signerEnv, pub, subject, out string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, keyrosterBin, "ca", "issue", "--socket", sg.Socket, "--admin-key", sg.AdminFingerprint, //nolint:gosec // G204: the binary under test
		"--installation-id", sg.InstallationID, "--pubkey", pub, "--principal", "role:ops", "--subject", subject,
		"--ttl", caRotTTL.String(), "--out", out)
	cmd.Env = append(envWithout("SSH_AUTH_SOCK"), "SSH_AUTH_SOCK="+sg.AdminAgent)
	b, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(b), nil
		}
		return -1, string(b), err
	}
	return 0, string(b), nil
}

// loopLogin logs in as user on 127.0.0.1:port from 127.0.0.1 with key and
// cert, as sshLogin does, with a 5 s deadline. Like loopIssue it returns
// the exit code, the output and an error and never touches *testing.T
// (03-12e2).
func loopLogin(sshBin string, port int, key, cert, user string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshBin, "-F", "none", "-i", key, "-o", "CertificateFile="+cert, //nolint:gosec // G204: the OpenSSH build under test
		"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=4", "-o", "BindAddress=127.0.0.1", "-p", strconv.Itoa(port), user+"@127.0.0.1", "true")
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	b, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(b), nil
		}
		return -1, string(b), err
	}
	return 0, string(b), nil
}

// caRotIssue issues a user certificate for a fresh key name through
// loopIssue, the test's one issuer, and fails the test unless it succeeds.
func caRotIssue(t *testing.T, sg *signerEnv, dir, name string) agentCert {
	t.Helper()
	key := filepath.Join(dir, "id_"+name)
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key)
	c := agentCert{key: key, cert: key + "-cert.pub"}
	if code, out, err := loopIssue(sg, key+".pub", "u:"+name, c.cert); err != nil || code != 0 {
		t.Fatalf("keyroster ca issue for %s exited %d (%v):\n%s", name, code, err, out)
	}
	c.serial = parseCertInfo(t, sshKeygen(t, "-L", "-f", c.cert)).serial
	return c
}

// caRotLoop is TestCARotationNoFailedLogin's login loop (03-12e2). One
// goroutine logs in once a second with the certificate the loop holds;
// another refreshes that certificate every 15 s, each into a new file that
// replaces the one in use under mu, so a login never reads a file being
// written. Neither touches *testing.T. signerStopped is set by the
// stopped-signer helper before each stop of the signer and cleared after
// the restart; a refresh is skipped only while it is set, and refreshMu
// keeps a refresh from straddling the change.
type caRotLoop struct {
	sg                *signerEnv
	sshBin, user, key string
	port              int
	dir               string
	logs              func() string // the agent's run log and the fetcher's log

	signerStopped atomic.Bool
	refreshMu     sync.Mutex

	mu        sync.Mutex
	cert      string
	seq       int
	start     time.Time
	attempts  int
	lastStart time.Time
	maxGap    time.Duration
	failures  []string

	quit              chan struct{}
	done, refreshDone chan struct{}
	quitOnce          sync.Once
}

// newCARotLoop issues the loop's first certificate, logs in with it once
// on the test's goroutine, and starts the loop. It stops at the test's
// cleanup.
func newCARotLoop(t *testing.T, sg *signerEnv, h *agentHost, user string, logs func() string) *caRotLoop {
	t.Helper()
	l := &caRotLoop{sg: sg, sshBin: filepath.Join(opensshPrefix(t), "bin", "ssh"), user: user, port: h.sshd.port,
		dir: t.TempDir(), logs: logs, quit: make(chan struct{}), done: make(chan struct{}), refreshDone: make(chan struct{})}
	l.key = filepath.Join(l.dir, "id_loop")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "loop", "-f", l.key)
	if err := l.refresh(); err != nil {
		t.Fatalf("the login loop's first certificate: %v", err)
	}
	if code, out, err := loopLogin(l.sshBin, l.port, l.key, l.cert, l.user); err != nil || code != 0 {
		t.Fatalf("the login loop's first login exited %d (%v):\n%s\nsshd log:\n%s", code, err, out, h.sshd.log.String())
	}
	l.start = time.Now()
	l.lastStart = l.start
	go l.loginLoop()
	go l.refreshLoop()
	t.Cleanup(l.stop)
	return l
}

// refresh issues a certificate into a new file and makes it the one in use.
func (l *caRotLoop) refresh() error {
	l.mu.Lock()
	l.seq++
	out := filepath.Join(l.dir, "id_loop-"+strconv.Itoa(l.seq)+"-cert.pub")
	l.mu.Unlock()
	code, msg, err := loopIssue(l.sg, l.key+".pub", "u:loop", out)
	if err != nil {
		return fmt.Errorf("keyroster ca issue: %w: %s", err, msg)
	}
	if code != 0 {
		return fmt.Errorf("keyroster ca issue exited %d: %s", code, msg)
	}
	l.mu.Lock()
	l.cert = out
	l.mu.Unlock()
	return nil
}

func (l *caRotLoop) fail(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures = append(l.failures, time.Now().UTC().Format(time.RFC3339)+" "+msg)
}

// loginLoop logs in at once and then on every tick of a 1 s ticker, and
// records each attempt's start, the largest gap between starts and each
// failure's output.
func (l *caRotLoop) loginLoop() {
	defer close(l.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		now := time.Now()
		l.mu.Lock()
		cert := l.cert
		l.maxGap = max(l.maxGap, now.Sub(l.lastStart))
		l.lastStart = now
		l.attempts++
		l.mu.Unlock()
		if code, out, err := loopLogin(l.sshBin, l.port, l.key, cert, l.user); err != nil || code != 0 {
			l.fail(fmt.Sprintf("login with %s exited %d (%v):\n%s", filepath.Base(cert), code, err, out))
		}
		select {
		case <-l.quit:
			return
		case <-tick.C:
		}
	}
}

// refreshLoop refreshes the certificate every 15 s unless the signer is
// stopped; a failed refresh while it serves is a login failure.
func (l *caRotLoop) refreshLoop() {
	defer close(l.refreshDone)
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-l.quit:
			return
		case <-tick.C:
		}
		l.refreshMu.Lock()
		if !l.signerStopped.Load() {
			if err := l.refresh(); err != nil {
				l.fail("refresh: " + err.Error())
			}
		}
		l.refreshMu.Unlock()
	}
}

// stop ends both goroutines and waits for them.
func (l *caRotLoop) stop() {
	l.quitOnce.Do(func() { close(l.quit) })
	<-l.done
	<-l.refreshDone
}

// counts returns the attempts, the largest gap between attempt starts
// (the time since the last start included, so a stalled attempt counts),
// the time since the loop started and the failures.
func (l *caRotLoop) counts() (int, time.Duration, time.Duration, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.attempts, max(l.maxGap, time.Since(l.lastStart)), time.Since(l.start), slices.Clone(l.failures)
}

// verify is nil while the loop runs, has no failure, has made at least the
// elapsed seconds minus 5 attempts and has no gap above 7 s.
func (l *caRotLoop) verify() error {
	select {
	case <-l.done:
		return errors.New("the login loop stopped early")
	default:
	}
	attempts, gap, elapsed, fails := l.counts()
	switch {
	case len(fails) != 0:
		return fmt.Errorf("login failures: %d after %s:\n%s", len(fails), elapsed.Round(time.Second), strings.Join(fails, "\n"))
	case float64(attempts) < elapsed.Seconds()-5:
		return fmt.Errorf("login attempts: %d in %s, want at least the elapsed seconds minus 5", attempts, elapsed.Round(time.Second))
	case gap > 7*time.Second:
		return fmt.Errorf("the largest gap between login attempts is %s, above 7 s", gap.Round(time.Millisecond))
	}
	return nil
}

// check fails the test with the loop's failures and the agent's and the
// fetcher's logs unless verify is nil, and logs the counts.
func (l *caRotLoop) check(t *testing.T, step string) {
	t.Helper()
	if err := l.verify(); err != nil {
		t.Fatalf("%s: %v\n%s", step, err, l.logs())
	}
	attempts, gap, elapsed, _ := l.counts()
	t.Logf("%s: login attempts: %d in %s, largest gap %s, login failures: 0", step, attempts, elapsed.Round(time.Second), gap.Round(time.Millisecond))
}

// stopped runs fn with the signer stopped: it issues the loop a fresh
// certificate, sets signerStopped, stops the signer (failing when that
// comes after notAfter, unless notAfter is zero), runs fn, serves again,
// clears the flag and refreshes at once. It fails when the signer was down
// longer than the 45 s that the held 60 s certificate can bridge.
func (l *caRotLoop) stopped(t *testing.T, env *serverEnv, what string, notAfter time.Time, fn func()) {
	t.Helper()
	l.refreshMu.Lock()
	err := l.refresh()
	if err == nil {
		l.signerStopped.Store(true)
	}
	l.refreshMu.Unlock()
	if err != nil {
		t.Fatalf("%s: the certificate before the stop: %v", what, err)
	}
	began := time.Now()
	if !notAfter.IsZero() && began.After(notAfter) {
		t.Fatalf("%s: the signer stops at %s, after %s", what, began.UTC().Format(trust.TimeFormat), notAfter.UTC().Format(trust.TimeFormat))
	}
	env.StopSigner()
	fn()
	env.StopSigner = serveStoppable(t, env.Signer)
	down := time.Since(began)
	l.refreshMu.Lock()
	l.signerStopped.Store(false)
	err = l.refresh()
	l.refreshMu.Unlock()
	if err != nil {
		t.Fatalf("%s: the certificate after the restart: %v", what, err)
	}
	if down > 45*time.Second {
		t.Fatalf("%s: the signer was down for %s, above the 45 s that the held 60 s certificate can bridge", what, down.Round(time.Millisecond))
	}
	t.Logf("%s: the signer was down for %s", what, down.Round(time.Millisecond))
}

// caRotDrainRE is install-bundle's drain line for the role's generation 1
// (03-12e, 03-12f2).
func caRotDrainRE(role string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^drain ` + regexp.QuoteMeta(role) + ` generation 1 until (\S+); the last certificate the log records for it is valid until (\S+)$`)
}

// caRotRevoke revokes serial through keyroster-server and waits until the
// host's heartbeat reports the KRL that carries it.
func caRotRevoke(t *testing.T, eh *enrolledHost, kr func(args ...string) string, serial string) {
	t.Helper()
	before := hostsStatusJSON(t, kr).Current.KRL
	kr("revoke", "serial", serial, "--reason", "e2e ca rotation")
	waitStatus(t, "the KRL that revokes serial "+serial, eh, kr, func(a serverclient.HostsStatusAnswer) bool {
		return a.Current.KRL > before && len(a.Hosts) == 1 && a.Hosts[0].Heartbeat != nil && a.Hosts[0].Heartbeat.Status.KRL.Version == a.Current.KRL
	})
}

// caRotRetireKey runs retire-key for the role with the signer stopped
// (03-12e, 03-12f2): it must exit 1 with retire_key_incomplete and print, for the
// generation-1 key the role agent holds, the ssh-add line with the key's
// public key line and one more pair per certificate identity of that key.
// Each printed line is written into a file of a private directory under
// its absolute path and the printed command is run on that path, in the
// printed order; any other line fails the test. Then retire-key exits 0.
// It returns the printed agent socket.
func caRotRetireKey(t *testing.T, sg *signerEnv, role, fp1 string) string {
	t.Helper()
	code, out := sg.signerCmd(t, "ca-rotate", "retire-key", "--state-dir", sg.StateDir, "--role", role)
	if code != 1 || !strings.Contains(out, "retire_key_incomplete") {
		t.Fatalf("retire-key with the key in the agent exited %d, want 1 and retire_key_incomplete:\n%s", code, out)
	}
	head := "role " + role + " generation 1 " + fp1 + ": "
	keyCmd := head + "still held by the agent; write this public key line into retire-" + role + "-g1 and run: SSH_AUTH_SOCK="
	certCmd := head + "write this certificate line into retire-" + role + "-g1-cert.pub and run: SSH_AUTH_SOCK="
	dir := t.TempDir()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	var socket string
	var keys, certs int
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		var rest, file string
		switch {
		case strings.HasPrefix(ln, keyCmd):
			rest, file = strings.TrimPrefix(ln, keyCmd), "retire-"+role+"-g1"
			keys++
		case strings.HasPrefix(ln, certCmd):
			rest, file = strings.TrimPrefix(ln, certCmd), "retire-"+role+"-g1-cert.pub"
			certs++
		case ln == "run retire-key again", strings.Contains(ln, "retire_key_incomplete"):
			continue
		default:
			t.Fatalf("retire-key printed a line the test does not know: %q\n%s", ln, out)
		}
		sock, ok := strings.CutSuffix(rest, " ssh-add -d "+file)
		if !ok || sock == "" || i+1 >= len(lines) {
			t.Fatalf("retire-key's command line %q does not end in ssh-add -d %s or has no line after it:\n%s", ln, file, out)
		}
		if socket != "" && sock != socket {
			t.Fatalf("retire-key names two agent sockets, %s and %s:\n%s", socket, sock, out)
		}
		socket = sock
		i++
		path := filepath.Join(dir, file)
		if err := os.WriteFile(path, []byte(lines[i]+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh-add"), "-d", path) //nolint:gosec // G204: the OpenSSH build under test
		cmd.Env = append(envWithout("SSH_AUTH_SOCK", "SSH_ASKPASS", "DISPLAY"), "SSH_AUTH_SOCK="+socket)
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("SSH_AUTH_SOCK=%s ssh-add -d %s: %v\n%s", socket, path, err, b)
		}
	}
	if keys != 1 || socket != sg.RoleAgent {
		t.Fatalf("retire-key printed %d key commands for the agent socket %q, want one for %s:\n%s", keys, socket, sg.RoleAgent, out)
	}
	t.Logf("retire-key printed the key line and %d certificate lines; each was removed with ssh-add -d", certs)
	if code, out := sg.signerCmd(t, "ca-rotate", "retire-key", "--state-dir", sg.StateDir, "--role", role); code != 0 ||
		!strings.Contains(out, "retire-key: no draining key of role "+role+" is held") {
		t.Fatalf("retire-key after ssh-add -d exited %d, want 0:\n%s", code, out)
	}
	return socket
}

// caRotAgentHolds fails the test when the agent at sock lists the key
// with fingerprint fp or a certificate on it.
func caRotAgentHolds(t *testing.T, sock, fp string) {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if c, ok := pub.(*ssh.Certificate); ok {
			pub = c.Key
		}
		if ssh.FingerprintSHA256(pub) == fp {
			t.Fatalf("the role agent still lists %s (%s) after retire-key exited 0", fp, k.Comment)
		}
	}
}

// TestCARotationNoFailedLogin (03-12e2, D-14, KEY-08) runs a whole user CA
// rotation with the real binaries against an sshd that keyroster-agent
// drives through keyroster-server, while a certificate login runs every
// second: prepare, ceremony 1, the install, the widening wait and the live
// count; ceremony 2 (`root sign --ca-switch user --drain-allowance 60s`)
// while the signer serves, the install with --previous, serve refusing
// draining_key_still_usable, retire-key and the restart; the old key
// trusted until its trusted_until and dropped by the host by itself no
// later than 120 s after it; and audit verify of the export. No login
// fails (the e2e-rotation lane, 9.5p1 and 10.5p1).
func TestCARotationNoFailedLogin(t *testing.T) {
	withGenesisUserMaxTTL(t, caRotTTL)
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true, StoppableSigner: true})
	sg := env.Signer
	login := currentUser(t)
	admin := adminCLI(t, env, sg.AdminFingerprint)
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
			// The admin routes share one bucket per client address that
			// refills one request a second, and a refused request spends
			// none (internal/server/ratelimit.go): a wait of N s lets a
			// command of N admin requests through at its first retry.
			// The largest command run through this helper is host approve,
			// three (GET pending hosts, GET and POST directory): 3 s.
			time.Sleep(3 * time.Second)
			code, out, errOut = env.keyroster(t, admin, "", args...)
		}
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}
	// The role's cap may not exceed the 60 s user CA cap, so the test makes
	// its own role instead of enrollApproved's 1h one.
	kr("role", "add", "ops", "--max-ttl", "1m", "--yes")
	kr("host-group", "add", "lab", "--yes")
	kr("host-group", "map", "lab", login, "ops", "--yes")
	eh := joinApproved(t, env, kr, "web1")
	// The server allows an enrolled agent 30 requests a minute (burst 64).
	// A fetcher that polls every second sends a state request and a
	// heartbeat each poll, so within a minute or two its heartbeats starve;
	// this test runs for about ten minutes, so its fetcher polls every 5 s,
	// as the host-certificate tests' do (03-09).
	eh.stopFetch(t)
	eh.startFetch(t, 5*time.Second)
	h := eh.agentHost
	keys := t.TempDir()
	rootFP, rootsPub := sg.RootFingerprints[0], filepath.Join(filepath.Dir(sg.BundleDir), "roots.pub")
	gen1, fp1 := caRotKeyLine(t, sg.UserCAPub), fingerprint(t, sg.UserCAPub)
	l := newCARotLoop(t, sg, h, login, func() string {
		return "agent run log:\n" + eh.run.String() + "\nfetch log:\n" + eh.fetch.String()
	})
	l.check(t, "the loop started")

	// 1. Prepare generation 2 with the signer stopped (the state lock);
	// ceremony 1 while it serves; the install with the signer stopped.
	k2 := filepath.Join(keys, "user_g2")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user-g2", "-f", k2)
	sshAdd(t, sg.RoleAgent, k2)
	fp2, line2 := fingerprint(t, k2+".pub"), caRotKeyLine(t, k2+".pub")
	prepared := filepath.Join(keys, "user-g2.json")
	l.stopped(t, env, "prepare", time.Time{}, func() {
		if code, out := sg.signerCmd(t, "ca-rotate", "prepare", "--state-dir", sg.StateDir, "--role", "user", "--key", fp2, "--out", prepared); code != 0 ||
			!strings.Contains(out, "role user generation 2 "+fp2) {
			t.Fatalf("ca-rotate prepare exited %d:\n%s", code, out)
		}
	})
	l.check(t, "prepare")
	v1, err := os.ReadFile(filepath.Join(sg.BundleDir, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	succ := filepath.Join(keys, "succ")
	out := caRotCeremony(t, sg.RootAgent, rootFP, rootsPub, sg.BundleDir, trust.SHA256Hex(v1), succ,
		"--ca-next", "user="+prepared, "--ca-next-fingerprint", "user="+fp2)
	if n := strings.Count(out, "CA user gen 2 "+fp2+": none -> next\n"); n != 2 {
		t.Fatalf("root sign and trust verify print the next line %d times, want once each:\n%s", n, out)
	}
	l.check(t, "ceremony 1")
	l.stopped(t, env, "the install of ceremony 1", time.Time{}, func() {
		if code, out := sg.signerCmd(t, "install-bundle", "--state-dir", sg.StateDir,
			"--bundle", filepath.Join(succ, "bundle.json"), "--policy", filepath.Join(succ, "policy.json")); code != 0 ||
			!strings.Contains(out, "installed bundle version 2") {
			t.Fatalf("install-bundle of ceremony 1 exited %d:\n%s", code, out)
		}
	})
	l.check(t, "the install of ceremony 1")

	// 2. Convergence: the live count, computed by the CLI from the hash the
	// host reports through the fetcher, and the live file itself.
	var status string
	for deadline := time.Now().Add(150 * time.Second); ; time.Sleep(2 * time.Second) {
		status = kr("host", "status")
		if strings.Contains(status, "user CA keys of bundle v2 live on 1/1 hosts\n") {
			break
		}
		if err := l.verify(); err != nil {
			t.Fatalf("waiting for the live count: %v\n%s", err, l.logs())
		}
		if time.Now().After(deadline) {
			t.Fatalf("host status never counted bundle v2 live on 1/1 hosts within 150 s:\n%s\n%s", status, l.logs())
		}
	}
	t.Logf("keyroster host status after ceremony 1:\n%s", status)
	if got := caRotUserCALines(t, h, gen1, line2); len(got) != 2 || got[0] != gen1 || got[1] != line2 {
		t.Fatalf("live user CA lines %q, want generation 1 then generation 2", got)
	}
	// The export taken after the last install: the switch's --previous.
	previous := sg.exportLog(t)
	revoked1 := caRotIssue(t, sg, keys, "revoked-g1")
	caRotRevoke(t, eh, kr, revoked1.serial)
	h.wantRefused(t, "the revoked generation-1 serial", revoked1, login, "127.0.0.2", logRevoked)
	l.check(t, "convergence")

	// 3. Ceremony 2 while the signer serves, then, within the allowance,
	// the install with --previous, serve's refusal, retire-key, the role
	// agent's listing and doctor, with the signer stopped.
	v2, err := os.ReadFile(filepath.Join(succ, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	sw := filepath.Join(keys, "switch")
	out = caRotCeremony(t, sg.RootAgent, rootFP, rootsPub, succ, trust.SHA256Hex(v2), sw, "--ca-switch", "user", "--drain-allowance", caRotAllowance.String())
	v3, err := os.ReadFile(filepath.Join(sw, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	b3, err := trust.ParseBundle(v3)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(trust.TimeFormat, b3.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	var trustedUntil string
	for _, e := range b3.CAs {
		if e.Role == "user" && e.Generation == 1 && e.State == "draining" {
			trustedUntil = e.TrustedUntil
		}
	}
	until, err := time.Parse(trust.TimeFormat, trustedUntil)
	if err != nil || !until.Equal(issuedAt.Add(caRotDrain)) {
		t.Fatalf("the switch bundle's draining entry is trusted until %q (%v), want issued_at %s plus %s:\n%s", trustedUntil, err, b3.IssuedAt, caRotDrain, v3)
	}
	for _, want := range []string{
		"CA user gen 1 " + fp1 + ": active -> draining, trusted until " + trustedUntil + "; install by " + issuedAt.Add(caRotAllowance).Format(trust.TimeFormat) + " (advice)\n",
		"CA user gen 2 " + fp2 + ": next -> active\n",
	} {
		if n := strings.Count(out, want); n != 2 {
			t.Fatalf("root sign and trust verify print %q %d times, want once each:\n%s", want, n, out)
		}
	}
	l.check(t, "ceremony 2")
	held := caRotIssue(t, sg, keys, "held-g1")
	l.stopped(t, env, "the switch", issuedAt.Add(50*time.Second), func() {
		code, out := sg.signerCmd(t, "install-bundle", "--state-dir", sg.StateDir,
			"--bundle", filepath.Join(sw, "bundle.json"), "--policy", filepath.Join(sw, "policy.json"), "--previous", previous)
		m := caRotDrainRE("user").FindStringSubmatch(out)
		if code != 0 || !strings.Contains(out, "installed bundle version 3") || m == nil || m[1] != trustedUntil {
			t.Fatalf("install-bundle --previous of the switch exited %d, want version 3 and the drain line until %s:\n%s", code, trustedUntil, out)
		}
		valid, err := time.Parse(trust.TimeFormat, m[2])
		if err != nil || valid.Add(300*time.Second).After(until) {
			t.Fatalf("the drain line's last certificate is valid until %q (%v); want it plus 300 s at or below %s", m[2], err, trustedUntil)
		}
		t.Logf("install-bundle: %s", m[0])
		// serve refuses while the backend holds the draining key.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, signerBin, "serve", "--state-dir", sg.StateDir, "--socket", sg.Socket, //nolint:gosec // G204: the binary under test
			"--allow-uid", strconv.Itoa(os.Getuid()))
		cmd.Env = envWithout("SSH_AUTH_SOCK")
		b, err := cmd.CombinedOutput()
		if err == nil || ctx.Err() != nil || !strings.Contains(string(b), "draining_key_still_usable") {
			t.Fatalf("serve with the old key in the agent: %v (deadline %v), want a refusal naming draining_key_still_usable:\n%s", err, ctx.Err(), b)
		}
		sock := caRotRetireKey(t, sg, "user", fp1)
		caRotAgentHolds(t, sock, fp1)
		code, out = sg.signerCmd(t, "doctor", "--state-dir", sg.StateDir)
		if strings.Contains(out, "draining_key_still_usable") {
			t.Fatalf("doctor after retire-key reports draining_key_still_usable:\n%s", out)
		}
		t.Logf("doctor after retire-key exited %d:\n%s", code, out)
	})
	l.check(t, "the switch")

	// 4. The draining key is trusted: the generation-1 certificate issued
	// before the stop logs in; new certificates are signed by generation 2;
	// both KRL sections refuse.
	h.wantAccepted(t, "the generation-1 certificate after the switch", held, login)
	g2 := caRotIssue(t, sg, keys, "g2")
	if fp := parseCertInfo(t, sshKeygen(t, "-L", "-f", g2.cert)).signingCAFP; fp != fp2 {
		t.Fatalf("a certificate issued after the switch is signed by %s, want generation 2 %s", fp, fp2)
	}
	h.wantAccepted(t, "a generation-2 certificate", g2, login)
	h.wantRefused(t, "the generation-1 serial revoked before the switch", revoked1, login, "127.0.0.3", logRevoked)
	revoked2 := caRotIssue(t, sg, keys, "revoked-g2")
	caRotRevoke(t, eh, kr, revoked2.serial)
	h.wantRefused(t, "the generation-2 serial revoked after the switch", revoked2, login, "127.0.0.4", logRevoked)
	waitStatus(t, "the switch bundle applied", eh, kr, func(a serverclient.HostsStatusAnswer) bool {
		return a.Current.Bundle == 3 && len(a.Hosts) == 1 && a.Hosts[0].Heartbeat != nil && a.Hosts[0].Heartbeat.Status.Committed(a.Current.Docs())
	})
	l.check(t, "after the switch")

	// 5. The drain: both user CA lines until trusted_until, and the host
	// drops the old one by itself no later than 120 s after it.
	t.Logf("draining generation 1 until %s (%s from now)", trustedUntil, time.Until(until).Round(time.Second))
	for {
		got := caRotUserCALines(t, h, gen1, line2)
		now := time.Now()
		if now.Before(until.Add(-2 * time.Second)) {
			if len(got) != 2 {
				t.Fatalf("the host dropped a user CA line at %s, before trusted_until %s: %q\n%s", now.UTC().Format(trust.TimeFormat), trustedUntil, got, l.logs())
			}
		} else if len(got) == 1 && got[0] == line2 {
			t.Logf("the host dropped generation 1 %s after trusted_until", now.Sub(until).Round(time.Second))
			break
		}
		if now.After(until.Add(120 * time.Second)) {
			attempts, _, elapsed, fails := l.counts()
			t.Fatalf("the host still lists %q at %s, more than 120 s after trusted_until %s (elapsed %s, login attempts %d, failures %d:\n%s)\n%s",
				got, now.UTC().Format(trust.TimeFormat), trustedUntil, elapsed.Round(time.Second), attempts, len(fails), strings.Join(fails, "\n"), l.logs())
		}
		if err := l.verify(); err != nil {
			t.Fatalf("during the drain: %v\n%s", err, l.logs())
		}
		time.Sleep(2 * time.Second)
	}
	code, report := runBin(t, agentBin(t), "", "check", "--state-dir", h.state, "--root", h.root,
		"--sshd", filepath.Join(opensshPrefix(t), "sbin", "sshd"), "--sshd-config", h.sshd.cfg)
	if code != 0 || strings.Contains(report, "trust_expired") || strings.Contains(report, "bundle_behind") {
		t.Fatalf("keyroster-agent check after the drop exited %d, want 0 with no trust_expired and no bundle_behind:\n%s", code, report)
	}
	if got := caRotUserCALines(t, h, gen1, line2); len(got) != 1 || got[0] != line2 {
		t.Fatalf("live user CA lines %q after the drop, want generation 2 only", got)
	}
	l.check(t, "the drain")

	// 6. The loop stops; the export verifies and names bundle v3.
	l.stop()
	attempts, gap, elapsed, fails := l.counts()
	if code, out := auditVerify(t, sg, sg.exportLog(t)); code != 0 || !strings.Contains(out, "trust bundle v3") {
		t.Fatalf("audit verify after the rotation exited %d:\n%s", code, out)
	}
	if len(fails) != 0 {
		t.Fatalf("login failures: %d\n%s\n%s", len(fails), strings.Join(fails, "\n"), l.logs())
	}
	t.Logf("login attempts: %d in %s", attempts, elapsed.Round(time.Second))
	t.Logf("largest gap between login attempts: %s", gap.Round(time.Millisecond))
	t.Logf("login failures: 0")
}
