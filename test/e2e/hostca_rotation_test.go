//go:build e2e && e2erotation

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/trust"
)

// The bounds of TestHostCARotation (03-12f2), each from the previous
// issuance and each with its anchor.
const (
	// hcrCap is the host certificate cap of the genesis policy: the signer
	// issues every host certificate for the smaller of 30 days and the cap
	// (internal/signer/hostissue.go:29, :146).
	hcrCap = 90 * time.Second
	// hcrRenewMin and hcrRenewMax bound a renewal's issuance after the
	// previous issuance: RenewAt is at least the previous issuance plus
	// 52 s (internal/agent/hostcert/hostcert.go:556, :549, :564-568), and
	// the house bound keeps a second of slack (hostcert_test.go:408); the
	// agent counts a certificate missing 15 s before its ValidBefore
	// (hostcert.go:546).
	hcrRenewMin = 51 * time.Second //nolint:revive // time-naming: Min is the minimum, not minutes
	hcrRenewMax = 75 * time.Second
	// hcrC1StopBy and hcrC1UpBy are c1's stopped windows: each starts by
	// c1's issuance plus 40 s and the signer serves again by plus 50 s,
	// before the earliest renewal request at plus 52 s. A request that
	// meets a stopped signer costs a 60 s back-off (hostcert.go:64, :593),
	// longer than what is left of a 90 s certificate.
	hcrC1StopBy = 40 * time.Second
	hcrC1UpBy   = 50 * time.Second
	// r1's window, every bound before plus 52 s. hcrSwitchStart: the switch
	// starts by then, 4 s after the latest fresh observation of r1, for
	// ceremony 2 (about 23 ms in the user rotation test's runs).
	hcrSwitchStart = 19 * time.Second
	// hcrSwitchUp: the signer serves again, 8 s after the latest fresh
	// observation, 4 s for a stopped window that took under 0.1 s in the
	// user rotation test's runs.
	hcrSwitchUp = 23 * time.Second
	// hcrStep6: step 6 is done.
	hcrStep6 = 28 * time.Second
	// hcrCommit3: the bundle-3 commit is seen, 21 s after the latest serve,
	// for a path of about 20 s: the server's 5 s status cache
	// (internal/server/signer.go:372), a fetch poll of at most 5.83 s
	// (internal/agent/fetch/fetch.go:259-272), the 1 s applier round, the
	// next poll's heartbeat within 5.83 s and the test's 2 s poll.
	hcrCommit3 = 44 * time.Second
	// hcrQuiet: the quiet check starts, at least 1 s after the commit bound;
	// hcrQuietEnd: its keyscan ends by then, each try's context bounded by
	// the time left.
	hcrQuiet    = 45 * time.Second
	hcrQuietEnd = 50 * time.Second
	// hcrFresh: an anchor certificate observed later than this after its
	// issuance is replaced by its renewal, once per test.
	hcrFresh = 15 * time.Second
	// hcrCommit: the bundle-2 commit after its install; the fetcher sends a
	// heartbeat each 5 s poll (hostCertPoll).
	hcrCommit = 45 * time.Second
	// hcrFirst: the first certificate after joinHostCert returns.
	hcrFirst = 60 * time.Second
	// hcrServe: sshd serving an installed certificate.
	hcrServe = 15 * time.Second
	// hcrAllowance is the switch's --drain-allowance, never 0: the agent
	// asks for certificates by itself, so it may renew between the
	// switch's issued_at and its install.
	hcrAllowance = 60 * time.Second
	// hcrDrain is bundle 3's trusted_until after its issued_at: the cap,
	// trust.DrainMargin (300 s) and the allowance (internal/trust/castate.go:122,
	// :134-150).
	hcrDrain = hcrCap + 300*time.Second + hcrAllowance
	// hcrLine is the line the test logs at its end, which the lane gate
	// counts.
	hcrLine = "host CA rotation: the refreshed client accepted generation 1 and generation 2, the client that did not refresh was refused"
	// hcrMachineLine is the line the test logs for client C, which the lane gate counts (03-12g).
	hcrMachineLine = "host CA rotation: machine renew added the generation 2 line to the third client, which accepted generation 1 and generation 2"
	// hcrSetupPayback is the wait after client C's setup (03-12g). The role
	// and the machine each spend two requests of the admin routes'
	// per-client bucket (a GET and a POST of the directory), which holds 20
	// requests and gains one a second (internal/server/ratelimit.go);
	// joinHostCert's poll of host pending and its approval draw on the same
	// bucket. Four seconds pay the four requests back, so the host joins
	// with the bucket it has without client C. The wait is outside every
	// window.
	hcrSetupPayback = 4 * time.Second
	// hcrClock is the layout of the times the test logs.
	hcrClock = "15:04:05.000"
)

// hcrIssued is a certificate's issuance second, ValidAfter plus the 300 s
// backdate (hostcert.IssuedAt, hostcert.go:542; Backdate, :55).
func hcrIssued(c *ssh.Certificate) time.Time {
	return time.Unix(int64(c.ValidAfter)+300, 0) //nolint:gosec // G115: Unix times
}

// hcrServes runs ssh-keyscan -c -t ed25519 against h's sshd every 500 ms,
// each try with a context of the smaller of 5 s and the time left, and no
// try after within has ended, until it exits 0 and prints a certificate
// equal to want. It fails with what it saw when within passes.
func hcrServes(t *testing.T, h *agentHost, want *ssh.Certificate, within time.Duration) {
	t.Helper()
	end := time.Now().Add(within)
	var seen []string
	for {
		left := time.Until(end)
		if left <= 0 {
			break
		}
		ctx, cancel := context.WithTimeout(context.Background(), min(5*time.Second, left))
		out, err := exec.CommandContext(ctx, filepath.Join(opensshPrefix(t), "bin", "ssh-keyscan"), "-c", "-t", "ed25519", //nolint:gosec // G204: the OpenSSH build under test
			"-p", strconv.Itoa(h.sshd.port), "127.0.0.1").Output()
		cancel()
		var got *ssh.Certificate
		if err == nil {
			// ssh-keyscan prints a certificate without the host field the
			// plain keys carry, so a line is read with and without its first
			// field (hostcert_test.go:160-171).
			for _, l := range strings.Split(string(out), "\n") {
				f := strings.Fields(l)
				if len(f) < 2 || strings.HasPrefix(l, "#") {
					continue
				}
				for _, cand := range []string{l, strings.Join(f[1:], " ")} {
					pub, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(cand))
					if c, ok := pub.(*ssh.Certificate); perr == nil && ok && got == nil {
						got = c
					}
				}
			}
		}
		switch {
		case err != nil:
			seen = append(seen, fmt.Sprintf("exit %v", err))
		case got == nil:
			seen = append(seen, "no certificate")
		case bytes.Equal(got.Marshal(), want.Marshal()):
			return
		default:
			seen = append(seen, "serial "+strconv.FormatUint(got.Serial, 10))
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("sshd did not serve serial %d within %s; ssh-keyscan saw: %s", want.Serial, within.Round(time.Millisecond), strings.Join(seen, ", "))
}

// hcrCert requires c to be signed by ca, to live 90 s and to be what sshd
// serves.
func hcrCert(t *testing.T, eh *enrolledHost, c *ssh.Certificate, ca ssh.PublicKey, what string) {
	t.Helper()
	if !bytes.Equal(c.SignatureKey.Marshal(), ca.Marshal()) {
		t.Fatalf("%s: serial %d is signed by %s, want %s", what, c.Serial, ssh.FingerprintSHA256(c.SignatureKey), ssh.FingerprintSHA256(ca))
	}
	if v := hostCertLifetime(c); v != int64(hcrCap/time.Second) {
		t.Fatalf("%s: serial %d lives %d s, want the 90 s cap", what, c.Serial, v)
	}
	hcrServes(t, eh.agentHost, c, hcrServe)
}

// hcrNext waits for the renewal of prev, a certificate with a larger serial,
// by prev's issuance plus 75 s (a call that starts later still looks once,
// hostcert_test.go:129-136), and requires its issuance 51 s to 75 s after
// prev's, its signature by ca, its 90 s and that sshd serves it.
func hcrNext(t *testing.T, eh *enrolledHost, prev *ssh.Certificate, ca ssh.PublicKey, what string) *ssh.Certificate {
	t.Helper()
	start := time.Now()
	deadline := hcrIssued(prev).Add(hcrRenewMax)
	next := waitHostCerts(t, eh, 1, max(time.Until(deadline), 0),
		fmt.Sprintf("%s: no renewal installed by serial %d's issuance plus 75 s", what, prev.Serial),
		func(cs []*ssh.Certificate) bool { return cs[0].Serial > prev.Serial })[0]
	d := hcrIssued(next).Sub(hcrIssued(prev))
	if d < hcrRenewMin || d >= hcrRenewMax {
		if d >= hcrRenewMax && start.After(deadline) {
			t.Fatalf("%s: looked at %s, after serial %d's issuance plus 75 s, and found a renewal issued %d s after it: the step before this call ran long",
				what, start.UTC().Format(hcrClock), prev.Serial, int64(d/time.Second))
		}
		t.Fatalf("%s: the renewal was issued %d s after the previous issuance, want in [51, 75): renew at issued + 60 - j, j < 9", what, int64(d/time.Second))
	}
	hcrCert(t, eh, next, ca, what)
	t.Logf("%s: serial %d -> %d, issued %d s after the previous issuance, at %s, observed %s after its issuance",
		what, prev.Serial, next.Serial, int64(d/time.Second), hcrIssued(next).UTC().Format(hcrClock), time.Since(hcrIssued(next)).Round(time.Millisecond))
	return next
}

// hcrAnchor keeps c as the anchor when it was observed no later than 15 s
// after its issuance and returns it with prev, the certificate c renewed.
// Otherwise it spends the test's one re-anchor: it waits for c's renewal,
// which must be fresh itself, and returns it with c. A second late anchor,
// of either certificate, fails the test.
func hcrAnchor(t *testing.T, eh *enrolledHost, c, prev *ssh.Certificate, ca ssh.PublicKey, what string, reanchored *bool) (anchor, renewed *ssh.Certificate) {
	t.Helper()
	late := time.Since(hcrIssued(c))
	if late <= hcrFresh {
		t.Logf("%s: anchored on serial %d, observed %s after its issuance", what, c.Serial, late.Round(time.Millisecond))
		return c, prev
	}
	if *reanchored {
		t.Fatalf("%s: observed %s after its issuance, and the test's one re-anchor is spent", what, late.Round(time.Millisecond))
	}
	*reanchored = true
	t.Logf("%s: serial %d observed %s after its issuance, later than %s: the test re-anchors on its renewal", what, c.Serial, late.Round(time.Millisecond), hcrFresh)
	return hcrAnchor(t, eh, hcrNext(t, eh, c, ca, what+" (re-anchored)"), c, ca, what+" (re-anchored)", reanchored)
}

// hcrAttempts is step 6a's first check: the host's attempts file holds no
// request created after r1's issuance second, every key has no failure and
// no last code, and, as its positive control, a key holds r1's own
// request, created after the issuance of prev (the certificate r1 renewed)
// and no later than r1's. The agent saves a request there before it sends
// it (internal/agent/apply/hostcert.go:925-926), so the check holds
// whatever the signer answered.
func hcrAttempts(t *testing.T, eh *enrolledHost, prev, r1 *ssh.Certificate) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(eh.state, hostcert.AttemptsFile)) //nolint:gosec // the test host's state
	if err != nil {
		t.Fatalf("step 6a: %v", err)
	}
	a, err := hostcert.ParseAttempts(data)
	if err != nil {
		t.Fatalf("step 6a: the attempts file does not parse: %v\n%s", err, data)
	}
	r := uint64(hcrIssued(r1).Unix())   //nolint:gosec // G115: Unix times
	p := uint64(hcrIssued(prev).Unix()) //nolint:gosec // G115: Unix times
	for _, k := range a.Keys {
		for _, q := range k.Requests {
			if q.CreatedAt > r {
				t.Fatalf("step 6a: the host asked for a certificate at %s, after r1's issuance %d: %s",
					time.Unix(int64(q.CreatedAt), 0).UTC().Format(trust.TimeFormat), r, data) //nolint:gosec // G115: Unix times
			}
		}
	}
	for _, k := range a.Keys {
		if k.Failures != 0 || k.LastCode != "" {
			t.Fatalf("step 6a: key %s has %d failures and last code %q, want 0 and none: %s", k.KeySHA256, k.Failures, k.LastCode, data)
		}
	}
	own := false
	for _, k := range a.Keys {
		for _, q := range k.Requests {
			if p < q.CreatedAt && q.CreatedAt <= r {
				own = true
			}
		}
	}
	if !own {
		t.Fatalf("step 6a: the attempts file holds no request for r1 (created after %d, by %d): %s", p, r, data)
	}
	t.Logf("step 6a: the attempts file holds r1's request and none after r1's issuance %d: %s", r, data)
}

// hcrNoRefusal requires that the agent's run log holds no refused host
// certificate answer (internal/agent/apply/hostcert.go:603).
func hcrNoRefusal(t *testing.T, eh *enrolledHost) {
	t.Helper()
	var found []string
	for _, l := range strings.Split(eh.run.String(), "\n") {
		if strings.Contains(l, "WARNING host certificate answer for") {
			found = append(found, l)
		}
	}
	if len(found) != 0 {
		t.Fatalf("the agent refused a host certificate answer:\n%s", strings.Join(found, "\n"))
	}
}

// hcrQuietCheck is step 6a: at r1's issuance plus 45 s, after the bundle-3
// commit and before the earliest renewal request at plus 52 s, the host has
// asked for nothing since it applied the switch (hcrAttempts), its drop-in
// names r1 alone, the refreshed client still reaches the host by a
// certificate of generation 1 (loginA, after the commit wait's host status
// polls have narrowed its live file, 03-12f2) and returns before plus 50 s,
// sshd serves r1 (by plus 50 s), and the agent has refused no answer.
func hcrQuietCheck(t *testing.T, eh *enrolledHost, prev, r1 *ssh.Certificate, loginA func()) {
	t.Helper()
	at := hcrIssued(r1).Add(hcrQuiet)
	wait := time.Until(at)
	if wait < 0 {
		t.Fatalf("step 6a: the quiet check starts after r1 + 45 s (%s)", at.UTC().Format(hcrClock))
	}
	time.Sleep(wait)
	hcrAttempts(t, eh, prev, r1)
	cs := installedHostCerts(t, eh.agentHost)
	if len(cs) != 1 || cs[0].Serial != r1.Serial {
		var serials []string
		for _, c := range cs {
			serials = append(serials, strconv.FormatUint(c.Serial, 10))
		}
		t.Fatalf("step 6a: the drop-in names serials [%s], want r1's %d alone", strings.Join(serials, " "), r1.Serial)
	}
	loginA()
	if now := time.Now(); !now.Before(hcrIssued(r1).Add(hcrQuietEnd)) {
		t.Fatalf("step 6a: client A's login returned at %s, after r1 + 50 s (%s)", now.UTC().Format(hcrClock), hcrIssued(r1).Add(hcrQuietEnd).UTC().Format(hcrClock))
	}
	hcrServes(t, eh.agentHost, r1, time.Until(hcrIssued(r1).Add(hcrQuietEnd)))
	hcrNoRefusal(t, eh)
	t.Logf("step 6a: the host stayed quiet; the check ended at r1 + %s", time.Since(hcrIssued(r1)).Round(time.Millisecond))
}

// hcrStopped runs fn with the signer stopped: it fails when it would stop
// the signer after startBy, stops it, runs fn, serves again and fails when
// the signer served again after upBy, so a renewal request may have met a
// stopped signer. It returns the time fn hands back (the end of its
// install-bundle call) and the moment the signer served again.
func hcrStopped(t *testing.T, env *serverEnv, what string, startBy, upBy time.Time, fn func() time.Time) (installed, servedAgain time.Time) {
	t.Helper()
	began := time.Now()
	if began.After(startBy) {
		t.Fatalf("%s: the signer stops at %s, after %s", what, began.UTC().Format(hcrClock), startBy.UTC().Format(hcrClock))
	}
	env.StopSigner()
	installed = fn()
	env.StopSigner = serveStoppable(t, env.Signer)
	servedAgain = time.Now()
	if servedAgain.After(upBy) {
		t.Fatalf("%s: the signer served again at %s, after %s, so a renewal request may have met a stopped signer",
			what, servedAgain.UTC().Format(hcrClock), upBy.UTC().Format(hcrClock))
	}
	t.Logf("%s: the signer was down for %s (stopped at %s, start bound %s; served again at %s, bound %s)", what,
		servedAgain.Sub(began).Round(time.Millisecond), began.UTC().Format(hcrClock), startBy.UTC().Format(hcrClock),
		servedAgain.UTC().Format(hcrClock), upBy.UTC().Format(hcrClock))
	return installed, servedAgain
}

// hcrSync runs keyroster known-hosts sync, which must print its outcome
// line, and requires the managed known_hosts file at khPath to hold
// exactly one @cert-authority line per key of want, each for web1 alone.
func hcrSync(t *testing.T, kr func(args ...string) string, khPath string, want ...ssh.PublicKey) {
	t.Helper()
	out := kr("known-hosts", "sync")
	if !strings.Contains(out, "Host trust refreshed (directory v") {
		t.Fatalf("known-hosts sync printed no refresh line:\n%s", out)
	}
	t.Logf("known-hosts sync:\n%s", out)
	hosts, keys := caLines(t, khPath)
	var got, exp []string
	for i := range hosts {
		if strings.Join(hosts[i], ",") != "web1" {
			t.Fatalf("%s holds a CA line for %v, want web1 alone:\n%s", khPath, hosts[i], readFile(t, khPath))
		}
		got = append(got, string(keys[i].Marshal()))
	}
	for _, k := range want {
		exp = append(exp, string(k.Marshal()))
	}
	slices.Sort(got)
	slices.Sort(exp)
	if !slices.Equal(got, exp) {
		t.Fatalf("%s holds %d CA lines, want exactly %d, one per expected host CA key:\n%s", khPath, len(got), len(exp), readFile(t, khPath))
	}
}

// hcrNamesCA reports whether out has a Server host certificate line and
// every such line names ca's fingerprint.
func hcrNamesCA(out string, ca ssh.PublicKey) bool {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Server host certificate") {
			if !strings.Contains(l, ssh.FingerprintSHA256(ca)) {
				return false
			}
			n++
		}
	}
	return n > 0
}

// hcrLogin logs in to web1 through cfg from src with c, offering
// trustCertAlgs (the certificate first, then the plain key), and logs the
// Server host certificate line beside the CA the caller expects.
func hcrLogin(t *testing.T, cfg, login, src string, c agentCert, ca ssh.PublicKey, what string) (int, string) {
	t.Helper()
	code, out := trustedHostLogin(t, cfg, login, "web1", src, keyAuth(c), "-o", "HostKeyAlgorithms="+trustCertAlgs)
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "Server host certificate") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	t.Logf("%s: ssh exited %d; expected CA %s; %s", what, code, ssh.FingerprintSHA256(ca), strings.Join(lines, " | "))
	return code, out
}

// hcrAccepted requires a login with exit 0, a Server host certificate line
// that names ca and no TOFU text.
func hcrAccepted(t *testing.T, cfg, login, src string, c agentCert, ca ssh.PublicKey, what string) {
	t.Helper()
	code, out := hcrLogin(t, cfg, login, src, c, ca, what)
	if code != 0 || !hcrNamesCA(out, ca) {
		t.Fatalf("%s: ssh to web1 exited %d, want 0 with Server host certificate by %s:\n%s", what, code, ssh.FingerprintSHA256(ca), out)
	}
	wantNoPrompt(t, what, out)
}

// hcrRefused requires a login that exits non-zero with Host key
// verification failed, a Server host certificate line that names ca, and no
// TOFU text.
func hcrRefused(t *testing.T, cfg, login, src string, c agentCert, ca ssh.PublicKey, what string) {
	t.Helper()
	code, out := hcrLogin(t, cfg, login, src, c, ca, what)
	if code == 0 || !strings.Contains(out, "Host key verification failed") || !hcrNamesCA(out, ca) {
		t.Fatalf("%s: ssh to web1 exited %d, want a refusal with Host key verification failed:\n%s", what, code, out)
	}
	wantNoPrompt(t, what, out)
}

// hcrCommitted polls host status --json every 2 s until the server's
// current bundle is version and the one host's heartbeat reports it
// committed (as ca_rotation_test.go:829-831 does). It fails at by, and an
// observation returned after by fails too, so the commit counts only when
// it was seen by its bound. It logs the lags from installed (the end of the
// install-bundle call) and from servedAgain (the signer serving again).
func hcrCommitted(t *testing.T, eh *enrolledHost, kr func(args ...string) string, version uint64, installed, servedAgain, by time.Time, what string) {
	t.Helper()
	for {
		a := hostsStatusJSON(t, kr)
		seen := time.Now()
		if a.Current.Bundle == version && len(a.Hosts) == 1 && a.Hosts[0].Heartbeat != nil && a.Hosts[0].Heartbeat.Status.Committed(a.Current.Docs()) {
			if seen.After(by) {
				t.Fatalf("%s: committed only at %s, after %s", what, seen.UTC().Format(hcrClock), by.UTC().Format(hcrClock))
			}
			t.Logf("bundle %d committed %.3f s after the install and %.3f s after the signer served again", version,
				seen.Sub(installed).Seconds(), seen.Sub(servedAgain).Seconds())
			return
		}
		if seen.After(by) {
			b, _ := json.MarshalIndent(a, "", "  ")
			t.Fatalf("%s: host status at %s:\n%s\nrun log:\n%s\nfetch log:\n%s", what, seen.UTC().Format(hcrClock), b, eh.run.String(), eh.fetch.String())
		}
		time.Sleep(2 * time.Second)
	}
}

// TestHostCARotation (03-12f2, D-14, KEY-08) rotates the host CA with the
// real binaries: one host at a 90 s host cap behind keyroster-server, a
// real keyroster-agent that renews its host certificate by itself, and a
// real keyroster known-hosts sync. Client A refreshed after ceremony 1;
// client B did not. Both reach the host right after the switch, and the
// host asks for nothing until its own renewal. After that renewal, under
// the new host CA key, A reaches the host and B is refused with Host key
// verification failed; B's remedy is a refreshed file. A third client's
// file, a copy of B's, gains generation 2's line from a not-due keyroster
// machine renew after ceremony 1's install (03-12g); it reaches the host
// before and after the renewal. Every refusal has a positive control (the
// e2e-rotation lane, 9.5p1 and 10.5p1).
func TestHostCARotation(t *testing.T) {
	// The real home first: known-hosts sync refuses a $HOME that is not the
	// account's home (cmd/keyroster/knownhosts.go:139).
	home := requireRealHome(t)
	sshDir := filepath.Join(home, ".ssh")
	withGenesisHostMaxTTL(t, hcrCap)
	env := startServerEnv(t, serverOpts{PoPHosts: true, PoPMachines: true, AgentListen: true, StoppableSigner: true})
	sg := env.Signer
	admin := adminCLI(t, env, sg.AdminFingerprint)
	admin.home = home
	kr := hostTrustKR(t, env, admin)
	// Client C's machine identity (03-12g): the machine ci and its key, as
	// TestMachineIdentityEndToEnd adds them, and keyroster machine renew in
	// the admin's configuration, whose home is the real home. The first
	// renewal, before any sync, finds no managed file and adds nothing.
	setupAt := time.Now()
	mKey := newUserKey(t, "id_ci")
	kr("role", "add", "deploy", "--max-ttl", "12h", "--yes")
	kr("machine", "add", "ci", "--key", mKey+".pub", "--role", "deploy", "--max-ttl", "24h", "--yes")
	mCert := filepath.Join(t.TempDir(), "ci-cert.pub")
	renew := func(args ...string) (string, string) {
		t.Helper()
		code, stdout, stderr := runCLIIn(t, admin, "", "", keyrosterBin, append([]string{"machine", "renew", "ci", "--key", mKey, "--out", mCert}, args...)...)
		if code != 0 {
			t.Fatalf("machine renew %s exited %d, want 0:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, stdout, stderr, env.Stderr.String())
		}
		return stdout, stderr
	}
	mOut, mErr := renew()
	if !strings.Contains(mOut, "machine certificate for ci written to ") || !strings.Contains(mOut, mCert) {
		t.Fatalf("setup: machine renew did not say it wrote %s:\nstdout:\n%s\nstderr:\n%s", mCert, mOut, mErr)
	}
	if strings.Contains(mErr, "host trust") || strings.Contains(mErr, "Host trust") {
		t.Fatalf("setup: machine renew printed host trust text with no managed file; stderr:\n%s", mErr)
	}
	for _, name := range trustManaged {
		if _, err := os.Lstat(filepath.Join(sshDir, name)); err == nil {
			t.Fatalf("setup: %s exists after the first machine renew, which must create no managed file", filepath.Join(sshDir, name))
		}
	}
	t.Logf("setup: the machine key, the role, the machine and the first machine renew took %s", time.Since(setupAt).Round(time.Millisecond))
	// Pay the setup's four admin requests back before the host joins
	// (hcrSetupPayback): in CI the approval's POST found the bucket empty,
	// and a retry of the approval spends on its two reads the two requests
	// that its 2 s wait refills.
	time.Sleep(hcrSetupPayback)
	// joinHostCert's fetcher polls every 5 s (hostCertPoll): a 1 s fetcher
	// would exhaust the agent's request rate in a test this long.
	eh := joinHostCert(t, env, kr, "web1")
	login := currentUser(t)
	keys := t.TempDir()
	gen1 := pubKey(t, readPub(t, sg.HostCAPub))
	fp1 := ssh.FingerprintSHA256(gen1)
	rootFP, rootsPub := sg.RootFingerprints[0], filepath.Join(filepath.Dir(sg.BundleDir), "roots.pub")
	kh := filepath.Join(sshDir, trustKnownHosts)
	// The test's one re-anchor, shared by c1 and r1.
	reanchored := false

	// 0. The genesis certificate c1: signed by host CA generation 1, 90 s,
	// served, observed within 15 s of its issuance or replaced by its
	// renewal (the one re-anchor).
	c1, _ := hcrAnchor(t, eh, waitHostCerts(t, eh, 1, hcrFirst, "step 0: no host certificate within 60 s of the join", nil)[0], nil, gen1, "c1", &reanchored)
	hcrCert(t, eh, c1, gen1, "c1")
	t.Logf("c1: serial %d, issued at %s", c1.Serial, hcrIssued(c1).UTC().Format(hcrClock))

	// 1. The genesis sync: one CA line, web1, generation 1. Client B's file
	// is a copy taken now, equal to A's byte for byte.
	hcrSync(t, kr, kh, gen1)
	bKH := filepath.Join(t.TempDir(), "b_known_hosts")
	copyFile(t, kh, bKH, 0o600)
	if !bytes.Equal(readFile(t, kh), readFile(t, bKH)) {
		t.Fatalf("client B's copy differs from %s", kh)
	}
	cfgA := writeTrustConfig(t, "~/.ssh/"+trustSSHConfig, eh.sshd.port)
	cfgB := writeTrustConfig(t, copyManagedConfig(t, sshDir, bKH, ""), eh.sshd.port)
	c := issueAgentCert(t, sg, "hc1", "role:ops")

	// 2. Prepare generation 2 of the host CA (its key in the role agent)
	// with the signer stopped, ceremony 1 while it serves, the install with
	// it stopped. Both stops start by c1's issuance plus 40 s and serve
	// again by plus 50 s; the host commits bundle 2 within 45 s.
	k2 := filepath.Join(keys, "host_g2")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "host-g2", "-f", k2)
	sshAdd(t, sg.RoleAgent, k2)
	gen2 := pubKey(t, readPub(t, k2+".pub"))
	fp2 := ssh.FingerprintSHA256(gen2)
	prepared := filepath.Join(keys, "host-g2.json")
	hcrStopped(t, env, "prepare", hcrIssued(c1).Add(hcrC1StopBy), hcrIssued(c1).Add(hcrC1UpBy), func() time.Time {
		code, out := sg.signerCmd(t, "ca-rotate", "prepare", "--state-dir", sg.StateDir, "--role", "host", "--key", fp2, "--out", prepared)
		if code != 0 || !strings.Contains(out, "role host generation 2 "+fp2) || !strings.Contains(out, "prepare file: ") {
			t.Fatalf("ca-rotate prepare --role host exited %d:\n%s", code, out)
		}
		return time.Now()
	})
	v1 := readFile(t, filepath.Join(sg.BundleDir, "bundle.json"))
	succ := filepath.Join(keys, "succ")
	out := caRotCeremony(t, sg.RootAgent, rootFP, rootsPub, sg.BundleDir, trust.SHA256Hex(v1), succ,
		"--ca-next", "host="+prepared, "--ca-next-fingerprint", "host="+fp2)
	if n := strings.Count(out, "CA host gen 2 "+fp2+": none -> next\n"); n != 2 {
		t.Fatalf("root sign and trust verify print the next line %d times, want once each:\n%s", n, out)
	}
	installed2, served2 := hcrStopped(t, env, "the install of ceremony 1", hcrIssued(c1).Add(hcrC1StopBy), hcrIssued(c1).Add(hcrC1UpBy), func() time.Time {
		code, out := sg.signerCmd(t, "install-bundle", "--state-dir", sg.StateDir,
			"--bundle", filepath.Join(succ, "bundle.json"), "--policy", filepath.Join(succ, "policy.json"))
		done := time.Now()
		if code != 0 || !strings.Contains(out, "installed bundle version 2") {
			t.Fatalf("install-bundle of ceremony 1 exited %d:\n%s", code, out)
		}
		return done
	})
	hcrCommitted(t, eh, kr, 2, installed2, served2, installed2.Add(hcrCommit), "bundle 2 not committed within 45 s of its install")

	// 3. Client A refreshes: the sync writes both host CA keys for web1.
	// A and B both reach the host by generation 1; B's logins here and at
	// step 6 are the controls of its refusal at step 8. The export taken
	// after ceremony 1's install is the switch's --previous.
	// Client C first (03-12g): the real file still equals B's copy. A
	// not-due machine renew with --no-known-hosts changes nothing; one
	// without it adds generation 2's line for web1 and moves the state's
	// bundle_version to 2. C's file is a copy of the result.
	f1 := readFile(t, bKH)
	if got := readFile(t, kh); !bytes.Equal(got, f1) {
		t.Fatalf("step 3: the managed file is not client B's copy before machine renew:\n%s\nB's copy:\n%s", got, f1)
	}
	statePath := filepath.Join(admin.configHome, "keyroster", "host-trust.json")
	st0 := readFile(t, statePath)
	renewAt := time.Now()
	nkOut, nkErr := renew("--if-due", "--no-known-hosts")
	if !strings.HasPrefix(nkOut, "not due: ") || strings.Contains(nkErr, "host trust") || strings.Contains(nkErr, "Host trust") {
		t.Fatalf("step 3: machine renew --if-due --no-known-hosts, want not due and no host trust text:\nstdout:\n%s\nstderr:\n%s", nkOut, nkErr)
	}
	if got := readFile(t, kh); !bytes.Equal(got, f1) {
		t.Fatalf("step 3: machine renew --if-due --no-known-hosts changed the managed file:\n%s\nwant client B's copy:\n%s", got, f1)
	}
	if got := readFile(t, statePath); !bytes.Equal(got, st0) {
		t.Fatalf("step 3: machine renew --if-due --no-known-hosts changed the host trust state:\n%s\nwant:\n%s", got, st0)
	}
	rOut, rErr := renew("--if-due")
	if !strings.HasPrefix(rOut, "not due: ") {
		t.Fatalf("step 3: machine renew --if-due, want not due:\nstdout:\n%s\nstderr:\n%s", rOut, rErr)
	}
	addedLine := "Host trust: added the CA line of host CA generation 2 to " + kh + " for the 1 host name(s) its lines already trust.\n"
	switch n := strings.Count(rErr, addedLine); {
	case n == 0:
		t.Fatalf("step 3: machine renew --if-due added no line; stderr:\n%s", rErr)
	case n > 1:
		t.Fatalf("step 3: machine renew --if-due printed its added line %d times, want once; stderr:\n%s", n, rErr)
	}
	wantKH := append(slices.Clone(f1), "@cert-authority web1 "+trust.FormatKey(gen2)+" keyroster host CA generation 2\n"...)
	if got := readFile(t, kh); !bytes.Equal(got, wantKH) {
		t.Fatalf("step 3: the managed file is not client B's copy plus generation 2's line:\n%s\nwant:\n%s", got, wantKH)
	}
	st1 := readFile(t, statePath)
	var stGot, stWant map[string]any
	if err := json.Unmarshal(st1, &stGot); err != nil {
		t.Fatalf("step 3: the host trust state after machine renew does not decode: %v\n%s", err, st1)
	}
	if err := json.Unmarshal(st0, &stWant); err != nil {
		t.Fatalf("step 3: the host trust state before machine renew does not decode: %v\n%s", err, st0)
	}
	stWant["bundle_version"] = float64(2)
	gotJSON, errGot := json.Marshal(stGot)
	wantJSON, errWant := json.Marshal(stWant)
	if errGot != nil || errWant != nil || !bytes.Equal(gotJSON, wantJSON) {
		t.Fatalf("step 3: the host trust state after machine renew is not the state before it with bundle_version 2:\n%s\nbefore:\n%s", st1, st0)
	}
	t.Logf("step 3: the two machine renew runs took %s", time.Since(renewAt).Round(time.Millisecond))
	cKH := filepath.Join(t.TempDir(), "c_known_hosts")
	copyFile(t, kh, cKH, 0o600)
	cfgC := writeTrustConfig(t, copyManagedConfig(t, sshDir, cKH, ""), eh.sshd.port)
	hcrSync(t, kr, kh, gen1, gen2)
	// A's sync rewrote the real file from its own inputs (03-12g).
	if bytes.Equal(readFile(t, kh), readFile(t, cKH)) {
		t.Fatalf("step 3: A's sync left the managed file equal to client C's copy, want the file the sync writes:\n%s", readFile(t, kh))
	}
	hcrAccepted(t, cfgA, login, "127.0.0.1", c, gen1, "client A after ceremony 1")
	hcrAccepted(t, cfgB, login, "127.0.0.1", c, gen1, "client B after ceremony 1")
	previous := sg.exportLog(t)

	// 4. Anchor on a fresh renewal r1 by generation 1, then ceremony 2 at
	// once: --ca-switch host with a 60 s allowance; generation 1 drains
	// until bundle 3's issued_at plus 450 s.
	r1, r1prev := hcrAnchor(t, eh, hcrNext(t, eh, c1, gen1, "r1"), c1, gen1, "r1", &reanchored)
	v2 := readFile(t, filepath.Join(succ, "bundle.json"))
	sw := filepath.Join(keys, "switch")
	out = caRotCeremony(t, sg.RootAgent, rootFP, rootsPub, succ, trust.SHA256Hex(v2), sw, "--ca-switch", "host", "--drain-allowance", hcrAllowance.String())
	b3, err := trust.ParseBundle(readFile(t, filepath.Join(sw, "bundle.json")))
	if err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(trust.TimeFormat, b3.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	var trustedUntil string
	for _, e := range b3.CAs {
		if e.Role == "host" && e.Generation == 1 && e.State == "draining" {
			trustedUntil = e.TrustedUntil
		}
	}
	until, err := time.Parse(trust.TimeFormat, trustedUntil)
	if err != nil || !until.Equal(issuedAt.Add(hcrDrain)) {
		t.Fatalf("the switch bundle's draining host entry is trusted until %q (%v), want issued_at %s plus %s", trustedUntil, err, b3.IssuedAt, hcrDrain)
	}
	for _, want := range []string{
		"CA host gen 1 " + fp1 + ": active -> draining, trusted until " + trustedUntil + "; install by " + issuedAt.Add(hcrAllowance).Format(trust.TimeFormat) + " (advice)\n",
		"CA host gen 2 " + fp2 + ": next -> active\n",
	} {
		if n := strings.Count(out, want); n != 2 {
			t.Fatalf("root sign and trust verify print %q %d times, want once each:\n%s", want, n, out)
		}
	}
	t.Logf("ceremony 2 ended at r1 + %s; bundle 3 issued_at %s, generation 1 trusted until %s", time.Since(hcrIssued(r1)).Round(time.Millisecond), b3.IssuedAt, trustedUntil)

	// 5. The switch, with the signer stopped from by the earlier of r1 + 19 s
	// and issued_at + 50 s until r1 + 23 s: install --previous binds the
	// drain to r1, the last generation-1 certificate the log records; serve
	// refuses while the role agent holds generation 1; retire-key removes
	// it; doctor exits 0 with its last block's line.
	startBy := hcrIssued(r1).Add(hcrSwitchStart)
	if alt := issuedAt.Add(50 * time.Second); alt.Before(startBy) {
		startBy = alt
	}
	installed3, served3 := hcrStopped(t, env, "the switch", startBy, hcrIssued(r1).Add(hcrSwitchUp), func() time.Time {
		code, out := sg.signerCmd(t, "install-bundle", "--state-dir", sg.StateDir,
			"--bundle", filepath.Join(sw, "bundle.json"), "--policy", filepath.Join(sw, "policy.json"), "--previous", previous)
		done := time.Now()
		m := caRotDrainRE("host").FindStringSubmatch(out)
		if code != 0 || !strings.Contains(out, "installed bundle version 3") || m == nil || m[1] != trustedUntil {
			t.Fatalf("install-bundle --previous of the switch exited %d, want version 3 and the drain line until %s:\n%s", code, trustedUntil, out)
		}
		valid, err := time.Parse(trust.TimeFormat, m[2])
		if wantV := time.Unix(int64(r1.ValidBefore), 0).UTC().Format(trust.TimeFormat); err != nil || m[2] != wantV || valid.Add(300*time.Second).After(until) { //nolint:gosec // G115: Unix times
			t.Fatalf("the drain line's last certificate is valid until %q (%v); want r1's %s, and it plus 300 s at or below %s", m[2], err, wantV, trustedUntil)
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
			t.Fatalf("serve with the old host key in the agent: %v (deadline %v), want a refusal naming draining_key_still_usable:\n%s", err, ctx.Err(), b)
		}
		sock := caRotRetireKey(t, sg, "host", fp1)
		caRotAgentHolds(t, sock, fp1)
		code, out = sg.signerCmd(t, "doctor", "--state-dir", sg.StateDir)
		if code != 0 || !strings.Contains(out, "OK switch_floor: host generation 2: the log records no certificate of this key; the earliest is the floor") ||
			strings.Contains(out, "draining_key_still_usable") {
			t.Fatalf("doctor after retire-key exited %d, want 0 with the host generation 2 switch_floor line and no draining_key_still_usable:\n%s", code, out)
		}
		t.Logf("doctor after retire-key exited 0:\n%s", out)
		return done
	})

	// 6. The old key still serves: right after the switch sshd serves r1,
	// and A and B both reach the host by generation 1, all by r1 + 28 s; B
	// fails with the renewal, not with the switch. Then the host commits
	// bundle 3, seen by r1 + 44 s.
	hcrServes(t, eh.agentHost, r1, hcrServe)
	hcrAccepted(t, cfgA, login, "127.0.0.1", c, gen1, "client A right after the switch")
	hcrAccepted(t, cfgB, login, "127.0.0.1", c, gen1, "client B right after the switch")
	// Client C, whose file machine renew refreshed (03-12g).
	hcrAccepted(t, cfgC, login, "127.0.0.1", c, gen1, "client C right after the switch")
	hcrServes(t, eh.agentHost, r1, hcrServe)
	if now := time.Now(); now.After(hcrIssued(r1).Add(hcrStep6)) {
		t.Fatalf("step 6 ended at %s, after r1 + 28 s (%s)", now.UTC().Format(hcrClock), hcrIssued(r1).Add(hcrStep6).UTC().Format(hcrClock))
	}
	t.Logf("step 6 ended at r1 + %s", time.Since(hcrIssued(r1)).Round(time.Millisecond))
	hcrCommitted(t, eh, kr, 3, installed3, served3, hcrIssued(r1).Add(hcrCommit3), "bundle 3 not committed by r1 + 44 s, which the quiet check at r1 + 45 s needs")

	// 6a. The host stays quiet between the switch and its own renewal. Each
	// host status poll of the commit wait verifies the trust bundle, and
	// narrows A's live file under it, before it asks for the host status;
	// the server answers /trust from a signer status it caches for up to 5 s,
	// so a poll soon after the switch may still have verified bundle 2. A
	// logs in once more and still meets a certificate by generation 1: the
	// old host CA's line survived those narrowings while generation 1 is
	// trusted (03-12f2).
	hcrQuietCheck(t, eh, r1prev, r1, func() {
		hcrAccepted(t, cfgA, login, "127.0.0.1", c, gen1, "client A after the host committed the switch")
	})

	// 7. The renewal r2, by generation 2, on the host's own schedule.
	r2 := hcrNext(t, eh, r1, gen2, "r2")

	// 8. After the renewal: the agent refused no answer in the whole test;
	// A reaches the host by generation 2; B, which did not refresh, is
	// refused, from a source of its own (127.0.0.2, OpenSSH 10.x
	// PerSourcePenalties); then B's remedy, a refreshed file, lets it in.
	hcrNoRefusal(t, eh)
	hcrAccepted(t, cfgA, login, "127.0.0.1", c, gen2, "client A after the renewal")
	// Client C, whose file differs from B's only by the line machine renew
	// added (03-12g).
	hcrAccepted(t, cfgC, login, "127.0.0.1", c, gen2, "client C after the renewal")
	hcrRefused(t, cfgB, login, net.IPv4(127, 0, 0, 2).String(), c, gen2, "client B after the renewal")
	hcrServes(t, eh.agentHost, r2, hcrServe)
	// The remedy: a fresh sync still writes both lines (generation 1 drains
	// until trusted_until), and B's file becomes a copy of the live one.
	hcrSync(t, kr, kh, gen2, gen1)
	copyFile(t, kh, bKH, 0o600)
	hcrAccepted(t, cfgB, login, "127.0.0.1", c, gen2, "client B after its remedy")

	// 9. The exported log verifies, names bundle v3 and counts the host
	// certificates.
	code, auditOut := auditVerify(t, sg, sg.exportLog(t))
	if code != 0 || !strings.Contains(auditOut, "trust bundle v3") {
		t.Fatalf("audit verify after the host CA rotation exited %d:\n%s", code, auditOut)
	}
	m := regexp.MustCompile(`(?m)^host certificates: (\d+)$`).FindStringSubmatch(auditOut)
	if m == nil {
		t.Fatalf("audit verify printed no host certificates line:\n%s", auditOut)
	}
	if n, _ := strconv.Atoi(m[1]); n < 3 {
		t.Fatalf("audit verify counts %d host certificates, want at least 3:\n%s", n, auditOut)
	}
	t.Logf("serials: c1 %d, r1 %d (renewed %d), r2 %d; re-anchored: %v", c1.Serial, r1.Serial, r1prev.Serial, r2.Serial, reanchored)
	t.Log(hcrMachineLine)
	t.Log(hcrLine)
}
