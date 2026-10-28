//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	fetchBinOnce sync.Once
	fetchBinPath string
	fetchBinErr  error
)

// fetchBin builds keyroster-agent-fetch once, like agentBin, with
// CGO_ENABLED=0: only the pure-Go resolver maps keyroster.localhost to
// loopback.
func fetchBin(t *testing.T) string {
	t.Helper()
	fetchBinOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			fetchBinErr = err
			return
		}
		fetchBinPath = filepath.Join(filepath.Dir(keyrosterBin), "keyroster-agent-fetch")
		cmd := exec.Command("go", "build", "-trimpath", "-o", fetchBinPath, "./cmd/keyroster-agent-fetch")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			fetchBinErr = fmt.Errorf("build keyroster-agent-fetch: %w\n%s", err, out)
		}
	})
	if fetchBinErr != nil {
		t.Fatal(fetchBinErr)
	}
	return fetchBinPath
}

// enrolledHost is one host enrolled through keyroster-agent install, with
// its applier loop and fetcher running.
type enrolledHost struct {
	*agentHost
	run, fetch       *syncBuffer
	runDone, fetchDn <-chan struct{}
}

// newEnrolledHostLayout makes a host root with the directories install
// expects to exist (<root>/etc, <root>/var/lib, the sshd configuration
// directory) and starts its sshd; the state directory is created by
// install.
func newEnrolledHostLayout(t *testing.T, env *signerEnv) *agentHost {
	t.Helper()
	base := t.TempDir()
	h := &agentHost{signer: env, root: filepath.Join(base, "root"), state: filepath.Join(base, "state")}
	h.spoolDr = filepath.Join(h.state, "spool")
	for _, d := range []string{"etc/ssh/sshd_config.d", "var/lib"} {
		if err := os.MkdirAll(filepath.Join(h.root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"", "etc", "etc/ssh", "etc/ssh/sshd_config.d", "var", "var/lib"} {
		if err := os.Chmod(filepath.Join(h.root, d), 0o755); err != nil { //nolint:gosec // the host's own directories
			t.Fatal(err)
		}
	}
	if err := os.Chmod(base, 0o755); err != nil { //nolint:gosec // the state directory's parent
		t.Fatal(err)
	}
	h.sshd = startIncludeSSHD(t, h.root)
	return h
}

// startEnrolled starts keyroster-agent run (--interval 1s) and
// keyroster-agent-fetch (--poll 1s) for h.
func startEnrolled(t *testing.T, h *agentHost) *enrolledHost {
	t.Helper()
	prefix := opensshPrefix(t)
	e := &enrolledHost{agentHost: h}
	runArgs := []string{"run", "--state-dir", h.state, "--root", h.root,
		"--sshd", filepath.Join(prefix, "sbin", "sshd"), "--sshd-config", h.sshd.cfg,
		"--ssh-keygen", filepath.Join(prefix, "bin", "ssh-keygen"), "--reload", "signal", "--interval", "1s"}
	_, e.run, e.runDone = startDaemon(t, "keyroster-agent run", envWithout("SSH_AUTH_SOCK"), agentBin(t), runArgs...)
	_, e.fetch, e.fetchDn = startDaemon(t, "keyroster-agent-fetch", envWithout("SSH_AUTH_SOCK"), fetchBin(t),
		"--config", filepath.Join(h.root, "etc", "keyroster-agent", "fetch.json"),
		"--dir", filepath.Join(h.root, "var", "lib", "keyroster-agent-fetch"),
		"--spool", filepath.Join(h.state, "spool"), "--outbox", filepath.Join(h.state, "outbox"), "--poll", "1s")
	return e
}

// agentLastApply is what the e2e tests read of the applier's report.
type agentLastApply struct {
	Generation       uint64   `json:"generation"`
	DirectoryVersion uint64   `json:"directory_version"`
	KRLVersion       uint64   `json:"krl_version"`
	SelfTest         string   `json:"self_test"`
	HostStatus       string   `json:"host_status"`
	Errors           []string `json:"errors"`
}

// lastApply is the last_apply of the applier's status.json, or nil.
func (h *agentHost) lastApply(t *testing.T) *agentLastApply {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.state, "status.json")) //nolint:gosec // test fixture
	if err != nil {
		return nil
	}
	var s struct {
		LastApply *agentLastApply `json:"last_apply"`
	}
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return s.LastApply
}

// TestAgentEnrollEndToEnd is 03-07's tracer (AGENT-01..03, REVOKE-02,
// REVOKE-03): an admin mints a join token with keyroster host join-token;
// keyroster-agent install lays out the host from the join file; the
// fetcher enrolls over mTLS with the applier's host-key proof of
// possession; keyroster host pending lists the host and keyroster host
// approve signs it into the directory; the fetcher then pulls the signed
// state over the agent listener and the applier installs it, so a
// certificate logs in. keyroster revoke serial goes through the server,
// and the host refuses that certificate a few polls later, with the same
// sshd PID since the first apply.
func TestAgentEnrollEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true})
	login := currentUser(t)
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	kr := func(args ...string) string {
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

	// 1. Role ops, host group lab mapping the test account to ops.
	kr("role", "add", "ops", "--max-ttl", "1h", "--yes")
	kr("host-group", "add", "lab", "--yes")
	kr("host-group", "map", "lab", login, "ops", "--yes")

	// 2. The join token, written 0600 and never printed.
	joinFile := filepath.Join(t.TempDir(), "join.txt")
	out := kr("host", "join-token", "web1", "--out", joinFile)
	raw, err := os.ReadFile(joinFile) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(joinFile); err != nil || st.Mode().Perm() != 0o600 || !strings.HasPrefix(string(raw), "kr-join-v1:") {
		t.Fatalf("join file: %v, mode %v, prefix %q", err, st.Mode().Perm(), string(raw)[:min(len(raw), 11)])
	}
	if strings.Contains(out, strings.TrimSpace(string(raw))) {
		t.Fatal("host join-token printed the join string")
	}
	t.Logf("keyroster host join-token: %s", strings.TrimSpace(out))

	// 3. keyroster-agent install, with the test user standing in for
	// keyroster-agent.
	h := newEnrolledHostLayout(t, env.Signer)
	code, iout := runBin(t, agentBin(t), "", "install", "--root", h.root, "--state-dir", h.state, "--join-file", joinFile, "--fetch-user", login)
	if code != 0 {
		t.Fatalf("keyroster-agent install exited %d:\n%s", code, iout)
	}
	t.Logf("keyroster-agent install: %s", strings.TrimSpace(iout))

	// 4. The applier's loop and the fetcher; the host enrolls.
	eh := startEnrolled(t, h)
	var pending string
	for deadline := time.Now().Add(30 * time.Second); !strings.Contains(pending, "Pending host web1"); time.Sleep(500 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("keyroster host pending never listed web1:\n%s\nfetch log:\n%s\nrun log:\n%s\nserver log:\n%s", pending, eh.fetch.String(), eh.run.String(), env.Stderr.String())
		}
		pending = kr("host", "pending")
	}
	t.Logf("keyroster host pending:\n%s", pending)
	if !regexp.MustCompile(`agent identity: SHA256:[A-Za-z0-9+/]{43}\n`).MatchString(pending) || !strings.Contains(pending, "host key: "+fingerprint(t, h.sshd.hostKey)) {
		t.Fatalf("host pending does not show the identity and the host key %s:\n%s", fingerprint(t, h.sshd.hostKey), pending)
	}
	// keyroster-agent identity on the host prints exactly those lines.
	prefix := opensshPrefix(t)
	code, ident := runBin(t, agentBin(t), "", "identity", "--state-dir", h.state, "--root", h.root,
		"--sshd", filepath.Join(prefix, "sbin", "sshd"), "--sshd-config", h.sshd.cfg)
	lines := strings.Split(strings.TrimSpace(ident), "\n")
	if code != 0 || len(lines) != 2 {
		t.Fatalf("keyroster-agent identity exited %d:\n%s", code, ident)
	}
	for _, l := range lines {
		if !strings.Contains(pending, "  "+l+"\n") {
			t.Fatalf("keyroster-agent identity prints %q, which host pending does not:\n%s", l, pending)
		}
	}
	t.Logf("keyroster-agent identity:\n%s", ident)
	before := time.Now()

	// 5. Approval: a directory version with host web1 and the enrolled key.
	// With --yes, host approve signs only the host keys the admin compared
	// (--host-key, every one; PR #71 review D-R4): here the ones
	// keyroster-agent identity printed.
	approveArgs := []string{"host", "approve", "web1", "--group", "lab", "--principal", "web1", "--yes"}
	for _, l := range lines {
		if fp, ok := strings.CutPrefix(l, "host key: "); ok {
			approveArgs = append(approveArgs, "--host-key", strings.Fields(fp)[0])
		}
	}
	approve := kr(approveArgs...)
	if !strings.Contains(approve, "+ host web1 host_group=lab status=active principals=[web1]") {
		t.Fatalf("host approve web1:\n%s", approve)
	}
	t.Logf("keyroster host approve:\n%s", approve)

	// 6. The applier applies within 10 s; a certificate logs in.
	waitFor(t, "the first apply", eh.runDone, eh.run, func() bool {
		r := h.lastApply(t)
		return r != nil && r.Generation > 0 && r.SelfTest == "pass" && len(r.Errors) == 0
	})
	first := time.Since(before)
	if first > 10*time.Second {
		t.Fatalf("the first apply came %s after the approval, want within 10 s\nrun log:\n%s\nfetch log:\n%s", first, eh.run.String(), eh.fetch.String())
	}
	r1 := h.lastApply(t)
	t.Logf("first apply %s after the approval: generation %d, KRL v%d", first.Round(time.Millisecond), r1.Generation, r1.KRLVersion)
	c := issueAgentCert(t, env.Signer, "c1", "role:ops")
	other := issueAgentCert(t, env.Signer, "c2", "role:ops")
	h.wantAccepted(t, "c1 after the first apply", c, login)
	t.Logf("certificate c1 (serial %s, role:ops) logs in as %s after the first apply", c.serial, login)
	pid := h.sshd.pid(t)

	// The server's kept copy of the KRL it served before the revocation:
	// an older genuine copy, for the cross-check below.
	served := filepath.Join(env.StateDir, "krl-served.json")
	servedBefore, err := os.ReadFile(served) //nolint:gosec // test fixture
	if err != nil {
		t.Fatalf("the server kept no KRL copy after serving the host: %v", err)
	}
	olderCopy := filepath.Join(t.TempDir(), "server-krl.json")
	if err := os.WriteFile(olderCopy, servedBefore, 0o600); err != nil {
		t.Fatal(err)
	}

	// 7. keyroster revoke serial through the server: refused a few polls
	// later (the server's KRL cache, one fetcher poll, one applier round).
	revokedAt := time.Now()
	rout := kr("revoke", "serial", c.serial, "--reason", "e2e agent enroll")
	t.Logf("keyroster revoke serial:\n%s", rout)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if r := h.lastApply(t); r != nil && r.KRLVersion > r1.KRLVersion && r.SelfTest == "pass" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no apply of the revocation's KRL within 20 s\nrun log:\n%s\nfetch log:\n%s", eh.run.String(), eh.fetch.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	took := time.Since(revokedAt)
	t.Logf("the revocation's KRL applied %s after keyroster revoke serial (KRL cache %s, fetcher poll 1 s, applier round 1 s)", took.Round(time.Millisecond), 5*time.Second)
	h.wantRefused(t, "c1 after its revocation", c, login, "127.0.0.2", logRevoked)
	h.wantAccepted(t, "c2 after c1's revocation", other, login)
	if got := h.sshd.pid(t); got != pid {
		t.Fatalf("sshd PID %d, was %d: sshd was restarted", got, pid)
	}
	t.Logf("sshd PID %d unchanged since the first apply", pid)

	// 8. The restore cross-check (T-03-277): the host's installed KRL
	// version against the server's own copy passes, and against the older
	// genuine copy it stops the runbook's block.
	code, kv := runBin(t, agentBin(t), "", "krl-version", "--root", h.root, "--state-dir", h.state)
	m := regexp.MustCompile(`^installed KRL version: ([0-9]+)\n$`).FindStringSubmatch(kv)
	if code != 0 || m == nil || m[1] != strconv.FormatUint(h.lastApply(t).KRLVersion, 10) {
		t.Fatalf("keyroster-agent krl-version exited %d: %q (the last apply reports KRL v%d)", code, kv, h.lastApply(t).KRLVersion)
	}
	if code, out := runCrossCheck(t, served, m[1]); code != 0 || !strings.Contains(out, "cross-check passed: the kept server copy's KRL v"+m[1]+" ") {
		t.Fatalf("the cross-check against the server's own copy: exit %d:\n%s", code, out)
	}
	if code, out := runCrossCheck(t, olderCopy, m[1]); code == 0 || !strings.Contains(out, "a host enforces KRL v"+m[1]+", above v") {
		t.Fatalf("the cross-check against an older genuine copy: exit %d:\n%s", code, out)
	} else {
		t.Logf("the cross-check stops on the older copy: %s", strings.TrimSpace(out))
	}

	// 9. Removal (owner decision D-R1, PR #71 review F8): the agent was
	// approved once, so after keyroster host remove it keeps getting signed
	// state. The removal version reaches the host, which then has no
	// principals files (c2 is refused), and a later revocation still
	// arrives. Then keyroster host forget deletes the agent.
	waitForApply := func(what string, cond func(r *agentLastApply) bool) {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
			if r := h.lastApply(t); r != nil && cond(r) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: no such apply within 30 s (last %+v)\nrun log:\n%s\nfetch log:\n%s", what, h.lastApply(t), eh.run.String(), eh.fetch.String())
			}
		}
	}
	before9 := h.lastApply(t)
	rm := kr("host", "remove", "web1", "--yes")
	t.Logf("keyroster host remove web1:\n%s", rm)
	waitForApply("the removal", func(r *agentLastApply) bool {
		return r.DirectoryVersion > before9.DirectoryVersion && r.HostStatus == "host_removed" && r.SelfTest == "pass"
	})
	h.wantRefused(t, "c2 after web1's removal", other, login, "127.0.0.3", logNoPrincipal)
	t.Logf("the removal applied: directory v%d, host_status host_removed", h.lastApply(t).DirectoryVersion)
	krlBefore := h.lastApply(t).KRLVersion
	c3 := issueAgentCert(t, env.Signer, "c3", "role:ops")
	kr("revoke", "serial", c3.serial, "--reason", "e2e after the removal")
	waitForApply("a revocation after the removal", func(r *agentLastApply) bool { return r.KRLVersion > krlBefore && r.SelfTest == "pass" })
	t.Logf("a revocation after the removal reached the removed host: KRL v%d", h.lastApply(t).KRLVersion)
	forgot := kr("host", "forget", "web1")
	if !strings.Contains(forgot, "Forgot the agent enrolled as web1") {
		t.Fatalf("keyroster host forget web1:\n%s", forgot)
	}
	t.Logf("keyroster host forget web1:\n%s", forgot)
}
