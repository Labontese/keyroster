//go:build e2e

package e2e

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
)

// forgetWait is the deadline of every wait of the forget e2e tests:
// twice the test fetcher's poll interval (1 s) plus 30 s (plan check
// item 7).
const forgetWait = 2*time.Second + 30*time.Second

// servedAgentRE finds the identity of a served host's line in keyroster
// host pending.
var servedAgentRE = regexp.MustCompile(`Host web1: [a-z_, ]+, served until forget \(agent identity (SHA256:[A-Za-z0-9+/]{43})\)\n  ([^\n]+)`)

// TestAgentReenrollEndToEnd is the runbook's re-enroll flow with a new
// identity and new host keys (03-08b, PR #72 fix-round carry-overs b and
// c; docs/runbooks/host-setup.md "Running the agent"): agent A of web1 is
// removed and its removal confirmed from its own heartbeat; agent B, a
// new host layout, enrolls and is approved under the same name, so A
// shows host_keys_changed and stays confirmed; keyroster host forget web1
// is refused forget_name_ambiguous; keyroster host forget --identity A
// succeeds without --host-gone; A's fetcher then gets unknown_agent, and
// B still applies a revocation made after the forget.
func TestAgentReenrollEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true})
	login := currentUser(t)
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	// The admin limiter allows a burst of 20 and 60 a minute per address;
	// every keyroster command spends one to three. A command it refused
	// is retried once the bucket refilled.
	run := func(args ...string) (int, string, string) {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		for try := 0; try < 10 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
			time.Sleep(3 * time.Second)
			code, out, errOut = env.keyroster(t, admin, "", args...)
		}
		return code, out, errOut
	}
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := run(args...)
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}

	// 1. Agent A enrolled and approved as web1.
	a := enrollApproved(t, env, kr, "web1")
	t.Logf("agent A applied its first state")

	// 2. web1 removed; wait until host pending shows A's removal confirmed.
	kr("host", "remove", "web1", "--yes")
	var pending, idA string
	for deadline := time.Now().Add(forgetWait); ; time.Sleep(2 * time.Second) {
		pending = kr("host", "pending")
		if m := servedAgentRE.FindStringSubmatch(pending); m != nil && strings.HasPrefix(m[2], "removal confirmed at directory v") {
			idA = m[1]
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("host pending never showed web1's removal confirmed within %s; last answer:\n%s\nA's fetch log:\n%s\nserver log:\n%s", forgetWait, pending, a.fetch.String(), env.Stderr.String())
		}
	}
	t.Logf("keyroster host pending after the removal:\n%s", pending)

	// 3. Agent B: a new host layout, with new host keys and a new
	// identity, enrolls under web1 and is approved.
	// Owner decision D-R2: while B is approved but has not polled yet,
	// host status lists it and the name is already ambiguous.
	b := joinApprovedHeld(t, env, kr, "web1", func() {
		code, out, errOut := run("host", "forget", "web1")
		if code == 0 || !strings.Contains(errOut, "forget_name_ambiguous") || !strings.Contains(errOut, "approved, not yet polled") ||
			!strings.Contains(errOut, "keyroster host forget --identity "+idA) {
			t.Fatalf("keyroster host forget web1 while B is approved but has not polled: exit %d:\n%s\n%s", code, out, errOut)
		}
		t.Logf("keyroster host forget web1 before B polled (refused):\n%s", errOut)
	})
	// A must have applied B's directory before the check below means
	// anything: it then reports host_keys_rotated with last-good's
	// principals, which are none, so it stays confirmed (owner decision
	// D-R1 clears a confirmation only when principals are shown again).
	var aRow serverclient.HostStatusRow
	for deadline := time.Now().Add(forgetWait); ; time.Sleep(2 * time.Second) {
		st := hostsStatusJSON(t, kr)
		found := false
		for _, r := range st.Hosts {
			if r.ExpectedName == "web1" && r.State == serverclient.HostStateKeysChanged && r.Heartbeat != nil {
				aRow, found = r, true
			}
		}
		if found && aRow.Heartbeat.Status.Directory.Version >= st.Current.Directory {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("A never reported B's directory v%d within %s; last row %+v\nA's fetch log:\n%s", st.Current.Directory, forgetWait, aRow, a.fetch.String())
		}
	}
	if la := aRow.Heartbeat.Status.LastApply; la != nil {
		t.Logf("A after B's approval: directory v%d, last apply %s, host_status %q, %d files", aRow.Heartbeat.Status.Directory.Version, la.Result, la.HostStatus, len(aRow.Heartbeat.Status.Files))
	}
	pending = kr("host", "pending")
	m := servedAgentRE.FindStringSubmatch(pending)
	if m == nil || m[1] != idA || !strings.Contains(pending, "Host web1: host_keys_changed, served until forget (agent identity "+idA+")") ||
		!strings.HasPrefix(m[2], "removal confirmed at directory v") {
		t.Fatalf("after B's approval, A is not shown host_keys_changed and confirmed:\n%s", pending)
	}
	t.Logf("keyroster host pending after B's approval:\n%s", pending)

	// 4. The name is ambiguous: nothing is sent.
	code, out, errOut := run("host", "forget", "web1")
	if code == 0 || !strings.Contains(errOut, "forget_name_ambiguous") || !strings.Contains(errOut, "keyroster host forget --identity "+idA) {
		t.Fatalf("keyroster host forget web1 with two agents named web1: exit %d:\n%s\n%s", code, out, errOut)
	}
	t.Logf("keyroster host forget web1 (refused):\n%s", errOut)
	if !regexp.MustCompile(`keyroster host forget --identity SHA256:[A-Za-z0-9+/]{43}\n(?s:.*)keyroster host forget --identity SHA256:[A-Za-z0-9+/]{43}`).MatchString(errOut) {
		t.Fatalf("the refusal does not name both identities:\n%s", errOut)
	}

	// 5. Forget A by its identity, without --host-gone.
	forgot := kr("host", "forget", "--identity", idA)
	if !strings.Contains(forgot, "Forgot the agent enrolled as web1") || !strings.Contains(forgot, "agent identity: "+idA) || strings.Contains(forgot, "--host-gone") {
		t.Fatalf("keyroster host forget --identity %s:\n%s", idA, forgot)
	}
	t.Logf("keyroster host forget --identity %s:\n%s", idA, forgot)

	// 6. A's fetcher gets unknown_agent; B still applies a revocation.
	for deadline := time.Now().Add(forgetWait); !strings.Contains(a.fetch.String(), "unknown_agent"); time.Sleep(200 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("A's fetcher never logged unknown_agent within %s\nA's fetch log:\n%s", forgetWait, a.fetch.String())
		}
	}
	for _, l := range strings.Split(a.fetch.String(), "\n") {
		if strings.Contains(l, "unknown_agent") {
			t.Logf("A's fetcher: %s", l)
			break
		}
	}
	krlBefore := b.lastApply(t).KRLVersion
	c := issueAgentCert(t, env.Signer, "c-after-forget", "role:ops")
	kr("revoke", "serial", c.serial, "--reason", "e2e after the forget of A")
	for deadline := time.Now().Add(forgetWait); ; time.Sleep(200 * time.Millisecond) {
		if r := b.lastApply(t); r != nil && r.KRLVersion > krlBefore && r.SelfTest == "pass" {
			t.Logf("B applied the revocation made after A's forget: KRL v%d -> v%d", krlBefore, r.KRLVersion)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B did not apply the revocation within %s (last %+v)\nB's run log:\n%s\nB's fetch log:\n%s", forgetWait, b.lastApply(t), b.run.String(), b.fetch.String())
		}
	}
	b.wantRefused(t, "the revoked certificate on B", c, login, "127.0.0.4", logRevoked)
	if strings.Contains(b.fetch.String(), "unknown_agent") {
		t.Fatalf("B's fetcher logged unknown_agent:\n%s", b.fetch.String())
	}
}
