package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/serverclient"
)

// hbStatus is a valid status of a host on bundle 1, directory dir, KRL
// krl.
func hbStatus(dir, krl uint64) heartbeat.Status {
	h := strings.Repeat("ab", 32)
	return heartbeat.Status{
		AgentVersion: "keyroster-agent (devel)",
		Bundle:       heartbeat.Doc{Version: 1, SHA256: h}, Policy: heartbeat.Doc{Version: 1, SHA256: h},
		Directory: heartbeat.Doc{Version: dir, SHA256: h}, KRL: heartbeat.KRL{Version: krl, SHA256: h},
		Generation: 2, Files: []heartbeat.File{{Path: "revoked.krl", SHA256: h}},
		LastApply: &heartbeat.LastApply{At: "2026-10-28T12:00:00Z", Result: heartbeat.ResultOK},
		LastCheck: &heartbeat.LastCheck{At: "2026-10-28T12:00:00Z"},
		Seq:       1,
	}
}

func statusRow(name, state string, hb *heartbeat.Heartbeat) serverclient.HostStatusRow {
	return serverclient.HostStatusRow{Name: name, ExpectedName: name, IdentitySPKISHA256: strings.Repeat("00", 32), State: state,
		LastSeen: time.Now().Add(-12 * time.Second).UTC().Format(time.RFC3339), ReceivedAt: "2026-10-28T12:00:00Z", Heartbeat: hb}
}

// statusEnv answers GET hosts/status with ans.
func statusEnv(t *testing.T, ans any) *dirEnv {
	t.Helper()
	e := popHostsEnv(t)
	b, err := json.Marshal(ans)
	if err != nil {
		t.Fatal(err)
	}
	var called bool
	e.recordCall(http.MethodGet, serverclient.AdminHostsStatusPath, &called, string(b), http.StatusOK)
	return e
}

// TestHostStatus is keyroster host status (03-08, AGENT-07): the
// convergence header, one row per host with its alerts, the removed host
// shown as served (carry-over a), and the CLI's own checks of what the
// server sent.
func TestHostStatus(t *testing.T) {
	stuck := hbStatus(5, 100)
	stuck.Stuck = heartbeat.StuckPendingStateUnknown
	stuck.LastApply.Result, stuck.LastApply.Error = heartbeat.ResultRefused, "pending_state_unknown: current names \"x\""
	mid := hbStatus(5, 100)
	mid.Pending = &heartbeat.Pending{Step: heartbeat.StepIntermediate, From: 2, To: 4, Intermediate: 3}
	probe := hbStatus(5, 100)
	probe.LastApply.Detail = "probe:negative_refused"
	stale := hbStatus(5, 99)
	stale.KRLStale = true
	silent := statusRow("web6", serverclient.HostStateActive, nil)
	silent.Silent = true
	ans := serverclient.HostsStatusAnswer{Current: serverclient.HostVersions{Bundle: 1, Directory: 5, KRL: 100, BundleSHA256: strings.Repeat("ab", 32), DirectorySHA256: strings.Repeat("ab", 32), KRLSHA256: strings.Repeat("ab", 32)}, Hosts: []serverclient.HostStatusRow{
		statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: probe}),
		statusRow("web2", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: stuck}),
		statusRow("web3", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: mid}),
		statusRow("web4", serverclient.HostStateRemoved, &heartbeat.Heartbeat{Status: stale, ClockOffsetS: -301}),
		silent,
	}}
	ans.Hosts[4].NeverApplied = true
	ans.Hosts[3].ClockSkew, ans.Hosts[3].ClockOffsetS = true, -301
	ans.Hosts[0].SeqRegressed = true
	ans.Hosts[1].IdentityRotatedAt, ans.Hosts[1].IdentityRotations = time.Now().Add(-3*time.Hour).UTC().Format(time.RFC3339), 2
	ans.Hosts[2].IdentityRotatedAt, ans.Hosts[2].IdentityRotations = time.Now().Add(-8*24*time.Hour).UTC().Format(time.RFC3339), 1
	t.Run("table", func(t *testing.T) {
		statusEnv(t, ans)
		code, out, stderr := run(t, "host", "status")
		if code != 0 {
			t.Fatalf("host status: exit %d: %s", code, stderr)
		}
		t.Logf("keyroster host status:\n%s", out)
		for _, want := range []string{
			"bundle v1 on 3/5 hosts\n", "directory v5 on 3/5 hosts\n", "KRL v100 on 2/5 hosts\n",
			"ok (probe:negative_refused)", "stuck: pending_state_unknown", "sudo keyroster-agent apply --once --recover-to-last-good",
			"pending: intermediate", "removed, served until forget", "krl_stale", "clock_skew (-301 s)", "silent", "seq_regressed", "web1: seq_regressed: its heartbeats carry a seq below the stored one", "never applied", "v99*",
			"Reported by keyroster-server; run `keyroster-agent check` on a host to verify it there.\n",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("host status lacks %q:\n%s", want, out)
			}
		}
		if !strings.Contains(out, "identity rotated 3h ago") || strings.Count(out, "identity rotated") != 1 {
			t.Errorf("host status shows a rotation 3 h ago, and none 8 days ago, as \"identity rotated <age>\":\n%s", out)
		}
		if strings.Contains(out, "waiting for approval") || strings.Contains(out, "Pending host") {
			t.Fatalf("a served host shown as waiting for approval:\n%s", out)
		}
	})
	t.Run("json", func(t *testing.T) {
		statusEnv(t, ans)
		code, out, stderr := run(t, "host", "status", "--json")
		var got serverclient.HostsStatusAnswer
		if code != 0 || json.Unmarshal([]byte(out), &got) != nil || len(got.Hosts) != 5 || got.Hosts[0].Heartbeat.Status.LastApply.Detail != "probe:negative_refused" {
			t.Fatalf("host status --json: exit %d: %s %s", code, out, stderr)
		}
	})
	t.Run("escape_from_the_server_refused", func(t *testing.T) {
		bad := hbStatus(5, 100)
		bad.SSHDVersion = "OpenSSH\x1b]0;owned\x07"
		statusEnv(t, serverclient.HostsStatusAnswer{Current: ans.Current, Hosts: []serverclient.HostStatusRow{statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: bad})}})
		code, out, stderr := run(t, "host", "status")
		if code == 0 || !strings.Contains(stderr, "does not check out") || strings.ContainsRune(out+stderr, 0x1b) {
			t.Fatalf("an escape sequence in the answer: exit %d: %q %q", code, out, stderr)
		}
	})
	t.Run("bad_state_refused", func(t *testing.T) {
		statusEnv(t, serverclient.HostsStatusAnswer{Current: ans.Current, Hosts: []serverclient.HostStatusRow{statusRow("web1", "pending", nil)}})
		if code, _, stderr := run(t, "host", "status"); code == 0 || !strings.Contains(stderr, "does not check out") {
			t.Fatalf("an unknown state: exit %d: %s", code, stderr)
		}
	})
	t.Run("approved_not_yet_polled", func(t *testing.T) {
		// Owner decision D-R2 (03-08b fix round 1): an agent the directory
		// approves that has not polled yet.
		r := statusRow("web7", serverclient.HostStateActive, nil)
		r.Silent, r.NeverApplied, r.NotYetPolled = true, true, true
		statusEnv(t, serverclient.HostsStatusAnswer{Current: ans.Current, Hosts: []serverclient.HostStatusRow{r}})
		code, out, stderr := run(t, "host", "status")
		if code != 0 || !strings.Contains(out, "approved, not yet polled") {
			t.Fatalf("an approved agent that has not polled: exit %d: %s%s", code, out, stderr)
		}
		for _, bad := range []func(r *serverclient.HostStatusRow){
			func(r *serverclient.HostStatusRow) { r.State = serverclient.HostStateRemoved },
			func(r *serverclient.HostStatusRow) { r.Heartbeat = &heartbeat.Heartbeat{Status: hbStatus(5, 100)} },
		} {
			b := r
			bad(&b)
			statusEnv(t, serverclient.HostsStatusAnswer{Current: ans.Current, Hosts: []serverclient.HostStatusRow{b}})
			if code, _, stderr := run(t, "host", "status"); code == 0 || !strings.Contains(stderr, "does not check out") {
				t.Fatalf("a not-yet-polled row that is not active without a heartbeat (%+v): exit %d: %s", b, code, stderr)
			}
		}
	})
	t.Run("no_hosts", func(t *testing.T) {
		statusEnv(t, serverclient.HostsStatusAnswer{Current: ans.Current, Hosts: []serverclient.HostStatusRow{}})
		code, out, _ := run(t, "host", "status")
		if code != 0 || !strings.Contains(out, "KRL v100 on 0/0 hosts\n") || !strings.Contains(out, "No approved host has reported yet.") {
			t.Fatalf("no hosts: exit %d:\n%s", code, out)
		}
	})
}

// TestServedHostNotPending is carry-over a on the CLI: host pending lists
// an approved-once host the directory no longer approves on its own line,
// never as waiting, and host approve never picks it.
func TestServedHostNotPending(t *testing.T) {
	_, key := writeEntryKey(t, "web1")
	served := serverclient.ServedHost{PendingHost: serverclient.PendingHost{ExpectedName: "web1", IdentitySPKISHA256: strings.Repeat("00", 32),
		HostKeys: []string{key}, Facts: enroll.Facts{OSID: "debian", Hostname: "web1"}, EnrolledAt: "2026-10-28T12:00:00Z"}, State: serverclient.HostStateRemoved}
	ans, err := json.Marshal(serverclient.PendingHostsAnswer{Hosts: []serverclient.PendingHost{}, Served: []serverclient.ServedHost{served}})
	if err != nil {
		t.Fatal(err)
	}
	env := func(t *testing.T) *dirEnv {
		t.Helper()
		e := popHostsEnv(t)
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminPendingHostsPath, &called, string(ans), http.StatusOK)
		return e
	}
	t.Run("pending_shows_served_line", func(t *testing.T) {
		env(t)
		code, out, stderr := run(t, "host", "pending")
		if code != 0 || !strings.Contains(out, "No host is waiting for approval.\n") || !strings.Contains(out, "Host web1: removed, served until forget (agent identity SHA256:") ||
			strings.Contains(out, "Pending host web1") {
			t.Fatalf("host pending: exit %d:\n%s%s", code, out, stderr)
		}
	})
	t.Run("approve_refuses_a_served_host", func(t *testing.T) {
		e := env(t)
		code, _, stderr := run(t, "host", "approve", "web1", "--group", "web", "--principal", "web1")
		if code == 0 || !strings.Contains(stderr, "was approved before and is now removed, served until forget") {
			t.Fatalf("host approve of a served host: exit %d: %s", code, stderr)
		}
		if e.agent.dirSigns() != 0 {
			t.Fatal("a directory version was signed for a served host")
		}
	})
	t.Run("unknown_state_refused", func(t *testing.T) {
		e := popHostsEnv(t)
		bad := served
		bad.State = "pending"
		b, _ := json.Marshal(serverclient.PendingHostsAnswer{Hosts: []serverclient.PendingHost{}, Served: []serverclient.ServedHost{bad}})
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminPendingHostsPath, &called, string(b), http.StatusOK)
		if code, _, stderr := run(t, "host", "pending"); code == 0 || !strings.Contains(stderr, "does not check out") {
			t.Fatalf("an unknown served state: exit %d: %s", code, stderr)
		}
	})
}

// TestHostForgetHostGone is carry-over b on the CLI (03-08, 03-08b): an
// agent approved once without a recorded removal confirmation is refused
// before anything is sent, the refusal naming --host-gone with its
// identity; --host-gone is then sent, printed before the request and
// after it.
func TestHostForgetHostGone(t *testing.T) {
	_, key := writeEntryKey(t, "web1")
	web1 := servedRow("web1", "00", key, false)
	t.Run("removal_not_applied_refused", func(t *testing.T) {
		e := forgetEnv(t, nil, web1)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminForgetHostPath, &called, forgetAnswer(t, web1.PendingHost), http.StatusOK)
		code, _, stderr := run(t, "host", "forget", "web1")
		if code == 0 || !strings.Contains(stderr, "host_removal_not_applied") || !strings.Contains(stderr, "keyroster host forget --identity SHA256:"+strings.Repeat("A", 43)+" --host-gone") {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if e.wasCalled(&called) {
			t.Fatal("the refused forget was sent")
		}
	})
	t.Run("host_gone_dropped_when_confirmed", func(t *testing.T) {
		confirmed := servedRow("web1", "00", key, true)
		e := forgetEnv(t, nil, confirmed)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminForgetHostPath, &called, forgetAnswer(t, confirmed.PendingHost), http.StatusOK)
		code, out, stderr := run(t, "host", "forget", "web1", "--host-gone")
		if code != 0 || !strings.Contains(stderr, "--host-gone dropped") || strings.Contains(out, "Forgotten with --host-gone") {
			t.Fatalf("exit %d:\n%s%s", code, out, stderr)
		}
		if req := e.postedForget(t); req == nil || req.HostGone || req.ConfirmedVersion == 0 {
			t.Fatalf("the request %s", e.lastPost)
		}
	})
	t.Run("host_gone_sent", func(t *testing.T) {
		e := forgetEnv(t, nil, web1)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminForgetHostPath, &called, forgetAnswer(t, web1.PendingHost), http.StatusOK)
		code, out, stderr := run(t, "host", "forget", "web1", "--host-gone")
		if code != 0 || !strings.Contains(stderr, "host forget --host-gone: forgetting web1 without its confirmation") ||
			!strings.Contains(out, "Forgotten with --host-gone: the host never confirmed that it applied its removal.") ||
			!strings.Contains(out, "  host_gone: the host never confirmed its removal\n") || !strings.Contains(out, "override: --host-gone") {
			t.Fatalf("exit %d:\n%s%s", code, out, stderr)
		}
		if req := e.postedForget(t); !identityIs(req, "00") || !req.HostGone || req.ConfirmedVersion != 0 || req.RemovalVersion != 3 {
			t.Fatalf("the request %s", e.lastPost)
		}
	})
}

// TestServedLine (PR #72 review C14, 03-08b): a re-keyed host is shown as
// host_keys_changed and served until forget, in host pending and host
// status alike; host pending prints each served row's confirmation and
// the command that forgets it by identity.
func TestServedLine(t *testing.T) {
	for state, want := range map[string]string{
		serverclient.HostStateKeysChanged: "host_keys_changed, served until forget",
		serverclient.HostStateRemoved:     "removed, served until forget",
		serverclient.HostStateDisabled:    "disabled, served until forget",
	} {
		if got := servedLine(state); got != want {
			t.Errorf("servedLine(%s) = %q, want %q", state, got, want)
		}
	}
	_, key := writeEntryKey(t, "web1")
	confirmed, open := servedRow("web1", "00", key, true), servedRow("web1", "11", key, false)
	open.State = serverclient.HostStateKeysChanged
	forgetEnv(t, nil, confirmed, open)
	code, out, stderr := run(t, "host", "pending")
	idOpen := enroll.IdentityFingerprint(bytes.Repeat([]byte{0x11}, 32))
	for _, want := range []string{
		"Host web1: removed, served until forget (agent identity SHA256:" + strings.Repeat("A", 43) + ")\n  removal confirmed at directory v4; enrolled 2026-10-28T12:00:00Z\n" +
			"  forget it with: keyroster host forget --identity SHA256:" + strings.Repeat("A", 43) + "\n",
		"Host web1: host_keys_changed, served until forget (agent identity " + idOpen + ")\n  removal at directory v3 not confirmed; enrolled 2026-10-28T12:00:00Z\n" +
			"  forget it with: keyroster host forget --identity " + idOpen + "\n",
	} {
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("host pending: exit %d, want %q in:\n%s%s", code, want, out, stderr)
		}
	}
}

// TestHostStatusDiverged (PR #72 review C5): a host counts on a version
// only when its SHA-256 is the server's too; one that reports the current
// number with another SHA-256, or a version above the current one, is
// flagged diverged. So is one whose unapplied record is above the current
// version, a version a signer restore lost (PR #78 review): its note gives
// the remedy instead of saying it applies the next version it can. Fix
// round 2: a record at the current number with other bytes is lost too,
// one with the same bytes is not, one without a SHA-256 (an older agent)
// is judged by its number only, and a mixed record's note names only its
// lost part as lost.
func TestHostStatusDiverged(t *testing.T) {
	ab, cd := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	same := hbStatus(5, 100)
	other := hbStatus(5, 100)
	other.Directory.SHA256 = cd
	ahead := hbStatus(6, 100)
	ahead.Directory.SHA256 = cd
	recorded := hbStatus(5, 100)
	recorded.Unapplied = &heartbeat.Unapplied{Directory: 65}
	remade := hbStatus(4, 100)
	remade.Unapplied = &heartbeat.Unapplied{Directory: 5, DirectorySHA256: cd}
	current := hbStatus(4, 100)
	current.Unapplied = &heartbeat.Unapplied{Directory: 5, DirectorySHA256: ab}
	older := hbStatus(4, 100)
	older.Unapplied = &heartbeat.Unapplied{Directory: 5}
	mixed := hbStatus(5, 100)
	mixed.Unapplied = &heartbeat.Unapplied{Bundle: 2, BundleSHA256: ab, Directory: 65, DirectorySHA256: cd}
	// Fix round 3: on the current bundle, with and without a lost
	// recorded bundle (and directory), so the bundle count is exercised.
	onBundle := hbStatus(5, 100)
	onBundle.Bundle = heartbeat.Doc{Version: 2, SHA256: ab}
	lostBoth := hbStatus(5, 100)
	lostBoth.Bundle = heartbeat.Doc{Version: 2, SHA256: ab}
	lostBoth.Unapplied = &heartbeat.Unapplied{Bundle: 3, BundleSHA256: cd, Directory: 5, DirectorySHA256: cd}
	// Built as JSON: the current versions carry their SHA-256.
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 2, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts": []serverclient.HostStatusRow{
			statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: same}),
			statusRow("web2", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: other}),
			statusRow("web3", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: ahead}),
			statusRow("web4", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: recorded}),
			statusRow("web5", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: remade}),
			statusRow("web6", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: current}),
			statusRow("web7", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: older}),
			statusRow("web8", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: mixed}),
			statusRow("web9", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: onBundle}),
			statusRow("web10", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: lostBoth}),
		},
	})
	code, out, stderr := run(t, "host", "status")
	if code != 0 {
		t.Fatalf("host status: exit %d: %s", code, stderr)
	}
	t.Logf("keyroster host status:\n%s", out)
	if !strings.Contains(out, "bundle v2 on 1/10 hosts\n") || !strings.Contains(out, "directory v5 on 2/10 hosts\n") || !strings.Contains(out, "KRL v100 on 10/10 hosts\n") {
		t.Fatalf("diverged hosts counted as converged:\n%s", out)
	}
	flagged := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 && strings.HasPrefix(f[0], "web") && !strings.HasSuffix(f[0], ":") && strings.Contains(l, "diverged") {
			flagged[f[0]] = true
		}
	}
	want := map[string]bool{"web2": true, "web3": true, "web4": true, "web5": true, "web8": true, "web10": true}
	if !maps.Equal(flagged, want) {
		t.Fatalf("diverged flags %v, want %v:\n%s", flagged, want, out)
	}
	lostAs := func(host, parts, it string) string {
		return host + ": unapplied: it verified " + parts + `, which the server does not hold as current (above its current version, or that number with other bytes), so a signer restore lost ` + it + `; the host refuses the re-made chain until root clears its record (docs/runbooks/signer-install.md "Enrolled hosts and a re-made version")`
	}
	lost := func(host, parts string) string { return lostAs(host, parts, "it") }
	cannot := func(host, parts string) string {
		return host + ": unapplied: it verified " + parts + " but cannot apply it"
	}
	for _, c := range []struct {
		want, not string
	}{
		{lost("web4", "directory v65"), cannot("web4", "directory v65")},
		{lost("web5", "directory v5"), cannot("web5", "directory v5")},
		{cannot("web6", "directory v5"), lost("web6", "directory v5")},
		{cannot("web7", "directory v5"), lost("web7", "directory v5")},
		{lost("web8", "directory v65"), "bundle v2 and directory v65"},
		{cannot("web8", "bundle v2"), lost("web8", "bundle v2")},
		{lostAs("web10", "bundle v3 and directory v5", "them"), cannot("web10", "bundle v3")},
	} {
		if !strings.Contains(out, c.want) || strings.Contains(out, c.not) {
			t.Errorf("want the note %q and not %q:\n%s", c.want, c.not, out)
		}
	}
}

// TestHostStatusUnapplied (PR #76 review F8 (03-08j)): a host that verified
// a version it cannot apply shows it as the unapplied alert, with a note.
func TestHostStatusUnapplied(t *testing.T) {
	ab := strings.Repeat("ab", 32)
	dir := hbStatus(5, 100)
	dir.Unapplied = &heartbeat.Unapplied{Directory: 65}
	both := hbStatus(5, 100)
	both.Unapplied = &heartbeat.Unapplied{Bundle: 3, Directory: 65}
	// The server's current versions are the recorded ones: the hosts are
	// behind, not diverged (PR #78 review).
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 3, "directory": 65, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts": []serverclient.HostStatusRow{
			statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: dir}),
			statusRow("web2", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: both}),
			statusRow("web3", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: hbStatus(5, 100)}),
		},
	})
	code, out, stderr := run(t, "host", "status")
	if code != 0 {
		t.Fatalf("host status: exit %d: %s", code, stderr)
	}
	t.Logf("keyroster host status:\n%s", out)
	row := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 && strings.HasPrefix(f[0], "web") && !strings.HasSuffix(f[0], ":") {
			row[f[0]] = l
		}
	}
	if !strings.Contains(row["web1"], "unapplied: directory v65") || strings.Contains(row["web1"], "bundle v") {
		t.Errorf("web1's alerts %q, want unapplied: directory v65", row["web1"])
	}
	if !strings.Contains(row["web2"], "unapplied: bundle v3, directory v65") {
		t.Errorf("web2's alerts %q, want unapplied: bundle v3, directory v65", row["web2"])
	}
	if strings.Contains(row["web3"], "unapplied") || strings.Contains(out, "web3: unapplied") {
		t.Errorf("web3 has no unapplied state but shows one:\n%s", out)
	}
	if strings.Contains(out, "diverged") {
		t.Errorf("a host behind the current versions is flagged diverged:\n%s", out)
	}
	for _, want := range []string{"web1: unapplied: it verified directory v65 but cannot apply it", "web2: unapplied: it verified bundle v3 and directory v65 but cannot apply it"} {
		if !strings.Contains(out, want) {
			t.Errorf("no note %q:\n%s", want, out)
		}
	}
}

// TestHostStatusAge (PR #72 review C2, C6): host status shows how old each
// host's stored status is beside LAST SEEN, and the server's status_stale
// flag as an alert.
func TestHostStatusAge(t *testing.T) {
	row := statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: hbStatus(5, 100)})
	row.ReceivedAt = time.Now().Add(-40 * time.Minute).UTC().Format(time.RFC3339)
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["status_stale"] = true
	ab := strings.Repeat("ab", 32)
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 1, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts":   []any{m, statusRow("web2", serverclient.HostStateActive, nil)},
	})
	code, out, stderr := run(t, "host", "status")
	if code != 0 {
		t.Fatalf("host status: exit %d: %s", code, stderr)
	}
	t.Logf("keyroster host status:\n%s", out)
	for _, want := range []string{"LAST SEEN  STATUS", "ago    40m ago", "status_stale", "web1: status_stale: its status is 40m old"} {
		if !strings.Contains(out, want) {
			t.Errorf("host status lacks %q:\n%s", want, out)
		}
	}
}

// TestHostStatusCheckFailed (PR #72 review C16): a failed drift check is
// shown as such, with its error, not as "no drift".
func TestHostStatusCheckFailed(t *testing.T) {
	row := statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: hbStatus(5, 100)})
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["heartbeat"].(map[string]any)["status"].(map[string]any)["last_check"].(map[string]any)["error"] =
		"sshd_T_failed: sshd -T exited 255: /etc/ssh/sshd_config line 3: Bad configuration option: PermitRootLogn"
	ab := strings.Repeat("ab", 32)
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 1, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts":   []any{m},
	})
	code, out, stderr := run(t, "host", "status")
	if code != 0 {
		t.Fatalf("host status: exit %d: %s", code, stderr)
	}
	for _, want := range []string{"failed", "check_failed", "web1: check_failed: the last drift check failed: sshd_T_failed: sshd -T exited 255"} {
		if !strings.Contains(out, want) {
			t.Errorf("host status lacks %q:\n%s", want, out)
		}
	}
}

// TestHostStatusHostCerts: keyroster host status prints a host's host
// certificates, skipped key types and host_cert_detail (03-09) through the
// existing escaping and checks; a host without them prints none.
func TestHostStatusHostCerts(t *testing.T) {
	ab := strings.Repeat("ab", 32)
	certs := hbStatus(5, 100)
	certs.HostCerts = []heartbeat.HostCert{
		{KeySHA256: strings.Repeat("01", 32), Type: "ssh-ed25519-cert-v01@openssh.com", Serial: 1793000000000001, ValidBefore: 1795592000, CASHA256: strings.Repeat("02", 32), Served: true},
		{KeySHA256: strings.Repeat("03", 32), Type: "ecdsa-sha2-nistp256-cert-v01@openssh.com", Serial: 1793000000000002, ValidBefore: 1795592000, CASHA256: strings.Repeat("02", 32)},
	}
	certs.HostKeysSkipped = []heartbeat.SkippedKey{{Type: "ssh-rsa", Reason: "rsa_host_key_skipped"}}
	certs.HostCertDetail = "refused:cert_revoked"
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 1, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts": []serverclient.HostStatusRow{
			statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: certs}),
			statusRow("web2", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: hbStatus(5, 100)}),
		},
	})
	code, out, stderr := run(t, "host", "status")
	if code != 0 {
		t.Fatalf("host status: exit %d: %s", code, stderr)
	}
	for _, want := range []string{
		"web1: host certificate ssh-ed25519-cert-v01@openssh.com serial 1793000000000001 for key " + strings.Repeat("01", 32) + ", valid before 2026-11-25T07:33:20Z, served true",
		"web1: host certificate ecdsa-sha2-nistp256-cert-v01@openssh.com serial 1793000000000002", "served false",
		"web1: host key ssh-rsa skipped: rsa_host_key_skipped",
		"host_cert: refused:cert_revoked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "web2: host certificate") || strings.Contains(out, "web2: host key") {
		t.Errorf("web2 has no host certificates but shows some:\n%s", out)
	}

	// A detail outside the grammar never reaches the terminal: the CLI's
	// check refuses the answer.
	bad := hbStatus(5, 100)
	bad.HostCertDetail = "refused:\x1b[2J"
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 1, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts":   []serverclient.HostStatusRow{statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: bad})},
	})
	code, out, stderr = run(t, "host", "status")
	if code == 0 || strings.Contains(out+stderr, "\x1b") || !strings.Contains(stderr, "host_cert_detail") {
		t.Fatalf("a bad host_cert_detail: exit %d, out %q, stderr %q; want a refusal naming the field and no escape byte", code, out, stderr)
	}
}

// TestHostStatusProbeAlert: keyroster host status prints a host's
// probe_detail as the alert "probe: <detail>" beside host_cert:; a host
// without one prints none; a detail outside the grammar, as a hostile
// heartbeat would send it, never reaches the terminal (03-10b).
func TestHostStatusProbeAlert(t *testing.T) {
	ab := strings.Repeat("ab", 32)
	cur := map[string]any{"bundle": 1, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab}
	held := hbStatus(5, 100)
	held.ProbeDetail = "probe_held:shell_not_nologin"
	held.HostCertDetail = "refused:cert_revoked"
	statusEnv(t, map[string]any{
		"current": cur,
		"hosts": []serverclient.HostStatusRow{
			statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: held}),
			statusRow("web2", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: hbStatus(5, 100)}),
		},
	})
	code, out, stderr := run(t, "host", "status")
	if code != 0 {
		t.Fatalf("host status: exit %d: %s", code, stderr)
	}
	if !strings.Contains(out, "host_cert: refused:cert_revoked") || !strings.Contains(out, "probe: probe_held:shell_not_nologin") {
		t.Fatalf("no probe alert beside host_cert:\n%s", out)
	}
	if n := strings.Count(out, "probe: "); n != 1 {
		t.Fatalf("%d probe alerts, want 1 (web2 has no probe_detail):\n%s", n, out)
	}

	bad := hbStatus(5, 100)
	bad.ProbeDetail = "probe_held:\x1b[2J"
	statusEnv(t, map[string]any{
		"current": cur,
		"hosts":   []serverclient.HostStatusRow{statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: bad})},
	})
	code, out, stderr = run(t, "host", "status")
	if code == 0 || strings.Contains(out+stderr, "\x1b") || !strings.Contains(stderr, "probe_detail") {
		t.Fatalf("a bad probe_detail: exit %d, out %q, stderr %q; want a refusal naming the field and no escape byte", code, out, stderr)
	}
}
