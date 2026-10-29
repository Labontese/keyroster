package main

import (
	"bytes"
	"encoding/json"
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
		if code != 0 || !strings.Contains(stderr, "host forget --host-gone: forgetting web1 without its confirmation") || !strings.Contains(out, "Forgotten with --host-gone") ||
			!strings.Contains(out, "override: --host-gone") {
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
// flagged diverged.
func TestHostStatusDiverged(t *testing.T) {
	ab, cd := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	same := hbStatus(5, 100)
	other := hbStatus(5, 100)
	other.Directory.SHA256 = cd
	ahead := hbStatus(6, 100)
	ahead.Directory.SHA256 = cd
	// Built as JSON: the current versions carry their SHA-256.
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 1, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts": []serverclient.HostStatusRow{
			statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: same}),
			statusRow("web2", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: other}),
			statusRow("web3", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: ahead}),
		},
	})
	code, out, stderr := run(t, "host", "status")
	if code != 0 {
		t.Fatalf("host status: exit %d: %s", code, stderr)
	}
	t.Logf("keyroster host status:\n%s", out)
	if !strings.Contains(out, "directory v5 on 1/3 hosts\n") || !strings.Contains(out, "KRL v100 on 3/3 hosts\n") {
		t.Fatalf("diverged hosts counted as converged:\n%s", out)
	}
	flagged := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 && strings.HasPrefix(f[0], "web") && strings.HasSuffix(l, "diverged") {
			flagged[f[0]] = true
		}
	}
	if !flagged["web2"] || !flagged["web3"] || flagged["web1"] {
		t.Fatalf("diverged flags %v, want web2 and web3:\n%s", flagged, out)
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
