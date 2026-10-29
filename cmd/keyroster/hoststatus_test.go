package main

import (
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
	ans := serverclient.HostsStatusAnswer{Current: serverclient.HostVersions{Bundle: 1, Directory: 5, KRL: 100}, Hosts: []serverclient.HostStatusRow{
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

// TestHostForgetHostGone is carry-over b on the CLI: the refusal names
// --host-gone, and --host-gone is sent, printed before the request and
// after it.
func TestHostForgetHostGone(t *testing.T) {
	_, key := writeEntryKey(t, "web1")
	forgotten, err := json.Marshal(serverclient.ForgetHostAnswer{Forgotten: []serverclient.PendingHost{{ExpectedName: "web1", IdentitySPKISHA256: strings.Repeat("00", 32),
		HostKeys: []string{key}, Facts: enroll.Facts{OSID: "debian", Hostname: "web1"}, EnrolledAt: "2026-10-28T12:00:00Z"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("removal_not_applied_refused", func(t *testing.T) {
		e := popHostsEnv(t)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminForgetHostPath, &called, `{"error":"host_removal_not_applied"}`, http.StatusConflict)
		code, _, stderr := run(t, "host", "forget", "web1")
		if code == 0 || !strings.Contains(stderr, "host_removal_not_applied") || !strings.Contains(stderr, "--host-gone") {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		var req serverclient.ForgetHostRequest
		if json.Unmarshal(e.lastPost, &req) != nil || req.HostGone {
			t.Fatalf("the request %s", e.lastPost)
		}
	})
	t.Run("host_gone_sent_and_printed", func(t *testing.T) {
		e := popHostsEnv(t)
		var called bool
		e.recordCall(http.MethodPost, serverclient.AdminForgetHostPath, &called, string(forgotten), http.StatusOK)
		code, out, stderr := run(t, "host", "forget", "web1", "--host-gone")
		if code != 0 || !strings.Contains(stderr, "host forget --host-gone: forgetting web1 without its confirmation") || !strings.Contains(out, "Forgotten with --host-gone") {
			t.Fatalf("exit %d:\n%s%s", code, out, stderr)
		}
		var req serverclient.ForgetHostRequest
		if json.Unmarshal(e.lastPost, &req) != nil || !req.HostGone || req.ExpectedName != "web1" {
			t.Fatalf("the request %s", e.lastPost)
		}
	})
}

// TestServedLine (PR #72 review C14): a re-keyed host is shown as one to
// re-enroll, in host pending and host status alike.
func TestServedLine(t *testing.T) {
	for state, want := range map[string]string{
		serverclient.HostStateKeysChanged: "host_keys_changed (re-enroll), served until forget",
		serverclient.HostStateRemoved:     "removed, served until forget",
		serverclient.HostStateDisabled:    "disabled, served until forget",
	} {
		if got := servedLine(state); got != want {
			t.Errorf("servedLine(%s) = %q, want %q", state, got, want)
		}
	}
}
