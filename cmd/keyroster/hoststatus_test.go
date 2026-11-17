package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
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
	t.Run("unknown_status_field_ignored", func(t *testing.T) {
		// serverclient decodes leniently (json.Unmarshal), so a CLI older
		// than its hosts' agents only lacks a column (03-12d).
		raw, err := json.Marshal(serverclient.HostsStatusAnswer{Current: ans.Current, Hosts: []serverclient.HostStatusRow{
			statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: hbStatus(5, 100)}),
		}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(raw), `"agent_version":`) != 1 {
			t.Fatalf("the answer has no single agent_version field:\n%s", raw)
		}
		raw = []byte(strings.Replace(string(raw), `"agent_version":`, `"a_field_of_a_newer_agent":{"n":1},"agent_version":`, 1))
		statusEnv(t, json.RawMessage(raw))
		code, out, stderr := run(t, "host", "status")
		if code != 0 || !strings.Contains(out, "bundle v1 on 1/1 hosts\n") || !strings.Contains(out, "web1") {
			t.Fatalf("a status with an unknown field: exit %d:\n%s%s", code, out, stderr)
		}
	})
	hostStatusLiveCases(t)
}

// liveFix is a version 3 bundle and the server's current versions that
// name it, for the live count of TestHostStatus (03-12d, T-03-76).
type liveFix struct {
	b   *trust.Bundle
	cur serverclient.HostVersions
}

// newLiveFix builds a bundle whose user CA entries are user, followed by
// one active machine CA.
func newLiveFix(t *testing.T, user ...trust.CAEntry) *liveFix {
	t.Helper()
	cas := append(slices.Clone(user), trust.CAEntry{Role: trust.RoleMachine, Key: trust.FormatKey(htSigner(t).PublicKey()), State: "active", Generation: 1})
	b := &trust.Bundle{Version: 3, CAs: cas}
	doc, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	h := strings.Repeat("ab", 32)
	return &liveFix{b: b, cur: serverclient.HostVersions{Bundle: 3, BundleSHA256: trust.SHA256Hex(doc), Directory: 5, DirectorySHA256: h, KRL: 100, KRLSHA256: h}}
}

// liveUserCA is a user CA entry with a fresh key; a draining one ends at
// end.
func liveUserCA(t *testing.T, state string, gen uint32, end time.Time) trust.CAEntry {
	t.Helper()
	ca := trust.CAEntry{Role: trust.RoleUser, Key: trust.FormatKey(htSigner(t).PublicKey()), State: state, Generation: gen}
	if state == "draining" {
		ca.TrustedUntil = end.UTC().Format(trust.TimeFormat)
	}
	return ca
}

// fileHash is the SHA-256 of the user_ca_keys file of f's bundle at now,
// without the entries skip names (nil: none).
func (f *liveFix) fileHash(t *testing.T, now time.Time, skip func(trust.CAEntry) bool) string {
	t.Helper()
	data, err := trust.UserCAKeysFileExcept(f.b, now, skip)
	if err != nil {
		t.Fatal(err)
	}
	return trust.SHA256Hex(data)
}

// row is an active host on f's bundle whose status lists user_ca_keys
// with sum ("" lists none), changed by edit (nil: unchanged).
func (f *liveFix) row(name, sum string, edit func(s *heartbeat.Status)) serverclient.HostStatusRow {
	st := hbStatus(5, 100)
	st.Bundle = heartbeat.Doc{Version: f.cur.Bundle, SHA256: f.cur.BundleSHA256}
	if sum != "" {
		st.Files = append(st.Files, heartbeat.File{Path: "user_ca_keys", SHA256: sum})
	}
	if edit != nil {
		edit(&st)
	}
	return statusRow(name, serverclient.HostStateActive, &heartbeat.Heartbeat{Status: st})
}

// render is host status's text for rows against f's bundle at now.
func (f *liveFix) render(now time.Time, rows ...serverclient.HostStatusRow) string {
	return renderHostsStatus(&serverclient.HostsStatusAnswer{Current: f.cur, Hosts: rows}, f.b, now)
}

// hostStatusLiveCases are TestHostStatus's leaves for 03-12d: the live
// count of the user CA keys from the hash each host reports (T-03-76,
// T-03-416, T-03-447), the AGENT and BEHIND columns (T-03-448) and the
// draining keys.
func hostStatusLiveCases(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	live := func(n, m int) string { return fmt.Sprintf("user CA keys of bundle v3 live on %d/%d hosts\n", n, m) }
	notConfirmed := func(host, reason string) string {
		return fmt.Sprintf("%s: user CA keys not confirmed: %s; run keyroster-agent check as root on the host\n", host, reason)
	}
	want := func(t *testing.T, out string, wants ...string) {
		t.Helper()
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("host status lacks %q:\n%s", w, out)
			}
		}
	}
	active := func(t *testing.T) *liveFix { return newLiveFix(t, liveUserCA(t, "active", 1, time.Time{})) }
	t.Run("live_count_by_trust_file_hash", func(t *testing.T) {
		f := active(t)
		sum := f.fileHash(t, now, nil)
		out := f.render(now, f.row("web1", sum, nil), f.row("web2", sum, nil), f.row("web3", strings.Repeat("cd", 32), nil))
		want(t, out, "bundle v3 on 3/3 hosts\n", "KRL v100 on 3/3 hosts\n"+live(2, 3))
	})
	t.Run("held_addition_not_live", func(t *testing.T) {
		// T-03-416: a host on the current bundle that holds the next
		// line back reports the file without it.
		f := newLiveFix(t, liveUserCA(t, "active", 1, time.Time{}), liveUserCA(t, "next", 2, time.Time{}))
		held := f.fileHash(t, now, func(ca trust.CAEntry) bool { return ca.Role == trust.RoleUser && ca.State == "next" })
		out := f.render(now, f.row("web1", f.fileHash(t, now, nil), nil), f.row("web2", held, nil))
		want(t, out, "bundle v3 on 2/2 hosts\n", live(1, 2))
	})
	t.Run("pending_swap_not_live", func(t *testing.T) {
		f := active(t)
		sum := f.fileHash(t, now, nil)
		out := f.render(now, f.row("web1", sum, nil), f.row("web2", sum, func(s *heartbeat.Status) {
			s.Pending = &heartbeat.Pending{Step: heartbeat.StepIntermediate, From: 2, To: 4, Intermediate: 3}
		}))
		want(t, out, live(1, 2))
	})
	t.Run("stale_host_not_live", func(t *testing.T) {
		f := active(t)
		sum := f.fileHash(t, now, nil)
		silent, stale, regressed := f.row("web2", sum, nil), f.row("web3", sum, nil), f.row("web4", sum, nil)
		silent.Silent, stale.StatusStale, regressed.SeqRegressed = true, true, true
		want(t, f.render(now, f.row("web1", sum, nil), silent, stale, regressed), live(1, 4))
	})
	for _, c := range []struct {
		name, reason string
		edit         func(s *heartbeat.Status)
	}{
		{"drifted_host_not_live", "its last check reported drift", func(s *heartbeat.Status) { s.LastCheck.Drift = true }},
		{"check_failed_not_live", "its last check failed", func(s *heartbeat.Status) { s.LastCheck.Error = "sshd -T failed" }},
		{"stuck_not_live", "it is stuck", func(s *heartbeat.Status) { s.Stuck = heartbeat.StuckPendingStateUnknown }},
		{"no_check_yet_not_live", "it has not run a drift check yet", func(s *heartbeat.Status) { s.LastCheck = nil }},
		{"check_older_than_apply_not_live", "its last check is older than its last apply", func(s *heartbeat.Status) { s.LastCheck.At = "2026-10-28T11:59:59Z" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The host's own report vouches for its file only when its
			// last check is clean and not older than its last apply.
			f := active(t)
			sum := f.fileHash(t, now, nil)
			out := f.render(now, f.row("web1", sum, nil), f.row("web2", sum, c.edit))
			want(t, out, live(1, 2), notConfirmed("web2", c.reason))
			if strings.Contains(out, "web1: user CA keys") {
				t.Errorf("a clean host got a note:\n%s", out)
			}
		})
	}
	t.Run("no_ca_file_not_live", func(t *testing.T) {
		f := active(t)
		out := f.render(now, f.row("web1", f.fileHash(t, now, nil), nil), f.row("web2", "", nil))
		want(t, out, live(1, 2))
		if strings.Contains(out, "web2: user CA keys") {
			t.Errorf("a host without the file got a note:\n%s", out)
		}
	})
	t.Run("truncated_files_not_confirmable", func(t *testing.T) {
		f := active(t)
		out := f.render(now, f.row("web1", f.fileHash(t, now, nil), nil), f.row("web2", "", func(s *heartbeat.Status) { s.FilesTruncated = true }))
		want(t, out, live(1, 2), "web2: user CA keys not confirmable: its status lists only the first 256 files (files_truncated); run keyroster-agent check as root on the host\n")
	})
	t.Run("bundle_mismatch_not_counted", func(t *testing.T) {
		f := active(t)
		sum := f.fileHash(t, now, nil)
		for _, edit := range []func(v *serverclient.HostVersions){
			func(v *serverclient.HostVersions) { v.Bundle = 4 },
			func(v *serverclient.HostVersions) { v.BundleSHA256 = strings.Repeat("cd", 32) },
		} {
			a := serverclient.HostsStatusAnswer{Current: f.cur, Hosts: []serverclient.HostStatusRow{f.row("web1", sum, nil)}}
			edit(&a.Current)
			out := renderHostsStatus(&a, f.b, now)
			want(t, out, fmt.Sprintf("user CA keys not counted: the trust bundle this client verified (v3) is not the server's current one (v%d)\n", a.Current.Bundle))
			if strings.Contains(out, "live on") {
				t.Errorf("a count against a bundle that is not the server's current one:\n%s", out)
			}
		}
	})
	t.Run("live_count_at_the_clients_clock", func(t *testing.T) {
		f := newLiveFix(t, liveUserCA(t, "draining", 1, now), liveUserCA(t, "active", 2, time.Time{}))
		r := f.row("web1", f.fileHash(t, now, nil), nil)
		want(t, f.render(now, r), live(1, 1))
		want(t, f.render(now.Add(-time.Second), r), live(0, 1))
	})
	t.Run("draining_keys_listed_with_their_end", func(t *testing.T) {
		f := newLiveFix(t, liveUserCA(t, "draining", 1, now), liveUserCA(t, "active", 2, time.Time{}))
		fp, err := keyFP(f.b.CAs[0].Key)
		if err != nil {
			t.Fatal(err)
		}
		end := now.Format(trust.TimeFormat)
		want(t, f.render(now.Add(-time.Second)), "user CA generation 1 "+fp+": draining, trusted until "+end+"\n")
		want(t, f.render(now), "user CA generation 1 "+fp+": drained (ended "+end+")\n")
	})
	header := regexp.MustCompile(`(?m)^HOST +DIRECTORY ENTRY +LAST SEEN +STATUS +BUNDLE +DIRECTORY +KRL +GENERATION +AGENT +DRIFT +LAST APPLY +BEHIND +ALERTS$`)
	t.Run("agent_version_column", func(t *testing.T) {
		f := active(t)
		out := f.render(now, f.row("web1", f.fileHash(t, now, nil), func(s *heartbeat.Status) { s.AgentVersion = "keyroster-agent v0.3.0" }),
			statusRow("web2", serverclient.HostStateActive, nil))
		if !header.MatchString(out) {
			t.Errorf("host status has no AGENT and BEHIND columns:\n%s", out)
		}
		if !regexp.MustCompile(`(?m)^web1 .* 2 +keyroster-agent v0\.3\.0 +no +ok +- +- *$`).MatchString(out) {
			t.Errorf("web1's AGENT cell is not its agent_version:\n%s", out)
		}
		if !regexp.MustCompile(`(?m)^web2 .* 0 +- +- +never applied +- +- *$`).MatchString(out) {
			t.Errorf("a host without a heartbeat has no - in AGENT:\n%s", out)
		}
	})
	t.Run("agent_version_escaped", func(t *testing.T) {
		f := active(t)
		out := f.render(now, f.row("web1", f.fileHash(t, now, nil), func(s *heartbeat.Status) { s.AgentVersion = "keyroster-agent\x1b[31m" }))
		if strings.ContainsRune(out, 0x1b) || !strings.Contains(out, "keyroster-agent?[31m") {
			t.Errorf("an escape byte in agent_version is not shown as ?:\n%q", out)
		}
	})
	t.Run("bundle_behind_column", func(t *testing.T) {
		f := active(t)
		sum := f.fileHash(t, now, nil)
		out := f.render(now,
			f.row("web1", sum, func(s *heartbeat.Status) {
				s.BundleBehind = &heartbeat.BundleBehind{ManifestBundleVersion: 5, AcceptedVersion: 3, Since: now.Add(-3 * time.Hour).Format(trust.TimeFormat), Reason: "not_delivered"}
			}),
			f.row("web2", sum, nil),
			f.row("web3", sum, func(s *heartbeat.Status) {
				s.BundleBehind = &heartbeat.BundleBehind{ManifestBundleVersion: 5, AcceptedVersion: 3, Since: "not a time", Reason: "unknown"}
			}))
		for _, re := range []string{`(?m)^web1 .* ok +v5 for 3h \(not_delivered\) +- *$`, `(?m)^web2 .* ok +- +- *$`, `(?m)^web3 .* ok +v5 \(unknown\) +- *$`} {
			if !regexp.MustCompile(re).MatchString(out) {
				t.Errorf("host status does not match %s:\n%s", re, out)
			}
		}
	})
	t.Run("live_count_end_to_end", func(t *testing.T) {
		// The draining user g1 ends an hour after the wall clock and the
		// client's clock is a second past that end, so only a host status
		// that renders at trustClock() counts web1, whose file lacks g1, and
		// labels g1 drained.
		end := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		clock := end.Add(time.Second)
		prev := trustClock
		trustClock = func() time.Time { return clock }
		t.Cleanup(func() { trustClock = prev })
		e := popHostsEnv(t)
		e.serveRotated(t, 3, func(b *trust.Bundle) {
			rotatedUserCAs(t, "draining", end, "active")(b)
			rotatedHostCAs(t, end, true)(b)
		})
		names := []string{"web1"}
		cas := hostCAsOf(e.bundle)
		sshDir := plantHostTrust(t, e, 2, cas, names)
		before := hostTrustSnapshot(t, sshDir)
		doc, err := e.bundle.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		file, err := trust.UserCAKeysFile(e.bundle, clock)
		if err != nil {
			t.Fatal(err)
		}
		h := strings.Repeat("ab", 32)
		st := hbStatus(5, 100)
		st.Bundle = heartbeat.Doc{Version: 3, SHA256: trust.SHA256Hex(doc)}
		st.Files = append(st.Files, heartbeat.File{Path: "user_ca_keys", SHA256: trust.SHA256Hex(file)})
		b, err := json.Marshal(serverclient.HostsStatusAnswer{
			Current: serverclient.HostVersions{Bundle: 3, BundleSHA256: trust.SHA256Hex(doc), Directory: 5, DirectorySHA256: h, KRL: 100, KRLSHA256: h},
			Hosts:   []serverclient.HostStatusRow{statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: st})},
		})
		if err != nil {
			t.Fatal(err)
		}
		var called bool
		e.recordCall(http.MethodGet, serverclient.AdminHostsStatusPath, &called, string(b), http.StatusOK)
		var g1 trust.CAEntry
		for _, ca := range e.bundle.CAs {
			if ca.Role == trust.RoleUser && ca.Generation == 1 {
				g1 = ca
			}
		}
		fp, err := keyFP(g1.Key)
		if err != nil {
			t.Fatal(err)
		}
		code, out, stderr := run(t, "host", "status")
		if code != 0 {
			t.Fatalf("host status: exit %d:\n%s%s", code, out, stderr)
		}
		want(t, out, live(1, 1), "user CA generation 1 "+fp+": drained (ended "+end.Format(trust.TimeFormat)+")\n")
		requireNarrowed(t, sshDir, before, caLineFor(cas[0], names), stderr)
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
