package server

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// testStatus is a valid status of a host that applied generation 3 with
// directory dir and KRL 100, seq seq.
func testHBStatus(seq, dir uint64) heartbeat.Status {
	h := strings.Repeat("ab", 32)
	return heartbeat.Status{
		AgentVersion: "keyroster-agent (devel)",
		Bundle:       heartbeat.Doc{Version: 1, SHA256: h}, Policy: heartbeat.Doc{Version: 1, SHA256: h},
		Directory:   heartbeat.Doc{Version: dir, SHA256: h},
		KRL:         heartbeat.KRL{Version: 100, SHA256: h, IssuedAt: "2026-10-28T12:00:00Z"},
		Generation:  3,
		Files:       []heartbeat.File{{Path: "principals/deploy", SHA256: h}, {Path: "revoked.krl", SHA256: h}, {Path: "user_ca_keys", SHA256: h}},
		SSHDVersion: "OpenSSH_10.5p1, OpenSSL 3.5.0",
		LastApply:   &heartbeat.LastApply{At: "2026-10-28T12:00:00Z", Result: heartbeat.ResultOK},
		LastCheck:   &heartbeat.LastCheck{At: "2026-10-28T12:00:00Z"},
		Seq:         seq,
	}
}

// hbBody encodes h as the fetcher does.
func hbBody(t *testing.T, h heartbeat.Heartbeat) []byte {
	t.Helper()
	b, err := trust.CanonicalJSON(h)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// heartbeat posts h as id.
func (e *agentEnv) heartbeat(t *testing.T, id agentID, h heartbeat.Heartbeat) *httptest.ResponseRecorder {
	t.Helper()
	return e.agentDo(t, id, http.MethodPost, serverclient.AgentHeartbeatPath, hbBody(t, h))
}

// hostsStatus GETs hosts/status as the admin.
func (e *agentEnv) hostsStatus(t *testing.T) serverclient.HostsStatusAnswer {
	t.Helper()
	rec := e.adminDo(t, http.MethodGet, serverclient.AdminHostsStatusPath, nil)
	var ans serverclient.HostsStatusAnswer
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ans) != nil {
		t.Fatalf("hosts/status: %d %s", rec.Code, rec.Body.String())
	}
	return ans
}

// polledAgent is an approved agent that got its first state.
func polledAgent(t *testing.T) (*agentEnv, agentID) {
	t.Helper()
	e := newAgentEnv(t, true)
	id, _ := e.approvedAgent(t)
	if rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusOK {
		t.Fatalf("the first state: %d %s", rec.Code, rec.Body.String())
	}
	return e, id
}

func heartbeatField(rec *httptest.ResponseRecorder) string {
	var r serverclient.HeartbeatRefusal
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if r.Error != serverclient.AgentErrHeartbeatField {
		return ""
	}
	return r.Field
}

// TestHeartbeat covers the heartbeat route and hosts/status (03-08,
// AGENT-07): storage by seq, every field rule, the silent and clock_skew
// boundaries, and the empty row.
func TestHeartbeat(t *testing.T) {
	t.Run("stored_and_shown", func(t *testing.T) {
		e, id := polledAgent(t)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 1)}); rec.Code != http.StatusOK {
			t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		ans := e.hostsStatus(t)
		if len(ans.Hosts) != 1 || ans.Hosts[0].Heartbeat == nil || ans.Hosts[0].Heartbeat.Status.Seq != 10 || ans.Hosts[0].Name != "web1" ||
			ans.Hosts[0].State != serverclient.HostStateActive || ans.Current.Directory != 1 || ans.Current.KRL != 100 || ans.Current.Bundle == 0 {
			t.Fatalf("hosts/status: %+v", ans)
		}
	})
	t.Run("never_applied_row", func(t *testing.T) {
		e, id := polledAgent(t)
		ans := e.hostsStatus(t)
		if len(ans.Hosts) != 1 || !ans.Hosts[0].NeverApplied || ans.Hosts[0].Heartbeat != nil || ans.Hosts[0].Silent {
			t.Fatalf("an approved host with no heartbeat: %+v", ans.Hosts)
		}
		s := heartbeat.Status{AgentVersion: "keyroster-agent (devel)", Files: []heartbeat.File{}, Seq: 1}
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s}); rec.Code != http.StatusOK {
			t.Fatalf("a never-applied heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		ans = e.hostsStatus(t)
		h := ans.Hosts[0]
		if !h.NeverApplied || h.Heartbeat == nil || h.Heartbeat.Status.Generation != 0 || h.Heartbeat.Status.Directory.Version != 0 || h.Heartbeat.Status.LastApply != nil {
			t.Fatalf("a never-applied host: %+v", h)
		}
	})
	t.Run("lower_seq_refused", func(t *testing.T) {
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 1)})
		old := testHBStatus(9, 1)
		old.LastApply.Result = heartbeat.ResultError
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: old}); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrStaleHeartbeat {
			t.Fatalf("a lower seq: %d %s", rec.Code, rec.Body.String())
		}
		if got := e.hostsStatus(t).Hosts[0].Heartbeat.Status; got.Seq != 10 || got.LastApply.Result != heartbeat.ResultOK {
			t.Fatalf("a lower seq replaced the stored heartbeat: %+v", got)
		}
	})
	t.Run("equal_seq_refused", func(t *testing.T) {
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 1)})
		same := testHBStatus(10, 1)
		same.LastApply.Result = heartbeat.ResultRefused
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: same}); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrStaleHeartbeat {
			t.Fatalf("an equal seq: %d %s", rec.Code, rec.Body.String())
		}
		if got := e.hostsStatus(t).Hosts[0].Heartbeat.Status.LastApply.Result; got != heartbeat.ResultOK {
			t.Fatalf("an equal seq replaced the stored heartbeat: result %s", got)
		}
	})
	t.Run("state_reset_seq_still_accepted", func(t *testing.T) {
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(uint64(t0.UnixMicro())+500, 1)})
		// The applier's state directory was wiped: its next status starts
		// from the clock (seq = now in microseconds), above the stored one.
		later := uint64(t0.Add(time.Minute).UnixMicro())
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(later, 1)}); rec.Code != http.StatusOK {
			t.Fatalf("a reset applier's heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		if got := e.hostsStatus(t).Hosts[0].Heartbeat.Status.Seq; got != later {
			t.Fatalf("seq %d, want %d", got, later)
		}
	})
	t.Run("files_sorted_by_path", func(t *testing.T) {
		e, id := polledAgent(t)
		s := testHBStatus(1, 1)
		s.Files[0], s.Files[1] = s.Files[1], s.Files[0]
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s}); rec.Code != http.StatusBadRequest || heartbeatField(rec) != "files[1].path" {
			t.Fatalf("an unsorted file list: %d %s", rec.Code, rec.Body.String())
		}
		s = testHBStatus(1, 1)
		s.Files[1] = s.Files[0]
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s}); rec.Code != http.StatusBadRequest || heartbeatField(rec) != "files[1].path" {
			t.Fatalf("a repeated path: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("oversize_heartbeat_refused", func(t *testing.T) {
		e, id := polledAgent(t)
		body := hbBody(t, heartbeat.Heartbeat{Status: testHBStatus(1, 1)})
		big := append(body[:len(body)-2:len(body)-2], []byte(strings.Repeat(" ", heartbeat.MaxBody)+"}\n")...)
		if rec := e.agentDo(t, id, http.MethodPost, serverclient.AgentHeartbeatPath, big); rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("a body above 64 KiB: %d %s", rec.Code, rec.Body.String())
		}
		if ans := e.hostsStatus(t); ans.Hosts[0].Heartbeat != nil {
			t.Fatal("an oversize heartbeat was stored")
		}
	})
	t.Run("detail_field_validated", func(t *testing.T) {
		e, id := polledAgent(t)
		for i, bad := range []string{"Probe:negative_refused", "probe negative", "probe:\x1b[31m", "probe:negative:refused", strings.Repeat("a", 65)} {
			s := testHBStatus(uint64(i+1), 1)
			s.LastApply.Detail = bad
			if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s}); rec.Code != http.StatusBadRequest || heartbeatField(rec) != "last_apply.detail" {
				t.Fatalf("detail %q: %d %s", bad, rec.Code, rec.Body.String())
			}
		}
		s := testHBStatus(20, 1)
		s.LastApply.Detail = "probe:negative_refused"
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s}); rec.Code != http.StatusOK {
			t.Fatalf("detail probe:negative_refused: %d %s", rec.Code, rec.Body.String())
		}
		if got := e.hostsStatus(t).Hosts[0].Heartbeat.Status.LastApply.Detail; got != "probe:negative_refused" {
			t.Fatalf("detail %q in hosts/status", got)
		}
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(21, 1)}); rec.Code != http.StatusOK {
			t.Fatalf("no detail: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("stuck_shown_in_host_status", func(t *testing.T) {
		e, id := polledAgent(t)
		s := testHBStatus(1, 1)
		s.Stuck = "pending_state_unknowN"
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s}); rec.Code != http.StatusBadRequest || heartbeatField(rec) != "stuck" {
			t.Fatalf("an unknown stuck value: %d %s", rec.Code, rec.Body.String())
		}
		s.Stuck = heartbeat.StuckPendingStateUnknown
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s}); rec.Code != http.StatusOK {
			t.Fatalf("stuck: %d %s", rec.Code, rec.Body.String())
		}
		if got := e.hostsStatus(t).Hosts[0].Heartbeat.Status.Stuck; got != heartbeat.StuckPendingStateUnknown {
			t.Fatalf("stuck %q in hosts/status", got)
		}
	})
	t.Run("silent_boundary_180_not_181", func(t *testing.T) {
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(1, 1)})
		seen := e.clock.Now()
		e.clock.set(seen.Add(180 * time.Second))
		if h := e.hostsStatus(t).Hosts[0]; h.Silent {
			t.Fatalf("a host last seen 180 s ago is silent: %+v", h)
		}
		e.clock.set(seen.Add(181 * time.Second))
		if h := e.hostsStatus(t).Hosts[0]; !h.Silent {
			t.Fatalf("a host last seen 181 s ago is not silent: %+v", h)
		}
		// Any authenticated request, a stale heartbeat included, is the
		// host being seen (owner decision D-2).
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(1, 1)}); rec.Code != http.StatusConflict {
			t.Fatalf("the repeated heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		if h := e.hostsStatus(t).Hosts[0]; h.Silent {
			t.Fatalf("a host that just posted is silent: %+v", h)
		}
	})
	t.Run("clock_skew_boundary_300_not_301", func(t *testing.T) {
		e, id := polledAgent(t)
		for i, c := range []struct {
			off  int64
			skew bool
		}{{300, false}, {-300, false}, {301, true}, {-301, true}, {0, false}} {
			if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(uint64(i+1), 1), ClockOffsetS: c.off}); rec.Code != http.StatusOK {
				t.Fatalf("offset %d: %d %s", c.off, rec.Code, rec.Body.String())
			}
			if got := e.hostsStatus(t).Hosts[0].ClockSkew; got != c.skew {
				t.Fatalf("clock_offset_s %d: clock_skew %v, want %v", c.off, got, c.skew)
			}
		}
	})
	for _, c := range []struct {
		name, field string
		mut         func(s *heartbeat.Status)
	}{
		{"escape_sequence_in_sshd_version_refused", "sshd_version", func(s *heartbeat.Status) { s.SSHDVersion = "OpenSSH_10.5p1\x1b]0;owned\x07" }},
		{"file_path_traversal_refused", "files[0].path", func(s *heartbeat.Status) { s.Files[0].Path = "../x" }},
		{"file_list_over_256_refused", "files", func(s *heartbeat.Status) {
			s.Files = nil
			for i := range heartbeat.MaxFiles + 1 {
				s.Files = append(s.Files, heartbeat.File{Path: fmt.Sprintf("principals/u%04d", i), SHA256: strings.Repeat("cd", 32)})
			}
		}},
		{"unknown_result_refused", "last_apply.result", func(s *heartbeat.Status) { s.LastApply.Result = "fine" }},
		{"hash_not_hex_refused", "bundle.sha256", func(s *heartbeat.Status) { s.Bundle.SHA256 = strings.Repeat("AB", 32) }},
		{"free_text_over_512_refused", "last_apply.error", func(s *heartbeat.Status) { s.LastApply.Error = strings.Repeat("x", 513) }},
		{"unknown_pending_step_refused", "pending.step", func(s *heartbeat.Status) { s.Pending = &heartbeat.Pending{Step: "half"} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, id := polledAgent(t)
			s := testHBStatus(1, 1)
			c.mut(&s)
			rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s})
			if rec.Code != http.StatusBadRequest || heartbeatField(rec) != c.field {
				t.Fatalf("%d %s, want 400 %s naming %s", rec.Code, rec.Body.String(), serverclient.AgentErrHeartbeatField, c.field)
			}
			if e.hostsStatus(t).Hosts[0].Heartbeat != nil {
				t.Fatal("a refused heartbeat was stored")
			}
		})
	}
	t.Run("free_text_at_512_accepted", func(t *testing.T) {
		e, id := polledAgent(t)
		s := testHBStatus(1, 1)
		s.LastApply.Error = strings.Repeat("x", 512)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s}); rec.Code != http.StatusOK {
			t.Fatalf("512 bytes: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("not_canonical_refused", func(t *testing.T) {
		e, id := polledAgent(t)
		body := hbBody(t, heartbeat.Heartbeat{Status: testHBStatus(1, 1)})
		body = append([]byte(" "), body...)
		if rec := e.agentDo(t, id, http.MethodPost, serverclient.AgentHeartbeatPath, body); rec.Code != http.StatusBadRequest || heartbeatField(rec) != "body" {
			t.Fatalf("a non-canonical body: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("pending_agent_not_approved", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, hosts := newAgentID(t), hostSigners(t, 1)
		if rec := e.enroll(t, id, e.mustMint(t, "web1", 0).Token, hosts); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll: %d", rec.Code)
		}
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(1, 1)}); rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrNotApproved {
			t.Fatalf("a pending agent's heartbeat: %d %s", rec.Code, rec.Body.String())
		}
	})
}

// forgetGone posts keyroster host forget name --host-gone.
func (e *agentEnv) forgetGone(t *testing.T, name string) *httptest.ResponseRecorder {
	t.Helper()
	return e.forgetName(t, name, true)
}

// TestHostForgetWaitsForRemoval is owner decision 2026-10-28 (carry-over
// b): host forget waits until the host reported that it applied the
// directory version that removed it (host_removal_not_applied), unless
// the admin passes --host-gone, which is logged.
func TestHostForgetWaitsForRemoval(t *testing.T) {
	removed := func(t *testing.T) (*agentEnv, agentID, uint64) {
		t.Helper()
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(1, 1)})
		return e, id, e.installDir(t)
	}
	t.Run("refused_before_the_host_requested_again", func(t *testing.T) {
		e, _, _ := removed(t)
		if rec := e.forget(t, "web1"); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrRemovalNotApplied {
			t.Fatalf("forget before the host saw its removal: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("refused_while_the_heartbeat_shows_an_older_directory", func(t *testing.T) {
		e, id, _ := removed(t)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbRemovedAt(t, 2, 1)}); rec.Code != http.StatusOK {
			t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		if rec := e.forget(t, "web1"); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrRemovalNotApplied {
			t.Fatalf("forget while the host reports directory 1: %d %s", rec.Code, rec.Body.String())
		}
		if agents, _ := e.s.db.ListAgents(t.Context()); len(agents) != 1 {
			t.Fatalf("%d agents after the refusal", len(agents))
		}
	})
	t.Run("accepted_once_the_removal_is_applied", func(t *testing.T) {
		e, id, removal := removed(t)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbRemovedAt(t, 2, removal)}); rec.Code != http.StatusOK {
			t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		if rec := e.forget(t, "web1"); rec.Code != http.StatusOK {
			t.Fatalf("forget after the removal applied: %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(e.log.String(), "--host-gone") {
			t.Fatal("a confirmed forget logged --host-gone")
		}
	})
	t.Run("removal_version_is_the_first_unapproving_one", func(t *testing.T) {
		e, id, removal := removed(t)
		// The host polls under the removal, then one more version: the
		// host's heartbeat at the removal version is enough.
		e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		e.installDir(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbRemovedAt(t, 2, removal)})
		if rec := e.forget(t, "web1"); rec.Code != http.StatusOK {
			t.Fatalf("forget: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("readded_host_clears_the_removal_version", func(t *testing.T) {
		e, id, removal := removed(t)
		e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		agents, _ := e.s.db.ListAgents(t.Context())
		if agents[0].RemovedDirVersion != removal {
			t.Fatalf("removed_dir_version %d, want %d", agents[0].RemovedDirVersion, removal)
		}
		e.installDir(t, e.webEntry(t))
		e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		agents, _ = e.s.db.ListAgents(t.Context())
		if agents[0].RemovedDirVersion != 0 {
			t.Fatalf("removed_dir_version %d after the re-approval, want 0", agents[0].RemovedDirVersion)
		}
	})
	t.Run("disabled_first_then_removed_waits_for_the_removal", func(t *testing.T) {
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(1, 1)})
		h := e.webEntry(t)
		h.Status = directory.StatusDisabled
		disabled := e.installDir(t, h)
		e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: asEmptied(e.hbAt(t, 2, disabled), "host_disabled")})
		removal := e.installDir(t)
		if rec := e.forget(t, "web1"); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrRemovalNotApplied {
			t.Fatalf("forget with the disable applied but not the removal: %d %s", rec.Code, rec.Body.String())
		}
		e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbRemovedAt(t, 3, removal)})
		if rec := e.forget(t, "web1"); rec.Code != http.StatusOK {
			t.Fatalf("forget after the removal applied: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("host_gone_overrides_and_is_logged", func(t *testing.T) {
		e, _, _ := removed(t)
		if rec := e.forgetGone(t, "web1"); rec.Code != http.StatusOK {
			t.Fatalf("forget --host-gone: %d %s", rec.Code, rec.Body.String())
		}
		if !strings.Contains(e.log.String(), "agent forgotten with --host-gone") {
			t.Fatalf("--host-gone not logged:\n%s", e.log.String())
		}
	})
	t.Run("host_gone_does_not_override_host_in_directory", func(t *testing.T) {
		e, _ := polledAgent(t)
		if rec := e.forgetGone(t, "web1"); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrHostInDirectory {
			t.Fatalf("forget --host-gone of an active host: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("never_approved_agent_needs_no_heartbeat", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, hosts := newAgentID(t), hostSigners(t, 1)
		if rec := e.enroll(t, id, e.mustMint(t, "web1", 0).Token, hosts); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll: %d", rec.Code)
		}
		if rec := e.forget(t, "web1"); rec.Code != http.StatusOK {
			t.Fatalf("forget a never-approved agent: %d %s", rec.Code, rec.Body.String())
		}
	})
}

// webEntry is the directory entry of the agent approvedAgent enrolled.
func (e *agentEnv) webEntry(t *testing.T) directory.Host {
	t.Helper()
	agents, err := e.s.db.ListAgents(t.Context())
	if err != nil || len(agents) != 1 {
		t.Fatalf("agents: %v %d", err, len(agents))
	}
	return directory.Host{Name: "web1", HostGroup: "lab", Keys: agents[0].HostKeys, Principals: []string{"web1"}, Status: directory.StatusActive}
}

// TestServedHostsNeverPending is carry-over a (owner decision
// 2026-10-28): an approved-once agent that the directory no longer
// approves is listed as served with its state, never as pending, in host
// pending and in hosts/status.
func TestServedHostsNeverPending(t *testing.T) {
	pending := func(t *testing.T, e *agentEnv) serverclient.PendingHostsAnswer {
		t.Helper()
		rec := e.adminDo(t, http.MethodGet, serverclient.AdminPendingHostsPath, nil)
		var ans serverclient.PendingHostsAnswer
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ans) != nil {
			t.Fatalf("pending: %d %s", rec.Code, rec.Body.String())
		}
		return ans
	}
	for _, c := range []struct {
		name, state string
		dir         func(e *agentEnv, h directory.Host) []directory.Host
	}{
		{"removed", serverclient.HostStateRemoved, func(*agentEnv, directory.Host) []directory.Host { return nil }},
		{"disabled", serverclient.HostStateDisabled, func(_ *agentEnv, h directory.Host) []directory.Host {
			h.Status = directory.StatusDisabled
			return []directory.Host{h}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, _ := polledAgent(t)
			e.installDir(t, c.dir(e, e.webEntry(t))...)
			ans := pending(t, e)
			if len(ans.Hosts) != 0 || len(ans.Served) != 1 || ans.Served[0].State != c.state || ans.Served[0].ExpectedName != "web1" {
				t.Fatalf("host pending after %s: %+v", c.name, ans)
			}
			st := e.hostsStatus(t)
			if len(st.Hosts) != 1 || st.Hosts[0].State != c.state {
				t.Fatalf("hosts/status after %s: %+v", c.name, st.Hosts)
			}
		})
	}
	t.Run("never_polled_is_still_pending", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, hosts := newAgentID(t), hostSigners(t, 1)
		e.enroll(t, id, e.mustMint(t, "web1", 0).Token, hosts)
		if ans := pending(t, e); len(ans.Hosts) != 1 || len(ans.Served) != 0 {
			t.Fatalf("a pending agent: %+v", ans)
		}
		if st := e.hostsStatus(t); len(st.Hosts) != 0 {
			t.Fatalf("hosts/status lists a pending agent: %+v", st.Hosts)
		}
	})
}

// newIdentityKey is a fresh Ed25519 identity, its certificate and SPKI.
func newIdentityKey(t *testing.T) (agentID, []byte) {
	t.Helper()
	id := newAgentID(t)
	return id, id.cert.RawSubjectPublicKeyInfo
}

// TestIdentityRotation (03-08, AGENT-02, T-03-55): the current identity
// signs the new SPKI; afterwards the old certificate is unknown and the
// new one is the agent; a signature by any other key, the same key and a
// non-Ed25519 key are refused.
func TestIdentityRotation(t *testing.T) {
	rotate := func(t *testing.T, e *agentEnv, as agentID, signer ed25519.PrivateKey, spki []byte) *httptest.ResponseRecorder {
		t.Helper()
		b, err := json.Marshal(serverclient.AgentIdentityRequest{NewSPKI: spki, Sig: ed25519.Sign(signer, serverclient.AgentIdentityMessage(spki))})
		if err != nil {
			t.Fatal(err)
		}
		return e.agentDo(t, as, http.MethodPost, serverclient.AgentIdentityPath, b)
	}
	t.Run("rotated", func(t *testing.T) {
		e, old := polledAgent(t)
		nid, spki := newIdentityKey(t)
		if rec := rotate(t, e, old, old.key, spki); rec.Code != http.StatusOK {
			t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
		}
		if rec := e.agentDo(t, old, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrUnknown {
			t.Fatalf("the old certificate after the rotation: %d %s", rec.Code, rec.Body.String())
		}
		if rec := e.agentDo(t, nid, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusOK {
			t.Fatalf("the new certificate: %d %s", rec.Code, rec.Body.String())
		}
		sum := sha256.Sum256(spki)
		if st := e.hostsStatus(t); st.Hosts[0].IdentitySPKISHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("hosts/status names identity %s", st.Hosts[0].IdentitySPKISHA256)
		}
	})
	t.Run("signature_by_another_key_refused", func(t *testing.T) {
		e, old := polledAgent(t)
		other, spki := newIdentityKey(t)
		if rec := rotate(t, e, old, other.key, spki); rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrIdentitySig {
			t.Fatalf("signed by the new key: %d %s", rec.Code, rec.Body.String())
		}
		if rec := e.agentDo(t, old, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusOK {
			t.Fatalf("the old certificate after a refused rotation: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("signature_over_another_spki_refused", func(t *testing.T) {
		e, old := polledAgent(t)
		_, spki := newIdentityKey(t)
		_, other := newIdentityKey(t)
		b, _ := json.Marshal(serverclient.AgentIdentityRequest{NewSPKI: spki, Sig: ed25519.Sign(old.key, serverclient.AgentIdentityMessage(other))})
		if rec := e.agentDo(t, old, http.MethodPost, serverclient.AgentIdentityPath, b); rec.Code != http.StatusForbidden {
			t.Fatalf("a signature over another SPKI: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("same_key_refused", func(t *testing.T) {
		e, old := polledAgent(t)
		if rec := rotate(t, e, old, old.key, old.cert.RawSubjectPublicKeyInfo); rec.Code != http.StatusForbidden {
			t.Fatalf("a rotation to the same key: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("non_ed25519_refused", func(t *testing.T) {
		e, old := polledAgent(t)
		spki := ecdsaSPKI(t)
		if rec := rotate(t, e, old, old.key, spki); rec.Code != http.StatusForbidden {
			t.Fatalf("an ECDSA identity: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("another_agents_identity_refused", func(t *testing.T) {
		e, old := polledAgent(t)
		other, hosts := newAgentID(t), hostSigners(t, 1)
		if rec := e.enroll(t, other, e.mustMint(t, "web2", 0).Token, hosts); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll web2: %d", rec.Code)
		}
		if rec := rotate(t, e, old, old.key, other.cert.RawSubjectPublicKeyInfo); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrIdentityInUse {
			t.Fatalf("a rotation to another agent's identity: %d %s", rec.Code, rec.Body.String())
		}
	})
}

// ecdsaSPKI is a P-256 SubjectPublicKeyInfo.
func ecdsaSPKI(t *testing.T) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"}, NotBefore: t0, NotAfter: t0.Add(time.Hour)}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c.RawSubjectPublicKeyInfo
}
