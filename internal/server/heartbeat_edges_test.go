package server

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
)

// TestHeartbeatAfterForget (PR #72 review C1): a forgotten agent's
// request can never write for the agents row that reuses its ID.
func TestHeartbeatAfterForget(t *testing.T) {
	t.Run("in_flight_heartbeat_not_inherited", func(t *testing.T) {
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(1, 1)})
		e.installDir(t)
		agents, _ := e.s.db.ListAgents(t.Context())
		oldID := agents[0].ID

		// The heartbeat's headers are in and requireAgent has passed; the
		// body is still arriving when the admin forgets the host.
		body := hbBody(t, heartbeat.Heartbeat{Status: testHBStatus(2, 1)})
		pr, pw := io.Pipe()
		req := httptest.NewRequest(http.MethodPost, "https://"+testRPID+":8443"+serverclient.AgentHeartbeatPath, pr)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{id.cert}}
		rec := httptest.NewRecorder()
		done := make(chan struct{})
		go func() {
			defer close(done)
			e.s.AgentHandler().ServeHTTP(rec, req)
		}()
		// io.Pipe: this write returns once the handler reads the body.
		if _, err := pw.Write(body[:1]); err != nil {
			t.Fatal(err)
		}
		if rec := e.forgetGone(t, "web1"); rec.Code != http.StatusOK {
			t.Fatalf("forget --host-gone: %d %s", rec.Code, rec.Body.String())
		}
		if _, err := pw.Write(body[1:]); err != nil {
			t.Fatal(err)
		}
		_ = pw.Close()
		<-done
		if rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrUnknown {
			t.Fatalf("the forgotten agent's heartbeat: %d %s", rec.Code, rec.Body.String())
		}

		// A new host enrolls and gets the freed row ID (no AUTOINCREMENT).
		id2, hosts := newAgentID(t), hostSigners(t, 1)
		if rec := e.enroll(t, id2, e.mustMint(t, "web2", 0).Token, hosts); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
		}
		e.installDir(t, hostEntry("web2", hosts))
		if rec := e.agentDo(t, id2, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusOK {
			t.Fatalf("the new agent's state: %d %s", rec.Code, rec.Body.String())
		}
		agents, _ = e.s.db.ListAgents(t.Context())
		if len(agents) != 1 || agents[0].ID != oldID {
			t.Fatalf("agents %+v; the test needs the new agent on the forgotten one's ID %d", agents, oldID)
		}
		st := e.hostsStatus(t)
		if len(st.Hosts) != 1 || st.Hosts[0].Heartbeat != nil || !st.Hosts[0].NeverApplied {
			t.Fatalf("the new host inherited a heartbeat: %+v", st.Hosts)
		}
		if rec := e.heartbeat(t, id2, heartbeat.Heartbeat{Status: testHBStatus(5, 1)}); rec.Code != http.StatusOK {
			t.Fatalf("the new host's own heartbeat: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("row_gone_after_lookup_refused", func(t *testing.T) {
		e, id := polledAgent(t)
		agents, _ := e.s.db.ListAgents(t.Context())
		e.s.afterAgentLookup = func() {
			if err := e.s.db.DeleteAgent(t.Context(), agents[0].ID); err != nil {
				t.Error(err)
			}
		}
		rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		if rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrUnknown {
			t.Fatalf("a request whose agents row went after the lookup: %d %s", rec.Code, rec.Body.String())
		}
	})
}

// rawHosts GETs hosts/status as the admin and returns its rows as JSON
// objects, so a test can read a field by its wire name.
func (e *agentEnv) rawHosts(t *testing.T) []map[string]any {
	t.Helper()
	rec := e.adminDo(t, http.MethodGet, serverclient.AdminHostsStatusPath, nil)
	var ans struct {
		Hosts []map[string]any `json:"hosts"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ans) != nil {
		t.Fatalf("hosts/status: %d %s", rec.Code, rec.Body.String())
	}
	return ans.Hosts
}

// TestHeartbeatSeq is owner decision D-R2 (PR #72 review C3, C11): a seq
// more than an hour beyond the server's clock is refused and changes
// nothing; a lower seq is still refused, logged and flagged; the clock
// offset of every heartbeat is kept, stale ones included.
func TestHeartbeatSeq(t *testing.T) {
	nowUS := func(e *agentEnv) uint64 { return uint64(e.clock.Now().UnixMicro()) } //nolint:gosec // G115: the test clock is after 1970
	t.Run("future_seq_refused", func(t *testing.T) {
		e, id := polledAgent(t)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 1)}); rec.Code != http.StatusOK {
			t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		for _, seq := range []uint64{math.MaxInt64, nowUS(e) + uint64(2*time.Hour/time.Microsecond), nowUS(e) + uint64(time.Hour/time.Microsecond) + 1} {
			s := testHBStatus(seq, 7)
			rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: s})
			if rec.Code != http.StatusBadRequest || apiError(rec) != serverclient.AgentErrHeartbeatSeqFuture {
				t.Fatalf("seq %d: %d %s", seq, rec.Code, rec.Body.String())
			}
			if got := e.hostsStatus(t).Hosts[0].Heartbeat.Status; got.Seq != 10 || got.Directory.Version != 1 {
				t.Fatalf("seq %d changed the stored status: %+v", seq, got)
			}
		}
		if !strings.Contains(e.log.String(), serverclient.AgentErrHeartbeatSeqFuture) {
			t.Fatalf("no %s log line:\n%s", serverclient.AgentErrHeartbeatSeqFuture, e.log.String())
		}
		edge := nowUS(e) + uint64(time.Hour/time.Microsecond)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(edge, 1)}); rec.Code != http.StatusOK {
			t.Fatalf("seq exactly an hour ahead: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("lower_seq_after_reset_flagged", func(t *testing.T) {
		e, id := polledAgent(t)
		// The host's clock ran 30 min ahead, then its state was reset:
		// its seq restarts from its corrected clock, below the stored one.
		ahead := nowUS(e) + uint64(30*time.Minute/time.Microsecond)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(ahead, 1)}); rec.Code != http.StatusOK {
			t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		if v := e.rawHosts(t)[0]["seq_regressed"]; v != false {
			t.Fatalf("seq_regressed %v before any lower seq", v)
		}
		for i := range 3 {
			e.clock.set(e.clock.Now().Add(time.Minute))
			rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(nowUS(e), 2)})
			if rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrStaleHeartbeat {
				t.Fatalf("lower seq %d: %d %s", i, rec.Code, rec.Body.String())
			}
		}
		if v := e.rawHosts(t)[0]["seq_regressed"]; v != true {
			t.Fatalf("seq_regressed %v after lower seqs", v)
		}
		if n := strings.Count(e.log.String(), "heartbeat_seq_regressed"); n != 1 {
			t.Fatalf("%d heartbeat_seq_regressed log lines for three lower seqs within an hour, want 1:\n%s", n, e.log.String())
		}
		// An hour later it is logged again.
		e.clock.set(e.clock.Now().Add(time.Hour))
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(ahead-1, 2)})
		if n := strings.Count(e.log.String(), "heartbeat_seq_regressed"); n != 2 {
			t.Fatalf("%d heartbeat_seq_regressed log lines an hour later, want 2", n)
		}
		// Silent: the flag is the silent host's, not seq_regressed.
		e.clock.set(e.clock.Now().Add(181 * time.Second))
		if v := e.rawHosts(t)[0]["seq_regressed"]; v != false {
			t.Fatalf("seq_regressed %v on a silent host", v)
		}
		// A higher seq is stored again: the flag goes.
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(nowUS(e), 3)}); rec.Code != http.StatusOK {
			t.Fatalf("a higher seq: %d %s", rec.Code, rec.Body.String())
		}
		if v := e.rawHosts(t)[0]["seq_regressed"]; v != false {
			t.Fatalf("seq_regressed %v after a stored heartbeat", v)
		}
	})
	t.Run("equal_seq_not_flagged", func(t *testing.T) {
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 1)})
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 1)})
		if v := e.rawHosts(t)[0]["seq_regressed"]; v != false {
			t.Fatalf("seq_regressed %v after an equal seq", v)
		}
		if strings.Contains(e.log.String(), "heartbeat_seq_regressed") {
			t.Fatal("an equal seq was logged as regressed")
		}
	})
	t.Run("offset_updates_on_stale", func(t *testing.T) {
		e, id := polledAgent(t)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(10, 1)})
		for _, c := range []struct {
			seq  uint64
			off  int64
			skew bool
		}{{10, 400, true}, {9, -20, false}, {nowUS(e) + uint64(2*time.Hour/time.Microsecond), -7300, true}} {
			e.heartbeat(t, id, heartbeat.Heartbeat{Status: testHBStatus(c.seq, 1), ClockOffsetS: c.off})
			row := e.rawHosts(t)[0]
			if row["clock_offset_s"] != float64(c.off) || row["clock_skew"] != c.skew {
				t.Fatalf("after a refused heartbeat (seq %d) with offset %d: clock_offset_s %v, clock_skew %v", c.seq, c.off, row["clock_offset_s"], row["clock_skew"])
			}
		}
		if got := e.hostsStatus(t).Hosts[0].Heartbeat.Status.Seq; got != 10 {
			t.Fatalf("stored seq %d, want 10", got)
		}
	})
}

// logRecord is the first JSON log record whose msg is msg, or nil.
func (e *agentEnv) logRecord(t *testing.T, msg string) map[string]any {
	t.Helper()
	for _, l := range e.log.Lines() {
		var rec map[string]any
		if json.Unmarshal([]byte(l), &rec) == nil && rec["msg"] == msg {
			return rec
		}
	}
	return nil
}

// rotateIdentity posts a rotation of as to spki, signed by as's key.
func (e *agentEnv) rotateIdentity(t *testing.T, as agentID, spki []byte) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(serverclient.AgentIdentityRequest{NewSPKI: spki, Sig: ed25519.Sign(as.key, serverclient.AgentIdentityMessage(spki))})
	if err != nil {
		t.Fatal(err)
	}
	return e.agentDo(t, as, http.MethodPost, serverclient.AgentIdentityPath, b)
}

// TestIdentityRotationRecorded is owner decision D-R1 (PR #72 review
// C12): every rotation is logged at warning level with the host, both
// identities and the client address, and recorded on the agents row,
// where hosts/status shows it.
func TestIdentityRotationRecorded(t *testing.T) {
	e, old := polledAgent(t)
	if row := e.rawHosts(t)[0]; row["identity_rotations"] != float64(0) || row["identity_rotated_at"] != "" {
		t.Fatalf("before any rotation: identity_rotations %v, identity_rotated_at %v", row["identity_rotations"], row["identity_rotated_at"])
	}
	nid, spki := newIdentityKey(t)
	if rec := e.rotateIdentity(t, old, spki); rec.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	rec := e.logRecord(t, "agent identity rotated")
	if rec == nil || rec["level"] != "WARN" || rec["host"] != "web1" || rec["agent"] != agentFingerprint(old.spki) ||
		rec["new_agent"] != agentFingerprint(nid.spki) || rec["client"] != "192.0.2.1" {
		t.Fatalf("the rotation's log record: %v\n%s", rec, e.log.String())
	}
	row := e.rawHosts(t)[0]
	if row["identity_rotations"] != float64(1) || row["identity_rotated_at"] != t0.UTC().Format(time.RFC3339) {
		t.Fatalf("after a rotation: identity_rotations %v, identity_rotated_at %v", row["identity_rotations"], row["identity_rotated_at"])
	}
}

// TestAgentLimitAcrossRotation (PR #72 review C10, C15): the enrolled
// agent's rate limit is its row's, so an identity rotation buys it no new
// budget, and a row rotates at most once an hour, so no single agent can
// drain the shared agent budget.
func TestAgentLimitAcrossRotation(t *testing.T) {
	e := newAgentEnv(t, true)
	e.s.agentLimit, e.s.agentAnonLimit = newAgentLimiters()
	id, _ := e.approvedAgent(t)
	for i := range agentBurst - 1 {
		if rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusOK {
			t.Fatalf("state request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	nid, spki := newIdentityKey(t)
	if rec := e.rotateIdentity(t, id, spki); rec.Code != http.StatusOK {
		t.Fatalf("the rotation (the burst's last token): %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.agentDo(t, nid, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the rotated identity's first state request with the row's burst spent: %d, want 429", rec.Code)
	}
	// A minute refills 30 tokens; the row still may not rotate again.
	e.clock.set(e.clock.Now().Add(time.Minute))
	_, spki2 := newIdentityKey(t)
	rec := e.rotateIdentity(t, nid, spki2)
	if rec.Code != http.StatusTooManyRequests || apiError(rec) != serverclient.AgentErrRotationTooSoon || rec.Header().Get("Retry-After") != "3540" {
		t.Fatalf("a second rotation a minute later: %d %s (Retry-After %q)", rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"))
	}
	// Churning the row cannot spend the global budget for others.
	for range 200 {
		x, s := newIdentityKey(t)
		e.rotateIdentity(t, nid, s)
		e.agentDo(t, x, http.MethodGet, serverclient.AgentStatePath, nil)
		e.agentDo(t, nid, http.MethodGet, serverclient.AgentStatePath, nil)
	}
	other, hosts := newAgentID(t), hostSigners(t, 1)
	// From another address: the unknown identities above spent the
	// anonymous class of this one.
	const addr = "198.51.100.9:40000"
	if rec := e.agentDoFrom(t, other, addr, http.MethodPost, serverclient.AgentEnrollPath, enrollBody(t, other, e.mustMint(t, "web2", 0).Token, hosts)); rec.Code != http.StatusAccepted {
		t.Fatalf("enroll web2: %d %s", rec.Code, rec.Body.String())
	}
	e.installDir(t, e.webEntry2(t, "web1"), hostEntry("web2", hosts))
	for i := range agentBurst {
		if rec := e.agentDoFrom(t, other, addr, http.MethodGet, serverclient.AgentStatePath, nil); rec.Code != http.StatusOK {
			t.Fatalf("another agent's state request %d: %d %s", i+1, rec.Code, rec.Body.String())
		}
	}
	// An hour after the rotation the row may rotate again.
	e.clock.set(e.clock.Now().Add(time.Hour))
	if rec := e.rotateIdentity(t, nid, spki2); rec.Code != http.StatusOK {
		t.Fatalf("a rotation an hour later: %d %s", rec.Code, rec.Body.String())
	}
}

// webEntry2 is the directory entry named name of the enrolled agent
// whose expected name it is.
func (e *agentEnv) webEntry2(t *testing.T, name string) directory.Host {
	t.Helper()
	agents, err := e.s.db.ListAgents(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range agents {
		if a.ExpectedName == name {
			return directory.Host{Name: name, HostGroup: "lab", Keys: a.HostKeys, Principals: []string{name}, Status: directory.StatusActive}
		}
	}
	t.Fatalf("no agent named %s", name)
	return directory.Host{}
}
