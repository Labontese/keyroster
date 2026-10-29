package server

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
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
