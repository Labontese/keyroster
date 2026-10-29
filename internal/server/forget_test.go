package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/trust"
	"golang.org/x/crypto/ssh"
)

// pendingAnswer GETs host pending as the admin.
func (e *agentEnv) pendingAnswer(t *testing.T) serverclient.PendingHostsAnswer {
	t.Helper()
	rec := e.adminDo(t, http.MethodGet, serverclient.AdminPendingHostsPath, nil)
	var ans serverclient.PendingHostsAnswer
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &ans) != nil {
		t.Fatalf("host pending: %d %s", rec.Code, rec.Body.String())
	}
	return ans
}

// agentRow is the agents row with the identity spki, or nil.
func (e *agentEnv) agentRow(t *testing.T, spki []byte) *serverdb.Agent {
	t.Helper()
	a, err := e.s.db.AgentBySPKI(t.Context(), spki)
	if err != nil {
		return nil
	}
	return a
}

// state sends a state request as id.
func (e *agentEnv) state(t *testing.T, id agentID) int {
	t.Helper()
	return e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil).Code
}

// removedAgent is an approved agent web1 that reported directory 1, then
// was removed at directory R and requested state under it, so R is its
// recorded removal version (no confirmation yet).
func removedAgent(t *testing.T) (*agentEnv, agentID, uint64) {
	t.Helper()
	e, id := polledAgent(t)
	e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbAt(t, 1, 1)})
	r := e.installDir(t)
	if c := e.state(t, id); c != http.StatusOK {
		t.Fatalf("state under the removal: %d", c)
	}
	if a := e.agentRow(t, id.spki); a.RemovedDirVersion != r || a.RemovalConfirmedVersion != 0 {
		t.Fatalf("after the removal: removed_dir_version %d, confirmed %d; want %d, none", a.RemovedDirVersion, a.RemovalConfirmedVersion, r)
	}
	return e, id, r
}

// confirmedAgent is removedAgent whose host then reported directory R
// with its SHA-256: the removal confirmed at R.
func confirmedAgent(t *testing.T) (*agentEnv, agentID, uint64) {
	t.Helper()
	e, id, r := removedAgent(t)
	if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbAt(t, 2, r)}); rec.Code != http.StatusOK {
		t.Fatalf("heartbeat at the removal: %d %s", rec.Code, rec.Body.String())
	}
	wantConfirmed(t, e, id, r, r)
	return e, id, r
}

// wantConfirmed fails unless id's row has removal version r and the
// confirmation at directory v (0: none), with that directory's SHA-256.
func wantConfirmed(t *testing.T, e *agentEnv, id agentID, r, v uint64) {
	t.Helper()
	a := e.agentRow(t, id.spki)
	if a == nil {
		t.Fatal("the agent's row is gone")
	}
	var sum []byte
	if v != 0 {
		s := sha256.Sum256(e.dirs[v-1])
		sum = s[:]
	}
	if a.RemovedDirVersion != r || a.RemovalConfirmedVersion != v || !bytes.Equal(a.RemovalConfirmedSHA256, sum) {
		t.Fatalf("removed_dir_version %d, confirmed v%d %x; want %d, v%d %x", a.RemovedDirVersion, a.RemovalConfirmedVersion, a.RemovalConfirmedSHA256, r, v, sum)
	}
}

// rekeyedWeb1 is an active entry web1 with new host keys: a re-keyed
// host, or another agent enrolled under the name.
func rekeyedWeb1(t *testing.T) directory.Host {
	t.Helper()
	return hostEntry("web1", hostSigners(t, 1))
}

// TestInFlightRequestOfForgottenAgent is PR #72 fix-round carry-over (a)
// (03-08b): a request of agent A looked up just before A was forgotten
// and B enrolled into A's reused row ID never writes B's row, and is
// answered 403 unknown_agent.
func TestInFlightRequestOfForgottenAgent(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(t *testing.T) (*agentEnv, agentID)
	}{
		// A's first state: requireAgent would record B as approved.
		{"first_state", func(t *testing.T) (*agentEnv, agentID) {
			e := newAgentEnv(t, true)
			id, _ := e.approvedAgent(t)
			return e, id
		}},
		// A removed: requireAgent would record B's removal version.
		{"removed", func(t *testing.T) (*agentEnv, agentID) {
			e, id := polledAgent(t)
			e.installDir(t)
			return e, id
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, a := c.setup(t)
			rowA := e.agentRow(t, a.spki)
			b, hostsB := newAgentID(t), hostSigners(t, 1)
			token := e.mustMint(t, "web2", 0).Token
			var once sync.Once
			e.s.afterAgentLookup = func() {
				once.Do(func() {
					if err := e.s.db.DeleteAgentIf(t.Context(), rowA.Key(), rowA.ForgetFacts()); err != nil {
						t.Errorf("forget A: %v", err)
					}
					if rec := e.enroll(t, b, token, hostsB); rec.Code != http.StatusAccepted {
						t.Errorf("enroll B: %d %s", rec.Code, rec.Body.String())
					}
				})
			}
			rec := e.agentDo(t, a, http.MethodGet, serverclient.AgentStatePath, nil)
			e.s.afterAgentLookup = nil
			rowB := e.agentRow(t, b.spki)
			if rowB == nil || rowB.ID != rowA.ID {
				t.Fatalf("B's row %+v; the test needs B on A's row ID %d", rowB, rowA.ID)
			}
			if rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrUnknown {
				t.Errorf("A's in-flight request: %d %s, want 403 %s", rec.Code, rec.Body.String(), serverclient.AgentErrUnknown)
			}
			if rowB.ApprovedAtUS != 0 || rowB.RemovedDirVersion != 0 || rowB.LastSeenUS != 0 {
				t.Errorf("A's request wrote B's row: approved_at_us %d, removed_dir_version %d, last_seen_us %d", rowB.ApprovedAtUS, rowB.RemovedDirVersion, rowB.LastSeenUS)
			}
		})
	}
}

// TestReenrolledIdentityKeepsItsRow is the pre-merge review's finding 8
// on PR #74 (03-08b fix round 1): the runbook's "same machine, keeping its
// fetcher identity" order re-enrolls the same identity, and SQLite gives
// the new row the old row's ID, so (ID, identity) no longer tells the two
// enrollments apart. Every agents-row write is therefore keyed on the join
// token too (each token enrolls at most one row):
//   - state_request_in_flight: a state request of removed agent A, looked
//     up before A was forgotten with --host-gone and the same identity
//     re-enrolled (same host keys, new token), writes nothing on the new
//     row and is refused 403 unknown_agent; the new pending row can still
//     be forgotten;
//   - forget_in_flight (split finding 2): a forget of pending agent A,
//     whose facts were checked before A was deleted and the same identity
//     re-enrolled, deletes nothing (409 forget_state_changed).
func TestReenrolledIdentityKeepsItsRow(t *testing.T) {
	reenroll := func(t *testing.T, e *agentEnv, id agentID, hosts []ssh.Signer) {
		t.Helper()
		if rec := e.enroll(t, id, e.mustMint(t, "web1", 0).Token, hosts); rec.Code != http.StatusAccepted {
			t.Errorf("re-enroll the same identity: %d %s", rec.Code, rec.Body.String())
		}
	}
	t.Run("state_request_in_flight", func(t *testing.T) {
		e := newAgentEnv(t, true)
		a, hosts := e.approvedAgent(t)
		if c := e.state(t, a); c != http.StatusOK {
			t.Fatalf("the first state: %d", c)
		}
		e.installDir(t)
		rowA := e.agentRow(t, a.spki)
		var once sync.Once
		e.s.afterAgentLookup = func() {
			once.Do(func() {
				if err := e.s.db.DeleteAgentIf(t.Context(), rowA.Key(), rowA.ForgetFacts()); err != nil {
					t.Errorf("forget A --host-gone: %v", err)
				}
				reenroll(t, e, a, hosts)
			})
		}
		rec := e.agentDo(t, a, http.MethodGet, serverclient.AgentStatePath, nil)
		e.s.afterAgentLookup = nil
		row := e.agentRow(t, a.spki)
		if row == nil || row.ID != rowA.ID || bytes.Equal(row.TokenSHA256, rowA.TokenSHA256) {
			t.Fatalf("the new row %+v; the test needs it on A's row ID %d with a new token", row, rowA.ID)
		}
		if rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrUnknown {
			t.Errorf("A's in-flight request: %d %s, want 403 %s", rec.Code, rec.Body.String(), serverclient.AgentErrUnknown)
		}
		if row.ApprovedAtUS != 0 || row.RemovedDirVersion != 0 || row.LastSeenUS != 0 {
			t.Errorf("A's request wrote the new row: approved_at_us %d, removed_dir_version %d, last_seen_us %d", row.ApprovedAtUS, row.RemovedDirVersion, row.LastSeenUS)
		}
		if rec := e.forget(t, "web1"); rec.Code != http.StatusOK {
			t.Errorf("forget of the new pending row: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("forget_in_flight", func(t *testing.T) {
		e := newAgentEnv(t, true)
		a, hosts := newAgentID(t), hostSigners(t, 1)
		reenroll(t, e, a, hosts)
		rowA := e.agentRow(t, a.spki)
		var once sync.Once
		e.s.beforeForgetDelete = func() {
			once.Do(func() {
				if err := e.s.db.DeleteAgentIf(t.Context(), rowA.Key(), rowA.ForgetFacts()); err != nil {
					t.Errorf("forget A: %v", err)
				}
				reenroll(t, e, a, hosts)
			})
		}
		rec := e.forgetFacts(t, forgetReqOf(rowA, false))
		e.s.beforeForgetDelete = nil
		row := e.agentRow(t, a.spki)
		if rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrForgetStateChanged {
			t.Errorf("the forget checked against A: %d %s, want 409 %s", rec.Code, rec.Body.String(), serverclient.AdminErrForgetStateChanged)
		}
		if row == nil || row.ID != rowA.ID || bytes.Equal(row.TokenSHA256, rowA.TokenSHA256) {
			t.Fatalf("the new row %+v; want it present on A's row ID %d with a new token", row, rowA.ID)
		}
	})
}

// TestRemovalConfirmation is PR #72 fix-round carry-over (b) (03-08b): a
// removal is confirmed once, from the host's own heartbeat, for a
// directory V the server served at or above the removal in which nothing
// names the host; a re-use of its name keeps a confirmation and never
// makes one.
func TestRemovalConfirmation(t *testing.T) {
	t.Run("confirmed_then_readded_kept", func(t *testing.T) {
		e, id, r := confirmedAgent(t)
		e.installDir(t, rekeyedWeb1(t))
		if c := e.state(t, id); c != http.StatusOK {
			t.Fatalf("state under the re-added name: %d", c)
		}
		wantConfirmed(t, e, id, r, r)
		if rec := e.forget(t, "web1"); rec.Code != http.StatusOK {
			t.Fatalf("forget of a confirmed host whose name was re-added: %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(e.log.String(), "--host-gone") {
			t.Fatal("a confirmed forget logged --host-gone")
		}
	})
	t.Run("late_heartbeat_reporting_the_removal_confirms", func(t *testing.T) {
		e, id, r := removedAgent(t)
		e.installDir(t, rekeyedWeb1(t))
		e.state(t, id)
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbAt(t, 2, r)}); rec.Code != http.StatusOK {
			t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		wantConfirmed(t, e, id, r, r)
	})
	t.Run("unconfirmed_then_readded_not_confirmed", func(t *testing.T) {
		e, id, r := removedAgent(t)
		v := e.installDir(t, rekeyedWeb1(t))
		e.state(t, id)
		// The host reached the re-add without applying its removal: it
		// kept last-good's principals (host_keys_rotated).
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbAt(t, 2, v)}); rec.Code != http.StatusOK {
			t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String())
		}
		e.pendingAnswer(t)
		wantConfirmed(t, e, id, r, 0)
		if rec := e.forget(t, "web1"); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrRemovalNotApplied {
			t.Fatalf("forget of an unconfirmed host whose name was re-added: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("entry_holding_its_keys_again_clears", func(t *testing.T) {
		for _, status := range []string{directory.StatusActive, directory.StatusDisabled} {
			e, id, _ := confirmedAgent(t)
			h := e.webEntry(t)
			h.Status = status
			e.installDir(t, h)
			e.state(t, id)
			wantConfirmed(t, e, id, 0, 0)
		}
	})
	t.Run("other_sha_not_confirmed", func(t *testing.T) {
		e, id, r := removedAgent(t)
		s := e.hbAt(t, 2, r)
		s.Directory.SHA256 = strings.Repeat("cd", 32)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: s})
		e.pendingAnswer(t)
		wantConfirmed(t, e, id, r, 0)
	})
	t.Run("signer_unreachable_skips_then_pending_records", func(t *testing.T) {
		e, id, r := removedAgent(t)
		e.installDir(t)
		e.state(t, id)
		e.fake.mu.Lock()
		saved := e.fake.dirVersions[r]
		delete(e.fake.dirVersions, r)
		e.fake.mu.Unlock()
		if rec := e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbAt(t, 2, r)}); rec.Code != http.StatusOK {
			t.Fatalf("a heartbeat while the signer cannot answer: %d %s", rec.Code, rec.Body.String())
		}
		wantConfirmed(t, e, id, r, 0)
		if ans := e.pendingAnswer(t); len(ans.Served) != 1 || ans.Served[0].RemovalConfirmed != nil || ans.Served[0].RemovalVersion != r {
			t.Fatalf("host pending while the signer cannot answer: %+v", ans.Served)
		}
		e.fake.mu.Lock()
		e.fake.dirVersions[r] = saved
		e.fake.mu.Unlock()
		ans := e.pendingAnswer(t)
		if len(ans.Served) != 1 || ans.Served[0].RemovalConfirmed == nil || ans.Served[0].RemovalConfirmed.Version != r {
			t.Fatalf("host pending once the signer answers: %+v", ans.Served)
		}
		wantConfirmed(t, e, id, r, r)
	})
	t.Run("confirmation_sha_is_the_document_hash", func(t *testing.T) {
		e, id, r := removedAgent(t)
		e.installDir(t)
		e.state(t, id)
		e.heartbeat(t, id, heartbeat.Heartbeat{Status: e.hbAt(t, 2, r)})
		d, err := e.fake.GetDirectoryVersion(t.Context(), r)
		if err != nil {
			t.Fatal(err)
		}
		want := trust.SHA256Hex(d.Directory)
		ans := e.pendingAnswer(t)
		a := e.agentRow(t, id.spki)
		if len(ans.Served) != 1 || ans.Served[0].RemovalConfirmed == nil || ans.Served[0].RemovalConfirmed.SHA256 != want || hex.EncodeToString(a.RemovalConfirmedSHA256) != want {
			t.Fatalf("the recorded SHA-256 %x (served %+v), want %s, the signer's document at v%d without its signatures", a.RemovalConfirmedSHA256, ans.Served, want, r)
		}
		if withSigs := sha256.Sum256(append(slices.Clone(d.Directory), d.Sigs...)); hex.EncodeToString(withSigs[:]) == want {
			t.Fatal("the test's document and signatures hash alike")
		}
	})
	t.Run("pre_0007_latest_heartbeat_only", func(t *testing.T) {
		// Heartbeats stored by a server before migration 0007, which
		// recorded no confirmation: the store goes to the database itself.
		store := func(t *testing.T, e *agentEnv, id agentID, seq, v uint64) {
			t.Helper()
			a := e.agentRow(t, id.spki)
			body := hbBody(t, heartbeat.Heartbeat{Status: e.hbAt(t, seq, v)})
			if _, err := e.s.db.StoreHeartbeat(t.Context(), a.Key(), int64(seq), body, 0, e.clock.Now().UnixMicro()); err != nil { //nolint:gosec // G115: a small test seq
				t.Fatal(err)
			}
		}
		t.Run("removal_cleared_by_03_08", func(t *testing.T) {
			e, id, r := removedAgent(t)
			store(t, e, id, 2, r)
			// 03-08 cleared the removal version when the name was re-added.
			a := e.agentRow(t, id.spki)
			if err := e.s.db.SetAgentRemovedVersion(t.Context(), a.Key(), 0); err != nil {
				t.Fatal(err)
			}
			e.installDir(t, rekeyedWeb1(t))
			if ans := e.pendingAnswer(t); len(ans.Served) != 1 || ans.Served[0].RemovalConfirmed != nil || ans.Served[0].RemovalVersion != 0 {
				t.Fatalf("host pending: %+v", ans.Served)
			}
			if rec := e.forget(t, "web1"); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrRemovalNotApplied {
				t.Fatalf("forget: %d %s", rec.Code, rec.Body.String())
			}
		})
		t.Run("latest_heartbeat_names_it_again", func(t *testing.T) {
			e, id, r := removedAgent(t)
			store(t, e, id, 2, r)
			v := e.installDir(t, rekeyedWeb1(t))
			store(t, e, id, 3, v)
			if ans := e.pendingAnswer(t); len(ans.Served) != 1 || ans.Served[0].RemovalConfirmed != nil || ans.Served[0].RemovalVersion != r {
				t.Fatalf("host pending: %+v", ans.Served)
			}
			if rec := e.forget(t, "web1"); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrRemovalNotApplied {
				t.Fatalf("forget: %d %s", rec.Code, rec.Body.String())
			}
		})
	})
}

// TestForgetHost is PR #72 fix-round carry-over (c) and plan check item 1
// (03-08b): forget names one agent by identity and deletes it only while
// the facts the admin saw still hold, re-checked by the delete itself.
func TestForgetHost(t *testing.T) {
	t.Run("by_identity_among_two_with_one_name", func(t *testing.T) {
		e, a, _ := confirmedAgent(t)
		b, hostsB := newAgentID(t), hostSigners(t, 1)
		if rec := e.enroll(t, b, e.mustMint(t, "web1", 0).Token, hostsB); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll B: %d %s", rec.Code, rec.Body.String())
		}
		e.installDir(t, hostEntry("web1", hostsB))
		if c := e.state(t, b); c != http.StatusOK {
			t.Fatalf("B's state: %d", c)
		}
		if rec := e.forgetFacts(t, forgetReqOf(e.agentRow(t, a.spki), false)); rec.Code != http.StatusOK {
			t.Fatalf("forget A: %d %s", rec.Code, rec.Body.String())
		}
		if e.agentRow(t, a.spki) != nil || e.agentRow(t, b.spki) == nil {
			t.Fatal("forget did not delete exactly A's row")
		}
		if c := e.state(t, b); c != http.StatusOK {
			t.Fatalf("B's state after A's forget: %d", c)
		}
		if c := e.state(t, a); c != http.StatusForbidden {
			t.Fatalf("A's state after its forget: %d", c)
		}
	})
	t.Run("facts_changed_refused", func(t *testing.T) {
		e, a, _ := confirmedAgent(t)
		for _, edit := range []func(r *serverclient.ForgetHostRequest){
			func(r *serverclient.ForgetHostRequest) { r.RemovalVersion-- },
			func(r *serverclient.ForgetHostRequest) { r.RemovalConfirmed.Version++ },
			func(r *serverclient.ForgetHostRequest) { r.RemovalConfirmed.SHA256 = strings.Repeat("cd", 32) },
			func(r *serverclient.ForgetHostRequest) { r.RemovalConfirmed, r.HostGone = nil, true },
			// Checked before the gate: not host_removal_not_applied.
			func(r *serverclient.ForgetHostRequest) { r.RemovalConfirmed = nil },
		} {
			req := forgetReqOf(e.agentRow(t, a.spki), false)
			edit(&req)
			if rec := e.forgetFacts(t, req); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrForgetStateChanged {
				t.Fatalf("forget with facts the row does not hold (%+v): %d %s", req, rec.Code, rec.Body.String())
			}
		}
		if e.agentRow(t, a.spki) == nil {
			t.Fatal("a refused forget deleted the row")
		}
	})
	t.Run("facts_changed_before_delete", func(t *testing.T) {
		for _, c := range []struct {
			name   string
			change func(t *testing.T, e *agentEnv, a *serverdb.Agent, r uint64)
		}{
			{"confirmation_recorded", func(t *testing.T, e *agentEnv, a *serverdb.Agent, r uint64) {
				sum := sha256.Sum256(e.dirs[r-1])
				if ok, err := e.s.db.RecordRemovalConfirmed(t.Context(), a.Key(), r, r, sum[:]); err != nil || !ok {
					t.Errorf("record the confirmation: %t %v", ok, err)
				}
			}},
			{"identity_rotated", func(t *testing.T, e *agentEnv, a *serverdb.Agent, _ uint64) {
				n := newAgentID(t)
				if err := e.s.db.RotateAgentIdentity(t.Context(), a.Key(), n.spki, e.clock.Now().UnixMicro()); err != nil {
					t.Errorf("rotate the identity: %v", err)
				}
			}},
		} {
			t.Run(c.name, func(t *testing.T) {
				e, id, r := removedAgent(t)
				a := e.agentRow(t, id.spki)
				e.s.beforeForgetDelete = func() { c.change(t, e, a, r) }
				rec := e.forgetFacts(t, forgetReqOf(a, true))
				e.s.beforeForgetDelete = nil
				if rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrForgetStateChanged {
					t.Fatalf("forget whose row changed before the delete: %d %s", rec.Code, rec.Body.String())
				}
				if agents, err := e.s.db.ListAgents(t.Context()); err != nil || len(agents) != 1 {
					t.Fatalf("%d agents (%v) after the refusal, want the row still present", len(agents), err)
				}
			})
		}
	})
	t.Run("host_gone_with_confirmation_malformed", func(t *testing.T) {
		e, a, _ := confirmedAgent(t)
		req := forgetReqOf(e.agentRow(t, a.spki), false)
		req.HostGone = true
		if rec := e.forgetFacts(t, req); rec.Code != http.StatusBadRequest {
			t.Fatalf("host_gone with a confirmation: %d %s", rec.Code, rec.Body.String())
		}
		for _, bad := range []serverclient.ForgetHostRequest{
			{IdentitySPKISHA256: strings.Repeat("AB", 32)},
			{IdentitySPKISHA256: req.IdentitySPKISHA256, RemovalVersion: 2},
			{IdentitySPKISHA256: req.IdentitySPKISHA256, HostGone: true},
			{IdentitySPKISHA256: req.IdentitySPKISHA256, ApprovedOnce: true, RemovalConfirmed: req.RemovalConfirmed},
			{IdentitySPKISHA256: req.IdentitySPKISHA256, ApprovedOnce: true, RemovalVersion: req.RemovalVersion + 1, RemovalConfirmed: req.RemovalConfirmed},
		} {
			if rec := e.forgetFacts(t, bad); rec.Code != http.StatusBadRequest {
				t.Fatalf("a request no admin saw (%+v): %d %s", bad, rec.Code, rec.Body.String())
			}
		}
		if e.agentRow(t, a.spki) == nil {
			t.Fatal("a malformed forget deleted the row")
		}
	})
	t.Run("never_approved_needs_no_confirmation", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, hosts := newAgentID(t), hostSigners(t, 1)
		if rec := e.enroll(t, id, e.mustMint(t, "web1", 0).Token, hosts); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
		}
		req := forgetReqOf(e.agentRow(t, id.spki), false)
		if req.ApprovedOnce || req.RemovalVersion != 0 || req.RemovalConfirmed != nil {
			t.Fatalf("a never-approved agent's facts: %+v", req)
		}
		if rec := e.forgetFacts(t, req); rec.Code != http.StatusOK {
			t.Fatalf("forget a never-approved agent: %d %s", rec.Code, rec.Body.String())
		}
		if e.agentRow(t, id.spki) != nil {
			t.Fatal("the never-approved agent was not deleted")
		}
	})
}
