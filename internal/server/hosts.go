package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// handleMintJoinToken serves POST AdminJoinTokensPath (keyroster host
// join-token, admin-signed): one join token for one expected host name,
// valid TTLSeconds (default 30 min, at most 1 h). The policy must set
// pop.hosts (409 host_pop_not_enabled) and an agent listener must be
// running (409 no_agent_listener), both checked before any row is
// written. The token is 32 random bytes; only their SHA-256 is stored,
// and the token itself goes only into the answer (never a log line).
func (s *Server) handleMintJoinToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	if !popHostsEnabled(v) {
		s.writeJSON(w, v, http.StatusConflict, serverclient.APIError{Error: serverclient.AgentErrHostPoPNotEnable})
		return
	}
	var req serverclient.JoinTokenRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() || !directory.ValidUserName(req.ExpectedName) || req.TTLSeconds < 0 {
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	ttl := req.TTLSeconds
	if ttl == 0 {
		ttl = serverclient.DefaultJoinTokenTTLSeconds
	}
	if ttl > serverclient.MaxJoinTokenTTLSeconds {
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AdminErrTTL})
		return
	}
	if s.agentPort == 0 {
		s.writeJSON(w, v, http.StatusConflict, serverclient.APIError{Error: serverclient.AdminErrNoAgentListener})
		return
	}
	raw := make([]byte, join.TokenBytes)
	if _, err := rand.Read(raw); err != nil {
		s.writeJSON(w, v, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	expires := s.clock().Truncate(time.Second).Add(time.Duration(ttl) * time.Second)
	hash := sha256.Sum256(raw)
	if err := s.db.CreateJoinToken(ctx, hash[:], req.ExpectedName, adminName(ctx), expires.UnixMicro()); err != nil {
		s.log.Error("join token", "err", err)
		s.writeJSON(w, v, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	s.log.Info("join token minted", "expected_name", req.ExpectedName, "admin", adminName(ctx), "expires_at", join.FormatExpiry(expires))
	s.writeJSON(w, v, http.StatusCreated, serverclient.JoinTokenAnswer{
		ExpectedName: req.ExpectedName, Token: join.EncodeToken(raw), ExpiresAt: join.FormatExpiry(expires), AgentPort: s.agentPort,
	})
}

// handlePendingHosts serves GET AdminPendingHostsPath (keyroster host
// pending, host approve and host forget, admin-signed): every enrolled
// agent that no active directory host entry with exactly its host keys
// approves. An agent the directory approved once is never pending again:
// it is listed under Served with its directory state (removed, disabled
// or keys_changed), its removal version and its recorded removal
// confirmation, and keeps getting signed state until keyroster host
// forget, so host approve can never pick its identity (03-08 carry-over
// a, owner decision 2026-10-28). Before it answers, it brings the
// recorded confirmation of each served agent with a removal version in
// step with its stored heartbeat (reconcileRemoval, 03-08b): it records
// one the rule confirms, which catches the rows from before migration
// 0007 and the recordings a heartbeat skipped while the signer was
// unreachable, and clears one whose heartbeat shows principals again
// (owner decision D-R1). A signer error there is logged and skipped. The
// policy must set pop.hosts (409 host_pop_not_enabled).
func (s *Server) handlePendingHosts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	if !popHostsEnabled(v) {
		s.writeJSON(w, v, http.StatusConflict, serverclient.APIError{Error: serverclient.AgentErrHostPoPNotEnable})
		return
	}
	dv, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("directory read failed", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	agents, err := s.db.ListAgents(ctx)
	if err != nil {
		s.log.Error("list agents", "err", err)
		s.writeJSON(w, v, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	hbs, err := s.db.Heartbeats(ctx)
	if err != nil {
		s.log.Error("heartbeats", "err", err)
		s.writeJSON(w, v, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	out := serverclient.PendingHostsAnswer{Hosts: []serverclient.PendingHost{}, Served: []serverclient.ServedHost{}}
	for _, a := range agents {
		if approved(dv, a.HostKeys) {
			continue
		}
		var f enroll.Facts
		if err := json.Unmarshal([]byte(a.Facts), &f); err != nil {
			s.log.Error("agent facts", "agent", a.ID, "err", err)
			continue
		}
		p := serverclient.PendingHost{
			ExpectedName: a.ExpectedName, IdentitySPKISHA256: hex.EncodeToString(a.IdentitySPKISHA256), HostKeys: a.HostKeys,
			Facts: f, EnrolledAt: time.UnixMicro(a.EnrolledAtUS).UTC().Format(time.RFC3339),
		}
		if a.ApprovedAtUS == 0 {
			out.Hosts = append(out.Hosts, p)
			continue
		}
		swap := false
		if hb, ok := hbs[a.ID]; ok {
			h, err := heartbeat.ParseHeartbeat(hb.Body)
			swap = swapPending(hb.Body) != nil
			if err == nil && a.RemovedDirVersion != 0 {
				if err := s.reconcileRemoval(ctx, dv, &a, hb.Seq, &h.Status); err != nil {
					s.log.Warn("removal confirmation skipped", "expected_name", a.ExpectedName, "agent", agentFingerprint(a.IdentitySPKISHA256), "err", err)
				}
			}
		}
		_, st := hostState(dv, a.HostKeys, a.ExpectedName)
		h := servedHost(p, st, &a)
		h.SwapPending = swap
		out.Served = append(out.Served, h)
	}
	s.log.Info("pending hosts listed", "admin", adminName(ctx), "count", len(out.Hosts), "served", len(out.Served))
	s.writeJSON(w, dv.status, http.StatusOK, out)
}

// servedHost is the served row of p, an agent approved once in directory
// state st, with a's removal version and recorded confirmation.
func servedHost(p serverclient.PendingHost, st string, a *serverdb.Agent) serverclient.ServedHost {
	h := serverclient.ServedHost{PendingHost: p, State: st, RemovalVersion: a.RemovedDirVersion}
	if a.RemovalConfirmedVersion != 0 {
		h.RemovalConfirmed = &serverclient.RemovalConfirmation{Version: a.RemovalConfirmedVersion, SHA256: hex.EncodeToString(a.RemovalConfirmedSHA256)}
	}
	return h
}

// forgetRequestFacts returns the facts a parsed forget request names
// (wire.ForgetRequest.Validate checked their combinations) as
// serverdb.ForgetFacts: approved once, the removal version, the
// confirmation (a raw SHA-256, nil for none) and the enrollment time.
func forgetRequestFacts(req *wire.ForgetRequest) (serverdb.ForgetFacts, bool) {
	if req.EnrolledAtMicros > math.MaxInt64 {
		return serverdb.ForgetFacts{}, false
	}
	f := serverdb.ForgetFacts{ApprovedOnce: req.ApprovedOnce, RemovalVersion: req.RemovalVersion,
		ConfirmedVersion: req.ConfirmedVersion, EnrolledAtUS: int64(req.EnrolledAtMicros)} //nolint:gosec // G115: checked above
	if req.ConfirmedVersion != 0 {
		f.ConfirmedSHA256 = bytes.Clone(req.ConfirmedSHA256[:])
	}
	return f, true
}

// sameFacts reports whether a's row still holds the facts f.
func sameFacts(a *serverdb.Agent, f serverdb.ForgetFacts) bool {
	g := a.ForgetFacts()
	return g.ApprovedOnce == f.ApprovedOnce && g.RemovalVersion == f.RemovalVersion && g.ConfirmedVersion == f.ConfirmedVersion &&
		bytes.Equal(g.ConfirmedSHA256, f.ConfirmedSHA256) && g.EnrolledAtUS == f.EnrolledAtUS
}

// sameAgent reports whether the forget request names a's expected name and
// exactly a's host keys (wire.HostKeyDigest, ascending).
func sameAgent(a *serverdb.Agent, req *wire.ForgetRequest) bool {
	if a.ExpectedName != req.ExpectedName {
		return false
	}
	digests := make([][32]byte, 0, len(a.HostKeys))
	for _, k := range a.HostKeys {
		pub, err := trust.ParseKey(k)
		if err != nil {
			return false
		}
		digests = append(digests, wire.HostKeyDigest(pub))
	}
	slices.SortFunc(digests, func(x, y [32]byte) int { return bytes.Compare(x[:], y[:]) })
	return slices.Equal(digests, req.HostKeyFingerprints)
}

// handleForgetHost serves POST AdminForgetHostPath (keyroster host forget,
// admin-signed; PR #71 review D-R1, 03-08b, 03-08c): it deletes the one
// agent the admins' signed wire.ForgetRequest names by identity, so that
// identity gets 403 unknown_agent from then on and its host keys can
// enroll again with a new join token. The server holds no forget
// authority: keyroster-signer checks the admins' signatures (one for an
// agent never approved, the policy's admin_quorum for every other; owner
// decision Q3) and logs the forget as a host_forget entry, and the server
// deletes only after that. In order, each refusal deleting nothing:
//  1. the body is {"request": <wire.ForgetRequest bytes>}, decoded
//     strictly (400 malformed request);
//  2. the directory in force (503 when it cannot be read);
//  3. the agent with that identity (404 host_not_enrolled);
//  4. its expected name, host keys, enrollment time, approval, removal
//     version and recorded confirmation equal the request's (409
//     forget_state_changed: run host pending again); the signer is not
//     asked;
//  5. no directory host entry, active or disabled, holds one of its host
//     keys (409 host_in_directory). An agent approved once is named with
//     its recorded removal confirmation or with host_gone, for a host that
//     will never report again (03-08 owner decision D-1): a signed request
//     can express nothing else (wire.ForgetRequest.Validate), and the CLI
//     refuses host_removal_not_applied before it signs. A forget that
//     rests on the confirmation is refused while the host's stored
//     heartbeat shows a swap it has not finished (409 host_swap_pending,
//     03-08c), or shows principals again before reconcileRemoval cleared
//     the confirmation, or none is stored (409 host_removal_not_applied,
//     PR #75 review finding 0; removalStillApplied); host_gone overrides
//     both;
//  6. the server states its own view of the row in the relay frame,
//     approved once or not (ServerApprovedOnce, from approved_at_us,
//     whatever the request says), and asks the signer within
//     signerCallTimeout: a malformed request is 400, a refusal 403 with
//     the signer's reason, and a signer that cannot be reached or does not
//     answer 503, with nothing deleted;
//  7. serverdb.DeleteAgentIf deletes the row and its heartbeat in one
//     transaction, by one statement that re-checks the identity and every
//     fact, after it checked the stored heartbeat again by step 5's rule
//     (removalStillApplied). When the row changed after the signer's
//     answer (a fact, its identity rotated, or a heartbeat stored that
//     shows a swap or principals), nothing is deleted
//     and the answer is 409
//     forget_logged_not_deleted with the entry's leaf, logged at error
//     level: the log then records an authorization the server did not
//     carry out, and the agent keeps being served (fail-safe).
//
// The answer names the deleted row and the host_forget entry's leaf.
func (s *Server) handleForgetHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var body serverclient.ForgetHostBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil || dec.More() {
		s.writeJSON(w, nil, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	req, err := wire.ParseForgetRequest(body.Request)
	if err != nil {
		s.writeJSON(w, nil, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	facts, ok := forgetRequestFacts(req)
	if !ok {
		s.writeJSON(w, nil, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	dv, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("directory read failed", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	a, err := s.db.AgentBySPKI(ctx, req.AgentIdentity[:])
	switch {
	case errors.Is(err, serverdb.ErrNotFound):
		s.writeJSON(w, dv.status, http.StatusNotFound, serverclient.APIError{Error: serverclient.AdminErrHostNotEnrolled})
		return
	case err != nil:
		s.log.Error("agent lookup", "err", err)
		s.writeJSON(w, dv.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	fp := agentFingerprint(a.IdentitySPKISHA256)
	refuse := func(reason string) {
		s.log.Warn("forget refused", "expected_name", a.ExpectedName, "agent", fp, "admin", adminName(ctx), "reason", reason,
			"removal_version", a.RemovedDirVersion, "removal_confirmed_version", a.RemovalConfirmedVersion)
		s.writeJSON(w, dv.status, http.StatusConflict, serverclient.APIError{Error: reason})
	}
	switch {
	case !sameFacts(a, facts) || !sameAgent(a, req):
		refuse(serverclient.AdminErrForgetStateChanged)
		return
	case hostHolds(dv, a.HostKeys):
		refuse(serverclient.AdminErrHostInDirectory)
		return
	}
	// A forget that rests on the confirmation waits for a pending swap
	// (03-08c) and needs the host to still report its removal applied (PR
	// #75 review finding 0); host_gone overrides both.
	var hbCheck func([]byte) error
	if facts.ConfirmedVersion != 0 && !req.HostGone {
		hbCheck = removalStillApplied
		hbs, err := s.db.Heartbeats(ctx)
		if err != nil {
			s.log.Error("heartbeats", "err", err)
			s.writeJSON(w, dv.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
			return
		}
		var body []byte
		if hb, ok := hbs[a.ID]; ok {
			body = hb.Body
		}
		if err := removalStillApplied(body); err != nil {
			refuse(err.Error())
			return
		}
	}
	// The server's own statement, outside the signing bytes: the signer
	// compares it with the signed approved_once (owner decision Q3).
	req.ServerApprovedOnce = a.ApprovedAtUS != 0
	cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
	resp, err := s.signer.ForgetAgent(cctx, req)
	cancel()
	if err != nil {
		var refused *wire.ErrorResponse
		if errors.As(err, &refused) {
			s.log.Warn("forget refused by the signer", "expected_name", a.ExpectedName, "agent", fp, "admin", adminName(ctx), "reason", refused.Message)
			switch refused.Code {
			case wire.CodeMalformed:
				s.writeJSON(w, dv.status, http.StatusBadRequest, serverclient.APIError{Error: refused.Message})
			case wire.CodeRefused:
				s.writeJSON(w, dv.status, http.StatusForbidden, serverclient.APIError{Error: refused.Message})
			default:
				s.signerUnavailable(w, false)
			}
			return
		}
		// The outcome is unknown: the signer may have logged the forget,
		// but the server deletes nothing without its answer.
		s.log.Error("forget: signer call failed, nothing deleted", "expected_name", a.ExpectedName, "agent", fp, "admin", adminName(ctx), "err", err)
		s.signerUnavailable(w, false)
		return
	}
	if s.beforeForgetDelete != nil {
		s.beforeForgetDelete()
	}
	switch err := s.db.DeleteAgentIf(ctx, a.Key(), facts, hbCheck); {
	case errors.Is(err, serverdb.ErrNotFound), errors.Is(err, errSwapPending), errors.Is(err, errHostResumed):
		s.log.Error("agent forget logged but not carried out: the agent's row or its host's report changed after the signer's answer, and it keeps being served",
			"expected_name", a.ExpectedName, "agent", fp, "admin", adminName(ctx), "leaf", resp.Leaf)
		s.writeJSON(w, dv.status, http.StatusConflict, serverclient.APIError{Error: serverclient.AdminErrForgetLoggedNotDeleted, Leaf: resp.Leaf})
		return
	case err != nil:
		s.log.Error("forget agent: logged but not carried out", "agent", a.ID, "leaf", resp.Leaf, "err", err)
		s.writeJSON(w, dv.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	if req.HostGone {
		s.log.Warn("agent forgotten with --host-gone: the host never confirmed that it applied its removal", "expected_name", a.ExpectedName,
			"agent", fp, "admin", adminName(ctx), "removal_version", a.RemovedDirVersion, "leaf", resp.Leaf)
	} else {
		s.log.Info("agent forgotten", "expected_name", a.ExpectedName, "agent", fp, "admin", adminName(ctx),
			"approved_once", facts.ApprovedOnce, "removal_version", a.RemovedDirVersion, "removal_confirmed_version", a.RemovalConfirmedVersion, "leaf", resp.Leaf)
	}
	var f enroll.Facts
	_ = json.Unmarshal([]byte(a.Facts), &f) // stored by enrollment, which checked them
	s.writeJSON(w, dv.status, http.StatusOK, serverclient.ForgetHostAnswer{Forgotten: []serverclient.PendingHost{{
		ExpectedName: a.ExpectedName, IdentitySPKISHA256: hex.EncodeToString(a.IdentitySPKISHA256), HostKeys: a.HostKeys,
		Facts: f, EnrolledAt: time.UnixMicro(a.EnrolledAtUS).UTC().Format(time.RFC3339),
	}}, Leaf: resp.Leaf})
}

// Host statuses an apply reports when it installed no principals of the
// host's own (apply.HostRemoved, apply.HostDisabled; owner decision
// 2026-10-26).
const (
	hostStatusRemoved  = "host_removed"
	hostStatusDisabled = "host_disabled"
)

// principalsShown reports whether st, a host's status, shows that the
// host has certificate principals in force (owner decision D-R1, PR #74
// review fix round 1): its committed generation lists a principals/ file,
// or it cannot be told because the file list is cut short, or its last
// apply succeeded and rendered an active entry under its current host
// keys (host_status empty). host_keys_rotated and host_keys_disagree keep
// last-good's principals files, which the file list shows; a refused or
// failed apply changed no file. A pending swap is not counted here (fix
// round 2's clear is replaced in 03-08c): it keeps a recorded
// confirmation, never makes one (principalsEmptied), and refuses forget
// while it is stored (removalStillApplied).
func principalsShown(st *heartbeat.Status) bool {
	if st.FilesTruncated || slices.ContainsFunc(st.Files, func(f heartbeat.File) bool { return strings.HasPrefix(f.Path, "principals/") }) {
		return true
	}
	la := st.LastApply
	return la != nil && la.Result == heartbeat.ResultOK && !la.Rollback && la.HostStatus == ""
}

// principalsEmptied reports whether st shows that the apply which
// committed its directory emptied the host's principals (owner decision
// D-R1): the last apply succeeded without a rollback, reported
// host_removed or host_disabled, no swap is pending (the committed
// generation is then that apply's; a pending status carries the previous
// last_apply and the file list of the generation the swap started from),
// and no principals are shown.
func principalsEmptied(st *heartbeat.Status) bool {
	la := st.LastApply
	return la != nil && la.Result == heartbeat.ResultOK && !la.Rollback && st.Pending == nil &&
		(la.HostStatus == hostStatusRemoved || la.HostStatus == hostStatusDisabled) && !principalsShown(st)
}

// errSwapPending is a forget refused because the host's stored heartbeat
// shows a swap it has not finished (03-08c).
var errSwapPending = errors.New(serverclient.AdminErrHostSwapPending)

// errHostResumed is a forget that rests on the confirmation refused
// because the host's stored heartbeat no longer reports its removal
// applied (PR #75 review finding 0): the forget needs --host-gone.
var errHostResumed = errors.New(serverclient.AdminErrRemovalNotApplied)

// removalStillApplied is the check that a forget resting on the recorded
// confirmation runs on the agent's stored heartbeat body, before the
// signer is asked and again in DeleteAgentIf's transaction (03-08c; PR
// #75 review finding 0): nil only while the body parses, shows no pending
// swap and shows no principals by principalsShown, the rule by which
// reconcileRemoval clears a confirmation. A heartbeat stored before
// reconcileRemoval ran on it is then judged by the same rule.
// errSwapPending for a pending swap or a body that does not parse;
// errHostResumed when principals are shown, or no heartbeat is stored (a
// confirmation is recorded only from a stored one).
func removalStillApplied(body []byte) error {
	if body == nil {
		return errHostResumed
	}
	h, err := heartbeat.ParseHeartbeat(body)
	switch {
	case err != nil || h.Status.Pending != nil:
		return errSwapPending
	case principalsShown(&h.Status):
		return errHostResumed
	}
	return nil
}

// swapPending reports, as errSwapPending, a stored heartbeat body that
// shows a pending swap or does not parse and so cannot tell; nil without
// one (host pending's swap_pending).
func swapPending(body []byte) error {
	if body == nil {
		return nil
	}
	h, err := heartbeat.ParseHeartbeat(body)
	if err != nil || h.Status.Pending != nil {
		return errSwapPending
	}
	return nil
}

// reconcileRemoval brings agent a's recorded removal confirmation in step
// with st, its host's stored status with seq seq (03-08b; owner decision
// D-R1): when st shows principals again, or cannot tell (principalsShown),
// a recorded confirmation is cleared, so the host's forget needs
// --host-gone again (the host resumed service, PR #74 review finding 0);
// a pending swap clears nothing (03-08c); otherwise
// confirmRemoval may record one. Both writes hold only while the stored
// heartbeat is still the one with seq. It updates a, and an error is the
// caller's to log and skip.
func (s *Server) reconcileRemoval(ctx context.Context, dv *directoryView, a *serverdb.Agent, seq int64, st *heartbeat.Status) error {
	if !principalsShown(st) {
		_, err := s.confirmRemoval(ctx, dv, a, seq, st)
		return err
	}
	if a.RemovedDirVersion == 0 && a.RemovalConfirmedVersion == 0 {
		return nil
	}
	cleared, err := s.db.ClearRemovalConfirmed(ctx, a.Key(), seq)
	if err != nil || !cleared {
		return err
	}
	s.log.Warn("agent removal confirmation cleared: its host reports principals again", "expected_name", a.ExpectedName,
		"agent", agentFingerprint(a.IdentitySPKISHA256), "removal_version", a.RemovedDirVersion, "removal_confirmed_version", a.RemovalConfirmedVersion,
		"directory_version", st.Directory.Version)
	a.RemovalConfirmedVersion, a.RemovalConfirmedSHA256 = 0, nil
	return nil
}

// confirmRemoval records the confirmation of agent a's removal (03-08b,
// PR #72 fix-round carry-over b) from st, its host's stored status with
// seq seq, which says what the host committed. It records only when a was
// approved once, has a removal version R and no confirmation yet, and all
// of these hold:
//   - the host's own report shows that the apply which committed its
//     directory emptied its principals (principalsEmptied; owner decision
//     D-R1, PR #74 review findings 7 and 10): a host that renders an
//     active entry, or keeps last-good's principals (host_keys_rotated),
//     never confirms;
//   - R <= V <= the current version, V the reported directory version;
//   - the reported SHA-256 is that of the server's directory document at
//     V, without its signatures (the current one, or the signer's
//     GetDirectoryVersion for an older one): the bytes the agent hashes
//     (apply/status.go) and a directory_install leaf records;
//   - in directory V, not the current one, no entry holds any of a's host
//     keys and no active entry carries its expected name (hostState is
//     removed).
//
// The report is the host's word: a fetcher that lies about it gets a
// confirmation recorded (T-03-284, accepted residual). It reports whether
// it recorded, and updates a when it did. A signer that cannot answer is
// an error, which the caller logs and skips; the next heartbeat or
// keyroster host pending runs the rule again.
func (s *Server) confirmRemoval(ctx context.Context, dv *directoryView, a *serverdb.Agent, seq int64, st *heartbeat.Status) (bool, error) {
	removal, reported := a.RemovedDirVersion, st.Directory
	if a.ApprovedAtUS == 0 || removal == 0 || a.RemovalConfirmedVersion != 0 || reported.Version < removal || reported.Version > dv.version || !principalsEmptied(st) {
		return false, nil
	}
	view, doc := dv, dv.doc
	if reported.Version != dv.version {
		cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
		d, err := s.signer.GetDirectoryVersion(cctx, reported.Version)
		cancel()
		if err != nil {
			return false, fmt.Errorf("directory version %d: %w", reported.Version, err)
		}
		if d.Version != reported.Version {
			return false, fmt.Errorf("the signer answered directory version %d for version %d", d.Version, reported.Version)
		}
		parsed, err := directory.Parse(d.Directory)
		if err != nil {
			return false, fmt.Errorf("directory version %d: %w", reported.Version, err)
		}
		view, doc = &directoryView{version: d.Version, dir: parsed}, d.Directory
	}
	if reported.SHA256 != trust.SHA256Hex(doc) {
		return false, nil
	}
	if _, st := hostState(view, a.HostKeys, a.ExpectedName); st != serverclient.HostStateRemoved {
		return false, nil
	}
	sum := sha256.Sum256(doc)
	recorded, err := s.db.RecordRemovalConfirmed(ctx, a.Key(), seq, removal, reported.Version, sum[:])
	if err != nil || !recorded {
		return false, err
	}
	a.RemovalConfirmedVersion, a.RemovalConfirmedSHA256 = reported.Version, sum[:]
	s.log.Info("agent removal confirmed", "expected_name", a.ExpectedName, "agent", agentFingerprint(a.IdentitySPKISHA256),
		"removal_version", removal, "directory_version", reported.Version, "directory_sha256", reported.SHA256)
	return true, nil
}

// hostState is the directory state of an agent with host keys keys and
// the expected name name: the name of the entry holding one of them, and
// HostStateActive when that entry is active with exactly keys,
// HostStateDisabled when it is disabled, HostStateKeysChanged when it is
// active with other keys. When no entry holds any of them, an active
// entry named name was re-keyed (HostStateKeysChanged, PR #72 review
// C14); otherwise "" and HostStateRemoved.
func hostState(dv *directoryView, keys []string, name string) (string, string) {
	if dv.dir == nil {
		return "", serverclient.HostStateRemoved
	}
	for _, k := range keys {
		pub, err := trust.ParseKey(k)
		if err != nil {
			continue
		}
		h, ok := dv.dir.HostForKey(pub)
		if !ok {
			continue
		}
		switch {
		case h.Status != directory.StatusActive:
			return h.Name, serverclient.HostStateDisabled
		case slices.Equal(h.Keys, keys):
			return h.Name, serverclient.HostStateActive
		default:
			return h.Name, serverclient.HostStateKeysChanged
		}
	}
	if rekeyed(dv, name) {
		return name, serverclient.HostStateKeysChanged
	}
	return "", serverclient.HostStateRemoved
}

// silentAfter is serverclient.SilentAfterS as a duration, and
// statusStaleAfter serverclient.StatusStaleAfterS.
const (
	silentAfter      = serverclient.SilentAfterS * time.Second
	statusStaleAfter = serverclient.StatusStaleAfterS * time.Second
)

// handleHostsStatus serves GET AdminHostsStatusPath (keyroster host
// status, admin-signed; 03-08, AGENT-07): the server's current bundle,
// directory and KRL versions, and per agent the directory approved once
// (a pending one is keyroster host pending's): its directory name and
// state, when it was last seen and whether that is more than 180 s ago
// on the server's clock (silent, D-10), and its newest heartbeat with
// never_applied and status_stale (its status more than two drift-check
// periods old while the host is seen; PR #72 review C2, C6), the newest
// clock offset with clock_skew (|clock_offset_s| > 300) and seq_regressed
// (owner decision D-R2). A removed,
// disabled or re-keyed agent that is still served shows its state, never
// as waiting for approval (03-08 carry-over a). An agent the current
// directory approves that has not got state since (approved_at_us unset)
// is listed too, marked not_yet_polled (03-08b owner decision D-R2), so
// keyroster host forget's name resolution sees every agent with a name;
// host pending lists it in neither of its lists. Convergence is the
// server's report, the host's own word through its heartbeat; the CLI
// says so and points to keyroster-agent check on the host.
func (s *Server) handleHostsStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	dv, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("directory read failed", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	k, err := s.krlItem(ctx, 0)
	if err != nil {
		s.log.Warn("hosts status: KRL", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	// One read: an agent's first request lands between two separate
	// reads as approved_at_us unset with a heartbeat stored, a row the CLI
	// refuses (not_yet_polled with a heartbeat).
	agents, hbs, err := s.db.AgentsAndHeartbeats(ctx)
	if err != nil {
		s.log.Error("list agents and heartbeats", "err", err)
		s.writeJSON(w, v, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	out := serverclient.HostsStatusAnswer{Current: serverclient.HostVersions{Bundle: v.raw.BundleVersion, Directory: dv.version}, Hosts: []serverclient.HostStatusRow{}}
	if out.Current.Bundle != 0 {
		out.Current.BundleSHA256 = trust.SHA256Hex(v.raw.Bundle)
	}
	if dv.version != 0 {
		out.Current.DirectorySHA256 = trust.SHA256Hex(dv.doc)
	}
	if k != nil {
		out.Current.KRL, out.Current.KRLSHA256 = k.Version, trust.SHA256Hex(k.KRL)
	}
	now := s.clock()
	for _, a := range agents {
		notPolled := a.ApprovedAtUS == 0
		if notPolled && !approved(dv, a.HostKeys) {
			continue // pending: keyroster host pending's
		}
		name, st := hostState(dv, a.HostKeys, a.ExpectedName)
		if name == "" {
			name = a.ExpectedName
		}
		row := serverclient.HostStatusRow{Name: name, ExpectedName: a.ExpectedName, IdentitySPKISHA256: hex.EncodeToString(a.IdentitySPKISHA256),
			State: st, Silent: true, NeverApplied: true, NotYetPolled: notPolled, IdentityRotations: a.IdentityRotations}
		if a.IdentityRotatedAtUS != 0 {
			row.IdentityRotatedAt = time.UnixMicro(a.IdentityRotatedAtUS).UTC().Format(time.RFC3339)
		}
		if a.LastSeenUS != 0 {
			seen := time.UnixMicro(a.LastSeenUS)
			row.LastSeen = seen.UTC().Format(time.RFC3339)
			row.Silent = now.Sub(seen) > silentAfter
		}
		if hb, ok := hbs[a.ID]; ok {
			h, err := heartbeat.ParseHeartbeat(hb.Body)
			if err != nil {
				s.log.Error("stored heartbeat does not parse", "agent", agentFingerprint(a.IdentitySPKISHA256), "field", heartbeat.Field(err))
			} else {
				row.Heartbeat = h
				row.ReceivedAt = time.UnixMicro(hb.ReceivedAtUS).UTC().Format(time.RFC3339)
				row.ClockOffsetS = h.ClockOffsetS
				row.NeverApplied = h.Status.Generation == 0
				row.SeqRegressed = !row.Silent && a.SeqRegressedAtUS > hb.ReceivedAtUS
				row.StatusStale = !row.Silent && now.Sub(time.UnixMicro(hb.ReceivedAtUS)) > statusStaleAfter
			}
		}
		// The newest offset any heartbeat carried, refused ones too (D-R2).
		if a.ClockOffsetKnown {
			row.ClockOffsetS = a.ClockOffsetS
		}
		row.ClockSkew = heartbeat.ClockSkew(row.ClockOffsetS)
		out.Hosts = append(out.Hosts, row)
	}
	s.writeJSON(w, dv.status, http.StatusOK, out)
}
