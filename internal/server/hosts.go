package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/trust"
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
// pending and host approve, admin-signed): every enrolled agent that no
// active directory host entry with exactly its host keys approves. An
// agent the directory approved once is never pending again: it is listed
// under Served with its directory state (removed, disabled or
// keys_changed) and keeps getting signed state until keyroster host
// forget, so host approve can never pick its identity (03-08 carry-over
// a, owner decision 2026-10-28). The policy must set pop.hosts (409
// host_pop_not_enabled).
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
		if a.ApprovedAtUS != 0 {
			_, st := hostState(dv, a.HostKeys, a.ExpectedName)
			out.Served = append(out.Served, serverclient.ServedHost{PendingHost: p, State: st})
			continue
		}
		out.Hosts = append(out.Hosts, p)
	}
	s.log.Info("pending hosts listed", "admin", adminName(ctx), "count", len(out.Hosts), "served", len(out.Served))
	s.writeJSON(w, dv.status, http.StatusOK, out)
}

// handleForgetHost serves POST AdminForgetHostPath (keyroster host forget,
// admin-signed; PR #71 review D-R1): it deletes every agent enrolled under
// the host name, so its identity gets 403 unknown_agent from then on and
// its host keys can enroll again with a new join token. It is refused,
// deleting nothing:
//   - 409 host_in_directory while any directory host entry, active or
//     disabled, holds a host key of one of them: forgetting an agent whose
//     host is still in the directory would stop the signed state,
//     revocations included, that host still needs;
//   - 409 host_removal_not_applied (03-08, owner decision 2026-10-28) for
//     an agent approved once until its newest heartbeat shows a committed
//     directory version at or above removed_dir_version, the first
//     version it was served under that no longer approved it, and that
//     directory is one the server served: not above the current version,
//     with the SHA-256 of the server's directory at that number
//     (removalApplied, PR #72 review C4). The host has then applied its
//     own removal. The request's host_gone overrides
//     this for a host that will never report again; the server logs it at
//     warning level. An agent never approved has no removal to wait for.
//
// 404 host_not_enrolled when no agent has the name. Forget is one admin's
// action and leaves a server log line only; the admin quorum and an audit
// leaf for forget and for host_gone are 03-08b's (owner decision D-1).
func (s *Server) handleForgetHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req serverclient.ForgetHostRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() || !directory.ValidUserName(req.ExpectedName) {
		s.writeJSON(w, nil, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
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
		s.writeJSON(w, dv.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	hbs, err := s.db.Heartbeats(ctx)
	if err != nil {
		s.log.Error("heartbeats", "err", err)
		s.writeJSON(w, dv.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	var forget []serverdb.Agent
	for _, a := range agents {
		if a.ExpectedName != req.ExpectedName {
			continue
		}
		if hostHolds(dv, a.HostKeys) {
			s.writeJSON(w, dv.status, http.StatusConflict, serverclient.APIError{Error: serverclient.AdminErrHostInDirectory})
			return
		}
		if a.ApprovedAtUS != 0 && !req.HostGone {
			var reported heartbeat.Doc
			if hb, ok := hbs[a.ID]; ok {
				if h, err := heartbeat.ParseHeartbeat(hb.Body); err == nil {
					reported = h.Status.Directory
				}
			}
			why, err := s.removalApplied(ctx, dv, a.RemovedDirVersion, reported)
			if err != nil {
				s.log.Warn("forget: directory read failed", "err", err)
				s.signerUnavailable(w, false)
				return
			}
			if why != "" {
				s.log.Warn("forget refused", "expected_name", a.ExpectedName, "agent", agentFingerprint(a.IdentitySPKISHA256), "admin", adminName(ctx),
					"reason", serverclient.AdminErrRemovalNotApplied, "detail", why, "removal_version", a.RemovedDirVersion,
					"reported_directory_version", reported.Version, "reported_directory_sha256", reported.SHA256)
				s.writeJSON(w, dv.status, http.StatusConflict, serverclient.APIError{Error: serverclient.AdminErrRemovalNotApplied})
				return
			}
		}
		forget = append(forget, a)
	}
	if len(forget) == 0 {
		s.writeJSON(w, dv.status, http.StatusNotFound, serverclient.APIError{Error: serverclient.AdminErrHostNotEnrolled})
		return
	}
	out := serverclient.ForgetHostAnswer{Forgotten: []serverclient.PendingHost{}}
	for _, a := range forget {
		if err := s.db.DeleteAgent(ctx, a.ID); err != nil {
			s.log.Error("forget agent", "agent", a.ID, "err", err)
			s.writeJSON(w, dv.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
			return
		}
		var f enroll.Facts
		_ = json.Unmarshal([]byte(a.Facts), &f) // stored by enrollment, which checked them
		if req.HostGone && a.ApprovedAtUS != 0 {
			s.log.Warn("agent forgotten with --host-gone: the host never confirmed that it applied its removal", "expected_name", a.ExpectedName,
				"agent", agentFingerprint(a.IdentitySPKISHA256), "admin", adminName(ctx), "removal_version", a.RemovedDirVersion)
		} else {
			s.log.Info("agent forgotten", "expected_name", a.ExpectedName, "agent", agentFingerprint(a.IdentitySPKISHA256), "admin", adminName(ctx))
		}
		out.Forgotten = append(out.Forgotten, serverclient.PendingHost{
			ExpectedName: a.ExpectedName, IdentitySPKISHA256: hex.EncodeToString(a.IdentitySPKISHA256), HostKeys: a.HostKeys,
			Facts: f, EnrolledAt: time.UnixMicro(a.EnrolledAtUS).UTC().Format(time.RFC3339),
		})
	}
	s.writeJSON(w, dv.status, http.StatusOK, out)
}

// removalApplied is forget's removal wait for one agent (PR #72 review
// C4): "" when the directory the host reported is at or above removal,
// not above the current version, and has the SHA-256 of the server's
// directory at that number (the current one, or the signer's
// GetDirectoryVersion for an older one); otherwise why not. A signer
// that cannot answer is an error: forget then refuses, it never guesses.
func (s *Server) removalApplied(ctx context.Context, dv *directoryView, removal uint64, reported heartbeat.Doc) (string, error) {
	switch {
	case removal == 0:
		return "no removal recorded", nil
	case reported.Version < removal:
		return "reported directory below the removal version", nil
	case reported.Version > dv.version:
		return "reported directory above the current version", nil
	}
	want := ""
	if reported.Version == dv.version {
		want = trust.SHA256Hex(dv.doc)
	} else {
		cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
		d, err := s.signer.GetDirectoryVersion(cctx, reported.Version)
		cancel()
		if err != nil {
			return "", fmt.Errorf("directory version %d: %w", reported.Version, err)
		}
		if d.Version != reported.Version {
			return "", fmt.Errorf("the signer answered directory version %d for version %d", d.Version, reported.Version)
		}
		want = trust.SHA256Hex(d.Directory)
	}
	if reported.SHA256 != want {
		return "reported directory differs from the server's under that version", nil
	}
	return "", nil
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
// as waiting for approval (03-08 carry-over a). Convergence is the
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
		if a.ApprovedAtUS == 0 {
			continue
		}
		name, st := hostState(dv, a.HostKeys, a.ExpectedName)
		if name == "" {
			name = a.ExpectedName
		}
		row := serverclient.HostStatusRow{Name: name, ExpectedName: a.ExpectedName, IdentitySPKISHA256: hex.EncodeToString(a.IdentitySPKISHA256),
			State: st, Silent: true, NeverApplied: true, IdentityRotations: a.IdentityRotations}
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
