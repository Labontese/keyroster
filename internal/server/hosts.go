package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
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
// active directory host entry with exactly its host keys approves. The
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
	out := serverclient.PendingHostsAnswer{Hosts: []serverclient.PendingHost{}}
	for _, a := range agents {
		if approved(dv, a.HostKeys) {
			continue
		}
		var f enroll.Facts
		if err := json.Unmarshal([]byte(a.Facts), &f); err != nil {
			s.log.Error("agent facts", "agent", a.ID, "err", err)
			continue
		}
		out.Hosts = append(out.Hosts, serverclient.PendingHost{
			ExpectedName: a.ExpectedName, IdentitySPKISHA256: hex.EncodeToString(a.IdentitySPKISHA256), HostKeys: a.HostKeys,
			Facts: f, EnrolledAt: time.UnixMicro(a.EnrolledAtUS).UTC().Format(time.RFC3339),
		})
	}
	s.log.Info("pending hosts listed", "admin", adminName(ctx), "count", len(out.Hosts))
	s.writeJSON(w, dv.status, http.StatusOK, out)
}

// handleForgetHost serves POST AdminForgetHostPath (keyroster host forget,
// admin-signed; PR #71 review D-R1): it deletes every agent enrolled under
// the host name, so its identity gets 403 unknown_agent from then on and
// its host keys can enroll again with a new join token. It is refused 409
// host_in_directory while any directory host entry, active or disabled,
// holds a host key of one of them: forgetting an agent whose host is
// still in the directory would stop the signed state, revocations
// included, that host still needs. The runbook order is: remove the host
// from the directory, let the host apply that version, then forget. 404
// host_not_enrolled when no agent has the name.
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
	var forget []serverdb.Agent
	for _, a := range agents {
		if a.ExpectedName != req.ExpectedName {
			continue
		}
		if dv.dir != nil {
			for _, k := range a.HostKeys {
				pub, err := trust.ParseKey(k)
				if err != nil {
					continue
				}
				if _, ok := dv.dir.HostForKey(pub); ok {
					s.writeJSON(w, dv.status, http.StatusConflict, serverclient.APIError{Error: serverclient.AdminErrHostInDirectory})
					return
				}
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
		s.log.Info("agent forgotten", "expected_name", a.ExpectedName, "agent", agentFingerprint(a.IdentitySPKISHA256), "admin", adminName(ctx))
		out.Forgotten = append(out.Forgotten, serverclient.PendingHost{
			ExpectedName: a.ExpectedName, IdentitySPKISHA256: hex.EncodeToString(a.IdentitySPKISHA256), HostKeys: a.HostKeys,
			Facts: f, EnrolledAt: time.UnixMicro(a.EnrolledAtUS).UTC().Format(time.RFC3339),
		})
	}
	s.writeJSON(w, dv.status, http.StatusOK, out)
}
