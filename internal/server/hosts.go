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
