package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/trust"
)

const (
	// maxAgentEnrollBody bounds an enrollment request: eight host keys,
	// their signatures and the facts fit in a few KiB.
	maxAgentEnrollBody = 16 << 10
	// agentPerMinute and agentBurst are the per-identity rate of the state
	// route for enrolled agents; the global backstop is agentGlobalFactor
	// times them. The burst is the fetcher's rounds per poll, so a host
	// catching up through `more` is never refused inside one poll (PR #71
	// review F4).
	agentPerMinute    = 30
	agentBurst        = serverclient.MaxAgentStateRounds
	agentGlobalFactor = 100
	// agentAnonPerMinute and agentAnonBurst are the per-address rate of
	// enrollment and of state requests from identities the server does
	// not know; their global backstop is globalFactor times them (PR #71
	// review F1/F2).
	agentAnonPerMinute = 30
	agentAnonBurst     = 10
)

// newAgentLimiters returns the two limiter classes of the agent routes
// (PR #71 review F1/F2). A self-signed identity costs nothing to make, so
// it buys no budget: only an enrolled agent's state requests are charged
// to agent, per identity (the client certificate's SPKI hash) with its
// global backstop; enrollment and state requests from an identity no
// agents row names are charged to anon, per client address (clientKey)
// with a global backstop of its own. No amount of unknown traffic can
// then spend the budget enrolled agents poll with.
func newAgentLimiters() (agent, anon *limiter) {
	return newLimiter(agentPerMinute, agentBurst, agentGlobalFactor*agentPerMinute, agentGlobalFactor*agentBurst),
		newLimiter(agentAnonPerMinute, agentAnonBurst, globalFactor*agentAnonPerMinute, globalFactor*agentAnonBurst)
}

// buildAgentMux registers the closed set of agent routes (AGENT-02) on
// their own mux, served only by the agent listener (AgentHandler): the
// enrollment and the state. Each takes the client certificate's identity
// from the TLS connection (AgentTLSConfig required one at the handshake).
// Enrollment goes through the anonymous limiter; the state route through
// requireAgent, which picks the class by whether the identity is
// enrolled.
func (s *Server) buildAgentMux() *routeMux {
	mux := newRouteMux()
	mux.Handle("POST "+serverclient.AgentEnrollPath, s.agentAnonLimited(http.HandlerFunc(s.handleAgentEnroll)))
	mux.Handle("GET "+serverclient.AgentStatePath, s.requireAgent(s.handleAgentState))
	return mux
}

// AgentHandler is the handler of the agent listener: the agent routes
// only, with the security headers. It serves nothing without the TLS
// configuration of AgentTLSConfig in front of it.
func (s *Server) AgentHandler() http.Handler { return s.agentHandler }

// agentAnonLimited applies the anonymous agent limiter, keyed by the
// client address; a request without a client certificate is refused 403.
func (s *Server) agentAnonLimited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := agentSPKI(r); !ok {
			s.writeJSON(w, nil, http.StatusForbidden, serverclient.APIError{Error: serverclient.AgentErrUnknown})
			return
		}
		if s.agentAllow(w, r, s.agentAnonLimit, clientKey(r), "client", clientKey(r)) {
			next.ServeHTTP(w, r)
		}
	})
}

// agentAllow charges one request to l under key. A refused request gets
// 429 with Retry-After and a log line naming who (what, value).
func (s *Server) agentAllow(w http.ResponseWriter, r *http.Request, l *limiter, key, what, value string) bool {
	if l.allow(key, s.clock()) {
		return true
	}
	s.log.Warn("rate limited", "route", r.Pattern, what, value)
	w.Header().Set("Retry-After", strconv.Itoa(l.retryAfter()))
	s.writeJSON(w, nil, http.StatusTooManyRequests, serverclient.APIError{Error: "rate limited"})
	return false
}

// agentFingerprint is the identity as keyroster-agent identity and
// keyroster host approve print it (enroll.IdentityFingerprint).
func agentFingerprint(spki []byte) string { return enroll.IdentityFingerprint(spki) }

// popHostsEnabled reports whether the installed root-signed policy sets
// pop.hosts. Minting, enrollment and the pending list refuse
// host_pop_not_enabled without it (owner decision 2026-10-24).
func popHostsEnabled(v *statusView) bool { return v.policy.PoP != nil && v.policy.PoP.Hosts }

// agentRequest is one request requireAgent admitted: the enrolled agent,
// and the status and directory it was approved under.
type agentRequest struct {
	agent  *serverdb.Agent
	status *statusView
	dir    *directoryView
}

// requireAgent admits a request only from an enrolled agent that was
// approved: the client certificate's SPKI hash must name an agents row
// (else 403 unknown_agent), and the installed directory must hold an
// active host entry whose keys equal that agent's enrolled host keys, or
// have held one when the agent last got state (else 403 not_approved).
// The approval is the admin-signed directory itself; the server records
// only when the agent first got state under it (approved_at_us). It
// updates the agent's last_seen_us.
//
// The agent is looked up before any rate limit is charged (PR #71 review
// F1/F2): an identity no agents row names is charged to the anonymous
// class by its client address, and only an enrolled one to the agent
// class by its identity.
func (s *Server) requireAgent(next func(http.ResponseWriter, *http.Request, *agentRequest)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		spki, ok := agentSPKI(r)
		if !ok {
			s.writeJSON(w, nil, http.StatusForbidden, serverclient.APIError{Error: serverclient.AgentErrUnknown})
			return
		}
		a, err := s.db.AgentBySPKI(ctx, spki)
		if errors.Is(err, serverdb.ErrNotFound) {
			if !s.agentAllow(w, r, s.agentAnonLimit, clientKey(r), "client", clientKey(r)) {
				return
			}
			v, _ := s.currentStatus(ctx)
			s.writeJSON(w, v, http.StatusForbidden, serverclient.APIError{Error: serverclient.AgentErrUnknown})
			return
		}
		if err != nil {
			s.log.Error("agent lookup", "err", err)
			s.writeJSON(w, nil, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
			return
		}
		if !s.agentAllow(w, r, s.agentLimit, hex.EncodeToString(spki), "agent", agentFingerprint(spki)) {
			return
		}
		dv, err := s.currentDirectory(ctx)
		if err != nil {
			s.log.Warn("directory read failed", "err", err)
			s.signerUnavailable(w, false)
			return
		}
		// An agent the directory approved once keeps getting signed state
		// after its host entry is disabled or removed, so the removal
		// itself and every later revocation reach the host; only an agent
		// never approved is refused (PR #71 review D-R1). keyroster host
		// forget deletes the row and ends it.
		switch {
		case approved(dv, a.HostKeys):
			if a.ApprovedAtUS == 0 {
				if err := s.db.MarkAgentApproved(ctx, a.ID, s.clock().UnixMicro()); err != nil {
					s.log.Error("agent approval", "err", err)
					s.writeJSON(w, nil, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
					return
				}
				s.log.Info("agent approved: first signed state", "expected_name", a.ExpectedName, "agent", agentFingerprint(spki))
			}
		case a.ApprovedAtUS == 0:
			s.writeJSON(w, dv.status, http.StatusForbidden, serverclient.APIError{Error: serverclient.AgentErrNotApproved})
			return
		}
		if err := s.db.TouchAgent(ctx, a.ID, s.clock().UnixMicro()); err != nil {
			s.log.Warn("agent last seen", "err", err)
		}
		next(w, r, &agentRequest{agent: a, status: dv.status, dir: dv})
	})
}

// approved reports whether the directory dv holds an active host entry
// whose keys are exactly keys (both sorted trust.FormatKey lists). The
// entry is found by its first key (HostForKey: a key is on at most one
// host).
func approved(dv *directoryView, keys []string) bool {
	if dv.dir == nil || len(keys) == 0 {
		return false
	}
	pub, err := trust.ParseKey(keys[0])
	if err != nil {
		return false
	}
	h, ok := dv.dir.HostForKey(pub)
	return ok && h.Status == directory.StatusActive && slices.Equal(h.Keys, keys)
}

// handleAgentEnroll serves POST AgentEnrollPath: one agent records itself
// as pending with a one-time join token (AGENT-01). In order:
//  1. the installed policy must set pop.hosts (409 host_pop_not_enabled),
//     before the token is looked at;
//  2. the body, at most maxAgentEnrollBody, decoded strictly;
//  3. the proof of possession (enroll.Verify) the server rebuilds from the
//     token's hash, the TLS identity, the signer's installation ID, the
//     host keys and the facts' hash: every host key must have signed it
//     (403 enroll_pop_invalid);
//  4. a retry of an enrollment this server already recorded, with the
//     same token, identity and host keys (its 202 was lost), is answered
//     202 again, before the checks below, which the recorded enrollment
//     itself (its host approved since, its token used) would fail (PR #71
//     review F11);
//  5. no host key on a directory host entry (409 host_keys_in_use);
//  6. in one transaction (serverdb.EnrollAgent): the token known, unused
//     and unexpired (403 token_unknown, token_used, token_expired), the
//     identity not enrolled (409 identity_in_use), no host key on another
//     agent (409 host_keys_in_use), the token used and the agent recorded.
//
// Nothing the agent sends becomes a name, host group or principal: the
// row keeps the host name the admin gave the token.
func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
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
	var req serverclient.AgentEnrollRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAgentEnrollBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	spki, _ := agentSPKI(r)
	raw, err := join.DecodeToken(req.Token)
	if err != nil {
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	if err := enroll.CheckFacts(req.Facts); err != nil {
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	factsSum, err := enroll.FactsSHA256(req.Facts)
	if err != nil {
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	bundle, err := trust.ParseBundle(v.raw.Bundle)
	if err != nil {
		s.log.Error("the signer's trust bundle does not parse", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	pop := enroll.PoP{
		Domain: enroll.Domain, InstallationID: bundle.InstallationID, TokenSHA256: join.TokenSHA256(raw),
		IdentitySPKISHA256: hex.EncodeToString(spki), HostKeys: req.HostKeys, FactsSHA256: factsSum,
	}
	if err := enroll.Verify(pop, nil, req.Sigs); err != nil {
		s.log.Warn("agent enrollment refused", "agent", agentFingerprint(spki), "reason", err.Error())
		s.writeJSON(w, v, http.StatusForbidden, serverclient.APIError{Error: serverclient.AgentErrPoPInvalid})
		return
	}
	hash := sha256.Sum256(raw)
	switch prior, err := s.db.AgentBySPKI(ctx, spki); {
	case err == nil && bytes.Equal(prior.TokenSHA256, hash[:]) && slices.Equal(prior.HostKeys, req.HostKeys):
		s.log.Info("agent enrollment retried, already recorded", "expected_name", prior.ExpectedName, "agent", agentFingerprint(spki))
		s.writeJSON(w, v, http.StatusAccepted, serverclient.AgentEnrollAnswer{ExpectedName: prior.ExpectedName, Status: "pending"})
		return
	case err != nil && !errors.Is(err, serverdb.ErrNotFound):
		s.log.Error("agent lookup", "err", err)
		s.writeJSON(w, v, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	dv, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("directory read failed", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	if dv.dir != nil {
		for _, k := range req.HostKeys {
			pub, _ := trust.ParseKey(k) // enroll.Verify parsed it
			if _, ok := dv.dir.HostForKey(pub); ok {
				s.writeJSON(w, v, http.StatusConflict, serverclient.APIError{Error: serverclient.AgentErrHostKeysInUse})
				return
			}
		}
	}
	facts, err := json.Marshal(req.Facts)
	if err != nil {
		s.writeJSON(w, v, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	a, err := s.db.EnrollAgent(ctx, hash[:], serverdb.Agent{IdentitySPKISHA256: spki, HostKeys: req.HostKeys, Facts: string(facts)},
		s.clock().Truncate(time.Second).UnixMicro())
	if err != nil {
		code, msg := http.StatusInternalServerError, "internal error"
		switch {
		case errors.Is(err, serverdb.ErrTokenUnknown):
			code, msg = http.StatusForbidden, serverclient.AgentErrTokenUnknown
		case errors.Is(err, serverdb.ErrTokenUsed):
			code, msg = http.StatusForbidden, serverclient.AgentErrTokenUsed
		case errors.Is(err, serverdb.ErrTokenExpired):
			code, msg = http.StatusForbidden, serverclient.AgentErrTokenExpired
		case errors.Is(err, serverdb.ErrIdentityInUse):
			code, msg = http.StatusConflict, serverclient.AgentErrIdentityInUse
		case errors.Is(err, serverdb.ErrHostKeysInUse):
			code, msg = http.StatusConflict, serverclient.AgentErrHostKeysInUse
		default:
			s.log.Error("agent enrollment", "err", err)
		}
		if code != http.StatusInternalServerError {
			s.log.Warn("agent enrollment refused", "agent", agentFingerprint(spki), "reason", msg)
		}
		s.writeJSON(w, v, code, serverclient.APIError{Error: msg})
		return
	}
	s.log.Info("agent enrolled, pending approval", "expected_name", a.ExpectedName, "agent", agentFingerprint(spki), "host_keys", len(a.HostKeys))
	s.writeJSON(w, v, http.StatusAccepted, serverclient.AgentEnrollAnswer{ExpectedName: a.ExpectedName, Status: "pending"})
}

// versionRE is one version in a state query: decimal from 1, no leading
// zero, at most 20 digits (ParseUint then bounds it to uint64).
var versionRE = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// parseVersions reads a state query: only bundle, directory and krl, each
// at most once and a version from 1; an empty, repeated, malformed or
// unknown parameter is an error (400).
func parseVersions(r *http.Request) (serverclient.AgentVersions, bool) {
	var v serverclient.AgentVersions
	q := r.URL.Query()
	for name, vals := range q {
		var dst *uint64
		switch name {
		case "bundle":
			dst = &v.Bundle
		case "directory":
			dst = &v.Directory
		case "krl":
			dst = &v.KRL
		default:
			return v, false
		}
		if len(vals) != 1 || !versionRE.MatchString(vals[0]) {
			return v, false
		}
		n, err := strconv.ParseUint(vals[0], 10, 64)
		if err != nil {
			return v, false
		}
		*dst = n
	}
	return v, true
}

// handleAgentState serves GET AgentStatePath to an approved agent: every
// bundle and directory above the versions it sent, ascending (bundleItems,
// directoryItems), and the KRL when newer, from what the server holds
// (currentStatus, currentDirectory and currentKRL, which keeps every KRL
// in krl-served.json before any route serves it, 03-06b). With no
// versions it is the current state only. The answer is filled within
// s.agentStateBudget (fillAgentState).
func (s *Server) handleAgentState(w http.ResponseWriter, r *http.Request, ar *agentRequest) {
	ctx := r.Context()
	since, ok := parseVersions(r)
	if !ok {
		s.writeJSON(w, ar.status, http.StatusBadRequest, serverclient.APIError{Error: serverclient.AgentErrMalformed})
		return
	}
	bundles, bundlesCut, err := s.bundleItems(ctx, ar.status, since.Bundle)
	if err != nil {
		s.log.Warn("agent state: bundles", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	dirs, dirsCut, err := s.directoryItems(ctx, ar.dir, since.Directory)
	if err != nil {
		s.log.Warn("agent state: directories", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	k, err := s.krlItem(ctx, since.KRL)
	if err != nil {
		s.log.Warn("agent state: KRL", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	body, err := fillAgentState(bundles, dirs, k, bundlesCut || dirsCut, s.agentStateBudget)
	if err != nil {
		s.log.Error("agent state", "err", err)
		s.writeJSON(w, nil, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	w.Header().Set(serverclient.CustodyHeader, ar.status.custody)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// bundleItems returns the bundles above since, ascending: with no version
// (since 0) the current one only (currentStatus); otherwise every version
// from since+1, at most serverclient.MaxAgentStatePerKind of them, each
// but the current read from the signer (GetBundle). cut reports versions
// left out by that cap. An agent ahead of the server gets none.
func (s *Server) bundleItems(ctx context.Context, v *statusView, since uint64) ([]serverclient.AgentBundle, bool, error) {
	cur := v.raw.BundleVersion
	if cur <= since {
		return nil, false, nil
	}
	current := serverclient.AgentBundle{
		Version: cur, Bundle: v.raw.Bundle, BundleSigs: v.raw.BundleSigs,
		PolicyVersion: v.policy.Version, Policy: v.raw.Policy, PolicySigs: v.raw.PolicySigs,
	}
	if since == 0 {
		return []serverclient.AgentBundle{current}, false, nil
	}
	var out []serverclient.AgentBundle
	ver := since + 1
	for ; ver <= cur && len(out) < serverclient.MaxAgentStatePerKind; ver++ {
		if ver == cur {
			out = append(out, current)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
		b, err := s.signer.GetBundle(cctx, ver)
		cancel()
		if err != nil {
			return nil, false, fmt.Errorf("bundle version %d: %w", ver, err)
		}
		if b.Version != ver {
			return nil, false, fmt.Errorf("the signer answered bundle version %d for version %d", b.Version, ver)
		}
		pol, err := trust.ParsePolicy(b.Policy)
		if err != nil {
			return nil, false, fmt.Errorf("bundle version %d: policy: %w", ver, err)
		}
		out = append(out, serverclient.AgentBundle{Version: ver, Bundle: b.Bundle, BundleSigs: b.BundleSigs,
			PolicyVersion: pol.Version, Policy: b.Policy, PolicySigs: b.PolicySigs})
	}
	return out, ver <= cur, nil
}

// directoryItems returns the directories above since, as bundleItems does
// for bundles: the current one (currentDirectory) only with no version,
// otherwise every version from since+1, at most MaxAgentStatePerKind, each
// but the current read from the signer (GetDirectoryVersion).
func (s *Server) directoryItems(ctx context.Context, dv *directoryView, since uint64) ([]serverclient.AgentDirectory, bool, error) {
	cur := dv.version
	if cur == 0 || cur <= since {
		return nil, false, nil
	}
	current := serverclient.AgentDirectory{Version: cur, Directory: dv.doc, Sigs: dv.sigs}
	if since == 0 {
		return []serverclient.AgentDirectory{current}, false, nil
	}
	var out []serverclient.AgentDirectory
	ver := since + 1
	for ; ver <= cur && len(out) < serverclient.MaxAgentStatePerKind; ver++ {
		if ver == cur {
			out = append(out, current)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
		d, err := s.signer.GetDirectoryVersion(cctx, ver)
		cancel()
		if err != nil {
			return nil, false, fmt.Errorf("directory version %d: %w", ver, err)
		}
		if d.Version != ver {
			return nil, false, fmt.Errorf("the signer answered directory version %d for version %d", d.Version, ver)
		}
		out = append(out, serverclient.AgentDirectory{Version: ver, Directory: d.Directory, Sigs: d.Sigs})
	}
	return out, ver <= cur, nil
}

// krlItem returns the published KRL when its version is above since, or
// nil. It comes only through currentKRL, which keeps it in krl-served.json
// first: a KRL reaches no host that no signer restore could recover.
func (s *Server) krlItem(ctx context.Context, since uint64) (*serverclient.AgentKRL, error) {
	resp, err := s.currentKRL(ctx)
	if err != nil {
		return nil, err
	}
	if len(resp.KRL) == 0 {
		return nil, nil
	}
	m, err := krl.ParseManifest(resp.Manifest)
	if err != nil {
		return nil, err
	}
	if m.KRLVersion <= since {
		return nil, nil
	}
	return &serverclient.AgentKRL{Version: m.KRLVersion, KRL: resp.KRL, Manifest: resp.Manifest, Sig: resp.Sig}, nil
}

// agentStateEnvelope is the encoded answer with no item and more false,
// as encodeAgentState writes it.
var agentStateEnvelope = len(`{"bundles":[],"directories":[],"krl":null,"more":false}` + "\n")

// fillAgentState encodes the state answer within budget bytes (F12):
// bundles, then directories, then the KRL, in that fixed order, each kept
// only while the encoded answer stays within budget; the first item is
// kept whatever its size, and filling stops at the first item that does
// not fit. more is set when an item was left out here or by the caller
// (cut). The answer is encoded by encodeAgentState, so its size is exactly
// what the budget counted.
func fillAgentState(bundles []serverclient.AgentBundle, dirs []serverclient.AgentDirectory, k *serverclient.AgentKRL, cut bool, budget int) ([]byte, error) {
	var encB, encD [][]byte
	var encK []byte
	size := agentStateEnvelope
	more := cut
	n := 0
	add := func(item any, list *[][]byte, single *[]byte) (bool, error) {
		b, err := json.Marshal(item)
		if err != nil {
			return false, err
		}
		grow := len(b)
		switch {
		case single != nil:
			grow -= len("null")
		case len(*list) > 0:
			grow++ // the comma
		}
		if n > 0 && size+grow > budget {
			return false, nil
		}
		size += grow
		n++
		if single != nil {
			*single = b
		} else {
			*list = append(*list, b)
		}
		return true, nil
	}
	stopped := false
	for _, b := range bundles {
		ok, err := add(b, &encB, nil)
		if err != nil {
			return nil, err
		}
		if !ok {
			stopped = true
			break
		}
	}
	for _, d := range dirs {
		if stopped {
			break
		}
		ok, err := add(d, &encD, nil)
		if err != nil {
			return nil, err
		}
		if !ok {
			stopped = true
		}
	}
	if k != nil && !stopped {
		ok, err := add(k, nil, &encK)
		if err != nil {
			return nil, err
		}
		stopped = !ok
	}
	if stopped {
		more = true
	}
	return encodeAgentState(encB, encD, encK, more), nil
}

// encodeAgentState writes the state answer from its encoded items, as
// json.Marshal of serverclient.AgentStateResponse would (empty lists as
// [], no KRL as null), with the final newline writeJSON adds.
func encodeAgentState(bundles, dirs [][]byte, k []byte, more bool) []byte {
	var b bytes.Buffer
	b.WriteString(`{"bundles":[`)
	b.Write(bytes.Join(bundles, []byte(",")))
	b.WriteString(`],"directories":[`)
	b.Write(bytes.Join(dirs, []byte(",")))
	b.WriteString(`],"krl":`)
	if k == nil {
		b.WriteString("null")
	} else {
		b.Write(k)
	}
	b.WriteString(`,"more":` + strconv.FormatBool(more) + "}\n")
	return b.Bytes()
}
