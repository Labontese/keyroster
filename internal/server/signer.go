package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// signerAPI is the only way from a handler in this package to the signer.
// socketSigner is the production side and fakeSigner (server_test.go) the
// one test double. This file is the only one in the package that imports
// signerclient.
//
// Growth rule: a later plan that needs another signer call adds that
// method here, to socketSigner and to fakeSigner, in the commit that adds
// its first caller (GetDirectory in 02-07, InstallDirectory in 02-09,
// Login in 02-12, Revoke and GetKRL in 03-01, GetBundle and
// GetDirectoryVersion in 03-07, ForgetAgent in 03-08c). Nobody adds a second
// interface, and no method is added before something calls it.
//
// F11 (03-08g): a new method also goes through budgetSigner, in the same
// commit; budgetSigner's named field makes the build fail until it does. A
// call relayed for a host agent takes the agent share (the agent-share
// rule, owner decision 2026-10-30). A call may skip the budget only if it
// takes no lock on the signer and is coalesced to one call in flight, as
// GetKRL is. An agent route that relays a signer call takes agentSlot
// after requireAgent, as the state and heartbeat routes do.
type signerAPI interface {
	Status(ctx context.Context) (*wire.StatusResponse, error)
	GetDirectory(ctx context.Context) (*wire.GetDirectoryResponse, error)
	InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error)
	// Login asks the signer to issue a login certificate (02-12). Only
	// the redeem handler calls it, after the code and PKCE verifier have
	// been redeemed; a refusal comes back as a *wire.ErrorResponse. ctx's
	// deadline bounds sending the request only: the answer is read for up
	// to signerCallTimeout after the send (03-02 pre-merge review).
	Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error)
	// Revoke forwards an admin-signed revocation request unchanged
	// (03-01); the signer alone decides. A refusal comes back as a
	// *wire.ErrorResponse.
	Revoke(ctx context.Context, req *wire.RevokeRequest) (*wire.RevokeResponse, error)
	// GetKRL reads the published KRL, its manifest and signature (03-01).
	GetKRL(ctx context.Context) (*wire.GetKRLResponse, error)
	// GetBundle and GetDirectoryVersion read one installed trust bundle
	// or directory by version (03-07), for an agent's state answer; an
	// absent version is refused not_found.
	GetBundle(ctx context.Context, v uint64) (*wire.GetBundleResponse, error)
	GetDirectoryVersion(ctx context.Context, v uint64) (*wire.GetDirectoryVersionResponse, error)
	// ForgetAgent relays an admin-signed forget request with the server's
	// own statement of its row (ServerApprovedOnce, 03-08c); the signer
	// alone decides and logs it. A refusal comes back as a
	// *wire.ErrorResponse.
	ForgetAgent(ctx context.Context, req *wire.ForgetRequest) (*wire.ForgetResponse, error)
}

// socketSigner reaches keyroster-signer over its Unix socket. Every call
// goes through s.client(), a signerclient.Client with AwaitClose, so it
// returns only after the signer has closed the connection, F16 (03-08h):
// budgetSigner frees a token when the method returns, and the signer
// frees the connection's slot before it closes, so the server's counted
// connections at the signer never exceed its tokens (plus its one
// GetKRL). Growth rule: a later method calls its signerclient Client
// method through s.client(), never a package function.
type socketSigner struct{ socket string }

// client is the signerclient Client of every socketSigner call.
func (s socketSigner) client() signerclient.Client {
	return signerclient.Client{Socket: s.socket, AwaitClose: true}
}

func (s socketSigner) Status(ctx context.Context) (*wire.StatusResponse, error) {
	return s.client().Status(ctx)
}

func (s socketSigner) GetDirectory(ctx context.Context) (*wire.GetDirectoryResponse, error) {
	return s.client().GetDirectory(ctx)
}

func (s socketSigner) InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	return s.client().InstallDirectory(ctx, req)
}

func (s socketSigner) Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	return s.client().LoginSend(ctx, req, signerCallTimeout)
}

func (s socketSigner) Revoke(ctx context.Context, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	return s.client().Revoke(ctx, req)
}

func (s socketSigner) GetKRL(ctx context.Context) (*wire.GetKRLResponse, error) {
	return s.client().GetKRL(ctx)
}

func (s socketSigner) GetBundle(ctx context.Context, v uint64) (*wire.GetBundleResponse, error) {
	return s.client().GetBundle(ctx, v)
}

func (s socketSigner) GetDirectoryVersion(ctx context.Context, v uint64) (*wire.GetDirectoryVersionResponse, error) {
	return s.client().GetDirectoryVersion(ctx, v)
}

func (s socketSigner) ForgetAgent(ctx context.Context, req *wire.ForgetRequest) (*wire.ForgetResponse, error) {
	return s.client().ForgetAgent(ctx, req)
}

const (
	// maxSignerCalls is the most signer calls keyroster-server has in
	// flight through its budget (budgetSigner). F11 (03-08g). It is
	// wire.MaxServerSignerCalls, 4 below the signer's per-account share
	// (F16 (03-08h)): with the one GetKRL outside the budget the server's
	// ceiling at the signer is 13, and the 3 left are margin, not a timing
	// allowance, since each call returns only after the signer has freed
	// its slot (socketSigner).
	maxSignerCalls = wire.MaxServerSignerCalls
	// maxAgentCalls is the most of them relayed for host agents (the agent
	// share), so that logins, revocations, directory installs, forgets and
	// the server's own reads always have the other half. F11 (03-08g).
	maxAgentCalls = maxSignerCalls / 2
)

// budgetSigner is the server's signer-call budget, F11 (03-08g). newServer
// puts it in front of every signer, the test double included. At most
// maxSignerCalls calls are in flight through it, and at most maxAgentCalls
// of them are calls relayed for host agents (the agent share).
//
// A call in the agent share takes its agent token first and its total
// token second. In the other order, agent calls queued on the agent share
// would sit on total tokens and starve the interactive calls; in this one,
// queued agent calls hold nothing, and the other maxSignerCalls -
// maxAgentCalls tokens stay open to logins, revocations, directory
// installs, forgets and the server's own Status and directory reads. A
// call waits for a token only until its ctx ends, takes nothing when its
// ctx has already ended, and gives back an agent token it took when its
// ctx ends at the total wait. Each method releases its tokens before it
// returns, on every path, so no caller holds a token across another
// signerAPI call.
//
// The agent-share rule (owner decision 2026-10-30): every signer call made
// on behalf of a host agent takes the agent share. The share is chosen by
// method: GetBundle and GetDirectoryVersion take it wherever they are
// called. Today GetDirectoryVersion has three callers: the state route
// (directoryItems), the heartbeat route through confirmRemoval, and the
// admin pending-hosts route through reconcileRemoval; GetBundle has one,
// the state route (bundleItems). The route half of the rule: every agent
// route that relays such a call takes the agent's in-flight slot
// (agentSlot) after requireAgent, as the state and heartbeat routes do.
// The admin pending-hosts route is an admin route and takes the share by
// method only.
//
// The one exemption is GetKRL (Q-G5, owner decision 2026-10-30): it takes
// no lock on the signer, and refreshKRL, its only caller, coalesces it to
// one call in flight. So it never waits behind budgeted calls, and the
// server holds at most maxSignerCalls + 1 signer calls at once.
//
// next is a named field, never embedded: a signerAPI method added later
// does not build until budgetSigner implements it, and an embedded
// interface would pass it through unbudgeted.
type budgetSigner struct {
	next  signerAPI
	total chan struct{} // one token per call in flight, maxSignerCalls
	agent chan struct{} // one token per agent call in flight, maxAgentCalls
}

// withSignerBudget returns sg behind the server's signer-call budget.
func withSignerBudget(sg signerAPI) signerAPI {
	return &budgetSigner{next: sg, total: make(chan struct{}, maxSignerCalls), agent: make(chan struct{}, maxAgentCalls)}
}

// acquire takes the tokens of one call: an agent token first when agent is
// set, then a total token. It returns ctx's error, holding nothing, when
// ctx has ended or ends while it waits. release frees the total token,
// then the agent token.
func (b *budgetSigner) acquire(ctx context.Context, agent bool) (release func(), err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if agent {
		select {
		case b.agent <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	select {
	case b.total <- struct{}{}:
	case <-ctx.Done():
		if agent {
			<-b.agent
		}
		return nil, ctx.Err()
	}
	return func() {
		<-b.total
		if agent {
			<-b.agent
		}
	}, nil
}

// budgeted makes one call through b: it acquires the budget, then calls
// call, and releases the budget when call returns, whatever it returned.
// A budget error is returned as is, so errors.Is(err,
// context.DeadlineExceeded) still holds for it.
func budgeted[T any](ctx context.Context, b *budgetSigner, agent bool, call func() (T, error)) (T, error) {
	release, err := b.acquire(ctx, agent)
	if err != nil {
		var zero T
		return zero, err
	}
	defer release()
	return call()
}

func (b *budgetSigner) Status(ctx context.Context) (*wire.StatusResponse, error) {
	return budgeted(ctx, b, false, func() (*wire.StatusResponse, error) { return b.next.Status(ctx) })
}

func (b *budgetSigner) GetDirectory(ctx context.Context) (*wire.GetDirectoryResponse, error) {
	return budgeted(ctx, b, false, func() (*wire.GetDirectoryResponse, error) { return b.next.GetDirectory(ctx) })
}

func (b *budgetSigner) InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	return budgeted(ctx, b, false, func() (*wire.InstallDirectoryResponse, error) { return b.next.InstallDirectory(ctx, req) })
}

// Login waits for the budget as part of the send, so ctx's deadline bounds
// that wait too; the read after the send stays bounded by
// signerCallTimeout (socketSigner).
func (b *budgetSigner) Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	return budgeted(ctx, b, false, func() (*wire.IssueResponse, error) { return b.next.Login(ctx, req) })
}

func (b *budgetSigner) Revoke(ctx context.Context, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	return budgeted(ctx, b, false, func() (*wire.RevokeResponse, error) { return b.next.Revoke(ctx, req) })
}

// GetKRL calls the next signer without a token (Q-G5): it takes no lock on
// the signer, and refreshKRL, its only caller, coalesces it to one call in
// flight, so the server holds at most maxSignerCalls + 1 signer calls.
func (b *budgetSigner) GetKRL(ctx context.Context) (*wire.GetKRLResponse, error) {
	return b.next.GetKRL(ctx)
}

// GetBundle is relayed for a host agent and takes the agent share.
func (b *budgetSigner) GetBundle(ctx context.Context, v uint64) (*wire.GetBundleResponse, error) {
	return budgeted(ctx, b, true, func() (*wire.GetBundleResponse, error) { return b.next.GetBundle(ctx, v) })
}

// GetDirectoryVersion is relayed for a host agent and takes the agent
// share, from every caller.
func (b *budgetSigner) GetDirectoryVersion(ctx context.Context, v uint64) (*wire.GetDirectoryVersionResponse, error) {
	return budgeted(ctx, b, true, func() (*wire.GetDirectoryVersionResponse, error) { return b.next.GetDirectoryVersion(ctx, v) })
}

func (b *budgetSigner) ForgetAgent(ctx context.Context, req *wire.ForgetRequest) (*wire.ForgetResponse, error) {
	return budgeted(ctx, b, false, func() (*wire.ForgetResponse, error) { return b.next.ForgetAgent(ctx, req) })
}

const (
	// statusTTL is how long a signer Status answer is served from the
	// cache. After that, a failed refresh fails the request; nothing is
	// rendered from an expired entry.
	statusTTL = 5 * time.Second
	// statusTimeout bounds one refresh.
	statusTimeout = 3 * time.Second
)

// errNoRP is a Status whose policy names no WebAuthn relying party.
var errNoRP = errors.New("the installed policy has no WebAuthn RP")

// statusView is one signer Status answer, checked and parsed: the policy
// it runs on with its relying party, the custody report, and when it was
// read.
type statusView struct {
	raw           *wire.StatusResponse
	policy        *trust.Policy
	rp            *trust.WebAuthnRP
	softwareRoles []string
	custody       string // CustodyHeader value
	fetched       time.Time
}

// newStatusView checks st: its policy must parse and name a WebAuthn RP,
// and its custody report must format as a header.
func newStatusView(st *wire.StatusResponse, now time.Time) (*statusView, error) {
	if st == nil {
		return nil, errors.New("empty signer status")
	}
	p, err := trust.ParsePolicy(st.Policy)
	if err != nil {
		return nil, fmt.Errorf("signer status policy: %w", err)
	}
	if p.WebAuthn == nil {
		return nil, errNoRP
	}
	custody, err := serverclient.CustodyHeaderValue(st.Keys)
	if err != nil {
		return nil, err
	}
	return &statusView{
		raw:           st,
		policy:        p,
		rp:            p.WebAuthn,
		softwareRoles: custodytext.SoftwareRoles(st.Keys),
		custody:       custody,
		fetched:       now,
	}, nil
}

// refresh is one signer Status call in flight. done closes when it has
// ended; v and err are its result, set before done closes.
type refresh struct {
	done chan struct{}
	v    *statusView
	err  error
}

// currentStatus returns the signer's state, the only way a handler gets
// RP, policy, custody or directory data. An entry younger than statusTTL
// comes from the cache. Otherwise one refresh asks the signer, and every
// caller that arrives while it is in flight waits for it and takes its
// result, a failure included; none starts a second signer call. A caller
// whose ctx ends stops waiting, and a caller whose ctx has already ended
// starts no refresh. A failed refresh is never cached: the first caller
// after it has ended starts a new one.
func (s *Server) currentStatus(ctx context.Context) (*statusView, error) {
	s.mu.Lock()
	now := s.clock()
	if v := s.status; v != nil {
		if age := now.Sub(v.fetched); age >= 0 && age < statusTTL {
			s.mu.Unlock()
			return v, nil
		}
	}
	s.status = nil
	r := s.inflight
	if r == nil {
		if err := ctx.Err(); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		r = &refresh{done: make(chan struct{})}
		s.inflight = r
		// Detached: a refresh shared by every waiting caller must not end
		// with this caller's request.
		go s.refresh(context.WithoutCancel(ctx), r, now)
	}
	s.mu.Unlock()
	select {
	case <-r.done:
		return r.v, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// refresh asks the signer for its Status, bounded by statusTimeout. ctx
// must carry no cancellation (context.WithoutCancel of the starting
// caller's ctx): the refresh is detached from every request, so one caller
// hanging up does not fail the others. It stores a good answer as the
// cache entry and hands the result to every caller waiting on r.
func (s *Server) refresh(ctx context.Context, r *refresh, now time.Time) {
	rctx, cancel := context.WithTimeout(ctx, statusTimeout)
	defer cancel()
	st, err := s.signer.Status(rctx)
	var v *statusView
	if err != nil {
		s.log.Warn("signer status unavailable", "err", err)
	} else if v, err = newStatusView(st, now); err != nil {
		s.log.Warn("signer status refused", "err", err)
	} else if v.rp.RPID != s.rpID {
		// The TLS certificate was checked against the start-up RP ID,
		// and the certificate holder keeps checking against it.
		err = fmt.Errorf("the signer's policy names RP ID %s, but this server started with %s", v.rp.RPID, s.rpID)
		s.log.Error("signer status refused; restart keyroster-server to serve the new RP ID", "err", err)
	}
	s.mu.Lock()
	if err == nil {
		s.status = v
	} else {
		v = nil
	}
	s.inflight = nil
	r.v, r.err = v, err
	s.mu.Unlock()
	close(r.done)
}

// dropStatus removes the cached status, so the next currentStatus asks the
// signer again, under the same fail-closed rule. It first waits for the
// refresh in flight, if any (at most statusTimeout), so an answer read
// before a change can never be put back after the drop. Handlers call it
// right after the server asked the signer to change something Status
// reports (the directory install, 02-09). It makes no signer call and
// cannot fail.
func (s *Server) dropStatus() {
	s.mu.Lock()
	r := s.inflight
	s.mu.Unlock()
	if r != nil {
		<-r.done
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = nil
}
