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
// Login in 02-12). Nobody adds a second interface, and no method is added
// before something calls it.
type signerAPI interface {
	Status(ctx context.Context) (*wire.StatusResponse, error)
	GetDirectory(ctx context.Context) (*wire.GetDirectoryResponse, error)
	InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error)
	// Login asks the signer to issue a login certificate (02-12). Only
	// the redeem handler calls it, after the code and PKCE verifier have
	// been redeemed; a refusal comes back as a *wire.ErrorResponse.
	Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error)
}

// socketSigner reaches keyroster-signer over its Unix socket.
type socketSigner struct{ socket string }

func (s socketSigner) Status(ctx context.Context) (*wire.StatusResponse, error) {
	return signerclient.Status(ctx, s.socket)
}

func (s socketSigner) GetDirectory(ctx context.Context) (*wire.GetDirectoryResponse, error) {
	return signerclient.GetDirectory(ctx, s.socket)
}

func (s socketSigner) InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	return signerclient.InstallDirectory(ctx, s.socket, req)
}

func (s socketSigner) Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	return signerclient.Login(ctx, s.socket, req)
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
