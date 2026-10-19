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
}

// socketSigner reaches keyroster-signer over its Unix socket.
type socketSigner struct{ socket string }

func (s socketSigner) Status(ctx context.Context) (*wire.StatusResponse, error) {
	return signerclient.Status(ctx, s.socket)
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

// currentStatus returns the signer's state, the only way a handler gets
// RP, policy, custody or directory data. An entry younger than statusTTL
// comes from the cache. Otherwise the caller refreshes it while holding
// s.mu for the whole signer call, so concurrent callers wait for that one
// refresh. A failed refresh drops the entry and returns the error: it is
// never cached, and the next request tries again.
func (s *Server) currentStatus(ctx context.Context) (*statusView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if v := s.status; v != nil {
		if age := now.Sub(v.fetched); age >= 0 && age < statusTTL {
			return v, nil
		}
	}
	s.status = nil
	// One caller hanging up must not fail the others waiting on this
	// refresh.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusTimeout)
	defer cancel()
	st, err := s.signer.Status(rctx)
	if err != nil {
		s.log.Warn("signer status unavailable", "err", err)
		return nil, err
	}
	v, err := newStatusView(st, now)
	if err != nil {
		s.log.Warn("signer status refused", "err", err)
		return nil, err
	}
	s.status = v
	return v, nil
}

// dropStatus removes the cached status, so the next currentStatus asks the
// signer again, under the same fail-closed rule. It takes the mutex a
// refresh holds for its whole signer call, so an answer read before a
// change can never be put back after the drop. Handlers call it right
// after the server asked the signer to change something Status reports
// (the directory install, 02-09). It makes no signer call and cannot fail.
func (s *Server) dropStatus() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = nil
}
