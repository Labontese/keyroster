package signer

import (
	"context"
	"errors"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// errNotFound is a chain request for a version that was never installed.
var errNotFound = errors.New("not_found")

// GetBundle returns the installed trust bundle of version v with its
// policy and both signature files, exactly as stored (03-07: the server
// serves an agent every bundle since its own). A version never installed
// is errNotFound. It reads only, and adds no state.
func (s *Signer) GetBundle(ctx context.Context, v uint64) (*wire.GetBundleResponse, error) {
	b, err := s.db.BundleByVersion(ctx, v)
	if errors.Is(err, signerdb.ErrNoBundle) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	return &wire.GetBundleResponse{Version: b.Version, Bundle: b.Bundle, BundleSigs: b.BundleSigs, Policy: b.Policy, PolicySigs: b.PolicySigs}, nil
}

// GetDirectoryVersion returns the installed directory of version v with
// its signatures, exactly as stored. A version never installed is
// errNotFound.
func (s *Signer) GetDirectoryVersion(ctx context.Context, v uint64) (*wire.GetDirectoryVersionResponse, error) {
	d, err := s.db.DirectoryByVersion(ctx, v)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, errNotFound
	}
	return &wire.GetDirectoryVersionResponse{Version: d.Version, Directory: d.Doc, Sigs: d.Sigs}, nil
}

// chainRefusal is the refusal of a failed chain read: not_found for a
// version never installed (malformed: the request named it), internal for
// a database error.
func (s *Signer) chainRefusal(ctx context.Context, peer Peer, err error) *wire.ErrorResponse {
	if errors.Is(err, errNotFound) {
		return s.refuse(ctx, peer, [32]byte{}, tlog.ReasonMalformed, "not_found")
	}
	s.log.Error("chain read", "error", err.Error())
	return s.refuse(ctx, peer, [32]byte{}, tlog.ReasonInternal, "internal")
}
