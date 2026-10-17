package signer

import (
	"context"
	"crypto/sha256"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/wire"
)

// statusDirectory is the directory part of a Status reply: the installed
// version (0 for none), the SHA-256 of its canonical bytes and whether it
// is authorized under the policy in force. All three are fixed-size on the
// wire.
type statusDirectory struct {
	version    uint64
	sha256     [32]byte
	authorized bool
}

// statusResponse builds a Status reply from the ca-init keys (in the fixed
// role order user, host, machine, ops, log, whatever order caKeys is in),
// the trust bundle and policy documents with their signatures, and the
// directory. Signer.Status and InstallBundle both use it, so the reply
// Status sends and the reply InstallBundle sizes before installing are
// encoded by the same code against the same limit (wire.MaxStatusFrame).
func statusResponse(caKeys []signerdb.CAKey, bundleVersion uint64, bundle, bundleSigs, policy, policySigs []byte, dir statusDirectory) *wire.StatusResponse {
	r := &wire.StatusResponse{
		Keys:                make([]wire.KeyStatus, 0, len(caKeys)),
		BundleVersion:       bundleVersion,
		Bundle:              bundle,
		BundleSigs:          bundleSigs,
		Policy:              policy,
		PolicySigs:          policySigs,
		DirectoryVersion:    dir.version,
		DirectorySHA256:     dir.sha256,
		DirectoryAuthorized: dir.authorized,
	}
	for _, role := range initRoles {
		for _, k := range caKeys {
			if k.Role == string(role) {
				r.Keys = append(r.Keys, wire.KeyStatus{
					Role: k.Role, Alg: k.Alg, Custody: k.Custody, Fingerprint: keyFingerprint(caKeys, k.Role),
				})
			}
		}
	}
	return r
}

// Status reports, from the signer itself (D-18), every online key's
// algorithm, custody and fingerprint as ca-init recorded them and start-up
// re-checked them in the backend, the trust bundle and policy with their
// signatures, and the installed directory's version, hash and
// authorization. It runs under s.mu and adds no state.
//
// The documents come from the latest trust_bundle row, read once. Its
// version must be the one this process loaded (checkTrustCurrent, as for
// issuance): after a bundle install under the running signer, Status
// refuses trust_changed until a restart, so a reply never carries a bundle
// or policy other than the one the signer runs on, and custody cannot
// change between a Status reply and the issuance after it. A reply above
// wire.MaxStatusFrame is refused with wire.ErrStatusTooLarge.
func (s *Signer) Status(ctx context.Context) (*wire.StatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.db.LatestBundle(ctx)
	if err != nil {
		// stored is nil here: never read its version.
		return nil, s.checkTrustCurrent(0, err)
	}
	if err := s.checkTrustCurrent(stored.Version, nil); err != nil {
		return nil, err
	}
	dir := statusDirectory{version: s.directoryVersion, authorized: s.directoryAuthorized}
	if s.directoryRaw != nil {
		dir.sha256 = sha256.Sum256(s.directoryRaw)
	}
	resp := statusResponse(s.caKeys, stored.Version, stored.Bundle, stored.BundleSigs, stored.Policy, stored.PolicySigs, dir)
	// Size the reply here, so an oversize trust state is reported as such
	// rather than as a response encoding failure.
	if _, err := resp.Marshal(); err != nil {
		return nil, err
	}
	return resp, nil
}

// statusOrRefuse runs Status and records an error through refuseErr, with
// a zero digest (a Status request carries nothing to hash). It runs after
// Status has released s.mu, which refuseLogging takes itself.
func (s *Signer) statusOrRefuse(ctx context.Context, peer Peer) (*wire.StatusResponse, *wire.ErrorResponse) {
	resp, err := s.Status(ctx)
	if err == nil {
		return resp, nil
	}
	return nil, s.refuseErr(ctx, s.limiter, peer, [32]byte{}, err)
}
