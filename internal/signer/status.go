package signer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"

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
// directory. The Status snapshot (newStatusSnapshot) and InstallBundle both
// use it, so the reply Status sends and the reply InstallBundle sizes
// before installing are encoded by the same code against the same limit
// (wire.MaxStatusFrame).
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

// statusSnapshot is one whole Status reply, built under s.mu after a
// committed directory change and read by Status without the lock (03-08i).
// A stored snapshot is never modified.
type statusSnapshot struct {
	// reply is built by statusResponse and never handed out: Status
	// returns a copy (copyReply).
	reply *wire.StatusResponse
	// err is reply.Marshal's verdict at publish: wire.ErrStatusTooLarge
	// above wire.MaxStatusFrame, nil when the reply fits.
	err error
}

// newStatusSnapshot builds the snapshot of the ca-init keys, the trust
// bundle row the signer loaded and the directory state ds (03-08i). The
// reply is sized once here: its size depends only on the keys and the row,
// because the directory part is fixed-size on the wire.
func newStatusSnapshot(caKeys []signerdb.CAKey, row *signerdb.StoredBundle, ds directoryState) *statusSnapshot {
	dir := statusDirectory{version: ds.directoryVersion, authorized: ds.directoryAuthorized}
	if ds.directoryRaw != nil {
		dir.sha256 = sha256.Sum256(ds.directoryRaw)
	}
	var version uint64
	var bundle, bundleSigs, policy, policySigs []byte
	if row != nil {
		version, bundle, bundleSigs, policy, policySigs = row.Version, row.Bundle, row.BundleSigs, row.Policy, row.PolicySigs
	}
	reply := statusResponse(caKeys, version, bundle, bundleSigs, policy, policySigs, dir)
	_, err := reply.Marshal()
	return &statusSnapshot{reply: reply, err: err}
}

// publishStatusLocked stores the snapshot of the current trust and
// directory state (03-08i). The caller holds s.mu, or runs in New before
// Serve; setDirectoryLocked is its only caller (TestStatusWriters).
func (s *Signer) publishStatusLocked() {
	s.status.Store(newStatusSnapshot(s.caKeys, s.bundleRow, s.directoryState))
}

// copyReply returns a copy of the snapshot's reply that shares no slice
// with it, so a caller that changes its reply cannot change the next one
// (03-08i).
func (ss *statusSnapshot) copyReply() *wire.StatusResponse {
	r := *ss.reply
	r.Keys = slices.Clone(ss.reply.Keys)
	r.Bundle = bytes.Clone(ss.reply.Bundle)
	r.BundleSigs = bytes.Clone(ss.reply.BundleSigs)
	r.Policy = bytes.Clone(ss.reply.Policy)
	r.PolicySigs = bytes.Clone(ss.reply.PolicySigs)
	return &r
}

// errNoStatusDB means the signer was built without a read-only status
// handle (Config.StatusDB), so Status cannot check the bundle version.
var errNoStatusDB = errors.New("signer: no read-only status handle")

// errNoStatusSnapshot means no Status snapshot was published, which New
// rules out.
var errNoStatusSnapshot = errors.New("signer: no status snapshot")

// Status reports, from the signer itself (D-18), every online key's
// algorithm, custody and fingerprint as ca-init recorded them and start-up
// re-checked them in the backend, the trust bundle and policy with their
// signatures, and the installed directory's version, hash and
// authorization. The reply is a copy of a snapshot that setDirectoryLocked
// publishes after every committed directory change (03-08i), and Status
// adds no state.
//
// Status takes no lock and reads nothing through the signer's main
// database handle, so it answers at once while a signature holds s.mu,
// inside the database transaction or outside it (03-08i). On every call it
// reads the latest installed bundle version through the read-only handle
// (Config.StatusDB), which under WAL does not wait for a transaction on the
// main handle, and that version must be the one this process loaded
// (checkTrustCurrent, as for issuance): a bundle installed under the
// running signer is refused trust_changed at once, also while a signature
// holds the lock, until a restart. Without that check Status refuses
// rather than answer: a missing handle, a read error or a cancelled ctx
// refuse state_unavailable. The bundle and policy in a reply are the row
// this process loaded and checked against the log at start, so a reply
// never carries a bundle or policy other than the one the signer runs on,
// and custody cannot change between a Status reply and the issuance after
// it. A reply above wire.MaxStatusFrame is refused with
// wire.ErrStatusTooLarge.
func (s *Signer) Status(ctx context.Context) (*wire.StatusResponse, error) {
	if s.statusDB == nil {
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", errNoStatusDB)
	}
	if err := s.checkTrustCurrent(s.statusDB.LatestBundleVersion(ctx)); err != nil {
		return nil, err
	}
	ss := s.status.Load()
	if ss == nil {
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", errNoStatusSnapshot)
	}
	if ss.err != nil {
		return nil, ss.err
	}
	return ss.copyReply(), nil
}

// statusOrRefuse runs Status and records an error through refuseErr, with
// a zero digest (a Status request carries nothing to hash). Status takes
// no lock, but a refusal is still logged through refuseErr, which takes
// s.mu, so a refused Status waits for a signature in flight (03-08i).
func (s *Signer) statusOrRefuse(ctx context.Context, peer Peer) (*wire.StatusResponse, *wire.ErrorResponse) {
	resp, err := s.Status(ctx)
	if err == nil {
		return resp, nil
	}
	return nil, s.refuseErr(ctx, s.limiter, peer, [32]byte{}, err)
}
