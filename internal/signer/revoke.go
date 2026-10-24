package signer

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// Revoke decides on one revocation request and, if it passes, revokes and
// publishes the next KRL version (REVOKE-01). It takes ONE clock reading,
// now, and uses it for the freshness check, for the revoke leaf's
// ResolvedAtSeconds (now in whole seconds), as the time of both leaves
// before appendLocked's clamp and as the manifest's issued_at; the clamp
// can only raise a leaf's time, so ResolvedAtSeconds × 10^6 never exceeds
// the revoke leaf's time. Unlike issuance, a revocation is never refused
// because the clock stepped back: revocation is the fail-safe direction.
//
// In order: freshness (CreatedAt within ±300 s), a request ID not accepted
// before (duplicate_request), admin-sshsig/v1 evidence by at least one
// policy admin over the request's exact signing bytes under
// keyroster/revoke-request/v1 (one admin suffices whatever admin_quorum
// says), an installation ID in the bundle in force (krl_no_installation_id),
// then one transaction: the bundle still the one loaded at start, the
// certificate with that serial issued by that CA role (unknown_serial,
// ca_role_mismatch), the revocation row, the revoke leaf, the request ID,
// the KRL rebuilt from the whole revocation table (krl.Encode, in
// publishKRLLocked) with its ops-signed manifest, and the krl_publish leaf.
// The KRL leaves the signer only after COMMIT.
func (s *Signer) Revoke(ctx context.Context, peer Peer, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req == nil {
		return nil, refusalErr(wire.CodeMalformed, "malformed_request", nil)
	}
	now := s.clock()
	created := time.Unix(int64(min(req.CreatedAt, uint64(1)<<62)), 0) //nolint:gosec // G115: clamped below 2^63
	if d := now.Sub(created); d > maxClockSkew || d < -maxClockSkew {
		return nil, refusalErr(wire.CodeRefused, "request_time_skew", nil)
	}
	switch used, err := s.db.RevokeRequestUsed(ctx, req.RequestID); {
	case err != nil:
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	case used:
		return nil, refusalErr(wire.CodeRefused, "duplicate_request", signerdb.ErrDuplicateRequest)
	}
	admins, err := verifyRevokeEvidence(req, s.policy)
	if err != nil {
		return nil, err
	}
	if s.installationID == "" {
		return nil, refusalErr(wire.CodeUnavailable, "krl_no_installation_id", nil)
	}
	resolvedAt := uint64(max(now.Unix(), 0)) //nolint:gosec // G115: >= 0

	var (
		revokeLeaf, publishLeaf uint64
		published               *signerdb.KRLState
	)
	err = s.logTx(ctx, func(tx *sql.Tx) error {
		// The admins the evidence was checked against come from the
		// policy loaded at start; commit only while it is still in force.
		if err := s.checkTrustCurrent(s.db.LatestBundleVersionTx(ctx, tx)); err != nil {
			return err
		}
		is, err := s.db.IssuanceBySerialTx(ctx, tx, req.Serial)
		if err != nil {
			return err
		}
		if is == nil {
			// Revocation by key, for a certificate this signer did not
			// issue or does not know, arrives with 03-03.
			return refusalErr(wire.CodeRefused, "unknown_serial", nil)
		}
		if is.CARole != req.CARole.String() {
			return refusalErr(wire.CodeRefused, "ca_role_mismatch", nil)
		}
		caKey, validBefore, err := certCAKey(is.Cert)
		if err != nil {
			return err
		}
		entry := tlog.RevokedEntry{Kind: tlog.RevokedSerial, CAKey: caKey, Serial: req.Serial, ValidBeforeSeconds: validBefore}
		body, err := (&tlog.RevokeBody{
			PolicyVersion:     s.policy.Version,
			ResolvedAtSeconds: resolvedAt,
			Request:           req.SigningBytes(),
			Evidence:          req.Evidence,
			Entries:           []tlog.RevokedEntry{entry},
		}).Encode()
		if err != nil {
			return refusalErr(wire.CodeInternal, "log_encoding", err)
		}
		idx, err := s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindRevoke, Body: body})
		if err != nil {
			return err
		}
		revokeLeaf = idx
		if err := s.db.InsertRevocation(tx, signerdb.Revocation{
			Kind:              signerdb.RevocationSerial,
			CAKey:             caKey,
			Serial:            req.Serial,
			ValidBeforeMicros: validBeforeMicros(validBefore),
			RequestID:         req.RequestID,
			LeafIndex:         idx,
			RevokedAt:         now,
		}); err != nil {
			return err
		}
		if err := s.db.InsertRevokeRequestTx(tx, req.RequestID, idx); err != nil {
			return err
		}
		published, publishLeaf, err = s.publishKRLLocked(ctx, tx, now)
		return err
	})
	if err != nil {
		var r *refusal
		if errors.As(err, &r) {
			return nil, err
		}
		if errors.Is(err, signerdb.ErrDuplicateRequest) {
			return nil, refusalErr(wire.CodeRefused, "duplicate_request", err)
		}
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	}
	s.krl.Store(published)
	s.log.Info("revoked",
		"target", "serial",
		"serial", req.Serial,
		"ca", req.CARole.String(),
		"krl_version", published.Version,
		"revoke_leaf", revokeLeaf,
		"publish_leaf", publishLeaf,
		"admins", strings.Join(admins, ","),
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.RevokeResponse{KRLVersion: published.Version, RevokeLeaf: revokeLeaf, PublishLeaf: publishLeaf}, nil
}

// validBeforeMicros is the revocation row's valid_before_us for a
// certificate valid_before in seconds: 0 (not known) when it does not fit,
// as for ssh.CertTimeInfinity.
func validBeforeMicros(seconds uint64) uint64 {
	if seconds < uint64(1)<<62/uint64(time.Second/time.Microsecond) {
		return seconds * uint64(time.Second/time.Microsecond)
	}
	return 0
}

// certCAKey returns the CA key (SSH wire format) and the valid_before of a
// stored certificate.
func certCAKey(certBytes []byte) ([]byte, uint64, error) {
	pub, err := ssh.ParsePublicKey(certBytes)
	if err != nil {
		return nil, 0, refusalErr(wire.CodeInternal, "bad_stored_certificate", err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok || c.SignatureKey == nil {
		return nil, 0, refusalErr(wire.CodeInternal, "bad_stored_certificate", nil)
	}
	return c.SignatureKey.Marshal(), c.ValidBefore, nil
}

// verifyRevokeEvidence authorizes a revocation under the installed policy
// (REVOKE-01): every evidence item must be admin-sshsig/v1, an armored
// SSHSIG under keyroster/revoke-request/v1 over req.SigningBytes() by a
// policy admin, and at least one distinct admin must have signed. One
// admin suffices whatever admin_quorum says: revocation only ever removes
// access (the fail-safe direction). It returns the sorted names of the
// admins who signed.
func verifyRevokeEvidence(req *wire.RevokeRequest, pol *trust.Policy) ([]string, error) {
	return verifyAdminSignatures(req.Evidence, req.SigningBytes(), wire.RevokeSSHSIGNamespace, 1, pol)
}
