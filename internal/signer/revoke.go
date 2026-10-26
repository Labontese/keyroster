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
// now, and uses it for the freshness check, as the resolution time T (the
// revoke leaf's ResolvedAtSeconds, now in whole seconds), as the time of
// every leaf before appendLocked's clamp and as the manifest's issued_at;
// the clamp can only raise a leaf's time, so ResolvedAtSeconds × 10^6
// never exceeds the revoke leaf's time. Unlike issuance, a revocation is
// never refused because the clock stepped back: revocation is the
// fail-safe direction.
//
// In order: a valid request (malformed_request), freshness (CreatedAt
// within ±300 s), a request ID not accepted before (duplicate_request),
// an installation ID in the bundle in force (krl_no_installation_id), a
// v2 request (revoke_installation_missing) for that installation
// (revoke_installation_mismatch: the T-03-20 rule of directories),
// admin-sshsig/v1 evidence by at least one policy admin over the request's
// exact signing bytes under keyroster/revoke-request/v2 (one admin
// suffices whatever admin_quorum says), a subject kind this version resolves
// (subject_kind_unsupported), then one transaction: the bundle still the
// one loaded at start, the target resolved to its entries, one revocation
// row per entry, the revoke leaf (several for a subject above
// tlog.MaxRevokedEntries certificates), the request ID, the KRL rebuilt
// from the whole revocation table (krl.Encode, in publishKRLLocked) with
// its ops-signed manifest, and the krl_publish leaf. The KRL leaves the
// signer only after COMMIT.
//
// The targets resolve to:
//   - serial: the certificate with that serial, issued by that CA role
//     (unknown_serial, ca_role_mismatch), with its CA key and ValidBefore;
//   - key_id: one entry per CA key of the role in the bundle in force, in
//     their wire-byte order, each with the latest ValidBefore of this
//     signer's certificates with that key ID under that CA key, or 0 (not
//     known, never pruned) when it issued none;
//   - key: the key itself, refused key_is_ca_of_this_installation when the
//     bundle in force names it (CA-key revocation is 03-13's emergency
//     path);
//   - subject user: every certificate this signer issued under the user
//     CA whose key ID names the subject and that is live at T
//     (signerdb.LiveIssuanceForSubjectTx, krl.EntryLive), in ascending
//     serial order, including those an earlier revocation already lists
//     (re-listing), split over consecutive revoke leaves of at most
//     tlog.MaxRevokedEntries entries. A subject with no live certificate
//     still records one revoke leaf with no entry.
func (s *Signer) Revoke(ctx context.Context, peer Peer, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req == nil || req.Validate() != nil {
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
	switch {
	case s.installationID == "":
		return nil, refusalErr(wire.CodeUnavailable, "krl_no_installation_id", nil)
	case req.InstallationID == "":
		// A keyroster/revoke-request/v1 request (03-01) names no
		// installation, so its admin signature is valid in every one.
		return nil, refusalErr(wire.CodeRefused, "revoke_installation_missing", nil)
	case req.InstallationID != s.installationID:
		return nil, refusalErr(wire.CodeRefused, "revoke_installation_mismatch", nil)
	}
	admins, err := verifyRevokeEvidence(req, s.policy)
	if err != nil {
		return nil, err
	}
	if req.Target == wire.TargetSubject && req.SubjectKind != wire.SubjectUser {
		// Host subjects arrive with 03-09, machine subjects with 03-11.
		return nil, refusalErr(wire.CodeRefused, "subject_kind_unsupported", nil)
	}
	resolvedAt := uint64(max(now.Unix(), 0)) //nolint:gosec // G115: >= 0

	var (
		revokeLeaf, publishLeaf uint64
		published               *signerdb.KRLState
		entries                 []tlog.RevokedEntry
	)
	err = s.logTx(ctx, func(tx *sql.Tx) error {
		// The admins the evidence was checked against come from the
		// policy loaded at start; commit only while it is still in force.
		if err := s.checkTrustCurrent(s.db.LatestBundleVersionTx(ctx, tx)); err != nil {
			return err
		}
		var err error
		if entries, err = s.resolveRevokeLocked(ctx, tx, req, resolvedAt); err != nil {
			return err
		}
		// Every leaf of the request carries the same request, evidence
		// and resolution time; only the entries are split.
		chunks := [][]tlog.RevokedEntry{entries[:min(len(entries), tlog.MaxRevokedEntries)]}
		for rest := entries[len(chunks[0]):]; len(rest) > 0; rest = rest[min(len(rest), tlog.MaxRevokedEntries):] {
			chunks = append(chunks, rest[:min(len(rest), tlog.MaxRevokedEntries)])
		}
		for _, chunk := range chunks {
			body, err := (&tlog.RevokeBody{
				PolicyVersion:     s.policy.Version,
				ResolvedAtSeconds: resolvedAt,
				Request:           req.SigningBytes(),
				Evidence:          req.Evidence,
				Entries:           chunk,
			}).Encode()
			if err != nil {
				return refusalErr(wire.CodeInternal, "log_encoding", err)
			}
			idx, err := s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindRevoke, Body: body})
			if err != nil {
				return err
			}
			revokeLeaf = idx
			// Each row names the leaf that holds its entry
			// (loggedRevocations ties the two by leaf index).
			for _, e := range chunk {
				if err := s.db.InsertRevocation(tx, revocationRow(e, req.RequestID, idx, now)); err != nil {
					return err
				}
			}
		}
		if err := s.db.InsertRevokeRequestTx(tx, req.RequestID, revokeLeaf); err != nil {
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
	resp := &wire.RevokeResponse{KRLVersion: published.Version, RevokeLeaf: revokeLeaf, PublishLeaf: publishLeaf}
	if req.Target == wire.TargetSubject {
		resp.SerialCount = uint32(len(entries)) //nolint:gosec // G115: the issuance table holds far fewer than 2^32 certificates per subject
		for _, e := range entries[:min(len(entries), wire.MaxRevokeAnswerSerials)] {
			resp.Serials = append(resp.Serials, e.Serial)
		}
	}
	s.log.Info("revoked",
		"target", revokeTargetName(req.Target),
		"serial", req.Serial,
		"key_id", req.KeyID,
		"subject", req.Subject,
		"ca", req.CARole.String(),
		"entries", len(entries),
		"krl_version", published.Version,
		"revoke_leaf", revokeLeaf,
		"publish_leaf", publishLeaf,
		"admins", strings.Join(admins, ","),
		"uid", peer.UID,
		"pid", peer.PID)
	return resp, nil
}

// resolveRevokeLocked resolves req to the entries its revoke leaves list,
// at the resolution time at (whole seconds), inside tx (see Revoke).
func (s *Signer) resolveRevokeLocked(ctx context.Context, tx *sql.Tx, req *wire.RevokeRequest, at uint64) ([]tlog.RevokedEntry, error) {
	switch req.Target {
	case wire.TargetSerial:
		is, err := s.db.IssuanceBySerialTx(ctx, tx, req.Serial)
		if err != nil {
			return nil, err
		}
		if is == nil {
			// A certificate this signer did not issue or does not know is
			// revoked by key (TargetKey).
			return nil, refusalErr(wire.CodeRefused, "unknown_serial", nil)
		}
		if is.CARole != req.CARole.String() {
			return nil, refusalErr(wire.CodeRefused, "ca_role_mismatch", nil)
		}
		caKey, validBefore, err := certCAKey(is.Cert)
		if err != nil {
			return nil, err
		}
		return []tlog.RevokedEntry{{Kind: tlog.RevokedSerial, CAKey: caKey, Serial: req.Serial, ValidBeforeSeconds: validBefore}}, nil
	case wire.TargetKeyID:
		var out []tlog.RevokedEntry
		for _, caKey := range s.roleCAKeys[req.CARole] {
			vb, err := s.db.KeyIDValidBeforeTx(ctx, tx, req.KeyID, caKey)
			if err != nil {
				return nil, err
			}
			out = append(out, tlog.RevokedEntry{Kind: tlog.RevokedKeyID, CAKey: caKey, KeyID: req.KeyID, ValidBeforeSeconds: vb})
		}
		if len(out) == 0 {
			return nil, refusalErr(wire.CodeRefused, "ca_not_configured", nil)
		}
		return out, nil
	case wire.TargetKey:
		if s.installationKeys[string(req.Key)] {
			return nil, refusalErr(wire.CodeRefused, "key_is_ca_of_this_installation", nil)
		}
		return []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: req.Key}}, nil
	case wire.TargetSubject:
		live, err := s.db.LiveIssuanceForSubjectTx(ctx, tx, trust.RoleUser, req.Subject, at)
		if err != nil {
			return nil, err
		}
		out := make([]tlog.RevokedEntry, 0, len(live))
		for _, c := range live {
			out = append(out, tlog.RevokedEntry{Kind: tlog.RevokedSerial, CAKey: c.CAKey, Serial: c.Serial, ValidBeforeSeconds: c.ValidBefore})
		}
		return out, nil
	}
	return nil, refusalErr(wire.CodeMalformed, "malformed_request", nil)
}

// revocationRow is the revocation row written with entry e of the revoke
// leaf leaf.
func revocationRow(e tlog.RevokedEntry, requestID [16]byte, leaf uint64, now time.Time) signerdb.Revocation {
	return signerdb.Revocation{
		Kind:              revocationKinds[e.Kind],
		CAKey:             e.CAKey,
		Serial:            e.Serial,
		KeyID:             e.KeyID,
		Key:               e.Key,
		ValidBeforeMicros: validBeforeMicros(e.ValidBeforeSeconds),
		RequestID:         requestID,
		LeafIndex:         leaf,
		RevokedAt:         now,
	}
}

// revokeTargetName names a revocation target for the operator log.
func revokeTargetName(target uint8) string {
	switch target {
	case wire.TargetSerial:
		return "serial"
	case wire.TargetKeyID:
		return "key_id"
	case wire.TargetKey:
		return "key"
	case wire.TargetSubject:
		return "subject"
	default:
		return "unknown"
	}
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
// SSHSIG under keyroster/revoke-request/v2 over req.SigningBytes() by a
// policy admin, and at least one distinct admin must have signed. One
// admin suffices whatever admin_quorum says: revocation only ever removes
// access (the fail-safe direction). It returns the sorted names of the
// admins who signed.
func verifyRevokeEvidence(req *wire.RevokeRequest, pol *trust.Policy) ([]string, error) {
	return verifyAdminSignatures(req.Evidence, req.SigningBytes(), wire.RevokeSSHSIGNamespace, 1, pol)
}
