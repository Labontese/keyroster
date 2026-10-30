package signer

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// ForgetAgent decides on one forget request (03-08c, owner decisions 03-08
// D-1 and 03-08b Q3) and, if it passes, logs it as a host_forget entry,
// before keyroster-server deletes the agent. It takes ONE clock reading,
// now, for the freshness check, as the resolution time (the leaf's
// ResolvedAtSeconds, now in whole seconds) and as the leaf time before
// appendLocked's clamp.
//
// In order, each refusal writing no host_forget leaf and no request ID (a
// rate-limited refusal leaf may be appended, as for every refusal):
//  1. a valid request (malformed_request);
//  2. CreatedAt within ±300 s (request_time_skew);
//  3. a request ID no revoke, recovery or forget used (duplicate_request);
//  4. an installation ID in the bundle in force (forget_no_installation_id)
//     that the request names (forget_installation_mismatch);
//  5. the signed approved_once equal to the server's own statement of its
//     row, which the relay frame carries outside the signing bytes
//     (forget_facts_mismatch);
//  6. admin-sshsig/v1 evidence over the exact signing bytes under
//     keyroster/host-forget-request/v1 by distinct policy admins: one for
//     an agent never approved, which never received state, and the
//     policy's admin_quorum for every other (owner decision Q3;
//     admin_quorum_not_met and the other verifyAdminSignatures details);
//  7. no host entry of the installed directory, active or disabled, holds
//     one of the named host keys (forget_host_in_directory); a stored
//     directory that does not parse cannot tell, and is refused
//     (forget_directory_unreadable);
//  8. a confirmation at or below the installed directory version (a
//     version above it is refused before any stored row is read) whose
//     SHA-256 is that of the signer's stored directory document at that
//     version, without signatures (forget_confirmation_invalid).
//
// Then one transaction: the bundle still the one loaded at start, the
// stored directory version still the one checked in memory
// (directory_changed, unavailable), the host_forget leaf (the policy and directory versions in force, the
// resolution time, the signing bytes and the evidence) and the request ID
// in the request-ID table that revoke and recovery share. The answer
// leaves the signer only after COMMIT.
//
// What a confirmation says about the host is keyroster-server's rule
// (03-08b), recorded here as attested by the admins who signed; the signer
// checks only that it names a directory it installed.
func (s *Signer) ForgetAgent(ctx context.Context, peer Peer, req *wire.ForgetRequest) (*wire.ForgetResponse, error) {
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
		return nil, refusalErr(wire.CodeRefused, "forget_no_installation_id", nil)
	case req.InstallationID != s.installationID:
		return nil, refusalErr(wire.CodeRefused, "forget_installation_mismatch", nil)
	case req.ApprovedOnce != req.ServerApprovedOnce:
		return nil, refusalErr(wire.CodeRefused, "forget_facts_mismatch", nil)
	}
	need := 1
	if req.ApprovedOnce && s.policy != nil {
		need = int(s.policy.AdminQuorum)
	}
	admins, err := verifyAdminSignatures(req.Evidence, req.SigningBytes(), wire.ForgetSSHSIGNamespace, need, s.policy)
	if err != nil {
		return nil, err
	}
	if err := s.checkForgetDirectoryLocked(ctx, req); err != nil {
		return nil, err
	}
	resolvedAt := uint64(max(now.Unix(), 0)) //nolint:gosec // G115: >= 0

	var leaf uint64
	err = s.logTx(ctx, func(tx *sql.Tx) error {
		// The admins the evidence was checked against come from the
		// policy loaded at start; commit only while it is still in force.
		if err := s.checkTrustCurrent(s.db.LatestBundleVersionTx(ctx, tx)); err != nil {
			return err
		}
		// Steps 7 and 8 were checked against the directory loaded in
		// memory; commit only while it is still the one stored, as a
		// login does (PR #75 review finding 7).
		switch v, err := s.db.LatestDirectoryVersionTx(ctx, tx); {
		case err != nil:
			return refusalErr(wire.CodeUnavailable, "state_unavailable", err)
		case v != s.directoryVersion:
			s.log.Error("directory changed under the running signer", "checked_version", s.directoryVersion, "installed_version", v)
			return refusalErr(wire.CodeUnavailable, "directory_changed", errDirectoryChanged)
		}
		body, err := (&tlog.HostForgetBody{
			PolicyVersion:     s.policy.Version,
			DirectoryVersion:  s.directoryVersion,
			ResolvedAtSeconds: resolvedAt,
			Request:           req.SigningBytes(),
			Evidence:          req.Evidence,
		}).Encode()
		if err != nil {
			return refusalErr(wire.CodeInternal, "log_encoding", err)
		}
		if leaf, err = s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindHostForget, Body: body}); err != nil {
			return err
		}
		return s.db.InsertRevokeRequestTx(tx, req.RequestID, leaf)
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
	attrs := []any{
		"identity", hex.EncodeToString(req.AgentIdentity[:]),
		"expected_name", req.ExpectedName,
		"approved_once", req.ApprovedOnce,
		"host_gone", req.HostGone,
		"removal_version", req.RemovalVersion,
		"confirmed_version", req.ConfirmedVersion,
		"admins", strings.Join(admins, ","),
		"leaf", leaf,
		"uid", peer.UID,
		"pid", peer.PID,
	}
	if req.HostGone {
		s.log.Warn("agent forget logged", attrs...)
	} else {
		s.log.Info("agent forget logged", attrs...)
	}
	return &wire.ForgetResponse{Leaf: leaf}, nil
}

// checkForgetDirectoryLocked is ForgetAgent's directory checks, steps 7
// and 8, against the directory the signer has installed (the caller holds
// s.mu).
func (s *Signer) checkForgetDirectoryLocked(ctx context.Context, req *wire.ForgetRequest) error {
	if s.directoryRaw != nil && s.directory == nil {
		return refusalErr(wire.CodeUnavailable, "forget_directory_unreadable", nil)
	}
	if s.directory != nil {
		named := map[[32]byte]bool{}
		for _, d := range req.HostKeyFingerprints {
			named[d] = true
		}
		for _, h := range s.directory.Hosts {
			for _, k := range h.Keys {
				pub, err := trust.ParseKey(k)
				if err != nil {
					// Parse validated every key of the directory in force.
					return refusalErr(wire.CodeInternal, "bad_stored_directory", err)
				}
				if named[wire.HostKeyDigest(pub)] {
					return refusalErr(wire.CodeRefused, "forget_host_in_directory", nil)
				}
			}
		}
	}
	if req.ConfirmedVersion == 0 {
		return nil
	}
	// A version above the one in force is refused before any stored row
	// is read: a row above it is not a directory in force (PR #75 review
	// finding 7), and the commit refuses a forget while one is stored.
	if req.ConfirmedVersion > s.directoryVersion {
		return refusalErr(wire.CodeRefused, "forget_confirmation_invalid", nil)
	}
	doc := s.directoryRaw
	if req.ConfirmedVersion != s.directoryVersion {
		d, err := s.db.DirectoryByVersion(ctx, req.ConfirmedVersion)
		if err != nil {
			return refusalErr(wire.CodeUnavailable, "state_unavailable", err)
		}
		if d == nil {
			return refusalErr(wire.CodeRefused, "forget_confirmation_invalid", nil)
		}
		doc = d.Doc
	}
	if sha256.Sum256(doc) != req.ConfirmedSHA256 {
		return refusalErr(wire.CodeRefused, "forget_confirmation_invalid", nil)
	}
	return nil
}
