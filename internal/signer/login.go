package signer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/wire"
)

// errDirectoryChanged means the installed directory version is no longer
// the one a login was authorized under.
var errDirectoryChanged = errors.New("signer: the installed directory changed during issuance")

// LoginIssue decides on one passkey login request (KEY-02) and, if it
// passes, issues a user certificate. The peer-credential allowlist was
// checked before the request was read. The steps, in order: freshness
// (CreatedAt within ±300 s); verifyLoginEvidence (exactly one
// webauthn-assertion/v1 item, the RP in the policy, an authorized
// directory, the directory's grant for the user and roles, the user's
// credential, and the assertion over the request's Digest); principals
// equal to the grant's exactly; a TTL within the smallest role cap and the
// user CA cap; extensions the roles grant (D-08). Then the admin path's
// sequence for the user CA: the bundle still in force, a request id not
// used before (one namespace with the admin path), a serial, a kr2 key ID
// and cert.Build. The certificate leaves only after its login_issue leaf,
// holding the full request signing bytes, committed (VIS-01). No flag,
// configuration or message type issues a login certificate without an
// assertion the signer verified itself.
func (s *Signer) LoginIssue(ctx context.Context, peer Peer, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
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
	grant, err := s.verifyLoginEvidence(req)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(req.Principals, grant.Principals) {
		return nil, refusalErr(wire.CodeRefused, "principals_mismatch", nil)
	}
	caKey, ok := s.ca[wire.CARoleUser]
	profile, okProfile := s.profiles[wire.CARoleUser]
	if !ok || !okProfile {
		return nil, refusalErr(wire.CodeRefused, "ca_not_configured", nil)
	}
	ttlCap := min(grant.MaxTTLSeconds, uint64(profile.MaxTTL/time.Second)) //nolint:gosec // G115: the profile cap is positive (certprofile.ForRole)
	if uint64(req.ValidForSeconds) > ttlCap {
		return nil, refusalErr(wire.CodeRefused, "ttl_exceeds_role", nil)
	}
	extra := make(map[string]string, len(req.Extensions))
	seen := make(map[string]bool, len(req.Extensions))
	for _, e := range req.Extensions {
		if seen[e] {
			return nil, refusalErr(wire.CodeRefused, "duplicate_extension", nil)
		}
		seen[e] = true
		if !slices.Contains(grant.Extensions, e) {
			return nil, refusalErr(wire.CodeRefused, "extension_not_allowed", nil)
		}
		// A role may grant a profile default (directory.CheckPolicy);
		// every certificate already carries those, and cert.Build takes
		// only allowed extensions as extras.
		if _, isDefault := profile.DefaultExtensions[e]; !isDefault {
			extra[e] = ""
		}
	}
	subject, err := ssh.ParsePublicKey(req.SubjectKey)
	if err != nil {
		return nil, refusalErr(wire.CodeRefused, "bad_subject_key", err)
	}
	if err := s.checkTrustCurrent(s.db.LatestBundleVersion(ctx)); err != nil {
		return nil, err
	}
	switch used, err := s.db.RequestIDUsed(ctx, req.RequestID); {
	case err != nil:
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	case used:
		return nil, refusalErr(wire.CodeRefused, "duplicate_request", signerdb.ErrDuplicateRequest)
	}

	last, err := s.db.LastSerial(ctx)
	if err != nil {
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	}
	ser, err := serial.Next(last, s.clock, time.Sleep)
	if err != nil {
		if errors.Is(err, serial.ErrClockRegression) {
			s.logClockRegressionLocked(ctx, last)
			return nil, refusalErr(wire.CodeUnavailable, "clock_regression", err)
		}
		return nil, refusalErr(wire.CodeUnavailable, "serial_unavailable", err)
	}
	issuedAt := s.clock()
	if micros(issuedAt) < ser {
		return nil, refusalErr(wire.CodeUnavailable, "clock_regression", serial.ErrClockRegression)
	}

	dirVersion := s.directoryVersion
	keyID := cert.KeyID{
		CA:        wire.CARoleUser.String(),
		Subject:   req.Subject,
		Request:   hex.EncodeToString(req.RequestID[:]),
		Policy:    s.policy.Version,
		Directory: dirVersion,
		Roles:     slices.Clone(grant.Roles),
		Serial:    ser,
	}
	c, err := cert.Build(cert.Request{
		Profile:         profile,
		Subject:         subject,
		Principals:      req.Principals,
		Now:             issuedAt,
		ValidFor:        time.Duration(req.ValidForSeconds) * time.Second,
		KeyID:           keyID,
		Serial:          ser,
		ExtraExtensions: extra,
	}, caKey, rand.Reader)
	if err != nil {
		return nil, buildRefusal(err)
	}
	certBytes := c.Marshal()
	leafBody, err := (&tlog.LoginIssueBody{
		Serial:           ser,
		PolicyVersion:    keyID.Policy,
		DirectoryVersion: dirVersion,
		Request:          req.SigningBytes(),
		Evidence:         req.Evidence,
		Cert:             certBytes,
		KeyID:            c.KeyId,
	}).Encode()
	if err != nil {
		return nil, refusalErr(wire.CodeInternal, "log_encoding", err)
	}
	var leafIndex uint64
	err = s.logTx(ctx, func(tx *sql.Tx) error {
		if err := s.checkTrustCurrent(s.db.LatestBundleVersionTx(ctx, tx)); err != nil {
			return err
		}
		switch v, err := s.db.LatestDirectoryVersionTx(ctx, tx); {
		case err != nil:
			return refusalErr(wire.CodeUnavailable, "state_unavailable", err)
		case v != dirVersion:
			s.log.Error("directory changed under the running signer", "authorized_version", dirVersion, "installed_version", v)
			return refusalErr(wire.CodeUnavailable, "directory_changed", errDirectoryChanged)
		}
		if err := s.db.InsertIssuance(tx, signerdb.Issuance{
			Serial:    ser,
			RequestID: req.RequestID,
			CARole:    keyID.CA,
			KeyID:     c.KeyId,
			Cert:      certBytes,
			IssuedAt:  issuedAt,
		}); err != nil {
			return err
		}
		if err := s.db.SetLastSerial(tx, ser); err != nil {
			return err
		}
		idx, err := s.appendLocked(ctx, tx, tlog.Leaf{
			TimeMicros: uint64(issuedAt.UnixMicro()), //nolint:gosec // G115: issuedAt >= serial > 0 µs, checked after serial.Next
			Kind:       tlog.KindLoginIssue,
			Body:       leafBody,
		})
		leafIndex = idx
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
	s.clockEpisode = false
	// Only now, after COMMIT, does the certificate leave the signer.
	s.log.Info("issued",
		"serial", ser,
		"key_id", c.KeyId,
		"leaf_index", leafIndex,
		"user", req.Subject,
		"roles", strings.Join(grant.Roles, "+"),
		"principals", len(c.ValidPrincipals),
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: certBytes, Serial: ser, LeafIndex: leafIndex}, nil
}

// verifyLoginEvidence authorizes a login request (KEY-02, D-05, D-08,
// D-17) and returns what the installed directory grants it. Default deny,
// one named refusal per failure: exactly one evidence item of type
// webauthn-assertion/v1; a WebAuthn RP in the policy in force; an
// installed directory signed under that policy; the directory's grant for
// the user and the requested roles; the assertion blob; the user's bound
// credential with the assertion's ID; and the assertion itself, verified
// against the policy's RP and origins with the challenge SHA-256 of the
// request's signing bytes. The caller holds s.mu.
func (s *Signer) verifyLoginEvidence(req *wire.LoginIssueRequest) (directory.Grant, error) {
	var none directory.Grant
	switch {
	case len(req.Evidence) == 0:
		return none, refusalErr(wire.CodeRefused, "missing_evidence", nil)
	case len(req.Evidence) > 1:
		return none, refusalErr(wire.CodeRefused, "too_many_evidence", nil)
	case req.Evidence[0].Type != wire.EvidenceWebAuthnAssertion:
		return none, refusalErr(wire.CodeRefused, "unknown_evidence_type", nil)
	}
	if s.policy == nil || s.policy.WebAuthn == nil {
		return none, refusalErr(wire.CodeRefused, "no_webauthn_policy", nil)
	}
	if s.directoryRaw == nil {
		return none, refusalErr(wire.CodeRefused, "directory_not_installed", nil)
	}
	if !s.directoryAuthorized || s.directory == nil {
		return none, refusalErr(wire.CodeRefused, "directory_not_authorized", nil)
	}
	grant, err := s.directory.Authorize(req.Subject, req.Roles)
	switch {
	case errors.Is(err, directory.ErrUnknownUser):
		return none, refusalErr(wire.CodeRefused, "unknown_user", err)
	case errors.Is(err, directory.ErrUserDisabled):
		return none, refusalErr(wire.CodeRefused, "user_disabled", err)
	case errors.Is(err, directory.ErrRoleNotGranted):
		return none, refusalErr(wire.CodeRefused, "role_not_granted", err)
	case err != nil:
		return none, refusalErr(wire.CodeInternal, "authorize_failed", err)
	}
	a, err := wire.ParseWebAuthnAssertion(req.Evidence[0].Blob)
	if err != nil {
		return none, refusalErr(wire.CodeRefused, "bad_evidence", err)
	}
	cred, ok := s.directory.Credential(req.Subject, a.CredentialID)
	if !ok {
		return none, refusalErr(wire.CodeRefused, "unknown_credential", nil)
	}
	rp := s.policy.WebAuthn
	err = webauthn.VerifyAssertion(cred, rp.RPID, rp.Origins, req.Digest(), webauthn.Assertion{
		CredentialID:      a.CredentialID,
		AuthenticatorData: a.AuthenticatorData,
		ClientDataJSON:    a.ClientDataJSON,
		Signature:         a.Signature,
	})
	if err != nil {
		return none, refusalErr(wire.CodeRefused, assertionRefusal(err), err)
	}
	return grant, nil
}

// assertionRefusal maps a webauthn.VerifyAssertion error to its refusal
// detail.
func assertionRefusal(err error) string {
	for _, m := range []struct {
		err    error
		detail string
	}{
		{webauthn.ErrCredentialID, "credential_mismatch"},
		{webauthn.ErrAuthenticatorData, "bad_authenticator_data"},
		{webauthn.ErrRPMismatch, "rp_mismatch"},
		{webauthn.ErrUserPresence, "user_presence_missing"},
		{webauthn.ErrUserVerification, "user_verification_missing"},
		{webauthn.ErrClientData, "bad_client_data"},
		{webauthn.ErrType, "type_mismatch"},
		{webauthn.ErrChallenge, "challenge_mismatch"},
		{webauthn.ErrOrigin, "origin_mismatch"},
		{webauthn.ErrCrossOrigin, "cross_origin_refused"},
		{webauthn.ErrAlgorithm, "unsupported_algorithm"},
		{webauthn.ErrSignature, "assertion_signature_invalid"},
	} {
		if errors.Is(err, m.err) {
			return m.detail
		}
	}
	return "assertion_signature_invalid"
}
