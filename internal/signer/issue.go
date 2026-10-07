package signer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// maxClockSkew bounds |now - CreatedAt| for a request.
const maxClockSkew = 300 * time.Second

// refusal is a decision not to issue, with a reason code safe to log and to
// send back (charset [a-z0-9_ .:-]).
type refusal struct {
	code   wire.ErrorCode
	reason string
	cause  error // logged as a type only, never sent
}

func (r *refusal) Error() string { return r.code.String() + ": " + r.reason }

func (r *refusal) Unwrap() error { return r.cause }

func refusalErr(code wire.ErrorCode, reason string, cause error) error {
	return &refusal{code: code, reason: reason, cause: cause}
}

// Issue decides on one request and, if it passes, issues the certificate.
// The peer-credential allowlist was checked before the request was read.
// Then: freshness (CreatedAt within ±300 s), admin-sshsig/v1 evidence from
// the installed policy's admins over the request's exact signing bytes
// (D-13), the CA key of the requested role from the installed bundle, that
// role's policy profile (validity cap and extensions, CA-04, CA-05), a
// serial, and cert.Build. The certificate leaves only after its log entry
// committed.
func (s *Signer) Issue(ctx context.Context, peer Peer, req *wire.IssueRequest) (*wire.IssueResponse, error) {
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
	admins, err := verifyAdminEvidence(req, s.policy)
	if err != nil {
		return nil, err
	}
	caKey, ok := s.ca[req.CARole]
	profile, okProfile := s.profiles[req.CARole]
	if !ok || !okProfile {
		return nil, refusalErr(wire.CodeRefused, "ca_not_configured", nil)
	}
	subject, err := ssh.ParsePublicKey(req.SubjectKey)
	if err != nil {
		return nil, refusalErr(wire.CodeRefused, "bad_subject_key", err)
	}
	extra := make(map[string]string, len(req.Extensions))
	for _, e := range req.Extensions {
		if _, dup := extra[e]; dup {
			return nil, refusalErr(wire.CodeRefused, "duplicate_extension", nil)
		}
		extra[e] = ""
	}
	// Refuse before the CA key is used when the installed bundle is no
	// longer the one this signer loaded; the check inside the issuance
	// transaction below is the one that holds until COMMIT.
	if err := s.checkTrustCurrent(s.db.LatestBundleVersion(ctx)); err != nil {
		return nil, err
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

	keyID := cert.KeyID{
		CA:      req.CARole.String(),
		Subject: req.Subject,
		Request: hex.EncodeToString(req.RequestID[:]),
		Policy:  s.policy.Version,
		Serial:  ser,
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
	// The signed certificate exists only in memory until the transaction
	// below commits the issuance row, the serial high-water mark and the
	// log leaf holding the full certificate, with a new signed checkpoint
	// (VIS-01). On any error the certificate is dropped.
	certBytes := c.Marshal()
	leafBody, err := (&tlog.IssueBody{
		CARole:        uint8(req.CARole),
		Serial:        ser,
		PolicyVersion: keyID.Policy,
		RequestDigest: req.Digest(),
		Evidence:      req.Evidence,
		Cert:          certBytes,
		KeyID:         c.KeyId,
	}).Encode()
	if err != nil {
		return nil, refusalErr(wire.CodeInternal, "log_encoding", err)
	}
	var leafIndex uint64
	err = s.logTx(ctx, func(tx *sql.Tx) error {
		// The policy, profiles and CA keys used above come from the bundle
		// loaded at start. Commit only while that bundle is still the
		// installed one, so no certificate is issued (and logged with
		// pol=<old version>) after a successor's bundle_install entry.
		if err := s.checkTrustCurrent(s.db.LatestBundleVersionTx(ctx, tx)); err != nil {
			return err
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
			TimeMicros: uint64(issuedAt.UnixMicro()), //nolint:gosec // G115: issuedAt >= serial > 0 µs (serial.Next)
			Kind:       tlog.KindIssue,
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
	s.clockEpisode = false // a successful issuance ends a clock-regression episode
	// Only now, after COMMIT, does the certificate leave the signer.
	s.log.Info("issued",
		"serial", ser,
		"key_id", c.KeyId,
		"leaf_index", leafIndex,
		"principals", len(c.ValidPrincipals),
		"evidence", len(req.Evidence),
		"admins", strings.Join(admins, ","),
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: certBytes, Serial: ser, LeafIndex: leafIndex}, nil
}

// errTrustChanged means the installed trust bundle is no longer the one the
// signer loaded at start: install-bundle ran against this state while the
// signer was serving (keyroster-signer serve holds a lock on the state
// directory that install-bundle respects, so only a process that bypassed
// it gets here). The signer refuses every request until it is restarted
// and loads the new bundle.
var errTrustChanged = errors.New("signer: the installed trust bundle changed since start")

// checkTrustCurrent refuses with trust_changed when version, the latest
// installed bundle version (read with err), is not the one this signer
// loaded. The caller holds s.mu.
func (s *Signer) checkTrustCurrent(version uint64, err error) error {
	if err != nil {
		return refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	}
	if version != s.bundleVersion {
		s.log.Error("trust bundle changed under the running signer: refusing every request until restart",
			"loaded_version", s.bundleVersion, "installed_version", version)
		return refusalErr(wire.CodeUnavailable, "trust_changed", errTrustChanged)
	}
	return nil
}

// buildRefusal maps a cert.Build error to a reason code.
func buildRefusal(err error) error {
	switch {
	case errors.Is(err, cert.ErrEmptyPrincipals):
		return refusalErr(wire.CodeRefused, "empty_principals", err)
	case errors.Is(err, cert.ErrPrincipal):
		return refusalErr(wire.CodeRefused, "bad_principal", err)
	case errors.Is(err, cert.ErrCertificateKey), errors.Is(err, cert.ErrSubjectKey):
		return refusalErr(wire.CodeRefused, "bad_subject_key", err)
	case errors.Is(err, cert.ErrKeyID):
		return refusalErr(wire.CodeRefused, "bad_subject", err)
	case errors.Is(err, cert.ErrValidity):
		return refusalErr(wire.CodeRefused, "bad_validity", err)
	case errors.Is(err, cert.ErrExtension):
		return refusalErr(wire.CodeRefused, "extension_not_allowed", err)
	default:
		return refusalErr(wire.CodeInternal, "build_failed", err)
	}
}

// logClockRegressionLocked appends one clock_regression leaf at the start
// of a clock-regression episode (the wall clock below the serial
// high-water mark, CA-03). Later regressions in the same episode are
// ordinary refusals. The caller holds s.mu.
func (s *Signer) logClockRegressionLocked(ctx context.Context, highWater uint64) {
	if s.clockEpisode {
		return
	}
	now := s.clock()
	body, err := (&tlog.ClockRegressionBody{NowMicros: micros(now), HighWaterMicros: highWater}).Encode()
	if err == nil {
		err = s.logTx(ctx, func(tx *sql.Tx) error {
			_, err := s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindClockRegression, Body: body})
			return err
		})
	}
	if err != nil {
		s.log.Error("clock regression not logged", "error", err.Error())
		return
	}
	s.clockEpisode = true
	s.log.Error("clock regression: issuance stopped until the clock passes the serial high-water mark",
		"now_us", micros(now), "high_water_us", highWater)
}
