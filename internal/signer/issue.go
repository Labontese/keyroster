package signer

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
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
// Authorization in this phase is the peer-credential allowlist checked
// before the request was read; plan 01-07 adds mandatory admin-sshsig/v1
// evidence (D-13). Evidence items are decoded and size-limited only.
func (s *Signer) Issue(ctx context.Context, peer Peer, req *wire.IssueRequest) (*wire.IssueResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req == nil {
		return nil, refusalErr(wire.CodeMalformed, "malformed_request", nil)
	}
	if req.CARole != wire.CARoleUser {
		return nil, refusalErr(wire.CodeRefused, "ca_not_configured", nil)
	}
	now := s.clock()
	created := time.Unix(int64(min(req.CreatedAt, uint64(1)<<62)), 0) //nolint:gosec // G115: clamped below 2^63
	if d := now.Sub(created); d > maxClockSkew || d < -maxClockSkew {
		return nil, refusalErr(wire.CodeRefused, "request_time_skew", nil)
	}
	subject, err := ssh.ParsePublicKey(req.SubjectKey)
	if err != nil {
		return nil, refusalErr(wire.CodeRefused, "bad_subject_key", err)
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
		CA:      wire.CARoleUser.String(),
		Subject: req.Subject,
		Request: hex.EncodeToString(req.RequestID[:]),
		Policy:  0, // no policy installed yet; plan 01-07 sets the installed version
		Serial:  ser,
	}
	c, err := cert.Build(cert.Request{
		Profile:    cert.DefaultUserProfile(),
		Subject:    subject,
		Principals: req.Principals,
		Now:        issuedAt,
		ValidFor:   time.Duration(req.ValidForSeconds) * time.Second,
		KeyID:      keyID,
		Serial:     ser,
	}, s.userCA, rand.Reader)
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
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: certBytes, Serial: ser, LeafIndex: leafIndex}, nil
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
