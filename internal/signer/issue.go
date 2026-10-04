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

func refuse(code wire.ErrorCode, reason string, cause error) error {
	return &refusal{code: code, reason: reason, cause: cause}
}

// Issue decides on one request and, if it passes, issues the certificate.
// Authorization in this phase is the peer-credential allowlist checked
// before the request was read; plan 01-07 adds mandatory admin-sshsig/v1
// evidence (D-13). Evidence items are decoded and size-limited only.
func (s *Signer) Issue(ctx context.Context, peer Peer, req *wire.IssueRequest) (*wire.IssueResponse, error) {
	s.issueMu.Lock()
	defer s.issueMu.Unlock()

	if req == nil {
		return nil, refuse(wire.CodeMalformed, "malformed_request", nil)
	}
	if req.CARole != wire.CARoleUser {
		return nil, refuse(wire.CodeRefused, "ca_not_configured", nil)
	}
	now := s.clock()
	created := time.Unix(int64(min(req.CreatedAt, uint64(1)<<62)), 0) //nolint:gosec // G115: clamped below 2^63
	if d := now.Sub(created); d > maxClockSkew || d < -maxClockSkew {
		return nil, refuse(wire.CodeRefused, "request_time_skew", nil)
	}
	subject, err := ssh.ParsePublicKey(req.SubjectKey)
	if err != nil {
		return nil, refuse(wire.CodeRefused, "bad_subject_key", err)
	}

	last, err := s.db.LastSerial(ctx)
	if err != nil {
		return nil, refuse(wire.CodeUnavailable, "state_unavailable", err)
	}
	ser, err := serial.Next(last, s.clock, time.Sleep)
	if err != nil {
		if errors.Is(err, serial.ErrClockRegression) {
			return nil, refuse(wire.CodeUnavailable, "clock_regression", err)
		}
		return nil, refuse(wire.CodeUnavailable, "serial_unavailable", err)
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
	certBytes := c.Marshal()

	err = s.db.WithTx(ctx, func(tx *sql.Tx) error {
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
		return s.db.SetLastSerial(tx, ser)
	})
	if err != nil {
		if errors.Is(err, signerdb.ErrDuplicateRequest) {
			return nil, refuse(wire.CodeRefused, "duplicate_request", err)
		}
		return nil, refuse(wire.CodeUnavailable, "state_unavailable", err)
	}
	s.log.Info("issued",
		"serial", ser,
		"key_id", c.KeyId,
		"principals", len(c.ValidPrincipals),
		"evidence", len(req.Evidence),
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: certBytes, Serial: ser}, nil
}

// buildRefusal maps a cert.Build error to a reason code.
func buildRefusal(err error) error {
	switch {
	case errors.Is(err, cert.ErrEmptyPrincipals):
		return refuse(wire.CodeRefused, "empty_principals", err)
	case errors.Is(err, cert.ErrPrincipal):
		return refuse(wire.CodeRefused, "bad_principal", err)
	case errors.Is(err, cert.ErrCertificateKey), errors.Is(err, cert.ErrSubjectKey):
		return refuse(wire.CodeRefused, "bad_subject_key", err)
	case errors.Is(err, cert.ErrKeyID):
		return refuse(wire.CodeRefused, "bad_subject", err)
	case errors.Is(err, cert.ErrValidity):
		return refuse(wire.CodeRefused, "bad_validity", err)
	case errors.Is(err, cert.ErrExtension):
		return refuse(wire.CodeRefused, "extension_not_allowed", err)
	default:
		return refuse(wire.CodeInternal, "build_failed", err)
	}
}
