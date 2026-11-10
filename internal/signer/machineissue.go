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
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// reservedMachinePrefix is the key ID subject prefix of probe certificates
// under ca=machine (03-10): a machine of that name would read as a probe
// certificate in recovery and audit, so the signer never issues for one
// (machine_name_reserved, 03-11 PD5).
const reservedMachinePrefix = "probe."

// errMachinePoP is every verifyMachinePoP failure; the refusal detail is
// machine_pop_invalid whatever the cause.
var errMachinePoP = errors.New("signer: machine proof of possession does not verify")

// MachineIssue decides on one request for a machine certificate (03-11,
// AUTH-06, D-15) and, if it passes, issues it. The signer decides from the
// admin-signed directory alone, and the identity of the requester comes
// first, by the key the directory lists (default 1, T-03-397): no state
// fact (disabled, revoked, held, bounded) is decided for anyone who has
// not proved that key. The steps, in order, each with its own refusal:
//   - global: the request validates; CreatedAt within ±300 s; the
//     bundle's installation ID, named by the request (D5); pop.machines;
//     an installed and authorized directory; a name outside the reserved
//     probe. prefix (PD5);
//   - identity: an entry of the request's name; the request's key equal
//     to the entry's key; exactly one machine-pop/v1 evidence, an SSHSIG
//     by the listed key over the signing bytes under the machine
//     namespace;
//   - state, after the proof of possession: the key not explicitly
//     revoked; the key not held (its latest certificate revoked and no
//     newer directory version installed: cert_revoked, default 2); the
//     entry active; the name not held (a logged machine subject revoke of
//     it and no newer directory version since: cert_revoked, PD11); the
//     key not one of the bundle in force; valid_for 0
//     (the signer chooses the lifetime, Q-09-6); the machine CA and
//     profile; the grant (directory.MachineGrant); the bundle still in
//     force; a request ID not used before; fewer than twelve issuances of
//     the key in the last hour (machine_renew_too_often, keyed by the key,
//     so a rename does not reset it), decided before a serial is drawn,
//     at a clock reading the serial and the issuance time may not fall
//     below (clock_regression).
//
// Then a serial, a kr3 key ID and cert.Build with exactly the grant's
// principals, the profile defaults plus the grant's extensions and the
// lifetime L = cert.MachineLifetime. The certificate leaves only after its
// machine_issue leaf, holding the request's signing bytes, the evidence
// and CapSeconds = L, and its issuance row committed, under the directory
// version it was decided under. There is no re-delivery (PD10).
func (s *Signer) MachineIssue(ctx context.Context, peer Peer, req *wire.MachineIssueRequest) (*wire.IssueResponse, error) {
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
	switch {
	case s.installationID == "":
		return nil, refusalErr(wire.CodeRefused, "machine_issue_no_installation_id", nil)
	case req.InstallationID != s.installationID:
		return nil, refusalErr(wire.CodeRefused, "machine_issue_installation_mismatch", nil)
	case s.policy == nil || s.policy.PoP == nil || !s.policy.PoP.Machines:
		return nil, refusalErr(wire.CodeRefused, "machine_pop_not_enabled", nil)
	case s.directoryRaw == nil:
		return nil, refusalErr(wire.CodeRefused, "directory_not_installed", nil)
	case !s.directoryAuthorized || s.directory == nil:
		return nil, refusalErr(wire.CodeRefused, "directory_not_authorized", nil)
	case strings.HasPrefix(req.MachineName, reservedMachinePrefix):
		return nil, refusalErr(wire.CodeRefused, "machine_name_reserved", nil)
	}

	// Identity, by the listed key (default 1, T-03-397).
	reqKey, err := parseSubjectKey(req.MachineKey)
	if err != nil {
		return nil, refusalErr(wire.CodeMalformed, "malformed_request", err)
	}
	entry, ok := s.directory.MachineByName(req.MachineName)
	if !ok {
		return nil, refusalErr(wire.CodeRefused, "unknown_machine", nil)
	}
	key := trust.FormatKey(reqKey)
	if key != entry.Key {
		return nil, refusalErr(wire.CodeRefused, "machine_key_mismatch", nil)
	}
	listed, err := trust.ParseKey(entry.Key)
	if err != nil {
		return nil, refusalErr(wire.CodeRefused, "machine_key_mismatch", err)
	}
	signed := req.SigningBytes()
	if err := verifyMachinePoP(wire.MachinePoPNamespace, signed, listed, req.Evidence); err != nil {
		return nil, refusalErr(wire.CodeRefused, "machine_pop_invalid", err)
	}

	// State, only for the holder of the listed key.
	if s.loaded.hosts.revokedKeys[key] {
		return nil, refusalErr(wire.CodeRefused, "machine_key_revoked", nil)
	}
	if d := cert.MachineCertHeld(s.loaded.machines.latest[key].prev(), s.directoryVersion); d != "" {
		return nil, refusalErr(wire.CodeRefused, d, nil)
	}
	if entry.Status != directory.StatusActive {
		return nil, refusalErr(wire.CodeRefused, "machine_disabled", nil)
	}
	// The name hold (PD11): after the disabled check, so a disabled entry
	// reports the stronger and lasting fact.
	if v, held := s.loaded.machines.nameHeld[entry.Name]; held {
		if d := cert.MachineCertHeld(cert.MachinePrev{Have: true, Revoked: true, RevokedAtDir: v}, s.directoryVersion); d != "" {
			return nil, refusalErr(wire.CodeRefused, d, nil)
		}
	}
	// Keyed by the wire bytes, as krl.InstallationKeys builds them (C11).
	if s.installationKeys[string(reqKey.Marshal())] {
		return nil, refusalErr(wire.CodeRefused, "machine_key_unusable", nil)
	}
	if req.ValidForSeconds != 0 {
		return nil, refusalErr(wire.CodeRefused, "machine_issue_valid_for_not_zero", nil)
	}
	caKey, ok := s.ca[wire.CARoleMachine]
	profile, okProfile := s.profiles[wire.CARoleMachine]
	if !ok || !okProfile {
		return nil, refusalErr(wire.CodeRefused, "ca_not_configured", nil)
	}
	grant, err := s.directory.MachineGrant(entry)
	if err != nil {
		return nil, refusalErr(wire.CodeInternal, "authorize_failed", err)
	}
	if len(grant.Principals) > cert.MaxPrincipals {
		return nil, refusalErr(wire.CodeRefused, "bad_principal", nil)
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
	if d := cert.MachineRenewTooOften(s.loaded.machines.recent[key], uint64(max(now.Unix(), 0))); d != "" { //nolint:gosec // G115: >= 0
		return nil, refusalErr(wire.CodeRefused, d, nil)
	}
	return s.issueMachineLocked(ctx, peer, req, entry, reqKey, caKey, profile, grant, now)
}

// issueMachineLocked is MachineIssue's issuance tail, issueHostLocked's: a
// serial, the kr3 key ID, cert.Build with the grant's principals and
// extensions and the lifetime L, then one transaction with the bundle
// check, the directory version check (directory_changed), the issuance
// row, the serial high-water mark and the machine_issue leaf. checkedAt is
// the clock MachineIssue checked the 12-per-hour bound at: a serial below
// it (the clock stepped back after the check) is refused as a
// clock_regression before anything is committed, since the bound counts
// more issuances at an earlier second than were checked, and audit
// verify, which evaluates the bound at the serial's second, would refuse
// the leaf. The caller holds s.mu.
func (s *Signer) issueMachineLocked(ctx context.Context, peer Peer, req *wire.MachineIssueRequest, entry *directory.Machine, key ssh.PublicKey,
	caKey ssh.Signer, profile cert.Profile, grant directory.Grant, checkedAt time.Time) (*wire.IssueResponse, error) {
	lifetime := cert.MachineLifetime(grant.MaxTTLSeconds, profile)
	// A role may grant a profile default (directory.CheckPolicy); every
	// certificate already carries those, and cert.Build takes only
	// non-default extensions as extras (login.go).
	extra := map[string]string{}
	for _, e := range grant.Extensions {
		if _, isDefault := profile.DefaultExtensions[e]; !isDefault {
			extra[e] = ""
		}
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
	// serial <= issuedAt holds here, so this also keeps the issuance clock
	// at or after the bound check. Like the check above, and unlike the
	// serial.Next branch, it logs no clock_regression leaf: the clock is
	// not below the serial high-water mark that leaf records.
	if ser < micros(checkedAt) {
		return nil, refusalErr(wire.CodeUnavailable, "clock_regression", serial.ErrClockRegression)
	}
	dirVersion := s.directoryVersion
	keyID := cert.KeyID{
		V3:        true,
		CA:        wire.CARoleMachine.String(),
		Subject:   entry.Name,
		Request:   hex.EncodeToString(req.RequestID[:]),
		Policy:    s.policy.Version,
		Directory: dirVersion,
		Serial:    ser,
	}
	c, err := cert.Build(cert.Request{
		Profile:         profile,
		Subject:         key,
		Principals:      slices.Clone(grant.Principals),
		Now:             issuedAt,
		ValidFor:        time.Duration(lifetime) * time.Second, //nolint:gosec // G115: at most the profile cap
		KeyID:           keyID,
		Serial:          ser,
		ExtraExtensions: extra,
	}, caKey, rand.Reader)
	if err != nil {
		return nil, buildRefusal(err)
	}
	certBytes := c.Marshal()
	leafBody, err := (&tlog.MachineIssueBody{
		Serial:           ser,
		PolicyVersion:    keyID.Policy,
		DirectoryVersion: dirVersion,
		CapSeconds:       lifetime,
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
			Kind:       tlog.KindMachineIssue,
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
	s.log.Info("machine certificate issued",
		"serial", ser,
		"key_id", c.KeyId,
		"leaf_index", leafIndex,
		"machine", entry.Name,
		"machine_key", ssh.FingerprintSHA256(key),
		"lifetime_s", lifetime,
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: certBytes, Serial: ser, LeafIndex: leafIndex}, nil
}

// verifyMachinePoP requires exactly one evidence item, of type
// machine-pop/v1: an SSHSIG by key (the listed key) that verifies under
// namespace over signed (03-11). It is built on verifyPoPItem.
func verifyMachinePoP(namespace string, signed []byte, key ssh.PublicKey, ev []wire.Evidence) error {
	if len(ev) != 1 {
		return errMachinePoP
	}
	if err := verifyPoPItem(ev[0], wire.EvidenceMachinePoP, namespace, signed, key); err != nil {
		return errors.Join(errMachinePoP, err)
	}
	return nil
}
