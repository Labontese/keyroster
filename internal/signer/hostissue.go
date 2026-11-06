package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// maxHostLifetime is the longest host certificate lifetime the signer
// chooses: 30 days (D-16). The lifetime is min(maxHostLifetime, the host
// profile's max_ttl_seconds in force), never the requester's (Q-09-6).
const maxHostLifetime = 2592000

// HostIssue decides on one host agent's request for a host certificate
// (03-09, AGENT-06, D-16) and, if it passes, issues it. keyroster-server
// relays it only for an approved agent whose enrolled keys hold the key
// and whose entry carries the name; the signer decides from the
// admin-signed directory alone. The steps, in order, each with its own
// refusal: the request validates; CreatedAt within ±300 s; the bundle's
// installation ID, named by the request (D5); pop.hosts; an installed and
// authorized directory; an entry of the request's name that lists the
// key; the entry active; exactly one host-pop/v1 evidence by that key over
// the signing bytes; the host CA and profile; valid_for 0 (the signer
// chooses the lifetime L = min(2592000, the cap in force), Q-09-6); the
// bundle still in force; a request ID not used before. Then a serial, a
// kr3 key ID and cert.Build with exactly the entry's principals. The
// certificate leaves only after its host_issue leaf, holding the request's
// signing bytes, the evidence and CapSeconds = L, and its issuance row
// committed, under the directory version it was decided under.
func (s *Signer) HostIssue(ctx context.Context, peer Peer, req *wire.HostIssueRequest) (*wire.IssueResponse, error) {
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
		return nil, refusalErr(wire.CodeRefused, "host_issue_no_installation_id", nil)
	case req.InstallationID != s.installationID:
		return nil, refusalErr(wire.CodeRefused, "host_issue_installation_mismatch", nil)
	case s.policy == nil || s.policy.PoP == nil || !s.policy.PoP.Hosts:
		return nil, refusalErr(wire.CodeRefused, "host_pop_not_enabled", nil)
	case s.directoryRaw == nil:
		return nil, refusalErr(wire.CodeRefused, "directory_not_installed", nil)
	case !s.directoryAuthorized || s.directory == nil:
		return nil, refusalErr(wire.CodeRefused, "directory_not_authorized", nil)
	}
	hostKey, err := parseSubjectKey(req.HostKey)
	if err != nil {
		return nil, refusalErr(wire.CodeMalformed, "malformed_request", err)
	}
	entry, ok := s.directory.HostByName(req.HostName)
	if !ok {
		return nil, refusalErr(wire.CodeRefused, "unknown_host", nil)
	}
	key := trust.FormatKey(hostKey)
	if !slices.Contains(entry.Keys, key) {
		return nil, refusalErr(wire.CodeRefused, "host_key_not_listed", nil)
	}
	if s.loaded.hosts.revokedKeys[key] {
		return nil, refusalErr(wire.CodeRefused, "host_key_revoked", nil)
	}
	if entry.Status != directory.StatusActive {
		return nil, refusalErr(wire.CodeRefused, "host_disabled", nil)
	}
	signed := req.SigningBytes()
	if err := verifyHostPoP(wire.HostPoPNamespace, signed, hostKey, req.Evidence); err != nil {
		return nil, refusalErr(wire.CodeRefused, "host_pop_invalid", err)
	}
	caKey, ok := s.ca[wire.CARoleHost]
	profile, okProfile := s.profiles[wire.CARoleHost]
	if !ok || !okProfile {
		return nil, refusalErr(wire.CodeRefused, "ca_not_configured", nil)
	}
	if req.ValidForSeconds != 0 {
		return nil, refusalErr(wire.CodeRefused, "host_issue_valid_for_not_zero", nil)
	}
	lifetime := hostLifetime(profile)
	if err := s.checkTrustCurrent(s.db.LatestBundleVersion(ctx)); err != nil {
		return nil, err
	}
	capInForce := uint64(profile.MaxTTL / time.Second) //nolint:gosec // G115: the profile cap is positive (certprofile.ForRole)
	latest, haveLatest := s.loaded.hosts.latest[key]
	switch used, err := s.db.RequestIDUsed(ctx, req.RequestID); {
	case err != nil:
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	case used:
		// An exact retry of the request the latest certificate answered
		// (byte-identical signing bytes) gets that certificate again, with
		// no new leaf (Q-09-4).
		d := ""
		if haveLatest {
			d = cert.HostCertRecent(latest.prev(), uint64(max(now.Unix(), 0)), capInForce, s.directoryVersion, entry.Principals)
		}
		switch {
		case haveLatest && latest.reqSHA256 == sha256.Sum256(signed) && d != "cert_revoked" && !latest.revoked && uint64(max(now.Unix(), 0)) < latest.cert.ValidBefore:
			return s.redeliverLocked(peer, hostKey, latest, "exact_retry"), nil
		case d == "cert_revoked":
			return nil, refusalErr(wire.CodeRefused, "cert_revoked", nil)
		}
		return nil, refusalErr(wire.CodeRefused, "duplicate_request", signerdb.ErrDuplicateRequest)
	}
	return s.issueHostLocked(ctx, peer, req, entry, hostKey, caKey, profile, lifetime, capInForce)
}

// redeliverLocked answers a host request with key's latest certificate,
// already issued and logged (Q-09-4): no leaf, no row, and the index is
// unchanged. A journal line records it.
func (s *Signer) redeliverLocked(peer Peer, hostKey ssh.PublicKey, l hostLatest, reason string) *wire.IssueResponse {
	s.log.Info("host certificate re-delivered",
		"serial", l.serial,
		"reason", reason,
		"host_key", ssh.FingerprintSHA256(hostKey),
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: slices.Clone(l.certBytes), Serial: l.serial, LeafIndex: l.leaf}
}

// hostLifetime is the lifetime the signer chooses for a host certificate:
// min(maxHostLifetime, the host profile's cap in force), in seconds
// (Q-09-6). It is also the host_issue leaf's CapSeconds.
func hostLifetime(profile cert.Profile) uint64 {
	return min(maxHostLifetime, uint64(profile.MaxTTL/time.Second)) //nolint:gosec // G115: the profile cap is positive (certprofile.ForRole)
}

// issueHostLocked is HostIssue's issuance tail, LoginIssue's: a serial, the
// kr3 key ID, cert.Build with the entry's principals and the chosen
// lifetime, then one transaction with the bundle check, the directory
// version check (directory_changed), the issuance row, the serial
// high-water mark and the host_issue leaf. The caller holds s.mu.
func (s *Signer) issueHostLocked(ctx context.Context, peer Peer, req *wire.HostIssueRequest, entry *directory.Host, hostKey ssh.PublicKey,
	caKey ssh.Signer, profile cert.Profile, lifetime, capInForce uint64) (*wire.IssueResponse, error) {
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
	// The issuance bounds per host key (Q-09-2, Q-09-5, D6), from the
	// in-memory index, at the instant cert.Build gets: a revoked latest
	// certificate holds the key until a newer directory version; inside the
	// window the latest certificate is re-delivered instead of re-issued.
	if latest, ok := s.loaded.hosts.latest[trust.FormatKey(hostKey)]; ok {
		nowSecs := uint64(max(issuedAt.Unix(), 0))
		switch cert.HostCertRecent(latest.prev(), nowSecs, capInForce, s.directoryVersion, entry.Principals) {
		case "cert_revoked":
			return nil, refusalErr(wire.CodeRefused, "cert_revoked", nil)
		case "host_cert_recent":
			if !latest.revoked && nowSecs < latest.cert.ValidBefore {
				return s.redeliverLocked(peer, hostKey, latest, "recent"), nil
			}
			return nil, refusalErr(wire.CodeRefused, "host_cert_recent", nil)
		}
	}
	dirVersion := s.directoryVersion
	keyID := cert.KeyID{
		V3:        true,
		CA:        wire.CARoleHost.String(),
		Subject:   entry.Name,
		Request:   hex.EncodeToString(req.RequestID[:]),
		Policy:    s.policy.Version,
		Directory: dirVersion,
		Serial:    ser,
	}
	c, err := cert.Build(cert.Request{
		Profile:    profile,
		Subject:    hostKey,
		Principals: slices.Clone(entry.Principals),
		Now:        issuedAt,
		ValidFor:   time.Duration(lifetime) * time.Second, //nolint:gosec // G115: at most maxHostLifetime
		KeyID:      keyID,
		Serial:     ser,
	}, caKey, rand.Reader)
	if err != nil {
		return nil, buildRefusal(err)
	}
	certBytes := c.Marshal()
	leafBody, err := (&tlog.HostIssueBody{
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
			Kind:       tlog.KindHostIssue,
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
	s.log.Info("host certificate issued",
		"serial", ser,
		"key_id", c.KeyId,
		"leaf_index", leafIndex,
		"host", entry.Name,
		"host_key", ssh.FingerprintSHA256(hostKey),
		"lifetime_s", lifetime,
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: certBytes, Serial: ser, LeafIndex: leafIndex}, nil
}

// errHostPoP is every verifyHostPoP failure; the refusal detail is
// host_pop_invalid whatever the cause.
var errHostPoP = errors.New("signer: host proof of possession does not verify")

// verifyHostPoP requires exactly one evidence item of type host-pop/v1, an
// SSHSIG whose key is key and which verifies under namespace over signed
// (03-09). 03-10's probes reuse it with their own namespace.
func verifyHostPoP(namespace string, signed []byte, key ssh.PublicKey, ev []wire.Evidence) error {
	if len(ev) != 1 || ev[0].Type != wire.EvidenceHostPoP {
		return errHostPoP
	}
	sig, err := sshsig.Parse(ev[0].Blob)
	if err != nil {
		return errors.Join(errHostPoP, err)
	}
	if !bytes.Equal(sig.PublicKey().Marshal(), key.Marshal()) {
		return errHostPoP
	}
	if err := sig.Verify(namespace, signed); err != nil {
		return errors.Join(errHostPoP, err)
	}
	return nil
}
