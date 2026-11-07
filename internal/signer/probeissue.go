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
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serial"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// ProbeIssue decides on one host agent's request for a probe certificate
// (03-10, D-06) and, if it passes, issues it. A probe certificate is a user
// certificate of the machine CA for exactly the principal
// keyroster-probe:<host> and the request's ephemeral probe key, with no
// extension and exactly the critical options force-command /bin/false and
// source-address 127.0.0.0/8,::1/128, so sshd accepts it only for the
// probe account of that host, from loopback, with no session. The agent
// uses a positive and a negative one to prove that its sshd accepts and
// enforces what it was given; for a Negative request the signer revokes
// the new certificate's own serial in the same transaction.
//
// The steps, in order, each with its own refusal: the request validates;
// CreatedAt within ±300 s; the bundle's installation ID, named by the
// request (D5); pop.hosts; an installed and authorized directory; an
// entry of the request's name that lists the host key; the key not
// explicitly revoked; the entry active; host-pop/v1 by the host key, then
// probe-pop/v1 by the probe key, both under ProbePoPNamespace over the
// signing bytes; a probe key that is neither the host key, nor a key of
// the bundle in force, nor a key the directory lists; valid_for 0 (the
// signer chooses the lifetime L = min(604800, the machine cap in force),
// Q-09-6); the machine CA and the probe profile; the bundle still in
// force; a request ID not used before. keyroster-server relays it only for
// an approved agent's own entry and key; the signer decides from the
// admin-signed directory alone.
func (s *Signer) ProbeIssue(ctx context.Context, peer Peer, req *wire.ProbeIssueRequest) (*wire.IssueResponse, error) {
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
		return nil, refusalErr(wire.CodeRefused, "probe_issue_no_installation_id", nil)
	case req.InstallationID != s.installationID:
		return nil, refusalErr(wire.CodeRefused, "probe_issue_installation_mismatch", nil)
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
	probeKey, err := parseSubjectKey(req.ProbeKey)
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
	if detail, err := verifyProbePoP(signed, hostKey, probeKey, req.Evidence); err != nil {
		return nil, refusalErr(wire.CodeRefused, detail, err)
	}
	if !probeKeyUsable(req.ProbeKey, req.HostKey, s.installationKeys, s.directory) {
		return nil, refusalErr(wire.CodeRefused, "probe_key_unusable", nil)
	}
	if req.ValidForSeconds != 0 {
		return nil, refusalErr(wire.CodeRefused, "probe_issue_valid_for_not_zero", nil)
	}
	caKey, ok := s.ca[wire.CARoleMachine]
	profile, perr := certprofile.ProbeProfile(s.policy)
	if !ok || perr != nil {
		return nil, refusalErr(wire.CodeRefused, "ca_not_configured", perr)
	}
	lifetime := certprofile.ProbeLifetime(profile)
	if err := s.checkTrustCurrent(s.db.LatestBundleVersion(ctx)); err != nil {
		return nil, err
	}
	nowSecs := uint64(max(now.Unix(), 0))
	latest, haveLatest := s.loaded.probes.latest(entry.Name, req.Negative)
	switch used, err := s.db.RequestIDUsed(ctx, req.RequestID); {
	case err != nil:
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	case used:
		// An exact retry of the request the latest certificate of its host
		// and polarity answered (byte-identical signing bytes) gets that
		// certificate again while it is valid, with no leaf, no row and no
		// serial (Q-09-4).
		if haveLatest && latest.reqSHA256 == sha256.Sum256(signed) && nowSecs < latest.cert.ValidBefore {
			return s.redeliverProbeLocked(peer, entry.Name, latest), nil
		}
		return nil, refusalErr(wire.CodeRefused, "duplicate_request", signerdb.ErrDuplicateRequest)
	}
	// One new certificate per host name and polarity per min(3600, L/3),
	// L being the lifetime the new certificate gets (D6, Q-09-4), decided
	// before a serial is drawn.
	if haveLatest && certprofile.ProbeCertRecent(latest.issued, lifetime, nowSecs) != "" {
		return nil, refusalErr(wire.CodeRefused, "probe_cert_recent", nil)
	}
	return s.issueProbeLocked(ctx, peer, req, entry, probeKey, caKey, profile, lifetime)
}

// probePublishMargin is how long the published negative predecessor of a
// host must stay valid for a new negative row to ride the hourly publish
// instead of publishing at once (03-10, Q1): one republish interval plus
// one more hour.
const probePublishMargin = 2 * time.Hour

// redeliverProbeLocked answers a probe request with the latest probe
// certificate of its host and polarity, already issued and logged
// (Q-09-4): no leaf, no row, and the index is unchanged. A journal line
// records it.
func (s *Signer) redeliverProbeLocked(peer Peer, host string, l probeLatest) *wire.IssueResponse {
	s.log.Info("probe certificate re-delivered",
		"serial", l.serial,
		"reason", "exact_retry",
		"host", host,
		"negative", l.negative,
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: slices.Clone(l.certBytes), Serial: l.serial, LeafIndex: l.leaf}
}

// issueProbeLocked is ProbeIssue's issuance tail, HostIssue's: a serial,
// the kr3 key ID, cert.Build under the probe profile with the one
// principal and the two options, then one transaction with the bundle
// check, the directory version check (directory_changed), the issuance
// row, the serial high-water mark and the probe_issue leaf, and for a
// Negative request the revocation row of the certificate's own serial and
// the KRL publish. Row, leaf and publish are this one function and this
// one transaction, so no edit can split them. The caller holds s.mu.
func (s *Signer) issueProbeLocked(ctx context.Context, peer Peer, req *wire.ProbeIssueRequest, entry *directory.Host, probeKey ssh.PublicKey,
	caKey ssh.Signer, profile cert.Profile, lifetime uint64) (*wire.IssueResponse, error) {
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
		V3:        true,
		CA:        wire.CARoleMachine.String(),
		Subject:   "probe." + entry.Name,
		Request:   hex.EncodeToString(req.RequestID[:]),
		Policy:    s.policy.Version,
		Directory: dirVersion,
		Serial:    ser,
	}
	c, err := cert.Build(cert.Request{
		Profile:         profile,
		Subject:         probeKey,
		Principals:      []string{"keyroster-probe:" + entry.Name},
		Now:             issuedAt,
		ValidFor:        time.Duration(lifetime) * time.Second, //nolint:gosec // G115: at most MaxProbeLifetimeSeconds
		KeyID:           keyID,
		Serial:          ser,
		CriticalOptions: certprofile.ProbeCriticalOptions(),
	}, caKey, rand.Reader)
	if err != nil {
		return nil, buildRefusal(err)
	}
	certBytes := c.Marshal()
	body := &tlog.ProbeIssueBody{
		Serial:           ser,
		Negative:         req.Negative,
		PolicyVersion:    keyID.Policy,
		DirectoryVersion: dirVersion,
		CapSeconds:       lifetime,
		Request:          req.SigningBytes(),
		Evidence:         req.Evidence,
		Cert:             certBytes,
		KeyID:            c.KeyId,
	}
	leafBody, err := body.Encode()
	if err != nil {
		return nil, refusalErr(wire.CodeInternal, "log_encoding", err)
	}
	// The revocation row of a negative probe comes from the one derivation
	// the log state and audit use (03-10).
	revoked, err := body.RevokedEntries()
	if err != nil {
		return nil, refusalErr(wire.CodeInternal, "log_encoding", err)
	}
	// The publish rule (Q1), decided on the committed index before this
	// issuance: a Negative row rides the hourly republish while the host's
	// latest negative predecessor is published and valid for
	// probePublishMargin more; otherwise it waits for the prompt flag while
	// the last probe-caused publish is younger than krlCheckInterval;
	// otherwise it publishes at once. Whichever way, the transaction
	// encodes the whole publish set first (krl_too_large refuses with
	// nothing written).
	issuedSecs := uint64(max(issuedAt.Unix(), 0)) //nolint:gosec // G115: >= 0
	ride := req.Negative && s.loaded.probes.coversUntil(entry.Name, issuedSecs+uint64(probePublishMargin/time.Second))
	coalesce := req.Negative && !ride && probePublishTooRecent(s.lastProbePublish, issuedAt)
	var (
		leafIndex   uint64
		published   *signerdb.KRLState
		publishLeaf uint64
	)
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
			Kind:       tlog.KindProbeIssue,
			Body:       leafBody,
		})
		if err != nil {
			return err
		}
		leafIndex = idx
		if !req.Negative {
			return nil
		}
		for _, e := range revoked {
			row := revocationRow(e, req.RequestID, idx, issuedAt)
			if err := s.db.InsertRevocation(tx, row); err != nil {
				return err
			}
		}
		if ride || coalesce {
			return s.checkKRLFitsLocked(ctx, tx, issuedAt)
		}
		published, publishLeaf, err = s.publishKRLLocked(ctx, tx, issuedAt)
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
	switch {
	case published != nil:
		s.krl.Store(published)
		s.lastProbePublish = issuedAt
	case coalesce:
		s.probePrompt = true
	}
	s.clockEpisode = false
	// Only now, after COMMIT, does the certificate leave the signer.
	s.log.Info("probe certificate issued",
		"serial", ser,
		"key_id", c.KeyId,
		"leaf_index", leafIndex,
		"negative", req.Negative,
		"publish_leaf", publishLeaf,
		"rides", ride,
		"prompt", coalesce,
		"host", entry.Name,
		"probe_key", ssh.FingerprintSHA256(probeKey),
		"lifetime_s", lifetime,
		"uid", peer.UID,
		"pid", peer.PID)
	return &wire.IssueResponse{Cert: certBytes, Serial: ser, LeafIndex: leafIndex}, nil
}

// errProbePoP is every verifyProbePoP failure.
var errProbePoP = errors.New("signer: probe proof of possession does not verify")

// verifyProbePoP requires exactly two evidence items in this order (03-10):
// host-pop/v1, an SSHSIG by hostKey, then probe-pop/v1, an SSHSIG by
// probeKey, both verifying under wire.ProbePoPNamespace over signed. It
// returns the refusal detail of the first item that fails: host_pop_invalid
// or probe_pop_invalid. A host-key signature made for a host certificate
// request (wire.HostPoPNamespace) never verifies here.
func verifyProbePoP(signed []byte, hostKey, probeKey ssh.PublicKey, ev []wire.Evidence) (string, error) {
	if len(ev) != 2 {
		return "host_pop_invalid", errProbePoP
	}
	if err := verifyPoPItem(ev[0], wire.EvidenceHostPoP, wire.ProbePoPNamespace, signed, hostKey); err != nil {
		return "host_pop_invalid", err
	}
	if err := verifyPoPItem(ev[1], wire.EvidenceProbePoP, wire.ProbePoPNamespace, signed, probeKey); err != nil {
		return "probe_pop_invalid", err
	}
	return "", nil
}

// verifyPoPItem requires e to be of type typ and an SSHSIG by key that
// verifies under namespace over signed.
func verifyPoPItem(e wire.Evidence, typ, namespace string, signed []byte, key ssh.PublicKey) error {
	if e.Type != typ {
		return errProbePoP
	}
	sig, err := sshsig.Parse(e.Blob)
	if err != nil {
		return errors.Join(errProbePoP, err)
	}
	if !bytes.Equal(sig.PublicKey().Marshal(), key.Marshal()) {
		return errProbePoP
	}
	if err := sig.Verify(namespace, signed); err != nil {
		return errors.Join(errProbePoP, err)
	}
	return nil
}

// probeKeyUsable reports whether probe (SSH wire format) may be certified
// as a probe key (03-10): it is not the host key, not a key of the bundle
// in force (installationKeys) and not a key any host or machine entry of
// dir lists. Otherwise the log would bind a key that has another role to
// a probe name.
func probeKeyUsable(probe, hostKey []byte, installationKeys map[string]bool, dir *directory.Directory) bool {
	if bytes.Equal(probe, hostKey) || installationKeys[string(probe)] {
		return false
	}
	pub, err := ssh.ParsePublicKey(probe)
	if err != nil {
		return false
	}
	k := trust.FormatKey(pub)
	for _, h := range dir.Hosts {
		if slices.Contains(h.Keys, k) {
			return false
		}
	}
	for _, m := range dir.Machines {
		if m.Key == k {
			return false
		}
	}
	return true
}
