package signer

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// RecoveryResult reports an applied revocation recovery: the indexes of
// its revocation_recovery and krl_publish log entries, the KRL version it
// published, and the counts of the entries it listed, the KRL versions it
// imported and the carried certificates it revoked and kept.
type RecoveryResult struct {
	RecoveryLeaf uint64
	PublishLeaf  uint64
	KRLVersion   uint64
	Entries      int
	Imports      int
	Revoked      int
	Kept         int
}

// recoveryRefusal is a recovery refusal: the reason name, with cause for
// the operator.
func recoveryRefusal(name string, cause error) error {
	return refusalErr(wire.CodeRefused, name, cause)
}

// recoveryRoles maps a key ID's CA field to the CA role.
var recoveryRoles = map[string]wire.CARole{
	trust.RoleUser:    wire.CARoleUser,
	trust.RoleHost:    wire.CARoleHost,
	trust.RoleMachine: wire.CARoleMachine,
}

// RecoverRevocations applies one revocation recovery (03-06b): it imports
// the revocations a restore of this signer's state lost, from ops-signed
// KRL versions and the lost certificates the request carries, in ONE
// transaction that appends one revocation_recovery entry, writes one
// revocation row per entry, records the request ID and publishes one KRL.
// keyroster-signer recover-revocations calls it under the state lock,
// before the restored signer ever serves; on any refusal or failure
// nothing is written. It only ever adds revocations: every restored row
// stays, and an entry's ValidBefore comes from a certificate with the same
// CA key and serial (or the serial its key ID names), else it is 0 and the
// entry is never pruned (krl.RecoveryEntries).
//
// In order, each failure a named refusal: the file form parses
// (recovery_malformed); the bundle in force has an installation ID
// (krl_no_installation_id) and it is the request's
// (recovery_installation_mismatch); the request names exactly this log,
// its size and root (recovery_log_mismatch), so it applies once and to
// nothing else; its request ID is unused (duplicate_request); its evidence
// is admin-sshsig/v1 by at least one admin of the policy in force over its
// signing bytes under keyroster/revoke-recovery/v1
// (recovery_evidence_invalid); every import verifies under the ops key of
// the bundle in force and its installation ID, parses, and carries the
// manifest's version in its header (recovery_import_invalid); every
// certificate verifies under its signature key, which is a CA key of the
// role its key ID names in the bundle in force, and its key ID names its
// serial (recovery_certificate_invalid); every certificate is one
// krl.CheckCarriedLost admits at the request's CreatedAt: revoked, or
// still live then (recovery_certificate_expired) and not a user
// certificate (recovery_user_certificate_kept: the owner's answer
// revoke-users-list-others revokes every lost user certificate, whatever
// any clock says). Then, inside the transaction: the bundle is
// still the one loaded at start; every certificate is above the restored
// serial high-water mark and not in the issuance table
// (recovery_certificate_not_lost); the entries (krl.RecoveryEntries, with
// the issuance table as the lookup) stay within tlog.MaxRecoveryEntries
// and tlog.MaxRecoveryBody (recovery_too_large); and the KRL published is
// above every imported version (recovery_version_not_above_import, which
// names the seconds to wait).
func (s *Signer) RecoverRevocations(ctx context.Context, data []byte) (*RecoveryResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := wire.ParseRecoveryRequest(data)
	if err != nil {
		return nil, recoveryRefusal("recovery_malformed", err)
	}
	signing, err := req.SigningBytes()
	if err != nil {
		return nil, recoveryRefusal("recovery_malformed", err)
	}
	switch {
	case s.installationID == "":
		return nil, refusalErr(wire.CodeUnavailable, "krl_no_installation_id", errors.New("the trust bundle in force has no installation ID, so this signer publishes no KRL"))
	case req.InstallationID != s.installationID:
		return nil, recoveryRefusal("recovery_installation_mismatch",
			fmt.Errorf("the request is for installation %s, this signer's trust bundle for %s", req.InstallationID, s.installationID))
	}
	root, err := s.tree.Root()
	if err != nil {
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	}
	if req.RestoredSize != s.tree.Size() || !bytes.Equal(req.RestoredRoot[:], root) {
		return nil, recoveryRefusal("recovery_log_mismatch",
			fmt.Errorf("the request is for a log of %d entries with root %x, this signer's log has %d entries with root %x "+
				"(the signer logged something after the restore, or the request was already applied)",
				req.RestoredSize, req.RestoredRoot, s.tree.Size(), root))
	}
	switch used, err := s.db.RevokeRequestUsed(ctx, req.RequestID); {
	case err != nil:
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	case used:
		return nil, refusalErr(wire.CodeRefused, "duplicate_request", signerdb.ErrDuplicateRequest)
	}
	admins, err := verifyAdminSignatures(req.Evidence, signing, wire.RecoverySSHSIGNamespace, 1, s.policy)
	if err != nil {
		return nil, recoveryRefusal("recovery_evidence_invalid", err)
	}
	imports, maxImport, err := s.checkRecoveryImports(req.Imports)
	if err != nil {
		return nil, err
	}
	certs, err := s.checkRecoveryCertificates(req.Certificates)
	if err != nil {
		return nil, err
	}
	now := s.clock()
	resolvedAt := uint64(max(now.Unix(), 0)) //nolint:gosec // G115: >= 0
	revoked := 0
	for _, c := range certs {
		switch err := krl.CheckCarriedLost(c.ValidBefore, req.CreatedAt, c.role == wire.CARoleUser, c.Revoke); {
		case errors.Is(err, krl.ErrLostExpired):
			return nil, recoveryRefusal("recovery_certificate_expired",
				fmt.Errorf("lost certificate serial %d expired before the request was created (valid before %d, created at %d) and is not revoked; a recovery carries only the lost certificates it revokes or that are still live then", c.Serial, c.ValidBefore, req.CreatedAt))
		case errors.Is(err, krl.ErrLostUserKept):
			return nil, recoveryRefusal("recovery_user_certificate_kept",
				fmt.Errorf("lost user certificate serial %d is not revoked; a recovery revokes every lost user certificate (revoke-users-list-others)", c.Serial))
		}
		if c.Revoke {
			revoked++
		}
	}
	highWater, err := s.db.LastSerial(ctx)
	if err != nil {
		return nil, refusalErr(wire.CodeUnavailable, "state_unavailable", err)
	}

	var (
		recoveryLeaf, publishLeaf uint64
		published                 *signerdb.KRLState
		entries                   []tlog.RevokedEntry
	)
	err = s.logTx(ctx, func(tx *sql.Tx) error {
		// The admins the evidence was checked against come from the
		// policy loaded at start; commit only while it is still in force.
		if err := s.checkTrustCurrent(s.db.LatestBundleVersionTx(ctx, tx)); err != nil {
			return err
		}
		rcs := make([]krl.RecoveredCert, 0, len(certs))
		for _, c := range certs {
			is, err := s.db.IssuanceBySerialTx(ctx, tx, c.Serial)
			if err != nil {
				return err
			}
			if is != nil || c.Serial <= highWater {
				return recoveryRefusal("recovery_certificate_not_lost",
					fmt.Errorf("certificate serial %d is not lost: it is in the issuance table or at or below the serial high-water mark %d", c.Serial, highWater))
			}
			rcs = append(rcs, c.RecoveredCert)
		}
		// The lookup is the issuance table alone (PR #66 review): a
		// certificate the restored log knows only from an earlier
		// recovery gives ValidBefore 0, never pruned (T-03-269).
		var lookupErr error
		lookup := func(serial uint64) ([]byte, string, uint64, bool) {
			is, err := s.db.IssuanceBySerialTx(ctx, tx, serial)
			if err != nil {
				lookupErr = err
				return nil, "", 0, false
			}
			if is == nil {
				return nil, "", 0, false
			}
			caKey, validBefore, err := certCAKey(is.Cert)
			if err != nil {
				lookupErr = err
				return nil, "", 0, false
			}
			return caKey, is.KeyID, validBefore, true
		}
		derived, err := krl.RecoveryEntries(imports, rcs, lookup)
		switch {
		case errors.Is(err, krl.ErrRecoveryTooLarge):
			return recoveryRefusal("recovery_too_large", err)
		case err != nil:
			return recoveryRefusal("recovery_import_invalid", err)
		case lookupErr != nil:
			return lookupErr
		case len(derived) > tlog.MaxRecoveryEntries:
			return recoveryRefusal("recovery_too_large", fmt.Errorf("%d entries, at most %d", len(derived), tlog.MaxRecoveryEntries))
		}
		for _, e := range derived {
			// Only an import with a field beyond a log entry's limits
			// gives one (this installation never publishes such a KRL).
			if len(e.KeyID) > tlog.MaxKeyID || len(e.CAKey) > wire.MaxSubjectKeyLen || len(e.Key) > wire.MaxSubjectKeyLen {
				return recoveryRefusal("recovery_import_invalid", errors.New("an imported entry exceeds the limits of a log entry"))
			}
		}
		entries = tlogEntries(derived)
		body, err := (&tlog.RecoveryBody{
			PolicyVersion:     s.policy.Version,
			ResolvedAtSeconds: resolvedAt,
			Request:           signing,
			Evidence:          req.Evidence,
			Entries:           entries,
		}).Encode()
		if err != nil {
			return recoveryRefusal("recovery_too_large", err)
		}
		idx, err := s.appendLocked(ctx, tx, tlog.Leaf{TimeMicros: micros(now), Kind: tlog.KindRevocationRecovery, Body: body})
		if err != nil {
			return err
		}
		recoveryLeaf = idx
		// Each row names the leaf that holds its entry (loggedRevocations
		// ties the two by leaf index).
		for _, e := range entries {
			if err := s.db.InsertRevocation(tx, revocationRow(e, req.RequestID, idx, now)); err != nil {
				return err
			}
		}
		if err := s.db.InsertRevokeRequestTx(tx, req.RequestID, idx); err != nil {
			return err
		}
		if published, publishLeaf, err = s.publishKRLLocked(ctx, tx, now); err != nil {
			return err
		}
		// Every host that saw an imported version accepts only a higher
		// one: refuse a publish that is not above all of them, so the
		// transaction rolls back.
		if published.Version <= maxImport {
			return recoveryRefusal("recovery_version_not_above_import",
				fmt.Errorf("the KRL this recovery would publish is version %d, not above the imported version %d; wait %d s (until the clock passes it) and run it again",
					published.Version, maxImport, maxImport+1-resolvedAt))
		}
		return nil
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
	res := &RecoveryResult{
		RecoveryLeaf: recoveryLeaf, PublishLeaf: publishLeaf, KRLVersion: published.Version,
		Entries: len(entries), Imports: len(imports), Revoked: revoked, Kept: len(certs) - revoked,
	}
	s.log.Info("revocations recovered",
		"entries", res.Entries,
		"imports", res.Imports,
		"revoked", res.Revoked,
		"kept", res.Kept,
		"krl_version", res.KRLVersion,
		"recovery_leaf", res.RecoveryLeaf,
		"publish_leaf", res.PublishLeaf,
		"admins", strings.Join(admins, ","))
	return res, nil
}

// checkRecoveryImports verifies every import of a recovery against the
// bundle in force and returns them parsed, with the highest imported KRL
// version (0 for none).
func (s *Signer) checkRecoveryImports(imports []wire.RecoveryImport) ([]*krl.Parsed, uint64, error) {
	var (
		out       []*krl.Parsed
		maxImport uint64
	)
	for i, im := range imports {
		m, err := krl.VerifyManifest(im.Manifest, im.Sig, im.KRL, s.bundle, s.installationID, 0)
		if errors.Is(err, krl.ErrSigner) {
			// Possible only after 03-13's ops-key rotation: the hold stays.
			return nil, 0, recoveryRefusal("recovery_import_invalid",
				fmt.Errorf("import %d is signed under an ops key the restored trust bundle does not name: %w", i, err))
		}
		if err != nil {
			return nil, 0, recoveryRefusal("recovery_import_invalid", fmt.Errorf("import %d: %w", i, err))
		}
		p, err := krl.Parse(im.KRL)
		if err != nil {
			return nil, 0, recoveryRefusal("recovery_import_invalid", fmt.Errorf("import %d (KRL v%d): %w", i, m.KRLVersion, err))
		}
		if p.Version != m.KRLVersion {
			return nil, 0, recoveryRefusal("recovery_import_invalid",
				fmt.Errorf("import %d: the KRL header says version %d, its signed manifest %d", i, p.Version, m.KRLVersion))
		}
		out = append(out, p)
		maxImport = max(maxImport, m.KRLVersion)
	}
	return out, maxImport, nil
}

// recoveryCert is a verified certificate a recovery carries, with its CA
// role.
type recoveryCert struct {
	krl.RecoveredCert
	role wire.CARole
}

// checkRecoveryCertificates verifies every certificate a recovery
// carries: it parses as a certificate in canonical encoding whose
// signature verifies under its signature key, that key is a CA key of the
// role its key ID names in the bundle in force (krl.RoleCAKeys), and its
// key ID parses and names its serial.
func (s *Signer) checkRecoveryCertificates(carried []wire.RecoveredCertificate) ([]recoveryCert, error) {
	out := make([]recoveryCert, 0, len(carried))
	for i, rc := range carried {
		c, kid, err := verifyCarriedCert(rc.Cert)
		if err != nil {
			return nil, recoveryRefusal("recovery_certificate_invalid", fmt.Errorf("certificate %d: %w", i, err))
		}
		role, ok := recoveryRoles[kid.CA]
		if !ok || !slices.ContainsFunc(s.roleCAKeys[role], func(k []byte) bool { return bytes.Equal(k, c.SignatureKey.Marshal()) }) {
			return nil, recoveryRefusal("recovery_certificate_invalid",
				fmt.Errorf("certificate %d (serial %d) is signed by %s, not by a %s CA key of the trust bundle in force", i, c.Serial, ssh.FingerprintSHA256(c.SignatureKey), kid.CA))
		}
		out = append(out, recoveryCert{
			RecoveredCert: krl.RecoveredCert{CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, KeyID: c.KeyId, ValidBefore: c.ValidBefore, Revoke: rc.Revoke},
			role:          role,
		})
	}
	return out, nil
}

// verifyCarriedCert parses blob as a certificate in canonical encoding
// whose CA signature verifies under its signature key and whose key ID
// parses and names its serial.
func verifyCarriedCert(blob []byte) (*ssh.Certificate, cert.KeyID, error) {
	var none cert.KeyID
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, none, fmt.Errorf("does not parse: %w", err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok || c.SignatureKey == nil || c.Signature == nil {
		return nil, none, errors.New("is not a signed certificate")
	}
	if !bytes.Equal(c.Marshal(), blob) {
		return nil, none, errors.New("is not canonically encoded")
	}
	if _, isCert := c.SignatureKey.(*ssh.Certificate); isCert {
		return nil, none, errors.New("is signed by a certificate")
	}
	if err := c.SignatureKey.Verify(certSignedBytes(c), c.Signature); err != nil {
		return nil, none, fmt.Errorf("CA signature does not verify: %w", err)
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil {
		return nil, none, fmt.Errorf("key ID: %w", err)
	}
	if kid.Serial != c.Serial {
		return nil, none, fmt.Errorf("key ID names serial %d, the certificate's serial is %d", kid.Serial, c.Serial)
	}
	return c, kid, nil
}

// certSignedBytes returns the bytes a CA signed: the certificate encoding
// without its final signature field (PROTOCOL.certkeys).
func certSignedBytes(c *ssh.Certificate) []byte {
	c2 := *c
	c2.Signature = nil
	out := c2.Marshal()
	return out[:len(out)-4] // drop the empty signature's length prefix
}

// tlogEntries maps derived entries to the revoked entries a log leaf
// records. An explicit key carries no ValidBefore.
func tlogEntries(entries []krl.Entry) []tlog.RevokedEntry {
	kinds := map[uint8]uint8{krl.EntrySerial: tlog.RevokedSerial, krl.EntryKeyID: tlog.RevokedKeyID, krl.EntryKey: tlog.RevokedKey}
	out := make([]tlog.RevokedEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, tlog.RevokedEntry{Kind: kinds[e.Kind], CAKey: e.CAKey, Serial: e.Serial, KeyID: e.KeyID, Key: e.Key, ValidBeforeSeconds: e.ValidBefore})
	}
	return out
}
