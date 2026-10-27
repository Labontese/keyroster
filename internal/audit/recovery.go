package audit

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// verifyRecovery checks one revocation_recovery entry (kind 15, 03-06b) at
// index, with leaf time leafMicros, where rootBefore is the root of the
// entries before it, against the trust state in force and the log before
// it, and returns the certificates it carries:
//
//   - its logged request parses strictly (wire.ParseRecoverySigningBytes),
//     names the installation of the bundle in force, and names the log
//     before it: its restored size is the entry's index and its restored
//     root rootBefore;
//   - its evidence is admin-sshsig/v1 under keyroster/revoke-recovery/v1
//     over exactly those bytes, every item by an admin of the policy in
//     force and at least one; the entry records that policy's version;
//   - its resolution time × 10^6 is not after the leaf time, and its
//     request ID was used by no earlier revoke or recovery entry;
//   - every import verifies under the ops key of the bundle in force and
//     its installation ID (krl.VerifyManifest), parses (krl.Parse), has the
//     manifest's version in its KRL header and no fingerprint section;
//   - every carried certificate verifies under its signature key, which
//     is a CA key of the role its key ID names in the bundle in force, its
//     key ID names its serial, and it is new to the log's issuance: no
//     issue or login_issue entry logged it and its serial is above theirs;
//   - every carried certificate is one krl.CarriesLost admits at the
//     request's CreatedAt, revoked or still live then, as the signer
//     requires (recovery_certificate_expired);
//   - every carried user certificate live at the resolution time is
//     revoked (the owner's answer revoke-users-list-others);
//   - the entries are exactly krl.RecoveryEntries over the imports and the
//     carried certificates, with the log's issued certificates as the
//     lookup, as the signer derives them;
//   - the next entry is its krl_publish, above every imported version
//     (before, verifyKRLPublish).
//
// A carried certificate never joins the log's issuance (rs.certs, subject
// and key-ID resolution), as it never joins the signer's issuance table.
func verifyRecovery(index uint64, body *tlog.RecoveryBody, leafMicros uint64, rootBefore []byte, a *anchor, rs *revocations, iss *issuance) ([][]byte, error) {
	req, err := wire.ParseRecoverySigningBytes(body.Request)
	if err != nil {
		return nil, fmt.Errorf("logged recovery request: %w", err)
	}
	if a.bundle == nil || a.policy == nil {
		return nil, errors.New("revocation_recovery entry before the first bundle_install: no root-signed policy is in force")
	}
	if a.bundle.InstallationID == "" {
		return nil, fmt.Errorf("trust bundle v%d in force has no installation ID, and the signer recovers nothing without one", a.bundle.Version)
	}
	if req.InstallationID != a.bundle.InstallationID {
		return nil, fmt.Errorf("the recovery is for installation %s, but trust bundle v%d in force is for %s (recovery_installation_mismatch)",
			req.InstallationID, a.bundle.Version, a.bundle.InstallationID)
	}
	if body.PolicyVersion != a.policy.Version {
		return nil, fmt.Errorf("entry records policy version %d, but the policy in force is version %d", body.PolicyVersion, a.policy.Version)
	}
	if req.RestoredSize != index {
		return nil, fmt.Errorf("the recovery names a restored log of %d entries, but it is entry %d (recovery_log_mismatch)", req.RestoredSize, index)
	}
	if !bytes.Equal(req.RestoredRoot[:], rootBefore) {
		return nil, fmt.Errorf("the recovery names a restored root that is not the root of the %d entries before it (recovery_log_mismatch)", index)
	}
	if err := verifyRevokeAdmins(body.Evidence, body.Request, wire.RecoverySSHSIGNamespace, a.policy); err != nil {
		return nil, err
	}
	if body.ResolvedAtSeconds > math.MaxUint64/1_000_000 || body.ResolvedAtSeconds*1_000_000 > leafMicros {
		return nil, fmt.Errorf("resolution time %d s is after the leaf time %d µs: the signer resolves a recovery at the clock reading the leaf time is taken from, and only ever raises the leaf time",
			body.ResolvedAtSeconds, leafMicros)
	}
	if first, used := rs.requests[req.RequestID]; used {
		return nil, fmt.Errorf("request ID %x replayed: entry %d already used it", req.RequestID, first)
	}

	var (
		imports   []*krl.Parsed
		maxImport uint64
	)
	for i, im := range req.Imports {
		m, err := krl.VerifyManifest(im.Manifest, im.Sig, im.KRL, a.bundle, a.bundle.InstallationID, 0)
		if err != nil {
			return nil, fmt.Errorf("import %d is not a KRL version of trust bundle v%d (recovery_import_invalid): %w", i, a.bundle.Version, err)
		}
		p, err := krl.Parse(im.KRL)
		if err != nil {
			return nil, fmt.Errorf("import %d (KRL v%d) does not parse (recovery_import_invalid): %w", i, m.KRLVersion, err)
		}
		if p.Version != m.KRLVersion {
			return nil, fmt.Errorf("import %d: its KRL header says version %d, its manifest %d (recovery_import_invalid)", i, p.Version, m.KRLVersion)
		}
		if len(p.SHA1) > 0 || len(p.SHA256) > 0 {
			return nil, fmt.Errorf("import %d (KRL v%d) has a fingerprint section, which this installation never publishes (recovery_import_invalid)", i, m.KRLVersion)
		}
		imports = append(imports, p)
		maxImport = max(maxImport, m.KRLVersion)
	}

	var (
		rcs     []krl.RecoveredCert
		carried [][]byte
	)
	for i, rc := range req.Certificates {
		c, kid, err := checkCarriedCert(rc.Cert)
		if err != nil {
			return nil, fmt.Errorf("carried certificate %d: %w", i, err)
		}
		keys, err := krl.RoleCAKeys(a.bundle, kid.CA)
		if err != nil {
			return nil, fmt.Errorf("trust bundle v%d: %w", a.bundle.Version, err)
		}
		if !slices.ContainsFunc(keys, func(k []byte) bool { return bytes.Equal(k, c.SignatureKey.Marshal()) }) {
			return nil, fmt.Errorf("carried certificate %d (serial %d) is signed by %s, not by a %s CA key of trust bundle v%d (recovery_certificate_invalid)",
				i, c.Serial, ssh.FingerprintSHA256(c.SignatureKey), kid.CA, a.bundle.Version)
		}
		if _, logged := rs.certs[c.Serial]; logged || (iss.seen && c.Serial <= iss.lastSerial) {
			return nil, fmt.Errorf("carried certificate %d (serial %d) is not lost: the log issued it, or a later serial (recovery_certificate_not_lost)", i, c.Serial)
		}
		if !krl.CarriesLost(c.ValidBefore, req.CreatedAt, rc.Revoke) {
			return nil, fmt.Errorf("carried certificate serial %d expired before the request was created (valid before %d, created at %d) and is not revoked (recovery_certificate_expired)",
				c.Serial, c.ValidBefore, req.CreatedAt)
		}
		if kid.CA == wire.CARoleUser.String() && !rc.Revoke && krl.EntryLive(c.ValidBefore, body.ResolvedAtSeconds) {
			return nil, fmt.Errorf("carried user certificate serial %d is live at %d s and not revoked; every lost user certificate still live is revoked (recovery_user_certificate_kept)",
				c.Serial, body.ResolvedAtSeconds)
		}
		rcs = append(rcs, krl.RecoveredCert{CAKey: c.SignatureKey.Marshal(), Serial: c.Serial, KeyID: c.KeyId, ValidBefore: c.ValidBefore, Revoke: rc.Revoke})
		carried = append(carried, rc.Cert)
	}
	derived, err := krl.RecoveryEntries(imports, rcs, func(serial uint64) ([]byte, string, uint64, bool) {
		c, ok := rs.certs[serial]
		return c.caKey, c.keyID, c.validBefore, ok
	})
	if err != nil {
		return nil, fmt.Errorf("the recovery's entries: %w", err)
	}
	if err := sameEntries(body.Entries, revokedEntries(derived)); err != nil {
		return nil, fmt.Errorf("its entries are not those its imports and carried certificates give: %w", err)
	}
	rs.requests[req.RequestID] = index
	rs.due = &publishDue{requestID: req.RequestID, last: index, kind: tlog.KindRevocationRecovery, floor: maxImport}
	rs.recoveries++
	rs.add(body.Entries)
	return carried, nil
}

// checkCarriedCert re-verifies a certificate a recovery carries and returns
// it with its parsed key ID: canonical encoding, a usable CA key that is
// not itself a certificate, a CA signature that verifies (expired
// certificates included), and a key ID that names its serial.
func checkCarriedCert(blob []byte) (*ssh.Certificate, cert.KeyID, error) {
	var none cert.KeyID
	c, err := parseCert(blob)
	if err != nil {
		return nil, none, fmt.Errorf("does not parse (recovery_certificate_invalid): %w", err)
	}
	if !bytes.Equal(c.Marshal(), blob) {
		return nil, none, errors.New("encoding is not canonical (recovery_certificate_invalid)")
	}
	if _, isCert := c.SignatureKey.(*ssh.Certificate); isCert {
		return nil, none, errors.New("its CA key is itself a certificate (recovery_certificate_invalid)")
	}
	if err := cert.CheckCAKey(c.SignatureKey); err != nil {
		return nil, none, fmt.Errorf("signed by an unusable CA key (recovery_certificate_invalid): %w", err)
	}
	if c.Signature == nil {
		return nil, none, errors.New("has no CA signature (recovery_certificate_invalid)")
	}
	if err := c.SignatureKey.Verify(signedBytes(c), c.Signature); err != nil {
		return nil, none, fmt.Errorf("CA signature does not verify (recovery_certificate_invalid): %w", err)
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil {
		return nil, none, fmt.Errorf("key ID (recovery_certificate_invalid): %w", err)
	}
	if kid.Serial != c.Serial {
		return nil, none, fmt.Errorf("key ID names serial %d, the certificate's serial is %d (recovery_certificate_invalid)", kid.Serial, c.Serial)
	}
	return c, kid, nil
}

// revokedEntries maps derived entries to the revoked entries a log leaf
// records.
func revokedEntries(entries []krl.Entry) []tlog.RevokedEntry {
	kinds := map[uint8]uint8{krl.EntrySerial: tlog.RevokedSerial, krl.EntryKeyID: tlog.RevokedKeyID, krl.EntryKey: tlog.RevokedKey}
	out := make([]tlog.RevokedEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, tlog.RevokedEntry{Kind: kinds[e.Kind], CAKey: e.CAKey, Serial: e.Serial, KeyID: e.KeyID, Key: e.Key, ValidBeforeSeconds: e.ValidBefore})
	}
	return out
}
