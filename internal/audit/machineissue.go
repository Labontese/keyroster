package audit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// machineReservedPrefix is the key ID subject prefix of probe certificates
// (internal/signer reservedMachinePrefix, 03-10): no machine certificate
// carries it (03-11 PD5).
const machineReservedPrefix = "probe."

// verifyMachineIssue re-proves one machine_issue entry (kind 13, 03-11)
// from the log alone, with the signer's rules, in the signer's order and
// with its shared functions. Every failure names its check:
//  1. the logged request parses and validates;
//  2. its installation ID is the bundle in force's (D5);
//  3. the policy in force sets pop.machines;
//  4. the entry's policy and directory versions are in force, and the
//     directory is installed and authorized;
//  5. CreatedAt lies within 300 s of the serial's time and of the
//     certificate's issuance time (ValidAfter + 300);
//  6. the machine name does not start with probe. (machine_name_reserved);
//  7. the entry of the request's name exists and lists the request's key;
//  8. exactly one machine-pop/v1 evidence by that key verifies over the
//     request's signing bytes under the machine namespace;
//  9. no earlier explicit-key entry revokes the key; the key is not held
//     (cert.MachineCertHeld over the mirror: its latest certificate
//     revoked and no newer directory version installed); the entry is
//     active; the key is not a key of the bundle in force
//     (machine_key_unusable);
//  10. valid_for is 0;
//  11. directory.MachineGrant and cert.MachineLifetime give L: CapSeconds
//     is L, the certificate lives exactly L, its principals are the
//     grant's, its extensions are the profile defaults plus the grant's,
//     and it carries no critical option;
//  12. the certificate: signed by the active machine CA, a rising serial,
//     the request's key, and a kr3 key ID naming the machine CA, the
//     entry, the request and the directory;
//  13. the request ID is new across the issue, login, host, probe and
//     machine entries;
//  14. fewer than twelve issuances of the key in the hour before the
//     certificate's issuance second (cert.MachineRenewTooOften over the
//     mirror's recent list).
//
// It records the certificate in machines.
func verifyMachineIssue(index uint64, body *tlog.MachineIssueBody, leafMicros uint64, a *anchor, ds *directoryInForce, iss *issuance,
	machines *machinesInForce, hosts *hostsInForce) (*ssh.Certificate, error) {
	req, err := wire.ParseMachineIssueSigningBytes(body.Request)
	if err != nil {
		return nil, fmt.Errorf("logged request: %w", err)
	}
	if a.policy == nil || a.bundle == nil {
		return nil, errors.New("machine_issue before the first bundle_install: no root-signed policy is in force")
	}
	switch {
	case a.bundle.InstallationID == "":
		return nil, fmt.Errorf("trust bundle v%d has no installation ID, so no machine request could be bound to it", a.bundle.Version)
	case req.InstallationID != a.bundle.InstallationID:
		return nil, fmt.Errorf("request names installation %s, but the bundle in force is installation %s", req.InstallationID, a.bundle.InstallationID)
	case a.policy.PoP == nil || !a.policy.PoP.Machines:
		return nil, fmt.Errorf("policy v%d does not set pop.machines, so no machine certificate could be issued", a.policy.Version)
	case body.PolicyVersion != a.policy.Version:
		return nil, fmt.Errorf("entry records policy version %d, but the policy in force is version %d", body.PolicyVersion, a.policy.Version)
	case ds.dir == nil:
		return nil, fmt.Errorf("entry records directory version %d, but no directory is installed", body.DirectoryVersion)
	case body.DirectoryVersion != ds.version:
		return nil, fmt.Errorf("entry records directory version %d, but the directory in force is version %d", body.DirectoryVersion, ds.version)
	case ds.authErr != nil:
		return nil, fmt.Errorf("the directory in force (v%d) is not authorized under the policy in force: %w", ds.version, ds.authErr)
	}
	c, err := parseCert(body.Cert)
	if err != nil {
		return nil, err
	}
	serialSecs := body.Serial / 1e6
	if d := absDiff(serialSecs, req.CreatedAt); d > maxLoginSkewSeconds {
		return nil, fmt.Errorf("request CreatedAt is %d s from the serial's time (created %d, serial %d s); the signer accepts at most %d s",
			d, req.CreatedAt, serialSecs, maxLoginSkewSeconds)
	}
	issuedSecs := c.ValidAfter + backdateSeconds
	if d := absDiff(issuedSecs, req.CreatedAt); d > maxLoginSkewSeconds {
		return nil, fmt.Errorf("request CreatedAt is %d s from the certificate's issuance time (created %d, issued %d s); the signer accepts at most %d s",
			d, req.CreatedAt, issuedSecs, maxLoginSkewSeconds)
	}
	if strings.HasPrefix(req.MachineName, machineReservedPrefix) {
		return nil, fmt.Errorf("machine name %q has the prefix %s reserved for probe certificates (machine_name_reserved)", req.MachineName, machineReservedPrefix)
	}
	key, err := ssh.ParsePublicKey(req.MachineKey)
	if err != nil {
		return nil, fmt.Errorf("request machine key does not parse: %w", err)
	}
	k := trust.FormatKey(key)
	entry, ok := ds.dir.MachineByName(req.MachineName)
	switch {
	case !ok:
		return nil, fmt.Errorf("directory v%d has no machine %q", ds.version, req.MachineName)
	case entry.Key != k:
		return nil, fmt.Errorf("directory v%d machine %q does not list key %s", ds.version, entry.Name, ssh.FingerprintSHA256(key))
	}
	if err := verifyMachinePoPEvidence(body.Evidence, body.Request, key); err != nil {
		return nil, err
	}
	if hosts.revokedKeys[k] {
		return nil, fmt.Errorf("machine key %s is explicitly revoked by an earlier entry (machine_key_revoked)", ssh.FingerprintSHA256(key))
	}
	if l, ok := machines.latest[k]; ok && cert.MachineCertHeld(l.prev(), ds.version) != "" {
		return nil, fmt.Errorf("machine key %s: its latest certificate, serial %d, was revoked at directory version %d and no newer directory version is installed (cert_revoked)",
			ssh.FingerprintSHA256(key), l.cert.Serial, l.revokedAtDir)
	}
	if entry.Status != directory.StatusActive {
		return nil, fmt.Errorf("directory v%d machine %q is %s, not active", ds.version, entry.Name, entry.Status)
	}
	instKeys, err := krl.InstallationKeys(a.bundle)
	if err != nil {
		return nil, fmt.Errorf("trust bundle v%d: %w", a.bundle.Version, err)
	}
	if instKeys[string(key.Marshal())] {
		return nil, fmt.Errorf("machine key %s is a key of trust bundle v%d (machine_key_unusable)", ssh.FingerprintSHA256(key), a.bundle.Version)
	}
	if req.ValidForSeconds != 0 {
		return nil, fmt.Errorf("request asks for valid_for %d s; the signer chooses the lifetime and refuses any value but 0", req.ValidForSeconds)
	}
	profile, err := certprofile.ForRole(trust.RoleMachine, a.policy)
	if err != nil {
		return nil, fmt.Errorf("policy v%d: %w", a.policy.Version, err)
	}
	grant, err := ds.dir.MachineGrant(entry)
	if err != nil {
		return nil, fmt.Errorf("directory v%d: %w", ds.version, err)
	}
	life := cert.MachineLifetime(grant.MaxTTLSeconds, profile)
	if body.CapSeconds != life {
		return nil, fmt.Errorf("entry records CapSeconds %d, but min(the grant's %d s, the machine cap %d s in force) is %d",
			body.CapSeconds, grant.MaxTTLSeconds, uint64(profile.MaxTTL/time.Second), life) //nolint:gosec // G115: positive
	}
	if c.ValidBefore < c.ValidAfter+backdateSeconds {
		return nil, errors.New("certificate ends before its issuance time")
	}
	if got := c.ValidBefore - c.ValidAfter - backdateSeconds; got != life {
		return nil, fmt.Errorf("certificate lives %d s, but the signer chooses min(the grant's %d s, the machine cap) = %d s", got, grant.MaxTTLSeconds, life)
	}
	if !slices.Equal(c.ValidPrincipals, grant.Principals) {
		return nil, fmt.Errorf("certificate principals %q differ from the %q that directory v%d machine %q's roles grant",
			c.ValidPrincipals, grant.Principals, ds.version, entry.Name)
	}
	wantExt := maps.Clone(profile.DefaultExtensions)
	if wantExt == nil {
		wantExt = map[string]string{}
	}
	for _, e := range grant.Extensions {
		wantExt[e] = ""
	}
	if !maps.Equal(c.Extensions, wantExt) {
		return nil, fmt.Errorf("certificate extensions %q, want the machine profile's defaults plus the grant's %q",
			slices.Sorted(maps.Keys(c.Extensions)), slices.Sorted(maps.Keys(wantExt)))
	}
	if len(c.CriticalOptions) != 0 {
		return nil, fmt.Errorf("certificate carries critical options %q; a machine request sets none", slices.Sorted(maps.Keys(c.CriticalOptions)))
	}
	ib := &tlog.IssueBody{CARole: uint8(wire.CARoleMachine), Serial: body.Serial, PolicyVersion: body.PolicyVersion, Cert: body.Cert, KeyID: body.KeyID}
	c, kid, err := checkIssue(ib, iss.lastSerial, iss.seen)
	if err != nil {
		return nil, err
	}
	if !kid.V3 {
		return nil, errors.New("a machine_issue entry must carry a kr3 key ID, not kr1 or kr2")
	}
	if err := a.checkIssue(ib, c, kid, leafMicros); err != nil {
		return nil, err
	}
	if !bytes.Equal(c.Key.Marshal(), key.Marshal()) {
		return nil, fmt.Errorf("certificate key %s is not the request's machine key", ssh.FingerprintSHA256(c.Key))
	}
	reqID := hex.EncodeToString(req.RequestID[:])
	switch {
	case kid.CA != wire.CARoleMachine.String():
		return nil, fmt.Errorf("key ID ca=%s, want machine", kid.CA)
	case kid.Subject != entry.Name:
		return nil, fmt.Errorf("key ID sub=%s, but the entry is %q", kid.Subject, entry.Name)
	case kid.Request != reqID:
		return nil, fmt.Errorf("key ID req=%s, but the request ID is %s", kid.Request, reqID)
	case kid.Directory != body.DirectoryVersion:
		return nil, fmt.Errorf("key ID dir=%d, but the entry records directory version %d", kid.Directory, body.DirectoryVersion)
	}
	if prev, used := iss.issueIDs[reqID]; used {
		return nil, fmt.Errorf("request ID %s replayed: issue entry %d already used it", reqID, prev)
	}
	if prev, used := iss.loginIDs[reqID]; used {
		return nil, fmt.Errorf("request ID %s replayed: login_issue entry %d already used it", reqID, prev)
	}
	if prev, used := iss.hostIDs[reqID]; used {
		return nil, fmt.Errorf("request ID %s replayed: host_issue entry %d already used it", reqID, prev)
	}
	if prev, used := iss.probeIDs[reqID]; used {
		return nil, fmt.Errorf("request ID %s replayed: probe_issue entry %d already used it", reqID, prev)
	}
	if prev, used := iss.machineIDs[reqID]; used {
		return nil, fmt.Errorf("request ID %s replayed: machine_issue entry %d already used it", reqID, prev)
	}
	if d := cert.MachineRenewTooOften(machines.recent[k], issuedSecs); d != "" {
		return nil, fmt.Errorf("machine key %s already has %d issuances in the hour before %d (%s)", ssh.FingerprintSHA256(key), len(machines.recent[k]), issuedSecs, d)
	}
	iss.machineIDs[reqID] = index
	iss.next(body.Serial)
	machines.record(c, body.CapSeconds, body.DirectoryVersion)
	return c, nil
}

// verifyMachinePoPEvidence requires exactly one machine-pop/v1 evidence
// item, an SSHSIG by key over signed under the machine namespace.
func verifyMachinePoPEvidence(ev []wire.Evidence, signed []byte, key ssh.PublicKey) error {
	switch {
	case len(ev) != 1:
		return fmt.Errorf("entry carries %d evidence items, want exactly one %s", len(ev), wire.EvidenceMachinePoP)
	case ev[0].Type != wire.EvidenceMachinePoP:
		return fmt.Errorf("evidence type %q, want %s", ev[0].Type, wire.EvidenceMachinePoP)
	}
	sig, err := sshsig.Parse(ev[0].Blob)
	if err != nil {
		return fmt.Errorf("machine proof of possession does not parse: %w", err)
	}
	if !bytes.Equal(sig.PublicKey().Marshal(), key.Marshal()) {
		return fmt.Errorf("machine proof of possession is by %s, not by the listed machine key %s",
			ssh.FingerprintSHA256(sig.PublicKey()), ssh.FingerprintSHA256(key))
	}
	if err := sig.Verify(wire.MachinePoPNamespace, signed); err != nil {
		return fmt.Errorf("machine proof of possession does not verify over the logged request: %w", err)
	}
	return nil
}

// machineLatest is the latest machine certificate audit verify knows for
// one machine key (03-11), as the signer's machine index keeps it, with
// whether it was revoked, at which directory version (keep-first).
type machineLatest struct {
	cert           *ssh.Certificate
	capSeconds     uint64
	issuedUnderDir uint64
	revoked        bool
	revokedAtDir   uint64
}

// prev is l as cert.MachineCertHeld takes it.
func (l machineLatest) prev() cert.MachinePrev {
	return cert.MachinePrev{Have: l.cert != nil, Revoked: l.revoked, RevokedAtDir: l.revokedAtDir}
}

// machinesInForce is audit verify's derivation of the signer's machine
// index from the log alone (03-11): per machine key the latest machine
// certificate and the issuance seconds of its last hour, the serials and
// key IDs of those latest certificates, and the directory version in
// force. Its rules and their order are the signer's (internal/signer
// machineIndex.apply), so the shared cert functions see the same inputs
// there and here.
type machinesInForce struct {
	latest   map[string]machineLatest
	recent   map[string][]uint64
	bySerial map[uint64]string
	byKeyID  map[string]string
	curDir   uint64
}

func newMachinesInForce() *machinesInForce {
	return &machinesInForce{latest: map[string]machineLatest{}, recent: map[string][]uint64{}, bySerial: map[uint64]string{}, byKeyID: map[string]string{}}
}

// setLatest makes c the latest certificate of its key and returns the key.
func (m *machinesInForce) setLatest(c *ssh.Certificate, capSeconds, dir uint64) string {
	k := trust.FormatKey(c.Key)
	if old, ok := m.latest[k]; ok {
		delete(m.bySerial, old.cert.Serial)
		delete(m.byKeyID, old.cert.KeyId)
	}
	m.latest[k] = machineLatest{cert: c, capSeconds: capSeconds, issuedUnderDir: dir}
	m.bySerial[c.Serial] = k
	m.byKeyID[c.KeyId] = k
	return k
}

// record makes c, a verified machine_issue certificate with its lifetime
// and directory version, the latest of its key and adds its issuance
// second to the key's recent list (cert.MachineRecentAdd, as the signer's
// index does).
func (m *machinesInForce) record(c *ssh.Certificate, capSeconds, dir uint64) {
	k := m.setLatest(c, capSeconds, dir)
	m.recent[k] = cert.MachineRecentAdd(m.recent[k], c.ValidAfter+backdateSeconds)
}

// carry records a recovery's carried kr3 ca=machine certificate that is
// not a probe certificate as the latest of its key when its serial is
// above the recorded one, marks it revoked when the recovery revokes it,
// and never adds it to the recent list (PD3): the signer's rule.
func (m *machinesInForce) carry(c *ssh.Certificate, revoke bool) {
	if c.CertType != ssh.UserCert {
		return
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil || !kid.V3 || kid.CA != wire.CARoleMachine.String() || krl.IsProbeKeyID(kid) {
		return
	}
	k := trust.FormatKey(c.Key)
	if cur, ok := m.latest[k]; ok && cur.cert.Serial >= c.Serial {
		return
	}
	life := uint64(0)
	if c.ValidBefore > c.ValidAfter+backdateSeconds {
		life = c.ValidBefore - c.ValidAfter - backdateSeconds
	}
	m.setLatest(c, life, kid.Directory)
	if revoke {
		m.markRevoked(k)
	}
}

// applyRevoke applies a verified revoke entry to the mirror: its entries
// (revokeEntries).
func (m *machinesInForce) applyRevoke(body *tlog.RevokeBody) {
	m.revokeEntries(body.Entries)
}

// revokeEntries applies a revoke or recovery entry list: a serial or key
// ID that names a latest machine certificate under its CA key marks it
// revoked at the directory version in force (explicit keys are the host
// mirror's revokedKeys).
func (m *machinesInForce) revokeEntries(entries []tlog.RevokedEntry) {
	for _, e := range entries {
		switch e.Kind {
		case tlog.RevokedSerial:
			if k, ok := m.bySerial[e.Serial]; ok && bytes.Equal(m.latest[k].cert.SignatureKey.Marshal(), e.CAKey) {
				m.markRevoked(k)
			}
		case tlog.RevokedKeyID:
			if k, ok := m.byKeyID[e.KeyID]; ok && bytes.Equal(m.latest[k].cert.SignatureKey.Marshal(), e.CAKey) {
				m.markRevoked(k)
			}
		}
	}
}

// markRevoked marks key k's latest certificate revoked at the directory
// version in force; one already revoked keeps its version (keep-first).
func (m *machinesInForce) markRevoked(k string) {
	l, ok := m.latest[k]
	if !ok || l.revoked {
		return
	}
	l.revoked, l.revokedAtDir = true, m.curDir
	m.latest[k] = l
}
