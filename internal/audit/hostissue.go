package audit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// maxHostLifetimeSeconds is the longest host certificate lifetime the
// signer chooses, 30 days (internal/signer maxHostLifetime, D-16).
const maxHostLifetimeSeconds = 2592000

// verifyHostIssue re-proves one host_issue entry (kind 11, 03-09) from the
// log alone, with the signer's rules. Every failure names its check:
//  1. the logged request parses and validates;
//  2. its installation ID is the bundle in force's (D5);
//  3. the policy in force sets pop.hosts;
//  4. CreatedAt lies within 300 s of the serial's time and of the
//     certificate's issuance time (ValidAfter + 300), never the entry's;
//  5. a directory is in force and authorized, at the entry's directory
//     version, under the entry's policy version;
//  6. the entry of the request's name is active and lists the key;
//  7. no earlier explicit-key entry revokes the key;
//  8. exactly one host-pop/v1 evidence by that key verifies over the
//     request's signing bytes under the host namespace;
//  9. valid_for is 0 (the signer chooses the lifetime, Q-09-6), and the
//     certificate lives exactly min(2592000, the host cap in force);
//  10. the request ID is new across the issue, login and host entries;
//  11. the certificate: a host certificate of the request's key, signed by
//     the active host CA, with exactly the entry's principals, the host
//     profile's extensions and no critical options, a kr3 key ID equal to
//     the entry's naming the entry, the request and the directory, and a
//     rising serial;
//  12. CapSeconds is min(2592000, the host cap in force) and the
//     certificate's lifetime, and cert.HostCertRecent, the signer's own
//     rule, with the certificate's issuance second as now, the cap and the
//     directory version in force and the entry's principals, allows it
//     (host_cert_recent and cert_revoked, keyed by host key, Q-09-2,
//     Q-09-5, Q-09-6).
//
// It records the certificate in hosts.
func verifyHostIssue(index uint64, body *tlog.HostIssueBody, leafMicros uint64, a *anchor, ds *directoryInForce, iss *issuance, hosts *hostsInForce) (*ssh.Certificate, error) {
	req, err := wire.ParseHostIssueSigningBytes(body.Request)
	if err != nil {
		return nil, fmt.Errorf("logged request: %w", err)
	}
	if a.policy == nil || a.bundle == nil {
		return nil, errors.New("host_issue before the first bundle_install: no root-signed policy is in force")
	}
	switch {
	case a.bundle.InstallationID == "":
		return nil, fmt.Errorf("trust bundle v%d has no installation ID, so no host request could be bound to it", a.bundle.Version)
	case req.InstallationID != a.bundle.InstallationID:
		return nil, fmt.Errorf("request names installation %s, but the bundle in force is installation %s", req.InstallationID, a.bundle.InstallationID)
	case a.policy.PoP == nil || !a.policy.PoP.Hosts:
		return nil, fmt.Errorf("policy v%d does not set pop.hosts, so no host certificate could be issued", a.policy.Version)
	case body.PolicyVersion != a.policy.Version:
		return nil, fmt.Errorf("entry records policy version %d, but the policy in force is version %d", body.PolicyVersion, a.policy.Version)
	case ds.dir == nil:
		return nil, fmt.Errorf("entry records directory version %d, but no directory is installed", body.DirectoryVersion)
	case body.DirectoryVersion != ds.version:
		return nil, fmt.Errorf("entry records directory version %d, but the directory in force is version %d", body.DirectoryVersion, ds.version)
	case ds.authErr != nil:
		return nil, fmt.Errorf("the directory in force (v%d) is not authorized under the policy in force: %w", ds.version, ds.authErr)
	}
	hostKey, err := ssh.ParsePublicKey(req.HostKey)
	if err != nil {
		return nil, fmt.Errorf("request host key does not parse: %w", err)
	}
	entry, ok := ds.dir.HostByName(req.HostName)
	switch {
	case !ok:
		return nil, fmt.Errorf("directory v%d has no host %q", ds.version, req.HostName)
	case !slices.Contains(entry.Keys, trust.FormatKey(hostKey)):
		return nil, fmt.Errorf("directory v%d host %q does not list key %s", ds.version, entry.Name, ssh.FingerprintSHA256(hostKey))
	case entry.Status != directory.StatusActive:
		return nil, fmt.Errorf("directory v%d host %q is %s, not active", ds.version, entry.Name, entry.Status)
	case hosts.revokedKeys[trust.FormatKey(hostKey)]:
		return nil, fmt.Errorf("host key %s is explicitly revoked by an earlier entry (host_key_revoked)", ssh.FingerprintSHA256(hostKey))
	}
	if err := verifyHostPoPEvidence(body.Evidence, body.Request, hostKey); err != nil {
		return nil, err
	}
	profile, err := certprofile.ForRole(trust.RoleHost, a.policy)
	if err != nil {
		return nil, fmt.Errorf("policy v%d: %w", a.policy.Version, err)
	}
	capInForce := min(maxHostLifetimeSeconds, uint64(profile.MaxTTL/time.Second)) //nolint:gosec // G115: the profile cap is positive (certprofile.ForRole)
	if req.ValidForSeconds != 0 {
		return nil, fmt.Errorf("request asks for valid_for %d s; the signer chooses the lifetime and refuses any value but 0", req.ValidForSeconds)
	}

	ib := &tlog.IssueBody{CARole: uint8(wire.CARoleHost), Serial: body.Serial, PolicyVersion: body.PolicyVersion, Cert: body.Cert, KeyID: body.KeyID}
	c, kid, err := checkIssue(ib, iss.lastSerial, iss.seen)
	if err != nil {
		return nil, err
	}
	if !kid.V3 {
		return nil, errors.New("a host_issue entry must carry a kr3 key ID, not kr1 or kr2")
	}
	if err := a.checkIssue(ib, c, kid, leafMicros); err != nil {
		return nil, err
	}
	if !bytes.Equal(c.Key.Marshal(), hostKey.Marshal()) {
		return nil, fmt.Errorf("certificate key %s is not the request's host key", ssh.FingerprintSHA256(c.Key))
	}
	if !slices.Equal(c.ValidPrincipals, entry.Principals) {
		return nil, fmt.Errorf("certificate principals %q differ from directory v%d host %q's %q", c.ValidPrincipals, ds.version, entry.Name, entry.Principals)
	}
	if c.ValidBefore < c.ValidAfter+backdateSeconds {
		return nil, errors.New("certificate ends before its issuance time")
	}
	if life := c.ValidBefore - c.ValidAfter - backdateSeconds; life != capInForce {
		return nil, fmt.Errorf("certificate lives %d s, but the signer chooses min(%d, the host cap %d s in force) = %d s",
			life, maxHostLifetimeSeconds, uint64(profile.MaxTTL/time.Second), capInForce) //nolint:gosec // G115: positive
	}
	if !maps.Equal(c.Extensions, profile.DefaultExtensions) {
		return nil, fmt.Errorf("certificate extensions %q, want exactly the host profile's %q",
			slices.Sorted(maps.Keys(c.Extensions)), slices.Sorted(maps.Keys(profile.DefaultExtensions)))
	}
	if len(c.CriticalOptions) != 0 {
		return nil, fmt.Errorf("certificate carries critical options %q; a host request sets none", slices.Sorted(maps.Keys(c.CriticalOptions)))
	}
	reqID := hex.EncodeToString(req.RequestID[:])
	switch {
	case kid.CA != wire.CARoleHost.String():
		return nil, fmt.Errorf("key ID ca=%s, want host", kid.CA)
	case kid.Subject != entry.Name:
		return nil, fmt.Errorf("key ID sub=%s, but the entry is %q", kid.Subject, entry.Name)
	case kid.Request != reqID:
		return nil, fmt.Errorf("key ID req=%s, but the request ID is %s", kid.Request, reqID)
	case kid.Directory != body.DirectoryVersion:
		return nil, fmt.Errorf("key ID dir=%d, but the entry records directory version %d", kid.Directory, body.DirectoryVersion)
	}
	// The signer's freshness and issuance bounds, as verifyLoginIssue
	// checks them: never against the entry time, which appendLocked raises
	// past a clock step.
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
	if prev, used := iss.hostIDs[reqID]; used {
		return nil, fmt.Errorf("request ID %s replayed: host_issue entry %d already used it", reqID, prev)
	}
	if prev, used := iss.issueIDs[reqID]; used {
		return nil, fmt.Errorf("request ID %s replayed: issue entry %d already used it", reqID, prev)
	}
	if prev, used := iss.loginIDs[reqID]; used {
		return nil, fmt.Errorf("request ID %s replayed: login_issue entry %d already used it", reqID, prev)
	}
	rawCap := uint64(profile.MaxTTL / time.Second) //nolint:gosec // G115: the profile cap is positive
	if body.CapSeconds != capInForce {
		return nil, fmt.Errorf("entry records CapSeconds %d, but min(%d, the host cap %d s in force) is %d", body.CapSeconds, maxHostLifetimeSeconds, rawCap, capInForce)
	}
	switch d := cert.HostCertRecent(hosts.prev(trust.FormatKey(hostKey)), issuedSecs, rawCap, ds.version, entry.Principals); d {
	case "cert_revoked":
		return nil, fmt.Errorf("the latest host certificate of key %s is revoked and no newer directory version is installed, so the signer refuses it (cert_revoked)", ssh.FingerprintSHA256(hostKey))
	case "host_cert_recent":
		return nil, fmt.Errorf("issued %d s after the previous host certificate of key %s, inside its window of a third of the host cap (host_cert_recent)",
			issuedSecs-hosts.prev(trust.FormatKey(hostKey)).Cert.ValidAfter-backdateSeconds, ssh.FingerprintSHA256(hostKey))
	}
	iss.hostIDs[reqID] = index
	iss.next(body.Serial)
	hosts.record(c, body.CapSeconds, body.DirectoryVersion)
	return c, nil
}

// verifyHostPoPEvidence requires exactly one host-pop/v1 evidence item, an
// SSHSIG by key over signed under the host namespace.
func verifyHostPoPEvidence(ev []wire.Evidence, signed []byte, key ssh.PublicKey) error {
	switch {
	case len(ev) != 1:
		return fmt.Errorf("entry carries %d evidence items, want exactly one %s", len(ev), wire.EvidenceHostPoP)
	case ev[0].Type != wire.EvidenceHostPoP:
		return fmt.Errorf("evidence type %q, want %s", ev[0].Type, wire.EvidenceHostPoP)
	}
	sig, err := sshsig.Parse(ev[0].Blob)
	if err != nil {
		return fmt.Errorf("host proof of possession does not parse: %w", err)
	}
	if !bytes.Equal(sig.PublicKey().Marshal(), key.Marshal()) {
		return fmt.Errorf("host proof of possession is by %s, not by the request's host key %s", ssh.FingerprintSHA256(sig.PublicKey()), ssh.FingerprintSHA256(key))
	}
	if err := sig.Verify(wire.HostPoPNamespace, signed); err != nil {
		return fmt.Errorf("host proof of possession does not verify over the logged request: %w", err)
	}
	return nil
}

// hostCertKeyID is a host certificate's parsed key ID (kr3, checked by
// verifyHostIssue).
func hostCertKeyID(c *ssh.Certificate) (cert.KeyID, error) { return cert.ParseKeyID(c.KeyId) }

// hostLatest is the latest host certificate audit verify knows for one
// host key (03-09), as the signer's host index keeps it.
type hostLatest struct {
	cert           *ssh.Certificate
	capSeconds     uint64
	issuedUnderDir uint64
	revoked        bool
	revokedAtDir   uint64
}

// hostsInForce is audit verify's derivation of the signer's host index
// from the log alone (03-09): per host key the latest host certificate,
// the serials and key IDs of those latest certificates, the explicitly
// revoked keys, and the directory version in force. Its rules and their
// order are the signer's (internal/signer hostIndex.apply), so
// cert.HostCertRecent sees the same inputs there and here.
type hostsInForce struct {
	latest      map[string]hostLatest
	bySerial    map[uint64]string
	byKeyID     map[string]string
	revokedKeys map[string]bool
	curDir      uint64
}

func newHostsInForce() *hostsInForce {
	return &hostsInForce{latest: map[string]hostLatest{}, bySerial: map[uint64]string{}, byKeyID: map[string]string{}, revokedKeys: map[string]bool{}}
}

// prev is key k's latest certificate as cert.HostCertRecent takes it (the
// zero HostPrev for none).
func (h *hostsInForce) prev(k string) cert.HostPrev {
	l, ok := h.latest[k]
	if !ok {
		return cert.HostPrev{}
	}
	return cert.HostPrev{Cert: l.cert, CapSeconds: l.capSeconds, IssuedUnderDir: l.issuedUnderDir, Revoked: l.revoked, RevokedAtDir: l.revokedAtDir}
}

// record makes c, a verified host_issue certificate with cap and dir, the
// latest of its key.
func (h *hostsInForce) record(c *ssh.Certificate, capSeconds, dir uint64) {
	k := trust.FormatKey(c.Key)
	if old, ok := h.latest[k]; ok {
		delete(h.bySerial, old.cert.Serial)
		delete(h.byKeyID, old.cert.KeyId)
	}
	h.latest[k] = hostLatest{cert: c, capSeconds: capSeconds, issuedUnderDir: dir}
	h.bySerial[c.Serial] = k
	h.byKeyID[c.KeyId] = k
}

// carry records a recovery's carried kr3 ca=host certificate as the
// latest of its key when its serial is above the recorded one, and marks
// it revoked when the recovery revokes it.
func (h *hostsInForce) carry(c *ssh.Certificate, revoke bool) {
	if c.CertType != ssh.HostCert {
		return
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil || !kid.V3 || kid.CA != wire.CARoleHost.String() {
		return
	}
	k := trust.FormatKey(c.Key)
	if cur, ok := h.latest[k]; ok && cur.cert.Serial >= c.Serial {
		return
	}
	life := uint64(0)
	if c.ValidBefore > c.ValidAfter+backdateSeconds {
		life = c.ValidBefore - c.ValidAfter - backdateSeconds
	}
	h.record(c, life, kid.Directory)
	if revoke {
		h.markRevoked(k)
	}
}

// revokeEntries applies a revoke or recovery entry list: a serial or key
// ID that names a latest host certificate under its CA key marks it
// revoked at the directory version in force; an explicit key is recorded.
func (h *hostsInForce) revokeEntries(entries []tlog.RevokedEntry) {
	for _, e := range entries {
		switch e.Kind {
		case tlog.RevokedSerial:
			if k, ok := h.bySerial[e.Serial]; ok && bytes.Equal(h.latest[k].cert.SignatureKey.Marshal(), e.CAKey) {
				h.markRevoked(k)
			}
		case tlog.RevokedKeyID:
			if k, ok := h.byKeyID[e.KeyID]; ok && bytes.Equal(h.latest[k].cert.SignatureKey.Marshal(), e.CAKey) {
				h.markRevoked(k)
			}
		case tlog.RevokedKey:
			if pub, err := ssh.ParsePublicKey(e.Key); err == nil {
				h.revokedKeys[trust.FormatKey(pub)] = true
			}
		}
	}
}

func (h *hostsInForce) markRevoked(k string) {
	l, ok := h.latest[k]
	if !ok || l.revoked {
		return
	}
	l.revoked, l.revokedAtDir = true, h.curDir
	h.latest[k] = l
}
