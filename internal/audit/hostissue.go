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
//  8. exactly one host-pop/v1 evidence by that key verifies over the
//     request's signing bytes under the host namespace;
//  9. valid_for is 0 (the signer chooses the lifetime, Q-09-6), and the
//     certificate lives exactly min(2592000, the host cap in force);
//  11. the certificate: a host certificate of the request's key, signed by
//     the active host CA, with exactly the entry's principals, the host
//     profile's extensions and no critical options, a kr3 key ID equal to
//     the entry's naming the entry, the request and the directory, and a
//     rising serial.
func verifyHostIssue(index uint64, body *tlog.HostIssueBody, leafMicros uint64, a *anchor, ds *directoryInForce, iss *issuance) (*ssh.Certificate, error) {
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
	_ = index
	iss.next(body.Serial)
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
