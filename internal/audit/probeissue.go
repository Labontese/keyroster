package audit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"

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

// verifyProbeIssue re-proves one probe_issue entry (kind 12, 03-10) from
// the log alone, with the signer's rules. Every failure names its check:
//  1. the logged request parses and validates;
//  2. its installation ID is the bundle in force's (D5);
//  3. the policy in force sets pop.hosts;
//  4. a directory is in force and authorized, at the entry's directory
//     version, under the entry's policy version;
//  5. the entry of the request's name is active and lists the host key
//     (the cross-host binding), and no earlier explicit-key entry revokes
//     the key;
//  6. evidence 0 is host-pop/v1 by the host key and evidence 1 is
//     probe-pop/v1 by the probe key, both verifying over the request's
//     signing bytes under the probe namespace;
//  7. the probe key is neither the host key, nor a key of the bundle in
//     force, nor a key the directory in force lists;
//  8. valid_for is 0 (the signer chooses the lifetime, Q-09-6);
//  9. the certificate: a user certificate of the probe key, signed by the
//     active machine CA, within the probe profile (cert.CheckIssued under
//     certprofile.ProbeProfile), with exactly the principal
//     keyroster-probe:<host>, no extension, exactly the critical options
//     force-command /bin/false and source-address 127.0.0.0/8,::1/128
//     compared by value, a kr3 key ID with ca=machine naming probe.<host>,
//     the request and the directory, a rising serial, and a lifetime of
//     exactly L = certprofile.ProbeLifetime of the profile, which is also
//     the entry's CapSeconds;
//  10. CreatedAt lies within 300 s of the serial's time and of the
//     certificate's issuance time;
//  11. the entry's negative flag is the request's.
//
// It records the certificate in revs and, for a negative entry, its own
// serial entry (tlog.ProbeIssueBody.RevokedEntries), which every later
// krl_publish entry must list while it is live; no adjacency rule applies
// (owner decision Q1: a renewal rides the hourly republish).
func verifyProbeIssue(index uint64, body *tlog.ProbeIssueBody, leafMicros uint64, a *anchor, ds *directoryInForce, iss *issuance, hosts *hostsInForce, revs *revocations) (*ssh.Certificate, error) {
	_ = index
	req, err := wire.ParseProbeIssueSigningBytes(body.Request)
	if err != nil {
		return nil, fmt.Errorf("logged request: %w", err)
	}
	if a.policy == nil || a.bundle == nil {
		return nil, errors.New("probe_issue before the first bundle_install: no root-signed policy is in force")
	}
	switch {
	case a.bundle.InstallationID == "":
		return nil, fmt.Errorf("trust bundle v%d has no installation ID, so no probe request could be bound to it", a.bundle.Version)
	case req.InstallationID != a.bundle.InstallationID:
		return nil, fmt.Errorf("request names installation %s, but the bundle in force is installation %s", req.InstallationID, a.bundle.InstallationID)
	case a.policy.PoP == nil || !a.policy.PoP.Hosts:
		return nil, fmt.Errorf("policy v%d does not set pop.hosts, so no probe certificate could be issued", a.policy.Version)
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
	probeKey, err := ssh.ParsePublicKey(req.ProbeKey)
	if err != nil {
		return nil, fmt.Errorf("request probe key does not parse: %w", err)
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
	if err := verifyProbeEvidence(body.Evidence, body.Request, hostKey, probeKey); err != nil {
		return nil, err
	}
	if err := checkProbeKey(req, a.bundle, ds); err != nil {
		return nil, err
	}
	if req.ValidForSeconds != 0 {
		return nil, fmt.Errorf("request asks for valid_for %d s; the signer chooses the lifetime and refuses any value but 0", req.ValidForSeconds)
	}
	profile, err := certprofile.ProbeProfile(a.policy)
	if err != nil {
		return nil, fmt.Errorf("policy v%d: %w", a.policy.Version, err)
	}
	lifetime := certprofile.ProbeLifetime(profile)

	ib := &tlog.IssueBody{CARole: uint8(wire.CARoleMachine), Serial: body.Serial, PolicyVersion: body.PolicyVersion, Cert: body.Cert, KeyID: body.KeyID}
	c, kid, err := checkIssue(ib, iss.lastSerial, iss.seen)
	if err != nil {
		return nil, err
	}
	// checkIssue has required the key ID's CA to be the leaf's, machine.
	if !kid.V3 {
		return nil, errors.New("a probe_issue entry must carry a kr3 key ID, not kr1 or kr2")
	}
	if err := a.checkProbeCert(ib, c, kid, leafMicros, profile); err != nil {
		return nil, err
	}
	if !bytes.Equal(c.Key.Marshal(), probeKey.Marshal()) {
		return nil, fmt.Errorf("certificate key %s is not the request's probe key", ssh.FingerprintSHA256(c.Key))
	}
	if want := []string{"keyroster-probe:" + entry.Name}; !slices.Equal(c.ValidPrincipals, want) {
		return nil, fmt.Errorf("certificate principals %q, want exactly %q", c.ValidPrincipals, want)
	}
	if c.ValidBefore < c.ValidAfter+backdateSeconds {
		return nil, errors.New("certificate ends before its issuance time")
	}
	if life := c.ValidBefore - c.ValidAfter - backdateSeconds; life != lifetime {
		return nil, fmt.Errorf("certificate lives %d s, but the signer chooses min(%d, the machine cap in force) = %d s",
			life, certprofile.MaxProbeLifetimeSeconds, lifetime)
	}
	if body.CapSeconds != lifetime {
		return nil, fmt.Errorf("entry records CapSeconds %d, but min(%d, the machine cap in force) is %d", body.CapSeconds, certprofile.MaxProbeLifetimeSeconds, lifetime)
	}
	// cert.CheckIssued checks extension and option names only; a probe
	// certificate is held to exact values, as verifyHostIssue does.
	if len(c.Extensions) != 0 {
		return nil, fmt.Errorf("certificate carries extensions %q; a probe certificate carries none", slices.Sorted(maps.Keys(c.Extensions)))
	}
	if want := certprofile.ProbeCriticalOptions(); !maps.Equal(c.CriticalOptions, want) {
		return nil, fmt.Errorf("certificate critical options %v, want exactly %v", c.CriticalOptions, want)
	}
	reqID := hex.EncodeToString(req.RequestID[:])
	switch {
	case kid.Subject != "probe."+entry.Name:
		return nil, fmt.Errorf("key ID sub=%s, but the entry is %q", kid.Subject, "probe."+entry.Name)
	case kid.Request != reqID:
		return nil, fmt.Errorf("key ID req=%s, but the request ID is %s", kid.Request, reqID)
	case kid.Directory != body.DirectoryVersion:
		return nil, fmt.Errorf("key ID dir=%d, but the entry records directory version %d", kid.Directory, body.DirectoryVersion)
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
	if body.Negative != req.Negative {
		return nil, fmt.Errorf("the entry's negative flag %t differs from the request's %t", body.Negative, req.Negative)
	}
	entries, err := body.RevokedEntries()
	if err != nil {
		return nil, err
	}
	iss.next(body.Serial)
	revs.addCert(c, kid)
	revs.add(entries)
	return c, nil
}

// verifyProbeEvidence requires exactly two evidence items, host-pop/v1 by
// hostKey then probe-pop/v1 by probeKey, each an SSHSIG over signed under
// the probe namespace (03-10).
func verifyProbeEvidence(ev []wire.Evidence, signed []byte, hostKey, probeKey ssh.PublicKey) error {
	if len(ev) != 2 || ev[0].Type != wire.EvidenceHostPoP || ev[1].Type != wire.EvidenceProbePoP {
		types := make([]string, len(ev))
		for i, e := range ev {
			types[i] = e.Type
		}
		return fmt.Errorf("evidence order: the entry carries %q, want exactly %q then %q", types, wire.EvidenceHostPoP, wire.EvidenceProbePoP)
	}
	for i, k := range []struct {
		key  ssh.PublicKey
		name string
	}{{hostKey, "host-pop/v1 is not by the request's host key"}, {probeKey, "probe-pop/v1 is not by the request's probe key"}} {
		sig, err := sshsig.Parse(ev[i].Blob)
		if err != nil {
			return fmt.Errorf("%s evidence does not parse: %w", ev[i].Type, err)
		}
		if !bytes.Equal(sig.PublicKey().Marshal(), k.key.Marshal()) {
			return errors.New(k.name)
		}
		if err := sig.Verify(wire.ProbePoPNamespace, signed); err != nil {
			return fmt.Errorf("%s does not verify under the probe namespace over the request: %w", ev[i].Type, err)
		}
	}
	return nil
}

// checkProbeKey applies the signer's probe key rule (probe_key_unusable):
// the probe key is not the host key, not a key the bundle in force names
// and not a key a host or machine entry of the directory in force lists.
func checkProbeKey(req *wire.ProbeIssueRequest, b *trust.Bundle, ds *directoryInForce) error {
	if bytes.Equal(req.ProbeKey, req.HostKey) {
		return errors.New("probe key is the request's host key (probe_key_unusable)")
	}
	own, err := krl.InstallationKeys(b)
	if err != nil {
		return fmt.Errorf("trust bundle v%d: %w", b.Version, err)
	}
	if own[string(req.ProbeKey)] {
		return fmt.Errorf("probe key is a key of trust bundle v%d (probe_key_unusable)", b.Version)
	}
	pub, err := ssh.ParsePublicKey(req.ProbeKey)
	if err != nil {
		return fmt.Errorf("request probe key does not parse: %w", err)
	}
	k := trust.FormatKey(pub)
	for _, h := range ds.dir.Hosts {
		if slices.Contains(h.Keys, k) {
			return fmt.Errorf("probe key is listed by directory v%d host %q (probe_key_unusable)", ds.version, h.Name)
		}
	}
	for _, m := range ds.dir.Machines {
		if m.Key == k {
			return fmt.Errorf("probe key is listed by directory v%d machine %q (probe_key_unusable)", ds.version, m.Name)
		}
	}
	return nil
}

// checkProbeCert is anchor.checkIssue for a probe certificate (03-10): it
// must be signed by the bundle's active machine CA, be a user certificate,
// carry the policy version in force in its key ID and in the leaf, and
// stay within profile, the probe profile (certprofile.ProbeProfile), with
// a validity that starts where cert.Build puts it for an issuance between
// the serial and leafMicros.
func (a *anchor) checkProbeCert(b *tlog.IssueBody, c *ssh.Certificate, kid cert.KeyID, leafMicros uint64, profile cert.Profile) error {
	want, ok := a.activeCA[trust.RoleMachine]
	if !ok {
		return fmt.Errorf("trust bundle v%d has no active machine CA", a.bundle.Version)
	}
	if !bytes.Equal(c.SignatureKey.Marshal(), want.Marshal()) {
		return fmt.Errorf("probe certificate signed by %s, not by the active machine CA %s of trust bundle v%d",
			ssh.FingerprintSHA256(c.SignatureKey), ssh.FingerprintSHA256(want), a.bundle.Version)
	}
	if c.CertType != ssh.UserCert {
		return fmt.Errorf("certificate type %s, a probe certificate is a user certificate", certTypeName(c.CertType))
	}
	if kid.Policy != a.policy.Version {
		return fmt.Errorf("key ID pol=%d, but the policy in force is version %d", kid.Policy, a.policy.Version)
	}
	if b.PolicyVersion != a.policy.Version {
		return fmt.Errorf("leaf records policy version %d, but the policy in force is version %d", b.PolicyVersion, a.policy.Version)
	}
	from, to, err := issuanceRange(b.Serial, leafMicros)
	if err != nil {
		return err
	}
	if err := cert.CheckIssued(c, profile, from, to); err != nil {
		return fmt.Errorf("certificate outside the probe profile of policy v%d: %w", a.policy.Version, err)
	}
	return nil
}
