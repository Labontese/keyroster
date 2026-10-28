package audit

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// maxRevokeSkewSeconds is the signer's freshness window for a revoke
// request's CreatedAt (wire.MaxRequestSkewSeconds): the signer takes the
// resolution time from the same clock reading it checks CreatedAt against.
const maxRevokeSkewSeconds = wire.MaxRequestSkewSeconds

// loggedCert is a certificate an issue or login_issue entry logged.
type loggedCert struct {
	role        string // the CA role of its key ID
	caKey       []byte // its signature key, SSH wire format
	validBefore uint64
	keyID       string
}

// revocations is the walk's revocation state: the certificates the log
// issued so far, every entry of the revoke entries so far (what each
// later krl_publish entry must publish), the revoke request IDs seen and
// the last published KRL version. It lets audit verify re-derive what
// every revoke entry must list and what every published KRL must contain
// from the log alone (REVOKE-01..03, T-03-13).
type revocations struct {
	certs     map[uint64]loggedCert // serial -> certificate
	bySubject map[string][]uint64   // role + "/" + subject -> serials, ascending
	byKeyID   map[string][]uint64   // key ID -> serials
	entries   []krl.Entry
	requests  map[[16]byte]uint64 // revoke request ID -> index of its first revoke entry
	// group is the subject revocation whose entries continue in the next
	// revoke entry: it resolved to more than tlog.MaxRevokedEntries
	// certificates and has not listed all of them yet.
	group *subjectGroup
	// due is the revocation whose krl_publish entry must come next: the
	// signer publishes in the transaction of every revocation, right
	// after its last revoke entry, so a log in which another entry, or
	// none, follows it hides the revocation from every KRL.
	due        *publishDue
	krlVersion uint64 // the last published KRL version, 0 before the first
	// floor is the version the krl_publish entry being checked must be
	// above: the highest version a revocation_recovery entry right before
	// it imported (03-06b), 0 otherwise. before sets it as it clears due.
	floor uint64
	// lastKRL is the last published KRL version, re-derived.
	lastKRL *PublishedKRL

	revokes, revokedEntries, publishes, recoveries int
}

// subjectGroup is a subject revocation split over consecutive revoke
// entries of one request.
type subjectGroup struct {
	requestID  [16]byte
	first      uint64 // index of its first revoke entry
	request    []byte
	resolvedAt uint64
	want       []tlog.RevokedEntry // every entry the request resolves to
	listed     int                 // entries listed so far
	next       uint64              // the index its next revoke entry must take
}

// publishDue is a revocation (or recovery) whose krl_publish entry has
// not come yet.
type publishDue struct {
	requestID [16]byte
	last      uint64    // index of its last revoke (or revocation_recovery) entry
	kind      tlog.Kind // the kind of that entry
	floor     uint64    // the version its krl_publish entry must be above (a recovery's highest import), else 0
}

func newRevocations() *revocations {
	return &revocations{
		certs: map[uint64]loggedCert{}, bySubject: map[string][]uint64{}, byKeyID: map[string][]uint64{},
		requests: map[[16]byte]uint64{},
	}
}

// addCert records the certificate c with key ID kid that a verified issue
// or login_issue entry logged.
func (rs *revocations) addCert(c *ssh.Certificate, kid cert.KeyID) {
	rs.certs[c.Serial] = loggedCert{role: kid.CA, caKey: c.SignatureKey.Marshal(), validBefore: c.ValidBefore, keyID: c.KeyId}
	k := kid.CA + "/" + kid.Subject
	rs.bySubject[k] = append(rs.bySubject[k], c.Serial)
	rs.byKeyID[c.KeyId] = append(rs.byKeyID[c.KeyId], c.Serial)
}

// before is called for every entry, at index, before its own check: a
// split subject revocation must continue in exactly the next entry, and a
// completed revocation must be followed by exactly its krl_publish entry.
func (rs *revocations) before(index uint64, kind tlog.Kind) error {
	if g := rs.group; g != nil && (kind != tlog.KindRevoke || index != g.next) {
		return rs.groupCut(g)
	}
	rs.floor = 0
	if d := rs.due; d != nil {
		if kind != tlog.KindKRLPublish || index != d.last+1 {
			return rs.publishMissing(d)
		}
		rs.due, rs.floor = nil, d.floor
	}
	return nil
}

// finish is called after the last entry.
func (rs *revocations) finish() error {
	if g := rs.group; g != nil {
		return rs.groupCut(g)
	}
	if d := rs.due; d != nil {
		return rs.publishMissing(d)
	}
	return nil
}

func (rs *revocations) publishMissing(d *publishDue) error {
	kind := d.kind
	if kind == 0 {
		kind = tlog.KindRevoke
	}
	return fmt.Errorf("audit: entry %d (%s): the revocation of request %s is not followed by the krl_publish entry the signer writes in the same transaction (entry %d)",
		d.last, kind, hex.EncodeToString(d.requestID[:]), d.last+1)
}

func (rs *revocations) groupCut(g *subjectGroup) error {
	return fmt.Errorf("audit: entry %d (revoke): the subject revocation of request %s lists %d of the %d live certificates the log shows, and its next entry %d does not continue it",
		g.first, hex.EncodeToString(g.requestID[:]), g.listed, len(g.want), g.next)
}

// verifyRevoke checks one revoke entry (kind 9) at index, with leaf time
// leafMicros, against the trust state in force and the log before it:
//
//   - its logged request bytes parse strictly (wire.ParseRevokeSigningBytes)
//     and its evidence is admin-sshsig/v1 under the request's namespace
//     (keyroster/revoke-request/v2, or v1 for a 03-01 serial request) over
//     exactly those bytes, every item by an admin of the policy in force
//     and at least one admin (the signer's rule: one admin revokes); the
//     entry records that policy's version, the bundle in force has an
//     installation ID, and a v2 request names that installation;
//   - its resolution time T = ResolvedAtSeconds (F9): T × 10^6 is not
//     after the leaf time, which appendLocked may only raise, and T is
//     within 300 s of the request's CreatedAt, the signer's freshness
//     bound on the same clock reading;
//   - its entries are exactly those the request resolves to, bound to the
//     admin-signed request and the certificates the log issued: serial,
//     the request's serial with the CA key and ValidBefore of its logged
//     certificate, of the request's CA role; key_id, the request's key ID
//     under every CA key of the role in the bundle in force
//     (krl.RoleCAKeys) under which the log issued a certificate with that
//     key ID, each with the latest ValidBefore of those certificates, and
//     at least one (key_id_not_issued); key, the request's key, which must
//     not be a key of the bundle in force (krl.InstallationKeys) and must
//     keep the log's explicit keys within krl.CheckExplicitKeys
//     (explicit_key_cap_reached); subject user, the (CA key, serial,
//     ValidBefore) of every certificate the issue and login_issue entries
//     before it logged under the user CA with a key ID naming the subject
//     and live at T (krl.EntryLive), ascending, whether or not an earlier
//     revoke entry already lists it, over the consecutive revoke entries
//     of that request (every one but the last listing
//     tlog.MaxRevokedEntries);
//   - its request ID was used by no earlier revoke entry, except the one
//     right before it in the same split subject revocation;
//   - the entry right after the revocation's last revoke entry is a
//     krl_publish entry (before, finish), as the signer writes it in the
//     same transaction, so no revocation stays out of the KRLs.
//
// The leaf time is used only for the bound on T, never for liveness: the
// signer evaluates liveness at T, and the leaf time may have been raised
// after a clock step back.
func verifyRevoke(index uint64, body *tlog.RevokeBody, leafMicros uint64, a *anchor, rs *revocations) error {
	req, err := wire.ParseRevokeSigningBytes(body.Request)
	if err != nil {
		return fmt.Errorf("logged request: %w", err)
	}
	if a.bundle == nil || a.policy == nil {
		return errors.New("revoke entry before the first bundle_install: no root-signed policy is in force")
	}
	if a.bundle.InstallationID == "" {
		return fmt.Errorf("trust bundle v%d in force has no installation ID, and the signer revokes nothing without one", a.bundle.Version)
	}
	if body.PolicyVersion != a.policy.Version {
		return fmt.Errorf("entry records policy version %d, but the policy in force is version %d", body.PolicyVersion, a.policy.Version)
	}
	// A v2 request names the installation it is for, and the signer revokes
	// only for its own (the T-03-20 rule of directories). A v1 request of
	// 03-01 names none and revokes only by serial (wire.ParseRevokeSigningBytes).
	if req.InstallationID != "" && req.InstallationID != a.bundle.InstallationID {
		return fmt.Errorf("the request is for installation %s, but trust bundle v%d in force is for %s, and the signer refuses it (revoke_installation_mismatch)",
			req.InstallationID, a.bundle.Version, a.bundle.InstallationID)
	}
	if err := verifyRevokeAdmins(body.Evidence, body.Request, req.Namespace(), a.policy); err != nil {
		return err
	}
	if body.ResolvedAtSeconds > math.MaxUint64/1_000_000 || body.ResolvedAtSeconds*1_000_000 > leafMicros {
		return fmt.Errorf("resolution time %d s is after the leaf time %d µs: the signer resolves a revocation at the clock reading the leaf time is taken from, and only ever raises the leaf time",
			body.ResolvedAtSeconds, leafMicros)
	}
	if d := absDiff(body.ResolvedAtSeconds, req.CreatedAt); d > maxRevokeSkewSeconds {
		return fmt.Errorf("resolution time %d s is %d s from the request's CreatedAt %d; the signer accepts at most %d s",
			body.ResolvedAtSeconds, d, req.CreatedAt, maxRevokeSkewSeconds)
	}

	// The next part of a split subject revocation (before checked that it
	// is the entry right after the previous part).
	if g := rs.group; g != nil {
		if req.RequestID != g.requestID || !bytes.Equal(body.Request, g.request) || body.ResolvedAtSeconds != g.resolvedAt {
			return rs.groupCut(g)
		}
		want := g.want[g.listed:min(len(g.want), g.listed+tlog.MaxRevokedEntries)]
		if err := sameEntries(body.Entries, want); err != nil {
			return fmt.Errorf("part of the subject revocation of %q begun at entry %d: %w", req.Subject, g.first, err)
		}
		g.listed += len(want)
		g.next++
		if g.listed == len(g.want) {
			rs.group = nil
			rs.due = &publishDue{requestID: req.RequestID, last: index}
		}
		rs.add(body.Entries)
		return nil
	}
	if first, used := rs.requests[req.RequestID]; used {
		return fmt.Errorf("request ID %s replayed: revoke entry %d already used it", hex.EncodeToString(req.RequestID[:]), first)
	}
	rs.requests[req.RequestID] = index

	var want []tlog.RevokedEntry
	switch req.Target {
	case wire.TargetSerial:
		c, ok := rs.certs[req.Serial]
		if !ok {
			return fmt.Errorf("revokes serial %d, which no earlier issue or login_issue entry logged", req.Serial)
		}
		if c.role != req.CARole.String() {
			return fmt.Errorf("revokes serial %d as a %s certificate, but the log issued it under the %s CA", req.Serial, req.CARole, c.role)
		}
		want = []tlog.RevokedEntry{{Kind: tlog.RevokedSerial, CAKey: c.caKey, Serial: req.Serial, ValidBeforeSeconds: c.validBefore}}
	case wire.TargetKeyID:
		keys, err := krl.RoleCAKeys(a.bundle, req.CARole.String())
		if err != nil {
			return fmt.Errorf("trust bundle v%d: %w", a.bundle.Version, err)
		}
		for _, caKey := range keys {
			var vb uint64
			for _, serial := range rs.byKeyID[req.KeyID] {
				if c := rs.certs[serial]; bytes.Equal(c.caKey, caKey) {
					vb = max(vb, c.validBefore)
				}
			}
			if vb == 0 {
				continue // the log issued no certificate with that key ID under caKey
			}
			want = append(want, tlog.RevokedEntry{Kind: tlog.RevokedKeyID, CAKey: caKey, KeyID: req.KeyID, ValidBeforeSeconds: vb})
		}
		if len(want) == 0 {
			return fmt.Errorf("revokes key ID %q, which no earlier issue or login_issue entry logged under a %s CA key of trust bundle v%d; the signer refuses it (key_id_not_issued)",
				req.KeyID, req.CARole, a.bundle.Version)
		}
	case wire.TargetKey:
		own, err := krl.InstallationKeys(a.bundle)
		if err != nil {
			return fmt.Errorf("trust bundle v%d: %w", a.bundle.Version, err)
		}
		if own[string(req.Key)] {
			return fmt.Errorf("revokes key %s, a key of trust bundle v%d, which the signer refuses (key_is_ca_of_this_installation)",
				keyFingerprint(req.Key), a.bundle.Version)
		}
		revoked := [][]byte{req.Key}
		for _, e := range rs.entries {
			if e.Kind == krl.EntryKey {
				revoked = append(revoked, e.Key)
			}
		}
		if err := krl.CheckExplicitKeys(revoked); err != nil {
			return fmt.Errorf("revokes key %s beyond the explicit-key cap, which the signer refuses (explicit_key_cap_reached): %w",
				keyFingerprint(req.Key), err)
		}
		want = []tlog.RevokedEntry{{Kind: tlog.RevokedKey, Key: req.Key}}
	case wire.TargetSubject:
		if req.SubjectKind != wire.SubjectUser {
			return fmt.Errorf("revokes a %s subject, which this version does not resolve", req.SubjectKind)
		}
		role := trust.RoleUser
		for _, serial := range rs.bySubject[role+"/"+req.Subject] {
			if c := rs.certs[serial]; c.role == role && krl.EntryLive(c.validBefore, body.ResolvedAtSeconds) {
				want = append(want, tlog.RevokedEntry{Kind: tlog.RevokedSerial, CAKey: c.caKey, Serial: serial, ValidBeforeSeconds: c.validBefore})
			}
		}
		slices.SortFunc(want, func(x, y tlog.RevokedEntry) int { return cmp.Compare(x.Serial, y.Serial) })
		if len(want) > tlog.MaxRevokedEntries {
			rs.group = &subjectGroup{requestID: req.RequestID, first: index, request: body.Request,
				resolvedAt: body.ResolvedAtSeconds, want: want, listed: tlog.MaxRevokedEntries, next: index + 1}
			want = want[:tlog.MaxRevokedEntries]
		}
	default:
		return fmt.Errorf("unknown revocation target %d", req.Target)
	}
	if err := sameEntries(body.Entries, want); err != nil {
		return err
	}
	if rs.group == nil {
		rs.due = &publishDue{requestID: req.RequestID, last: index}
	}
	rs.revokes++
	rs.add(body.Entries)
	return nil
}

// add records the entries of a verified revoke entry.
func (rs *revocations) add(entries []tlog.RevokedEntry) {
	kinds := map[uint8]uint8{tlog.RevokedSerial: krl.EntrySerial, tlog.RevokedKeyID: krl.EntryKeyID, tlog.RevokedKey: krl.EntryKey}
	for _, e := range entries {
		rs.entries = append(rs.entries, krl.Entry{Kind: kinds[e.Kind], CAKey: e.CAKey, Serial: e.Serial, KeyID: e.KeyID, Key: e.Key, ValidBefore: e.ValidBeforeSeconds})
	}
	rs.revokedEntries += len(entries)
}

// sameEntries requires got, a revoke entry's entries, to be exactly want,
// in order.
func sameEntries(got, want []tlog.RevokedEntry) error {
	if len(got) != len(want) {
		return fmt.Errorf("lists %d entries, but the log shows %d for the admin-signed request", len(got), len(want))
	}
	for i := range got {
		g, w := got[i], want[i]
		if g.Kind != w.Kind || !bytes.Equal(g.CAKey, w.CAKey) || g.Serial != w.Serial || g.KeyID != w.KeyID ||
			!bytes.Equal(g.Key, w.Key) || g.ValidBeforeSeconds != w.ValidBeforeSeconds {
			return fmt.Errorf("entry %d is %s, but the log shows %s for the admin-signed request", i, describeEntry(g), describeEntry(w))
		}
	}
	return nil
}

func describeEntry(e tlog.RevokedEntry) string {
	switch e.Kind {
	case tlog.RevokedSerial:
		return fmt.Sprintf("serial %d under CA %s valid before %d", e.Serial, keyFingerprint(e.CAKey), e.ValidBeforeSeconds)
	case tlog.RevokedKeyID:
		return fmt.Sprintf("key ID %q under CA %s valid before %d", e.KeyID, keyFingerprint(e.CAKey), e.ValidBeforeSeconds)
	case tlog.RevokedKey:
		return "key " + keyFingerprint(e.Key)
	}
	return fmt.Sprintf("an entry of kind %d", e.Kind)
}

// keyFingerprint is the SHA256 fingerprint of an SSH wire-format key, or
// a description when it does not parse.
func keyFingerprint(blob []byte) string {
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return "(unparsable key)"
	}
	return ssh.FingerprintSHA256(pub)
}

// verifyRevokeAdmins checks a revoke entry's evidence the way the signer
// authorizes a revocation: every item admin-sshsig/v1, an SSHSIG under
// namespace (the logged request's: keyroster/revoke-request/v2, or v1 for
// a 03-01 request) over msg by an admin of pol, and at least one admin.
func verifyRevokeAdmins(evidence []wire.Evidence, msg []byte, namespace string, pol *trust.Policy) error {
	admins := map[string]bool{}
	for _, ad := range pol.Admins {
		admins[ad.Key] = true
	}
	if len(evidence) == 0 {
		return errors.New("the revocation carries no admin evidence")
	}
	for i, ev := range evidence {
		if ev.Type != wire.EvidenceAdminSSHSIG {
			return fmt.Errorf("evidence %d has type %q, want %s", i, ev.Type, wire.EvidenceAdminSSHSIG)
		}
		sig, err := sshsig.Parse(ev.Blob)
		if err != nil {
			return fmt.Errorf("evidence %d does not parse: %w", i, err)
		}
		if !admins[trust.FormatKey(sig.PublicKey())] {
			return fmt.Errorf("evidence %d is signed by %s, not an admin of policy v%d", i, ssh.FingerprintSHA256(sig.PublicKey()), pol.Version)
		}
		if err := sig.Verify(namespace, msg); err != nil {
			return fmt.Errorf("evidence %d does not approve the logged request under %s: %w", i, namespace, err)
		}
	}
	return nil
}

// verifyKRLPublish checks one krl_publish entry (kind 10) at index, with
// leaf time leafMicros: the manifest is signed by the ops key of the
// bundle in force under keyroster/krl/v1, for the bundle's installation
// ID, and names the bundle version in force and the entry's own index;
// the entry's issued_at (IssuedAtSeconds, whole seconds) is the
// manifest's and, × 10^6, not after the leaf time; the version is the
// previous one + 1, or IssuedAtSeconds when that is larger (owner decision
// 2026-10-25, Q1: max(prev + 1, issued_at), and the +1 of 03-01); and the
// KRL's SHA-256, in the entry and the manifest, is that of the KRL
// re-encoded (krl.Encode) from every revoke entry before it with the
// signer's own set builder and pruning rule at IssuedAtSeconds
// (krl.PublishSet). So a published KRL that omits a revocation, or prunes
// an entry early, fails.
func verifyKRLPublish(index uint64, body *tlog.KRLPublishBody, leafMicros uint64, a *anchor, rs *revocations) error {
	if a.bundle == nil {
		return errors.New("krl_publish entry before the first bundle_install: no root-signed ops key is in force")
	}
	if a.bundle.InstallationID == "" {
		return fmt.Errorf("trust bundle v%d in force has no installation ID, and the signer publishes no KRL without one", a.bundle.Version)
	}
	if body.BundleVersion != a.bundle.Version {
		return fmt.Errorf("entry records bundle version %d, but trust bundle v%d is in force", body.BundleVersion, a.bundle.Version)
	}
	issuedAt := body.IssuedAtSeconds
	if issuedAt > math.MaxUint64/1_000_000 || issuedAt*1_000_000 > leafMicros {
		return fmt.Errorf("issued_at %d s is after the leaf time %d µs: the signer takes both from one clock reading and only ever raises the leaf time",
			issuedAt, leafMicros)
	}
	prev, v := rs.krlVersion, body.KRLVersion
	switch {
	case v <= prev:
		return fmt.Errorf("KRL version %d is not above the previous version %d", v, prev)
	case v == prev+1, issuedAt > prev+1 && v == issuedAt:
	case v > max(prev+1, issuedAt):
		return fmt.Errorf("KRL version %d is above max(previous + 1, issued_at) = %d", v, max(prev+1, issuedAt))
	default:
		return fmt.Errorf("KRL version %d is neither the previous version + 1 (%d) nor issued_at (%d)", v, prev+1, issuedAt)
	}
	// The publish right after a revocation_recovery entry must be above
	// every version it imported, so every host that saw one accepts it.
	if rs.floor != 0 && v <= rs.floor {
		return fmt.Errorf("KRL version %d right after a revocation recovery is not above the imported version %d, so a host that saw it would refuse this KRL", v, rs.floor)
	}
	set, err := krl.PublishSet(rs.entries, issuedAt)
	if err != nil {
		return fmt.Errorf("the log's revocations: %w", err)
	}
	data, err := krl.Encode(set, v, time.Unix(int64(issuedAt), 0)) //nolint:gosec // G115: issuedAt <= MaxUint64/10^6, checked above
	if err != nil {
		return fmt.Errorf("re-encoding the KRL from the log's revocations: %w", err)
	}
	if sha256.Sum256(data) != body.SHA256 {
		return errors.New("its KRL SHA-256 is not that of the KRL re-derived from the log's revocations (an entry omitted, added or pruned early?)")
	}
	m, err := krl.VerifyManifest(body.Manifest, body.Sig, data, a.bundle, a.bundle.InstallationID, prev)
	if err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	switch {
	case m.KRLVersion != v:
		return fmt.Errorf("manifest names KRL version %d, the entry %d", m.KRLVersion, v)
	case m.BundleVersion != body.BundleVersion:
		return fmt.Errorf("manifest names bundle version %d, the entry %d", m.BundleVersion, body.BundleVersion)
	case m.LogIndex != index:
		return fmt.Errorf("manifest names log index %d, but it is entry %d", m.LogIndex, index)
	case m.IssuedAt != time.Unix(int64(issuedAt), 0).UTC().Format(trust.TimeFormat): //nolint:gosec // G115: checked above
		return fmt.Errorf("manifest issued_at %s is not the entry's %d s", m.IssuedAt, issuedAt)
	}
	rs.krlVersion = v
	rs.publishes++
	rs.lastKRL = &PublishedKRL{KRL: data, Manifest: body.Manifest, Sig: body.Sig}
	return nil
}
