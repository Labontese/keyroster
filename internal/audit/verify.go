package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/certprofile"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/wire"
)

// maxLine bounds one export line (a bundle_install leaf carries up to four
// 1 MiB documents, base64 encoded, plus its decoded object).
const maxLine = 16 << 20

// Options configures Verify.
type Options struct {
	// Pins are the SHA256 fingerprints of the offline root keys, obtained
	// out of band. They are the only trust anchor. They name the root set
	// of one trust bundle in the log, the anchor bundle: the genesis
	// bundle, or a later one such as the current roots after a rotation.
	// The anchor's signatures by the pinned roots cover its prev hash, so
	// every earlier bundle is authenticated through the prev-hash chain;
	// the log key and the CA keys are taken from bundle_install entries in
	// that chain, never from the export otherwise.
	Pins []string
	// Threshold is the number of pinned roots that must have signed the
	// anchor bundle; it must equal that bundle's own threshold.
	Threshold int
	// Previous is an earlier signed checkpoint of the same log (optional).
	// The export must extend it: at least as many entries, and its first
	// entries must reproduce the earlier root.
	Previous []byte
}

// Report summarizes a verified export.
type Report struct {
	Size    uint64
	Root    []byte
	Counts  map[tlog.Kind]uint64
	Serials int // issued certificates (issue leaves), each re-verified
	// IssuedByCA counts the issue leaves per CA role (user, host, machine).
	IssuedByCA map[string]int
	// SummarizedRefusals is the total of all refusal_summary counts:
	// refusals that were counted but not logged individually.
	SummarizedRefusals uint64
	// BundleVersion and PolicyVersion are those of the last installed
	// trust bundle and policy; LogKey is the log key they name.
	BundleVersion uint64
	PolicyVersion uint64
	LogKey        ssh.PublicKey
	// AnchorVersion is the version of the first trust bundle in the log
	// whose root set and threshold are exactly the pins (the anchor).
	AnchorVersion uint64
}

// anchor is the trust state in force at a point of the log: the last
// bundle and policy that verified against the pins (genesis) or against
// their predecessor (successor), and the keys taken from them.
type anchor struct {
	bundle    *trust.Bundle
	canonical []byte
	policy    *trust.Policy
	policyDoc []byte // the policy's bytes, which a successor's policy chains to
	logKey    ssh.PublicKey
	activeCA  map[string]ssh.PublicKey // role -> active CA key
	// anchorVersion is the version of the first accepted bundle whose root
	// set and threshold equal the pins (0: none yet); lastMismatch is why
	// the last accepted bundle did not match them.
	anchorVersion uint64
	lastMismatch  error
	// roots are the root keys of every accepted bundle. A retired root
	// may still exist, so no later policy may name one as an admin
	// (KEY-07). It is one set, added to once per bundle, so the check
	// costs each bundle its own admins, not every earlier root again.
	roots trust.RootKeySet
}

// install verifies one bundle_install entry and makes its bundle the one in
// force. The first must be a genesis bundle (version 1, all-zero prev)
// signed by its own root threshold; every later one must be a valid
// successor of the bundle in force (TUF rule), with its policy chained to
// the policy in force, and its policy must name no root of any earlier
// bundle as an admin. In Phase 1 every bundle must name the same log key.
// The first accepted bundle whose root set and threshold are exactly opts'
// pins becomes the anchor (trust.MatchPins); Verify fails at the end of the
// log if there is none.
func (a *anchor) install(body *tlog.BundleInstallBody, opts Options) error {
	var (
		b   *trust.Bundle
		p   *trust.Policy
		err error
	)
	if a.bundle == nil {
		b, p, err = verifySelfSignedGenesis(body)
		if err != nil {
			return fmt.Errorf("bundle_install is not a valid genesis bundle: %w", err)
		}
	} else {
		b, p, err = trust.VerifySuccessor(a.bundle, a.canonical, a.policyDoc, body.Bundle, body.BundleSigs, body.Policy, body.PolicySigs)
		if err != nil {
			return fmt.Errorf("bundle_install is not a valid successor of trust bundle v%d: %w", a.bundle.Version, err)
		}
	}
	if body.BundleVersion != b.Version {
		return fmt.Errorf("bundle_install records bundle version %d, but its bundle is version %d", body.BundleVersion, b.Version)
	}
	// VerifySuccessor checks the policy against next's and prev's roots
	// only; a root retired earlier must not become an admin either.
	if err := trust.CheckAdminsNotRootSet(p, a.roots); err != nil {
		return fmt.Errorf("trust bundle v%d: a root of an earlier trust bundle stays a root: %w", b.Version, err)
	}
	logKey, err := trust.ParseKey(b.Log.Key)
	if err != nil {
		return fmt.Errorf("bundle_install: log key: %w", err)
	}
	if a.logKey != nil && !bytes.Equal(a.logKey.Marshal(), logKey.Marshal()) {
		return fmt.Errorf("log key change unsupported: trust bundle v%d names log key %s, earlier bundles %s",
			b.Version, ssh.FingerprintSHA256(logKey), ssh.FingerprintSHA256(a.logKey))
	}
	active := map[string]ssh.PublicKey{}
	for _, ca := range b.CAs {
		if ca.State != "active" {
			continue
		}
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return fmt.Errorf("bundle_install: %s CA key: %w", ca.Role, err)
		}
		active[ca.Role] = pub
	}
	a.bundle, a.canonical, a.policy, a.policyDoc, a.logKey, a.activeCA = b, body.Bundle, p, body.Policy, logKey, active
	if a.roots == nil {
		a.roots = trust.RootKeySet{}
	}
	if err := a.roots.Add(b.Root.Keys); err != nil {
		return fmt.Errorf("trust bundle v%d: %w", b.Version, err)
	}
	if a.anchorVersion == 0 {
		// b is the bundle the verifier returned, so its signatures by its
		// own root threshold were checked; MatchPins adds that this root
		// set and threshold are exactly the pinned ones.
		if err := trust.MatchPins(b, opts.Pins, opts.Threshold); err != nil {
			a.lastMismatch = fmt.Errorf("trust bundle v%d: %w", b.Version, err)
		} else {
			a.anchorVersion = b.Version
		}
	}
	return nil
}

// verifySelfSignedGenesis verifies the first bundle_install entry as a
// genesis bundle pinned to its own root set and threshold: version 1 with
// the all-zero prev, its policy hash, and its own threshold of its roots
// signing both documents. Whether those roots are the operator's is decided
// by the anchor (trust.MatchPins), not here.
func verifySelfSignedGenesis(body *tlog.BundleInstallBody) (*trust.Bundle, *trust.Policy, error) {
	g, err := trust.ParseBundle(body.Bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("bundle: %w", err)
	}
	own := make([]string, 0, len(g.Root.Keys))
	for _, rk := range g.Root.Keys {
		pub, err := trust.ParseKey(rk.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("bundle: root key: %w", err)
		}
		own = append(own, ssh.FingerprintSHA256(pub))
	}
	return trust.VerifyGenesisBundle(body.Bundle, body.BundleSigs, body.Policy, body.PolicySigs, own, int(g.Root.Threshold))
}

// checkIssue checks an issue leaf's certificate against the bundle and
// policy in force: it must be signed by the active CA of the leaf's role,
// be a host certificate exactly for the host role, carry the policy
// version in force in its key ID and in the leaf, and stay within the
// role's certificate profile of that policy (cert.CheckIssued: validity
// cap, extensions, critical options, principals, subject key), with a
// validity that starts where cert.Build puts it for an issuance between
// the serial and leafMicros (both microsecond times; see Verify).
func (a *anchor) checkIssue(b *tlog.IssueBody, c *ssh.Certificate, kid cert.KeyID, leafMicros uint64) error {
	role := kid.CA
	if a.bundle == nil {
		return errors.New("issue entry before the first bundle_install: no root-signed CA key is in force")
	}
	want, ok := a.activeCA[role]
	if !ok {
		return fmt.Errorf("trust bundle v%d has no active %s CA", a.bundle.Version, role)
	}
	if !bytes.Equal(c.SignatureKey.Marshal(), want.Marshal()) {
		return fmt.Errorf("certificate for CA role %s signed by %s, not by the role's active CA %s in trust bundle v%d",
			role, ssh.FingerprintSHA256(c.SignatureKey), ssh.FingerprintSHA256(want), a.bundle.Version)
	}
	wantType := uint32(ssh.UserCert)
	if role == trust.RoleHost {
		wantType = ssh.HostCert
	}
	if c.CertType != wantType {
		return fmt.Errorf("certificate type %s for CA role %s, want %s", certTypeName(c.CertType), role, certTypeName(wantType))
	}
	if kid.Policy != a.policy.Version {
		return fmt.Errorf("key ID pol=%d, but the policy in force is version %d", kid.Policy, a.policy.Version)
	}
	if b.PolicyVersion != a.policy.Version {
		return fmt.Errorf("leaf records policy version %d, but the policy in force is version %d", b.PolicyVersion, a.policy.Version)
	}
	profile, err := certprofile.ForRole(role, a.policy)
	if err != nil {
		return fmt.Errorf("policy v%d: %w", a.policy.Version, err)
	}
	from, to, err := issuanceRange(b.Serial, leafMicros)
	if err != nil {
		return err
	}
	if err := cert.CheckIssued(c, profile, from, to); err != nil {
		return fmt.Errorf("certificate outside the %s profile of policy v%d: %w", role, a.policy.Version, err)
	}
	return nil
}

// issuanceRange returns the times between which the signer issued the
// certificate of an issue leaf with serial and leafMicros. serial.Next
// allocates the serial from the clock in microseconds and returns only
// once the clock has reached it, the signer refuses to issue when its
// next clock reading (the issuance time) is below the serial, and
// appendLocked records the issuance time as the leaf time, raised to the
// previous leaf's if the clock went back. So serial <= issuance time <=
// leaf time, and a serial after the leaf time is one the signer could not
// have written.
func issuanceRange(serial, leafMicros uint64) (time.Time, time.Time, error) {
	if serial > math.MaxInt64 || leafMicros > math.MaxInt64 {
		return time.Time{}, time.Time{}, fmt.Errorf("serial %d or leaf time %d out of range", serial, leafMicros)
	}
	if serial > leafMicros {
		return time.Time{}, time.Time{}, fmt.Errorf("serial %d is after the leaf time %d: the signer allocates serials from its clock in microseconds, never after the issuance time the leaf records",
			serial, leafMicros)
	}
	return time.UnixMicro(int64(serial)), time.UnixMicro(int64(leafMicros)), nil //nolint:gosec // G115: both <= math.MaxInt64, checked above
}

// directoryInForce is the directory the log's last directory_install entry
// installed (D-01), kept as the walk goes, the way anchor keeps the policy
// in force.
type directoryInForce struct {
	raw     []byte // canonical bytes; nil while no directory is installed
	sigs    []byte // the admins' signatures it was installed with
	dir     *directory.Directory
	version uint64
	// authErr is why the directory is not authorized under the policy in
	// force (nil: it is). It is the one cached result for the current
	// (directory, policy) pair: authorizeDirectory runs only when one side
	// changes, at a directory_install entry and after each bundle_install
	// entry, and every login_issue entry reads it (review finding
	// 02-04-F8). A directory installed under an earlier policy therefore
	// stays in force across a policy change that still authorizes it,
	// such as one that only adds the WebAuthn RP, as the signer's start-up
	// check (loadDirectory) treats it.
	authErr error
}

// authorizeDirectory checks a directory against pol the way the signer
// authorizes one (InstallDirectory, loadDirectory): signed by at least
// pol's admin quorum of distinct admins, and every role within pol's user
// CA profile.
func authorizeDirectory(raw, sigs []byte, d *directory.Directory, pol *trust.Policy) error {
	if _, err := directory.VerifySignatures(raw, sigs, pol); err != nil {
		return fmt.Errorf("not signed by the admin quorum of policy v%d: %w", pol.Version, err)
	}
	if err := directory.CheckPolicy(d, pol); err != nil {
		return fmt.Errorf("outside the user CA profile of policy v%d: %w", pol.Version, err)
	}
	return nil
}

// install verifies one directory_install entry (kind 7) against the trust
// state in force and makes its directory the one in force: the document
// parses, is the successor of the directory in force (version + 1, prev =
// SHA-256 of its bytes; version 1 with the all-zero prev first), is
// signed by the admin quorum of the policy in force and fits that policy's
// user CA profile, and the entry records that policy's version and the
// document's own version.
func (ds *directoryInForce) install(body *tlog.DirectoryInstallBody, a *anchor) error {
	if a.policy == nil {
		return errors.New("directory_install before the first bundle_install: no root-signed policy is in force")
	}
	if body.PolicyVersion != a.policy.Version {
		return fmt.Errorf("entry records policy version %d, but the policy in force is version %d", body.PolicyVersion, a.policy.Version)
	}
	d, err := directory.Parse(body.Directory)
	if err != nil {
		return fmt.Errorf("directory does not parse: %w", err)
	}
	if body.Version != d.Version {
		return fmt.Errorf("entry records directory version %d, but its document is version %d", body.Version, d.Version)
	}
	if err := directory.CheckSuccessor(ds.raw, d); err != nil {
		return fmt.Errorf("directory v%d is not the successor of the directory in force (v%d): %w", d.Version, ds.version, err)
	}
	if err := authorizeDirectory(body.Directory, body.Sigs, d, a.policy); err != nil {
		return fmt.Errorf("directory v%d is %w", d.Version, err)
	}
	ds.raw, ds.sigs, ds.dir, ds.version, ds.authErr = body.Directory, body.Sigs, d, d.Version, nil
	return nil
}

// recheck recomputes the cached authorization of the directory in force
// under pol, after a bundle_install entry made pol the policy in force.
func (ds *directoryInForce) recheck(pol *trust.Policy) {
	if ds.dir == nil {
		return
	}
	ds.authErr = authorizeDirectory(ds.raw, ds.sigs, ds.dir, pol)
}

// issuance is the walk's state shared by issue and login_issue entries.
// The signer issues both from one serial counter and one issuance table,
// and its start-up check counts both kinds together (02-01, T-02-116), so
// serials form one strictly increasing sequence across the two kinds, and
// a request ID is used at most once by a login.
type issuance struct {
	lastSerial uint64
	// seen is whether any certificate (of either kind) came before. It is
	// its own variable: Report.Serials counts issue entries only.
	seen bool
	// issueIDs and loginIDs map the request IDs (32 hex digits, the key
	// ID's req field) of issue and login_issue entries to their entry
	// index. A login request ID must be new to both, and an issue entry
	// must not reuse a login's. Two issue entries are not compared, which
	// keeps the Phase 1 checks of issue entries unchanged.
	issueIDs map[string]uint64
	loginIDs map[string]uint64
}

// next records a verified certificate with serial.
func (s *issuance) next(serial uint64) {
	s.lastSerial, s.seen = serial, true
}

const (
	// maxLoginSkewSeconds is the signer's freshness window for a login
	// request's CreatedAt (internal/signer maxClockSkew).
	maxLoginSkewSeconds = 300
	// backdateSeconds is how far cert.Build puts ValidAfter before the
	// issuance time, so a certificate for ValidForSeconds spans exactly
	// ValidForSeconds + backdateSeconds. The login fixtures build their
	// certificates with cert.Build, so a change there fails them.
	backdateSeconds = 300
)

// verifyLoginIssue re-proves one login_issue entry (kind 8) from the log
// alone (KEY-02, T-02-17): the logged request bytes, the directory and the
// policy in force, and the certificate. Every failure names its check.
func verifyLoginIssue(index uint64, body *tlog.LoginIssueBody, leafMicros uint64, a *anchor, ds *directoryInForce, iss *issuance) error {
	req, err := wire.ParseLoginIssueSigningBytes(body.Request)
	if err != nil {
		return fmt.Errorf("logged request: %w", err)
	}
	if a.policy == nil {
		return errors.New("login_issue before the first bundle_install: no root-signed policy is in force")
	}
	if body.PolicyVersion != a.policy.Version {
		return fmt.Errorf("entry records policy version %d, but the policy in force is version %d", body.PolicyVersion, a.policy.Version)
	}
	if ds.dir == nil {
		return fmt.Errorf("entry records directory version %d, but no directory is installed", body.DirectoryVersion)
	}
	if body.DirectoryVersion != ds.version {
		return fmt.Errorf("entry records directory version %d, but the directory in force is version %d", body.DirectoryVersion, ds.version)
	}
	if ds.authErr != nil {
		return fmt.Errorf("the directory in force (v%d) is not authorized under the policy in force: directory v%d is %w", ds.version, ds.version, ds.authErr)
	}
	rp := a.policy.WebAuthn
	if rp == nil {
		return fmt.Errorf("policy v%d has no WebAuthn relying party, so no login could be approved", a.policy.Version)
	}
	switch {
	case len(body.Evidence) != 1:
		return fmt.Errorf("entry carries %d evidence items, want exactly one %s", len(body.Evidence), wire.EvidenceWebAuthnAssertion)
	case body.Evidence[0].Type != wire.EvidenceWebAuthnAssertion:
		return fmt.Errorf("evidence type %q, want %s", body.Evidence[0].Type, wire.EvidenceWebAuthnAssertion)
	}
	asrt, err := wire.ParseWebAuthnAssertion(body.Evidence[0].Blob)
	if err != nil {
		return fmt.Errorf("passkey assertion does not parse: %w", err)
	}
	grant, err := ds.dir.Authorize(req.Subject, req.Roles)
	if err != nil {
		return fmt.Errorf("directory v%d grants no login to user %q for roles %q: %w", ds.version, req.Subject, req.Roles, err)
	}
	cred, ok := ds.dir.Credential(req.Subject, asrt.CredentialID)
	if !ok {
		return fmt.Errorf("directory v%d binds no credential %s to user %q", ds.version,
			base64.RawURLEncoding.EncodeToString(asrt.CredentialID), req.Subject)
	}
	if err := webauthn.VerifyAssertion(cred, rp.RPID, rp.Origins, sha256.Sum256(body.Request), webauthn.Assertion{
		CredentialID:      asrt.CredentialID,
		AuthenticatorData: asrt.AuthenticatorData,
		ClientDataJSON:    asrt.ClientDataJSON,
		Signature:         asrt.Signature,
	}); err != nil {
		return fmt.Errorf("passkey assertion of user %q does not approve the logged request: %w", req.Subject, err)
	}
	if !slices.Equal(req.Principals, grant.Principals) {
		return fmt.Errorf("request principals %q differ from what directory v%d grants for roles %q: %q",
			req.Principals, ds.version, grant.Roles, grant.Principals)
	}
	profile, err := certprofile.ForRole(trust.RoleUser, a.policy)
	if err != nil {
		return fmt.Errorf("policy v%d: %w", a.policy.Version, err)
	}
	profileCap := uint64(profile.MaxTTL / time.Second) //nolint:gosec // G115: the profile cap is positive (certprofile.ForRole)
	if ttl := uint64(req.ValidForSeconds); ttl > min(grant.MaxTTLSeconds, profileCap) {
		return fmt.Errorf("request TTL %d s is above the cap: role %d s, user CA profile %d s", ttl, grant.MaxTTLSeconds, profileCap)
	}
	// The certificate must carry exactly what cert.Build gives the signer's
	// request: the profile defaults plus the requested extensions, each
	// named once and granted by the selected roles.
	wantExt := maps.Clone(profile.DefaultExtensions)
	named := make(map[string]bool, len(req.Extensions))
	for _, e := range req.Extensions {
		if named[e] {
			return fmt.Errorf("request names extension %q twice", e)
		}
		named[e] = true
		if !slices.Contains(grant.Extensions, e) {
			return fmt.Errorf("request extension %q is not granted by roles %q", e, grant.Roles)
		}
		wantExt[e] = ""
	}

	// The certificate: the issue-entry checks with the user CA role, then
	// the binding to the request.
	ib := &tlog.IssueBody{CARole: uint8(wire.CARoleUser), Serial: body.Serial, PolicyVersion: body.PolicyVersion, Cert: body.Cert, KeyID: body.KeyID}
	c, kid, err := checkIssue(ib, iss.lastSerial, iss.seen)
	if err != nil {
		return err
	}
	if kid.Roles == nil {
		return errors.New("a login_issue entry must carry a kr2 key ID, not kr1")
	}
	if err := a.checkIssue(ib, c, kid, leafMicros); err != nil {
		return err
	}
	// The key is compared by identity, not by the request's bytes: the
	// passkey approved bytes that decode to exactly one key, and a signer
	// before the canonical-encoding refusal logged a non-canonical
	// encoding (an RSA mpint with a leading zero) verbatim.
	subject, err := ssh.ParsePublicKey(req.SubjectKey)
	if err != nil {
		return fmt.Errorf("request subject key does not parse: %w", err)
	}
	if !bytes.Equal(c.Key.Marshal(), subject.Marshal()) {
		return fmt.Errorf("certificate key %s is not the request's subject key", ssh.FingerprintSHA256(c.Key))
	}
	if !slices.Equal(c.ValidPrincipals, req.Principals) {
		return fmt.Errorf("certificate principals %q differ from the request's %q", c.ValidPrincipals, req.Principals)
	}
	if span, want := c.ValidBefore-c.ValidAfter, uint64(req.ValidForSeconds)+uint64(backdateSeconds); span != want {
		return fmt.Errorf("certificate spans %d s, but cert.Build gives %d s for the requested %d s", span, want, req.ValidForSeconds)
	}
	if !maps.Equal(c.Extensions, wantExt) {
		return fmt.Errorf("certificate extensions %q, want exactly the profile defaults and the requested extensions %q",
			slices.Sorted(maps.Keys(c.Extensions)), slices.Sorted(maps.Keys(wantExt)))
	}
	if len(c.CriticalOptions) != 0 {
		return fmt.Errorf("certificate carries critical options %q; a login request sets none", slices.Sorted(maps.Keys(c.CriticalOptions)))
	}
	reqID := hex.EncodeToString(req.RequestID[:])
	switch {
	case kid.Subject != req.Subject:
		return fmt.Errorf("key ID sub=%s, but the request's subject is %q", kid.Subject, req.Subject)
	case kid.Request != reqID:
		return fmt.Errorf("key ID req=%s, but the request ID is %s", kid.Request, reqID)
	case kid.Directory != body.DirectoryVersion:
		return fmt.Errorf("key ID dir=%d, but the entry records directory version %d", kid.Directory, body.DirectoryVersion)
	case !slices.Equal(kid.Roles, grant.Roles):
		return fmt.Errorf("key ID roles %q differ from the roles the directory grants %q", kid.Roles, grant.Roles)
	}
	if prev, used := iss.loginIDs[reqID]; used {
		return fmt.Errorf("request ID %s replayed: entry %d already issued a login certificate for it", reqID, prev)
	}
	if prev, used := iss.issueIDs[reqID]; used {
		return fmt.Errorf("request ID %s replayed: issue entry %d already used it", reqID, prev)
	}
	// The signer refuses a CreatedAt more than 300 s from its clock when the
	// request arrives, then reads the serial from that clock (serial.Next,
	// microseconds) and the issuance time right after it. Both must lie
	// within 300 s of CreatedAt, in whole seconds, CreatedAt's unit. The
	// issuance time is recovered from the certificate (ValidAfter is it
	// minus the backdate, rounded down); checkIssue put it between the
	// serial and the entry time. The entry time itself is not compared:
	// appendLocked raises it to the previous leaf's time when the clock
	// went back, so an honest login's entry time can lie far after its
	// issuance. Without the issuance bound, a signer could hold an
	// approval and issue against it later, under a serial taken when it
	// arrived and a raised entry time.
	serialSecs := body.Serial / 1e6
	if d := absDiff(serialSecs, req.CreatedAt); d > maxLoginSkewSeconds {
		return fmt.Errorf("request CreatedAt is %d s from the serial's time (created %d, serial %d s); the signer accepts at most %d s",
			d, req.CreatedAt, serialSecs, maxLoginSkewSeconds)
	}
	issuedSecs := c.ValidAfter + backdateSeconds
	if d := absDiff(issuedSecs, req.CreatedAt); d > maxLoginSkewSeconds {
		return fmt.Errorf("request CreatedAt is %d s from the certificate's issuance time (created %d, issued %d s: ValidAfter + %d s backdate); the signer accepts at most %d s",
			d, req.CreatedAt, issuedSecs, backdateSeconds, maxLoginSkewSeconds)
	}
	iss.loginIDs[reqID] = index
	iss.next(body.Serial)
	return nil
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

func certTypeName(t uint32) string {
	switch t {
	case ssh.UserCert:
		return "user"
	case ssh.HostCert:
		return "host"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// Verify checks an export read from r. Its only trust anchors are the
// pinned root fingerprints in opts; it trusts nothing in the export but
// the leaf bytes and the checkpoint, and only after checking them:
//
//   - strict JSONL: leaf indices exactly 0..n-1, exactly one checkpoint
//     line and it is last; the "decoded" objects are informational, except
//     for the fields the restore runbook reads with grep (03-02,
//     checkGrepFields and checkReplayFields), which must be the leaf's own:
//     "kind" once on every leaf line; "bundle_version" once on every
//     bundle_install line; on a directory_install line, "version" once
//     where present, and "directory" and "sigs" once each, both or
//     neither, as the standard base64 of its document and signatures; and
//     none of the last four on a line of another kind
//   - every leaf decodes, records its own index, and leaf times never
//     decrease
//   - the first bundle_install entry holds a genesis bundle (version 1,
//     all-zero prev) and policy signed by its own root threshold; every
//     later one is a successor of the bundle in force, signed by the
//     previous roots' threshold and its own, whose prev is the SHA-256 of
//     the bundle in force and whose policy is either unchanged or the next
//     policy version chained to the one in force (trust.VerifySuccessor);
//     no policy names a root of that bundle or of any earlier one as an
//     admin; each records its bundle's version, and all of them name the
//     same log key (Phase 1)
//   - the anchor: some bundle in the log has exactly the pinned root set at
//     exactly opts.Threshold (trust.MatchPins), and the first such bundle
//     is reported as Report.AnchorVersion. The pinned roots' signatures
//     over the anchor cover its prev hash, so every earlier bundle (and,
//     through policy_sha256, its policy) is authenticated by the prev-hash
//     chain back to the genesis bundle, and every later bundle by
//     VerifySuccessor. A log in which no bundle matches the pins is
//     refused. Pins of a root set that is exposed still anchor any chain
//     that root set signed, so after rotating away from exposed roots,
//     auditors pin the new roots
//   - every issue leaf comes after the first bundle_install and holds a
//     certificate whose CA signature verifies over its signed bytes
//     (expired certificates included), signed by the active CA of the
//     leaf's role in the bundle in force, of the role's type (host
//     certificates for the host CA only), whose key ID and leaf carry the
//     policy version in force, whose serial equals the leaf's and the key
//     ID's, which stays within the role's profile of the policy in force
//     (validity cap, extensions, critical options, principals, subject
//     key; cert.CheckIssued), whose serial is not after the leaf time and
//     whose ValidAfter is what cert.Build sets for an issuance between the
//     two (both microsecond times: the serial is allocated from the
//     signer's clock), so a postdated or backdated certificate is refused,
//     and serials strictly increase across the log, in one sequence with
//     the login_issue entries'
//   - every directory_install entry holds a directory that parses, is the
//     successor of the directory installed before it (version + 1, prev =
//     its SHA-256; version 1 with the all-zero prev first), is signed by at
//     least the admin quorum of the policy in force and fits that policy's
//     user CA profile, and records that policy's version and its own
//   - every login_issue entry is re-proven from the log (KEY-02): its
//     logged request bytes parse canonically, it records the policy and
//     directory in force, and that directory is authorized under that
//     policy (re-checked after each bundle_install); it carries exactly one
//     webauthn-assertion/v1 item that verifies against the credential the
//     directory binds to the request's active user, under the policy's
//     WebAuthn RP and origins, with challenge = SHA-256 of the logged
//     request bytes; the request's principals equal the directory's grant
//     for its roles, its TTL is within the role and user CA caps, and its
//     extensions are granted; the certificate passes the issue-entry checks
//     for the user CA, is for the request's subject key with exactly its
//     principals, spans what cert.Build gives the requested TTL, carries
//     exactly the profile defaults and the requested extensions and no
//     critical option, and its kr2 key ID names the request's subject,
//     request ID, the policy and directory versions, the granted roles and
//     the serial; its request ID was used by no earlier issue or
//     login_issue entry; and its CreatedAt is within 300 s, in whole
//     seconds, of both the serial's time and the certificate's issuance
//     time (ValidAfter + the 300 s backdate, which the issue-entry checks
//     put between the serial and the entry time). The entry time itself
//     is not compared with CreatedAt: the signer raises it to the previous
//     leaf's time after a clock step back
//   - the RFC 6962 root recomputed from the leaf bytes alone equals the
//     root of the checkpoint, the checkpoint covers exactly n entries, and
//     it is signed by the log key of the root-signed bundle
//   - with opts.Previous, the log neither shrank nor rewrote the entries
//     that checkpoint covered
//
// Login issuances are re-proven from the log, as above: a signer holding
// the CA key and the log key cannot log a login certificate that passes
// unless the user's bound passkey approved exactly the logged request.
// Admin issuances (issue entries, kind 1) are still not: an issue leaf
// records the admin evidence (SSHSIG signatures over the request's
// signing bytes) but only a SHA-256 digest of the request, so neither the
// signatures nor the admin quorum of the policy in force, nor that the
// certificate is the one the admins approved, can be verified from the
// log: a signer holding the CA key can log an unauthorized admin issuance
// with any evidence and the log still verifies. Without opts.Previous it
// cannot detect a log rolled back to an earlier prefix either. A leaf kind
// this version has no check for is refused, never skipped.
func Verify(r io.Reader, opts Options) (*Report, error) {
	if len(opts.Pins) == 0 {
		return nil, errors.New("audit: no pinned root fingerprints")
	}
	if err := trust.CheckPins(opts.Pins, opts.Threshold); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	rep := &Report{Counts: map[tlog.Kind]uint64{}, IssuedByCA: map[string]int{}}
	tree := tlog.NewLog()
	var (
		trustState anchor
		dirState   directoryInForce
		hashes     [][]byte
		checkpoint []byte
		lineNo     int
		lastTime   uint64
	)
	iss := issuance{issueIDs: map[string]uint64{}, loginIDs: map[string]uint64{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)
	for sc.Scan() {
		lineNo++
		line, err := parseLine(sc.Bytes())
		if err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", lineNo, err)
		}
		isCheckpoint := line.Checkpoint != ""
		if checkpoint != nil {
			if isCheckpoint {
				return nil, fmt.Errorf("audit: line %d: more than one checkpoint line", lineNo)
			}
			return nil, fmt.Errorf("audit: line %d: the checkpoint line is not last", lineNo)
		}
		if isCheckpoint {
			checkpoint = []byte(line.Checkpoint)
			continue
		}
		want := tree.Size()
		switch {
		case *line.Index < want:
			return nil, fmt.Errorf("audit: line %d: index %d repeated or out of order (want %d)", lineNo, *line.Index, want)
		case *line.Index > want:
			return nil, fmt.Errorf("audit: line %d: index %d out of order, or entries %d..%d missing", lineNo, *line.Index, want, *line.Index-1)
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(line.Leaf)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != line.Leaf {
			return nil, fmt.Errorf("audit: line %d: leaf is not canonical base64", lineNo)
		}
		leaf, err := tlog.DecodeLeaf(raw)
		if err != nil {
			return nil, fmt.Errorf("audit: entry %d: %w", want, err)
		}
		if leaf.Index != want {
			return nil, fmt.Errorf("audit: entry %d: leaf records index %d", want, leaf.Index)
		}
		if leaf.TimeMicros < lastTime {
			return nil, fmt.Errorf("audit: entry %d: leaf time goes back (%d after %d)", want, leaf.TimeMicros, lastTime)
		}
		lastTime = leaf.TimeMicros
		if err := checkReplayFields(sc.Bytes(), leaf); err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", lineNo, err)
		}
		if err := checkGrepFields(sc.Bytes(), leaf); err != nil {
			return nil, fmt.Errorf("audit: line %d: %w", lineNo, err)
		}
		switch leaf.Kind {
		case tlog.KindBundleInstall:
			body, err := tlog.DecodeBundleInstallBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			if err := trustState.install(body, opts); err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			// The policy in force may have changed: re-check the directory
			// in force under it, once, for every later login_issue entry.
			dirState.recheck(trustState.policy)
		case tlog.KindIssue:
			body, err := tlog.DecodeIssueBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			c, kid, err := checkIssue(body, iss.lastSerial, iss.seen)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			if kid.Roles != nil {
				// The admin path issues kr1 key IDs; kr2 is the login
				// path's, which an issue leaf must not pass itself off as.
				return nil, fmt.Errorf("audit: entry %d: an issue entry must carry a kr1 key ID, not kr2", want)
			}
			if err := trustState.checkIssue(body, c, kid, leaf.TimeMicros); err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			if prev, used := iss.loginIDs[kid.Request]; used {
				return nil, fmt.Errorf("audit: entry %d: request ID %s replayed: login_issue entry %d already used it", want, kid.Request, prev)
			}
			if _, used := iss.issueIDs[kid.Request]; !used {
				iss.issueIDs[kid.Request] = want
			}
			iss.next(body.Serial)
			rep.Serials++
			rep.IssuedByCA[kid.CA]++
		case tlog.KindDirectoryInstall:
			body, err := tlog.DecodeDirectoryInstallBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d (%s): %w", want, leaf.Kind, err)
			}
			if err := dirState.install(body, &trustState); err != nil {
				return nil, fmt.Errorf("audit: entry %d (%s): %w", want, leaf.Kind, err)
			}
		case tlog.KindLoginIssue:
			body, err := tlog.DecodeLoginIssueBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d (%s): %w", want, leaf.Kind, err)
			}
			if err := verifyLoginIssue(want, body, leaf.TimeMicros, &trustState, &dirState, &iss); err != nil {
				return nil, fmt.Errorf("audit: entry %d (%s): %w", want, leaf.Kind, err)
			}
		case tlog.KindRefusalSummary:
			body, err := tlog.DecodeRefusalSummaryBody(leaf.Body)
			if err != nil {
				return nil, fmt.Errorf("audit: entry %d: %w", want, err)
			}
			rep.SummarizedRefusals += body.Total()
		case tlog.KindRefusal, tlog.KindClockRegression, tlog.KindCAInit:
			// No check beyond the strict decode DecodeLeaf already did.
		default:
			// A kind this version has no check for is refused before it is
			// hashed or counted, never skipped. Since plan 02-04 every kind
			// tlog.DecodeLeaf accepts has a case above, so no leaf reaches
			// this branch and no test exercises it: UNVERIFIED in this
			// version. It is kept as the guard that makes a kind added to
			// tlog later fail closed until audit verify has a check for it.
			return nil, fmt.Errorf("audit: entry %d (%s): not verifiable by this version", want, leaf.Kind)
		}
		hash := tlog.HashLeaf(raw)
		if err := tree.Append(hash); err != nil {
			return nil, fmt.Errorf("audit: entry %d: %w", want, err)
		}
		hashes = append(hashes, hash)
		rep.Counts[leaf.Kind]++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("audit: read export: %w", err)
	}
	if checkpoint == nil {
		return nil, errors.New("audit: empty log: the export has no checkpoint line")
	}
	if tree.Size() == 0 {
		return nil, errors.New("audit: empty log: the export has no entries")
	}
	if trustState.logKey == nil {
		return nil, errors.New("audit: the export has no bundle_install entry, so no root-signed log key")
	}
	if trustState.anchorVersion == 0 {
		return nil, fmt.Errorf("audit: bundle_install is not anchored in the pinned roots: no trust bundle in the log has exactly the pinned root set at threshold %d (%w)",
			opts.Threshold, trustState.lastMismatch)
	}
	verifier, err := tlog.NewNoteVerifier(tlog.Origin(trustState.logKey), trustState.logKey)
	if err != nil {
		return nil, fmt.Errorf("audit: log key: %w", err)
	}
	cp, err := tlog.OpenCheckpoint(checkpoint, verifier)
	if err != nil {
		return nil, fmt.Errorf("audit: checkpoint: %w", err)
	}
	if cp.Size != tree.Size() {
		return nil, fmt.Errorf("audit: the checkpoint covers %d entries, the export has %d", cp.Size, tree.Size())
	}
	root, err := tree.Root()
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	if !bytes.Equal(root, cp.Root) {
		return nil, errors.New("audit: root mismatch: the entries do not reproduce the signed checkpoint")
	}
	if opts.Previous != nil {
		prev, err := tlog.OpenCheckpoint(opts.Previous, verifier)
		if err != nil {
			return nil, fmt.Errorf("audit: previous checkpoint: %w", err)
		}
		if prev.Size > cp.Size {
			return nil, fmt.Errorf("audit: log shrank: the previous checkpoint covers %d entries, this log has %d", prev.Size, cp.Size)
		}
		old, err := tlog.FromHashes(hashes[:prev.Size])
		if err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		oldRoot, err := old.Root()
		if err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		if !bytes.Equal(oldRoot, prev.Root) {
			return nil, fmt.Errorf("audit: log rewritten: the first %d entries do not reproduce the previous checkpoint", prev.Size)
		}
	}
	rep.Size, rep.Root = cp.Size, root
	rep.BundleVersion, rep.PolicyVersion, rep.LogKey = trustState.bundle.Version, trustState.policy.Version, trustState.logKey
	rep.AnchorVersion = trustState.anchorVersion
	return rep, nil
}

// checkIssue re-verifies the certificate of one issue leaf and returns it
// with its parsed key ID. It does not use ssh.CertChecker, so certificates
// that have since expired still verify.
func checkIssue(b *tlog.IssueBody, prevSerial uint64, havePrev bool) (*ssh.Certificate, cert.KeyID, error) {
	var none cert.KeyID
	pk, err := ssh.ParsePublicKey(b.Cert)
	if err != nil {
		return nil, none, fmt.Errorf("certificate does not parse: %w", err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		return nil, none, errors.New("the logged key is not a certificate")
	}
	if !bytes.Equal(c.Marshal(), b.Cert) {
		return nil, none, errors.New("certificate encoding is not canonical")
	}
	if _, isCert := c.SignatureKey.(*ssh.Certificate); isCert {
		return nil, none, errors.New("the CA key of the certificate is itself a certificate")
	}
	if err := cert.CheckCAKey(c.SignatureKey); err != nil {
		return nil, none, fmt.Errorf("certificate signed by an unusable CA key: %w", err)
	}
	if c.Signature == nil {
		return nil, none, errors.New("certificate has no CA signature")
	}
	if err := c.SignatureKey.Verify(signedBytes(c), c.Signature); err != nil {
		return nil, none, fmt.Errorf("CA signature does not verify: %w", err)
	}
	if c.Serial != b.Serial {
		return nil, none, fmt.Errorf("leaf serial %d differs from the certificate serial %d", b.Serial, c.Serial)
	}
	if havePrev && b.Serial <= prevSerial {
		return nil, none, fmt.Errorf("serials not strictly increasing: %d after %d", b.Serial, prevSerial)
	}
	if b.KeyID != c.KeyId {
		return nil, none, errors.New("leaf key ID differs from the certificate key ID")
	}
	kid, err := cert.ParseKeyID(c.KeyId)
	if err != nil {
		return nil, none, fmt.Errorf("certificate key ID: %w", err)
	}
	if kid.Serial != c.Serial {
		return nil, none, fmt.Errorf("key ID serial %d differs from the certificate serial %d", kid.Serial, c.Serial)
	}
	if role := wire.CARole(b.CARole).String(); kid.CA != role {
		return nil, none, fmt.Errorf("key ID CA %q differs from the leaf's CA role %q", kid.CA, role)
	}
	return c, kid, nil
}

// signedBytes returns the bytes the CA signed: the certificate encoding
// without its final signature field (PROTOCOL.certkeys).
func signedBytes(c *ssh.Certificate) []byte {
	c2 := *c
	c2.Signature = nil
	out := c2.Marshal()
	return out[:len(out)-4] // drop the empty signature's length prefix
}

// checkReplayFields checks the "directory" and "sigs" fields of an export
// line's text, which a restore writes back as a proposal with grep
// (03-02, signer-install.md step 3). A line whose text carries either key
// must be a directory_install entry, and each key must occur exactly
// once, followed by the standard base64 of the leaf's own document or
// signatures; so the bytes the runbook extracts are the verified leaf's.
// A line without them, as exports before 03-02 wrote, is not checked, and
// the line's other decoded fields stay informational.
func checkReplayFields(text []byte, leaf tlog.Leaf) error {
	const keyDir, keySigs = `"directory":`, `"sigs":`
	s := string(text)
	if !strings.Contains(s, keyDir) && !strings.Contains(s, keySigs) {
		return nil
	}
	refuse := errors.New("its directory or sigs field is not the document and signatures of its directory_install leaf")
	if leaf.Kind != tlog.KindDirectoryInstall {
		return refuse
	}
	body, err := tlog.DecodeDirectoryInstallBody(leaf.Body)
	if err != nil {
		return err
	}
	for _, f := range []struct {
		key string
		val []byte
	}{{keyDir, body.Directory}, {keySigs, body.Sigs}} {
		if strings.Count(s, f.key) != 1 || !strings.Contains(s, f.key+`"`+base64.StdEncoding.EncodeToString(f.val)+`"`) {
			return refuse
		}
	}
	return nil
}

// checkGrepFields checks the other decoded fields that the restore
// runbook reads from an export line's text with grep, to count, list and
// pick entries (03-02, signer-install.md steps 2 and 3): "kind" on every
// leaf line, "bundle_version" on every bundle_install line, and "version"
// on a directory_install line that carries it (exports written before
// plan 02-12 do not). Each must occur exactly once on such a line,
// followed by the leaf's own value, and a bundle_version or version key
// on a line of another kind is refused; so a line that grep counts, lists
// or picks is the verified leaf it says it is. Export has written each
// key this way since it was added: kind and bundle_version since Phase 1.
func checkGrepFields(text []byte, leaf tlog.Leaf) error {
	s := string(text)
	if strings.Count(s, `"kind":`) != 1 || !strings.Contains(s, `"kind":"`+leaf.Kind.String()+`"`) {
		return fmt.Errorf("its decoded kind is not the kind of its leaf (%s)", leaf.Kind)
	}
	var (
		key      string // the version key of this leaf's kind, if any
		val      uint64
		required bool
	)
	switch leaf.Kind {
	case tlog.KindBundleInstall:
		body, err := tlog.DecodeBundleInstallBody(leaf.Body)
		if err != nil {
			return err
		}
		key, val, required = "bundle_version", body.BundleVersion, true
	case tlog.KindDirectoryInstall:
		body, err := tlog.DecodeDirectoryInstallBody(leaf.Body)
		if err != nil {
			return err
		}
		key, val = "version", body.Version
	}
	for _, k := range []string{"bundle_version", "version"} {
		quoted := `"` + k + `":`
		n := strings.Count(s, quoted)
		if n == 0 && (k != key || !required) {
			continue
		}
		v := quoted + strconv.FormatUint(val, 10)
		if k != key || n != 1 || !strings.Contains(s, v+",") && !strings.Contains(s, v+"}") {
			return fmt.Errorf("its decoded %s field is not the one of its %s leaf", k, leaf.Kind)
		}
	}
	return nil
}

// parseLine decodes one line strictly: unknown fields, trailing data and
// lines that are neither a leaf line nor a checkpoint line are refused.
func parseLine(b []byte) (*ExportLine, error) {
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("empty line")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var l ExportLine
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("not a valid export line: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON object")
	}
	switch {
	case l.Checkpoint != "" && l.Index == nil && l.Leaf == "" && l.Decoded == nil:
	case l.Checkpoint == "" && l.Index != nil && l.Leaf != "":
	default:
		return nil, errors.New("neither a leaf line nor a checkpoint line")
	}
	return &l, nil
}
