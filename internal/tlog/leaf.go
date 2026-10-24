// Package tlog is keyroster's tamper-evident audit log format: leaf
// encoding, the RFC 6962 Merkle tree state (github.com/transparency-dev/merkle,
// D-15) and C2SP checkpoints signed with golang.org/x/mod/sumdb/note.
//
// Every leaf is self-describing and domain-separated:
//
//	uint8-length-prefixed "keyroster/log-leaf/v1"
//	uint64 index        position in the log, 0-based
//	uint64 time         microseconds since the Unix epoch
//	uint8  kind
//	uint24-length-prefixed body (kind-specific, see the *Body types)
//
// Decoding is strict: unknown kinds, short or trailing bytes and bodies
// that do not decode canonically are refused, so decode-then-encode
// reproduces the input exactly.
package tlog

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/Labontese/keyroster/internal/wire"
)

// LeafDomain is the domain tag at the start of every leaf (v1).
const LeafDomain = "keyroster/log-leaf/v1"

// ErrMalformedLeaf reports leaf bytes that do not decode strictly.
var ErrMalformedLeaf = errors.New("tlog: malformed leaf")

// Kind is the type of a leaf.
type Kind uint8

// Leaf kinds of format v1. Kinds 1 to 6 are Phase 1's (plan 01-07 emits
// CAInit and BundleInstall). Kinds 7 and 8 joined format v1 in Phase 2:
// DirectoryInstall records an admin-signed directory the signer installed,
// LoginIssue a certificate issued on a passkey login. Kinds 9 and 10 joined
// format v1 in Phase 3: Revoke records an admin-authorized revocation and
// the entries it resolved to, KRLPublish a KRL version the signer published
// with its ops-key-signed manifest. A reader that has no check for a kind
// must refuse it, never skip it (audit verify does).
const (
	KindIssue            Kind = 1
	KindRefusal          Kind = 2
	KindRefusalSummary   Kind = 3
	KindClockRegression  Kind = 4
	KindCAInit           Kind = 5
	KindBundleInstall    Kind = 6
	KindDirectoryInstall Kind = 7
	KindLoginIssue       Kind = 8
	KindRevoke           Kind = 9
	KindKRLPublish       Kind = 10
)

// String returns the kind name used in exports and reports.
func (k Kind) String() string {
	switch k {
	case KindIssue:
		return "issue"
	case KindRefusal:
		return "refusal"
	case KindRefusalSummary:
		return "refusal_summary"
	case KindClockRegression:
		return "clock_regression"
	case KindCAInit:
		return "ca_init"
	case KindBundleInstall:
		return "bundle_install"
	case KindDirectoryInstall:
		return "directory_install"
	case KindLoginIssue:
		return "login_issue"
	case KindRevoke:
		return "revoke"
	case KindKRLPublish:
		return "krl_publish"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

func (k Kind) valid() bool { return k >= KindIssue && k <= KindKRLPublish }

// Size limits enforced by the encoders and the strict decoders.
const (
	maxBody        = 1<<24 - 1
	MaxDetail      = 256
	MaxKeyID       = 1024
	MaxCert        = 64 << 10
	MaxCAInitKeys  = 16
	maxCAInitField = 8 << 10
	MaxDocument    = 1 << 20
	maxCounts      = 256
	MaxSigs        = 64 << 10
	MaxRequest     = 64 << 10
	// MaxRevokedEntries bounds the entries one revoke leaf records.
	MaxRevokedEntries = 4096
	// MaxManifest and MaxManifestSig bound a krl_publish leaf's manifest
	// and its armored signature (equal to krl.MaxManifest and
	// krl.MaxManifestSig, which a test in internal/krl asserts).
	MaxManifest    = 4 << 10
	MaxManifestSig = 16 << 10
)

// Leaf is one log entry.
type Leaf struct {
	Index      uint64
	TimeMicros uint64
	Kind       Kind
	Body       []byte
}

// EncodeLeaf encodes l. It returns nil for an unknown kind or an oversize
// body; MarshalLeaf reports why.
func EncodeLeaf(l Leaf) []byte {
	out, err := MarshalLeaf(l)
	if err != nil {
		return nil
	}
	return out
}

// MarshalLeaf encodes l and reports an invalid kind or an oversize body.
func MarshalLeaf(l Leaf) ([]byte, error) {
	if !l.Kind.valid() {
		return nil, fmt.Errorf("%w: unknown kind %d", ErrMalformedLeaf, l.Kind)
	}
	if len(l.Body) > maxBody {
		return nil, fmt.Errorf("%w: body too large", ErrMalformedLeaf)
	}
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(LeafDomain)) })
	b.AddUint64(l.Index)
	b.AddUint64(l.TimeMicros)
	b.AddUint8(uint8(l.Kind))
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(l.Body) })
	return b.Bytes()
}

// DecodeLeaf decodes a leaf strictly, including its kind-specific body.
func DecodeLeaf(data []byte) (Leaf, error) {
	s := cryptobyte.String(data)
	var (
		l    Leaf
		tag  cryptobyte.String
		kind uint8
		body cryptobyte.String
	)
	if !s.ReadUint8LengthPrefixed(&tag) || string(tag) != LeafDomain ||
		!s.ReadUint64(&l.Index) || !s.ReadUint64(&l.TimeMicros) ||
		!s.ReadUint8(&kind) || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() {
		return Leaf{}, ErrMalformedLeaf
	}
	l.Kind = Kind(kind)
	l.Body = append([]byte(nil), body...)
	if err := checkBody(l.Kind, l.Body); err != nil {
		return Leaf{}, err
	}
	return l, nil
}

// checkBody decodes body as kind's body type.
func checkBody(k Kind, body []byte) error {
	var err error
	switch k {
	case KindIssue:
		_, err = DecodeIssueBody(body)
	case KindRefusal:
		_, err = DecodeRefusalBody(body)
	case KindRefusalSummary:
		_, err = DecodeRefusalSummaryBody(body)
	case KindClockRegression:
		_, err = DecodeClockRegressionBody(body)
	case KindCAInit:
		_, err = DecodeCAInitBody(body)
	case KindBundleInstall:
		_, err = DecodeBundleInstallBody(body)
	case KindDirectoryInstall:
		_, err = DecodeDirectoryInstallBody(body)
	case KindLoginIssue:
		_, err = DecodeLoginIssueBody(body)
	case KindRevoke:
		_, err = DecodeRevokeBody(body)
	case KindKRLPublish:
		_, err = DecodeKRLPublishBody(body)
	default:
		err = fmt.Errorf("%w: unknown kind %d", ErrMalformedLeaf, k)
	}
	return err
}

// IssueBody records one issued certificate: the full signed certificate in
// SSH wire format (so audit verify can re-check its CA signature), the
// request digest, the evidence presented and the policy version applied.
type IssueBody struct {
	CARole        uint8 // wire.CARole
	Serial        uint64
	PolicyVersion uint64
	RequestDigest [32]byte
	Evidence      []wire.Evidence
	Cert          []byte
	KeyID         string
}

// Encode encodes the body.
func (b *IssueBody) Encode() ([]byte, error) {
	if len(b.Evidence) > wire.MaxEvidence || len(b.Cert) == 0 || len(b.Cert) > MaxCert ||
		len(b.KeyID) == 0 || len(b.KeyID) > MaxKeyID {
		return nil, fmt.Errorf("%w: issue body size", ErrMalformedLeaf)
	}
	for _, e := range b.Evidence {
		if len(e.Type) == 0 || len(e.Type) > wire.MaxEvidenceType || len(e.Blob) > wire.MaxEvidenceBlob {
			return nil, fmt.Errorf("%w: evidence size", ErrMalformedLeaf)
		}
	}
	var c cryptobyte.Builder
	c.AddUint8(b.CARole)
	c.AddUint64(b.Serial)
	c.AddUint64(b.PolicyVersion)
	c.AddBytes(b.RequestDigest[:])
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, e := range b.Evidence {
			add16(c, []byte(e.Type))
			add16(c, e.Blob)
		}
	})
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.Cert) })
	add16(&c, []byte(b.KeyID))
	return c.Bytes()
}

// DecodeIssueBody decodes an issue body strictly.
func DecodeIssueBody(data []byte) (*IssueBody, error) {
	s := cryptobyte.String(data)
	var (
		b        IssueBody
		digest   []byte
		evidence cryptobyte.String
		certB    cryptobyte.String
		keyID    []byte
	)
	if !s.ReadUint8(&b.CARole) || !s.ReadUint64(&b.Serial) || !s.ReadUint64(&b.PolicyVersion) ||
		!s.ReadBytes(&digest, 32) || !s.ReadUint24LengthPrefixed(&evidence) ||
		!s.ReadUint24LengthPrefixed(&certB) || !read16(&s, &keyID, MaxKeyID) || !s.Empty() {
		return nil, ErrMalformedLeaf
	}
	copy(b.RequestDigest[:], digest)
	for !evidence.Empty() {
		if len(b.Evidence) == wire.MaxEvidence {
			return nil, fmt.Errorf("%w: too many evidence items", ErrMalformedLeaf)
		}
		var typ, blob []byte
		if !read16(&evidence, &typ, wire.MaxEvidenceType) || len(typ) == 0 ||
			!read16(&evidence, &blob, wire.MaxEvidenceBlob) {
			return nil, ErrMalformedLeaf
		}
		b.Evidence = append(b.Evidence, wire.Evidence{Type: string(typ), Blob: blob})
	}
	if len(certB) == 0 || len(certB) > MaxCert || len(keyID) == 0 {
		return nil, ErrMalformedLeaf
	}
	b.Cert = append([]byte(nil), certB...)
	b.KeyID = string(keyID)
	return &b, nil
}

// PeerUnknown is the PeerUID recorded when the kernel did not report the
// peer's credentials ((uid_t)-1, "no user" on Linux).
const PeerUnknown = ^uint32(0)

// Refusal reason codes (D-14). The code names the class of the refusal; the
// refusal leaf's Detail carries the signer's specific reason string.
const (
	ReasonPeerNotAllowed      uint8 = 1
	ReasonMalformed           uint8 = 2
	ReasonCANotConfigured     uint8 = 3
	ReasonBadPrincipal        uint8 = 4
	ReasonBadSubjectKey       uint8 = 5
	ReasonTTLExceeded         uint8 = 6
	ReasonStaleRequest        uint8 = 7
	ReasonDuplicateRequest    uint8 = 8
	ReasonClockRegression     uint8 = 9
	ReasonBadSubject          uint8 = 10
	ReasonExtensionNotAllowed uint8 = 11
	ReasonUnavailable         uint8 = 12
	ReasonInternal            uint8 = 13
	ReasonOverloaded          uint8 = 14
	ReasonUnauthorized        uint8 = 15
	maxReason                       = ReasonUnauthorized
)

var reasonNames = [...]string{
	ReasonPeerNotAllowed:      "peer_not_allowed",
	ReasonMalformed:           "malformed",
	ReasonCANotConfigured:     "ca_not_configured",
	ReasonBadPrincipal:        "bad_principal",
	ReasonBadSubjectKey:       "bad_subject_key",
	ReasonTTLExceeded:         "ttl_exceeded",
	ReasonStaleRequest:        "stale_request",
	ReasonDuplicateRequest:    "duplicate_request",
	ReasonClockRegression:     "clock_regression",
	ReasonBadSubject:          "bad_subject",
	ReasonExtensionNotAllowed: "extension_not_allowed",
	ReasonUnavailable:         "unavailable",
	ReasonInternal:            "internal",
	ReasonOverloaded:          "overloaded",
	ReasonUnauthorized:        "unauthorized",
}

// ReasonName returns the name of a refusal reason code.
func ReasonName(r uint8) string {
	if r == 0 || r > maxReason {
		return fmt.Sprintf("unknown(%d)", r)
	}
	return reasonNames[r]
}

// ValidReason reports whether r is a defined reason code.
func ValidReason(r uint8) bool { return r >= 1 && r <= maxReason }

// RefusalBody records one refused request. RequestDigest is zero when the
// request was never decoded (peer-credential and framing refusals).
type RefusalBody struct {
	RequestDigest [32]byte
	PeerUID       uint32
	Reason        uint8
	Detail        string
}

// Encode encodes the body.
func (b *RefusalBody) Encode() ([]byte, error) {
	if !ValidReason(b.Reason) || len(b.Detail) > MaxDetail {
		return nil, fmt.Errorf("%w: refusal body", ErrMalformedLeaf)
	}
	var c cryptobyte.Builder
	c.AddBytes(b.RequestDigest[:])
	c.AddUint32(b.PeerUID)
	c.AddUint8(b.Reason)
	add16(&c, []byte(b.Detail))
	return c.Bytes()
}

// DecodeRefusalBody decodes a refusal body strictly.
func DecodeRefusalBody(data []byte) (*RefusalBody, error) {
	s := cryptobyte.String(data)
	var (
		b      RefusalBody
		digest []byte
		detail []byte
	)
	if !s.ReadBytes(&digest, 32) || !s.ReadUint32(&b.PeerUID) || !s.ReadUint8(&b.Reason) ||
		!read16(&s, &detail, MaxDetail) || !s.Empty() || !ValidReason(b.Reason) {
		return nil, ErrMalformedLeaf
	}
	copy(b.RequestDigest[:], digest)
	b.Detail = string(detail)
	return &b, nil
}

// ReasonCount is the number of suppressed refusals with one reason.
type ReasonCount struct {
	Reason uint8
	Count  uint64
}

// RefusalSummaryBody counts the refusals of one window that were not
// logged individually. Counts are ordered by strictly increasing reason and
// every count is above zero, so the encoding is canonical.
type RefusalSummaryBody struct {
	WindowStartMicros uint64
	WindowEndMicros   uint64
	Counts            []ReasonCount
}

// Total returns the sum of all counts.
func (b *RefusalSummaryBody) Total() uint64 {
	var n uint64
	for _, c := range b.Counts {
		n += c.Count
	}
	return n
}

func (b *RefusalSummaryBody) check() error {
	if b.WindowEndMicros < b.WindowStartMicros || len(b.Counts) == 0 || len(b.Counts) > maxCounts {
		return fmt.Errorf("%w: refusal summary", ErrMalformedLeaf)
	}
	var prev uint8
	for _, c := range b.Counts {
		if !ValidReason(c.Reason) || c.Reason <= prev || c.Count == 0 {
			return fmt.Errorf("%w: refusal summary counts", ErrMalformedLeaf)
		}
		prev = c.Reason
	}
	return nil
}

// Encode encodes the body.
func (b *RefusalSummaryBody) Encode() ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	var c cryptobyte.Builder
	c.AddUint64(b.WindowStartMicros)
	c.AddUint64(b.WindowEndMicros)
	c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, rc := range b.Counts {
			c.AddUint8(rc.Reason)
			c.AddUint64(rc.Count)
		}
	})
	return c.Bytes()
}

// DecodeRefusalSummaryBody decodes a refusal summary body strictly.
func DecodeRefusalSummaryBody(data []byte) (*RefusalSummaryBody, error) {
	s := cryptobyte.String(data)
	var (
		b      RefusalSummaryBody
		counts cryptobyte.String
	)
	if !s.ReadUint64(&b.WindowStartMicros) || !s.ReadUint64(&b.WindowEndMicros) ||
		!s.ReadUint16LengthPrefixed(&counts) || !s.Empty() {
		return nil, ErrMalformedLeaf
	}
	for !counts.Empty() {
		if len(b.Counts) == maxCounts {
			return nil, ErrMalformedLeaf
		}
		var rc ReasonCount
		if !counts.ReadUint8(&rc.Reason) || !counts.ReadUint64(&rc.Count) {
			return nil, ErrMalformedLeaf
		}
		b.Counts = append(b.Counts, rc)
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// ClockRegressionBody records the start of a clock-regression episode: the
// wall clock read below the serial high-water mark (CA-03).
type ClockRegressionBody struct {
	NowMicros       uint64
	HighWaterMicros uint64
}

// Encode encodes the body.
func (b *ClockRegressionBody) Encode() ([]byte, error) {
	var c cryptobyte.Builder
	c.AddUint64(b.NowMicros)
	c.AddUint64(b.HighWaterMicros)
	return c.Bytes()
}

// DecodeClockRegressionBody decodes a clock-regression body strictly.
func DecodeClockRegressionBody(data []byte) (*ClockRegressionBody, error) {
	s := cryptobyte.String(data)
	var b ClockRegressionBody
	if !s.ReadUint64(&b.NowMicros) || !s.ReadUint64(&b.HighWaterMicros) || !s.Empty() {
		return nil, ErrMalformedLeaf
	}
	return &b, nil
}

// CAInitKey is one key created or adopted at CA initialization.
type CAInitKey struct {
	Role      string
	PublicKey []byte // SSH wire format
	Alg       string
	Custody   string
}

// CAInitBody records the keys of a CA initialization (emitted by 01-07).
type CAInitBody struct {
	Keys []CAInitKey
}

// Encode encodes the body.
func (b *CAInitBody) Encode() ([]byte, error) {
	if len(b.Keys) == 0 || len(b.Keys) > MaxCAInitKeys {
		return nil, fmt.Errorf("%w: ca_init keys", ErrMalformedLeaf)
	}
	for _, k := range b.Keys {
		if k.Role == "" || len(k.PublicKey) == 0 || k.Alg == "" || k.Custody == "" ||
			len(k.Role) > maxCAInitField || len(k.PublicKey) > maxCAInitField ||
			len(k.Alg) > maxCAInitField || len(k.Custody) > maxCAInitField {
			return nil, fmt.Errorf("%w: ca_init key fields", ErrMalformedLeaf)
		}
	}
	var c cryptobyte.Builder
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, k := range b.Keys {
			add16(c, []byte(k.Role))
			add16(c, k.PublicKey)
			add16(c, []byte(k.Alg))
			add16(c, []byte(k.Custody))
		}
	})
	return c.Bytes()
}

// DecodeCAInitBody decodes a CA-init body strictly.
func DecodeCAInitBody(data []byte) (*CAInitBody, error) {
	s := cryptobyte.String(data)
	var (
		b    CAInitBody
		keys cryptobyte.String
	)
	if !s.ReadUint24LengthPrefixed(&keys) || !s.Empty() {
		return nil, ErrMalformedLeaf
	}
	for !keys.Empty() {
		if len(b.Keys) == MaxCAInitKeys {
			return nil, ErrMalformedLeaf
		}
		var role, pub, alg, custody []byte
		if !read16(&keys, &role, maxCAInitField) || !read16(&keys, &pub, maxCAInitField) ||
			!read16(&keys, &alg, maxCAInitField) || !read16(&keys, &custody, maxCAInitField) ||
			len(role) == 0 || len(pub) == 0 || len(alg) == 0 || len(custody) == 0 {
			return nil, ErrMalformedLeaf
		}
		b.Keys = append(b.Keys, CAInitKey{Role: string(role), PublicKey: pub, Alg: string(alg), Custody: string(custody)})
	}
	if len(b.Keys) == 0 {
		return nil, ErrMalformedLeaf
	}
	return &b, nil
}

// BundleInstallBody records an installed trust bundle and policy with
// their full documents and signatures, so an export is self-contained for a
// root-anchored verification (emitted by 01-07, verified by 01-08).
type BundleInstallBody struct {
	BundleVersion uint64
	Bundle        []byte
	BundleSigs    []byte
	Policy        []byte
	PolicySigs    []byte
}

// Encode encodes the body.
func (b *BundleInstallBody) Encode() ([]byte, error) {
	for _, d := range [][]byte{b.Bundle, b.BundleSigs, b.Policy, b.PolicySigs} {
		if len(d) == 0 || len(d) > MaxDocument {
			return nil, fmt.Errorf("%w: bundle_install document size", ErrMalformedLeaf)
		}
	}
	var c cryptobyte.Builder
	c.AddUint64(b.BundleVersion)
	for _, d := range [][]byte{b.Bundle, b.BundleSigs, b.Policy, b.PolicySigs} {
		c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(d) })
	}
	return c.Bytes()
}

// DecodeBundleInstallBody decodes a bundle-install body strictly.
func DecodeBundleInstallBody(data []byte) (*BundleInstallBody, error) {
	s := cryptobyte.String(data)
	var b BundleInstallBody
	if !s.ReadUint64(&b.BundleVersion) {
		return nil, ErrMalformedLeaf
	}
	for _, out := range []*[]byte{&b.Bundle, &b.BundleSigs, &b.Policy, &b.PolicySigs} {
		var d cryptobyte.String
		if !s.ReadUint24LengthPrefixed(&d) || len(d) == 0 || len(d) > MaxDocument {
			return nil, ErrMalformedLeaf
		}
		*out = append([]byte(nil), d...)
	}
	if !s.Empty() {
		return nil, ErrMalformedLeaf
	}
	return &b, nil
}

// DirectoryInstallBody records an admin-signed directory version the
// signer installed (kind 7): its version, the policy version it was
// verified under, its canonical bytes (at most MaxDocument) and the admins'
// SSHSIG signatures (at most MaxSigs), so an export is self-contained for
// re-verifying the directory chain and its quorum.
type DirectoryInstallBody struct {
	Version       uint64
	PolicyVersion uint64
	Directory     []byte
	Sigs          []byte
}

func (b *DirectoryInstallBody) check() error {
	if len(b.Directory) == 0 || len(b.Directory) > MaxDocument || len(b.Sigs) == 0 || len(b.Sigs) > MaxSigs {
		return fmt.Errorf("%w: directory_install document size", ErrMalformedLeaf)
	}
	return nil
}

// Encode encodes the body.
func (b *DirectoryInstallBody) Encode() ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	var c cryptobyte.Builder
	c.AddUint64(b.Version)
	c.AddUint64(b.PolicyVersion)
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.Directory) })
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.Sigs) })
	return c.Bytes()
}

// DecodeDirectoryInstallBody decodes a directory-install body strictly.
// Every error wraps ErrMalformedLeaf.
func DecodeDirectoryInstallBody(data []byte) (*DirectoryInstallBody, error) {
	s := cryptobyte.String(data)
	var (
		b         DirectoryInstallBody
		doc, sigs cryptobyte.String
	)
	if !s.ReadUint64(&b.Version) || !s.ReadUint64(&b.PolicyVersion) ||
		!s.ReadUint24LengthPrefixed(&doc) || !s.ReadUint24LengthPrefixed(&sigs) || !s.Empty() {
		return nil, ErrMalformedLeaf
	}
	b.Directory = append([]byte(nil), doc...)
	b.Sigs = append([]byte(nil), sigs...)
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// LoginIssueBody records one certificate issued on a passkey login (kind
// 8): the serial, the policy and directory versions the signer authorized
// it under, the login request's full signing bytes (at most MaxRequest),
// the evidence presented (the WebAuthn assertion over SHA-256 of those
// bytes), the full certificate and its key ID. With the request bytes, an
// auditor can re-check that the user's bound credential approved exactly
// this request.
type LoginIssueBody struct {
	Serial           uint64
	PolicyVersion    uint64
	DirectoryVersion uint64
	Request          []byte
	Evidence         []wire.Evidence
	Cert             []byte
	KeyID            string
}

func (b *LoginIssueBody) check() error {
	if len(b.Request) == 0 || len(b.Request) > MaxRequest || len(b.Evidence) > wire.MaxEvidence ||
		len(b.Cert) == 0 || len(b.Cert) > MaxCert || len(b.KeyID) == 0 || len(b.KeyID) > MaxKeyID {
		return fmt.Errorf("%w: login_issue body size", ErrMalformedLeaf)
	}
	for _, e := range b.Evidence {
		if len(e.Type) == 0 || len(e.Type) > wire.MaxEvidenceType || len(e.Blob) > wire.MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformedLeaf)
		}
	}
	return nil
}

// Encode encodes the body.
func (b *LoginIssueBody) Encode() ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	var c cryptobyte.Builder
	c.AddUint64(b.Serial)
	c.AddUint64(b.PolicyVersion)
	c.AddUint64(b.DirectoryVersion)
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.Request) })
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, e := range b.Evidence {
			add16(c, []byte(e.Type))
			add16(c, e.Blob)
		}
	})
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.Cert) })
	add16(&c, []byte(b.KeyID))
	return c.Bytes()
}

// DecodeLoginIssueBody decodes a login-issue body strictly. Every error
// wraps ErrMalformedLeaf.
func DecodeLoginIssueBody(data []byte) (*LoginIssueBody, error) {
	s := cryptobyte.String(data)
	var (
		b        LoginIssueBody
		request  cryptobyte.String
		evidence cryptobyte.String
		certB    cryptobyte.String
		keyID    []byte
	)
	if !s.ReadUint64(&b.Serial) || !s.ReadUint64(&b.PolicyVersion) || !s.ReadUint64(&b.DirectoryVersion) ||
		!s.ReadUint24LengthPrefixed(&request) || !s.ReadUint24LengthPrefixed(&evidence) ||
		!s.ReadUint24LengthPrefixed(&certB) || !read16(&s, &keyID, MaxKeyID) || !s.Empty() {
		return nil, ErrMalformedLeaf
	}
	for !evidence.Empty() {
		if len(b.Evidence) == wire.MaxEvidence {
			return nil, fmt.Errorf("%w: too many evidence items", ErrMalformedLeaf)
		}
		var typ, blob []byte
		if !read16(&evidence, &typ, wire.MaxEvidenceType) || len(typ) == 0 ||
			!read16(&evidence, &blob, wire.MaxEvidenceBlob) {
			return nil, ErrMalformedLeaf
		}
		b.Evidence = append(b.Evidence, wire.Evidence{Type: string(typ), Blob: blob})
	}
	b.Request = append([]byte(nil), request...)
	b.Cert = append([]byte(nil), certB...)
	b.KeyID = string(keyID)
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// Revoked entry kinds of a RevokedEntry: a certificate serial under a CA
// key, a key ID, or a public key. The 03-01 tracer writes serial entries
// only; the other two arrive with 03-03.
const (
	RevokedSerial uint8 = 1
	RevokedKeyID  uint8 = 2
	RevokedKey    uint8 = 3
)

// RevokedEntry is one entry a revocation resolved to: for RevokedSerial
// the CA key (SSH wire format) and the serial, for RevokedKeyID the key
// ID, for RevokedKey the public key (SSH wire format). ValidBeforeSeconds
// is the revoked certificate's valid_before, 0 when not known.
type RevokedEntry struct {
	Kind               uint8
	CAKey              []byte
	Serial             uint64
	KeyID              string
	Key                []byte
	ValidBeforeSeconds uint64
}

func (e *RevokedEntry) check() error {
	switch {
	case e.Kind < RevokedSerial || e.Kind > RevokedKey:
		return fmt.Errorf("%w: revoked entry kind", ErrMalformedLeaf)
	case len(e.CAKey) > wire.MaxSubjectKeyLen || len(e.Key) > wire.MaxSubjectKeyLen || len(e.KeyID) > MaxKeyID:
		return fmt.Errorf("%w: revoked entry size", ErrMalformedLeaf)
	case e.Kind == RevokedSerial && (len(e.CAKey) == 0 || e.Serial == 0):
		return fmt.Errorf("%w: a serial entry needs a CA key and a serial above 0", ErrMalformedLeaf)
	case e.Kind == RevokedSerial && (e.KeyID != "" || len(e.Key) != 0):
		// Exact, so no reader can take a serial entry for a key ID or key
		// revocation. The rules for the key_id and key kinds come with
		// 03-03, which first writes them.
		return fmt.Errorf("%w: a serial entry carries no key ID and no key", ErrMalformedLeaf)
	}
	return nil
}

// RevokeBody records one accepted revocation (kind 9): the policy version
// its admin evidence was verified under, the time the signer resolved the
// request (ResolvedAtSeconds, whole seconds; times 10^6 never above the
// leaf's TimeMicros, which appendLocked may only raise), the request's
// full signing bytes (at most MaxRequest), the evidence presented and the
// entries the request resolved to (possibly none).
type RevokeBody struct {
	PolicyVersion     uint64
	ResolvedAtSeconds uint64
	Request           []byte
	Evidence          []wire.Evidence
	Entries           []RevokedEntry
}

func (b *RevokeBody) check() error {
	if len(b.Request) == 0 || len(b.Request) > MaxRequest || len(b.Evidence) > wire.MaxEvidence ||
		len(b.Entries) > MaxRevokedEntries {
		return fmt.Errorf("%w: revoke body size", ErrMalformedLeaf)
	}
	for _, e := range b.Evidence {
		if len(e.Type) == 0 || len(e.Type) > wire.MaxEvidenceType || len(e.Blob) > wire.MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformedLeaf)
		}
	}
	for i := range b.Entries {
		if err := b.Entries[i].check(); err != nil {
			return err
		}
	}
	return nil
}

// Encode encodes the body.
func (b *RevokeBody) Encode() ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	var c cryptobyte.Builder
	c.AddUint64(b.PolicyVersion)
	c.AddUint64(b.ResolvedAtSeconds)
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.Request) })
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, e := range b.Evidence {
			add16(c, []byte(e.Type))
			add16(c, e.Blob)
		}
	})
	c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) {
		for _, e := range b.Entries {
			c.AddUint8(e.Kind)
			add16(c, e.CAKey)
			c.AddUint64(e.Serial)
			add16(c, []byte(e.KeyID))
			add16(c, e.Key)
			c.AddUint64(e.ValidBeforeSeconds)
		}
	})
	return c.Bytes()
}

// DecodeRevokeBody decodes a revoke body strictly. Every error wraps
// ErrMalformedLeaf.
func DecodeRevokeBody(data []byte) (*RevokeBody, error) {
	s := cryptobyte.String(data)
	var (
		b                          RevokeBody
		request, evidence, entries cryptobyte.String
	)
	if !s.ReadUint64(&b.PolicyVersion) || !s.ReadUint64(&b.ResolvedAtSeconds) ||
		!s.ReadUint24LengthPrefixed(&request) || !s.ReadUint24LengthPrefixed(&evidence) ||
		!s.ReadUint24LengthPrefixed(&entries) || !s.Empty() {
		return nil, ErrMalformedLeaf
	}
	for !evidence.Empty() {
		if len(b.Evidence) == wire.MaxEvidence {
			return nil, fmt.Errorf("%w: too many evidence items", ErrMalformedLeaf)
		}
		var typ, blob []byte
		if !read16(&evidence, &typ, wire.MaxEvidenceType) || len(typ) == 0 ||
			!read16(&evidence, &blob, wire.MaxEvidenceBlob) {
			return nil, ErrMalformedLeaf
		}
		b.Evidence = append(b.Evidence, wire.Evidence{Type: string(typ), Blob: blob})
	}
	for !entries.Empty() {
		if len(b.Entries) == MaxRevokedEntries {
			return nil, fmt.Errorf("%w: too many revoked entries", ErrMalformedLeaf)
		}
		var (
			e                 RevokedEntry
			caKey, keyID, key []byte
		)
		if !entries.ReadUint8(&e.Kind) || !read16(&entries, &caKey, wire.MaxSubjectKeyLen) ||
			!entries.ReadUint64(&e.Serial) || !read16(&entries, &keyID, MaxKeyID) ||
			!read16(&entries, &key, wire.MaxSubjectKeyLen) || !entries.ReadUint64(&e.ValidBeforeSeconds) {
			return nil, ErrMalformedLeaf
		}
		// Empty fields decode as nil, so decode-then-encode is exact and a
		// decoded body compares equal to the one that was encoded.
		if len(caKey) > 0 {
			e.CAKey = caKey
		}
		if len(key) > 0 {
			e.Key = key
		}
		e.KeyID = string(keyID)
		b.Entries = append(b.Entries, e)
	}
	b.Request = append([]byte(nil), request...)
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

// KRLPublishBody records one published KRL version (kind 10): its version,
// the trust bundle version in force, the manifest's issued_at in whole
// seconds, the SHA-256 of the KRL bytes, and the canonical manifest with
// its detached SSHSIG by the ops key (namespace keyroster/krl/v1). The KRL
// bytes themselves are not in the leaf; the manifest binds them.
type KRLPublishBody struct {
	KRLVersion      uint64
	BundleVersion   uint64
	IssuedAtSeconds uint64
	SHA256          [32]byte
	Manifest        []byte
	Sig             []byte
}

func (b *KRLPublishBody) check() error {
	if b.KRLVersion == 0 || len(b.Manifest) == 0 || len(b.Manifest) > MaxManifest ||
		len(b.Sig) == 0 || len(b.Sig) > MaxManifestSig {
		return fmt.Errorf("%w: krl_publish body", ErrMalformedLeaf)
	}
	return nil
}

// Encode encodes the body.
func (b *KRLPublishBody) Encode() ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	var c cryptobyte.Builder
	c.AddUint64(b.KRLVersion)
	c.AddUint64(b.BundleVersion)
	c.AddUint64(b.IssuedAtSeconds)
	c.AddBytes(b.SHA256[:])
	add16(&c, b.Manifest)
	add16(&c, b.Sig)
	return c.Bytes()
}

// DecodeKRLPublishBody decodes a krl_publish body strictly. Every error
// wraps ErrMalformedLeaf.
func DecodeKRLPublishBody(data []byte) (*KRLPublishBody, error) {
	s := cryptobyte.String(data)
	var (
		b      KRLPublishBody
		digest []byte
	)
	if !s.ReadUint64(&b.KRLVersion) || !s.ReadUint64(&b.BundleVersion) || !s.ReadUint64(&b.IssuedAtSeconds) ||
		!s.ReadBytes(&digest, 32) || !read16(&s, &b.Manifest, MaxManifest) || !read16(&s, &b.Sig, MaxManifestSig) ||
		!s.Empty() {
		return nil, ErrMalformedLeaf
	}
	copy(b.SHA256[:], digest)
	if err := b.check(); err != nil {
		return nil, err
	}
	return &b, nil
}

func add16(b *cryptobyte.Builder, v []byte) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(v) })
}

// read16 reads a uint16-length-prefixed field of at most limit bytes and
// copies it out of the input.
func read16(s *cryptobyte.String, out *[]byte, limit int) bool {
	var v cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&v) || len(v) > limit {
		return false
	}
	*out = append([]byte(nil), v...)
	return true
}
