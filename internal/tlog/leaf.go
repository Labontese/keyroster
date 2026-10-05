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

// Leaf kinds. The set is complete for format v1; plan 01-07 emits CAInit
// and BundleInstall.
const (
	KindIssue           Kind = 1
	KindRefusal         Kind = 2
	KindRefusalSummary  Kind = 3
	KindClockRegression Kind = 4
	KindCAInit          Kind = 5
	KindBundleInstall   Kind = 6
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
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

func (k Kind) valid() bool { return k >= KindIssue && k <= KindBundleInstall }

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
	maxReason                       = ReasonOverloaded
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
