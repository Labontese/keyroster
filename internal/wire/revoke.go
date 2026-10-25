package wire

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

// RevokeRequestDomain separates the signing bytes of a RevokeRequest from
// every other signed format (REVOKE-01).
const RevokeRequestDomain = "keyroster/revoke-request/v1"

// RevokeSSHSIGNamespace is the SSHSIG namespace of the admin-sshsig/v1
// evidence on a RevokeRequest. It equals RevokeRequestDomain, so an
// issuance approval can never authorize a revocation and the reverse.
const RevokeSSHSIGNamespace = RevokeRequestDomain

// Revocation targets. A request names exactly one; the parsers refuse
// every other value.
const (
	// TargetSerial revokes the certificate with Serial issued by CARole.
	TargetSerial uint8 = 1
	// TargetKeyID revokes every certificate with KeyID under each CA key
	// of CARole (KRL subsection 0x23).
	TargetKeyID uint8 = 2
	// TargetKey revokes the public key Key: the plain key and every
	// certificate for it (KRL section 2).
	TargetKey uint8 = 3
	// TargetSubject revokes every unexpired certificate the signer issued
	// to Subject under SubjectKind's CA.
	TargetSubject uint8 = 4
)

// SubjectKind names the kind of subject a TargetSubject request revokes.
// It decodes user, host and machine; the signer refuses a kind it does not
// resolve yet (subject_kind_unsupported).
type SubjectKind uint8

// Subject kinds, one per CA role.
const (
	SubjectUser    SubjectKind = 1
	SubjectHost    SubjectKind = 2
	SubjectMachine SubjectKind = 3
)

// String returns the kind's name.
func (k SubjectKind) String() string {
	switch k {
	case SubjectUser:
		return "user"
	case SubjectHost:
		return "host"
	case SubjectMachine:
		return "machine"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(k))
	}
}

func (k SubjectKind) valid() bool { return k >= SubjectUser && k <= SubjectMachine }

// MaxRevokeReason bounds a RevokeRequest's Reason (printable ASCII).
const MaxRevokeReason = 256

// MaxRevokeKeyID bounds a RevokeRequest's KeyID (printable ASCII): the
// certificate key ID limit.
const MaxRevokeKeyID = 1024

// MaxRevokeAnswerSerials bounds the serials a RevokeResponse lists, so the
// answer stays inside MaxFrame.
const MaxRevokeAnswerSerials = 4096

// subjectRE is the subject grammar of a certificate key ID (internal/cert
// KeyID). A subject never contains "/", so it names exactly the key IDs
// whose sub field it equals.
var subjectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._@:+-]{0,63}$`)

// MaxRequestSkewSeconds is the signer's freshness window: it refuses an
// issue, login or revoke request whose CreatedAt is further than this
// from its clock (request_time_skew). A client may rely on it to bound
// when the signer decided on its request.
const MaxRequestSkewSeconds = 300

// Size bounds of a published KRL on the wire, equal to krl.MaxKRL,
// krl.MaxManifest and krl.MaxManifestSig (wire does not import krl; a test
// in internal/krl asserts the equality).
const (
	MaxKRLBytes       = 4 << 20
	maxKRLManifest    = 4 << 10
	maxKRLManifestSig = 16 << 10
)

// MaxKRLFrame is the largest frame length of a GetKRLResponse: a KRL of
// MaxKRLBytes plus 64 KiB for the manifest, its signature, the three
// length prefixes and the header.
const MaxKRLFrame = MaxKRLBytes + 64<<10

// RevokeRequest asks the signer to revoke. Each target carries exactly its
// own fields, the others zero: TargetSerial CARole and Serial, TargetKeyID
// CARole and KeyID (1 to 1024 bytes of printable ASCII), TargetKey Key (a
// plain public key in canonical SSH wire encoding, never a certificate),
// TargetSubject SubjectKind and Subject (the key ID subject grammar).
// CreatedAt is the client's clock in Unix seconds. Evidence
// (admin-sshsig/v1 by one policy admin, over SigningBytes under
// RevokeSSHSIGNamespace) is not part of the signing bytes.
type RevokeRequest struct {
	Target      uint8
	CARole      CARole
	Serial      uint64
	KeyID       string
	Key         []byte
	SubjectKind SubjectKind
	Subject     string
	RequestID   [16]byte
	CreatedAt   uint64
	Reason      string
	Evidence    []Evidence
}

// Validate checks the request: a known target carrying exactly its own
// fields, each within its limits, and the reason and evidence limits.
// Marshal and both parsers apply it, and the signer applies it to every
// request it decides on.
func (r *RevokeRequest) Validate() error {
	if err := r.checkTarget(); err != nil {
		return err
	}
	switch {
	case len(r.Reason) > MaxRevokeReason:
		return fmt.Errorf("%w: reason too long", ErrMalformed)
	case len(r.Evidence) > MaxEvidence:
		return fmt.Errorf("%w: too many evidence items", ErrMalformed)
	case !printable(r.Reason):
		return fmt.Errorf("%w: reason must be printable ASCII", ErrMalformed)
	}
	for _, e := range r.Evidence {
		if len(e.Type) == 0 || len(e.Type) > MaxEvidenceType || len(e.Blob) > MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformed)
		}
	}
	return nil
}

// checkTarget checks the target and that the request carries exactly the
// target's own fields.
func (r *RevokeRequest) checkTarget() error {
	var role, serial, keyID, key, subject bool // the fields the target carries
	switch r.Target {
	case TargetSerial:
		role, serial = true, true
		if r.Serial == 0 {
			return fmt.Errorf("%w: serial 0", ErrMalformed)
		}
	case TargetKeyID:
		role, keyID = true, true
		if r.KeyID == "" || len(r.KeyID) > MaxRevokeKeyID || !printable(r.KeyID) {
			return fmt.Errorf("%w: a key ID is 1 to %d bytes of printable ASCII", ErrMalformed, MaxRevokeKeyID)
		}
	case TargetKey:
		key = true
		if err := checkRevokeKey(r.Key); err != nil {
			return err
		}
	case TargetSubject:
		subject = true
		if !r.SubjectKind.valid() {
			return fmt.Errorf("%w: unknown subject kind", ErrMalformed)
		}
		if !subjectRE.MatchString(r.Subject) {
			return fmt.Errorf("%w: invalid subject", ErrMalformed)
		}
	default:
		return fmt.Errorf("%w: unknown revocation target", ErrMalformed)
	}
	switch {
	case role && !r.CARole.valid():
		return fmt.Errorf("%w: unknown CA role", ErrMalformed)
	case !role && r.CARole != 0, !serial && r.Serial != 0, !keyID && r.KeyID != "", !key && len(r.Key) != 0,
		!subject && (r.SubjectKind != 0 || r.Subject != ""):
		return fmt.Errorf("%w: a field the revocation target does not carry is set", ErrMalformed)
	}
	return nil
}

// checkRevokeKey requires key to be a plain public key in canonical SSH
// wire encoding: a KRL lists the key's bytes, and sshd compares them with
// the canonical encoding of the key it is offered, so a non-canonical
// encoding would revoke nothing.
func checkRevokeKey(key []byte) error {
	if len(key) == 0 || len(key) > MaxSubjectKeyLen {
		return fmt.Errorf("%w: key size", ErrMalformed)
	}
	pub, err := ssh.ParsePublicKey(key)
	if err != nil {
		return fmt.Errorf("%w: key does not parse", ErrMalformed)
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return fmt.Errorf("%w: the key to revoke is a certificate; revoke its key", ErrMalformed)
	}
	if !bytes.Equal(pub.Marshal(), key) {
		return fmt.Errorf("%w: key encoding is not canonical", ErrMalformed)
	}
	return nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// addFields appends every field except Evidence: Target, then the
// target's own fields (serial: CARole and Serial, the 03-01 layout;
// key_id: CARole and KeyID; key: Key; subject: SubjectKind and Subject),
// then RequestID, CreatedAt and Reason.
func (r *RevokeRequest) addFields(b *cryptobyte.Builder) {
	b.AddUint8(r.Target)
	switch r.Target {
	case TargetSerial:
		b.AddUint8(uint8(r.CARole))
		b.AddUint64(r.Serial)
	case TargetKeyID:
		b.AddUint8(uint8(r.CARole))
		addBytes16(b, []byte(r.KeyID))
	case TargetKey:
		addBytes16(b, r.Key)
	case TargetSubject:
		b.AddUint8(uint8(r.SubjectKind))
		addBytes16(b, []byte(r.Subject))
	}
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
	addBytes16(b, []byte(r.Reason))
}

// readFields reads what addFields writes into r, without validating it.
func (r *RevokeRequest) readFields(s *cryptobyte.String) bool {
	if !s.ReadUint8(&r.Target) {
		return false
	}
	var (
		role, kind uint8
		field      []byte
	)
	switch r.Target {
	case TargetSerial:
		if !s.ReadUint8(&role) || !s.ReadUint64(&r.Serial) {
			return false
		}
	case TargetKeyID:
		if !s.ReadUint8(&role) || !readBytes16(s, &field, MaxRevokeKeyID) {
			return false
		}
		r.KeyID = string(field)
	case TargetKey:
		if !readBytes16(s, &field, MaxSubjectKeyLen) {
			return false
		}
		r.Key = field
	case TargetSubject:
		if !s.ReadUint8(&kind) || !readBytes16(s, &field, MaxSubjectLen) {
			return false
		}
		r.SubjectKind, r.Subject = SubjectKind(kind), string(field)
	default:
		return false
	}
	r.CARole = CARole(role)
	var reqID, reason []byte
	if !s.ReadBytes(&reqID, len(r.RequestID)) || !s.ReadUint64(&r.CreatedAt) || !readBytes16(s, &reason, MaxRevokeReason) {
		return false
	}
	copy(r.RequestID[:], reqID)
	r.Reason = string(reason)
	return true
}

// Marshal encodes the request body. It refuses a request that Validate
// refuses.
func (r *RevokeRequest) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	r.addFields(&b)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, e := range r.Evidence {
			addBytes16(b, []byte(e.Type))
			addBytes16(b, e.Blob)
		}
	})
	return b.Bytes()
}

// SigningBytes returns the domain tag RevokeRequestDomain, as raw bytes,
// followed by every field except Evidence. A revoke leaf logs exactly
// these bytes, and ParseRevokeSigningBytes reads them back.
func (r *RevokeRequest) SigningBytes() []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(RevokeRequestDomain))
	r.addFields(&b)
	// Fails only for a field above 65535 bytes, which Validate refuses.
	out, err := b.Bytes()
	if err != nil {
		return nil
	}
	return out
}

// Digest returns the SHA-256 of SigningBytes.
func (r *RevokeRequest) Digest() [32]byte {
	return sha256.Sum256(r.SigningBytes())
}

// ParseRevokeRequest decodes a request body strictly: every limit is
// enforced, an unknown target or CA role is refused, and trailing bytes
// are refused.
func ParseRevokeRequest(body []byte) (*RevokeRequest, error) {
	s := cryptobyte.String(body)
	var (
		r        RevokeRequest
		evidence cryptobyte.String
	)
	if !r.readFields(&s) || !s.ReadUint16LengthPrefixed(&evidence) || !s.Empty() {
		return nil, ErrMalformed
	}
	for !evidence.Empty() {
		if len(r.Evidence) == MaxEvidence {
			return nil, fmt.Errorf("%w: too many evidence items", ErrMalformed)
		}
		var typ, blob []byte
		if !readBytes16(&evidence, &typ, MaxEvidenceType) || !readBytes16(&evidence, &blob, MaxEvidenceBlob) {
			return nil, ErrMalformed
		}
		r.Evidence = append(r.Evidence, Evidence{Type: string(typ), Blob: blob})
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// ParseRevokeSigningBytes decodes the signing bytes of a request, which a
// revoke leaf logs as its request (tlog.RevokeBody.Request), strictly: the
// raw domain tag first, then the layout of the request's target, the
// limits of ParseRevokeRequest, an unknown target or CA role refused and
// trailing bytes refused. The result carries no evidence, and its
// SigningBytes equal b.
func ParseRevokeSigningBytes(b []byte) (*RevokeRequest, error) {
	rest, ok := bytes.CutPrefix(b, []byte(RevokeRequestDomain))
	if !ok {
		return nil, fmt.Errorf("%w: not the signing bytes of a revoke request", ErrMalformed)
	}
	s := cryptobyte.String(rest)
	var r RevokeRequest
	if !r.readFields(&s) || !s.Empty() {
		return nil, ErrMalformed
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if !bytes.Equal(r.SigningBytes(), b) {
		return nil, fmt.Errorf("%w: the signing bytes do not re-encode identically", ErrMalformed)
	}
	return &r, nil
}

// RevokeResponse reports an accepted revocation: the KRL version published
// with it and the indexes of its revoke and krl_publish log entries
// (RevokeLeaf is the last revoke entry, the one right before PublishLeaf,
// when a subject revocation is split over several). For a subject
// revocation SerialCount is the number of certificates it resolved to and
// Serials the first MaxRevokeAnswerSerials of their serials, ascending;
// both are empty for the other targets. The signer sends it only after
// the transaction holding all its entries committed.
type RevokeResponse struct {
	KRLVersion  uint64
	RevokeLeaf  uint64
	PublishLeaf uint64
	SerialCount uint32
	Serials     []uint64
}

func (r *RevokeResponse) check() error {
	switch {
	case r.KRLVersion == 0:
		return fmt.Errorf("%w: krl version 0", ErrMalformed)
	case len(r.Serials) > MaxRevokeAnswerSerials:
		return fmt.Errorf("%w: a revoke answer lists at most %d serials", ErrMalformed, MaxRevokeAnswerSerials)
	case uint64(len(r.Serials)) != min(uint64(r.SerialCount), MaxRevokeAnswerSerials):
		return fmt.Errorf("%w: a revoke answer lists min(SerialCount, %d) serials", ErrMalformed, MaxRevokeAnswerSerials)
	}
	for i := 1; i < len(r.Serials); i++ {
		if r.Serials[i] <= r.Serials[i-1] {
			return fmt.Errorf("%w: the answer's serials must be ascending and unique", ErrMalformed)
		}
	}
	return nil
}

// Marshal encodes the response body.
func (r *RevokeResponse) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint64(r.KRLVersion)
	b.AddUint64(r.RevokeLeaf)
	b.AddUint64(r.PublishLeaf)
	b.AddUint32(r.SerialCount)
	b.AddUint16(uint16(len(r.Serials))) //nolint:gosec // G115: at most MaxRevokeAnswerSerials, checked above
	for _, s := range r.Serials {
		b.AddUint64(s)
	}
	return b.Bytes()
}

// ParseRevokeResponse decodes a response body strictly: more than
// MaxRevokeAnswerSerials serials, a list whose length is not
// min(SerialCount, MaxRevokeAnswerSerials) (a count below the list
// included), unsorted or duplicated serials and trailing bytes are
// refused.
func ParseRevokeResponse(body []byte) (*RevokeResponse, error) {
	s := cryptobyte.String(body)
	var (
		r RevokeResponse
		n uint16
	)
	if !s.ReadUint64(&r.KRLVersion) || !s.ReadUint64(&r.RevokeLeaf) || !s.ReadUint64(&r.PublishLeaf) ||
		!s.ReadUint32(&r.SerialCount) || !s.ReadUint16(&n) || n > MaxRevokeAnswerSerials {
		return nil, ErrMalformed
	}
	for range n {
		var v uint64
		if !s.ReadUint64(&v) {
			return nil, ErrMalformed
		}
		r.Serials = append(r.Serials, v)
	}
	if !s.Empty() {
		return nil, ErrMalformed
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}

// GetKRLResponse carries the published KRL, its canonical manifest and the
// manifest's detached SSHSIG by the ops key. All three are empty when no
// KRL is published yet, and all three are set otherwise.
type GetKRLResponse struct {
	KRL      []byte
	Manifest []byte
	Sig      []byte
}

func (r *GetKRLResponse) check() error {
	empty := len(r.KRL) == 0 && len(r.Manifest) == 0 && len(r.Sig) == 0
	full := len(r.KRL) > 0 && len(r.Manifest) > 0 && len(r.Sig) > 0
	switch {
	case !empty && !full:
		return fmt.Errorf("%w: a KRL response carries all of KRL, manifest and signature, or none", ErrMalformed)
	case len(r.KRL) > MaxKRLBytes || len(r.Manifest) > maxKRLManifest || len(r.Sig) > maxKRLManifestSig:
		return fmt.Errorf("%w: KRL response size", ErrMalformed)
	}
	return nil
}

// Marshal encodes the response body.
func (r *GetKRLResponse) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r.KRL) })
	addBytes16(&b, r.Manifest)
	addBytes16(&b, r.Sig)
	return b.Bytes()
}

// ParseGetKRLResponse decodes a response body strictly.
func ParseGetKRLResponse(body []byte) (*GetKRLResponse, error) {
	s := cryptobyte.String(body)
	var (
		r   GetKRLResponse
		n   uint32
		krl []byte
	)
	// cryptobyte has no uint32-prefixed reader: read the length, bound it,
	// then the bytes.
	if !s.ReadUint32(&n) || n > MaxKRLBytes || !s.ReadBytes(&krl, int(n)) ||
		!readBytes16(&s, &r.Manifest, maxKRLManifest) || !readBytes16(&s, &r.Sig, maxKRLManifestSig) || !s.Empty() {
		return nil, ErrMalformed
	}
	if len(krl) > 0 {
		r.KRL = append([]byte(nil), krl...)
	}
	if len(r.Manifest) == 0 {
		r.Manifest = nil
	}
	if len(r.Sig) == 0 {
		r.Sig = nil
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}
