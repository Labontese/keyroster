package wire

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// RevokeRequestDomain separates the signing bytes of a RevokeRequest from
// every other signed format (REVOKE-01).
const RevokeRequestDomain = "keyroster/revoke-request/v1"

// RevokeSSHSIGNamespace is the SSHSIG namespace of the admin-sshsig/v1
// evidence on a RevokeRequest. It equals RevokeRequestDomain, so an
// issuance approval can never authorize a revocation and the reverse.
const RevokeSSHSIGNamespace = RevokeRequestDomain

// Revocation targets. This version knows the serial target only; the
// parser refuses every other value.
const (
	TargetSerial uint8 = 1
)

// MaxRevokeReason bounds a RevokeRequest's Reason (printable ASCII).
const MaxRevokeReason = 256

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

// RevokeRequest asks the signer to revoke. For TargetSerial it names the
// certificate by its serial and the CA role that issued it. CreatedAt is
// the client's clock in Unix seconds. Evidence (admin-sshsig/v1 by one
// policy admin, over SigningBytes under RevokeSSHSIGNamespace) is not
// part of the signing bytes.
type RevokeRequest struct {
	Target    uint8
	CARole    CARole
	Serial    uint64
	RequestID [16]byte
	CreatedAt uint64
	Reason    string
	Evidence  []Evidence
}

func (r *RevokeRequest) check() error {
	switch {
	case r.Target != TargetSerial:
		return fmt.Errorf("%w: unknown revocation target", ErrMalformed)
	case !r.CARole.valid():
		return fmt.Errorf("%w: unknown CA role", ErrMalformed)
	case r.Serial == 0:
		return fmt.Errorf("%w: serial 0", ErrMalformed)
	case len(r.Reason) > MaxRevokeReason:
		return fmt.Errorf("%w: reason too long", ErrMalformed)
	case len(r.Evidence) > MaxEvidence:
		return fmt.Errorf("%w: too many evidence items", ErrMalformed)
	}
	for i := 0; i < len(r.Reason); i++ {
		if c := r.Reason[i]; c < 0x20 || c > 0x7e {
			return fmt.Errorf("%w: reason must be printable ASCII", ErrMalformed)
		}
	}
	for _, e := range r.Evidence {
		if len(e.Type) == 0 || len(e.Type) > MaxEvidenceType || len(e.Blob) > MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformed)
		}
	}
	return nil
}

// addFields appends every field except Evidence.
func (r *RevokeRequest) addFields(b *cryptobyte.Builder) {
	b.AddUint8(r.Target)
	b.AddUint8(uint8(r.CARole))
	b.AddUint64(r.Serial)
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
	addBytes16(b, []byte(r.Reason))
}

// Marshal encodes the request body. It refuses a request that violates the
// field limits.
func (r *RevokeRequest) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
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
// followed by every field except Evidence.
func (r *RevokeRequest) SigningBytes() []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(RevokeRequestDomain))
	r.addFields(&b)
	// Fails only for a Reason above 65535 bytes, which check refuses.
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
		role     uint8
		reqID    []byte
		reason   []byte
		evidence cryptobyte.String
	)
	if !s.ReadUint8(&r.Target) || !s.ReadUint8(&role) || !s.ReadUint64(&r.Serial) ||
		!s.ReadBytes(&reqID, len(r.RequestID)) || !s.ReadUint64(&r.CreatedAt) ||
		!readBytes16(&s, &reason, MaxRevokeReason) || !s.ReadUint16LengthPrefixed(&evidence) || !s.Empty() {
		return nil, ErrMalformed
	}
	r.CARole = CARole(role)
	copy(r.RequestID[:], reqID)
	r.Reason = string(reason)
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
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}

// RevokeResponse reports an accepted revocation: the KRL version published
// with it and the indexes of its revoke and krl_publish log entries. The
// signer sends it only after the transaction holding both committed.
type RevokeResponse struct {
	KRLVersion  uint64
	RevokeLeaf  uint64
	PublishLeaf uint64
}

// Marshal encodes the response body.
func (r *RevokeResponse) Marshal() ([]byte, error) {
	if r.KRLVersion == 0 {
		return nil, fmt.Errorf("%w: krl version 0", ErrMalformed)
	}
	var b cryptobyte.Builder
	b.AddUint64(r.KRLVersion)
	b.AddUint64(r.RevokeLeaf)
	b.AddUint64(r.PublishLeaf)
	return b.Bytes()
}

// ParseRevokeResponse decodes a response body strictly.
func ParseRevokeResponse(body []byte) (*RevokeResponse, error) {
	s := cryptobyte.String(body)
	var r RevokeResponse
	if !s.ReadUint64(&r.KRLVersion) || !s.ReadUint64(&r.RevokeLeaf) || !s.ReadUint64(&r.PublishLeaf) ||
		!s.Empty() || r.KRLVersion == 0 {
		return nil, ErrMalformed
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
