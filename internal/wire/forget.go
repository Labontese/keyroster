package wire

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// ForgetRequestDomain separates the signing bytes of a ForgetRequest from
// every other signed format (03-08c): a request to forget one enrolled
// agent, which the admins sign and keyroster-signer decides and logs as a
// host_forget entry before keyroster-server deletes the agent.
const ForgetRequestDomain = "keyroster/host-forget-request/v1"

// ForgetSSHSIGNamespace is the SSHSIG namespace of the admin-sshsig/v1
// evidence on a ForgetRequest. It equals ForgetRequestDomain (the
// convention of RevokeRequestDomain), so no issue, revoke or recovery
// signature authorizes a forget and the reverse.
const ForgetSSHSIGNamespace = ForgetRequestDomain

// MaxForgetHostKeys bounds the host key fingerprints of a ForgetRequest:
// directory.MaxHostKeys, the host keys an agent enrolls (wire does not
// import directory; a test asserts the equality).
const MaxForgetHostKeys = 8

// maxForgetName bounds the expected name as read; Validate then requires
// the host name grammar.
const maxForgetName = 64

// forgetNameRE is the host name grammar of directory.ValidUserName (a test
// asserts the two agree).
var forgetNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// HostKeyDigest is the SHA-256 of a host key's SSH wire encoding, the
// digest ssh.FingerprintSHA256 prints in base64. A ForgetRequest names the
// agent's host keys by it, and the server, the signer and audit verify
// compare by it.
func HostKeyDigest(pub ssh.PublicKey) [32]byte { return sha256.Sum256(pub.Marshal()) }

// ForgetRequest asks the signer to authorize and log the forget of one
// enrolled agent (03-08c). It names the installation it is for, the agent
// by the SHA-256 of its TLS identity's SPKI (AgentIdentity), its expected
// name, when it enrolled (EnrolledAtMicros, the server's enrolled_at_us,
// which binds the request to that one enrollment of the identity), its
// enrolled host keys by HostKeyDigest (1 to MaxForgetHostKeys, ascending,
// no digest twice), and the facts the admins saw in keyroster host
// pending: whether the directory approved it once, its removal version
// (0: none), its recorded removal confirmation (ConfirmedVersion 0 and an
// all-zero ConfirmedSHA256: none) and whether the admins override a
// missing or unusable confirmation for a host that is gone for good
// (HostGone). CreatedAt is the client's clock in Unix seconds.
//
// Evidence (admin-sshsig/v1 over SigningBytes under ForgetSSHSIGNamespace)
// and ServerApprovedOnce are not part of the signing bytes:
// ServerApprovedOnce is keyroster-server's own statement of whether its
// row was approved once, which it sets before it relays the request, and
// which the signer compares with the signed ApprovedOnce.
type ForgetRequest struct {
	InstallationID      string
	AgentIdentity       [32]byte
	ExpectedName        string
	EnrolledAtMicros    uint64
	HostKeyFingerprints [][32]byte
	ApprovedOnce        bool
	RemovalVersion      uint64
	ConfirmedVersion    uint64
	ConfirmedSHA256     [32]byte
	HostGone            bool
	RequestID           [16]byte
	CreatedAt           uint64
	Evidence            []Evidence
	ServerApprovedOnce  bool
}

// Validate checks the request: an installation ID of the trust bundle
// form, an expected name in the host name grammar, 1 to MaxForgetHostKeys
// host key digests in ascending order with none twice, a confirmation's
// SHA-256 all zero exactly when it has no version, and the evidence
// limits, and the combinations the admins can have seen:
//   - an agent never approved has no removal version, no confirmation
//     and no HostGone;
//   - an agent approved once has a confirmation, HostGone, or both
//     (HostGone with a confirmation overrides a swap the host has not
//     finished; 03-08c), and a confirmation lies at or above a removal
//     version of at least 1.
//
// Marshal, both parsers and the signer apply it.
func (r *ForgetRequest) Validate() error {
	var zero [32]byte
	switch {
	case !trust.IsInstallationID(r.InstallationID):
		return fmt.Errorf("%w: the installation ID is not 32 lowercase hex digits", ErrMalformed)
	case !forgetNameRE.MatchString(r.ExpectedName):
		return fmt.Errorf("%w: invalid expected name", ErrMalformed)
	case len(r.HostKeyFingerprints) == 0 || len(r.HostKeyFingerprints) > MaxForgetHostKeys:
		return fmt.Errorf("%w: a forget names 1 to %d host keys", ErrMalformed, MaxForgetHostKeys)
	case (r.ConfirmedVersion == 0) != (r.ConfirmedSHA256 == zero):
		return fmt.Errorf("%w: a confirmation has both its version and its SHA-256, or neither", ErrMalformed)
	case !r.ApprovedOnce && (r.RemovalVersion != 0 || r.ConfirmedVersion != 0 || r.HostGone):
		return fmt.Errorf("%w: an agent never approved has no removal, confirmation or host_gone", ErrMalformed)
	case r.ApprovedOnce && r.ConfirmedVersion == 0 && !r.HostGone:
		return fmt.Errorf("%w: an agent approved once is forgotten with its removal confirmation or host_gone", ErrMalformed)
	case r.ConfirmedVersion != 0 && (r.RemovalVersion == 0 || r.ConfirmedVersion < r.RemovalVersion):
		return fmt.Errorf("%w: a confirmation lies at or above a removal version of at least 1", ErrMalformed)
	case len(r.Evidence) > MaxEvidence:
		return fmt.Errorf("%w: too many evidence items", ErrMalformed)
	}
	for i := 1; i < len(r.HostKeyFingerprints); i++ {
		if bytes.Compare(r.HostKeyFingerprints[i-1][:], r.HostKeyFingerprints[i][:]) >= 0 {
			return fmt.Errorf("%w: the host key digests must be ascending with none twice", ErrMalformed)
		}
	}
	for _, e := range r.Evidence {
		if len(e.Type) == 0 || len(e.Type) > MaxEvidenceType || len(e.Blob) > MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformed)
		}
	}
	return nil
}

// addFields appends every field except Evidence and ServerApprovedOnce:
// the installation ID (uint16 length), the identity (32 bytes), the
// expected name (uint16 length), EnrolledAtMicros, the host key digests (a
// count byte, then 32 bytes each), ApprovedOnce (one byte, 0 or 1),
// RemovalVersion, ConfirmedVersion, ConfirmedSHA256 (32 bytes), HostGone
// (one byte), RequestID (16 bytes) and CreatedAt.
func (r *ForgetRequest) addFields(b *cryptobyte.Builder) {
	addBytes16(b, []byte(r.InstallationID))
	b.AddBytes(r.AgentIdentity[:])
	addBytes16(b, []byte(r.ExpectedName))
	b.AddUint64(r.EnrolledAtMicros)
	b.AddUint8(uint8(len(r.HostKeyFingerprints))) //nolint:gosec // G115: at most MaxForgetHostKeys, checked by Validate
	for _, d := range r.HostKeyFingerprints {
		b.AddBytes(d[:])
	}
	addBool(b, r.ApprovedOnce)
	b.AddUint64(r.RemovalVersion)
	b.AddUint64(r.ConfirmedVersion)
	b.AddBytes(r.ConfirmedSHA256[:])
	addBool(b, r.HostGone)
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
}

// readFields reads what addFields writes into r, without validating it;
// a boolean byte other than 0 or 1 does not read.
func (r *ForgetRequest) readFields(s *cryptobyte.String) bool {
	var id, identity, name []byte
	var n uint8
	if !readBytes16(s, &id, maxRevokeInstallationID) || !s.ReadBytes(&identity, len(r.AgentIdentity)) ||
		!readBytes16(s, &name, maxForgetName) || !s.ReadUint64(&r.EnrolledAtMicros) || !s.ReadUint8(&n) || int(n) > MaxForgetHostKeys {
		return false
	}
	r.InstallationID, r.ExpectedName = string(id), string(name)
	copy(r.AgentIdentity[:], identity)
	for range n {
		var d []byte
		if !s.ReadBytes(&d, 32) {
			return false
		}
		r.HostKeyFingerprints = append(r.HostKeyFingerprints, [32]byte(d))
	}
	var sum, reqID []byte
	if !readBool(s, &r.ApprovedOnce) || !s.ReadUint64(&r.RemovalVersion) || !s.ReadUint64(&r.ConfirmedVersion) ||
		!s.ReadBytes(&sum, len(r.ConfirmedSHA256)) || !readBool(s, &r.HostGone) || !s.ReadBytes(&reqID, len(r.RequestID)) ||
		!s.ReadUint64(&r.CreatedAt) {
		return false
	}
	copy(r.ConfirmedSHA256[:], sum)
	copy(r.RequestID[:], reqID)
	return true
}

func addBool(b *cryptobyte.Builder, v bool) {
	if v {
		b.AddUint8(1)
	} else {
		b.AddUint8(0)
	}
}

// readBool reads one byte, 0 or 1; any other value does not read.
func readBool(s *cryptobyte.String, out *bool) bool {
	var v uint8
	if !s.ReadUint8(&v) || v > 1 {
		return false
	}
	*out = v == 1
	return true
}

// SigningBytes returns the domain tag (ForgetRequestDomain), as raw bytes,
// followed by every field except Evidence and ServerApprovedOnce. A
// host_forget leaf logs exactly these bytes, and ParseForgetSigningBytes
// reads them back.
func (r *ForgetRequest) SigningBytes() []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(ForgetRequestDomain))
	r.addFields(&b)
	// Fails only for a field above 65535 bytes, which Validate refuses.
	out, err := b.Bytes()
	if err != nil {
		return nil
	}
	return out
}

// Digest returns the SHA-256 of SigningBytes.
func (r *ForgetRequest) Digest() [32]byte { return sha256.Sum256(r.SigningBytes()) }

// Marshal encodes the request body: every field but Evidence and
// ServerApprovedOnce in the layout of SigningBytes (without the domain
// tag), the evidence (a uint16-length-prefixed list of type and blob, each
// uint16-length prefixed) and one byte ServerApprovedOnce (0 or 1). It
// refuses a request that Validate refuses.
func (r *ForgetRequest) Marshal() ([]byte, error) {
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
	addBool(&b, r.ServerApprovedOnce)
	return b.Bytes()
}

// ParseForgetRequest decodes a request body strictly: every limit of
// Validate, a boolean byte other than 0 or 1 refused, and trailing bytes
// refused. The result's Marshal equals body.
func ParseForgetRequest(body []byte) (*ForgetRequest, error) {
	s := cryptobyte.String(body)
	var (
		r        ForgetRequest
		evidence cryptobyte.String
	)
	if !r.readFields(&s) || !s.ReadUint16LengthPrefixed(&evidence) || !readBool(&s, &r.ServerApprovedOnce) || !s.Empty() {
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

// ParseForgetSigningBytes decodes the signing bytes of a request, which a
// host_forget leaf logs as its request (tlog.HostForgetBody.Request),
// strictly: the raw domain tag first, the limits of ParseForgetRequest and
// trailing bytes refused. The result carries no evidence and
// ServerApprovedOnce false, and its SigningBytes equal b.
func ParseForgetSigningBytes(b []byte) (*ForgetRequest, error) {
	rest, ok := bytes.CutPrefix(b, []byte(ForgetRequestDomain))
	if !ok {
		return nil, fmt.Errorf("%w: not the signing bytes of a forget request", ErrMalformed)
	}
	s := cryptobyte.String(rest)
	var r ForgetRequest
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

// ForgetResponse reports an accepted forget: the index of the host_forget
// log entry that records it. The signer sends it only after the
// transaction holding that entry committed.
type ForgetResponse struct {
	Leaf uint64
}

// Marshal encodes the response body.
func (r *ForgetResponse) Marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint64(r.Leaf)
	return b.Bytes()
}

// ParseForgetResponse decodes a response body strictly: exactly eight
// bytes.
func ParseForgetResponse(body []byte) (*ForgetResponse, error) {
	s := cryptobyte.String(body)
	var r ForgetResponse
	if !s.ReadUint64(&r.Leaf) || !s.Empty() {
		return nil, ErrMalformed
	}
	return &r, nil
}
