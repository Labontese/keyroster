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

// HostIssueRequestDomain separates the signing bytes of a HostIssueRequest
// from every other signed format (03-09): a host agent's request for a
// host certificate for one of its host keys, under its admin-signed
// directory entry's name.
const HostIssueRequestDomain = "keyroster/host-issue-request/v1"

// HostPoPNamespace is the SSHSIG namespace of the host-pop/v1 evidence on
// a HostIssueRequest. It equals HostIssueRequestDomain (the repository's
// convention, and the format registry's rule that a tag is never shared),
// so no other signature by a host key authorizes a host certificate.
const HostPoPNamespace = HostIssueRequestDomain

// EvidenceHostPoP is the evidence type of a HostIssueRequest: an SSHSIG
// (armored) by the requested host key over the request's SigningBytes
// under HostPoPNamespace, the proof of possession of that key.
const EvidenceHostPoP = "host-pop/v1"

// maxHostIssueName bounds the host name as read; Validate then requires
// the host name grammar.
const maxHostIssueName = 64

// hostIssueNameRE is the host name grammar of directory.ValidUserName (a
// test asserts the two agree); wire does not import directory.
var hostIssueNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// HostIssueRequest asks the signer for a host certificate (03-09, D-16):
// for the installation it is for (D5), the directory host entry named
// HostName, and HostKey, one of that entry's listed keys (a plain Ed25519
// or ECDSA key in SSH wire format). ValidForSeconds is always 0, meaning
// the maximum: the signer chooses the lifetime, min(30 days, the host cap
// in force), and refuses any other value (host_issue_valid_for_not_zero,
// Q-09-6); the field stays in the signing bytes. There is no principal
// field: the principals come only from the entry. CreatedAt is the host's
// clock in Unix seconds, and RequestID is fresh for every attempt.
//
// Evidence is exactly one host-pop/v1 item and is not part of the signing
// bytes.
type HostIssueRequest struct {
	InstallationID  string
	HostName        string
	HostKey         []byte
	ValidForSeconds uint32
	RequestID       [16]byte
	CreatedAt       uint64
	Evidence        []Evidence
}

// Validate checks the request: an installation ID of the trust bundle
// form, a host name in the host name grammar, a plain ssh-ed25519 or
// ecdsa-sha2-nistp256/384/521 host key (not a certificate), a non-zero
// RequestID and CreatedAt, and exactly one evidence item within the
// evidence limits. It puts no rule on ValidForSeconds: the signer refuses
// a nonzero value with its own classified detail. Marshal, both parsers
// and the signer apply it.
func (r *HostIssueRequest) Validate() error {
	switch {
	case !trust.IsInstallationID(r.InstallationID):
		return fmt.Errorf("%w: the installation ID is not 32 lowercase hex digits", ErrMalformed)
	case !hostIssueNameRE.MatchString(r.HostName):
		return fmt.Errorf("%w: invalid host name", ErrMalformed)
	case len(r.HostKey) == 0 || len(r.HostKey) > MaxSubjectKeyLen:
		return fmt.Errorf("%w: host key size", ErrMalformed)
	case r.RequestID == [16]byte{}:
		return fmt.Errorf("%w: request ID zero", ErrMalformed)
	case r.CreatedAt == 0:
		return fmt.Errorf("%w: created_at zero", ErrMalformed)
	case len(r.Evidence) != 1:
		return fmt.Errorf("%w: a host issue request carries exactly one evidence item", ErrMalformed)
	}
	pub, err := ssh.ParsePublicKey(r.HostKey)
	if err != nil {
		return fmt.Errorf("%w: host key does not parse", ErrMalformed)
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	default:
		return fmt.Errorf("%w: host key type %q is not a plain Ed25519 or ECDSA key", ErrMalformed, pub.Type())
	}
	if !bytes.Equal(pub.Marshal(), r.HostKey) {
		return fmt.Errorf("%w: host key encoding is not canonical", ErrMalformed)
	}
	for _, e := range r.Evidence {
		if len(e.Type) == 0 || len(e.Type) > MaxEvidenceType || len(e.Blob) > MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformed)
		}
	}
	return nil
}

// addFields appends every field except Evidence, in declaration order:
// the installation ID and host name (uint16 length each), the host key
// (uint16 length), ValidForSeconds (uint32), RequestID (16 bytes) and
// CreatedAt (uint64).
func (r *HostIssueRequest) addFields(b *cryptobyte.Builder) {
	addBytes16(b, []byte(r.InstallationID))
	addBytes16(b, []byte(r.HostName))
	addBytes16(b, r.HostKey)
	b.AddUint32(r.ValidForSeconds)
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
}

// readFields reads what addFields writes into r, without validating it.
func (r *HostIssueRequest) readFields(s *cryptobyte.String) bool {
	var id, name, key, reqID []byte
	if !readBytes16(s, &id, maxRevokeInstallationID) || !readBytes16(s, &name, maxHostIssueName) ||
		!readBytes16(s, &key, MaxSubjectKeyLen) || !s.ReadUint32(&r.ValidForSeconds) ||
		!s.ReadBytes(&reqID, len(r.RequestID)) || !s.ReadUint64(&r.CreatedAt) {
		return false
	}
	r.InstallationID, r.HostName, r.HostKey = string(id), string(name), key
	copy(r.RequestID[:], reqID)
	return true
}

// SigningBytes returns the domain tag (HostIssueRequestDomain), as raw
// bytes, followed by every field except Evidence. A host_issue leaf logs
// exactly these bytes, and ParseHostIssueSigningBytes reads them back.
func (r *HostIssueRequest) SigningBytes() []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(HostIssueRequestDomain))
	r.addFields(&b)
	// Fails only for a field above 65535 bytes, which Validate refuses.
	out, err := b.Bytes()
	if err != nil {
		return nil
	}
	return out
}

// Digest returns the SHA-256 of SigningBytes.
func (r *HostIssueRequest) Digest() [32]byte { return sha256.Sum256(r.SigningBytes()) }

// Marshal encodes the request body: every field but Evidence in the
// layout of SigningBytes (without the domain tag), then the evidence (a
// uint16-length-prefixed list of type and blob, each uint16-length
// prefixed). It refuses a request that Validate refuses.
func (r *HostIssueRequest) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	r.addFields(&b)
	addEvidence(&b, r.Evidence)
	return b.Bytes()
}

// ParseHostIssueRequest decodes a request body strictly: every limit of
// Validate and trailing bytes refused. The result's Marshal equals body.
func ParseHostIssueRequest(body []byte) (*HostIssueRequest, error) {
	s := cryptobyte.String(body)
	var (
		r        HostIssueRequest
		evidence cryptobyte.String
		err      error
	)
	if !r.readFields(&s) || !s.ReadUint16LengthPrefixed(&evidence) || !s.Empty() {
		return nil, ErrMalformed
	}
	if r.Evidence, err = readEvidence(&evidence); err != nil {
		return nil, err
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// ParseHostIssueSigningBytes decodes the signing bytes of a request, which
// a host_issue leaf logs as its request (tlog.HostIssueBody.Request),
// strictly: the raw domain tag first, the field limits, and trailing
// bytes refused. Validate's evidence rule does not apply (signing bytes
// carry none); every other rule does. Its SigningBytes equal b.
func ParseHostIssueSigningBytes(b []byte) (*HostIssueRequest, error) {
	rest, ok := bytes.CutPrefix(b, []byte(HostIssueRequestDomain))
	if !ok {
		return nil, fmt.Errorf("%w: not the signing bytes of a host issue request", ErrMalformed)
	}
	s := cryptobyte.String(rest)
	var r HostIssueRequest
	if !r.readFields(&s) || !s.Empty() {
		return nil, ErrMalformed
	}
	// Validate needs one evidence item; the signing bytes carry none, so a
	// placeholder stands in for the check and is dropped again.
	r.Evidence = []Evidence{{Type: EvidenceHostPoP}}
	err := r.Validate()
	r.Evidence = nil
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.SigningBytes(), b) {
		return nil, fmt.Errorf("%w: the signing bytes do not re-encode identically", ErrMalformed)
	}
	return &r, nil
}
