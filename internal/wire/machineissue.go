package wire

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// MachineIssueRequestDomain separates the signing bytes of a
// MachineIssueRequest from every other signed format (03-11): the request
// of the holder of a machine key for a machine certificate under its
// admin-signed directory entry's name.
const MachineIssueRequestDomain = "keyroster/machine-issue-request/v1"

// MachinePoPNamespace is the SSHSIG namespace of the machine-pop/v1
// evidence on a MachineIssueRequest. It equals MachineIssueRequestDomain
// (the repository's convention: a tag is never shared), so no other
// signature by a machine key authorizes a machine certificate.
const MachinePoPNamespace = MachineIssueRequestDomain

// EvidenceMachinePoP is the evidence type of a MachineIssueRequest: an
// SSHSIG (armored) by the machine key over the request's SigningBytes
// under MachinePoPNamespace, the proof of possession of that key.
const EvidenceMachinePoP = "machine-pop/v1"

// maxMachineIssueName bounds the machine name as read; Validate then
// requires the directory name grammar (hostIssueNameRE, which a test
// asserts equal to directory.ValidUserName).
const maxMachineIssueName = 64

// MachineIssueRequest asks the signer for a machine certificate (03-11,
// D-15): for the installation it is for (D5), the directory machine entry
// named MachineName, and MachineKey, the key that entry lists (a plain
// Ed25519, ECDSA or sk key in SSH wire format). ValidForSeconds is always
// 0: the signer chooses the lifetime, min(the entry, every role, the
// machine cap in force), and refuses any other value
// (machine_issue_valid_for_not_zero, Q-09-6); the field stays in the
// signing bytes. There is no principal field: the principals come only
// from the entry's roles. CreatedAt is the caller's clock in Unix seconds,
// and RequestID is fresh for every attempt (D6).
//
// Evidence is exactly one machine-pop/v1 item and is not part of the
// signing bytes.
type MachineIssueRequest struct {
	InstallationID  string
	MachineName     string
	MachineKey      []byte
	ValidForSeconds uint32
	RequestID       [16]byte
	CreatedAt       uint64
	Evidence        []Evidence
}

// Validate checks the request: an installation ID of the trust bundle
// form, a machine name in the directory name grammar, a plain
// ssh-ed25519, ecdsa-sha2-nistp256/384/521, sk-ssh-ed25519@openssh.com or
// sk-ecdsa-sha2-nistp256@openssh.com key in canonical encoding (never
// RSA, never a certificate), a non-zero RequestID and CreatedAt, and
// exactly one evidence item within the evidence limits. It puts no rule on
// ValidForSeconds or on whether the key is the listed one: the signer
// refuses those with its own classified details. Marshal, both parsers
// and the signer apply it.
func (r *MachineIssueRequest) Validate() error {
	switch {
	case !trust.IsInstallationID(r.InstallationID):
		return fmt.Errorf("%w: the installation ID is not 32 lowercase hex digits", ErrMalformed)
	case !hostIssueNameRE.MatchString(r.MachineName):
		return fmt.Errorf("%w: invalid machine name", ErrMalformed)
	case len(r.MachineKey) == 0 || len(r.MachineKey) > MaxSubjectKeyLen:
		return fmt.Errorf("%w: machine key size", ErrMalformed)
	case r.RequestID == [16]byte{}:
		return fmt.Errorf("%w: request ID zero", ErrMalformed)
	case r.CreatedAt == 0:
		return fmt.Errorf("%w: created_at zero", ErrMalformed)
	case len(r.Evidence) != 1:
		return fmt.Errorf("%w: a machine issue request carries exactly one evidence item", ErrMalformed)
	}
	pub, err := ssh.ParsePublicKey(r.MachineKey)
	if err != nil {
		return fmt.Errorf("%w: machine key does not parse", ErrMalformed)
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
	default:
		return fmt.Errorf("%w: machine key type %q is not a plain Ed25519, ECDSA or sk key", ErrMalformed, pub.Type())
	}
	if !bytes.Equal(pub.Marshal(), r.MachineKey) {
		return fmt.Errorf("%w: machine key encoding is not canonical", ErrMalformed)
	}
	for _, e := range r.Evidence {
		if len(e.Type) == 0 || len(e.Type) > MaxEvidenceType || len(e.Blob) > MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformed)
		}
	}
	return nil
}

// addFields appends every field except Evidence, in declaration order:
// the installation ID, the machine name and the machine key (uint16
// length each), ValidForSeconds (uint32), RequestID (16 bytes) and
// CreatedAt (uint64).
func (r *MachineIssueRequest) addFields(b *cryptobyte.Builder) {
	addBytes16(b, []byte(r.InstallationID))
	addBytes16(b, []byte(r.MachineName))
	addBytes16(b, r.MachineKey)
	b.AddUint32(r.ValidForSeconds)
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
}

// readFields reads what addFields writes into r, without validating it.
func (r *MachineIssueRequest) readFields(s *cryptobyte.String) bool {
	var id, name, key, reqID []byte
	if !readBytes16(s, &id, maxRevokeInstallationID) || !readBytes16(s, &name, maxMachineIssueName) ||
		!readBytes16(s, &key, MaxSubjectKeyLen) || !s.ReadUint32(&r.ValidForSeconds) ||
		!s.ReadBytes(&reqID, len(r.RequestID)) || !s.ReadUint64(&r.CreatedAt) {
		return false
	}
	r.InstallationID, r.MachineName, r.MachineKey = string(id), string(name), key
	copy(r.RequestID[:], reqID)
	return true
}

// SigningBytes returns the domain tag (MachineIssueRequestDomain), as raw
// bytes, followed by every field except Evidence. A machine_issue leaf
// logs exactly these bytes, and ParseMachineIssueSigningBytes reads them
// back.
func (r *MachineIssueRequest) SigningBytes() []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(MachineIssueRequestDomain))
	r.addFields(&b)
	// Fails only for a field above 65535 bytes, which Validate refuses.
	out, err := b.Bytes()
	if err != nil {
		return nil
	}
	return out
}

// Digest returns the SHA-256 of SigningBytes.
func (r *MachineIssueRequest) Digest() [32]byte { return sha256.Sum256(r.SigningBytes()) }

// Marshal encodes the request body: every field but Evidence in the
// layout of SigningBytes (without the domain tag), then the evidence (a
// uint16-length-prefixed list of type and blob, each uint16-length
// prefixed). It refuses a request that Validate refuses.
func (r *MachineIssueRequest) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	r.addFields(&b)
	addEvidence(&b, r.Evidence)
	return b.Bytes()
}

// ParseMachineIssueRequest decodes a request body strictly: every limit
// of Validate and trailing bytes refused. The result's Marshal equals
// body.
func ParseMachineIssueRequest(body []byte) (*MachineIssueRequest, error) {
	s := cryptobyte.String(body)
	var (
		r        MachineIssueRequest
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

// ParseMachineIssueSigningBytes decodes the signing bytes of a request,
// which a machine_issue leaf logs as its request
// (tlog.MachineIssueBody.Request), strictly: the raw domain tag first,
// the field limits, and trailing bytes refused. Validate's evidence rule
// does not apply (signing bytes carry none); every other rule does. Its
// SigningBytes equal b.
func ParseMachineIssueSigningBytes(b []byte) (*MachineIssueRequest, error) {
	rest, ok := bytes.CutPrefix(b, []byte(MachineIssueRequestDomain))
	if !ok {
		return nil, fmt.Errorf("%w: not the signing bytes of a machine issue request", ErrMalformed)
	}
	s := cryptobyte.String(rest)
	var r MachineIssueRequest
	if !r.readFields(&s) || !s.Empty() {
		return nil, ErrMalformed
	}
	// Validate needs one evidence item; the signing bytes carry none, so a
	// placeholder stands in for the check and is dropped again.
	r.Evidence = []Evidence{{Type: EvidenceMachinePoP}}
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
