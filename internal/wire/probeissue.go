package wire

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// ProbeIssueRequestDomain separates the signing bytes of a
// ProbeIssueRequest from every other signed format (03-10): a host agent's
// request for a probe certificate, a restricted machine-CA user
// certificate for an ephemeral probe key, which the agent uses to prove
// that its own sshd accepts and enforces what it was given.
const ProbeIssueRequestDomain = "keyroster/probe-issue-request/v1"

// ProbePoPNamespace is the SSHSIG namespace of both evidence items of a
// ProbeIssueRequest (03-10). It equals ProbeIssueRequestDomain, so a host
// key's signature made for a host certificate request (HostPoPNamespace)
// never authorizes a probe certificate, and the reverse.
const ProbePoPNamespace = ProbeIssueRequestDomain

// EvidenceProbePoP is the second evidence type of a ProbeIssueRequest: an
// SSHSIG (armored) by the probe key over the request's SigningBytes under
// ProbePoPNamespace, the proof of possession of the probe key (03-10). The
// first item is EvidenceHostPoP by the host key, under the same namespace.
const EvidenceProbePoP = "probe-pop/v1"

// ProbeIssueRequest asks the signer for a probe certificate (03-10, D-06):
// for the installation it is for (D5), the directory host entry named
// HostName, HostKey (one of that entry's listed keys, a plain Ed25519 or
// ECDSA key), and ProbeKey, an ephemeral plain ssh-ed25519 key the agent
// made for this request alone. Negative asks for the negative probe, a
// certificate whose own serial the signer revokes in the same transaction.
// ValidForSeconds must be 0: the signer chooses the lifetime and refuses
// any other value (probe_issue_valid_for_not_zero, Q-09-6); the field
// stays in the signing bytes. CreatedAt is the host's clock in Unix
// seconds, and RequestID is fresh for every attempt (D6).
//
// Evidence is exactly two items, in this order: host-pop/v1 by HostKey,
// then probe-pop/v1 by ProbeKey, both SSHSIGs under ProbePoPNamespace over
// SigningBytes. It is not part of the signing bytes.
type ProbeIssueRequest struct {
	InstallationID  string
	HostName        string
	HostKey         []byte
	ProbeKey        []byte
	Negative        bool
	ValidForSeconds uint32
	RequestID       [16]byte
	CreatedAt       uint64
	Evidence        []Evidence
}

// Validate checks the request: an installation ID of the trust bundle
// form, a host name in the host name grammar, a canonical plain
// ssh-ed25519 or ecdsa-sha2-nistp256/384/521 host key, a canonical plain
// ssh-ed25519 probe key (not a certificate), a non-zero RequestID and
// CreatedAt, and exactly two evidence items within the evidence limits.
// It puts no rule on ValidForSeconds, the evidence types or the relation
// between the keys: the signer refuses those with classified details.
// Marshal, both parsers and the signer apply it.
func (r *ProbeIssueRequest) Validate() error {
	switch {
	case !trust.IsInstallationID(r.InstallationID):
		return fmt.Errorf("%w: the installation ID is not 32 lowercase hex digits", ErrMalformed)
	case !hostIssueNameRE.MatchString(r.HostName):
		return fmt.Errorf("%w: invalid host name", ErrMalformed)
	case len(r.HostKey) == 0 || len(r.HostKey) > MaxSubjectKeyLen:
		return fmt.Errorf("%w: host key size", ErrMalformed)
	case len(r.ProbeKey) == 0 || len(r.ProbeKey) > MaxSubjectKeyLen:
		return fmt.Errorf("%w: probe key size", ErrMalformed)
	case r.RequestID == [16]byte{}:
		return fmt.Errorf("%w: request ID zero", ErrMalformed)
	case r.CreatedAt == 0:
		return fmt.Errorf("%w: created_at zero", ErrMalformed)
	case len(r.Evidence) != 2:
		return fmt.Errorf("%w: a probe issue request carries exactly two evidence items", ErrMalformed)
	}
	host, err := ssh.ParsePublicKey(r.HostKey)
	if err != nil {
		return fmt.Errorf("%w: host key does not parse", ErrMalformed)
	}
	switch host.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
	default:
		return fmt.Errorf("%w: host key type %q is not a plain Ed25519 or ECDSA key", ErrMalformed, host.Type())
	}
	if !bytes.Equal(host.Marshal(), r.HostKey) {
		return fmt.Errorf("%w: host key encoding is not canonical", ErrMalformed)
	}
	probe, err := ssh.ParsePublicKey(r.ProbeKey)
	if err != nil {
		return fmt.Errorf("%w: probe key does not parse", ErrMalformed)
	}
	if probe.Type() != ssh.KeyAlgoED25519 {
		return fmt.Errorf("%w: probe key type %q is not a plain ssh-ed25519 key", ErrMalformed, probe.Type())
	}
	if !bytes.Equal(probe.Marshal(), r.ProbeKey) {
		return fmt.Errorf("%w: probe key encoding is not canonical", ErrMalformed)
	}
	for _, e := range r.Evidence {
		if len(e.Type) == 0 || len(e.Type) > MaxEvidenceType || len(e.Blob) > MaxEvidenceBlob {
			return fmt.Errorf("%w: evidence size", ErrMalformed)
		}
	}
	return nil
}

// addFields appends every field except Evidence, in declaration order:
// the installation ID, host name, host key and probe key (uint16 length
// each), Negative (one byte, 0 or 1), ValidForSeconds (uint32), RequestID
// (16 bytes) and CreatedAt (uint64).
func (r *ProbeIssueRequest) addFields(b *cryptobyte.Builder) {
	addBytes16(b, []byte(r.InstallationID))
	addBytes16(b, []byte(r.HostName))
	addBytes16(b, r.HostKey)
	addBytes16(b, r.ProbeKey)
	var neg uint8
	if r.Negative {
		neg = 1
	}
	b.AddUint8(neg)
	b.AddUint32(r.ValidForSeconds)
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
}

// readFields reads what addFields writes into r, without validating it
// beyond the Negative byte, which must be 0 or 1.
func (r *ProbeIssueRequest) readFields(s *cryptobyte.String) bool {
	var id, name, host, probe, reqID []byte
	var neg uint8
	if !readBytes16(s, &id, maxRevokeInstallationID) || !readBytes16(s, &name, maxHostIssueName) ||
		!readBytes16(s, &host, MaxSubjectKeyLen) || !readBytes16(s, &probe, MaxSubjectKeyLen) ||
		!s.ReadUint8(&neg) || neg > 1 || !s.ReadUint32(&r.ValidForSeconds) ||
		!s.ReadBytes(&reqID, len(r.RequestID)) || !s.ReadUint64(&r.CreatedAt) {
		return false
	}
	r.InstallationID, r.HostName, r.HostKey, r.ProbeKey = string(id), string(name), host, probe
	r.Negative = neg == 1
	copy(r.RequestID[:], reqID)
	return true
}

// SigningBytes returns the domain tag (ProbeIssueRequestDomain), as raw
// bytes, followed by every field except Evidence. A probe_issue leaf logs
// exactly these bytes, and ParseProbeIssueSigningBytes reads them back.
func (r *ProbeIssueRequest) SigningBytes() []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(ProbeIssueRequestDomain))
	r.addFields(&b)
	// Fails only for a field above 65535 bytes, which Validate refuses.
	out, err := b.Bytes()
	if err != nil {
		return nil
	}
	return out
}

// Digest returns the SHA-256 of SigningBytes.
func (r *ProbeIssueRequest) Digest() [32]byte { return sha256.Sum256(r.SigningBytes()) }

// Marshal encodes the request body: every field but Evidence in the
// layout of SigningBytes (without the domain tag), then the evidence (a
// uint16-length-prefixed list of type and blob, each uint16-length
// prefixed). It refuses a request that Validate refuses.
func (r *ProbeIssueRequest) Marshal() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	r.addFields(&b)
	addEvidence(&b, r.Evidence)
	return b.Bytes()
}

// ParseProbeIssueRequest decodes a request body strictly: every limit of
// Validate, a Negative byte other than 0 or 1 and trailing bytes refused.
// The result's Marshal equals body.
func ParseProbeIssueRequest(body []byte) (*ProbeIssueRequest, error) {
	s := cryptobyte.String(body)
	var (
		r        ProbeIssueRequest
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

// ParseProbeIssueSigningBytes decodes the signing bytes of a request,
// which a probe_issue leaf logs as its request (tlog.ProbeIssueBody.Request),
// strictly: the raw domain tag first, the field limits, a Negative byte of
// 0 or 1, and trailing bytes refused. Validate's evidence rule does not
// apply (signing bytes carry none); every other rule does. Its
// SigningBytes equal b.
func ParseProbeIssueSigningBytes(b []byte) (*ProbeIssueRequest, error) {
	rest, ok := bytes.CutPrefix(b, []byte(ProbeIssueRequestDomain))
	if !ok {
		return nil, fmt.Errorf("%w: not the signing bytes of a probe issue request", ErrMalformed)
	}
	s := cryptobyte.String(rest)
	var r ProbeIssueRequest
	if !r.readFields(&s) || !s.Empty() {
		return nil, ErrMalformed
	}
	// Validate needs two evidence items; the signing bytes carry none, so
	// placeholders stand in for the check and are dropped again.
	r.Evidence = []Evidence{{Type: EvidenceHostPoP}, {Type: EvidenceProbePoP}}
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
