package wire

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// IssueRequestDomain separates the signing bytes of an IssueRequest from
// every other signed format (D-01, D-13).
const IssueRequestDomain = "keyroster/issue-request/v1"

// Field limits of an IssueRequest. ParseIssueRequest and Marshal both
// enforce them.
const (
	MaxPrincipals     = 32
	MaxPrincipalLen   = 128
	MaxSubjectLen     = 64
	MaxSubjectKeyLen  = 8 << 10
	MaxEvidence       = 4
	MaxEvidenceType   = 64
	MaxEvidenceBlob   = 8 << 10
	MaxErrorMessage   = 256
	maxResponseCertSz = MaxFrame - 16
)

// ErrMalformed reports a message body that does not decode strictly.
var ErrMalformed = errors.New("wire: malformed message")

// CARole names the certificate authority a request is addressed to.
type CARole uint8

// CA roles.
const (
	CARoleUser    CARole = 1
	CARoleHost    CARole = 2
	CARoleMachine CARole = 3
)

// String returns the role name used in key IDs ("user", "host", "machine").
func (r CARole) String() string {
	switch r {
	case CARoleUser:
		return "user"
	case CARoleHost:
		return "host"
	case CARoleMachine:
		return "machine"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(r))
	}
}

func (r CARole) valid() bool { return r >= CARoleUser && r <= CARoleMachine }

// Evidence is one authorization item attached to a request (for example an
// admin SSHSIG over the request digest). Evidence is not part of the signing
// bytes.
type Evidence struct {
	Type string
	Blob []byte
}

// IssueRequest asks the signer for one certificate. SubjectKey is an SSH
// wire-format public key blob; the signer never receives a private key.
// CreatedAt is the client's clock in Unix seconds.
type IssueRequest struct {
	CARole          CARole
	SubjectKey      []byte
	Subject         string
	Principals      []string
	ValidForSeconds uint32
	RequestID       [16]byte
	CreatedAt       uint64
	Evidence        []Evidence
}

func (r *IssueRequest) check() error {
	switch {
	case !r.CARole.valid():
		return fmt.Errorf("%w: unknown CA role", ErrMalformed)
	case len(r.SubjectKey) == 0 || len(r.SubjectKey) > MaxSubjectKeyLen:
		return fmt.Errorf("%w: subject key size", ErrMalformed)
	case len(r.Subject) > MaxSubjectLen:
		return fmt.Errorf("%w: subject too long", ErrMalformed)
	case len(r.Principals) > MaxPrincipals:
		return fmt.Errorf("%w: too many principals", ErrMalformed)
	case len(r.Evidence) > MaxEvidence:
		return fmt.Errorf("%w: too many evidence items", ErrMalformed)
	}
	for _, p := range r.Principals {
		if len(p) > MaxPrincipalLen {
			return fmt.Errorf("%w: principal too long", ErrMalformed)
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
func (r *IssueRequest) addFields(b *cryptobyte.Builder) {
	b.AddUint8(uint8(r.CARole))
	addBytes16(b, r.SubjectKey)
	addBytes16(b, []byte(r.Subject))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, p := range r.Principals {
			addBytes16(b, []byte(p))
		}
	})
	b.AddUint32(r.ValidForSeconds)
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
}

// Marshal encodes the request body. It refuses a request that violates the
// field limits.
func (r *IssueRequest) Marshal() ([]byte, error) {
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

// SigningBytes returns the domain tag followed by every field except
// Evidence. Evidence items sign (a digest of) these bytes, so they cannot be
// part of them.
func (r *IssueRequest) SigningBytes() []byte {
	var b cryptobyte.Builder
	addBytes16(&b, []byte(IssueRequestDomain))
	r.addFields(&b)
	// The builder fails only when a field exceeds 65535 bytes. Every
	// request that went through ParseIssueRequest or Marshal is far below
	// that, so an error here means the caller built an invalid request.
	out, err := b.Bytes()
	if err != nil {
		return nil
	}
	return out
}

// Digest returns the SHA-256 of SigningBytes.
func (r *IssueRequest) Digest() [32]byte {
	return sha256.Sum256(r.SigningBytes())
}

// ParseIssueRequest decodes a request body strictly: every limit is
// enforced and trailing bytes are refused.
func ParseIssueRequest(body []byte) (*IssueRequest, error) {
	s := cryptobyte.String(body)
	var (
		r          IssueRequest
		role       uint8
		subjectKey []byte
		subject    []byte
		principals cryptobyte.String
		reqID      []byte
		evidence   cryptobyte.String
	)
	if !s.ReadUint8(&role) ||
		!readBytes16(&s, &subjectKey, MaxSubjectKeyLen) ||
		!readBytes16(&s, &subject, MaxSubjectLen) ||
		!s.ReadUint16LengthPrefixed(&principals) ||
		!s.ReadUint32(&r.ValidForSeconds) ||
		!s.ReadBytes(&reqID, len(r.RequestID)) ||
		!s.ReadUint64(&r.CreatedAt) ||
		!s.ReadUint16LengthPrefixed(&evidence) ||
		!s.Empty() {
		return nil, ErrMalformed
	}
	r.CARole = CARole(role)
	r.SubjectKey = subjectKey
	r.Subject = string(subject)
	copy(r.RequestID[:], reqID)
	for !principals.Empty() {
		if len(r.Principals) == MaxPrincipals {
			return nil, fmt.Errorf("%w: too many principals", ErrMalformed)
		}
		var p []byte
		if !readBytes16(&principals, &p, MaxPrincipalLen) {
			return nil, ErrMalformed
		}
		r.Principals = append(r.Principals, string(p))
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
	if err := r.check(); err != nil {
		return nil, err
	}
	return &r, nil
}

// IssueResponse carries the issued certificate in SSH wire format.
type IssueResponse struct {
	Cert   []byte
	Serial uint64
}

// Marshal encodes the response body.
func (r *IssueResponse) Marshal() ([]byte, error) {
	if len(r.Cert) == 0 || len(r.Cert) > maxResponseCertSz {
		return nil, fmt.Errorf("%w: certificate size", ErrMalformed)
	}
	var b cryptobyte.Builder
	addBytes16(&b, r.Cert)
	b.AddUint64(r.Serial)
	return b.Bytes()
}

// ParseIssueResponse decodes a response body strictly.
func ParseIssueResponse(body []byte) (*IssueResponse, error) {
	s := cryptobyte.String(body)
	var r IssueResponse
	if !readBytes16(&s, &r.Cert, maxResponseCertSz) || !s.ReadUint64(&r.Serial) || !s.Empty() || len(r.Cert) == 0 {
		return nil, ErrMalformed
	}
	return &r, nil
}

// ErrorCode classifies a refusal or failure reported by the signer.
type ErrorCode uint8

// Error codes.
const (
	CodeRefused     ErrorCode = 1
	CodeMalformed   ErrorCode = 2
	CodeUnavailable ErrorCode = 3
	CodeInternal    ErrorCode = 4
)

// String returns the code name.
func (c ErrorCode) String() string {
	switch c {
	case CodeRefused:
		return "refused"
	case CodeMalformed:
		return "malformed"
	case CodeUnavailable:
		return "unavailable"
	case CodeInternal:
		return "internal"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(c))
	}
}

func (c ErrorCode) valid() bool { return c >= CodeRefused && c <= CodeInternal }

// ErrorResponse reports why the signer did not issue. Message is a short
// reason code restricted to [a-z0-9_ .:-], so it can be logged and printed
// without escaping; the signer never echoes request bytes in it.
type ErrorResponse struct {
	Code    ErrorCode
	Message string
}

// Error makes an ErrorResponse usable as a Go error on the client side.
func (e *ErrorResponse) Error() string {
	return "signer " + e.Code.String() + ": " + e.Message
}

// ValidMessage reports whether m fits the ErrorResponse message charset and
// length.
func ValidMessage(m string) bool {
	if len(m) == 0 || len(m) > MaxErrorMessage {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '_' || c == ' ' || c == '.' || c == ':' || c == '-':
		default:
			return false
		}
	}
	return true
}

// Marshal encodes the error body.
func (e *ErrorResponse) Marshal() ([]byte, error) {
	if !e.Code.valid() || !ValidMessage(e.Message) {
		return nil, fmt.Errorf("%w: error response", ErrMalformed)
	}
	var b cryptobyte.Builder
	b.AddUint8(uint8(e.Code))
	addBytes16(&b, []byte(e.Message))
	return b.Bytes()
}

// ParseErrorResponse decodes an error body strictly.
func ParseErrorResponse(body []byte) (*ErrorResponse, error) {
	s := cryptobyte.String(body)
	var (
		code uint8
		msg  []byte
	)
	if !s.ReadUint8(&code) || !readBytes16(&s, &msg, MaxErrorMessage) || !s.Empty() {
		return nil, ErrMalformed
	}
	e := &ErrorResponse{Code: ErrorCode(code), Message: string(msg)}
	if !e.Code.valid() || !ValidMessage(e.Message) {
		return nil, ErrMalformed
	}
	return e, nil
}

func addBytes16(b *cryptobyte.Builder, v []byte) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(v) })
}

// readBytes16 reads a uint16-length-prefixed field of at most limit bytes
// and copies it out of the input buffer.
func readBytes16(s *cryptobyte.String, out *[]byte, limit int) bool {
	var v cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&v) || len(v) > limit {
		return false
	}
	*out = append([]byte(nil), v...)
	return true
}
