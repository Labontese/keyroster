package wire

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// LoginRequestDomain separates the signing bytes of a LoginIssueRequest
// from every other signed format. A WebAuthn assertion approves a login
// request by signing a challenge equal to SHA-256 of those bytes.
const LoginRequestDomain = "keyroster/login-request/v1"

// EvidenceWebAuthnAssertion is the evidence type of a WebAuthn assertion
// (a WebAuthnAssertion blob) over a login request's Digest (KEY-02, D-17).
// It is the only evidence a LoginIssueRequest accepts.
const EvidenceWebAuthnAssertion = "webauthn-assertion/v1"

// Limits of a LoginIssueRequest beyond the IssueRequest limits it reuses.
const (
	MaxLoginRoles  = 16
	MaxRoleNameLen = 64
)

// Limits of a WebAuthnAssertion blob.
const (
	MaxCredentialIDLen    = 1023
	MaxAuthenticatorData  = 1024
	MaxClientDataJSON     = 2048
	MaxAssertionSignature = 1024
)

// LoginIssueRequest asks the signer for a user certificate on behalf of a
// directory user, approved by that user's passkey. Subject is the user
// name; Roles names a subset of the user's roles (empty: all of them).
// Principals must equal what the signer computes from the installed
// directory for those roles (D-08). There is no CA role field: a login
// certificate always comes from the user CA.
type LoginIssueRequest struct {
	SubjectKey      []byte
	Subject         string
	Roles           []string
	Principals      []string
	ValidForSeconds uint32
	RequestID       [16]byte
	CreatedAt       uint64
	Extensions      []string
	Evidence        []Evidence
}

func (r *LoginIssueRequest) check() error {
	switch {
	case len(r.SubjectKey) == 0 || len(r.SubjectKey) > MaxSubjectKeyLen:
		return fmt.Errorf("%w: subject key size", ErrMalformed)
	case len(r.Subject) > MaxSubjectLen:
		return fmt.Errorf("%w: subject too long", ErrMalformed)
	case len(r.Roles) > MaxLoginRoles:
		return fmt.Errorf("%w: too many roles", ErrMalformed)
	case len(r.Principals) > MaxPrincipals:
		return fmt.Errorf("%w: too many principals", ErrMalformed)
	case len(r.Extensions) > MaxExtensions:
		return fmt.Errorf("%w: too many extensions", ErrMalformed)
	case len(r.Evidence) > MaxEvidence:
		return fmt.Errorf("%w: too many evidence items", ErrMalformed)
	}
	for _, role := range r.Roles {
		if len(role) == 0 || len(role) > MaxRoleNameLen {
			return fmt.Errorf("%w: role name size", ErrMalformed)
		}
	}
	for _, p := range r.Principals {
		if len(p) > MaxPrincipalLen {
			return fmt.Errorf("%w: principal too long", ErrMalformed)
		}
	}
	for _, e := range r.Extensions {
		if len(e) == 0 || len(e) > MaxExtensionLen {
			return fmt.Errorf("%w: extension name size", ErrMalformed)
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
func (r *LoginIssueRequest) addFields(b *cryptobyte.Builder) {
	addBytes16(b, r.SubjectKey)
	addBytes16(b, []byte(r.Subject))
	addList16(b, r.Roles)
	addList16(b, r.Principals)
	b.AddUint32(r.ValidForSeconds)
	b.AddBytes(r.RequestID[:])
	b.AddUint64(r.CreatedAt)
	addList16(b, r.Extensions)
}

// Marshal encodes the request body. It refuses a request that violates the
// field limits.
func (r *LoginIssueRequest) Marshal() ([]byte, error) {
	if err := r.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	r.addFields(&b)
	addEvidence(&b, r.Evidence)
	return b.Bytes()
}

// SigningBytes returns the domain tag LoginRequestDomain, as raw bytes,
// followed by every field except Evidence, in declaration order.
func (r *LoginIssueRequest) SigningBytes() []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(LoginRequestDomain))
	r.addFields(&b)
	out, err := b.Bytes()
	if err != nil {
		return nil // a field above 65535 bytes: the caller built an invalid request
	}
	return out
}

// Digest returns the SHA-256 of SigningBytes: the WebAuthn challenge that
// approves this request.
func (r *LoginIssueRequest) Digest() [32]byte {
	return sha256.Sum256(r.SigningBytes())
}

// ParseLoginIssueRequest decodes a login request body strictly: every limit
// is enforced and trailing bytes are refused.
func ParseLoginIssueRequest(body []byte) (*LoginIssueRequest, error) {
	s := cryptobyte.String(body)
	r, err := readLoginFields(&s)
	if err != nil {
		return nil, err
	}
	var evidence cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&evidence) || !s.Empty() {
		return nil, ErrMalformed
	}
	if r.Evidence, err = readEvidence(&evidence); err != nil {
		return nil, err
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return r, nil
}

// ParseLoginIssueSigningBytes decodes the signing bytes of a login request
// (SigningBytes: the raw LoginRequestDomain tag, then every field except
// Evidence), as a login_issue log leaf stores them. It is as strict as
// ParseLoginIssueRequest: every limit is enforced, there is no evidence
// section, trailing bytes are refused, and the bytes must be exactly what
// SigningBytes encodes for the decoded request, so that the request an
// auditor reads is the one whose SHA-256 the passkey signed. The returned
// request has no Evidence.
func ParseLoginIssueSigningBytes(b []byte) (*LoginIssueRequest, error) {
	s := cryptobyte.String(b)
	var tag []byte
	if !s.ReadBytes(&tag, len(LoginRequestDomain)) || string(tag) != LoginRequestDomain {
		return nil, fmt.Errorf("%w: not a %s signing encoding", ErrMalformed, LoginRequestDomain)
	}
	r, err := readLoginFields(&s)
	if err != nil {
		return nil, err
	}
	if !s.Empty() {
		return nil, fmt.Errorf("%w: trailing bytes after the login request fields", ErrMalformed)
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	if !bytes.Equal(r.SigningBytes(), b) {
		return nil, fmt.Errorf("%w: login request signing bytes are not canonical", ErrMalformed)
	}
	return r, nil
}

// readLoginFields reads every LoginIssueRequest field except Evidence, in
// the order addFields writes them. Per-entry minimums are left to check().
func readLoginFields(s *cryptobyte.String) (*LoginIssueRequest, error) {
	var (
		r          LoginIssueRequest
		subjectKey []byte
		subject    []byte
		roles      cryptobyte.String
		principals cryptobyte.String
		reqID      []byte
		extensions cryptobyte.String
	)
	if !readBytes16(s, &subjectKey, MaxSubjectKeyLen) ||
		!readBytes16(s, &subject, MaxSubjectLen) ||
		!s.ReadUint16LengthPrefixed(&roles) ||
		!s.ReadUint16LengthPrefixed(&principals) ||
		!s.ReadUint32(&r.ValidForSeconds) ||
		!s.ReadBytes(&reqID, len(r.RequestID)) ||
		!s.ReadUint64(&r.CreatedAt) ||
		!s.ReadUint16LengthPrefixed(&extensions) {
		return nil, ErrMalformed
	}
	r.SubjectKey = subjectKey
	r.Subject = string(subject)
	copy(r.RequestID[:], reqID)
	var err error
	if r.Roles, err = readList16(&roles, MaxLoginRoles, MaxRoleNameLen); err != nil {
		return nil, err
	}
	if r.Principals, err = readList16(&principals, MaxPrincipals, MaxPrincipalLen); err != nil {
		return nil, err
	}
	if r.Extensions, err = readList16(&extensions, MaxExtensions, MaxExtensionLen); err != nil {
		return nil, err
	}
	return &r, nil
}

// WebAuthnAssertion is the blob of a webauthn-assertion/v1 evidence item:
// what navigator.credentials.get returned, as uint16-length-prefixed
// fields.
type WebAuthnAssertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

func (a *WebAuthnAssertion) check() error {
	if len(a.CredentialID) == 0 || len(a.CredentialID) > MaxCredentialIDLen ||
		len(a.AuthenticatorData) > MaxAuthenticatorData || len(a.ClientDataJSON) > MaxClientDataJSON ||
		len(a.Signature) > MaxAssertionSignature {
		return fmt.Errorf("%w: webauthn assertion field size", ErrMalformed)
	}
	return nil
}

// Marshal encodes the assertion blob.
func (a *WebAuthnAssertion) Marshal() ([]byte, error) {
	if err := a.check(); err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	addBytes16(&b, a.CredentialID)
	addBytes16(&b, a.AuthenticatorData)
	addBytes16(&b, a.ClientDataJSON)
	addBytes16(&b, a.Signature)
	return b.Bytes()
}

// ParseWebAuthnAssertion decodes an assertion blob strictly.
func ParseWebAuthnAssertion(blob []byte) (*WebAuthnAssertion, error) {
	s := cryptobyte.String(blob)
	var a WebAuthnAssertion
	if !readBytes16(&s, &a.CredentialID, MaxCredentialIDLen) ||
		!readBytes16(&s, &a.AuthenticatorData, MaxAuthenticatorData) ||
		!readBytes16(&s, &a.ClientDataJSON, MaxClientDataJSON) ||
		!readBytes16(&s, &a.Signature, MaxAssertionSignature) ||
		!s.Empty() {
		return nil, ErrMalformed
	}
	if err := a.check(); err != nil {
		return nil, err
	}
	return &a, nil
}

// addList16 appends a uint16-length-prefixed list of uint16-length-prefixed
// strings.
func addList16(b *cryptobyte.Builder, list []string) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, v := range list {
			addBytes16(b, []byte(v))
		}
	})
}

// readList16 reads the entries of a list written by addList16: at most
// maxEntries entries of at most limit bytes each. Per-entry minimums are
// left to check(), as for IssueRequest.
func readList16(s *cryptobyte.String, maxEntries, limit int) ([]string, error) {
	var out []string
	for !s.Empty() {
		if len(out) == maxEntries {
			return nil, fmt.Errorf("%w: too many list entries", ErrMalformed)
		}
		var v []byte
		if !readBytes16(s, &v, limit) {
			return nil, ErrMalformed
		}
		out = append(out, string(v))
	}
	return out, nil
}

// addEvidence appends a uint16-length-prefixed evidence list.
func addEvidence(b *cryptobyte.Builder, evidence []Evidence) {
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, e := range evidence {
			addBytes16(b, []byte(e.Type))
			addBytes16(b, e.Blob)
		}
	})
}

// readEvidence reads the entries of an evidence list.
func readEvidence(s *cryptobyte.String) ([]Evidence, error) {
	var out []Evidence
	for !s.Empty() {
		if len(out) == MaxEvidence {
			return nil, fmt.Errorf("%w: too many evidence items", ErrMalformed)
		}
		var typ, blob []byte
		if !readBytes16(s, &typ, MaxEvidenceType) || !readBytes16(s, &blob, MaxEvidenceBlob) {
			return nil, ErrMalformed
		}
		out = append(out, Evidence{Type: string(typ), Blob: blob})
	}
	return out, nil
}
