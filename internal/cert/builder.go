// Package cert builds and signs OpenSSH certificates. Build is the only place
// in the module that calls SignCert (enforced by signcert_guard_test.go and a
// forbidigo rule). The package is a leaf: it imports no other internal
// package.
package cert

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
)

// backdate is how far ValidAfter lies before the issuance time, to absorb
// clock skew between the signer and the hosts.
const backdate = 5 * time.Minute

// Profile is the per-CA certificate profile.
type Profile struct {
	CertType               uint32
	MaxTTL                 time.Duration
	DefaultExtensions      map[string]string
	AllowedExtensions      []string
	AllowedCriticalOptions []string
}

// DefaultUserProfile is the user CA profile: at most 12 hours, permit-pty
// and nothing else (CA-05). Forwarding, X11 and user-rc are therefore off.
func DefaultUserProfile() Profile {
	return Profile{
		CertType:          ssh.UserCert,
		MaxTTL:            12 * time.Hour,
		DefaultExtensions: map[string]string{"permit-pty": ""},
	}
}

// Request is everything Build needs. Every field must be set explicitly;
// zero values are refused.
type Request struct {
	Profile         Profile
	Subject         ssh.PublicKey
	Principals      []string
	Now             time.Time
	ValidFor        time.Duration
	KeyID           KeyID
	Serial          uint64
	ExtraExtensions map[string]string
	CriticalOptions map[string]string
}

// Build validates req, signs the certificate with ca, then re-parses the
// marshalled certificate and verifies its signature with the CA public key
// before returning it. It is the only SignCert call site in the module.
func Build(req Request, ca ssh.Signer, rnd io.Reader) (*ssh.Certificate, error) {
	if ca == nil || rnd == nil {
		return nil, errors.New("cert: Build needs a CA signer and a random source")
	}
	caPub := ca.PublicKey()
	if err := CheckCAKey(caPub); err != nil {
		return nil, err
	}
	if err := CheckSubjectKey(req.Subject, caPub); err != nil {
		return nil, err
	}
	if err := ValidatePrincipals(req.Principals); err != nil {
		return nil, err
	}
	if req.Serial == 0 {
		return nil, fmt.Errorf("%w: serial 0", ErrSerial)
	}
	if req.KeyID.Serial != req.Serial {
		return nil, fmt.Errorf("%w: key ID serial differs from the certificate serial", ErrSerial)
	}
	keyID := req.KeyID.String()
	if parsed, err := ParseKeyID(keyID); err != nil {
		return nil, err
	} else if parsed != req.KeyID {
		return nil, fmt.Errorf("%w: key ID does not round-trip", ErrKeyID)
	}

	p := req.Profile
	switch p.CertType {
	case ssh.UserCert, ssh.HostCert:
	default:
		return nil, fmt.Errorf("%w: unknown certificate type", ErrProfile)
	}
	if p.MaxTTL <= 0 {
		return nil, fmt.Errorf("%w: no maximum TTL", ErrProfile)
	}
	if req.ValidFor <= 0 || req.ValidFor > p.MaxTTL {
		return nil, fmt.Errorf("%w: validity must be above 0 and at most %s", ErrValidity, p.MaxTTL)
	}
	if req.Now.IsZero() {
		return nil, fmt.Errorf("%w: no issuance time", ErrValidity)
	}
	after := req.Now.Add(-backdate).Unix()
	before := req.Now.Add(req.ValidFor).Unix()
	if after <= 0 || before <= after {
		return nil, fmt.Errorf("%w: issuance time out of range", ErrValidity)
	}

	extensions, err := buildExtensions(p, req.ExtraExtensions)
	if err != nil {
		return nil, err
	}
	critical := map[string]string{}
	for k, v := range req.CriticalOptions {
		if !slices.Contains(p.AllowedCriticalOptions, k) {
			return nil, fmt.Errorf("%w: critical option %q", ErrExtension, k)
		}
		critical[k] = v
	}

	c := &ssh.Certificate{
		Key:             req.Subject,
		Serial:          req.Serial,
		CertType:        p.CertType,
		KeyId:           keyID,
		ValidPrincipals: slices.Clone(req.Principals),
		ValidAfter:      uint64(after),  //nolint:gosec // G115: after > 0, checked above
		ValidBefore:     uint64(before), //nolint:gosec // G115: before > after > 0, checked above
		Permissions: ssh.Permissions{
			CriticalOptions: critical,
			Extensions:      extensions,
		},
	}
	if err := c.SignCert(rnd, ca); err != nil {
		return nil, fmt.Errorf("cert: sign: %w", err)
	}
	if err := verifySigned(c, caPub); err != nil {
		return nil, err
	}
	return c, nil
}

// buildExtensions returns the profile defaults plus the allowed extras. Host
// certificates carry no extensions at all.
func buildExtensions(p Profile, extra map[string]string) (map[string]string, error) {
	if p.CertType == ssh.HostCert {
		if len(p.DefaultExtensions) != 0 || len(extra) != 0 {
			return nil, fmt.Errorf("%w: host certificates carry no extensions", ErrExtension)
		}
		return map[string]string{}, nil
	}
	ext := maps.Clone(p.DefaultExtensions)
	if ext == nil {
		ext = map[string]string{}
	}
	for k, v := range extra {
		if !slices.Contains(p.AllowedExtensions, k) {
			return nil, fmt.Errorf("%w: extension %q", ErrExtension, k)
		}
		ext[k] = v
	}
	return ext, nil
}

// verifySigned re-parses the marshalled certificate and checks that it is
// byte-identical, names the CA key, and carries a valid signature by it.
func verifySigned(c *ssh.Certificate, caPub ssh.PublicKey) error {
	wire := c.Marshal()
	pk, err := ssh.ParsePublicKey(wire)
	if err != nil {
		return fmt.Errorf("cert: re-parse signed certificate: %w", err)
	}
	parsed, ok := pk.(*ssh.Certificate)
	if !ok {
		return errors.New("cert: signed blob is not a certificate")
	}
	if !bytes.Equal(parsed.Marshal(), wire) {
		return errors.New("cert: signed certificate does not round-trip")
	}
	if parsed.SignatureKey == nil || !bytes.Equal(parsed.SignatureKey.Marshal(), caPub.Marshal()) {
		return errors.New("cert: signed certificate names another CA key")
	}
	if parsed.Signature == nil {
		return errors.New("cert: signed certificate has no signature")
	}
	if err := caPub.Verify(bytesForSigning(parsed), parsed.Signature); err != nil {
		return fmt.Errorf("cert: signature does not verify: %w", err)
	}
	return nil
}

// bytesForSigning mirrors x/crypto's unexported helper: the marshalled
// certificate without its trailing signature field.
func bytesForSigning(c *ssh.Certificate) []byte {
	c2 := *c
	c2.Signature = nil
	out := c2.Marshal()
	return out[:len(out)-4]
}
