package cert

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Validation errors. Callers map them to refusal reason codes with
// errors.Is.
var (
	ErrCertificateKey  = errors.New("cert: a certificate cannot be used as a key")
	ErrCAKeyAlgorithm  = errors.New("cert: CA key algorithm not allowed")
	ErrSubjectKey      = errors.New("cert: subject key not allowed")
	ErrEmptyPrincipals = errors.New("cert: no principals")
	ErrPrincipal       = errors.New("cert: invalid principal")
	ErrKeyID           = errors.New("cert: invalid key ID")
	ErrValidity        = errors.New("cert: invalid validity period")
	ErrSerial          = errors.New("cert: invalid serial")
	ErrExtension       = errors.New("cert: extension or critical option not allowed")
	ErrProfile         = errors.New("cert: invalid profile")
)

// MaxPrincipals is the most principals one certificate may list.
const MaxPrincipals = 32

// minRSABits is the smallest RSA subject key accepted.
const minRSABits = 3072

// principalRE is an allowlist: no wildcards (* ?), no commas, no '!', no
// whitespace, no control characters, no '/' (CA-02).
var principalRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._@:+-]{0,127}$`)

// isCertificate reports whether pub is, or claims the type of, an OpenSSH
// certificate.
func isCertificate(pub ssh.PublicKey) bool {
	if _, ok := pub.(*ssh.Certificate); ok {
		return true
	}
	return strings.HasSuffix(pub.Type(), "-cert-v01@openssh.com")
}

// CheckCAKey refuses certificate-type keys (CA-07) and every algorithm other
// than ssh-ed25519 and ecdsa-sha2-nistp256 (D-09).
func CheckCAKey(pub ssh.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: no key", ErrCAKeyAlgorithm)
	}
	if isCertificate(pub) {
		return ErrCertificateKey
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrCAKeyAlgorithm, pub.Type())
	}
}

// CheckSubjectKey accepts Ed25519, ECDSA P-256/384/521, sk-ed25519,
// sk-ecdsa and RSA keys of at least 3072 bits. It refuses certificates, DSA,
// shorter RSA keys, unknown types, and a subject key equal to the CA key.
func CheckSubjectKey(pub, ca ssh.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: no key", ErrSubjectKey)
	}
	if isCertificate(pub) {
		return ErrCertificateKey
	}
	if ca != nil && bytes.Equal(pub.Marshal(), ca.Marshal()) {
		return fmt.Errorf("%w: subject key is the CA key", ErrSubjectKey)
	}
	switch pub.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		cpk, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return fmt.Errorf("%w: unreadable RSA key", ErrSubjectKey)
		}
		rk, ok := cpk.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rk.N.BitLen() < minRSABits {
			return fmt.Errorf("%w: RSA keys need at least %d bits", ErrSubjectKey, minRSABits)
		}
		return nil
	default:
		return fmt.Errorf("%w: type %q", ErrSubjectKey, pub.Type())
	}
}

// ValidatePrincipals requires 1 to 32 principals, each matching the
// allowlist, with no byte-exact duplicates.
func ValidatePrincipals(ps []string) error {
	if len(ps) == 0 {
		return ErrEmptyPrincipals
	}
	if len(ps) > MaxPrincipals {
		return fmt.Errorf("%w: more than %d principals", ErrPrincipal, MaxPrincipals)
	}
	seen := make(map[string]struct{}, len(ps))
	for i, p := range ps {
		if !principalRE.MatchString(p) {
			return fmt.Errorf("%w: principal %d does not match the allowed pattern", ErrPrincipal, i)
		}
		if _, dup := seen[p]; dup {
			return fmt.Errorf("%w: principal %d is a duplicate", ErrPrincipal, i)
		}
		seen[p] = struct{}{}
	}
	return nil
}
