// Package rootceremony is the only code path in which a root key signs.
// It signs exactly two document types, the canonical trust bundle and the
// canonical policy, each under its own SSHSIG namespace. It cannot sign a
// certificate: it does not import internal/cert, internal/signer or
// internal/keystore, and its exported API is SignBundle, SignPolicy,
// Summary and BundleHash (both pinned by tests, KEY-07).
package rootceremony

import (
	"fmt"
	"io"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// SignBundle returns an armored SSHSIG signature by s over bundleJSON under
// trust.NamespaceBundle. It refuses input that is not a canonical, valid
// trust bundle, so a root key never signs anything else through it.
func SignBundle(rnd io.Reader, s ssh.Signer, bundleJSON []byte) ([]byte, error) {
	if _, err := trust.ParseBundle(bundleJSON); err != nil {
		return nil, fmt.Errorf("rootceremony: refusing to sign: not a valid trust bundle: %w", err)
	}
	return sshsig.Sign(rnd, s, trust.NamespaceBundle, bundleJSON)
}

// SignPolicy returns an armored SSHSIG signature by s over policyJSON under
// trust.NamespacePolicy. It refuses input that is not a canonical, valid
// policy.
func SignPolicy(rnd io.Reader, s ssh.Signer, policyJSON []byte) ([]byte, error) {
	if _, err := trust.ParsePolicy(policyJSON); err != nil {
		return nil, fmt.Errorf("rootceremony: refusing to sign: not a valid policy: %w", err)
	}
	return sshsig.Sign(rnd, s, trust.NamespacePolicy, policyJSON)
}

// BundleHash returns the lowercase hex SHA-256 of the bundle bytes: the
// value a successor's prev field carries and whose prefix the operator types
// to confirm a signature.
func BundleHash(bundleJSON []byte) string {
	return trust.SHA256Hex(bundleJSON)
}
