// Package webauthn is the signer's minimal WebAuthn assertion verifier
// (D-17). It checks an assertion (authenticatorData, clientDataJSON and the
// signature) against a credential the admin-signed directory binds to a
// user, the relying party of the root-signed policy and the challenge the
// signer computed itself. It imports the standard library only, never
// parses CBOR or COSE (credentials arrive as an algorithm number plus SPKI
// DER) and must stay network-less: it is in the signer's dependency graph.
package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
)

// COSE algorithm identifiers the signer accepts (RESEARCH Q3): ES256 (ECDSA
// P-256 with SHA-256, ASN.1 DER signature), EdDSA (Ed25519) and RS256
// (RSASSA-PKCS1-v1_5 with SHA-256, modulus of at least 2048 bits).
const (
	AlgES256 int64 = -7
	AlgEdDSA int64 = -8
	AlgRS256 int64 = -257
)

// minRSABits is the smallest RS256 modulus accepted.
const minRSABits = 2048

// authenticatorData flag bits (W3C WebAuthn L3 §6.1).
const (
	flagUP = 1 << 0
	flagUV = 1 << 2
	flagAT = 1 << 6
	flagED = 1 << 7
)

// authDataLen is the only authenticatorData length accepted: rpIdHash (32),
// flags (1) and signCount (4), with no attested credential data and no
// extensions, so no CBOR ever reaches the signer.
const authDataLen = 37

// Verification errors, one per step of VerifyAssertion. The signer maps
// each to a named refusal.
var (
	ErrCredentialID      = errors.New("webauthn: the assertion is not for this credential")
	ErrAuthenticatorData = errors.New("webauthn: malformed authenticator data")
	ErrRPMismatch        = errors.New("webauthn: rpIdHash is not the relying party's")
	ErrUserPresence      = errors.New("webauthn: user presence flag not set")
	ErrUserVerification  = errors.New("webauthn: user verification flag not set")
	ErrClientData        = errors.New("webauthn: malformed clientDataJSON")
	ErrType              = errors.New("webauthn: clientDataJSON type is not webauthn.get")
	ErrChallenge         = errors.New("webauthn: challenge mismatch")
	ErrOrigin            = errors.New("webauthn: origin not allowed")
	ErrCrossOrigin       = errors.New("webauthn: cross-origin assertion refused")
	ErrSignature         = errors.New("webauthn: assertion signature does not verify")
	ErrAlgorithm         = errors.New("webauthn: unsupported algorithm")
	ErrPublicKey         = errors.New("webauthn: public key does not match its algorithm")
)

// Credential is a WebAuthn credential bound to a user: its ID, its COSE
// algorithm and its public key as SPKI DER.
type Credential struct {
	ID   []byte
	Alg  int64
	SPKI []byte
}

// Assertion is what the browser returns from navigator.credentials.get.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
}

// ParsePublicKey parses spki and requires the key type alg names: a P-256
// ECDSA key for ES256, an Ed25519 key for EdDSA, an RSA key of at least
// 2048 bits for RS256. Any other algorithm is ErrAlgorithm.
func ParsePublicKey(alg int64, spki []byte) (crypto.PublicKey, error) {
	switch alg {
	case AlgES256, AlgEdDSA, AlgRS256:
	default:
		return nil, fmt.Errorf("%w: %d", ErrAlgorithm, alg)
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPublicKey, err)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if alg == AlgES256 && k.Curve == elliptic.P256() {
			return k, nil
		}
	case ed25519.PublicKey:
		if alg == AlgEdDSA {
			return k, nil
		}
	case *rsa.PublicKey:
		if alg == AlgRS256 && k.N.BitLen() >= minRSABits {
			return k, nil
		}
	}
	return nil, fmt.Errorf("%w: key type %T for algorithm %d", ErrPublicKey, pub, alg)
}

// Fingerprint returns "SHA256:" and the unpadded standard base64 of
// SHA-256(spki), the same style as SSH key fingerprints (AUTH-04).
func Fingerprint(spki []byte) string {
	h := sha256.Sum256(spki)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(h[:])
}

// VerifyAssertion checks assertion a for credential cred under the relying
// party rpID with the allowed origins, against challenge, which the caller
// computed from the request it is about to authorize. The steps run in
// this order and the first failure returns its sentinel:
//
//  1. the assertion's credential ID is cred.ID (ErrCredentialID);
//  2. authenticatorData is exactly 37 bytes (ErrAuthenticatorData);
//  3. rpIdHash is SHA-256(rpID), compared in constant time (ErrRPMismatch);
//  4. UP is set (ErrUserPresence), UV is set (ErrUserVerification), and AT
//     and ED are clear (ErrAuthenticatorData);
//  5. clientDataJSON parses strictly (ErrClientData);
//  6. its type is webauthn.get (ErrType);
//  7. its challenge is strict unpadded base64url of challenge, compared in
//     constant time (ErrChallenge);
//  8. its origin is exactly one of origins (ErrOrigin);
//  9. crossOrigin is not true and topOrigin is absent (ErrCrossOrigin);
//  10. the signature over authenticatorData ‖ SHA-256(clientDataJSON)
//     verifies under cred's key for its algorithm (ErrSignature), and the
//     algorithm is one of ES256, EdDSA, RS256 (ErrAlgorithm).
//
// The signature counter and the BE/BS flags are not checked (D-05).
func VerifyAssertion(cred Credential, rpID string, origins []string, challenge [32]byte, a Assertion) error {
	if len(cred.ID) == 0 || !bytes.Equal(a.CredentialID, cred.ID) {
		return ErrCredentialID
	}
	ad := a.AuthenticatorData
	if len(ad) != authDataLen {
		return ErrAuthenticatorData
	}
	rpHash := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(ad[:32], rpHash[:]) != 1 {
		return ErrRPMismatch
	}
	flags := ad[32]
	switch {
	case flags&flagUP == 0:
		return ErrUserPresence
	case flags&flagUV == 0:
		return ErrUserVerification
	case flags&(flagAT|flagED) != 0:
		return ErrAuthenticatorData
	}
	cd, err := parseClientData(a.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrClientData, err)
	}
	if cd.Type != "webauthn.get" {
		return ErrType
	}
	got, err := base64.RawURLEncoding.Strict().DecodeString(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge[:]) != 1 {
		return ErrChallenge
	}
	if !slices.Contains(origins, cd.Origin) {
		return ErrOrigin
	}
	if cd.CrossOrigin || cd.HasTopOrigin {
		return ErrCrossOrigin
	}
	return verifySignature(cred, ad, a.ClientDataJSON, a.Signature)
}

// verifySignature checks sig over authData ‖ SHA-256(clientDataJSON).
func verifySignature(cred Credential, authData, clientDataJSON, sig []byte) error {
	switch cred.Alg {
	case AlgES256, AlgEdDSA, AlgRS256:
	default:
		return ErrAlgorithm
	}
	pub, err := ParsePublicKey(cred.Alg, cred.SPKI)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	cdHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authData)+len(cdHash))
	signed = append(append(signed, authData...), cdHash[:]...)
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(signed)
		ok = ecdsa.VerifyASN1(k, h[:], sig)
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, signed, sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(signed)
		ok = rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	}
	if !ok {
		return ErrSignature
	}
	return nil
}
