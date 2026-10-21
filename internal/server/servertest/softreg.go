// Package servertest is soft WebAuthn registration for keyroster-server's
// unit and e2e tests: it turns a begin response and a webauthntest
// authenticator into the finish body a browser would post, with an
// attestation object of format "none". It is a non-test package so the
// e2e tests can use it, and it must never be linked into a release binary
// (scripts/testonly-firewall.sh fails CI when any ./cmd/... binary imports
// it).
package servertest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// authenticatorData flag bits (W3C WebAuthn L3 §6.1).
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
	FlagED = 0x80
)

// DefaultFlags is UP|UV|AT, what a user-verifying authenticator sets at
// registration.
const DefaultFlags = FlagUP | FlagUV | FlagAT

// AttestationFunc builds the attestation statement of a registration
// from its authenticator data and the SHA-256 of its clientDataJSON.
type AttestationFunc func(authData, clientDataHash []byte) (format string, attStmt any, err error)

type regOptions struct {
	cose        []byte
	attestation AttestationFunc
	challenge   *string
	typ         string
	credID      []byte
}

// Option changes one part of the registration Register produces.
type Option func(*regOptions)

// WithCOSEKey replaces the credential public key in the authenticator
// data by cose (see COSEKey). Attestation "none" carries no signature, so
// any key can be registered this way without its private key.
func WithCOSEKey(cose []byte) Option {
	return func(o *regOptions) { o.cose = append([]byte(nil), cose...) }
}

// WithAttestation replaces the attestation statement ("none", {}).
func WithAttestation(f AttestationFunc) Option { return func(o *regOptions) { o.attestation = f } }

// WithChallenge puts c into clientDataJSON instead of the options'
// challenge.
func WithChallenge(c string) Option { return func(o *regOptions) { o.challenge = &c } }

// WithType sets the clientDataJSON type (default webauthn.create).
func WithType(t string) Option { return func(o *regOptions) { o.typ = t } }

// WithCredentialID replaces the authenticator's credential ID, in the
// attested credential data and in id and rawId alike.
func WithCredentialID(id []byte) Option {
	return func(o *regOptions) { o.credID = append([]byte(nil), id...) }
}

// Register returns the body of a registration finish for options, the
// JSON a begin answered ({"publicKey":{...}}): the soft authenticator a
// registers its credential for rpID from origin with the authenticatorData
// flags (0: DefaultFlags). authenticatorData is SHA-256(rpID) ‖ flags ‖ a
// zero counter ‖ a zero AAGUID ‖ the credential ID length and ID ‖ the
// COSE key built from a's public key; the attestation object is {fmt:
// "none", attStmt: {}, authData}, encoded with go-webauthn's CTAP2 CBOR;
// clientDataJSON has type webauthn.create, the options' challenge and
// origin.
func Register(a *webauthntest.Authenticator, rpID, origin string, options []byte, flags byte, opts ...Option) ([]byte, error) {
	var o regOptions
	for _, opt := range opts {
		opt(&o)
	}
	if flags == 0 {
		flags = DefaultFlags
	}
	var begin struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &begin); err != nil {
		return nil, fmt.Errorf("servertest: begin options: %w", err)
	}
	challenge := begin.PublicKey.Challenge
	if o.challenge != nil {
		challenge = *o.challenge
	}
	if challenge == "" {
		return nil, errors.New("servertest: the begin options carry no challenge")
	}
	cred := a.Credential()
	id := cred.ID
	if o.credID != nil {
		id = o.credID
	}
	cose := o.cose
	if cose == nil {
		pub, err := x509.ParsePKIXPublicKey(cred.SPKI)
		if err != nil {
			return nil, err
		}
		if cose, err = COSEKey(cred.Alg, pub); err != nil {
			return nil, err
		}
	}
	if len(id) > 0xffff {
		return nil, errors.New("servertest: credential ID too long")
	}
	rp := sha256.Sum256([]byte(rpID))
	authData := append([]byte(nil), rp[:]...)
	authData = append(authData, flags, 0, 0, 0, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id))) //nolint:gosec // G115: len(id) <= 0xffff, checked above
	authData = append(authData, id...)
	authData = append(authData, cose...)

	typ := o.typ
	if typ == "" {
		typ = "webauthn.create"
	}
	clientData := fmt.Appendf(nil, `{"type":%q,"challenge":%q,"origin":%q,"crossOrigin":false}`, typ, challenge, origin)
	cdHash := sha256.Sum256(clientData)

	format, attStmt := "none", any(map[string]any{})
	if o.attestation != nil {
		var err error
		if format, attStmt, err = o.attestation(authData, cdHash[:]); err != nil {
			return nil, err
		}
	}
	attObj, err := webauthncbor.Marshal(map[string]any{"fmt": format, "attStmt": attStmt, "authData": authData})
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString
	return json.Marshal(map[string]any{
		"id":                      enc(id),
		"rawId":                   enc(id),
		"type":                    "public-key",
		"authenticatorAttachment": "cross-platform",
		"response": map[string]any{
			"clientDataJSON":    enc(clientData),
			"attestationObject": enc(attObj),
			"transports":        []string{"usb"},
		},
		"clientExtensionResults": map[string]any{},
	})
}

// COSEKey encodes pub as a COSE_Key for the COSE algorithm alg: EC2 (kty
// 2) with crv 1, 2 or 3 for an ECDSA P-256, P-384 or P-521 key, OKP (kty
// 1, crv 6) for an Ed25519 key, RSA (kty 3) with n and e for an RSA key.
// It does not check that alg fits the key, so a test can label a key with
// the wrong algorithm.
func COSEKey(alg int64, pub crypto.PublicKey) ([]byte, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		var crv int64
		switch k.Curve {
		case elliptic.P256():
			crv = 1
		case elliptic.P384():
			crv = 2
		case elliptic.P521():
			crv = 3
		default:
			return nil, errors.New("servertest: unsupported curve")
		}
		size := (k.Curve.Params().BitSize + 7) / 8
		raw, err := k.Bytes() // uncompressed point 0x04 ‖ X ‖ Y
		if err != nil {
			return nil, err
		}
		return webauthncbor.Marshal(map[int64]any{1: 2, 3: alg, -1: crv, -2: raw[1 : 1+size], -3: raw[1+size:]})
	case ed25519.PublicKey:
		return webauthncbor.Marshal(map[int64]any{1: 1, 3: alg, -1: 6, -2: []byte(k)})
	case *rsa.PublicKey:
		return RSACOSEKey(alg, k.N, k.E)
	}
	return nil, fmt.Errorf("servertest: unsupported key type %T", pub)
}

// RSACOSEKey encodes an RSA COSE_Key with modulus n and exponent e,
// which need not form a usable key: a registration test can offer any
// size or exponent this way.
func RSACOSEKey(alg int64, n *big.Int, e int) ([]byte, error) {
	if n == nil || e <= 0 {
		return nil, errors.New("servertest: bad RSA parameters")
	}
	eb := big.NewInt(int64(e)).Bytes()
	return webauthncbor.Marshal(map[int64]any{1: 3, 3: alg, -1: n.Bytes(), -2: eb})
}

// Algorithm names the accepted COSE algorithms in test messages.
func Algorithm(alg int64) string {
	switch alg {
	case webauthn.AlgEdDSA:
		return "EdDSA"
	case webauthn.AlgES256:
		return "ES256"
	case webauthn.AlgRS256:
		return "RS256"
	}
	return fmt.Sprintf("COSE %d", alg)
}
