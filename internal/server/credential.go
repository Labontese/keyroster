package server

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/Labontese/keyroster/internal/webauthn"
)

// errUnsupportedCredential is a registered public key keyroster does not
// accept: one internal/webauthn.ParsePublicKey refuses, which is the rule
// the signer and the directory apply too.
var errUnsupportedCredential = errors.New("unsupported credential")

// spkiFromCOSE converts the COSE public key go-webauthn verified at
// registration into the form keyroster stores everywhere: its COSE
// algorithm and the key as SPKI DER (D-03, D-05). EC2 becomes an ECDSA
// key, OKP an Ed25519 key and RSA a key built from its modulus and
// exponent. The result is accepted only when webauthn.ParsePublicKey
// accepts it for that algorithm, so the server never stores a credential
// the signer would refuse (an RSA key outside its size bounds, an ECDSA
// key on another curve, a key whose type does not match its algorithm).
func spkiFromCOSE(cose []byte) (alg int64, spki []byte, err error) {
	parsed, err := webauthncose.ParsePublicKey(cose)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", errUnsupportedCredential, err)
	}
	var pub crypto.PublicKey
	switch k := parsed.(type) {
	case webauthncose.EC2PublicKeyData:
		ec, err := k.ToECDSA()
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %w", errUnsupportedCredential, err)
		}
		alg, pub = k.Algorithm, ec
	case webauthncose.OKPPublicKeyData:
		if len(k.XCoord) != ed25519.PublicKeySize {
			return 0, nil, fmt.Errorf("%w: OKP key of %d bytes", errUnsupportedCredential, len(k.XCoord))
		}
		alg, pub = k.Algorithm, ed25519.PublicKey(append([]byte(nil), k.XCoord...))
	case webauthncose.RSAPublicKeyData:
		e, err := webauthncose.ParseRSAPublicKeyDataExponent(&k)
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %w", errUnsupportedCredential, err)
		}
		alg, pub = k.Algorithm, &rsa.PublicKey{N: new(big.Int).SetBytes(k.Modulus), E: e}
	default:
		return 0, nil, fmt.Errorf("%w: key type %T", errUnsupportedCredential, parsed)
	}
	spki, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %w", errUnsupportedCredential, err)
	}
	if _, err := webauthn.ParsePublicKey(alg, spki); err != nil {
		return 0, nil, fmt.Errorf("%w: %w", errUnsupportedCredential, err)
	}
	return alg, spki, nil
}

// algName is the name of an accepted COSE algorithm.
func algName(alg int64) string {
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
