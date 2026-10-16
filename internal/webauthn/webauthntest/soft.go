// Package webauthntest is a software WebAuthn authenticator for tests: it
// produces the assertions a browser and authenticator would, so the signer,
// the server and the e2e tests run without a browser. It must never be
// linked into a release binary (scripts/testonly-firewall.sh fails CI when
// any ./cmd/... binary imports it). Even if it were, it would create no
// bypass: the signer verifies every assertion against a credential the
// admin-signed directory binds.
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/Labontese/keyroster/internal/webauthn"
)

// Authenticator holds one credential: a key pair and a random credential
// ID.
type Authenticator struct {
	alg  int64
	id   []byte
	key  crypto.Signer
	spki []byte
}

// New generates a credential for alg: Ed25519 for webauthn.AlgEdDSA, P-256
// for webauthn.AlgES256, RSA-2048 for webauthn.AlgRS256, with a random
// 32-byte credential ID.
func New(alg int64) (*Authenticator, error) {
	var (
		key crypto.Signer
		err error
	)
	switch alg {
	case webauthn.AlgEdDSA:
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case webauthn.AlgES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case webauthn.AlgRS256:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("webauthntest: unsupported algorithm %d", alg)
	}
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return &Authenticator{alg: alg, id: id, key: key, spki: spki}, nil
}

// Credential returns the credential as the directory binds it.
func (a *Authenticator) Credential() webauthn.Credential {
	return webauthn.Credential{ID: append([]byte(nil), a.id...), Alg: a.alg, SPKI: append([]byte(nil), a.spki...)}
}

// options are the knobs of Assert.
type options struct {
	flags      byte
	typ        string
	clientData []byte
}

// Option changes one part of the assertion Assert produces.
type Option func(*options)

// WithFlags sets the authenticatorData flags byte (default 0x05, UP|UV).
func WithFlags(f byte) Option { return func(o *options) { o.flags = f } }

// WithType sets the clientDataJSON type (default webauthn.get).
func WithType(t string) Option { return func(o *options) { o.typ = t } }

// WithClientDataJSON replaces the whole clientDataJSON; the signature is
// made over it.
func WithClientDataJSON(cd []byte) Option {
	return func(o *options) { o.clientData = append([]byte(nil), cd...) }
}

// Assert returns an assertion over challenge for rpID from origin:
// authenticatorData = SHA-256(rpID) ‖ flags ‖ a zero counter, clientDataJSON
// = {"type":...,"challenge":<b64url>,"origin":...,"crossOrigin":false}, and
// the signature over authenticatorData ‖ SHA-256(clientDataJSON) in the
// format the credential's algorithm uses. It panics only if the key fails to
// sign, which a test treats as fatal.
func (a *Authenticator) Assert(rpID, origin string, challenge [32]byte, opts ...Option) webauthn.Assertion {
	o := options{flags: 0x05, typ: "webauthn.get"}
	for _, opt := range opts {
		opt(&o)
	}
	rp := sha256.Sum256([]byte(rpID))
	authData := append(rp[:], o.flags, 0, 0, 0, 0)
	cd := o.clientData
	if cd == nil {
		cd = fmt.Appendf(nil, `{"type":%q,"challenge":%q,"origin":%q,"crossOrigin":false}`,
			o.typ, base64.RawURLEncoding.EncodeToString(challenge[:]), origin)
	}
	cdHash := sha256.Sum256(cd)
	signed := append(append([]byte(nil), authData...), cdHash[:]...)
	var (
		sig []byte
		err error
	)
	switch a.alg {
	case webauthn.AlgEdDSA:
		sig, err = a.key.Sign(rand.Reader, signed, crypto.Hash(0))
	default:
		h := sha256.Sum256(signed)
		sig, err = a.key.Sign(rand.Reader, h[:], crypto.SHA256)
	}
	if err != nil {
		panic(fmt.Sprintf("webauthntest: sign: %v", err))
	}
	return webauthn.Assertion{
		CredentialID:      append([]byte(nil), a.id...),
		AuthenticatorData: authData,
		ClientDataJSON:    cd,
		Signature:         sig,
	}
}
