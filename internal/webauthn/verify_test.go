package webauthn_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

const (
	testRP     = "keyroster.example.org"
	testOrigin = "https://keyroster.example.org"
)

var testChallenge = sha256.Sum256([]byte("keyroster/login-request/v1 test request"))

func newAuth(t *testing.T, alg int64) *webauthntest.Authenticator {
	t.Helper()
	a, err := webauthntest.New(alg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestWebAuthnVerifyAssertion is the happy path for every algorithm the
// signer accepts, each paired with refusals of a cleared UV flag, a wrong RP, a
// wrong challenge and a wrong origin. The full mutation matrix and the
// fuzz target are plan 02-03's.
func TestWebAuthnVerifyAssertion(t *testing.T) {
	for _, alg := range []struct {
		name string
		alg  int64
	}{{"eddsa", webauthn.AlgEdDSA}, {"es256", webauthn.AlgES256}, {"rs256", webauthn.AlgRS256}} {
		t.Run(alg.name, func(t *testing.T) {
			auth := newAuth(t, alg.alg)
			cred := auth.Credential()
			origins := []string{testOrigin}
			if err := webauthn.VerifyAssertion(cred, testRP, origins, testChallenge, auth.Assert(testRP, testOrigin, testChallenge)); err != nil {
				t.Fatalf("valid assertion refused: %v", err)
			}
			otherChallenge := sha256.Sum256([]byte("another request"))
			for _, tc := range []struct {
				name string
				a    webauthn.Assertion
				want error
			}{
				{"uv_cleared", auth.Assert(testRP, testOrigin, testChallenge, webauthntest.WithFlags(0x01)), webauthn.ErrUserVerification},
				{"up_cleared", auth.Assert(testRP, testOrigin, testChallenge, webauthntest.WithFlags(0x04)), webauthn.ErrUserPresence},
				{"wrong_rp", auth.Assert("other.example.org", testOrigin, testChallenge), webauthn.ErrRPMismatch},
				{"wrong_challenge", auth.Assert(testRP, testOrigin, otherChallenge), webauthn.ErrChallenge},
				{"wrong_origin", auth.Assert(testRP, "https://evil.example.org", testChallenge), webauthn.ErrOrigin},
				{"wrong_type", auth.Assert(testRP, testOrigin, testChallenge, webauthntest.WithType("webauthn.create")), webauthn.ErrType},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if err := webauthn.VerifyAssertion(cred, testRP, origins, testChallenge, tc.a); !errors.Is(err, tc.want) {
						t.Fatalf("VerifyAssertion = %v, want %v", err, tc.want)
					}
				})
			}
		})
	}
}

// TestWebAuthnSignatureAndCredential: a signature by another key and
// an assertion for another credential ID are refused.
func TestWebAuthnSignatureAndCredential(t *testing.T) {
	auth, other := newAuth(t, webauthn.AlgEdDSA), newAuth(t, webauthn.AlgEdDSA)
	cred := auth.Credential()
	a := other.Assert(testRP, testOrigin, testChallenge)
	a.CredentialID = cred.ID // the right ID, signed by the wrong key
	if err := webauthn.VerifyAssertion(cred, testRP, []string{testOrigin}, testChallenge, a); !errors.Is(err, webauthn.ErrSignature) {
		t.Fatalf("assertion signed by another key: %v, want ErrSignature", err)
	}
	if err := webauthn.VerifyAssertion(cred, testRP, []string{testOrigin}, testChallenge, other.Assert(testRP, testOrigin, testChallenge)); !errors.Is(err, webauthn.ErrCredentialID) {
		t.Fatalf("assertion for another credential: %v, want ErrCredentialID", err)
	}
}

// TestWebAuthnClientData: the token walk refuses duplicate names, wrong
// value types, invalid UTF-8 and trailing data, and skips unknown members.
func TestWebAuthnClientData(t *testing.T) {
	auth := newAuth(t, webauthn.AlgEdDSA)
	cred := auth.Credential()
	cdj := string(auth.Assert(testRP, testOrigin, testChallenge).ClientDataJSON)
	b64 := cdj[strings.Index(cdj, `"challenge":"`)+len(`"challenge":"`):]
	b64 = b64[:strings.Index(b64, `"`)]
	// The 43rd character of a 32-byte challenge carries two unused low
	// bits. Setting one gives another text for the same bytes, which only
	// the strict decoding refuses.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, b64[len(b64)-1])
	nonCanonical := b64[:len(b64)-1] + string(alphabet[last^1])
	if lax, err := base64.RawURLEncoding.DecodeString(nonCanonical); err != nil || !bytes.Equal(lax, testChallenge[:]) {
		t.Fatalf("lax decode of the non-canonical challenge = %x, %v; want the challenge bytes", lax, err)
	}
	for _, tc := range []struct {
		name string
		cd   string
		want error
	}{
		{"extra_member_skipped", `{"type":"webauthn.get","challenge":"` + b64 + `","origin":"` + testOrigin + `","crossOrigin":false,"other_keys_can_be_added_here":{"a":[1,2,{"b":null}]}}`, nil},
		{"duplicate_type", `{"type":"webauthn.get","type":"webauthn.get","challenge":"` + b64 + `","origin":"` + testOrigin + `"}`, webauthn.ErrClientData},
		{"type_not_string", `{"type":1,"challenge":"` + b64 + `","origin":"` + testOrigin + `"}`, webauthn.ErrClientData},
		{"cross_origin_not_bool", `{"type":"webauthn.get","challenge":"` + b64 + `","origin":"` + testOrigin + `","crossOrigin":"false"}`, webauthn.ErrClientData},
		{"trailing_data", `{"type":"webauthn.get","challenge":"` + b64 + `","origin":"` + testOrigin + `"}{}`, webauthn.ErrClientData},
		{"invalid_utf8", "{\"type\":\"webauthn.get\xff\",\"challenge\":\"" + b64 + `","origin":"` + testOrigin + `"}`, webauthn.ErrClientData},
		{"not_an_object", `["webauthn.get"]`, webauthn.ErrClientData},
		{"cross_origin_true", `{"type":"webauthn.get","challenge":"` + b64 + `","origin":"` + testOrigin + `","crossOrigin":true}`, webauthn.ErrCrossOrigin},
		{"top_origin_present", `{"type":"webauthn.get","challenge":"` + b64 + `","origin":"` + testOrigin + `","topOrigin":"https://x.example"}`, webauthn.ErrCrossOrigin},
		{"padded_challenge", `{"type":"webauthn.get","challenge":"` + b64 + `=","origin":"` + testOrigin + `"}`, webauthn.ErrChallenge},
		{"non_canonical_challenge", `{"type":"webauthn.get","challenge":"` + nonCanonical + `","origin":"` + testOrigin + `"}`, webauthn.ErrChallenge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := auth.Assert(testRP, testOrigin, testChallenge, webauthntest.WithClientDataJSON([]byte(tc.cd)))
			err := webauthn.VerifyAssertion(cred, testRP, []string{testOrigin}, testChallenge, a)
			if tc.want == nil && err != nil {
				t.Fatalf("VerifyAssertion = %v, want success", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("VerifyAssertion = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestWebAuthnParsePublicKey: each algorithm takes only its own key type,
// and RS256 needs at least 2048 bits.
func TestWebAuthnParsePublicKey(t *testing.T) {
	ed := newAuth(t, webauthn.AlgEdDSA).Credential().SPKI
	ec := newAuth(t, webauthn.AlgES256).Credential().SPKI
	if _, err := webauthn.ParsePublicKey(webauthn.AlgEdDSA, ed); err != nil {
		t.Fatalf("Ed25519 for EdDSA: %v", err)
	}
	if _, err := webauthn.ParsePublicKey(webauthn.AlgES256, ed); !errors.Is(err, webauthn.ErrPublicKey) {
		t.Fatalf("Ed25519 for ES256: %v, want ErrPublicKey", err)
	}
	if _, err := webauthn.ParsePublicKey(webauthn.AlgEdDSA, ec); !errors.Is(err, webauthn.ErrPublicKey) {
		t.Fatalf("P-256 for EdDSA: %v, want ErrPublicKey", err)
	}
	if _, err := webauthn.ParsePublicKey(-35, ec); !errors.Is(err, webauthn.ErrAlgorithm) {
		t.Fatalf("ES384: %v, want ErrAlgorithm", err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the point is a too-short key
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&small.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := webauthn.ParsePublicKey(webauthn.AlgRS256, spki); !errors.Is(err, webauthn.ErrPublicKey) {
		t.Fatalf("RSA-1024 for RS256: %v, want ErrPublicKey", err)
	}
	if fp := webauthn.Fingerprint(ed); !strings.HasPrefix(fp, "SHA256:") || strings.HasSuffix(fp, "=") {
		t.Fatalf("Fingerprint = %q, want SHA256: and unpadded base64", fp)
	}
}
