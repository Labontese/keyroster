package webauthn_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strconv"
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

// TestWebAuthnMutationMatrix: every mutation of an otherwise valid
// assertion is refused with its own sentinel, for each algorithm the
// signer accepts, with the unmutated assertion verifying as the control.
func TestWebAuthnMutationMatrix(t *testing.T) {
	b64 := base64.RawURLEncoding.EncodeToString(testChallenge[:])
	cd := func(text string) webauthntest.Option {
		return webauthntest.WithClientDataJSON([]byte(strings.NewReplacer("CHALLENGE", b64, "ORIGIN", testOrigin).Replace(text)))
	}
	otherChallenge := sha256.Sum256([]byte("another request"))
	for _, alg := range []struct {
		name string
		alg  int64
	}{{"eddsa", webauthn.AlgEdDSA}, {"es256", webauthn.AlgES256}, {"rs256", webauthn.AlgRS256}} {
		t.Run(alg.name, func(t *testing.T) {
			auth := newAuth(t, alg.alg)
			cred := auth.Credential()
			origins := []string{testOrigin}
			valid := func(opts ...webauthntest.Option) webauthn.Assertion {
				return auth.Assert(testRP, testOrigin, testChallenge, opts...)
			}
			if err := webauthn.VerifyAssertion(cred, testRP, origins, testChallenge, valid()); err != nil {
				t.Fatalf("control: valid assertion refused: %v", err)
			}
			edit := func(a webauthn.Assertion, f func(*webauthn.Assertion)) webauthn.Assertion {
				a.AuthenticatorData = bytes.Clone(a.AuthenticatorData)
				a.Signature = bytes.Clone(a.Signature)
				f(&a)
				return a
			}
			for _, tc := range []struct {
				name string
				a    webauthn.Assertion
				want error
			}{
				// authenticatorData is exactly 37 bytes with AT and ED clear.
				{"auth_data_36_bytes", edit(valid(), func(a *webauthn.Assertion) { a.AuthenticatorData = a.AuthenticatorData[:36] }), webauthn.ErrAuthenticatorData},
				{"auth_data_38_bytes", edit(valid(), func(a *webauthn.Assertion) { a.AuthenticatorData = append(a.AuthenticatorData, 0) }), webauthn.ErrAuthenticatorData},
				{"at_flag_set", valid(webauthntest.WithFlags(0x45)), webauthn.ErrAuthenticatorData},
				{"ed_flag_set", valid(webauthntest.WithFlags(0x85)), webauthn.ErrAuthenticatorData},
				{"rp_mismatch", auth.Assert("other.example.org", testOrigin, testChallenge), webauthn.ErrRPMismatch},
				{"user_presence_missing", valid(webauthntest.WithFlags(0x04)), webauthn.ErrUserPresence},
				{"user_verification_missing", valid(webauthntest.WithFlags(0x01)), webauthn.ErrUserVerification},
				{"duplicate_type", valid(cd(`{"type":"webauthn.get","type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN"}`)), webauthn.ErrClientData},
				{"invalid_utf8", valid(cd("{\"type\":\"webauthn.get\xff\",\"challenge\":\"CHALLENGE\",\"origin\":\"ORIGIN\"}")), webauthn.ErrClientData},
				{"cross_origin_string_false", valid(cd(`{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":"false"}`)), webauthn.ErrClientData},
				{"trailing_data", valid(cd(`{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN"}{}`)), webauthn.ErrClientData},
				{"type_create", valid(webauthntest.WithType("webauthn.create")), webauthn.ErrType},
				{"challenge_mismatch", auth.Assert(testRP, testOrigin, otherChallenge), webauthn.ErrChallenge},
				{"origin_http_scheme", auth.Assert(testRP, "http://keyroster.example.org", testChallenge), webauthn.ErrOrigin},
				{"origin_other_host", auth.Assert(testRP, "https://other.example.org", testChallenge), webauthn.ErrOrigin},
				{"origin_extra_port", auth.Assert(testRP, testOrigin+":8443", testChallenge), webauthn.ErrOrigin},
				{"cross_origin_true", valid(cd(`{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":true}`)), webauthn.ErrCrossOrigin},
				{"top_origin_present", valid(cd(`{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":false,"topOrigin":"https://other.example.org"}`)), webauthn.ErrCrossOrigin},
				{"signature_bit_flipped", edit(valid(), func(a *webauthn.Assertion) { a.Signature[len(a.Signature)/2] ^= 0x01 }), webauthn.ErrSignature},
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

// TestWebAuthnClientDataExtraMembers (T-02-82): unknown clientDataJSON
// members of any JSON type (webauthn.ClientDataExtraMembers) are skipped, and a nested "type" key neither
// counts as a duplicate nor overrides the top-level one, for each
// algorithm. The same JSON with the top-level type duplicated is still
// refused (control).
func TestWebAuthnClientDataExtraMembers(t *testing.T) {
	r := strings.NewReplacer("CHALLENGE", base64.RawURLEncoding.EncodeToString(testChallenge[:]), "ORIGIN", testOrigin)
	accepted := r.Replace(webauthn.ClientDataExtraMembers)
	duplicated := strings.TrimSuffix(accepted, "}") + `,"type":"webauthn.get"}`
	for _, alg := range []struct {
		name string
		alg  int64
	}{{"eddsa", webauthn.AlgEdDSA}, {"es256", webauthn.AlgES256}, {"rs256", webauthn.AlgRS256}} {
		t.Run(alg.name, func(t *testing.T) {
			auth := newAuth(t, alg.alg)
			cred := auth.Credential()
			t.Run("client_data_extra_members_accepted", func(t *testing.T) {
				a := auth.Assert(testRP, testOrigin, testChallenge, webauthntest.WithClientDataJSON([]byte(accepted)))
				if err := webauthn.VerifyAssertion(cred, testRP, []string{testOrigin}, testChallenge, a); err != nil {
					t.Fatalf("clientDataJSON with extra members refused: %v", err)
				}
			})
			t.Run("top_level_type_duplicated_refused", func(t *testing.T) {
				a := auth.Assert(testRP, testOrigin, testChallenge, webauthntest.WithClientDataJSON([]byte(duplicated)))
				if err := webauthn.VerifyAssertion(cred, testRP, []string{testOrigin}, testChallenge, a); !errors.Is(err, webauthn.ErrClientData) {
					t.Fatalf("duplicated top-level type: %v, want ErrClientData", err)
				}
			})
		})
	}
}

// TestWebAuthnParsePublicKeyRefusals: ES256 takes only P-256 and RS256
// only RSA keys of at least 2048 bits, each with a control.
func TestWebAuthnParsePublicKeyRefusals(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := webauthn.ParsePublicKey(webauthn.AlgES256, spki); !errors.Is(err, webauthn.ErrPublicKey) {
		t.Fatalf("P-384 for ES256: %v, want ErrPublicKey", err)
	}
	if _, err := webauthn.ParsePublicKey(webauthn.AlgES256, newAuth(t, webauthn.AlgES256).Credential().SPKI); err != nil {
		t.Fatalf("control: P-256 for ES256: %v", err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the point is a too-short key
	if err != nil {
		t.Fatal(err)
	}
	if spki, err = x509.MarshalPKIXPublicKey(&small.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := webauthn.ParsePublicKey(webauthn.AlgRS256, spki); !errors.Is(err, webauthn.ErrPublicKey) {
		t.Fatalf("RSA-1024 for RS256: %v, want ErrPublicKey", err)
	}
	if _, err := webauthn.ParsePublicKey(webauthn.AlgRS256, newAuth(t, webauthn.AlgRS256).Credential().SPKI); err != nil {
		t.Fatalf("control: RSA-2048 for RS256: %v", err)
	}
}

// rsaSPKI is the SPKI DER of an RSA public key whose modulus is a random
// odd number of exactly bits bits and whose exponent is e. It has no
// private key: the bounds are checked before anything uses the key.
func rsaSPKI(t *testing.T, bits, e int) []byte {
	t.Helper()
	buf := make([]byte, (bits+7)/8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	n := new(big.Int).SetBytes(buf)
	for i := bits; i < len(buf)*8; i++ {
		n.SetBit(n, i, 0)
	}
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)
	spki, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: e})
	if err != nil {
		t.Fatalf("marshal a %d-bit key with e=%d: %v", bits, e, err)
	}
	return spki
}

// TestWebAuthnRSABounds (owner hardening H2, 2026-10-21): RS256 takes only
// a modulus of 2048 to 4096 bits and the exponent 65537. go-webauthn
// v0.18.2 puts no upper bound on an RSA credential key, and verifying
// even a garbage signature under a 64k-bit modulus costs a noticeable
// fraction of a second, so the shared verifier bounds it at registration
// (the server) and at login (the signer) alike.
func TestWebAuthnRSABounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		bits int
		e    int
		ok   bool
	}{
		{"rsa1024", 1024, 65537, false},
		{"rsa2047", 2047, 65537, false},
		{"rsa2048", 2048, 65537, true},
		{"rsa3072", 3072, 65537, true},
		{"rsa4096", 4096, 65537, true},
		{"rsa4097", 4097, 65537, false},
		{"rsa8192", 8192, 65537, false},
		{"rsa65536_huge", 65536, 65537, false},
		{"exponent_3", 2048, 3, false},
		{"exponent_65539", 2048, 65539, false},
		{"exponent_2_pow_31_minus_1", 2048, 1<<31 - 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := webauthn.ParsePublicKey(webauthn.AlgRS256, rsaSPKI(t, tc.bits, tc.e))
			if tc.ok && err != nil {
				t.Fatalf("ParsePublicKey = %v, want accepted", err)
			}
			if !tc.ok && !errors.Is(err, webauthn.ErrPublicKey) {
				t.Fatalf("ParsePublicKey = %v, want ErrPublicKey", err)
			}
		})
	}
	// At login the bound holds before any signature work: a credential
	// with an 8192-bit or a 64k-bit key fails as ErrPublicKey, not as a
	// signature that did not verify.
	for _, bits := range []int{8192, 65536} {
		t.Run("login_refuses_"+strconv.Itoa(bits), func(t *testing.T) {
			auth := newAuth(t, webauthn.AlgRS256)
			cred := auth.Credential()
			cred.SPKI = rsaSPKI(t, bits, 65537)
			err := webauthn.VerifyAssertion(cred, testRP, []string{testOrigin}, testChallenge, auth.Assert(testRP, testOrigin, testChallenge))
			if !errors.Is(err, webauthn.ErrSignature) || !errors.Is(err, webauthn.ErrPublicKey) {
				t.Fatalf("VerifyAssertion = %v, want ErrSignature wrapping ErrPublicKey", err)
			}
		})
	}
}
