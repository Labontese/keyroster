package server

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"

	"github.com/Labontese/keyroster/internal/server/servertest"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// The oracle's relying party: the same RP ID and origins for both
// verifiers.
const (
	oracleRP     = "keyroster.example.org"
	oracleOrigin = "https://keyroster.example.org"
)

// oracleVector is one assertion and how it was made.
type oracleVector struct {
	name string // mutation name, without the algorithm
	cred webauthn.Credential
	cose []byte
	a    webauthn.Assertion
}

// bothRefuse are the mutations of the 02-03 matrix that internal/webauthn
// and go-webauthn both refuse.
var bothRefuse = []string{
	"signature_bit_flip",
	"wrong_challenge",
	"wrong_origin",
	"wrong_rp_id_hash",
	"uv_clear",
	"up_clear",
	"wrong_type",
	// go-webauthn with the production setting allowCrossOrigin=false
	// refuses crossOrigin true itself (protocol/client.go), and a
	// topOrigin without crossOrigin true. The plan predicted both in
	// strictOnly; the runs put them here.
	"cross_origin_true",
	"top_origin_present",
	// go-webauthn compares the challenge text exactly, so a padded or a
	// non-canonical text of the right bytes fails there too.
	"padded_challenge",
	"non_canonical_challenge",
	"trailing_client_data",
	// The rest of the 02-03 matrix (TestWebAuthnMutationMatrix), added at
	// the pre-merge review, and two malformed clientDataJSON shapes.
	"auth_data_36_bytes",
	"auth_data_38_bytes",
	"at_flag_set_without_data",
	"ed_flag_set_without_data",
	"invalid_utf8",
	"cross_origin_string_false",
	"origin_http_scheme",
	"origin_other_host",
	"origin_extra_port",
	"type_not_string",
	"client_data_not_an_object",
}

// strictOnly are the mutations go-webauthn accepts and internal/webauthn
// deliberately refuses. Each is a choice in the signer's verifier, not a
// gap in go-webauthn's.
var strictOnly = []string{
	// AT set, with attested credential data appended to the
	// authenticatorData: the signer accepts only the 37-byte form with AT
	// and ED clear, so it never parses CBOR (D-17).
	"at_set_with_attested_data",
	// ED set with an extensions map: no extension is requested at login,
	// and refusing the flag keeps CBOR out of the signer.
	"ed_set_with_extension",
	// A duplicate member in clientDataJSON: encoding/json in go-webauthn
	// keeps the last one; the signer's token walk refuses any duplicate,
	// so one text cannot be read two ways.
	"duplicate_type_member",
	// The same, with both members "webauthn.get" (02-03's duplicate_type):
	// go-webauthn reads the one value it sees; the signer refuses the
	// duplicate itself.
	"duplicate_type_same_value",
}

// oursOnly are the vectors internal/webauthn accepts and go-webauthn
// refuses. Each is one where internal/webauthn follows the spec and
// go-webauthn reads more into clientDataJSON than the spec does, and none
// is exploitable: the signature covers clientDataJSON, so the
// authenticator signed exactly these bytes.
var oursOnly = []string{
	// tokenBinding is a member the client may add; WebAuthn L3 tells
	// relying parties to ignore it (no token binding is used), and
	// internal/webauthn skips it as an extra member. go-webauthn validates
	// its shape and status.
	"token_binding_bogus_status",
	"token_binding_no_status",
	"token_binding_string",
	// A member whose name differs from origin, challenge or type only by
	// case is an extra member to internal/webauthn, which matches member
	// names exactly as the spec's JSON does. encoding/json in go-webauthn
	// matches names case-insensitively, so the later member overrides the
	// real one there and its check fails.
	"case_variant_origin_member",
	"case_variant_challenge_member",
	"case_variant_type_member",
}

// bothAccept are the vectors both accept.
var bothAccept = []string{"valid", "extra_client_data_member"}

// oracleVectors builds every mutation for one soft authenticator.
func oracleVectors(t *testing.T, alg int64) []oracleVector {
	t.Helper()
	auth := newAuthenticator(t, alg)
	cred := auth.Credential()
	pub, err := x509.ParsePKIXPublicKey(cred.SPKI)
	if err != nil {
		t.Fatal(err)
	}
	cose, err := servertest.COSEKey(alg, pub)
	if err != nil {
		t.Fatal(err)
	}
	ch := sha256.Sum256([]byte("oracle challenge"))
	other := sha256.Sum256([]byte("another challenge"))
	b64 := base64.RawURLEncoding.EncodeToString(ch[:])
	cd := func(rest string) webauthntest.Option {
		return webauthntest.WithClientDataJSON([]byte(`{"type":"webauthn.get","challenge":"` + b64 + `","origin":"` + oracleOrigin + `"` + rest + `}`))
	}
	// The 43rd character of a 32-byte challenge carries two unused bits.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := slices.Index([]byte(alphabet), b64[len(b64)-1])
	nonCanonical := b64[:len(b64)-1] + string(alphabet[last^1])

	attested := make([]byte, 16)                                             // AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(cred.ID))) //nolint:gosec // G115: a 32-byte soft credential ID
	attested = append(append(attested, cred.ID...), cose...)
	ext, err := webauthncbor.Marshal(map[string]any{"credProtect": 2})
	if err != nil {
		t.Fatal(err)
	}

	mk := func(name string, a webauthn.Assertion) oracleVector {
		return oracleVector{name: name, cred: cred, cose: cose, a: a}
	}
	flipped := auth.Assert(oracleRP, oracleOrigin, ch)
	flipped.Signature = append([]byte(nil), flipped.Signature...)
	flipped.Signature[len(flipped.Signature)/2] ^= 0x01
	return []oracleVector{
		mk("valid", auth.Assert(oracleRP, oracleOrigin, ch)),
		mk("extra_client_data_member", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"crossOrigin":false,"other_keys_can_be_added_here":"x"`))),
		mk("signature_bit_flip", flipped),
		mk("wrong_challenge", auth.Assert(oracleRP, oracleOrigin, other)),
		mk("wrong_origin", auth.Assert(oracleRP, "https://evil.example.org", ch)),
		mk("wrong_rp_id_hash", auth.Assert("other.example.org", oracleOrigin, ch)),
		mk("uv_clear", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithFlags(0x01))),
		mk("up_clear", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithFlags(0x04))),
		mk("wrong_type", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithType("webauthn.create"))),
		mk("cross_origin_true", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"crossOrigin":true`))),
		mk("top_origin_present", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"topOrigin":"https://top.example.org"`))),
		mk("padded_challenge", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithClientDataJSON(
			[]byte(`{"type":"webauthn.get","challenge":"`+b64+`=","origin":"`+oracleOrigin+`"}`)))),
		mk("non_canonical_challenge", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithClientDataJSON(
			[]byte(`{"type":"webauthn.get","challenge":"`+nonCanonical+`","origin":"`+oracleOrigin+`"}`)))),
		mk("trailing_client_data", auth.Assert(oracleRP, oracleOrigin, ch, cd(`}{`))),
		mk("at_set_with_attested_data", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithFlags(0x45), webauthntest.WithAuthDataSuffix(attested))),
		mk("ed_set_with_extension", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithFlags(0x85), webauthntest.WithAuthDataSuffix(ext))),
		mk("duplicate_type_member", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithClientDataJSON(
			[]byte(`{"type":"webauthn.create","type":"webauthn.get","challenge":"`+b64+`","origin":"`+oracleOrigin+`"}`)))),
		mk("duplicate_type_same_value", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithClientDataJSON(
			[]byte(`{"type":"webauthn.get","type":"webauthn.get","challenge":"`+b64+`","origin":"`+oracleOrigin+`"}`)))),
		mk("auth_data_36_bytes", editAssertion(auth.Assert(oracleRP, oracleOrigin, ch), func(a *webauthn.Assertion) { a.AuthenticatorData = a.AuthenticatorData[:36] })),
		mk("auth_data_38_bytes", editAssertion(auth.Assert(oracleRP, oracleOrigin, ch), func(a *webauthn.Assertion) { a.AuthenticatorData = append(a.AuthenticatorData, 0) })),
		mk("at_flag_set_without_data", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithFlags(0x45))),
		mk("ed_flag_set_without_data", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithFlags(0x85))),
		mk("invalid_utf8", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithClientDataJSON(
			[]byte("{\"type\":\"webauthn.get\xff\",\"challenge\":\""+b64+"\",\"origin\":\""+oracleOrigin+"\"}")))),
		mk("cross_origin_string_false", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"crossOrigin":"false"`))),
		mk("origin_http_scheme", auth.Assert(oracleRP, "http://keyroster.example.org", ch)),
		mk("origin_other_host", auth.Assert(oracleRP, "https://other.example.org", ch)),
		mk("origin_extra_port", auth.Assert(oracleRP, oracleOrigin+":8443", ch)),
		mk("type_not_string", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithClientDataJSON(
			[]byte(`{"type":1,"challenge":"`+b64+`","origin":"`+oracleOrigin+`"}`)))),
		mk("client_data_not_an_object", auth.Assert(oracleRP, oracleOrigin, ch, webauthntest.WithClientDataJSON([]byte(`[]`)))),
		mk("token_binding_bogus_status", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"tokenBinding":{"status":"bogus"}`))),
		mk("token_binding_no_status", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"tokenBinding":{}`))),
		mk("token_binding_string", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"tokenBinding":"present"`))),
		mk("case_variant_origin_member", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"Origin":"https://evil.example.org"`))),
		mk("case_variant_challenge_member", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"CHALLENGE":"`+base64.RawURLEncoding.EncodeToString(other[:])+`"`))),
		mk("case_variant_type_member", auth.Assert(oracleRP, oracleOrigin, ch, cd(`,"Type":"webauthn.create"`))),
	}
}

// editAssertion returns a with its byte slices copied and f applied.
func editAssertion(a webauthn.Assertion, f func(*webauthn.Assertion)) webauthn.Assertion {
	a.AuthenticatorData = append([]byte(nil), a.AuthenticatorData...)
	a.Signature = append([]byte(nil), a.Signature...)
	f(&a)
	return a
}

// goWebAuthnVerify verifies a with go-webauthn: the JSON a browser posts,
// parsed with ParseCredentialRequestResponseBytes, then
// ParsedCredentialAssertionData.Verify with the production settings (UV
// and UP required, no cross-origin, explicit top-origin mode, DER ECDSA
// signatures, no appid) and the credential's COSE key.
func goWebAuthnVerify(v oracleVector, challenge [32]byte) error {
	enc := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    enc(v.a.CredentialID),
		"rawId": enc(v.a.CredentialID),
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": enc(v.a.AuthenticatorData),
			"clientDataJSON":    enc(v.a.ClientDataJSON),
			"signature":         enc(v.a.Signature),
		},
		"clientExtensionResults": map[string]any{},
	})
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	return parsed.Verify(enc(challenge[:]), oracleRP, "", []string{oracleOrigin}, nil, nil,
		protocol.TopOriginExplicitVerificationMode, false, true, true, v.cose,
		protocol.SignaturePolicy{ECDSAEncoding: protocol.ECDSASignatureEncodingDER})
}

// TestWebAuthnOracle is the differential test of the signer's verifier
// against go-webauthn's assertion verification: the same vectors, each
// algorithm and each mutation, the same relying party and origins. Over
// these vectors, the two disagree exactly on the strictOnly list and on
// the oursOnly list, whose every entry is a spec-conforming
// clientDataJSON that go-webauthn over-reads; any other vector accepted
// by internal/webauthn and refused by go-webauthn fails the test. The
// claim covers the listed vectors only.
func TestWebAuthnOracle(t *testing.T) {
	challenge := sha256.Sum256([]byte("oracle challenge"))
	for _, alg := range []int64{webauthn.AlgEdDSA, webauthn.AlgES256, webauthn.AlgRS256} {
		t.Run(servertest.Algorithm(alg), func(t *testing.T) {
			got := map[string][]string{}
			for _, v := range oracleVectors(t, alg) {
				ours := webauthn.VerifyAssertion(v.cred, oracleRP, []string{oracleOrigin}, challenge, v.a)
				theirs := goWebAuthnVerify(v, challenge)
				switch {
				case ours == nil && theirs != nil:
					if !slices.Contains(oursOnly, v.name) {
						t.Errorf("%s: accepted by internal/webauthn, refused by go-webauthn (%v)", v.name, theirs)
					}
					got["ours_only"] = append(got["ours_only"], v.name)
				case ours == nil:
					got["both_accept"] = append(got["both_accept"], v.name)
				case theirs == nil:
					got["strict_only"] = append(got["strict_only"], v.name)
				default:
					got["both_refuse"] = append(got["both_refuse"], v.name)
				}
				t.Logf("%-28s internal/webauthn: %v | go-webauthn: %v", v.name, ours, theirs)
			}
			for _, c := range []struct {
				class string
				want  []string
			}{{"both_accept", bothAccept}, {"both_refuse", bothRefuse}, {"strict_only", strictOnly}, {"ours_only", oursOnly}} {
				g, w := slices.Clone(got[c.class]), slices.Clone(c.want)
				sort.Strings(g)
				sort.Strings(w)
				if !slices.Equal(g, w) {
					t.Errorf("%s = %v, want %v", c.class, g, w)
				}
			}
		})
	}
}
