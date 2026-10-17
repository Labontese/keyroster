package webauthn

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// ClientDataExtraMembers is a clientDataJSON template (CHALLENGE and
// ORIGIN are replaced) with what browsers add besides type, challenge,
// origin and crossOrigin: Chrome's other_keys_can_be_added_here string, a
// tokenBinding object, an unknown array holding a nested object and
// literals, and an unknown object that itself contains "type" keys. It is
// exported to the external tests (client_data_extra_members_accepted) and
// seeds FuzzParseClientData.
const ClientDataExtraMembers = `{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":false,` +
	`"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex",` +
	`"tokenBinding":{"status":"not-supported"},` +
	`"x_list":[1,"two",{"three":3},true,null,[false]],` +
	`"x_object":{"type":"webauthn.create","nested":{"type":"webauthn.create"}}}`

const (
	fuzzRP     = "keyroster.localhost"
	fuzzOrigin = "https://keyroster.localhost"
)

// FuzzParseClientData (T-02-13, T-02-82): parseClientData never panics,
// refuses only with its sentinel, and accepts only one strict JSON object
// whose top-level type, challenge and origin it reports.
func FuzzParseClientData(f *testing.F) {
	ch := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	r := strings.NewReplacer("CHALLENGE", ch, "ORIGIN", fuzzOrigin)
	for _, s := range []string{
		`{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":false}`,
		ClientDataExtraMembers,
		`{"type":"webauthn.get","type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN"}`,
		`{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","crossOrigin":"false"}`,
		`{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN","topOrigin":"https://other.localhost"}`,
		`{"type":"webauthn.get","challenge":"CHALLENGE","origin":"ORIGIN"}{}`,
		"{\"type\":\"webauthn.get\xff\"}",
		`["webauthn.get"]`,
		`{}`,
		``,
	} {
		f.Add([]byte(r.Replace(s)))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cd, err := parseClientData(data)
		if err != nil {
			if !errors.Is(err, errClientDataSyntax) {
				t.Fatalf("parseClientData error = %v, want errClientDataSyntax", err)
			}
			return
		}
		if !json.Valid(data) {
			t.Fatalf("accepted clientDataJSON that is not valid JSON: %q", data)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatalf("accepted clientDataJSON that is not one JSON object: %v", err)
		}
		for name, got := range map[string]string{"type": cd.Type, "challenge": cd.Challenge, "origin": cd.Origin} {
			raw, ok := top[name]
			if !ok {
				if got != "" {
					t.Fatalf("%s reported as %q but absent", name, got)
				}
				continue
			}
			var want string
			if err := json.Unmarshal(raw, &want); err != nil || want != got {
				t.Fatalf("%s reported as %q, the document has %s", name, got, raw)
			}
		}
		if _, ok := top["topOrigin"]; ok != cd.HasTopOrigin {
			t.Fatalf("HasTopOrigin %v, topOrigin present %v", cd.HasTopOrigin, ok)
		}
	})
}

// FuzzVerifyAssertion (T-02-13): VerifyAssertion never panics, refuses
// only with its sentinels, and accepts a fuzzed assertion only when it is
// the unmodified one: a fixed EdDSA credential signed it over a fixed
// challenge.
func FuzzVerifyAssertion(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	spki, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		f.Fatal(err)
	}
	cred := Credential{ID: bytes.Repeat([]byte{0xc1}, 32), Alg: AlgEdDSA, SPKI: spki}
	challenge := sha256.Sum256([]byte("keyroster/login-request/v1 fuzz request"))
	rp := sha256.Sum256([]byte(fuzzRP))
	authData := append(rp[:], 0x05, 0, 0, 0, 0)
	clientData := []byte(`{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge[:]) +
		`","origin":"` + fuzzOrigin + `","crossOrigin":false}`)
	cdHash := sha256.Sum256(clientData)
	sig := ed25519.Sign(priv, append(append([]byte(nil), authData...), cdHash[:]...))
	if err := VerifyAssertion(cred, fuzzRP, []string{fuzzOrigin}, challenge, Assertion{cred.ID, authData, clientData, sig}); err != nil {
		f.Fatalf("the seed assertion does not verify: %v", err)
	}
	f.Add(cred.ID, authData, clientData, sig)
	f.Add(cred.ID, authData[:36], clientData, sig)
	f.Add(cred.ID, append(append([]byte(nil), authData[:32]...), 0x45, 0, 0, 0, 0), clientData, sig)
	f.Add(cred.ID, authData, []byte(strings.Replace(string(clientData), "webauthn.get", "webauthn.create", 1)), sig)
	f.Add([]byte{1}, authData, clientData, sig)
	f.Add(cred.ID, authData, clientData, []byte{})
	sentinels := []error{ErrCredentialID, ErrAuthenticatorData, ErrRPMismatch, ErrUserPresence, ErrUserVerification,
		ErrClientData, ErrType, ErrChallenge, ErrOrigin, ErrCrossOrigin, ErrSignature, ErrAlgorithm}
	f.Fuzz(func(t *testing.T, id, ad, cd, s []byte) {
		err := VerifyAssertion(cred, fuzzRP, []string{fuzzOrigin}, challenge, Assertion{id, ad, cd, s})
		if err == nil {
			if !bytes.Equal(id, cred.ID) || !bytes.Equal(ad, authData) || !bytes.Equal(cd, clientData) || !bytes.Equal(s, sig) {
				t.Fatalf("a modified assertion verified:\n id %x\n ad %x\n cd %q\n sig %x", id, ad, cd, s)
			}
			return
		}
		for _, want := range sentinels {
			if errors.Is(err, want) {
				return
			}
		}
		t.Fatalf("VerifyAssertion error = %v, want one of its sentinels", err)
	})
}
