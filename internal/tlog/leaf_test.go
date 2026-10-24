package tlog

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"

	"github.com/Labontese/keyroster/internal/wire"
)

var update = flag.Bool("update", false, "rewrite the golden vectors in test/vectors")

// vectorPath returns the path of a file in the repository's test/vectors.
func vectorPath(name string) string { return filepath.Join("..", "..", "test", "vectors", name) }

// golden compares got with the named golden file, or rewrites the file
// when -update is set.
func readGolden(t testing.TB, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(vectorPath(name)) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatalf("golden vector %s: %v (run go test -run %s -update to create it)", name, err, t.Name())
	}
	return data
}

func writeGolden(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(vectorPath(name), data, 0o644); err != nil { //nolint:gosec // G306: public test vector
		t.Fatal(err)
	}
}

// issueVector is the fixed issue leaf of test/vectors/leaf_issue_v1.hex.
func issueVector(t testing.TB) (Leaf, *IssueBody) {
	t.Helper()
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i)
	}
	body := &IssueBody{
		CARole:        uint8(wire.CARoleUser),
		Serial:        1_700_000_000_000_001,
		PolicyVersion: 0,
		RequestDigest: digest,
		Evidence:      []wire.Evidence{{Type: "admin-sshsig/v1", Blob: []byte("sig")}},
		Cert:          []byte("certificate bytes (test vector)"),
		KeyID:         "kr1/ca=user/sub=u:alice/req=000102030405060708090a0b0c0d0e0f/pol=0/ser=1700000000000001",
	}
	enc, err := body.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{Index: 7, TimeMicros: 1_700_000_000_000_002, Kind: KindIssue, Body: enc}, body
}

// TestLeafIssueVector pins the v1 issue-leaf encoding and checks it with a
// decoder written against the format description, not DecodeLeaf.
func TestLeafIssueVector(t *testing.T) {
	leaf, body := issueVector(t)
	got := EncodeLeaf(leaf)
	if *update {
		writeGolden(t, "leaf_issue_v1.hex", []byte(hex.EncodeToString(got)+"\n"))
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(readGolden(t, "leaf_issue_v1.hex"))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeLeaf differs from test/vectors/leaf_issue_v1.hex:\n got %x\nwant %x", got, want)
	}

	// Independent decode, by offsets.
	p := want
	take := func(n int) []byte {
		t.Helper()
		if len(p) < n {
			t.Fatalf("vector too short")
		}
		out := p[:n]
		p = p[n:]
		return out
	}
	u16 := func() int { return int(binary.BigEndian.Uint16(take(2))) }
	u24 := func() int { b := take(3); return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }
	if n := int(take(1)[0]); string(take(n)) != "keyroster/log-leaf/v1" {
		t.Fatal("domain tag")
	}
	if binary.BigEndian.Uint64(take(8)) != 7 || binary.BigEndian.Uint64(take(8)) != 1_700_000_000_000_002 {
		t.Fatal("index or time")
	}
	if take(1)[0] != 1 {
		t.Fatal("kind")
	}
	if u24() != len(p) {
		t.Fatal("body length")
	}
	if take(1)[0] != 1 || binary.BigEndian.Uint64(take(8)) != body.Serial || binary.BigEndian.Uint64(take(8)) != 0 {
		t.Fatal("role, serial or policy")
	}
	if !bytes.Equal(take(32), body.RequestDigest[:]) {
		t.Fatal("request digest")
	}
	ev := take(u24())
	if !bytes.Equal(ev, []byte("\x00\x0fadmin-sshsig/v1\x00\x03sig")) {
		t.Fatalf("evidence %q", ev)
	}
	if string(take(u24())) != string(body.Cert) {
		t.Fatal("cert")
	}
	if string(take(u16())) != body.KeyID {
		t.Fatal("key id")
	}
	if len(p) != 0 {
		t.Fatalf("%d trailing bytes", len(p))
	}

	dec, err := DecodeLeaf(want)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Index != 7 || dec.Kind != KindIssue || !bytes.Equal(dec.Body, leaf.Body) {
		t.Fatalf("DecodeLeaf = %+v", dec)
	}
}

func TestLeafBodiesRoundTrip(t *testing.T) {
	_, issue := issueVector(t)
	refusal := &RefusalBody{PeerUID: 1000, Reason: ReasonBadPrincipal, Detail: "bad_principal"}
	summary := &RefusalSummaryBody{WindowStartMicros: 1, WindowEndMicros: 60_000_001,
		Counts: []ReasonCount{{ReasonPeerNotAllowed, 990}, {ReasonMalformed, 3}}}
	clock := &ClockRegressionBody{NowMicros: 5, HighWaterMicros: 9}
	caInit := &CAInitBody{Keys: []CAInitKey{{Role: "user", PublicKey: []byte{1, 2}, Alg: "ssh-ed25519", Custody: "agent"}}}
	bundle := &BundleInstallBody{BundleVersion: 1, Bundle: []byte("b"), BundleSigs: []byte("bs"), Policy: []byte("p"), PolicySigs: []byte("ps")}
	type encoder interface{ Encode() ([]byte, error) }
	cases := []struct {
		kind   Kind
		body   encoder
		decode func([]byte) (encoder, error)
	}{
		{KindIssue, issue, func(b []byte) (encoder, error) { return DecodeIssueBody(b) }},
		{KindRefusal, refusal, func(b []byte) (encoder, error) { return DecodeRefusalBody(b) }},
		{KindRefusalSummary, summary, func(b []byte) (encoder, error) { return DecodeRefusalSummaryBody(b) }},
		{KindClockRegression, clock, func(b []byte) (encoder, error) { return DecodeClockRegressionBody(b) }},
		{KindCAInit, caInit, func(b []byte) (encoder, error) { return DecodeCAInitBody(b) }},
		{KindBundleInstall, bundle, func(b []byte) (encoder, error) { return DecodeBundleInstallBody(b) }},
	}
	for _, tc := range cases {
		t.Run(tc.kind.String(), func(t *testing.T) {
			enc, err := tc.body.Encode()
			if err != nil {
				t.Fatal(err)
			}
			dec, err := tc.decode(enc)
			if err != nil {
				t.Fatal(err)
			}
			again, err := dec.Encode()
			if err != nil || !bytes.Equal(again, enc) {
				t.Fatalf("re-encode differs: %v", err)
			}
			raw := EncodeLeaf(Leaf{Index: 1, TimeMicros: 2, Kind: tc.kind, Body: enc})
			l, err := DecodeLeaf(raw)
			if err != nil || l.Kind != tc.kind {
				t.Fatalf("DecodeLeaf = %+v, %v", l, err)
			}
			if _, err := tc.decode(append(enc, 0)); !errors.Is(err, ErrMalformedLeaf) {
				t.Fatalf("trailing byte: %v", err)
			}
		})
	}
}

func TestDecodeLeafStrict(t *testing.T) {
	good, _ := issueVector(t)
	raw := EncodeLeaf(good)
	refusal, err := (&RefusalBody{Reason: ReasonMalformed}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":            nil,
		"trailing_byte":    append(append([]byte(nil), raw...), 0),
		"truncated":        raw[:len(raw)-1],
		"wrong_domain":     append([]byte{21}, append([]byte("keyroster/log-leaf/v2"), raw[22:]...)...),
		"unknown_kind":     rawKindLeaf(t, Leaf{Kind: KindKRLPublish + 1, Body: refusal}),
		"body_of_another":  EncodeLeaf(Leaf{Kind: KindIssue, Body: refusal}),
		"summary_no_count": EncodeLeaf(Leaf{Kind: KindRefusalSummary, Body: make([]byte, 18)}),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLeaf(data); !errors.Is(err, ErrMalformedLeaf) {
				t.Fatalf("DecodeLeaf error = %v, want ErrMalformedLeaf", err)
			}
		})
	}
}

// rawKindLeaf builds leaf bytes with an arbitrary kind byte, bypassing
// MarshalLeaf's kind check.
func rawKindLeaf(t *testing.T, l Leaf) []byte {
	t.Helper()
	if _, err := MarshalLeaf(l); err == nil {
		t.Fatalf("MarshalLeaf accepted kind %d", l.Kind)
	}
	valid := EncodeLeaf(Leaf{Index: l.Index, TimeMicros: l.TimeMicros, Kind: KindRefusal, Body: l.Body})
	off := 1 + len(LeafDomain) + 16
	valid[off] = byte(l.Kind)
	return valid
}

func TestRefusalSummaryCanonical(t *testing.T) {
	for name, b := range map[string]*RefusalSummaryBody{
		"zero_count":       {Counts: []ReasonCount{{ReasonMalformed, 0}}},
		"unordered":        {Counts: []ReasonCount{{ReasonMalformed, 1}, {ReasonPeerNotAllowed, 1}}},
		"duplicate_reason": {Counts: []ReasonCount{{ReasonMalformed, 1}, {ReasonMalformed, 1}}},
		"unknown_reason":   {Counts: []ReasonCount{{0, 1}}},
		"window_reversed":  {WindowStartMicros: 2, WindowEndMicros: 1, Counts: []ReasonCount{{ReasonMalformed, 1}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := b.Encode(); !errors.Is(err, ErrMalformedLeaf) {
				t.Fatalf("Encode error = %v, want ErrMalformedLeaf", err)
			}
		})
	}
}

// directoryInstallVector is the fixed directory_install leaf of
// test/vectors/leaf_directory_install_v1.hex.
func directoryInstallVector(t testing.TB) (Leaf, *DirectoryInstallBody) {
	t.Helper()
	body := &DirectoryInstallBody{
		Version:       1,
		PolicyVersion: 1,
		Directory:     []byte("directory bytes (test vector)"),
		Sigs:          []byte("sigs (test vector)"),
	}
	enc, err := body.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{Index: 8, TimeMicros: 1_700_000_000_000_004, Kind: KindDirectoryInstall, Body: enc}, body
}

// loginIssueVector is the fixed login_issue leaf of
// test/vectors/leaf_login_issue_v1.hex. Its request is the login request
// of test/vectors/login_request_signing_v1.hex, and its evidence blob a
// WebAuthnAssertion of literal bytes, so the leaf vector also pins the
// evidence-blob encoding.
func loginIssueVector(t testing.TB) (Leaf, *LoginIssueBody) {
	t.Helper()
	request, err := hex.DecodeString(strings.TrimSpace(string(readGolden(t, "login_request_signing_v1.hex"))))
	if err != nil {
		t.Fatal(err)
	}
	credID := make([]byte, 16)
	authData := make([]byte, 37)
	for i := range credID {
		credID[i] = byte(i + 1)
	}
	for i := range authData {
		authData[i] = byte(0xa0 + i)
	}
	blob, err := (&wire.WebAuthnAssertion{
		CredentialID:      credID,
		AuthenticatorData: authData,
		ClientDataJSON:    []byte(`{"type":"webauthn.get","challenge":"test-vector","origin":"https://keyroster.example.org","crossOrigin":false}`),
		Signature:         []byte("signature (test vector)"),
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body := &LoginIssueBody{
		Serial:           1_700_000_000_000_003,
		PolicyVersion:    2,
		DirectoryVersion: 1,
		Request:          request,
		Evidence:         []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: blob}},
		Cert:             []byte("certificate bytes (test vector)"),
		KeyID:            "kr2/ca=user/sub=alice/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=1/roles=admin+ops/ser=1700000000000003",
	}
	enc, err := body.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{Index: 9, TimeMicros: 1_700_000_000_000_005, Kind: KindLoginIssue, Body: enc}, body
}

// checkLeafVector compares the encoding of leaf with the named golden
// file (rewritten under -update) and decodes the file back with DecodeLeaf
// and decode, which must reproduce want.
func checkLeafVector(t *testing.T, name string, leaf Leaf, want any, decode func([]byte) (any, error)) {
	t.Helper()
	got, err := MarshalLeaf(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		writeGolden(t, name, []byte(hex.EncodeToString(got)+"\n"))
	}
	file, err := hex.DecodeString(strings.TrimSpace(string(readGolden(t, name))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, file) {
		t.Fatalf("%s differs from the fixture leaf\ngot:  %x\nwant: %x", name, got, file)
	}
	l, err := DecodeLeaf(file)
	if err != nil {
		t.Fatalf("DecodeLeaf(%s): %v", name, err)
	}
	if l.Kind != leaf.Kind || l.Index != leaf.Index || l.TimeMicros != leaf.TimeMicros {
		t.Fatalf("%s decodes to kind %s index %d time %d", name, l.Kind, l.Index, l.TimeMicros)
	}
	body, err := decode(l.Body)
	if err != nil {
		t.Fatalf("decode the body of %s: %v", name, err)
	}
	if !reflect.DeepEqual(body, want) {
		t.Fatalf("%s body decodes to %+v, want %+v", name, body, want)
	}
}

// TestDirectoryInstallLeafVector pins the kind-7 leaf encoding.
func TestDirectoryInstallLeafVector(t *testing.T) {
	leaf, body := directoryInstallVector(t)
	checkLeafVector(t, "leaf_directory_install_v1.hex", leaf, body, func(b []byte) (any, error) { return DecodeDirectoryInstallBody(b) })
}

// TestLoginIssueLeafVector pins the kind-8 leaf encoding, including the
// webauthn-assertion/v1 evidence blob.
func TestLoginIssueLeafVector(t *testing.T) {
	leaf, body := loginIssueVector(t)
	checkLeafVector(t, "leaf_login_issue_v1.hex", leaf, body, func(b []byte) (any, error) { return DecodeLoginIssueBody(b) })
}

// bodyCases runs the three cases every kind-7/8 body test shares:
// round_trip, trailing_byte_refused and decode_leaf_checks_body.
func bodyCases(t *testing.T, leaf Leaf, want any, decode func([]byte) (any, error)) {
	t.Run("round_trip", func(t *testing.T) {
		got, err := decode(leaf.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round trip: %+v, want %+v", got, want)
		}
		re, err := got.(interface{ Encode() ([]byte, error) }).Encode()
		if err != nil || !bytes.Equal(re, leaf.Body) {
			t.Fatalf("re-encoding differs (%v)", err)
		}
	})
	t.Run("trailing_byte_refused", func(t *testing.T) {
		if _, err := decode(append(bytes.Clone(leaf.Body), 0)); !errors.Is(err, ErrMalformedLeaf) {
			t.Fatalf("decode with a trailing byte = %v, want ErrMalformedLeaf", err)
		}
	})
	t.Run("decode_leaf_checks_body", func(t *testing.T) {
		enc, err := MarshalLeaf(leaf)
		if err != nil {
			t.Fatal(err)
		}
		l, err := DecodeLeaf(enc)
		if err != nil {
			t.Fatalf("DecodeLeaf of a valid %s leaf: %v", leaf.Kind, err)
		}
		if again := EncodeLeaf(l); !bytes.Equal(again, enc) {
			t.Fatal("the leaf does not re-encode to the same bytes")
		}
		cut := leaf
		cut.Body = leaf.Body[:len(leaf.Body)-1]
		bad, err := MarshalLeaf(cut)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeLeaf(bad); !errors.Is(err, ErrMalformedLeaf) {
			t.Fatalf("DecodeLeaf of a %s leaf with its body cut by one byte = %v, want ErrMalformedLeaf", leaf.Kind, err)
		}
	})
}

// TestDirectoryInstallBody covers the kind-7 body decoder.
func TestDirectoryInstallBody(t *testing.T) {
	leaf, body := directoryInstallVector(t)
	bodyCases(t, leaf, body, func(b []byte) (any, error) { return DecodeDirectoryInstallBody(b) })
	if _, err := (&DirectoryInstallBody{Version: 1, Directory: []byte("d")}).Encode(); !errors.Is(err, ErrMalformedLeaf) {
		t.Fatalf("a body without signatures encodes: %v", err)
	}
}

// TestLoginIssueBody covers the kind-8 body decoder.
func TestLoginIssueBody(t *testing.T) {
	leaf, body := loginIssueVector(t)
	bodyCases(t, leaf, body, func(b []byte) (any, error) { return DecodeLoginIssueBody(b) })
	if _, err := (&LoginIssueBody{Serial: 1, Cert: []byte("c"), KeyID: "k"}).Encode(); !errors.Is(err, ErrMalformedLeaf) {
		t.Fatalf("a body without the request encodes: %v", err)
	}
	if _, err := (&LoginIssueBody{Serial: 1, Request: make([]byte, MaxRequest+1), Cert: []byte("c"), KeyID: "k"}).Encode(); !errors.Is(err, ErrMalformedLeaf) {
		t.Fatalf("a request above MaxRequest encodes: %v", err)
	}
}

// TestDirectoryLimitsMatchWire: every directory and signature set that
// fits the wire messages (InstallDirectory, GetDirectoryResponse) fits a
// directory_install leaf, and no larger one does.
func TestDirectoryLimitsMatchWire(t *testing.T) {
	if wire.MaxDirectory != MaxDocument || wire.MaxDirectorySigs != MaxSigs {
		t.Fatalf("wire.MaxDirectory %d, wire.MaxDirectorySigs %d; want tlog.MaxDocument %d and tlog.MaxSigs %d",
			wire.MaxDirectory, wire.MaxDirectorySigs, MaxDocument, MaxSigs)
	}
}

// revokeVector is the fixed revoke leaf of test/vectors/leaf_revoke_v1.hex.
// Its request is the revoke request of
// test/vectors/revoke_request_signing_v1.hex and its entry a serial under
// a literal CA key blob.
func revokeVector(t testing.TB) (Leaf, *RevokeBody) {
	t.Helper()
	request, err := hex.DecodeString(strings.TrimSpace(string(readGolden(t, "revoke_request_signing_v1.hex"))))
	if err != nil {
		t.Fatal(err)
	}
	body := &RevokeBody{
		PolicyVersion:     3,
		ResolvedAtSeconds: 1_700_000_000,
		Request:           request,
		Evidence:          []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("sig")}},
		Entries: []RevokedEntry{{
			Kind:               RevokedSerial,
			CAKey:              []byte("ca key (test vector)"),
			Serial:             1_700_000_000_000_001,
			ValidBeforeSeconds: 1_700_003_600,
		}},
	}
	enc, err := body.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{Index: 10, TimeMicros: 1_700_000_000_000_006, Kind: KindRevoke, Body: enc}, body
}

// krlPublishVector is the fixed krl_publish leaf of
// test/vectors/leaf_krl_publish_v1.hex.
func krlPublishVector(t testing.TB) (Leaf, *KRLPublishBody) {
	t.Helper()
	var sum [32]byte
	for i := range sum {
		sum[i] = byte(0xc0 + i)
	}
	body := &KRLPublishBody{
		KRLVersion:      1,
		BundleVersion:   4,
		IssuedAtSeconds: 1_700_000_000,
		SHA256:          sum,
		Manifest:        []byte("manifest (test vector)"),
		Sig:             []byte("sig (test vector)"),
	}
	enc, err := body.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return Leaf{Index: 11, TimeMicros: 1_700_000_000_000_006, Kind: KindKRLPublish, Body: enc}, body
}

// TestRevokeLeafVector pins the kind-9 leaf encoding, ResolvedAtSeconds
// included (F9: 03-03's audit rule needs no format change).
func TestRevokeLeafVector(t *testing.T) {
	leaf, body := revokeVector(t)
	checkLeafVector(t, "leaf_revoke_v1.hex", leaf, body, func(b []byte) (any, error) { return DecodeRevokeBody(b) })
}

// TestKRLPublishLeafVector pins the kind-10 leaf encoding.
func TestKRLPublishLeafVector(t *testing.T) {
	leaf, body := krlPublishVector(t)
	checkLeafVector(t, "leaf_krl_publish_v1.hex", leaf, body, func(b []byte) (any, error) { return DecodeKRLPublishBody(b) })
}

// TestRevokeBody covers the kind-9 body decoder.
func TestRevokeBody(t *testing.T) {
	leaf, body := revokeVector(t)
	bodyCases(t, leaf, body, func(b []byte) (any, error) { return DecodeRevokeBody(b) })
	if KindRevoke != 9 || KindRevoke.String() != "revoke" {
		t.Fatalf("KindRevoke = %d %q", KindRevoke, KindRevoke)
	}
	for name, b := range map[string]*RevokeBody{
		"no_request":         {Entries: body.Entries},
		"serial_entry_no_ca": {Request: []byte("r"), Entries: []RevokedEntry{{Kind: RevokedSerial, Serial: 1}}},
		"serial_entry_zero":  {Request: []byte("r"), Entries: []RevokedEntry{{Kind: RevokedSerial, CAKey: []byte("k")}}},
		"unknown_entry_kind": {Request: []byte("r"), Entries: []RevokedEntry{{Kind: 4, CAKey: []byte("k"), Serial: 1}}},
		// A serial entry is exact: a key ID or key beside it would let
		// two readers take one leaf for different revocations.
		"serial_entry_with_key_id": {Request: []byte("r"), Entries: []RevokedEntry{{Kind: RevokedSerial, CAKey: []byte("k"), Serial: 1, KeyID: "junk"}}},
		"serial_entry_with_key":    {Request: []byte("r"), Entries: []RevokedEntry{{Kind: RevokedSerial, CAKey: []byte("k"), Serial: 1, Key: []byte("junk")}}},
	} {
		if _, err := b.Encode(); !errors.Is(err, ErrMalformedLeaf) {
			t.Errorf("%s: Encode = %v, want ErrMalformedLeaf", name, err)
		}
	}
	// The decoder refuses the same entries in bytes nobody encoded.
	for name, e := range map[string]RevokedEntry{
		"decode_serial_entry_with_key_id": {Kind: RevokedSerial, CAKey: []byte("k"), Serial: 1, KeyID: "junk"},
		"decode_serial_entry_with_key":    {Kind: RevokedSerial, CAKey: []byte("k"), Serial: 1, Key: []byte("junk")},
	} {
		var c cryptobyte.Builder
		c.AddUint64(1)
		c.AddUint64(1)
		c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes([]byte("r")) })
		c.AddUint24LengthPrefixed(func(*cryptobyte.Builder) {})
		c.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) {
			c.AddUint8(e.Kind)
			c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(e.CAKey) })
			c.AddUint64(e.Serial)
			c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes([]byte(e.KeyID)) })
			c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(e.Key) })
			c.AddUint64(e.ValidBeforeSeconds)
		})
		raw, err := c.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRevokeBody(raw); !errors.Is(err, ErrMalformedLeaf) {
			t.Errorf("%s: DecodeRevokeBody = %v, want ErrMalformedLeaf", name, err)
		}
	}
	empty := &RevokeBody{Request: []byte("r")}
	enc, err := empty.Encode()
	if err != nil {
		t.Fatalf("a revoke that resolved to no entry: %v", err)
	}
	if got, err := DecodeRevokeBody(enc); err != nil || len(got.Entries) != 0 {
		t.Fatalf("DecodeRevokeBody(no entries) = %+v, %v", got, err)
	}
}

// TestKRLPublishBody covers the kind-10 body decoder.
func TestKRLPublishBody(t *testing.T) {
	leaf, body := krlPublishVector(t)
	bodyCases(t, leaf, body, func(b []byte) (any, error) { return DecodeKRLPublishBody(b) })
	if KindKRLPublish != 10 || KindKRLPublish.String() != "krl_publish" {
		t.Fatalf("KindKRLPublish = %d %q", KindKRLPublish, KindKRLPublish)
	}
	for name, b := range map[string]*KRLPublishBody{
		"version_zero":       {Manifest: []byte("m"), Sig: []byte("s")},
		"no_signature":       {KRLVersion: 1, Manifest: []byte("m")},
		"manifest_too_large": {KRLVersion: 1, Manifest: make([]byte, MaxManifest+1), Sig: []byte("s")},
		"sig_too_large":      {KRLVersion: 1, Manifest: []byte("m"), Sig: make([]byte, MaxManifestSig+1)},
	} {
		if _, err := b.Encode(); !errors.Is(err, ErrMalformedLeaf) {
			t.Errorf("%s: Encode = %v, want ErrMalformedLeaf", name, err)
		}
	}
}
