package tlog

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/wire"
)

var update = flag.Bool("update", false, "rewrite the golden vectors in test/vectors")

// vectorPath returns the path of a file in the repository's test/vectors.
func vectorPath(name string) string { return filepath.Join("..", "..", "test", "vectors", name) }

// golden compares got with the named golden file, or rewrites the file
// when -update is set.
func readGolden(t *testing.T, name string) []byte {
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
		"unknown_kind":     rawKindLeaf(t, Leaf{Kind: 9, Body: refusal}),
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
