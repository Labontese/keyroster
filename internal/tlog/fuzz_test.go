package tlog

import (
	"bytes"
	"encoding/base64"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

// FuzzDecodeLeaf: a leaf that decodes re-encodes to exactly the input, and
// so does its kind-specific body.
func FuzzDecodeLeaf(f *testing.F) {
	issue, _ := issueVector(f)
	f.Add(EncodeLeaf(issue))
	for _, b := range []interface{ Encode() ([]byte, error) }{
		&RefusalBody{PeerUID: 1, Reason: ReasonMalformed, Detail: "malformed_frame"},
		&RefusalSummaryBody{WindowEndMicros: 1, Counts: []ReasonCount{{ReasonPeerNotAllowed, 2}}},
		&ClockRegressionBody{NowMicros: 1, HighWaterMicros: 2},
		&CAInitBody{Keys: []CAInitKey{{Role: "log", PublicKey: []byte{1}, Alg: "a", Custody: "agent"}}},
		&BundleInstallBody{BundleVersion: 1, Bundle: []byte{1}, BundleSigs: []byte{2}, Policy: []byte{3}, PolicySigs: []byte{4}},
	} {
		body, err := b.Encode()
		if err != nil {
			f.Fatal(err)
		}
		for k := KindIssue; k <= KindBundleInstall; k++ {
			f.Add(EncodeLeaf(Leaf{Index: 1, TimeMicros: 2, Kind: k, Body: body}))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		l, err := DecodeLeaf(data)
		if err != nil {
			return
		}
		again, err := MarshalLeaf(l)
		if err != nil {
			t.Fatalf("decoded leaf does not re-encode: %v", err)
		}
		if !bytes.Equal(again, data) {
			t.Fatalf("decode-encode changed the leaf:\n in %x\nout %x", data, again)
		}
		var body interface{ Encode() ([]byte, error) }
		switch l.Kind {
		case KindIssue:
			body, err = DecodeIssueBody(l.Body)
		case KindRefusal:
			body, err = DecodeRefusalBody(l.Body)
		case KindRefusalSummary:
			body, err = DecodeRefusalSummaryBody(l.Body)
		case KindClockRegression:
			body, err = DecodeClockRegressionBody(l.Body)
		case KindCAInit:
			body, err = DecodeCAInitBody(l.Body)
		case KindBundleInstall:
			body, err = DecodeBundleInstallBody(l.Body)
		default:
			t.Fatalf("DecodeLeaf accepted kind %d", l.Kind)
		}
		if err != nil {
			t.Fatalf("DecodeLeaf accepted a body its kind does not decode: %v", err)
		}
		enc, err := body.Encode()
		if err != nil || !bytes.Equal(enc, l.Body) {
			t.Fatalf("body is not canonical: %v", err)
		}
	})
}

// FuzzOpenCheckpoint: arbitrary notes never panic, and anything accepted
// is a well-formed checkpoint signed by the key that re-serializes to the
// same text.
func FuzzOpenCheckpoint(f *testing.F) {
	s := testEd25519Signer(f)
	origin := Origin(s.PublicKey())
	ns, err := NewNoteSigner(origin, s)
	if err != nil {
		f.Fatal(err)
	}
	v, err := NewNoteVerifier(origin, s.PublicKey())
	if err != nil {
		f.Fatal(err)
	}
	root := make([]byte, 32)
	good, err := SignCheckpoint(Checkpoint{Origin: origin, Size: 5, Root: root}, ns)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(origin + "\n5\n" + base64.StdEncoding.EncodeToString(root) + "\n\n— " + origin + " AAAA\n"))
	f.Add([]byte("\n\n"))
	f.Fuzz(func(t *testing.T, msg []byte) {
		cp, err := OpenCheckpoint(msg, v)
		if err != nil {
			return
		}
		n, err := note.Open(msg, note.VerifierList(v))
		if err != nil {
			t.Fatalf("OpenCheckpoint accepted a note that note.Open rejects: %v", err)
		}
		if n.Text != cp.Text() || cp.Origin != origin || len(cp.Root) != HashSize {
			t.Fatalf("accepted checkpoint %+v does not round-trip its text %q", cp, n.Text)
		}
	})
}
