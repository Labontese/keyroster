package wire

import (
	"bytes"
	"errors"
	"testing"
)

func FuzzParseIssueRequest(f *testing.F) {
	seed := func(edit func(*IssueRequest)) []byte {
		r := validRequest()
		edit(r)
		return marshalUnchecked(r)
	}
	valid := seed(func(*IssueRequest) {})
	f.Add(valid)
	f.Add(seed(func(r *IssueRequest) { r.Evidence = nil }))
	f.Add(seed(func(r *IssueRequest) { r.Principals = nil }))
	f.Add(seed(func(r *IssueRequest) { r.CARole = 0 }))
	f.Add(seed(func(r *IssueRequest) { r.Evidence = make([]Evidence, MaxEvidence+1) }))
	f.Add(append(append([]byte(nil), valid...), 0))
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseIssueRequest(body)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseIssueRequest error = %v, want ErrMalformed", err)
			}
			return
		}
		out, err := r.Marshal()
		if err != nil {
			t.Fatalf("parsed request does not marshal: %v", err)
		}
		if !bytes.Equal(out, body) {
			t.Fatalf("Marshal does not reproduce the input:\n in  %x\n out %x", body, out)
		}
		_ = r.SigningBytes()
	})
}

func FuzzReadFrame(f *testing.F) {
	var valid bytes.Buffer
	if err := WriteMessage(&valid, TypeIssueRequest, marshalUnchecked(validRequest())); err != nil {
		f.Fatal(err)
	}
	f.Add(valid.Bytes())
	f.Add(frameHeader(0))
	f.Add(frameHeader(1 << 30))
	f.Add(frameHeader(MaxFrame + 1))
	f.Add(append(frameHeader(3), Version, TypeError, 0))
	f.Add(append(frameHeader(10), 1, 2))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		payload, err := ReadFrame(bytes.NewReader(in))
		if err != nil {
			return
		}
		if len(payload) == 0 || len(payload) > MaxFrame {
			t.Fatalf("ReadFrame returned a %d-byte payload", len(payload))
		}
		var out bytes.Buffer
		if err := WriteFrame(&out, payload); err != nil {
			t.Fatalf("WriteFrame of a read payload: %v", err)
		}
		if !bytes.Equal(out.Bytes(), in[:out.Len()]) {
			t.Fatal("WriteFrame does not reproduce the frame that was read")
		}
		if _, _, err := ReadMessage(bytes.NewReader(in)); err != nil && !errors.Is(err, ErrVersion) && len(payload) >= 2 {
			t.Fatalf("ReadMessage error = %v for a %d-byte payload", err, len(payload))
		}
	})
}
