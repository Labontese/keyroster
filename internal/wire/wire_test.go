package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

// validRequest returns a request within every limit.
func validRequest() *IssueRequest {
	r := &IssueRequest{
		CARole:          CARoleUser,
		SubjectKey:      bytes.Repeat([]byte{0x5a}, 51),
		Subject:         "u:alice",
		Principals:      []string{"alice", "ops"},
		ValidForSeconds: 3600,
		CreatedAt:       1_790_000_000,
		Evidence:        []Evidence{{Type: "admin-sshsig/v1", Blob: []byte("sig")}},
	}
	for i := range r.RequestID {
		r.RequestID[i] = byte(i)
	}
	return r
}

// marshalUnchecked encodes r exactly like Marshal but without the limit
// checks, so tests can produce over-limit bodies.
func marshalUnchecked(r *IssueRequest) []byte {
	var b cryptobyte.Builder
	r.addFields(&b)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, e := range r.Evidence {
			addBytes16(b, []byte(e.Type))
			addBytes16(b, e.Blob)
		}
	})
	return b.BytesOrPanic()
}

func TestIssueRequestRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		edit func(*IssueRequest)
	}{
		{"typical", func(*IssueRequest) {}},
		{"no_evidence", func(r *IssueRequest) { r.Evidence = nil }},
		{"no_principals", func(r *IssueRequest) { r.Principals = nil }},
		{"extensions", func(r *IssueRequest) { r.Extensions = []string{"permit-agent-forwarding", "permit-port-forwarding"} }},
		{"at_every_limit", func(r *IssueRequest) {
			r.SubjectKey = bytes.Repeat([]byte{1}, MaxSubjectKeyLen)
			r.Subject = strings.Repeat("s", MaxSubjectLen)
			r.Principals = make([]string, MaxPrincipals)
			for i := range r.Principals {
				r.Principals[i] = strings.Repeat("p", MaxPrincipalLen-2) + string(rune('a'+i%26)) + string(rune('a'+i/26))
			}
			r.Extensions = make([]string, MaxExtensions)
			for i := range r.Extensions {
				r.Extensions[i] = strings.Repeat("e", MaxExtensionLen-1) + string(rune('a'+i))
			}
			r.Evidence = make([]Evidence, MaxEvidence)
			for i := range r.Evidence {
				r.Evidence[i] = Evidence{Type: strings.Repeat("t", MaxEvidenceType), Blob: bytes.Repeat([]byte{2}, 1024)}
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validRequest()
			tc.edit(r)
			body, err := r.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			got, err := ParseIssueRequest(body)
			if err != nil {
				t.Fatalf("ParseIssueRequest: %v", err)
			}
			if !reflect.DeepEqual(got, r) {
				t.Fatalf("round trip = %+v, want %+v", got, r)
			}
			again, err := got.Marshal()
			if err != nil || !bytes.Equal(again, body) {
				t.Fatalf("re-marshal differs (err %v)", err)
			}
		})
	}
}

func TestParseIssueRequestRefusals(t *testing.T) {
	over := func(edit func(*IssueRequest)) []byte {
		r := validRequest()
		edit(r)
		return marshalUnchecked(r)
	}
	valid := marshalUnchecked(validRequest())
	tests := []struct {
		name string
		body []byte
	}{
		{"empty_body", nil},
		{"trailing_byte", append(append([]byte(nil), valid...), 0)},
		{"trailing_bytes", append(append([]byte(nil), valid...), "junk"...)},
		{"principals_33", over(func(r *IssueRequest) {
			r.Principals = make([]string, MaxPrincipals+1)
			for i := range r.Principals {
				r.Principals[i] = "p" + strings.Repeat("x", i)
			}
		})},
		{"principal_129_bytes", over(func(r *IssueRequest) { r.Principals = []string{strings.Repeat("a", MaxPrincipalLen+1)} })},
		{"subject_65_bytes", over(func(r *IssueRequest) { r.Subject = strings.Repeat("s", MaxSubjectLen+1) })},
		{"subject_key_above_8k", over(func(r *IssueRequest) { r.SubjectKey = bytes.Repeat([]byte{1}, MaxSubjectKeyLen+1) })},
		{"subject_key_empty", over(func(r *IssueRequest) { r.SubjectKey = nil })},
		{"evidence_5_items", over(func(r *IssueRequest) {
			r.Evidence = make([]Evidence, MaxEvidence+1)
			for i := range r.Evidence {
				r.Evidence[i] = Evidence{Type: "t", Blob: []byte{byte(i)}}
			}
		})},
		{"evidence_type_65_bytes", over(func(r *IssueRequest) { r.Evidence = []Evidence{{Type: strings.Repeat("t", MaxEvidenceType+1)}} })},
		{"evidence_type_empty", over(func(r *IssueRequest) { r.Evidence = []Evidence{{Type: "", Blob: []byte("x")}} })},
		{"evidence_blob_above_8k", over(func(r *IssueRequest) {
			r.Evidence = []Evidence{{Type: "t", Blob: bytes.Repeat([]byte{1}, MaxEvidenceBlob+1)}}
		})},
		{"extensions_9", over(func(r *IssueRequest) {
			r.Extensions = make([]string, MaxExtensions+1)
			for i := range r.Extensions {
				r.Extensions[i] = "e" + strings.Repeat("x", i)
			}
		})},
		{"extension_65_bytes", over(func(r *IssueRequest) { r.Extensions = []string{strings.Repeat("e", MaxExtensionLen+1)} })},
		{"extension_empty", over(func(r *IssueRequest) { r.Extensions = []string{""} })},
		{"unknown_ca_role_0", over(func(r *IssueRequest) { r.CARole = 0 })},
		{"unknown_ca_role_4", over(func(r *IssueRequest) { r.CARole = 4 })},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseIssueRequest(tc.body); !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseIssueRequest error = %v, want ErrMalformed", err)
			}
		})
	}
	// Every strict prefix of a valid body is a truncated field.
	t.Run("truncated_fields", func(t *testing.T) {
		for n := range len(valid) {
			if _, err := ParseIssueRequest(valid[:n]); !errors.Is(err, ErrMalformed) {
				t.Fatalf("prefix of %d/%d bytes: error = %v, want ErrMalformed", n, len(valid), err)
			}
		}
	})
}

// Marshal enforces the same limits as ParseIssueRequest.
func TestIssueRequestMarshalRefusesOverLimit(t *testing.T) {
	tests := []struct {
		name string
		edit func(*IssueRequest)
	}{
		{"principals_33", func(r *IssueRequest) { r.Principals = make([]string, MaxPrincipals+1) }},
		{"principal_129_bytes", func(r *IssueRequest) { r.Principals = []string{strings.Repeat("a", MaxPrincipalLen+1)} }},
		{"subject_65_bytes", func(r *IssueRequest) { r.Subject = strings.Repeat("s", MaxSubjectLen+1) }},
		{"subject_key_above_8k", func(r *IssueRequest) { r.SubjectKey = make([]byte, MaxSubjectKeyLen+1) }},
		{"evidence_5_items", func(r *IssueRequest) { r.Evidence = make([]Evidence, MaxEvidence+1) }},
		{"unknown_ca_role", func(r *IssueRequest) { r.CARole = 9 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := validRequest()
			tc.edit(r)
			if _, err := r.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Marshal error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestSigningBytes(t *testing.T) {
	r := validRequest()
	sb := r.SigningBytes()
	if !bytes.HasPrefix(sb, []byte(IssueRequestDomain)) {
		t.Fatalf("SigningBytes starts with %q, want the domain tag %q", sb[:min(len(sb), 32)], IssueRequestDomain)
	}
	if IssueRequestDomain != "keyroster/issue-request/v1" {
		t.Fatalf("domain tag = %q", IssueRequestDomain)
	}

	t.Run("evidence_excluded", func(t *testing.T) {
		withEvidence := validRequest()
		withEvidence.Evidence = append(withEvidence.Evidence, Evidence{Type: "other/v1", Blob: []byte("more")})
		noEvidence := validRequest()
		noEvidence.Evidence = nil
		if r.Digest() != withEvidence.Digest() || r.Digest() != noEvidence.Digest() {
			t.Fatal("Digest changes with the evidence list; evidence must not be part of the signing bytes")
		}
		if bytes.Contains(sb, []byte("admin-sshsig/v1")) {
			t.Fatal("SigningBytes contain an evidence type")
		}
	})
	t.Run("every_other_field_bound", func(t *testing.T) {
		for name, edit := range map[string]func(*IssueRequest){
			"ca_role":     func(r *IssueRequest) { r.CARole = CARoleHost },
			"subject_key": func(r *IssueRequest) { r.SubjectKey[0] ^= 1 },
			"subject":     func(r *IssueRequest) { r.Subject = "u:bob" },
			"principals":  func(r *IssueRequest) { r.Principals = []string{"alice"} },
			"valid_for":   func(r *IssueRequest) { r.ValidForSeconds++ },
			"request_id":  func(r *IssueRequest) { r.RequestID[15] ^= 1 },
			"created_at":  func(r *IssueRequest) { r.CreatedAt++ },
			"extensions":  func(r *IssueRequest) { r.Extensions = []string{"permit-port-forwarding"} },
		} {
			m := validRequest()
			edit(m)
			if m.Digest() == r.Digest() {
				t.Errorf("changing %s leaves the digest unchanged", name)
			}
		}
	})
}

// countingReader serves a fixed header and then an endless body, counting
// every byte handed out.
type countingReader struct {
	hdr  []byte
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if c.read < len(c.hdr) {
			p[n] = c.hdr[c.read]
		} else {
			p[n] = 0x41
		}
		n++
		c.read++
	}
	return n, nil
}

func frameHeader(n uint32) []byte {
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], n)
	return h[:]
}

// frameOf returns a frame of msgType with a body of n bytes (0x07 each).
func frameOf(t testing.TB, msgType byte, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteMessage(&buf, msgType, bytes.Repeat([]byte{7}, n)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestReadFrame covers the framing errors of ReadMessage that do not
// depend on the message type: a 1 GiB length refused after the 6 header
// bytes without allocating the body, an empty frame, and truncated input.
func TestReadFrame(t *testing.T) {
	t.Run("one_gib_header_refused_before_body", func(t *testing.T) {
		r := &countingReader{hdr: append(frameHeader(1<<30), Version, TypeIssueRequest)}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, _, err := ReadMessage(r)
		runtime.ReadMemStats(&after)
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("ReadMessage error = %v, want ErrFrameTooLarge", err)
		}
		if r.read != 6 {
			t.Fatalf("ReadMessage consumed %d bytes, want only the 4-byte length and the 2-byte header", r.read)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew >= 1<<20 {
			t.Fatalf("ReadMessage allocated %d bytes for a refused 1 GiB frame, want below 1 MiB", grew)
		}
	})
	tests := []struct {
		name    string
		in      []byte
		wantErr error
		wantEOF bool
	}{
		{name: "empty_frame", in: frameHeader(0), wantErr: ErrEmptyFrame},
		{name: "no_length", in: nil, wantEOF: true},
		{name: "short_length", in: []byte{0, 0}, wantEOF: true},
		{name: "short_header", in: append(frameHeader(10), Version), wantEOF: true},
		{name: "short_body", in: append(frameHeader(10), Version, TypeIssueRequest, 1, 2, 3), wantEOF: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ReadMessage(bytes.NewReader(tc.in))
			switch {
			case tc.wantEOF:
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("ReadMessage error = %v, want EOF or unexpected EOF", err)
				}
			case !errors.Is(err, tc.wantErr):
				t.Fatalf("ReadMessage error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestReadMessage(t *testing.T) {
	t.Run("unknown_version", func(t *testing.T) {
		in := append(frameHeader(3), Version+1, TypeIssueRequest, 0)
		if _, _, err := ReadMessage(bytes.NewReader(in)); !errors.Is(err, ErrVersion) {
			t.Fatalf("ReadMessage error = %v, want ErrVersion", err)
		}
	})
	t.Run("payload_without_type", func(t *testing.T) {
		in := append(frameHeader(1), Version)
		if _, _, err := ReadMessage(bytes.NewReader(in)); !errors.Is(err, ErrShortFrame) {
			t.Fatalf("ReadMessage error = %v, want ErrShortFrame", err)
		}
	})
	t.Run("type_and_body_round_trip", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteMessage(&buf, TypeIssueRequest, []byte("body")); err != nil {
			t.Fatal(err)
		}
		typ, body, err := ReadMessage(&buf)
		if err != nil || typ != TypeIssueRequest || string(body) != "body" {
			t.Fatalf("ReadMessage = %#x, %q, %v", typ, body, err)
		}
	})
}

// TestReadMessageCaps is the read-side boundary table of the per-type
// frame caps (T-02-12, T-02-81). A cap limits the frame length, which
// counts the 2 header bytes. Every refusal reads only the length (and the
// header when it got that far) and allocates no body.
func TestReadMessageCaps(t *testing.T) {
	t.Run("length_one_refused_without_consuming_next", func(t *testing.T) {
		next := frameOf(t, TypeIssueRequest, 10)
		r := bytes.NewReader(append(append(frameHeader(1), 0x5a), next...))
		if _, _, err := ReadMessage(r); !errors.Is(err, ErrShortFrame) {
			t.Fatalf("ReadMessage of a length-1 frame = %v, want ErrShortFrame", err)
		}
		rest, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		if want := append([]byte{0x5a}, next...); !bytes.Equal(rest, want) {
			t.Fatalf("after the refusal %d bytes remain, want the length-1 frame's byte and the whole next frame (%d bytes)", len(rest), len(want))
		}
	})
	t.Run("length_two_header_only", func(t *testing.T) {
		typ, body, err := ReadMessage(bytes.NewReader(append(frameHeader(2), Version, TypeIssueRequest)))
		if err != nil || typ != TypeIssueRequest || len(body) != 0 {
			t.Fatalf("ReadMessage of a header-only frame = %#x, %d body bytes, %v; want the issue type, no body, no error", typ, len(body), err)
		}
	})
	accepted := []struct {
		name    string
		msgType byte
		length  int
	}{
		{"issue_exactly_max_frame", TypeIssueRequest, MaxFrame},
		{"install_exactly_max_directory_frame", TypeInstallDirectory, MaxDirectoryFrame},
		{"get_directory_response_exactly_max_directory_frame", TypeGetDirectoryResponse, MaxDirectoryFrame},
		{"unknown_type_exactly_max_frame", 0x7e, MaxFrame},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			in := frameOf(t, tc.msgType, tc.length-headerLen)
			if got := binary.BigEndian.Uint32(in); got != uint32(tc.length) { //nolint:gosec // G115: test lengths fit
				t.Fatalf("frame length %d, want %d", got, tc.length)
			}
			typ, body, err := ReadMessage(bytes.NewReader(in))
			if err != nil || typ != tc.msgType || len(body) != tc.length-headerLen {
				t.Fatalf("ReadMessage = %#x, %d body bytes, %v; want %#x with %d body bytes", typ, len(body), err, tc.msgType, tc.length-headerLen)
			}
		})
	}
	refused := []struct {
		name    string
		msgType byte
		length  uint32
	}{
		{"issue_max_frame_plus_one", TypeIssueRequest, MaxFrame + 1},
		{"login_max_frame_plus_one", TypeLoginIssueRequest, MaxFrame + 1},
		{"install_max_directory_frame_plus_one", TypeInstallDirectory, MaxDirectoryFrame + 1},
		{"get_directory_response_max_directory_frame_plus_one", TypeGetDirectoryResponse, MaxDirectoryFrame + 1},
		{"unknown_type_max_frame_plus_one", 0x7e, MaxFrame + 1},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReader{hdr: append(frameHeader(tc.length), Version, tc.msgType)}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, _, err := ReadMessage(r)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, ErrFrameTooLarge) {
				t.Fatalf("ReadMessage error = %v, want ErrFrameTooLarge", err)
			}
			if r.read != 6 {
				t.Fatalf("ReadMessage consumed %d bytes, want only the 6 bytes of length and header", r.read)
			}
			if grew := after.TotalAlloc - before.TotalAlloc; grew >= 1<<20 {
				t.Fatalf("ReadMessage allocated %d bytes for a refused frame, want below 1 MiB", grew)
			}
		})
	}
}

// TestWriteMessageCaps is the write-side boundary table: a body at its
// type's cap is written and reads back; one byte more is refused with
// nothing written.
func TestWriteMessageCaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		msgType byte
		maxBody int
	}{
		{"issue", TypeIssueRequest, MaxFrame - headerLen},
		{"install_directory", TypeInstallDirectory, MaxDirectoryFrame - headerLen},
		{"get_directory_response", TypeGetDirectoryResponse, MaxDirectoryFrame - headerLen},
	} {
		t.Run(tc.name+"_at_cap", func(t *testing.T) {
			var buf bytes.Buffer
			body := bytes.Repeat([]byte{9}, tc.maxBody)
			if err := WriteMessage(&buf, tc.msgType, body); err != nil {
				t.Fatalf("WriteMessage of a %d-byte body: %v", tc.maxBody, err)
			}
			if buf.Len() != 4+headerLen+tc.maxBody {
				t.Fatalf("wrote %d bytes, want %d", buf.Len(), 4+headerLen+tc.maxBody)
			}
			typ, got, err := ReadMessage(&buf)
			if err != nil || typ != tc.msgType || !bytes.Equal(got, body) {
				t.Fatalf("round trip: %#x, %d bytes, %v", typ, len(got), err)
			}
		})
		t.Run(tc.name+"_cap_plus_one", func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteMessage(&buf, tc.msgType, make([]byte, tc.maxBody+1)); !errors.Is(err, ErrFrameTooLarge) {
				t.Fatalf("WriteMessage of a %d-byte body = %v, want ErrFrameTooLarge", tc.maxBody+1, err)
			}
			if buf.Len() != 0 {
				t.Fatalf("the writer received %d bytes for a refused frame, want 0", buf.Len())
			}
		})
	}
}

// TestParseGetDirectoryResponse: strict decoding of the GetDirectory
// response (02-03-F13, 02-03-R2-F16). Version 0 has exactly one encoding;
// an installed directory round-trips whether or not it is authorized.
func TestParseGetDirectoryResponse(t *testing.T) {
	raw := func(version uint64, doc, sigs []byte, auth uint8) []byte {
		var b cryptobyte.Builder
		b.AddUint64(version)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(doc) })
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sigs) })
		b.AddUint8(auth)
		return b.BytesOrPanic()
	}
	t.Run("get_directory_v0_with_bytes_refused", func(t *testing.T) {
		for name, body := range map[string][]byte{
			"directory":  raw(0, []byte("{}"), nil, 0),
			"signatures": raw(0, nil, []byte("sig"), 0),
		} {
			if _, err := ParseGetDirectoryResponse(body); !errors.Is(err, ErrMalformed) {
				t.Errorf("version 0 with %s bytes: %v, want ErrMalformed", name, err)
			}
		}
		if _, err := (&GetDirectoryResponse{Directory: []byte("{}")}).Marshal(); !errors.Is(err, ErrMalformed) {
			t.Errorf("Marshal of version 0 with a directory: %v, want ErrMalformed", err)
		}
	})
	t.Run("get_directory_v0_authorized_refused", func(t *testing.T) {
		if _, err := ParseGetDirectoryResponse(raw(0, nil, nil, 1)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("version 0 authorized: %v, want ErrMalformed", err)
		}
	})
	t.Run("get_directory_v0_round_trips", func(t *testing.T) {
		body, err := (&GetDirectoryResponse{}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, raw(0, nil, nil, 0)) {
			t.Fatalf("empty response encodes as %x", body)
		}
		got, err := ParseGetDirectoryResponse(body)
		if err != nil || got.Version != 0 || got.Directory != nil || got.Sigs != nil || got.Authorized {
			t.Fatalf("empty response round trip: %+v, %v", got, err)
		}
	})
	t.Run("get_directory_installed_round_trips", func(t *testing.T) {
		for _, authorized := range []bool{true, false} {
			want := &GetDirectoryResponse{Version: 1, Directory: []byte(`{"version":1}`), Sigs: []byte("-----BEGIN SSH SIGNATURE-----"), Authorized: authorized}
			body, err := want.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseGetDirectoryResponse(body)
			if err != nil {
				t.Fatalf("authorized %v: %v", authorized, err)
			}
			if got.Version != want.Version || !bytes.Equal(got.Directory, want.Directory) || !bytes.Equal(got.Sigs, want.Sigs) || got.Authorized != authorized {
				t.Fatalf("authorized %v: round trip %+v, want %+v", authorized, got, want)
			}
			again, err := got.Marshal()
			if err != nil || !bytes.Equal(again, body) {
				t.Fatalf("authorized %v: re-encoding differs (%v)", authorized, err)
			}
		}
	})
	t.Run("strict", func(t *testing.T) {
		valid := raw(1, []byte("{}"), []byte("sig"), 1)
		for name, body := range map[string][]byte{
			"authorized_byte_2":       raw(1, []byte("{}"), []byte("sig"), 2),
			"trailing_byte":           append(append([]byte(nil), valid...), 0),
			"truncated":               valid[:len(valid)-1],
			"installed_without_bytes": raw(1, nil, nil, 0),
			"installed_without_sigs":  raw(1, []byte("{}"), nil, 0),
		} {
			if _, err := ParseGetDirectoryResponse(body); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: %v, want ErrMalformed", name, err)
			}
		}
		if _, err := ParseGetDirectoryResponse(valid); err != nil {
			t.Fatalf("control: %v", err)
		}
	})
	if TypeGetDirectory != 0x03 || TypeGetDirectoryResponse != 0x83 {
		t.Fatal("a GetDirectory message type number changed")
	}
}

func TestErrorResponse(t *testing.T) {
	t.Run("round_trip", func(t *testing.T) {
		e := &ErrorResponse{Code: CodeRefused, Message: "bad_principal"}
		body, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseErrorResponse(body)
		if err != nil || *got != *e {
			t.Fatalf("ParseErrorResponse = %+v, %v", got, err)
		}
	})
	tests := []struct {
		name string
		e    ErrorResponse
	}{
		{"unknown_code", ErrorResponse{Code: 9, Message: "x"}},
		{"zero_code", ErrorResponse{Code: 0, Message: "x"}},
		{"empty_message", ErrorResponse{Code: CodeRefused, Message: ""}},
		{"uppercase_message", ErrorResponse{Code: CodeRefused, Message: "Bad"}},
		{"newline_message", ErrorResponse{Code: CodeRefused, Message: "a\nb"}},
		{"long_message", ErrorResponse{Code: CodeRefused, Message: strings.Repeat("a", MaxErrorMessage+1)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.e.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Marshal error = %v, want ErrMalformed", err)
			}
			var b cryptobyte.Builder
			b.AddUint8(uint8(tc.e.Code))
			addBytes16(&b, []byte(tc.e.Message))
			if _, err := ParseErrorResponse(b.BytesOrPanic()); !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseErrorResponse error = %v, want ErrMalformed", err)
			}
		})
	}
}

func TestIssueResponse(t *testing.T) {
	r := &IssueResponse{Cert: []byte("cert"), Serial: 7, LeafIndex: 3}
	body, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseIssueResponse(body)
	if err != nil || !bytes.Equal(got.Cert, r.Cert) || got.Serial != r.Serial || got.LeafIndex != r.LeafIndex {
		t.Fatalf("ParseIssueResponse = %+v, %v", got, err)
	}
	if _, err := ParseIssueResponse(append(body, 0)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing byte: error = %v, want ErrMalformed", err)
	}
	if _, err := (&IssueResponse{Serial: 1}).Marshal(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty certificate: error = %v, want ErrMalformed", err)
	}
}

var update = flag.Bool("update", false, "rewrite the golden vectors in test/vectors")

const vectorDir = "../../test/vectors"

// TestIssueRequestBytesUnchanged pins the Phase 1 admin request: the
// SHA-256 of validRequest's body and signing bytes, computed with
// internal/wire/issue.go as on main before Phase 2 (keyroster/issue-request/v1
// and admin-sshsig/v1 stay byte-for-byte unchanged).
func TestIssueRequestBytesUnchanged(t *testing.T) {
	r := validRequest()
	body, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	sb, bb := sha256.Sum256(r.SigningBytes()), sha256.Sum256(body)
	if got := hex.EncodeToString(sb[:]); got != "1156dfdbebdacbbbd273d9a8545ba53ec571cf8bb70749e42548c8dd535a3c20" {
		t.Fatalf("IssueRequest signing bytes changed: sha256 %s", got)
	}
	if got := hex.EncodeToString(bb[:]); got != "d730e405f20155e35dbb861050607d3c0aef9c5213c297da7a09f703fcc7d4f9" {
		t.Fatalf("IssueRequest body changed: sha256 %s", got)
	}
	if TypeIssueRequest != 0x01 || AdminSSHSIGNamespace != "keyroster/issue-request/v1" || EvidenceAdminSSHSIG != "admin-sshsig/v1" {
		t.Fatal("an admin-path constant changed")
	}
}

// loginVector is the login request of
// test/vectors/login_request_signing_v1.hex: the SSH encoding of the
// Ed25519 key with seed 0x00..0x1f, alice, role ops, principal role:ops,
// 600 s, request id 0x00..0x0f, created 1700000000, no extensions.
func loginVector(t testing.TB) *LoginIssueRequest {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatal(err)
	}
	r := &LoginIssueRequest{
		SubjectKey:      pub.Marshal(),
		Subject:         "alice",
		Roles:           []string{"ops"},
		Principals:      []string{"role:ops"},
		ValidForSeconds: 600,
		CreatedAt:       1700000000,
	}
	for i := range r.RequestID {
		r.RequestID[i] = byte(i)
	}
	return r
}

// TestLoginRequestSigningVector pins the login request's signing bytes
// (the WebAuthn challenge rule, D-12): they equal the golden file, start
// with the raw domain tag, and Digest is their SHA-256.
func TestLoginRequestSigningVector(t *testing.T) {
	r := loginVector(t)
	got := r.SigningBytes()
	path := filepath.Join(vectorDir, "login_request_signing_v1.hex")
	if *update {
		if err := os.WriteFile(path, []byte(hex.EncodeToString(got)+"\n"), 0o644); err != nil { //nolint:gosec // G306: public test vector
			t.Fatal(err)
		}
	}
	file, err := os.ReadFile(path) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatalf("%v (create it with -update only for a deliberate format change)", err)
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(file)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("login request signing bytes differ from %s\ngot:  %x\nwant: %x", path, got, want)
	}
	if !bytes.HasPrefix(got, []byte("keyroster/login-request/v1")) || LoginRequestDomain != "keyroster/login-request/v1" {
		t.Fatalf("signing bytes do not start with the raw domain tag: %q", got[:min(len(got), 32)])
	}
	if r.Digest() != sha256.Sum256(want) {
		t.Fatal("Digest is not the SHA-256 of the signing bytes")
	}
}

// TestLoginIssueRequest covers the round trip, evidence outside the
// signing bytes, every field bound, and strict parsing.
func TestLoginIssueRequest(t *testing.T) {
	r := loginVector(t)
	blob, err := (&WebAuthnAssertion{CredentialID: []byte{1, 2, 3}, AuthenticatorData: bytes.Repeat([]byte{7}, 37),
		ClientDataJSON: []byte(`{"type":"webauthn.get"}`), Signature: []byte("sig")}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	r.Extensions = []string{"permit-agent-forwarding"}
	r.Evidence = []Evidence{{Type: EvidenceWebAuthnAssertion, Blob: blob}}
	body, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseLoginIssueRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, r) {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, r)
	}
	a, err := ParseWebAuthnAssertion(got.Evidence[0].Blob)
	if err != nil || !bytes.Equal(a.CredentialID, []byte{1, 2, 3}) || len(a.AuthenticatorData) != 37 {
		t.Fatalf("assertion blob round trip: %+v, %v", a, err)
	}
	noEvidence := loginVector(t)
	noEvidence.Extensions = r.Extensions
	if noEvidence.Digest() != r.Digest() {
		t.Fatal("the evidence is part of the login signing bytes")
	}
	for name, edit := range map[string]func(*LoginIssueRequest){
		"subject_key": func(r *LoginIssueRequest) { r.SubjectKey[len(r.SubjectKey)-1] ^= 1 },
		"subject":     func(r *LoginIssueRequest) { r.Subject = "bob" },
		"roles":       func(r *LoginIssueRequest) { r.Roles = nil },
		"principals":  func(r *LoginIssueRequest) { r.Principals = []string{"role:dev"} },
		"valid_for":   func(r *LoginIssueRequest) { r.ValidForSeconds++ },
		"request_id":  func(r *LoginIssueRequest) { r.RequestID[0] ^= 1 },
		"created_at":  func(r *LoginIssueRequest) { r.CreatedAt++ },
		"extensions":  func(r *LoginIssueRequest) { r.Extensions = []string{"permit-pty"} },
	} {
		m := loginVector(t)
		m.Extensions = r.Extensions
		edit(m)
		if m.Digest() == r.Digest() {
			t.Errorf("changing %s leaves the login digest unchanged", name)
		}
	}
	if _, err := ParseLoginIssueRequest(append(body, 0)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing byte: %v, want ErrMalformed", err)
	}
	if _, err := ParseWebAuthnAssertion(append(blob, 0)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("assertion blob with a trailing byte: %v, want ErrMalformed", err)
	}
	tooMany := loginVector(t)
	for i := range MaxLoginRoles + 1 {
		tooMany.Roles = append(tooMany.Roles, "r"+strings.Repeat("x", i))
	}
	if _, err := tooMany.Marshal(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("17 roles: %v, want ErrMalformed", err)
	}
}

// TestInstallDirectoryMessages: round trip and strict parsing of the
// directory install request and response.
func TestInstallDirectoryMessages(t *testing.T) {
	req := &InstallDirectoryRequest{Directory: []byte("{}\n"), Sigs: []byte("-----BEGIN SSH SIGNATURE-----")}
	body, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseInstallDirectoryRequest(body)
	if err != nil || !reflect.DeepEqual(got, req) {
		t.Fatalf("request round trip: %+v, %v", got, err)
	}
	if _, err := ParseInstallDirectoryRequest(append(body, 0)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing byte: %v", err)
	}
	if _, err := (&InstallDirectoryRequest{Directory: []byte("x")}).Marshal(); !errors.Is(err, ErrMalformed) {
		t.Fatalf("no signatures: %v", err)
	}
	resp := &InstallDirectoryResponse{Version: 2, LeafIndex: 9, SHA256: sha256.Sum256([]byte("doc"))}
	rb, err := resp.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	gr, err := ParseInstallDirectoryResponse(rb)
	if err != nil || *gr != *resp {
		t.Fatalf("response round trip: %+v, %v", gr, err)
	}
	if TypeInstallDirectory != 0x02 || TypeInstallDirectoryResponse != 0x82 || TypeLoginIssueRequest != 0x05 {
		t.Fatal("a Phase 2 message type number changed")
	}
}
