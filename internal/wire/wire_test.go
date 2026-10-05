package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/cryptobyte"
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
		{"at_every_limit", func(r *IssueRequest) {
			r.SubjectKey = bytes.Repeat([]byte{1}, MaxSubjectKeyLen)
			r.Subject = strings.Repeat("s", MaxSubjectLen)
			r.Principals = make([]string, MaxPrincipals)
			for i := range r.Principals {
				r.Principals[i] = strings.Repeat("p", MaxPrincipalLen-2) + string(rune('a'+i%26)) + string(rune('a'+i/26))
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

func TestReadFrame(t *testing.T) {
	t.Run("one_gib_header_refused_before_body", func(t *testing.T) {
		r := &countingReader{hdr: frameHeader(1 << 30)}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := ReadFrame(r)
		runtime.ReadMemStats(&after)
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("ReadFrame error = %v, want ErrFrameTooLarge", err)
		}
		if r.read != 4 {
			t.Fatalf("ReadFrame consumed %d bytes, want only the 4-byte header", r.read)
		}
		if grew := after.TotalAlloc - before.TotalAlloc; grew >= 1<<20 {
			t.Fatalf("ReadFrame allocated %d bytes for a refused 1 GiB frame, want below 1 MiB", grew)
		}
	})
	tests := []struct {
		name    string
		in      []byte
		wantErr error
		wantEOF bool
	}{
		{name: "max_frame_plus_one", in: frameHeader(MaxFrame + 1), wantErr: ErrFrameTooLarge},
		{name: "empty_frame", in: frameHeader(0), wantErr: ErrEmptyFrame},
		{name: "no_header", in: nil, wantEOF: true},
		{name: "short_header", in: []byte{0, 0}, wantEOF: true},
		{name: "short_payload", in: append(frameHeader(10), 1, 2, 3), wantEOF: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReadFrame(bytes.NewReader(tc.in))
			switch {
			case tc.wantEOF:
				if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("ReadFrame error = %v, want EOF or unexpected EOF", err)
				}
			case !errors.Is(err, tc.wantErr):
				t.Fatalf("ReadFrame error = %v, want %v", err, tc.wantErr)
			}
		})
	}
	t.Run("exactly_max_frame", func(t *testing.T) {
		payload := bytes.Repeat([]byte{7}, MaxFrame)
		var buf bytes.Buffer
		if err := WriteFrame(&buf, payload); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(&buf)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("ReadFrame of a MaxFrame payload: err %v", err)
		}
	})
	t.Run("write_frame_refuses_oversize", func(t *testing.T) {
		if err := WriteFrame(io.Discard, make([]byte, MaxFrame+1)); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("WriteFrame error = %v, want ErrFrameTooLarge", err)
		}
		if err := WriteFrame(io.Discard, nil); !errors.Is(err, ErrEmptyFrame) {
			t.Fatalf("WriteFrame error = %v, want ErrEmptyFrame", err)
		}
	})
}

func TestReadMessage(t *testing.T) {
	t.Run("unknown_version", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, []byte{Version + 1, TypeIssueRequest, 0}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadMessage(&buf); !errors.Is(err, ErrVersion) {
			t.Fatalf("ReadMessage error = %v, want ErrVersion", err)
		}
	})
	t.Run("payload_without_type", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, []byte{Version}); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadMessage(&buf); err == nil || errors.Is(err, ErrVersion) {
			t.Fatalf("ReadMessage error = %v, want a short-payload error", err)
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
