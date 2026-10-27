package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
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
		_, _, err := ReadMessage(r, RequestCaps)
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
			_, _, err := ReadMessage(bytes.NewReader(tc.in), RequestCaps)
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
		if _, _, err := ReadMessage(bytes.NewReader(in), RequestCaps); !errors.Is(err, ErrVersion) {
			t.Fatalf("ReadMessage error = %v, want ErrVersion", err)
		}
	})
	t.Run("payload_without_type", func(t *testing.T) {
		in := append(frameHeader(1), Version)
		if _, _, err := ReadMessage(bytes.NewReader(in), RequestCaps); !errors.Is(err, ErrShortFrame) {
			t.Fatalf("ReadMessage error = %v, want ErrShortFrame", err)
		}
	})
	t.Run("type_and_body_round_trip", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteMessage(&buf, TypeIssueRequest, []byte("body")); err != nil {
			t.Fatal(err)
		}
		typ, body, err := ReadMessage(&buf, RequestCaps)
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
		if _, _, err := ReadMessage(r, RequestCaps); !errors.Is(err, ErrShortFrame) {
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
		typ, body, err := ReadMessage(bytes.NewReader(append(frameHeader(2), Version, TypeIssueRequest)), RequestCaps)
		if err != nil || typ != TypeIssueRequest || len(body) != 0 {
			t.Fatalf("ReadMessage of a header-only frame = %#x, %d body bytes, %v; want the issue type, no body, no error", typ, len(body), err)
		}
	})
	// RequestCaps is the signer's; ResponseCaps(want) a client's waiting
	// for want.
	issueClient, directoryClient := ResponseCaps(TypeIssueResponse), ResponseCaps(TypeGetDirectoryResponse)
	accepted := []struct {
		name    string
		caps    Caps
		msgType byte
		length  int
	}{
		{"issue_exactly_max_frame", RequestCaps, TypeIssueRequest, MaxFrame},
		{"install_exactly_max_directory_frame", RequestCaps, TypeInstallDirectory, MaxDirectoryFrame},
		{"unknown_type_exactly_max_frame", RequestCaps, 0x7e, MaxFrame},
		{"get_directory_response_to_signer_exactly_max_frame", RequestCaps, TypeGetDirectoryResponse, MaxFrame},
		{"get_directory_response_exactly_max_directory_frame", directoryClient, TypeGetDirectoryResponse, MaxDirectoryFrame},
		{"issue_response_exactly_max_frame", issueClient, TypeIssueResponse, MaxFrame},
		{"error_exactly_max_frame", issueClient, TypeError, MaxFrame},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			in := frameOf(t, tc.msgType, tc.length-headerLen)
			if got := binary.BigEndian.Uint32(in); got != uint32(tc.length) { //nolint:gosec // G115: test lengths fit
				t.Fatalf("frame length %d, want %d", got, tc.length)
			}
			typ, body, err := ReadMessage(bytes.NewReader(in), tc.caps)
			if err != nil || typ != tc.msgType || len(body) != tc.length-headerLen {
				t.Fatalf("ReadMessage = %#x, %d body bytes, %v; want %#x with %d body bytes", typ, len(body), err, tc.msgType, tc.length-headerLen)
			}
		})
	}
	refused := []struct {
		name    string
		caps    Caps
		msgType byte
		length  uint32
		wantErr error
	}{
		{"issue_max_frame_plus_one", RequestCaps, TypeIssueRequest, MaxFrame + 1, ErrFrameTooLarge},
		{"login_max_frame_plus_one", RequestCaps, TypeLoginIssueRequest, MaxFrame + 1, ErrFrameTooLarge},
		{"install_max_directory_frame_plus_one", RequestCaps, TypeInstallDirectory, MaxDirectoryFrame + 1, ErrFrameTooLarge},
		{"unknown_type_max_frame_plus_one", RequestCaps, 0x7e, MaxFrame + 1, ErrFrameTooLarge},
		// The signer reads no response type at the directory cap.
		{"get_directory_response_to_signer_max_frame_plus_one", RequestCaps, TypeGetDirectoryResponse, MaxFrame + 1, ErrFrameTooLarge},
		{"get_directory_response_max_directory_frame_plus_one", directoryClient, TypeGetDirectoryResponse, MaxDirectoryFrame + 1, ErrFrameTooLarge},
		{"error_max_frame_plus_one", issueClient, TypeError, MaxFrame + 1, ErrFrameTooLarge},
		// A client refuses every type but the one it waits for and errors.
		{"get_directory_response_on_issue", issueClient, TypeGetDirectoryResponse, MaxDirectoryFrame, ErrUnexpectedType},
		{"install_directory_on_issue", issueClient, TypeInstallDirectory, MaxDirectoryFrame, ErrUnexpectedType},
		{"issue_response_on_get_directory", directoryClient, TypeIssueResponse, MaxFrame, ErrUnexpectedType},
		{"unknown_type_on_issue", issueClient, 0x7e, 3, ErrUnexpectedType},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReader{hdr: append(frameHeader(tc.length), Version, tc.msgType)}
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			_, _, err := ReadMessage(r, tc.caps)
			runtime.ReadMemStats(&after)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReadMessage error = %v, want %v", err, tc.wantErr)
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
		caps    Caps // of the reader that reads it back
	}{
		{"issue", TypeIssueRequest, MaxFrame - headerLen, RequestCaps},
		{"install_directory", TypeInstallDirectory, MaxDirectoryFrame - headerLen, RequestCaps},
		{"get_directory_response", TypeGetDirectoryResponse, MaxDirectoryFrame - headerLen, ResponseCaps(TypeGetDirectoryResponse)},
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
			typ, got, err := ReadMessage(&buf, tc.caps)
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

// TestParseLoginIssueSigningBytes: the signing bytes a login_issue leaf
// stores (02-04) parse back to the request, from the golden vector, and
// every other encoding is refused: no or another domain tag, a request
// body (Marshal's encoding, evidence included), an evidence section after
// the fields, a truncation, and field limits.
func TestParseLoginIssueSigningBytes(t *testing.T) {
	file, err := os.ReadFile(filepath.Join(vectorDir, "login_request_signing_v1.hex")) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatal(err)
	}
	vector, err := hex.DecodeString(strings.TrimSpace(string(file)))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("golden_vector_round_trip", func(t *testing.T) {
		got, err := ParseLoginIssueSigningBytes(vector)
		if err != nil {
			t.Fatal(err)
		}
		if want := loginVector(t); !reflect.DeepEqual(got, want) {
			t.Fatalf("parsed vector:\n got %+v\nwant %+v", got, want)
		}
		if !bytes.Equal(got.SigningBytes(), vector) || got.Evidence != nil {
			t.Fatal("the parsed vector does not re-encode to itself, or carries evidence")
		}
	})
	t.Run("with_extensions_and_roles", func(t *testing.T) {
		r := loginVector(t)
		r.Roles = []string{"dev", "ops"}
		r.Extensions = []string{"permit-agent-forwarding"}
		got, err := ParseLoginIssueSigningBytes(r.SigningBytes())
		if err != nil || !reflect.DeepEqual(got, r) {
			t.Fatalf("round trip = %+v, %v; want %+v", got, err, r)
		}
	})
	r := loginVector(t)
	r.Evidence = []Evidence{{Type: EvidenceWebAuthnAssertion, Blob: []byte("assertion")}}
	body, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tooMany := loginVector(t)
	for i := range MaxLoginRoles + 1 {
		tooMany.Roles = append(tooMany.Roles, "r"+strings.Repeat("x", i))
	}
	emptyRole := loginVector(t)
	emptyRole.Roles = []string{""}
	for name, in := range map[string][]byte{
		"empty":                    {},
		"no_domain_tag":            vector[len(LoginRequestDomain):],
		"other_domain_tag":         append([]byte("keyroster/issue-request/v1"), vector[len(LoginRequestDomain):]...),
		"request_body_not_signing": body,
		"evidence_section_after":   append(append([]byte(nil), vector...), 0, 0),
		"trailing_byte":            append(append([]byte(nil), vector...), 0),
		"truncated":                vector[:len(vector)-1],
		"tag_only":                 []byte(LoginRequestDomain),
		"too_many_roles":           tooMany.SigningBytes(),
		"empty_role_name":          emptyRole.SigningBytes(),
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := ParseLoginIssueSigningBytes(in); !errors.Is(err, ErrMalformed) || got != nil {
				t.Fatalf("ParseLoginIssueSigningBytes = %+v, %v; want nil and ErrMalformed", got, err)
			}
		})
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

// revokeVector is the revoke request of
// test/vectors/revoke_request_signing_v1.hex: target serial, the user CA,
// serial 1700000000000001, request id 0x00..0x0f, created 1700000000,
// reason "key lost".
func revokeVector() *RevokeRequest {
	r := &RevokeRequest{Target: TargetSerial, CARole: CARoleUser, Serial: 1_700_000_000_000_001, CreatedAt: 1700000000, Reason: "key lost"}
	for i := range r.RequestID {
		r.RequestID[i] = byte(i)
	}
	return r
}

// testRevokeInstallationID is the installation ID of the v2 revoke
// vectors.
const testRevokeInstallationID = "000102030405060708090a0b0c0d0e0f"

// revokeVectorV2 is the revoke request of
// test/vectors/revoke_request_signing_v2.hex: revokeVector for the
// installation testRevokeInstallationID.
func revokeVectorV2() *RevokeRequest {
	r := revokeVector()
	r.InstallationID = testRevokeInstallationID
	return r
}

// TestRevokeRequest: the revoke request round-trips with its evidence,
// its signing bytes start with the raw v2 domain tag, name the
// installation and leave the evidence out, and the parser refuses an
// unknown target, a CA role outside the wire.CARole enum, serial 0, a
// reason with a control byte or above 256 bytes, trailing bytes, a body
// without an installation ID (a 03-01 v1 body) and an installation ID not
// of the bundle form; Marshal refuses a v1 request.
func TestRevokeRequest(t *testing.T) {
	r := revokeVectorV2()
	r.Evidence = []Evidence{{Type: EvidenceAdminSSHSIG, Blob: []byte("sig")}}
	body, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("v1_marshal_refused", func(t *testing.T) {
		v1 := revokeVector()
		if _, err := v1.Marshal(); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Marshal of a v1 request: %v, want ErrMalformed", err)
		}
	})
	t.Run("round_trip", func(t *testing.T) {
		got, err := ParseRevokeRequest(body)
		if err != nil || !reflect.DeepEqual(got, r) {
			t.Fatalf("ParseRevokeRequest = %+v, %v; want %+v", got, err, r)
		}
	})
	t.Run("signing_bytes", func(t *testing.T) {
		sb := r.SigningBytes()
		if !bytes.HasPrefix(sb, []byte("keyroster/revoke-request/v2\x00\x20"+testRevokeInstallationID)) ||
			RevokeSSHSIGNamespace != RevokeRequestDomain || r.Namespace() != RevokeSSHSIGNamespace {
			t.Fatalf("signing bytes %q", sb[:min(len(sb), 64)])
		}
		if v1 := revokeVector(); v1.Namespace() != RevokeSSHSIGNamespaceV1 || RevokeSSHSIGNamespaceV1 != "keyroster/revoke-request/v1" {
			t.Fatalf("a v1 request's namespace is %q", v1.Namespace())
		}
		noEv := *r
		noEv.Evidence = nil
		if !bytes.Equal(noEv.SigningBytes(), sb) || r.Digest() != sha256.Sum256(sb) {
			t.Fatal("the evidence is part of the signing bytes, or Digest is not their SHA-256")
		}
		if TypeRevokeRequest != 0x06 || TypeGetKRL != 0x07 || TypeRevokeResponse != 0x86 || TypeGetKRLResponse != 0x87 {
			t.Fatal("a revoke message type changed")
		}
	})
	// mutate re-encodes r with edit applied to the encoded fields, bypassing
	// Marshal's own checks.
	mutate := func(edit func(r *RevokeRequest)) []byte {
		c := *r
		edit(&c)
		var b cryptobyte.Builder
		c.addFields(&b)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, e := range c.Evidence {
				addBytes16(b, []byte(e.Type))
				addBytes16(b, e.Blob)
			}
		})
		out, err := b.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for name, data := range map[string][]byte{
		"target_5_refused":            mutate(func(r *RevokeRequest) { r.Target = 5 }),
		"ca_role_out_of_range_0":      mutate(func(r *RevokeRequest) { r.CARole = 0 }),
		"ca_role_out_of_range_4":      mutate(func(r *RevokeRequest) { r.CARole = 4 }),
		"serial_zero_refused":         mutate(func(r *RevokeRequest) { r.Serial = 0 }),
		"reason_control_byte_refused": mutate(func(r *RevokeRequest) { r.Reason = "key\nlost" }),
		"reason_too_long_refused":     mutate(func(r *RevokeRequest) { r.Reason = strings.Repeat("x", MaxRevokeReason+1) }),
		"trailing_byte_refused":       append(bytes.Clone(body), 0),
		"truncated_refused":           body[:len(body)-1],
		"v1_body_refused":             mutate(func(r *RevokeRequest) { r.InstallationID = "" }),
		// The v2 layout with a zero-length installation ID: the fields
		// after it are a valid serial request, so without the refusal of an
		// empty ID it would parse as a v1 request (03-03b carry-over).
		"v2_layout_empty_installation_id": append([]byte{0, 0}, mutate(func(r *RevokeRequest) { r.InstallationID = "" })...),
		"installation_id_upper_case":      mutate(func(r *RevokeRequest) { r.InstallationID = strings.ToUpper(testRevokeInstallationID) }),
		"installation_id_short":           mutate(func(r *RevokeRequest) { r.InstallationID = testRevokeInstallationID[1:] }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRevokeRequest(data); !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseRevokeRequest: %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("responses_round_trip", func(t *testing.T) {
		rr := &RevokeResponse{KRLVersion: 3, RevokeLeaf: 7, PublishLeaf: 8}
		b, err := rr.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if got, err := ParseRevokeResponse(b); err != nil || !reflect.DeepEqual(got, rr) {
			t.Fatalf("ParseRevokeResponse = %+v, %v", got, err)
		}
		if _, err := (&RevokeResponse{}).Marshal(); err == nil {
			t.Fatal("a RevokeResponse with KRL version 0 marshals")
		}
		for _, g := range []*GetKRLResponse{{}, {KRL: []byte("krl"), Manifest: []byte("m"), Sig: []byte("s")}} {
			b, err := g.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if got, err := ParseGetKRLResponse(b); err != nil || !reflect.DeepEqual(got, g) {
				t.Fatalf("ParseGetKRLResponse = %+v, %v; want %+v", got, err, g)
			}
		}
		if _, err := (&GetKRLResponse{KRL: []byte("krl")}).Marshal(); err == nil {
			t.Fatal("a GetKRLResponse with a KRL but no manifest marshals")
		}
	})
}

// TestRevokeRequestSigningVector pins the revoke request's signing bytes:
// they equal the golden file, start with the raw domain tag, Digest is
// their SHA-256, and ParseRevokeSigningBytes reads them back. v1 is the
// 03-01 serial request, which audit verify still reads from logs; v2 (the
// pre-merge review of PR #61, owner decision 2026-10-26) is the same
// request for an installation.
func TestRevokeRequestSigningVector(t *testing.T) {
	for _, tc := range []struct {
		file, domain string
		r            *RevokeRequest
	}{
		{"revoke_request_signing_v1.hex", RevokeRequestDomainV1, revokeVector()},
		{"revoke_request_signing_v2.hex", RevokeRequestDomain, revokeVectorV2()},
	} {
		t.Run(tc.file, func(t *testing.T) {
			got := tc.r.SigningBytes()
			path := filepath.Join(vectorDir, tc.file)
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
				t.Fatalf("revoke request signing bytes differ from %s\ngot:  %x\nwant: %x", path, got, want)
			}
			if !bytes.HasPrefix(want, []byte(tc.domain)) || tc.r.Digest() != sha256.Sum256(want) {
				t.Fatal("the vector does not start with the domain tag, or Digest is not its SHA-256")
			}
			if p, err := ParseRevokeSigningBytes(want); err != nil || !reflect.DeepEqual(p, tc.r) {
				t.Fatalf("ParseRevokeSigningBytes = %+v, %v; want %+v", p, err, tc.r)
			}
		})
	}
}

// TestKRLFrameBound (F12): a GetKRLResponse frame of exactly MaxKRLFrame
// is read through ResponseCaps(TypeGetKRLResponse) and one of
// MaxKRLFrame+1 is refused; a GetKRLResponse of the largest legal content
// marshals within MaxKRLFrame; RevokeRequest stays capped at MaxFrame and
// RequestCaps is unchanged.
func TestKRLFrameBound(t *testing.T) {
	frame := func(n int, typ byte) []byte {
		buf := make([]byte, 4+n)
		binary.BigEndian.PutUint32(buf, uint32(n)) //nolint:gosec // G115: test sizes
		buf[4], buf[5] = Version, typ
		return buf
	}
	if typ, body, err := ReadMessage(bytes.NewReader(frame(MaxKRLFrame, TypeGetKRLResponse)), ResponseCaps(TypeGetKRLResponse)); err != nil ||
		typ != TypeGetKRLResponse || len(body) != MaxKRLFrame-headerLen {
		t.Fatalf("a frame of MaxKRLFrame: %v", err)
	}
	if _, _, err := ReadMessage(bytes.NewReader(frame(MaxKRLFrame+1, TypeGetKRLResponse)), ResponseCaps(TypeGetKRLResponse)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a frame of MaxKRLFrame+1: %v, want ErrFrameTooLarge", err)
	}
	full := &GetKRLResponse{KRL: make([]byte, MaxKRLBytes), Manifest: make([]byte, maxKRLManifest), Sig: make([]byte, maxKRLManifestSig)}
	body, err := full.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if headerLen+len(body) > MaxKRLFrame {
		t.Fatalf("the largest GetKRLResponse is a frame of %d bytes, above MaxKRLFrame %d", headerLen+len(body), MaxKRLFrame)
	}
	var w bytes.Buffer
	if err := WriteMessage(&w, TypeGetKRLResponse, body); err != nil {
		t.Fatalf("WriteMessage of the largest GetKRLResponse: %v", err)
	}
	if got, err := ParseGetKRLResponse(body); err != nil || len(got.KRL) != MaxKRLBytes {
		t.Fatalf("ParseGetKRLResponse of the largest response: %v", err)
	}
	if err := WriteMessage(io.Discard, TypeRevokeRequest, make([]byte, MaxFrame-headerLen+1)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a RevokeRequest above MaxFrame: %v, want ErrFrameTooLarge", err)
	}
	for _, typ := range []byte{TypeRevokeRequest, TypeGetKRL, TypeGetKRLResponse} {
		if n, ok := RequestCaps(typ); !ok || n != MaxFrame {
			t.Fatalf("RequestCaps(%#x) = %d, %v; want MaxFrame", typ, n, ok)
		}
	}
}

// TestRevokeResponse (03-03): the answer of a subject revocation lists up
// to MaxRevokeAnswerSerials serials, ascending and unique, and as many as
// min(SerialCount, MaxRevokeAnswerSerials); every other shape is refused,
// on Marshal and on ParseRevokeResponse alike.
func TestRevokeResponse(t *testing.T) {
	serials := func(n int) []uint64 {
		out := make([]uint64, n)
		for i := range out {
			out[i] = uint64(1000 + 2*i) //nolint:gosec // G115: test serials
		}
		return out
	}
	// raw encodes r without Marshal's checks.
	raw := func(r *RevokeResponse, n int) []byte {
		var b cryptobyte.Builder
		b.AddUint64(r.KRLVersion)
		b.AddUint64(r.RevokeLeaf)
		b.AddUint64(r.PublishLeaf)
		b.AddUint32(r.SerialCount)
		b.AddUint16(uint16(n)) //nolint:gosec // G115: test sizes
		for _, s := range r.Serials {
			b.AddUint64(s)
		}
		out, err := b.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, tc := range []struct {
		name string
		r    *RevokeResponse
	}{
		{"no_serials_round_trip", &RevokeResponse{KRLVersion: 1792869357, RevokeLeaf: 7, PublishLeaf: 8}},
		{"two_serials_round_trip", &RevokeResponse{KRLVersion: 9, RevokeLeaf: 7, PublishLeaf: 8, SerialCount: 2, Serials: []uint64{5, 9}}},
		{"4096_listed_round_trip", &RevokeResponse{KRLVersion: 9, RevokeLeaf: 7, PublishLeaf: 8, SerialCount: 4096, Serials: serials(4096)}},
		{"count_above_list_round_trip", &RevokeResponse{KRLVersion: 9, RevokeLeaf: 8, PublishLeaf: 9, SerialCount: 4097, Serials: serials(4096)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.r.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if 4+len(b) > MaxFrame-headerLen {
				t.Fatalf("a %d-byte answer does not fit a frame", len(b))
			}
			got, err := ParseRevokeResponse(b)
			if err != nil || !reflect.DeepEqual(got, tc.r) {
				t.Fatalf("ParseRevokeResponse = %+v, %v", got, err)
			}
		})
	}
	for _, tc := range []struct {
		name string
		r    *RevokeResponse
	}{
		{"4097_listed_refused", &RevokeResponse{KRLVersion: 9, SerialCount: 4097, Serials: serials(4097)}},
		{"unsorted_refused", &RevokeResponse{KRLVersion: 9, SerialCount: 2, Serials: []uint64{9, 5}}},
		{"duplicated_refused", &RevokeResponse{KRLVersion: 9, SerialCount: 2, Serials: []uint64{5, 5}}},
		{"count_below_list_refused", &RevokeResponse{KRLVersion: 9, SerialCount: 1, Serials: []uint64{5, 9}}},
		{"list_short_of_count_refused", &RevokeResponse{KRLVersion: 9, SerialCount: 3, Serials: []uint64{5, 9}}},
		{"krl_version_0_refused", &RevokeResponse{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.r.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Marshal: %v, want ErrMalformed", err)
			}
			if _, err := ParseRevokeResponse(raw(tc.r, len(tc.r.Serials))); !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseRevokeResponse: %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("trailing_bytes_refused", func(t *testing.T) {
		b, err := (&RevokeResponse{KRLVersion: 9, SerialCount: 1, Serials: []uint64{5}}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseRevokeResponse(append(b, 0)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseRevokeResponse: %v, want ErrMalformed", err)
		}
	})
}

// revokeTargets is one valid request per revocation target, created at
// 1700000000 with request ID 0x00..0x0f.
func revokeTargets(t testing.TB) map[string]*RevokeRequest {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*RevokeRequest{
		"serial":  {Target: TargetSerial, CARole: CARoleUser, Serial: 1_700_000_000_000_001},
		"key_id":  {Target: TargetKeyID, CARole: CARoleHost, KeyID: "kr1/ca=host/sub=web1/req=000102030405060708090a0b0c0d0e0f/pol=1/ser=7"},
		"key":     {Target: TargetKey, Key: key.Marshal()},
		"subject": {Target: TargetSubject, SubjectKind: SubjectUser, Subject: "alice"},
	}
	for _, r := range out {
		r.InstallationID, r.CreatedAt, r.Reason = testRevokeInstallationID, 1700000000, "key lost"
		for i := range r.RequestID {
			r.RequestID[i] = byte(i)
		}
	}
	return out
}

// TestParseRevokeSigningBytes (03-03): the logged request bytes of every
// target round-trip with SigningBytes; a wrong domain tag, an unknown
// target, an unknown CA role or subject kind, a field the target does not
// carry, a certificate or non-canonical key, a subject outside the key ID
// grammar and trailing bytes are refused.
func TestParseRevokeSigningBytes(t *testing.T) {
	for name, r := range revokeTargets(t) {
		t.Run(name+"_round_trip", func(t *testing.T) {
			sb := r.SigningBytes()
			got, err := ParseRevokeSigningBytes(sb)
			if err != nil || !reflect.DeepEqual(got, r) || !bytes.Equal(got.SigningBytes(), sb) {
				t.Fatalf("ParseRevokeSigningBytes = %+v, %v; want %+v", got, err, r)
			}
			body, err := r.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if p, err := ParseRevokeRequest(body); err != nil || !reflect.DeepEqual(p, r) {
				t.Fatalf("ParseRevokeRequest = %+v, %v", p, err)
			}
		})
	}
	targets := revokeTargets(t)
	// raw is the signing bytes of r with edit applied, bypassing Validate.
	raw := func(name string, edit func(*RevokeRequest)) []byte {
		c := *targets[name]
		edit(&c)
		var b cryptobyte.Builder
		b.AddBytes([]byte(RevokeRequestDomain))
		c.addFields(&b)
		return b.BytesOrPanic()
	}
	// layoutV1 is the signing bytes of target name without an installation
	// ID (the 03-01 layout) under the domain tag domain.
	layoutV1 := func(domain, name string) []byte {
		c := *targets[name]
		c.InstallationID = ""
		var b cryptobyte.Builder
		b.AddBytes([]byte(domain))
		c.addFields(&b)
		return b.BytesOrPanic()
	}
	signer, err := ssh.NewSignerFromKey(mustPriv(t))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := cert.Build(cert.Request{Profile: cert.DefaultUserProfile(), Subject: mustKey(t), Principals: []string{"alice"},
		Now: time.Unix(1700000000, 0), ValidFor: time.Hour, Serial: 7,
		KeyID: cert.KeyID{CA: "user", Subject: "alice", Request: "000102030405060708090a0b0c0d0e0f", Policy: 1, Serial: 7}}, signer, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	padded := append([]byte{0, 0, 0, 0x0c}, []byte("ssh-ed25519x")...) // not a key
	for name, data := range map[string][]byte{
		"wrong_domain_tag_refused":     append([]byte("keyroster/issue-request/v1"), targets["serial"].SigningBytes()[len(RevokeRequestDomain):]...),
		"no_domain_tag_refused":        targets["serial"].SigningBytes()[len(RevokeRequestDomain):],
		"unknown_target_refused":       raw("serial", func(r *RevokeRequest) { r.Target = 5 }),
		"target_0_refused":             raw("serial", func(r *RevokeRequest) { r.Target = 0 }),
		"unknown_ca_role_refused":      raw("key_id", func(r *RevokeRequest) { r.CARole = 4 }),
		"ca_role_0_refused":            raw("serial", func(r *RevokeRequest) { r.CARole = 0 }),
		"unknown_subject_kind_refused": raw("subject", func(r *RevokeRequest) { r.SubjectKind = 4 }),
		"subject_with_slash_refused":   raw("subject", func(r *RevokeRequest) { r.Subject = "alice/x" }),
		"subject_upper_case_refused":   raw("subject", func(r *RevokeRequest) { r.Subject = "Alice" }),
		"empty_key_id_refused":         raw("key_id", func(r *RevokeRequest) { r.KeyID = "" }),
		"key_id_control_byte_refused":  raw("key_id", func(r *RevokeRequest) { r.KeyID = "a\nb" }),
		"key_id_too_long_refused":      raw("key_id", func(r *RevokeRequest) { r.KeyID = strings.Repeat("k", MaxRevokeKeyID+1) }),
		"certificate_as_key_refused":   raw("key", func(r *RevokeRequest) { r.Key = certificate.Marshal() }),
		"unparsable_key_refused":       raw("key", func(r *RevokeRequest) { r.Key = padded }),
		"empty_key_refused":            raw("key", func(r *RevokeRequest) { r.Key = nil }),
		"serial_zero_refused":          raw("serial", func(r *RevokeRequest) { r.Serial = 0 }),
		"trailing_byte_refused":        append(targets["subject"].SigningBytes(), 0),
		"truncated_refused":            targets["key"].SigningBytes()[:len(targets["key"].SigningBytes())-1],
		"reason_control_byte_refused":  raw("key", func(r *RevokeRequest) { r.Reason = "a\tb" }),
		"key_id_trailing_byte_refused": append(raw("key_id", func(*RevokeRequest) {}), 0),
		// v1 (03-01) carries only serial revocations, and a v2 tag always
		// names an installation (pre-merge review of PR #61).
		"v1_key_id_refused":           layoutV1(RevokeRequestDomainV1, "key_id"),
		"v1_key_refused":              layoutV1(RevokeRequestDomainV1, "key"),
		"v1_subject_refused":          layoutV1(RevokeRequestDomainV1, "subject"),
		"v2_without_installation_id":  layoutV1(RevokeRequestDomain, "serial"),
		"v2_empty_installation_id":    append(append([]byte(RevokeRequestDomain), 0, 0), layoutV1(RevokeRequestDomain, "serial")[len(RevokeRequestDomain):]...),
		"installation_id_not_hex":     raw("serial", func(r *RevokeRequest) { r.InstallationID = strings.Repeat("g", 32) }),
		"v1_tag_with_installation_id": append([]byte(RevokeRequestDomainV1), targets["serial"].SigningBytes()[len(RevokeRequestDomain):]...),
	} {
		t.Run(name, func(t *testing.T) {
			if r, err := ParseRevokeSigningBytes(data); r != nil || !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseRevokeSigningBytes = %+v, %v; want ErrMalformed", r, err)
			}
		})
	}
	t.Run("non_canonical_key_refused", func(t *testing.T) {
		// An RSA key whose exponent carries a superfluous leading zero:
		// ssh.ParsePublicKey accepts it, Marshal is one byte shorter.
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		blob := ssh.Marshal(struct {
			Name string
			E    []byte
			N    *big.Int
		}{ssh.KeyAlgoRSA, []byte{0, 1, 0, 1}, k.N})
		if pub, err := ssh.ParsePublicKey(blob); err != nil || bytes.Equal(pub.Marshal(), blob) {
			t.Fatalf("the padded RSA key: %v, or it is canonical", err)
		}
		data := raw("key", func(r *RevokeRequest) { r.Key = blob })
		if r, err := ParseRevokeSigningBytes(data); r != nil || !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseRevokeSigningBytes = %+v, %v; want ErrMalformed", r, err)
		}
	})
	t.Run("field_of_another_target_refused", func(t *testing.T) {
		for name, edit := range map[string]func(*RevokeRequest){
			"key_with_ca_role":    func(r *RevokeRequest) { r.CARole = CARoleUser },
			"subject_with_serial": func(r *RevokeRequest) { r.Serial = 3 },
			"serial_with_key_id":  func(r *RevokeRequest) { r.KeyID = "x" },
			"key_id_with_subject": func(r *RevokeRequest) { r.Subject = "alice" },
		} {
			target := map[string]string{"key_with_ca_role": "key", "subject_with_serial": "subject", "serial_with_key_id": "serial", "key_id_with_subject": "key_id"}[name]
			c := *targets[target]
			edit(&c)
			if err := c.Validate(); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: Validate = %v, want ErrMalformed", name, err)
			}
			if _, err := c.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: Marshal = %v, want ErrMalformed", name, err)
			}
		}
	})
}

func mustPriv(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func mustKey(t testing.TB) ssh.PublicKey {
	t.Helper()
	k, err := ssh.NewPublicKey(mustPriv(t).Public())
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// recoveryCert returns a fixed user certificate with serial, deterministic
// for the golden vector: Ed25519 keys from fixed seeds, a zero nonce and a
// kr1 key ID naming the serial.
func recoveryCert(t testing.TB, serial uint64) []byte {
	t.Helper()
	ca, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xca}, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5b}, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	c := &ssh.Certificate{
		Key: sub, Serial: serial, CertType: ssh.UserCert, ValidPrincipals: []string{"alice"},
		KeyId:      cert.KeyID{CA: "user", Subject: "u:alice", Request: strings.Repeat("ab", 16), Policy: 1, Serial: serial}.String(),
		ValidAfter: 1_790_000_000, ValidBefore: 1_790_003_600, Nonce: make([]byte, 32), SignatureKey: ca.PublicKey(),
	}
	// Signed by hand (only cert.Build may call SignCert, CA-06); Ed25519
	// signatures are deterministic, so the vector is stable.
	out := c.Marshal()
	sig, err := ca.Sign(nil, out[:len(out)-4]) // without the empty signature's length prefix
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = sig
	return c.Marshal()
}

const testRecoveryInstallationID = "0123456789abcdef0123456789abcdef"

// recoveryVector is the recovery request of
// test/vectors/recovery_request_signing_v1.hex: one import, one carried
// certificate to revoke.
func recoveryVector(t testing.TB) *RecoveryRequest {
	t.Helper()
	r := &RecoveryRequest{
		InstallationID: testRecoveryInstallationID,
		CreatedAt:      1_790_000_100,
		RestoredSize:   12,
		Imports:        []RecoveryImport{{KRL: []byte("krl (test vector)"), Manifest: []byte("manifest (test vector)"), Sig: []byte("sig (test vector)")}},
		Certificates:   []RecoveredCertificate{{Cert: recoveryCert(t, 1_790_000_000_000_001), Revoke: true}},
	}
	for i := range r.RequestID {
		r.RequestID[i] = byte(0x40 + i)
	}
	for i := range r.RestoredRoot {
		r.RestoredRoot[i] = byte(0x80 + i)
	}
	return r
}

// TestRecoveryCertificateCap (PR #69 review, D-R2): a request carries more
// certificates than the old cap of 4096, and MaxRecoveryCertificates, the
// most the uint16 count holds, never binds before MaxRecoveryRequest: even
// the smallest certificate that parses takes more than
// MaxRecoveryRequest / MaxRecoveryCertificates bytes in a request.
func TestRecoveryCertificateCap(t *testing.T) {
	if MaxRecoveryCertificates != 1<<16-1 {
		t.Fatalf("MaxRecoveryCertificates = %d, want the uint16 count's maximum", MaxRecoveryCertificates)
	}
	r := recoveryVector(t)
	r.Certificates = nil
	for i := range 5000 {
		r.Certificates = append(r.Certificates, RecoveredCertificate{Cert: recoveryCert(t, 1_790_000_000_000_001+uint64(i))}) //nolint:gosec // G115: a test index
	}
	data, err := r.Marshal()
	if err != nil {
		t.Fatalf("Marshal with 5000 certificates: %v", err)
	}
	got, err := ParseRecoveryRequest(data)
	if err != nil || len(got.Certificates) != 5000 {
		t.Fatalf("ParseRecoveryRequest with 5000 certificates: %v", err)
	}

	ca, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xca}, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x5b}, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	smallest := (&ssh.Certificate{Key: sub, CertType: ssh.UserCert, SignatureKey: ca,
		Signature: &ssh.Signature{Format: ssh.KeyAlgoED25519, Blob: make([]byte, ed25519.SignatureSize)}}).Marshal()
	if pub, err := ssh.ParsePublicKey(smallest); err != nil {
		t.Fatalf("the smallest certificate does not parse: %v", err)
	} else if _, ok := pub.(*ssh.Certificate); !ok {
		t.Fatal("the smallest certificate is not a certificate")
	}
	per := len(smallest) + 3 + 1 // the uint24 length and the revoke byte
	if per*MaxRecoveryCertificates <= MaxRecoveryRequest {
		t.Fatalf("%d certificates of %d bytes fit in %d bytes: the count cap would bind first", MaxRecoveryCertificates, per, MaxRecoveryRequest)
	}
	t.Logf("the smallest certificate takes %d bytes, so at most %d fit in a request", per, MaxRecoveryRequest/per)
}

// TestRecoveryRequest (03-06b): a recovery request round-trips in its
// file form (Marshal, ParseRecoveryRequest) and its logged form
// (SigningBytes, ParseRecoverySigningBytes); the parsers and the encoders
// refuse an empty installation ID, more than MaxRecoveryImports imports, a
// KRL above MaxRecoveryKRL, two imports with the same manifest, unsorted
// or repeated certificate serials, more than MaxRecoveryCertificates
// certificates, trailing bytes and a wrong domain tag.
func TestRecoveryRequest(t *testing.T) {
	r := recoveryVector(t)
	r.Evidence = []Evidence{{Type: EvidenceAdminSSHSIG, Blob: []byte("sig")}}
	file, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRecoveryRequest(file)
	if err != nil || !reflect.DeepEqual(got, r) {
		t.Fatalf("ParseRecoveryRequest = %+v, %v", got, err)
	}
	sb, err := r.SigningBytes()
	if err != nil || !bytes.HasPrefix(sb, []byte(RecoveryRequestDomain)) || !bytes.HasPrefix(file, sb) || RecoverySSHSIGNamespace != RecoveryRequestDomain {
		t.Fatalf("SigningBytes = %x, %v; want the raw domain tag first and a prefix of the file form", sb, err)
	}
	logged, err := ParseRecoverySigningBytes(sb)
	if err != nil || logged.Evidence != nil || !reflect.DeepEqual(logged.Imports, r.Imports) || !reflect.DeepEqual(logged.Certificates, r.Certificates) {
		t.Fatalf("ParseRecoverySigningBytes = %+v, %v", logged, err)
	}
	if again, err := logged.SigningBytes(); err != nil || !bytes.Equal(again, sb) {
		t.Fatalf("the logged form does not re-encode: %v", err)
	}
	certA, certB := recoveryCert(t, 5), recoveryCert(t, 9)
	for name, edit := range map[string]func(*RecoveryRequest){
		"empty_installation_id": func(r *RecoveryRequest) { r.InstallationID = "" },
		"too_many_imports": func(r *RecoveryRequest) {
			r.Imports = nil
			for i := range MaxRecoveryImports + 1 {
				r.Imports = append(r.Imports, RecoveryImport{KRL: []byte("k"), Manifest: []byte{byte(i)}, Sig: []byte("s")})
			}
		},
		"krl_above_cap":  func(r *RecoveryRequest) { r.Imports[0].KRL = make([]byte, MaxRecoveryKRL+1) },
		"same_manifest":  func(r *RecoveryRequest) { r.Imports = append(r.Imports, r.Imports[0]) },
		"empty_manifest": func(r *RecoveryRequest) { r.Imports[0].Manifest = nil },
		"unsorted_serials": func(r *RecoveryRequest) {
			r.Certificates = []RecoveredCertificate{{Cert: certB}, {Cert: certA}}
		},
		"repeated_serial": func(r *RecoveryRequest) {
			r.Certificates = []RecoveredCertificate{{Cert: certA}, {Cert: certA, Revoke: true}}
		},
		"too_many_certificates": func(r *RecoveryRequest) {
			r.Certificates = make([]RecoveredCertificate, MaxRecoveryCertificates+1)
			for i := range r.Certificates {
				r.Certificates[i].Cert = certA
			}
		},
		"plain_key_as_certificate": func(r *RecoveryRequest) {
			pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
			if err != nil {
				t.Fatal(err)
			}
			r.Certificates = []RecoveredCertificate{{Cert: pub.Marshal()}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := recoveryVector(t)
			edit(bad)
			if _, err := bad.SigningBytes(); !errors.Is(err, ErrMalformed) {
				t.Fatalf("SigningBytes = %v, want ErrMalformed", err)
			}
			if _, err := bad.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Marshal = %v, want ErrMalformed", err)
			}
		})
	}
	t.Run("sorted_certificates_accepted", func(t *testing.T) {
		ok := recoveryVector(t)
		ok.Certificates = []RecoveredCertificate{{Cert: certA}, {Cert: certB, Revoke: true}}
		if _, err := ok.Marshal(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("trailing_bytes", func(t *testing.T) {
		if _, err := ParseRecoveryRequest(append(bytes.Clone(file), 0)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseRecoveryRequest with a trailing byte = %v", err)
		}
		if _, err := ParseRecoverySigningBytes(append(bytes.Clone(sb), 0)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseRecoverySigningBytes with a trailing byte = %v", err)
		}
	})
	t.Run("wrong_domain_tag", func(t *testing.T) {
		other := append([]byte(RevokeRequestDomain), sb[len(RecoveryRequestDomain):]...)
		if _, err := ParseRecoverySigningBytes(other); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseRecoverySigningBytes under %s = %v", RevokeRequestDomain, err)
		}
		if _, err := ParseRecoveryRequest(append([]byte("keyroster/revoke-recovery/v2"), file[len(RecoveryRequestDomain):]...)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseRecoveryRequest under another tag = %v", err)
		}
	})
	t.Run("revoke_byte_not_0_or_1", func(t *testing.T) {
		bad := bytes.Clone(sb)
		bad[len(bad)-1] = 2 // the revoke byte of the last certificate
		if _, err := ParseRecoverySigningBytes(bad); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseRecoverySigningBytes with revoke byte 2 = %v", err)
		}
	})
	t.Run("signing_bytes_above_cap", func(t *testing.T) {
		big := recoveryVector(t)
		big.Imports = nil
		for i := range 3 {
			big.Imports = append(big.Imports, RecoveryImport{KRL: make([]byte, MaxRecoveryKRL), Manifest: []byte{byte(i)}, Sig: []byte("s")})
		}
		if _, err := big.SigningBytes(); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "above") {
			t.Fatalf("SigningBytes of a request above MaxRecoveryRequest = %v", err)
		}
	})
}

// TestRecoveryRequestSigningVector pins the keyroster/revoke-recovery/v1
// signing bytes (test/vectors/recovery_request_signing_v1.hex), which
// every revocation_recovery leaf logs.
func TestRecoveryRequestSigningVector(t *testing.T) {
	got, err := recoveryVector(t).SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vectorDir, "recovery_request_signing_v1.hex")
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
		t.Fatalf("recovery request signing bytes differ from %s\ngot:  %x\nwant: %x", path, got, want)
	}
	if !bytes.HasPrefix(want, []byte(RecoveryRequestDomain)) {
		t.Fatalf("%s does not start with the domain tag %s", path, RecoveryRequestDomain)
	}
	r, err := ParseRecoverySigningBytes(want)
	if err != nil || len(r.Imports) != 1 || len(r.Certificates) != 1 || !r.Certificates[0].Revoke {
		t.Fatalf("ParseRecoverySigningBytes(%s) = %+v, %v", path, r, err)
	}
}
