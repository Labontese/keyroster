package wire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// statusRoles is the signer's role order.
var statusRoles = []string{"user", "host", "machine", "ops", "log"}

// validStatus is a StatusResponse as a software signer with an authorized
// directory reports it.
func validStatus() *StatusResponse {
	r := &StatusResponse{
		BundleVersion:       3,
		Bundle:              []byte(`{"version":3}` + "\n"),
		BundleSigs:          []byte("-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"),
		Policy:              []byte(`{"version":2}` + "\n"),
		PolicySigs:          []byte("-----BEGIN SSH SIGNATURE-----\nBBBB\n-----END SSH SIGNATURE-----\n"),
		DirectoryVersion:    7,
		DirectorySHA256:     [32]byte{1, 2, 3},
		DirectoryAuthorized: true,
	}
	for _, role := range statusRoles {
		r.Keys = append(r.Keys, KeyStatus{Role: role, Alg: "ssh-ed25519", Custody: "software", Fingerprint: "SHA256:" + role})
	}
	return r
}

// statusOfBodySize returns validStatus with Bundle padded so that its body
// encodes to exactly n bytes.
func statusOfBodySize(t *testing.T, n int) *StatusResponse {
	t.Helper()
	r := validStatus()
	base, err := r.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	r.Bundle = append(r.Bundle, bytes.Repeat([]byte{'x'}, n-len(base))...)
	return r
}

func equalStatus(a, b *StatusResponse) bool {
	if len(a.Keys) != len(b.Keys) {
		return false
	}
	for i := range a.Keys {
		if a.Keys[i] != b.Keys[i] {
			return false
		}
	}
	return a.BundleVersion == b.BundleVersion && bytes.Equal(a.Bundle, b.Bundle) && bytes.Equal(a.BundleSigs, b.BundleSigs) &&
		bytes.Equal(a.Policy, b.Policy) && bytes.Equal(a.PolicySigs, b.PolicySigs) && a.DirectoryVersion == b.DirectoryVersion &&
		a.DirectorySHA256 == b.DirectorySHA256 && a.DirectoryAuthorized == b.DirectoryAuthorized
}

func TestStatusResponseCodec(t *testing.T) {
	t.Run("round_trip", func(t *testing.T) {
		for name, r := range map[string]*StatusResponse{
			"authorized_directory": validStatus(),
			"no_directory": func() *StatusResponse {
				r := validStatus()
				r.DirectoryVersion, r.DirectorySHA256, r.DirectoryAuthorized = 0, [32]byte{}, false
				return r
			}(),
			"directory_not_authorized": func() *StatusResponse { r := validStatus(); r.DirectoryAuthorized = false; return r }(),
		} {
			t.Run(name, func(t *testing.T) {
				body, err := r.Marshal()
				if err != nil {
					t.Fatal(err)
				}
				got, err := ParseStatusResponse(body)
				if err != nil {
					t.Fatalf("ParseStatusResponse: %v", err)
				}
				if !equalStatus(got, r) {
					t.Fatalf("round trip: got %+v, want %+v", got, r)
				}
				again, err := got.Marshal()
				if err != nil || !bytes.Equal(again, body) {
					t.Fatalf("re-encoding differs (%v)", err)
				}
			})
		}
	})
	body, err := validStatus().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	t.Run("trailing_byte_refused", func(t *testing.T) {
		if _, err := ParseStatusResponse(append(append([]byte(nil), body...), 0)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("trailing byte: %v, want ErrMalformed", err)
		}
	})
	t.Run("truncated_refused", func(t *testing.T) {
		for n := range len(body) {
			if _, err := ParseStatusResponse(body[:n]); err == nil {
				t.Fatalf("a body truncated to %d of %d bytes parsed", n, len(body))
			}
		}
	})
	t.Run("more_than_8_keys_refused", func(t *testing.T) {
		r := validStatus()
		for len(r.Keys) <= MaxStatusKeys {
			r.Keys = append(r.Keys, r.Keys[0])
		}
		if _, err := r.Marshal(); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Marshal of %d keys = %v, want ErrMalformed", len(r.Keys), err)
		}
		// The same body built by hand: the parser refuses it too.
		r.Keys = r.Keys[:MaxStatusKeys]
		eight, err := r.Marshal()
		if err != nil {
			t.Fatalf("Marshal of %d keys: %v", MaxStatusKeys, err)
		}
		if _, err := ParseStatusResponse(eight); err != nil {
			t.Fatalf("ParseStatusResponse of %d keys: %v", MaxStatusKeys, err)
		}
		k := eight[1:]
		keyLen := 0
		for range 4 {
			keyLen += 2 + (int(k[keyLen])<<8 | int(k[keyLen+1]))
		}
		nine := append([]byte{MaxStatusKeys + 1}, k[:keyLen]...)
		nine = append(nine, k...)
		if _, err := ParseStatusResponse(nine); !errors.Is(err, ErrMalformed) {
			t.Fatalf("ParseStatusResponse of %d keys = %v, want ErrMalformed", MaxStatusKeys+1, err)
		}
	})
	t.Run("no_keys_refused", func(t *testing.T) {
		if _, err := (&StatusResponse{}).Marshal(); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Marshal without keys = %v, want ErrMalformed", err)
		}
		if _, err := ParseStatusResponse(append([]byte{0}, body[1:]...)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("a zero key count = %v, want ErrMalformed", err)
		}
	})
	t.Run("role_and_custody_must_be_tokens", func(t *testing.T) {
		// The CLI prints role names and keyroster-server puts role and
		// custody in a header: neither may carry anything but a token.
		for _, bad := range []string{"USER", "us r", "-user", strings.Repeat("u", 65)} {
			r := validStatus()
			r.Keys[0].Role = bad
			if _, err := r.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("Marshal with role %q = %v, want ErrMalformed", bad, err)
			}
			r = validStatus()
			r.Keys[0].Custody = bad
			if _, err := r.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("Marshal with custody %q = %v, want ErrMalformed", bad, err)
			}
		}
		for _, patch := range []string{"USER", "us r", "-use"} {
			// The first "user" in the body is the first key's role.
			raw := bytes.Replace(body, []byte("user"), []byte(patch), 1)
			if _, err := ParseStatusResponse(raw); !errors.Is(err, ErrMalformed) {
				t.Errorf("ParseStatusResponse with role %q = %v, want ErrMalformed", patch, err)
			}
		}
	})
	t.Run("authorized_byte_above_one_refused", func(t *testing.T) {
		bad := append([]byte(nil), body...)
		bad[len(bad)-1] = 2
		if _, err := ParseStatusResponse(bad); !errors.Is(err, ErrMalformed) {
			t.Fatalf("authorized byte 2 = %v, want ErrMalformed", err)
		}
	})
	t.Run("no_directory_has_one_encoding", func(t *testing.T) {
		for name, mutate := range map[string]func(*StatusResponse){
			"hash_without_directory":       func(r *StatusResponse) { r.DirectoryVersion = 0 },
			"authorized_without_directory": func(r *StatusResponse) { r.DirectoryVersion, r.DirectorySHA256 = 0, [32]byte{} },
		} {
			t.Run(name, func(t *testing.T) {
				r := validStatus()
				mutate(r)
				if _, err := r.Marshal(); !errors.Is(err, ErrMalformed) {
					t.Fatalf("Marshal = %v, want ErrMalformed", err)
				}
			})
		}
	})
	t.Run("empty_key_field_refused", func(t *testing.T) {
		r := validStatus()
		r.Keys[2].Custody = ""
		if _, err := r.Marshal(); !errors.Is(err, ErrMalformed) {
			t.Fatalf("Marshal with an empty custody = %v, want ErrMalformed", err)
		}
	})
}

// TestStatusFrameCaps: the StatusResponse frame-length cap MaxStatusFrame
// counts the 2 header bytes (02-03's unit rule), so the largest body is
// MaxStatusFrame - 2, in WriteMessage, ReadMessage and Marshal alike; the
// signer itself reads a Status response type only at MaxFrame.
func TestStatusFrameCaps(t *testing.T) {
	t.Run("status_frame_at_budget_round_trips", func(t *testing.T) {
		var buf bytes.Buffer
		body := bytes.Repeat([]byte{9}, MaxStatusFrame-headerLen)
		if err := WriteMessage(&buf, TypeStatusResponse, body); err != nil {
			t.Fatalf("WriteMessage of a %d-byte body: %v", len(body), err)
		}
		if buf.Len() != 4+MaxStatusFrame {
			t.Fatalf("wrote %d bytes, want %d", buf.Len(), 4+MaxStatusFrame)
		}
		typ, got, err := ReadMessage(&buf, ResponseCaps(TypeStatusResponse))
		if err != nil || typ != TypeStatusResponse || !bytes.Equal(got, body) {
			t.Fatalf("round trip: %#x, %d bytes, %v", typ, len(got), err)
		}
	})
	t.Run("status_frame_over_budget_refused", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteMessage(&buf, TypeStatusResponse, make([]byte, MaxStatusFrame-headerLen+1)); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("WriteMessage of a %d-byte body = %v, want ErrFrameTooLarge", MaxStatusFrame-headerLen+1, err)
		}
		if buf.Len() != 0 {
			t.Fatalf("WriteMessage wrote %d bytes of a refused frame, want 0", buf.Len())
		}
		r := &countingReader{hdr: append(frameHeader(MaxStatusFrame+1), Version, TypeStatusResponse)}
		if _, _, err := ReadMessage(r, ResponseCaps(TypeStatusResponse)); !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("ReadMessage of a %d-byte frame = %v, want ErrFrameTooLarge", MaxStatusFrame+1, err)
		}
		if r.read != 6 {
			t.Fatalf("ReadMessage consumed %d bytes, want only the 6 bytes of length and header", r.read)
		}
	})
	t.Run("marshal_over_budget_refused", func(t *testing.T) {
		if body, err := statusOfBodySize(t, MaxStatusFrame-headerLen).Marshal(); err != nil || len(body) != MaxStatusFrame-headerLen {
			t.Fatalf("Marshal of a %d-byte body: %d bytes, %v", MaxStatusFrame-headerLen, len(body), err)
		}
		if _, err := statusOfBodySize(t, MaxStatusFrame-headerLen+1).Marshal(); !errors.Is(err, ErrStatusTooLarge) {
			t.Fatalf("Marshal of a %d-byte body = %v, want ErrStatusTooLarge", MaxStatusFrame-headerLen+1, err)
		}
	})
	t.Run("caps_of_status_types", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			caps    Caps
			msgType byte
			want    int
		}{
			{"signer_reads_status_request_at_max_frame", RequestCaps, TypeStatus, MaxFrame},
			{"signer_reads_status_response_type_at_max_frame", RequestCaps, TypeStatusResponse, MaxFrame},
			{"client_reads_status_response_at_status_frame", ResponseCaps(TypeStatusResponse), TypeStatusResponse, MaxStatusFrame},
			{"client_reads_errors_at_max_frame", ResponseCaps(TypeStatusResponse), TypeError, MaxFrame},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got, ok := tc.caps(tc.msgType); !ok || got != tc.want {
					t.Fatalf("caps(%#x) = %d, %v; want %d", tc.msgType, got, ok, tc.want)
				}
			})
		}
		if _, ok := ResponseCaps(TypeStatusResponse)(TypeGetDirectoryResponse); ok {
			t.Fatal("a Status client accepts a GetDirectory response")
		}
		// The signer refuses a Status response frame above MaxFrame after
		// its header, before allocating the body.
		r := &countingReader{hdr: append(frameHeader(MaxFrame+1), Version, TypeStatusResponse)}
		if _, _, err := ReadMessage(r, RequestCaps); !errors.Is(err, ErrFrameTooLarge) || r.read != 6 {
			t.Fatalf("RequestCaps on a %d-byte Status response frame: %v after %d bytes, want ErrFrameTooLarge after 6", MaxFrame+1, err, r.read)
		}
	})
}

// FuzzParseStatusResponse: ParseStatusResponse never panics, and every
// body it accepts re-encodes to exactly the same bytes.
func FuzzParseStatusResponse(f *testing.F) {
	body, err := validStatus().Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(body)
	none := validStatus()
	none.DirectoryVersion, none.DirectorySHA256, none.DirectoryAuthorized = 0, [32]byte{}, false
	if b, err := none.Marshal(); err == nil {
		f.Add(b)
	}
	f.Add(append(append([]byte(nil), body...), 0))
	f.Add([]byte{MaxStatusKeys + 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		r, err := ParseStatusResponse(in)
		if err != nil {
			return
		}
		out, err := r.Marshal()
		if err != nil {
			t.Fatalf("Marshal of a parsed response: %v", err)
		}
		if !bytes.Equal(out, in) {
			t.Fatalf("Marshal does not reproduce the input:\n in  %x\n out %x", in, out)
		}
	})
}
