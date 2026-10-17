package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"golang.org/x/crypto/cryptobyte"
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
	f.Add(seed(func(r *IssueRequest) { r.Extensions = []string{"permit-port-forwarding"} }))
	f.Add(seed(func(r *IssueRequest) { r.Extensions = make([]string, MaxExtensions+1) }))
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

// FuzzReadMessage (T-02-12, T-02-81): ReadMessage never panics, every
// error is a framing sentinel or a short read, and an accepted frame is
// within its type's cap and is exactly what WriteMessage writes for it.
func FuzzReadMessage(f *testing.F) {
	valid := frameOf(f, TypeIssueRequest, len(marshalUnchecked(validRequest())))
	f.Add(valid)
	f.Add(append(append(frameHeader(1), 0x5a), valid...)) // a length-1 frame, then a valid one
	f.Add(append(frameHeader(2), Version, TypeIssueRequest))
	f.Add(frameOf(f, TypeIssueRequest, MaxFrame-headerLen))
	f.Add(frameOf(f, TypeInstallDirectory, MaxDirectoryFrame-headerLen))
	f.Add(append(frameHeader(MaxFrame+1), Version, TypeIssueRequest))
	f.Add(append(frameHeader(MaxDirectoryFrame+1), Version, TypeGetDirectoryResponse))
	f.Add(frameHeader(0))
	f.Add(frameHeader(1 << 30))
	f.Add(append(frameHeader(3), Version+1, TypeError, 0))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, in []byte) {
		typ, body, err := ReadMessage(bytes.NewReader(in))
		if err != nil {
			for _, want := range []error{ErrEmptyFrame, ErrShortFrame, ErrVersion, ErrFrameTooLarge, io.EOF, io.ErrUnexpectedEOF} {
				if errors.Is(err, want) {
					return
				}
			}
			t.Fatalf("ReadMessage error = %v, want a framing sentinel or a short read", err)
		}
		if len(body) > maxBodyFor(typ) {
			t.Fatalf("ReadMessage returned a %d-byte body for type %#x, above its cap", len(body), typ)
		}
		var out bytes.Buffer
		if err := WriteMessage(&out, typ, body); err != nil {
			t.Fatalf("WriteMessage of a read frame: %v", err)
		}
		if !bytes.Equal(out.Bytes(), in[:out.Len()]) {
			t.Fatal("WriteMessage does not reproduce the frame that was read")
		}
	})
}

// FuzzParseLoginIssueRequest: a body that parses re-encodes to exactly
// itself, and every refusal is ErrMalformed.
func FuzzParseLoginIssueRequest(f *testing.F) {
	seed := func(edit func(*LoginIssueRequest)) []byte {
		r := loginVector(f)
		blob, err := (&WebAuthnAssertion{CredentialID: []byte{1, 2, 3}, AuthenticatorData: bytes.Repeat([]byte{7}, 37),
			ClientDataJSON: []byte(`{"type":"webauthn.get"}`), Signature: []byte("sig")}).Marshal()
		if err != nil {
			f.Fatal(err)
		}
		r.Evidence = []Evidence{{Type: EvidenceWebAuthnAssertion, Blob: blob}}
		edit(r)
		var b cryptobyte.Builder
		r.addFields(&b)
		addEvidence(&b, r.Evidence)
		return b.BytesOrPanic()
	}
	valid := seed(func(*LoginIssueRequest) {})
	f.Add(valid)
	f.Add(seed(func(r *LoginIssueRequest) { r.Evidence = nil }))
	f.Add(seed(func(r *LoginIssueRequest) { r.Roles = []string{"ops", "dev"} }))
	f.Add(seed(func(r *LoginIssueRequest) { r.Extensions = []string{"permit-pty"} }))
	f.Add(seed(func(r *LoginIssueRequest) { r.Roles = make([]string, MaxLoginRoles+1) }))
	f.Add(seed(func(r *LoginIssueRequest) { r.Roles = []string{""} }))
	f.Add(seed(func(r *LoginIssueRequest) { r.SubjectKey = nil }))
	f.Add(append(append([]byte(nil), valid...), 0))
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseLoginIssueRequest(body)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseLoginIssueRequest error = %v, want ErrMalformed", err)
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
		if r.SigningBytes() == nil {
			t.Fatal("a parsed request has no signing bytes")
		}
	})
}

// FuzzParseWebAuthnAssertion: an evidence blob that parses re-encodes to
// exactly itself, and every refusal is ErrMalformed.
func FuzzParseWebAuthnAssertion(f *testing.F) {
	valid, err := (&WebAuthnAssertion{CredentialID: bytes.Repeat([]byte{1}, 32), AuthenticatorData: bytes.Repeat([]byte{7}, 37),
		ClientDataJSON: []byte(`{"type":"webauthn.get","challenge":"x","origin":"https://keyroster.localhost","crossOrigin":false}`),
		Signature:      bytes.Repeat([]byte{9}, 64)}).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(append(append([]byte(nil), valid...), 0))
	f.Add(valid[:len(valid)-1])
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, blob []byte) {
		a, err := ParseWebAuthnAssertion(blob)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseWebAuthnAssertion error = %v, want ErrMalformed", err)
			}
			return
		}
		out, err := a.Marshal()
		if err != nil || !bytes.Equal(out, blob) {
			t.Fatalf("Marshal does not reproduce the input (%v)", err)
		}
	})
}

// FuzzParseInstallDirectory: an InstallDirectory body that parses
// re-encodes to exactly itself, and every refusal is ErrMalformed.
func FuzzParseInstallDirectory(f *testing.F) {
	valid, err := (&InstallDirectoryRequest{Directory: []byte(`{"version":1}`), Sigs: []byte("-----BEGIN SSH SIGNATURE-----")}).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(append(append([]byte(nil), valid...), 0))
	f.Add(valid[:len(valid)-1])
	f.Add([]byte{0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x10, 0, 1, 'x', 0, 0, 1, 'y'}) // directory length above MaxDirectory
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseInstallDirectoryRequest(body)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseInstallDirectoryRequest error = %v, want ErrMalformed", err)
			}
			return
		}
		out, err := r.Marshal()
		if err != nil || !bytes.Equal(out, body) {
			t.Fatalf("Marshal does not reproduce the input (%v)", err)
		}
	})
}

// FuzzParseGetDirectoryResponse: a response that parses re-encodes to
// exactly itself and keeps the version-0 rule; every refusal is
// ErrMalformed.
func FuzzParseGetDirectoryResponse(f *testing.F) {
	for _, r := range []*GetDirectoryResponse{
		{},
		{Version: 1, Directory: []byte(`{"version":1}`), Sigs: []byte("sig"), Authorized: true},
		{Version: 2, Directory: []byte(`{"version":2}`), Sigs: []byte("sig"), Authorized: false},
	} {
		body, err := r.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(body)
		f.Add(append(append([]byte(nil), body...), 0))
		f.Add(body[:len(body)-1])
	}
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) // version 0 authorized
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseGetDirectoryResponse(body)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseGetDirectoryResponse error = %v, want ErrMalformed", err)
			}
			return
		}
		if r.Version == 0 && (len(r.Directory) != 0 || len(r.Sigs) != 0 || r.Authorized) {
			t.Fatalf("accepted a version 0 response carrying a directory: %+v", r)
		}
		out, err := r.Marshal()
		if err != nil || !bytes.Equal(out, body) {
			t.Fatalf("Marshal does not reproduce the input (%v)", err)
		}
	})
}
