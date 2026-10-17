package signerclient

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/Labontese/keyroster/internal/wire"
)

// countingReader yields hdr and then 0x41 bytes forever, counting every
// byte read.
type countingReader struct {
	hdr  []byte
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		if c.read < len(c.hdr) {
			p[i] = c.hdr[c.read]
		} else {
			p[i] = 0x41
		}
		c.read++
	}
	return len(p), nil
}

// frameHeader returns the 4-byte length and the version and type bytes of
// a frame of msgType with frame length n.
func frameHeader(n uint32, msgType byte) []byte {
	h := binary.BigEndian.AppendUint32(nil, n)
	return append(h, wire.Version, msgType)
}

// TestReadResponseRefusesUnexpectedType (T-02-12): a client waiting for
// one response type refuses a frame of any other type after its 6 header
// bytes, before reading or allocating its body. A hostile socket answering
// an Issue call with a GetDirectoryResponse frame of MaxDirectoryFrame
// costs the client 6 bytes, not 1.06 MiB. Controls: a frame of the wanted
// type and an error frame are read whole.
func TestReadResponseRefusesUnexpectedType(t *testing.T) {
	for _, tc := range []struct {
		name    string
		want    byte
		msgType byte
		length  uint32
	}{
		{"get_directory_response_on_issue", wire.TypeIssueResponse, wire.TypeGetDirectoryResponse, wire.MaxDirectoryFrame},
		{"install_directory_on_issue", wire.TypeIssueResponse, wire.TypeInstallDirectory, wire.MaxDirectoryFrame},
		{"issue_response_on_get_directory", wire.TypeGetDirectoryResponse, wire.TypeIssueResponse, wire.MaxFrame},
		{"unknown_type_on_issue", wire.TypeIssueResponse, 0x7e, wire.MaxFrame},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &countingReader{hdr: frameHeader(tc.length, tc.msgType)}
			body, err := readResponse(r, tc.want)
			if !errors.Is(err, wire.ErrUnexpectedType) || body != nil {
				t.Fatalf("readResponse = %d body bytes, %v; want wire.ErrUnexpectedType", len(body), err)
			}
			if r.read != 6 {
				t.Fatalf("readResponse read %d bytes of a refused %#x frame, want only the 6 bytes of length and header", r.read, tc.msgType)
			}
		})
	}
	t.Run("control_wanted_type_read_whole", func(t *testing.T) {
		r := &countingReader{hdr: frameHeader(wire.MaxDirectoryFrame, wire.TypeGetDirectoryResponse)}
		body, err := readResponse(r, wire.TypeGetDirectoryResponse)
		if err != nil || len(body) != wire.MaxDirectoryFrame-2 {
			t.Fatalf("readResponse = %d body bytes, %v; want the whole %d-byte body", len(body), err, wire.MaxDirectoryFrame-2)
		}
	})
	t.Run("control_error_frame_read_whole", func(t *testing.T) {
		e := &wire.ErrorResponse{Code: wire.CodeRefused, Message: "missing_evidence"}
		eb, err := e.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		r := &countingReader{hdr: append(frameHeader(uint32(2+len(eb)), wire.TypeError), eb...)} //nolint:gosec // G115: a short error body
		_, err = readResponse(r, wire.TypeIssueResponse)
		var got *wire.ErrorResponse
		if !errors.As(err, &got) || got.Message != "missing_evidence" {
			t.Fatalf("readResponse = %v, want the signer's refusal missing_evidence", err)
		}
		if r.read != 6+len(eb) {
			t.Fatalf("readResponse read %d bytes, want the whole %d-byte error frame", r.read, 6+len(eb))
		}
	})
}
