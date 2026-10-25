package signerclient

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

// slowSigner listens on a Unix socket in a short temporary directory
// (t.TempDir can exceed macOS's 104-byte socket path limit). For each
// connection it reads one request frame, records when it had it, waits
// answerAfter and answers with an IssueResponse carrying cert; reply
// false reads and never answers. Every byte it receives is counted.
type slowSigner struct {
	socket string

	mu    sync.Mutex
	got   []time.Time // when each request frame was read whole
	bytes int64
}

func startSlowSigner(t *testing.T, answerAfter time.Duration, reply bool, cert []byte) *slowSigner {
	t.Helper()
	dir, err := os.MkdirTemp("", "krsc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	s := &slowSigner{socket: filepath.Join(dir, "s.sock")}
	l, err := net.Listen("unix", s.socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	resp, err := (&wire.IssueResponse{Cert: cert, Serial: 7, LeafIndex: 9}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				cr := &countReader{r: conn, s: s}
				if _, _, err := wire.ReadMessage(cr, wire.RequestCaps); err != nil {
					_, _ = io.Copy(io.Discard, cr)
					return
				}
				s.mu.Lock()
				s.got = append(s.got, time.Now())
				s.mu.Unlock()
				if !reply {
					_, _ = io.Copy(io.Discard, cr)
					return
				}
				time.Sleep(answerAfter)
				_ = wire.WriteMessage(conn, wire.TypeIssueResponse, resp)
			}()
		}
	}()
	return s
}

// countReader counts the bytes read from r into s.bytes.
type countReader struct {
	r io.Reader
	s *slowSigner
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.s.mu.Lock()
	c.s.bytes += int64(n)
	c.s.mu.Unlock()
	return n, err
}

// TestLoginSendReadDeadline (03-02 pre-merge review): LoginSend bounds the
// dial and the write of a login request by ctx's deadline, and the read of
// the answer by readTimeout alone. A request the signer takes before the
// deadline and answers after it still brings its certificate back; a
// request whose deadline has passed is never sent; and the read ends at
// readTimeout, not at ctx's later deadline.
func TestLoginSendReadDeadline(t *testing.T) {
	req := &wire.LoginIssueRequest{SubjectKey: []byte{1}, Subject: "alice"}
	t.Run("answer_after_send_deadline_received", func(t *testing.T) {
		s := startSlowSigner(t, 600*time.Millisecond, true, []byte("cert"))
		deadline := time.Now().Add(300 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		resp, err := LoginSend(ctx, s.socket, req, 5*time.Second)
		answered := time.Now()
		if err != nil {
			t.Fatalf("LoginSend: %v; want the certificate the signer answered with after the send deadline", err)
		}
		if string(resp.Cert) != "cert" || resp.Serial != 7 || resp.LeafIndex != 9 {
			t.Fatalf("LoginSend = %+v, want the signer's answer", resp)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if len(s.got) != 1 || !s.got[0].Before(deadline) {
			t.Fatalf("the signer read %d requests (%v), want one, before the send deadline %v", len(s.got), s.got, deadline)
		}
		if !answered.After(deadline) {
			t.Fatalf("the answer came at %v, before the send deadline %v: the test did not wait past it", answered, deadline)
		}
	})
	t.Run("past_send_deadline_never_sent", func(t *testing.T) {
		s := startSlowSigner(t, 0, true, []byte("cert"))
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		if resp, err := LoginSend(ctx, s.socket, req, 5*time.Second); err == nil {
			t.Fatalf("LoginSend = %+v past the send deadline, want an error", resp)
		}
		time.Sleep(200 * time.Millisecond) // let a connection that was made be read
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.bytes != 0 || len(s.got) != 0 {
			t.Fatalf("the signer received %d bytes (%d requests) of a request sent after its deadline, want none", s.bytes, len(s.got))
		}
	})
	t.Run("read_bounded_by_read_timeout", func(t *testing.T) {
		s := startSlowSigner(t, 0, false, []byte("cert"))
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		start := time.Now()
		if resp, err := LoginSend(ctx, s.socket, req, 200*time.Millisecond); err == nil {
			t.Fatalf("LoginSend = %+v from a signer that never answers, want an error", resp)
		}
		if took := time.Since(start); took > 2*time.Second {
			t.Fatalf("LoginSend took %v, want about the 200 ms read timeout, not ctx's 4 s deadline", took)
		}
	})
}
