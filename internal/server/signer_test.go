package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/wire"
)

// TestSocketSignerLoginReadsPastSendDeadline (03-02 pre-merge review): the
// redeem's signer limit bounds sending the login request, not reading the
// answer. A signer on a real socket that reads the request before the
// context's deadline and answers after it still gets its certificate to
// the caller.
func TestSocketSignerLoginReadsPastSendDeadline(t *testing.T) {
	dir, err := os.MkdirTemp("", "krsv") // t.TempDir can exceed macOS's socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	resp, err := (&wire.IssueResponse{Cert: []byte("cert"), Serial: 7, LeafIndex: 9}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	read := make(chan time.Time, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, err := wire.ReadMessage(conn, wire.RequestCaps); err != nil {
			return
		}
		read <- time.Now()
		time.Sleep(500 * time.Millisecond)
		_ = wire.WriteMessage(conn, wire.TypeIssueResponse, resp)
	}()
	deadline := time.Now().Add(200 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	got, err := socketSigner{socket: socket}.Login(ctx, &wire.LoginIssueRequest{SubjectKey: []byte{1}, Subject: "alice"})
	if err != nil {
		t.Fatalf("Login: %v; want the certificate the signer answered with after the deadline", err)
	}
	if string(got.Cert) != "cert" {
		t.Fatalf("Login = %+v, want the signer's answer", got)
	}
	if at := <-read; !at.Before(deadline) || !time.Now().After(deadline) {
		t.Fatalf("the signer read the request at %v and the answer came by %v; want the read before the deadline %v and the answer after it", at, time.Now(), deadline)
	}
}
