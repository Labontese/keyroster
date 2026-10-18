package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/wire"
)

// lockedBuffer is a stderr the fake signer can read while the CLI writes
// to it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeSigner answers Status with a fixed reply and refuses every
// IssueRequest. It records the type of every request frame and the CLI's
// stderr at the moment an IssueRequest arrived.
type fakeSigner struct {
	mu            sync.Mutex
	types         []byte
	stderrAtIssue string
}

func (f *fakeSigner) seen() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.types...)
}

// startFakeSigner listens on a Unix socket in a short temporary directory
// (t.TempDir can exceed macOS's 104-byte socket path limit) and serves
// one request per connection.
func startFakeSigner(t *testing.T, statusType byte, statusBody []byte, stderr *lockedBuffer) (string, *fakeSigner) {
	t.Helper()
	dir, err := os.MkdirTemp("", "kr")
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
	refusal, err := (&wire.ErrorResponse{Code: wire.CodeRefused, Message: "fake_signer_refuses_issue"}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSigner{}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				msgType, _, err := wire.ReadMessage(conn, wire.RequestCaps)
				if err != nil {
					return
				}
				f.mu.Lock()
				f.types = append(f.types, msgType)
				if msgType == wire.TypeIssueRequest {
					f.stderrAtIssue = stderr.String()
				}
				f.mu.Unlock()
				switch msgType {
				case wire.TypeStatus:
					_ = wire.WriteMessage(conn, statusType, statusBody)
				default:
					_ = wire.WriteMessage(conn, wire.TypeError, refusal)
				}
			}()
		}
	}()
	return socket, f
}

// TestCAIssueStatusGate proves that ca issue asks the signer for its
// Status before it sends an IssueRequest (D-18, KEY-06): a Status error
// aborts it before any IssueRequest is sent, and custody software prints
// the framed evaluation-only banner before the IssueRequest is sent. The
// fake signer's refusals are synthetic; a real signer's trust_changed is
// not fed through here.
func TestCAIssueStatusGate(t *testing.T) {
	_, subject, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjectPub, err := ssh.NewPublicKey(subject.Public())
	if err != nil {
		t.Fatal(err)
	}
	_, admin, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	adminSigner, err := ssh.NewSignerFromKey(admin)
	if err != nil {
		t.Fatal(err)
	}
	useKeyring(t, admin)
	keyFile := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(keyFile, ssh.MarshalAuthorizedKey(subjectPub), 0o600); err != nil {
		t.Fatal(err)
	}
	certFile := strings.TrimSuffix(keyFile, ".pub") + "-cert.pub"

	statusWith := func(t *testing.T, custody string) []byte {
		t.Helper()
		st := &wire.StatusResponse{BundleVersion: 1}
		for _, role := range []string{"user", "host", "machine", "ops", "log"} {
			st.Keys = append(st.Keys, wire.KeyStatus{Role: role, Alg: ssh.KeyAlgoED25519, Custody: custody, Fingerprint: "SHA256:fake-" + role})
		}
		body, err := st.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	statusError := func(t *testing.T, code wire.ErrorCode, msg string) []byte {
		t.Helper()
		body, err := (&wire.ErrorResponse{Code: code, Message: msg}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	run := func(t *testing.T, socket string, stderr *lockedBuffer) int {
		t.Helper()
		var stdout bytes.Buffer
		return dispatch(context.Background(), []string{
			"ca", "issue",
			"--socket", socket,
			"--pubkey", keyFile,
			"--subject", "u:alice",
			"--principal", "alice",
			"--admin-key", ssh.FingerprintSHA256(adminSigner.PublicKey()),
		}, &stdout, stderr)
	}
	banner := bannerFrame + "\n" + custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"}) + "\n" + bannerFrame + "\n"

	for _, tc := range []struct {
		name string
		code wire.ErrorCode
		msg  string
	}{
		{"status_trust_changed", wire.CodeUnavailable, "trust_changed"},
		{"status_internal_error", wire.CodeInternal, "internal_error"},
	} {
		t.Run(tc.name+"_aborts_before_issue", func(t *testing.T) {
			stderr := &lockedBuffer{}
			socket, f := startFakeSigner(t, wire.TypeError, statusError(t, tc.code, tc.msg), stderr)
			if code := run(t, socket, stderr); code != 1 {
				t.Fatalf("exit status %d, want 1 (stderr %q)", code, stderr.String())
			}
			if s := stderr.String(); !strings.Contains(s, "signer status") || !strings.Contains(s, tc.msg) {
				t.Fatalf("stderr = %q, want the signer status error with %q", s, tc.msg)
			}
			if got := f.seen(); !bytes.Equal(got, []byte{wire.TypeStatus}) {
				t.Fatalf("the signer received request types %x, want only Status (%x): ca issue sent an IssueRequest without knowing custody", got, wire.TypeStatus)
			}
			if _, err := os.Stat(certFile); !os.IsNotExist(err) {
				t.Fatalf("a certificate file was written (stat error %v)", err)
			}
		})
	}

	t.Run("software_custody_banner_before_issue", func(t *testing.T) {
		stderr := &lockedBuffer{}
		socket, f := startFakeSigner(t, wire.TypeStatusResponse, statusWith(t, "software"), stderr)
		if code := run(t, socket, stderr); code != 1 {
			t.Fatalf("exit status %d, want 1 from the fake refusal (stderr %q)", code, stderr.String())
		}
		if got := f.seen(); !bytes.Equal(got, []byte{wire.TypeStatus, wire.TypeIssueRequest}) {
			t.Fatalf("the signer received request types %x, want Status then IssueRequest", got)
		}
		f.mu.Lock()
		atIssue := f.stderrAtIssue
		f.mu.Unlock()
		if !strings.Contains(atIssue, banner) {
			t.Fatalf("stderr when the IssueRequest arrived = %q, want the framed banner %q", atIssue, banner)
		}
		if !strings.Contains(stderr.String(), "fake_signer_refuses_issue") {
			t.Fatalf("stderr = %q, want the fake signer's refusal", stderr.String())
		}
	})

	t.Run("agent_custody_no_banner", func(t *testing.T) {
		stderr := &lockedBuffer{}
		socket, f := startFakeSigner(t, wire.TypeStatusResponse, statusWith(t, "agent"), stderr)
		if code := run(t, socket, stderr); code != 1 {
			t.Fatalf("exit status %d, want 1 from the fake refusal (stderr %q)", code, stderr.String())
		}
		if got := f.seen(); !bytes.Equal(got, []byte{wire.TypeStatus, wire.TypeIssueRequest}) {
			t.Fatalf("the signer received request types %x, want Status then IssueRequest", got)
		}
		if s := stderr.String(); strings.Contains(s, "EVALUATION ONLY") || strings.Contains(s, bannerFrame) {
			t.Fatalf("stderr = %q: a banner for custody agent", s)
		}
	})
}
