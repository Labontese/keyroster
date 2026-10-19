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

	"golang.org/x/crypto/cryptobyte"
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

// fakeSigner answers Status with a fixed reply and answers every
// IssueRequest with a fixed IssueResponse body, or refuses it when that
// body is nil. It records the type of every request frame and the CLI's
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
func startFakeSigner(t *testing.T, statusType byte, statusBody, issueBody []byte, stderr *lockedBuffer) (string, *fakeSigner) {
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
				case wire.TypeIssueRequest:
					if issueBody != nil {
						_ = wire.WriteMessage(conn, wire.TypeIssueResponse, issueBody)
						return
					}
					_ = wire.WriteMessage(conn, wire.TypeError, refusal)
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
			socket, f := startFakeSigner(t, wire.TypeError, statusError(t, tc.code, tc.msg), nil, stderr)
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
		socket, f := startFakeSigner(t, wire.TypeStatusResponse, statusWith(t, "software"), nil, stderr)
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
		socket, f := startFakeSigner(t, wire.TypeStatusResponse, statusWith(t, "agent"), nil, stderr)
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

	// Signer-supplied text the CLI prints (D: a role name in the custody
	// banner, the key ID) must be a token or a keyroster key ID: a signer
	// report with control characters or padding is refused, and nothing
	// is issued or written.
	const padded = "                                                                " +
		"keyroster init --force --root-pin SHA256:EVIL"
	t.Run("status_role_with_control_characters_refused", func(t *testing.T) {
		for _, role := range []string{"user\x1b[2K", padded} {
			stderr := &lockedBuffer{}
			body := rawStatus([]wire.KeyStatus{{Role: role, Alg: ssh.KeyAlgoED25519, Custody: "software", Fingerprint: "SHA256:fake"}})
			socket, f := startFakeSigner(t, wire.TypeStatusResponse, body, nil, stderr)
			if code := run(t, socket, stderr); code != 1 {
				t.Fatalf("role %q: exit status %d, want 1 (stderr %q)", role, code, stderr.String())
			}
			if got := f.seen(); !bytes.Equal(got, []byte{wire.TypeStatus}) {
				t.Fatalf("role %q: the signer received request types %x, want only Status: a malformed custody report must stop the issue", role, got)
			}
			if s := stderr.String(); strings.Contains(s, "EVIL") || strings.Contains(s, "[2K") {
				t.Fatalf("role %q: stderr repeats the signer's role: %q", role, s)
			}
		}
	})
	t.Run("key_id_not_keyroster_refused", func(t *testing.T) {
		_, caKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		caSigner, err := ssh.NewSignerFromKey(caKey)
		if err != nil {
			t.Fatal(err)
		}
		for _, keyID := range []string{"kr1/ca=user\x1b[2K\r" + padded, padded} {
			c := &ssh.Certificate{Key: subjectPub, Serial: 42, CertType: ssh.UserCert, KeyId: keyID,
				ValidPrincipals: []string{"alice"}, ValidBefore: ssh.CertTimeInfinity}
			// A hostile signer's certificate: cert.Build refuses such a key ID.
			if err := c.SignCert(rand.Reader, caSigner); err != nil { //nolint:forbidigo // a test double of a signer that breaks CA-04
				t.Fatal(err)
			}
			issued, err := (&wire.IssueResponse{Cert: c.Marshal(), Serial: 42, LeafIndex: 1}).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			stderr := &lockedBuffer{}
			socket, f := startFakeSigner(t, wire.TypeStatusResponse, statusWith(t, "agent"), issued, stderr)
			if code := run(t, socket, stderr); code != 1 {
				t.Fatalf("key ID %q: exit status %d, want 1 (stderr %q)", keyID, code, stderr.String())
			}
			if got := f.seen(); !bytes.Equal(got, []byte{wire.TypeStatus, wire.TypeIssueRequest}) {
				t.Fatalf("the signer received request types %x, want Status then IssueRequest", got)
			}
			if s := stderr.String(); strings.Contains(s, "EVIL") || strings.Contains(s, "[2K") || !strings.Contains(s, "not a keyroster key ID") {
				t.Fatalf("key ID %q: stderr = %q, want the refusal without the key ID", keyID, s)
			}
			if _, err := os.Stat(certFile); !os.IsNotExist(err) {
				t.Fatalf("a certificate with a forged key ID was written (stat error %v)", err)
			}
		}
	})
}

// rawStatus encodes a StatusResponse body with keys as given, without the
// checks of StatusResponse.Marshal: what a signer that does not follow
// them could send.
func rawStatus(keys []wire.KeyStatus) []byte {
	var b cryptobyte.Builder
	b.AddUint8(uint8(len(keys))) //nolint:gosec // G115: a handful of test keys
	for _, k := range keys {
		for _, f := range []string{k.Role, k.Alg, k.Custody, k.Fingerprint} {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(f)) })
		}
	}
	b.AddUint64(1)
	for range 4 {
		b.AddUint24LengthPrefixed(func(*cryptobyte.Builder) {})
	}
	b.AddUint64(0)
	b.AddBytes(make([]byte, 32))
	b.AddUint8(0)
	return b.BytesOrPanic()
}
