//go:build linux

package signer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/keystore"
	_ "github.com/Labontese/keyroster/internal/keystore/agent" // registers the "agent" backend
	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/wire"
)

// capturedRecord is one slog record as the signer emitted it.
type capturedRecord struct {
	Level slog.Level
	Msg   string
	Attrs map[string]string
}

// text renders the record for substring checks.
func (r capturedRecord) text() string {
	var b strings.Builder
	b.WriteString(r.Msg)
	for k, v := range r.Attrs {
		b.WriteString(" " + k + "=" + v)
	}
	return b.String()
}

// recordSink collects slog records in memory.
type recordSink struct {
	mu   sync.Mutex
	recs []capturedRecord
}

func (s *recordSink) all() []capturedRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]capturedRecord(nil), s.recs...)
}

// captureHandler is a slog.Handler that writes into a recordSink.
type captureHandler struct {
	sink  *recordSink
	attrs []slog.Attr
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	m := make(map[string]string, len(h.attrs)+r.NumAttrs())
	for _, a := range h.attrs {
		m[a.Key] = a.Value.String()
	}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.String()
		return true
	})
	h.sink.mu.Lock()
	h.sink.recs = append(h.sink.recs, capturedRecord{Level: r.Level, Msg: r.Message, Attrs: m})
	h.sink.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &captureHandler{sink: h.sink, attrs: append(append([]slog.Attr(nil), h.attrs...), as...)}
}

func (h *captureHandler) WithGroup(string) slog.Handler { return h }

// signerOpts adjusts newTestSigner.
type signerOpts struct {
	// allowSet replaces the default allowlist (the test process uid) with
	// allowUIDs and allowGIDs.
	allowSet  bool
	allowUIDs []uint32
	allowGIDs []uint32
}

// testSigner is a running signer on a real Unix socket, backed by an
// in-memory ssh-agent keyring holding an Ed25519 CA key and a state DB in a
// temporary directory.
type testSigner struct {
	t         *testing.T
	opts      signerOpts
	dir       string
	dbPath    string
	agentSock string
	caFP      string
	CAPub     ssh.PublicKey
	Socket    string
	DB        *signerdb.DB
	logs      *recordSink

	backend keystore.Backend
	cancel  context.CancelFunc
	done    chan error
}

// shortTempDir returns a short temporary directory (Unix socket paths are
// limited to 108 bytes, and t.TempDir embeds the test name).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "krs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveAgent serves keyring on a Unix socket at path until the test ends.
func serveAgent(t *testing.T, path string, keyring sshagent.Agent) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = sshagent.ServeAgent(keyring, c)
				_ = c.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		wg.Wait()
	})
}

func newTestSigner(t *testing.T, opts signerOpts) *testSigner {
	t.Helper()
	dir := shortTempDir(t)
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	keyring := sshagent.NewKeyring()
	if err := keyring.Add(sshagent.AddedKey{PrivateKey: caPriv}); err != nil {
		t.Fatal(err)
	}
	ts := &testSigner{
		t:         t,
		opts:      opts,
		dir:       dir,
		dbPath:    filepath.Join(dir, "signer.db"),
		agentSock: filepath.Join(dir, "agent.sock"),
		caFP:      ssh.FingerprintSHA256(caSigner.PublicKey()),
		CAPub:     caSigner.PublicKey(),
		Socket:    filepath.Join(dir, "signer.sock"),
		logs:      &recordSink{},
	}
	serveAgent(t, ts.agentSock, keyring)
	ts.start()
	t.Cleanup(ts.stop)
	return ts
}

// start opens the DB and the backend, builds the signer and serves it.
func (ts *testSigner) start() {
	t := ts.t
	t.Helper()
	db, err := signerdb.Open(ts.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := keystore.Open("agent", map[string]string{"socket": ts.agentSock})
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	allowUIDs := []uint32{uint32(os.Getuid())} //nolint:gosec // G115: a uid fits uint32
	var allowGIDs []uint32
	if ts.opts.allowSet {
		allowUIDs, allowGIDs = ts.opts.allowUIDs, ts.opts.allowGIDs
	}
	s, err := signer.New(signer.Config{
		Backend:           backend,
		UserCAFingerprint: ts.caFP,
		DB:                db,
		Clock:             time.Now,
		AllowUIDs:         allowUIDs,
		AllowGIDs:         allowGIDs,
		Logger:            slog.New(&captureHandler{sink: ts.logs}),
	})
	if err != nil {
		_ = backend.Close()
		_ = db.Close()
		t.Fatal(err)
	}
	l, err := signer.Listen(ts.Socket, -1)
	if err != nil {
		_ = backend.Close()
		_ = db.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	ts.DB, ts.backend, ts.cancel, ts.done = db, backend, cancel, done
}

// stop cancels Serve, waits for it, and closes the backend and the DB. It
// is idempotent.
func (ts *testSigner) stop() {
	if ts.cancel == nil {
		return
	}
	ts.cancel()
	if err := <-ts.done; err != nil {
		ts.t.Errorf("Serve returned %v", err)
	}
	if err := ts.backend.Close(); err != nil {
		ts.t.Errorf("backend close: %v", err)
	}
	if err := ts.DB.Close(); err != nil {
		ts.t.Errorf("db close: %v", err)
	}
	ts.cancel, ts.done, ts.backend, ts.DB = nil, nil, nil, nil
}

// issuanceCount counts the rows of the issuance table.
func (ts *testSigner) issuanceCount(t *testing.T) int {
	t.Helper()
	var n int
	err := ts.DB.WithTx(context.Background(), func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM issuance`).Scan(&n)
	})
	if err != nil {
		t.Fatalf("count issuance rows: %v", err)
	}
	return n
}

// lastSerial returns the serial high-water mark.
func (ts *testSigner) lastSerial(t *testing.T) uint64 {
	t.Helper()
	last, err := ts.DB.LastSerial(context.Background())
	if err != nil {
		t.Fatalf("LastSerial: %v", err)
	}
	return last
}

// reasonRecords returns the captured records that carry a reason code.
func (ts *testSigner) reasonRecords() []capturedRecord {
	var out []capturedRecord
	for _, r := range ts.logs.all() {
		if _, ok := r.Attrs["reason"]; ok {
			out = append(out, r)
		}
	}
	return out
}

// issue sends req through the real client and socket.
func (ts *testSigner) issue(req *wire.IssueRequest) (*wire.IssueResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return signerclient.Issue(ctx, ts.Socket, req)
}

// verifyCert parses resp's certificate and checks that it is a user
// certificate for principal with resp's serial and a valid signature by the
// fixture's CA key.
func (ts *testSigner) verifyCert(t *testing.T, resp *wire.IssueResponse, principal string) *ssh.Certificate {
	t.Helper()
	pk, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatalf("response holds a %T, not a certificate", pk)
	}
	if c.Serial == 0 || c.Serial != resp.Serial {
		t.Fatalf("certificate serial %d, response serial %d; want equal and above 0", c.Serial, resp.Serial)
	}
	if !bytes.Equal(c.SignatureKey.Marshal(), ts.CAPub.Marshal()) {
		t.Fatalf("certificate signed by %s, want the CA %s", ssh.FingerprintSHA256(c.SignatureKey), ts.caFP)
	}
	checker := ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return bytes.Equal(auth.Marshal(), ts.CAPub.Marshal()) },
	}
	if err := checker.CheckCert(principal, c); err != nil {
		t.Fatalf("certificate does not verify for %q: %v", principal, err)
	}
	return c
}

// newRequest builds a valid user-CA request with a fresh Ed25519 subject
// key and a random request id.
func newRequest(t *testing.T, principals ...string) *wire.IssueRequest {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	req := &wire.IssueRequest{
		CARole:          wire.CARoleUser,
		SubjectKey:      sshPub.Marshal(),
		Subject:         "u:alice",
		Principals:      principals,
		ValidForSeconds: 3600,
		CreatedAt:       uint64(time.Now().Unix()), //nolint:gosec // G115: the clock is after 1970
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	return req
}

// wantErrorResponse asserts that err is a signer ErrorResponse with code
// and reason message.
func wantErrorResponse(t *testing.T, err error, code wire.ErrorCode, reason string) {
	t.Helper()
	var er *wire.ErrorResponse
	if !errors.As(err, &er) {
		t.Fatalf("error = %v, want a *wire.ErrorResponse %s: %s", err, code, reason)
	}
	if er.Code != code || er.Message != reason {
		t.Fatalf("ErrorResponse = %s: %s, want %s: %s", er.Code, er.Message, code, reason)
	}
}

// TestRefusalEndToEnd is the tracer: an out-of-policy request crosses the
// real socket, the wire decoder, the signer and the cert builder, is
// refused without touching the state DB, leaves exactly one reason-coded
// log record without request bytes, and the signer serves the next request.
func TestRefusalEndToEnd(t *testing.T) {
	ts := newTestSigner(t, signerOpts{})
	lastBefore := ts.lastSerial(t)
	countBefore := ts.issuanceCount(t)

	bad := newRequest(t, "*")
	_, err := ts.issue(bad)
	wantErrorResponse(t, err, wire.CodeRefused, "bad_principal")

	if got := ts.lastSerial(t); got != lastBefore {
		t.Errorf("LastSerial after refusal = %d, want unchanged %d", got, lastBefore)
	}
	if got := ts.issuanceCount(t); got != countBefore {
		t.Errorf("issuance rows after refusal = %d, want unchanged %d", got, countBefore)
	}
	recs := ts.reasonRecords()
	if len(recs) != 1 {
		t.Fatalf("got %d reason-coded records, want exactly 1: %+v", len(recs), recs)
	}
	if got := recs[0].Attrs["reason"]; got != "bad_principal" {
		t.Errorf("record reason = %q, want bad_principal", got)
	}
	keyB64 := base64.StdEncoding.EncodeToString(bad.SubjectKey)
	for k, v := range recs[0].Attrs {
		if strings.Contains(v, keyB64) || strings.Contains(v, bad.Principals[0]) {
			t.Errorf("record attribute %s=%q carries request bytes", k, v)
		}
	}
	if strings.Contains(recs[0].text(), keyB64) {
		t.Errorf("record %q carries the subject key", recs[0].text())
	}

	resp, err := ts.issue(newRequest(t, "alice"))
	if err != nil {
		t.Fatalf("valid request after the refusal: %v", err)
	}
	ts.verifyCert(t, resp, "alice")
	if got := ts.issuanceCount(t); got != countBefore+1 {
		t.Errorf("issuance rows after the valid request = %d, want %d", got, countBefore+1)
	}
}
