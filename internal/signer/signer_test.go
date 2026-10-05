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
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
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
	logFP     string
	LogPub    ssh.PublicKey
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
	_, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	logSigner, err := ssh.NewSignerFromKey(logPriv)
	if err != nil {
		t.Fatal(err)
	}
	keyring := sshagent.NewKeyring()
	for _, k := range []ed25519.PrivateKey{caPriv, logPriv} {
		if err := keyring.Add(sshagent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	ts := &testSigner{
		t:         t,
		opts:      opts,
		dir:       dir,
		dbPath:    filepath.Join(dir, "signer.db"),
		agentSock: filepath.Join(dir, "agent.sock"),
		caFP:      ssh.FingerprintSHA256(caSigner.PublicKey()),
		logFP:     ssh.FingerprintSHA256(logSigner.PublicKey()),
		LogPub:    logSigner.PublicKey(),
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
		LogKeyFingerprint: ts.logFP,
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

// wantOneRefusalRecord asserts that exactly one reason-coded record was
// added after the first `before` records, carrying reason.
func (ts *testSigner) wantOneRefusalRecord(t *testing.T, before int, reason string) capturedRecord {
	t.Helper()
	added := ts.reasonRecords()[before:]
	if len(added) != 1 {
		t.Fatalf("got %d new reason-coded records, want exactly 1: %+v", len(added), added)
	}
	if got := added[0].Attrs["reason"]; got != reason {
		t.Fatalf("record reason = %q, want %q", got, reason)
	}
	return added[0]
}

// waitRefusalRecords polls until at least n reason-coded records exist; the
// signer may log a refusal after the client has already seen the close.
func (ts *testSigner) waitRefusalRecords(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(ts.reasonRecords()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d reason-coded records, have %+v", n, ts.reasonRecords())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestSignerRefusals(t *testing.T) {
	ts := newTestSigner(t, signerOpts{})
	now := uint64(time.Now().Unix()) //nolint:gosec // G115: the clock is after 1970
	certSubject := func(t *testing.T) []byte {
		// A certificate issued by this signer, offered as a subject key.
		resp, err := ts.issue(newRequest(t, "seed"))
		if err != nil {
			t.Fatal(err)
		}
		return resp.Cert
	}
	tests := []struct {
		name   string
		edit   func(t *testing.T, r *wire.IssueRequest)
		code   wire.ErrorCode
		reason string
	}{
		{"host_role", func(_ *testing.T, r *wire.IssueRequest) { r.CARole = wire.CARoleHost }, wire.CodeRefused, "ca_not_configured"},
		{"machine_role", func(_ *testing.T, r *wire.IssueRequest) { r.CARole = wire.CARoleMachine }, wire.CodeRefused, "ca_not_configured"},
		{"created_301s_past", func(_ *testing.T, r *wire.IssueRequest) { r.CreatedAt = now - 301 }, wire.CodeRefused, "request_time_skew"},
		{"created_301s_future", func(_ *testing.T, r *wire.IssueRequest) { r.CreatedAt = now + 301 }, wire.CodeRefused, "request_time_skew"},
		{"created_at_zero", func(_ *testing.T, r *wire.IssueRequest) { r.CreatedAt = 0 }, wire.CodeRefused, "request_time_skew"},
		{"created_at_max", func(_ *testing.T, r *wire.IssueRequest) { r.CreatedAt = 1<<64 - 1 }, wire.CodeRefused, "request_time_skew"},
		{"empty_principals", func(_ *testing.T, r *wire.IssueRequest) { r.Principals = nil }, wire.CodeRefused, "empty_principals"},
		{"uppercase_principal", func(_ *testing.T, r *wire.IssueRequest) { r.Principals = []string{"Alice"} }, wire.CodeRefused, "bad_principal"},
		{"duplicate_principal", func(_ *testing.T, r *wire.IssueRequest) { r.Principals = []string{"alice", "alice"} }, wire.CodeRefused, "bad_principal"},
		{"ttl_zero", func(_ *testing.T, r *wire.IssueRequest) { r.ValidForSeconds = 0 }, wire.CodeRefused, "bad_validity"},
		{"ttl_above_max", func(_ *testing.T, r *wire.IssueRequest) { r.ValidForSeconds = 12*3600 + 1 }, wire.CodeRefused, "bad_validity"},
		{"subject_key_garbage", func(_ *testing.T, r *wire.IssueRequest) { r.SubjectKey = []byte("not a key") }, wire.CodeRefused, "bad_subject_key"},
		{"subject_is_ca_key", func(_ *testing.T, r *wire.IssueRequest) { r.SubjectKey = ts.CAPub.Marshal() }, wire.CodeRefused, "bad_subject_key"},
		{"certificate_subject", func(t *testing.T, r *wire.IssueRequest) { r.SubjectKey = certSubject(t) }, wire.CodeRefused, "bad_subject_key"},
		{"bad_key_id_subject", func(_ *testing.T, r *wire.IssueRequest) { r.Subject = "u:a/pol=9" }, wire.CodeRefused, "bad_subject"},
		{"empty_key_id_subject", func(_ *testing.T, r *wire.IssueRequest) { r.Subject = "" }, wire.CodeRefused, "bad_subject"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(t, "alice")
			tc.edit(t, req)
			lastBefore, countBefore, recsBefore := ts.lastSerial(t), ts.issuanceCount(t), len(ts.reasonRecords())
			_, err := ts.issue(req)
			wantErrorResponse(t, err, tc.code, tc.reason)
			if got := ts.lastSerial(t); got != lastBefore {
				t.Errorf("LastSerial = %d, want unchanged %d", got, lastBefore)
			}
			if got := ts.issuanceCount(t); got != countBefore {
				t.Errorf("issuance rows = %d, want unchanged %d", got, countBefore)
			}
			ts.wantOneRefusalRecord(t, recsBefore, tc.reason)
		})
	}
}

// TestSignerFraming sends raw frames the real client never produces.
func TestSignerFraming(t *testing.T) {
	ts := newTestSigner(t, signerOpts{})
	valid, err := newRequest(t, "alice").Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		msgType byte
		body    []byte
		code    wire.ErrorCode
		reason  string
	}{
		{"unknown_message_type", wire.TypeError, valid, wire.CodeMalformed, "unknown_message_type"},
		{"trailing_byte", wire.TypeIssueRequest, append(append([]byte(nil), valid...), 0), wire.CodeMalformed, "malformed_request"},
		{"unknown_ca_role", wire.TypeIssueRequest, append([]byte{9}, valid[1:]...), wire.CodeMalformed, "malformed_request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			recsBefore := len(ts.reasonRecords())
			conn, err := net.Dial("unix", ts.Socket)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := wire.WriteMessage(conn, tc.msgType, tc.body); err != nil {
				t.Fatal(err)
			}
			typ, body, err := wire.ReadMessage(conn)
			if err != nil || typ != wire.TypeError {
				t.Fatalf("response type %#x, error %v; want an error response", typ, err)
			}
			er, err := wire.ParseErrorResponse(body)
			if err != nil {
				t.Fatal(err)
			}
			wantErrorResponse(t, er, tc.code, tc.reason)
			ts.wantOneRefusalRecord(t, recsBefore, tc.reason)
		})
	}
	if got := ts.issuanceCount(t); got != 0 {
		t.Fatalf("issuance rows = %d, want 0", got)
	}
}

// TestSignerClockBehindHighWaterMark: a stored high-water mark ahead of the
// clock (for example a clock set back) stops issuance (CA-03).
func TestSignerClockBehindHighWaterMark(t *testing.T) {
	ts := newTestSigner(t, signerOpts{})
	future := uint64(time.Now().Add(time.Hour).UnixMicro()) //nolint:gosec // G115: the clock is after 1970
	if err := ts.DB.WithTx(context.Background(), func(tx *sql.Tx) error { return ts.DB.SetLastSerial(tx, future) }); err != nil {
		t.Fatal(err)
	}
	_, err := ts.issue(newRequest(t, "alice"))
	wantErrorResponse(t, err, wire.CodeUnavailable, "clock_regression")
	ts.wantOneRefusalRecord(t, 0, "clock_regression")
	if got := ts.lastSerial(t); got != future {
		t.Fatalf("LastSerial = %d, want unchanged %d", got, future)
	}
	if got := ts.issuanceCount(t); got != 0 {
		t.Fatalf("issuance rows = %d, want 0", got)
	}
}

func TestSignerConcurrency(t *testing.T) {
	t.Run("duplicate_request", func(t *testing.T) {
		ts := newTestSigner(t, signerOpts{})
		req := newRequest(t, "alice")
		if _, err := ts.issue(req); err != nil {
			t.Fatal(err)
		}
		_, err := ts.issue(req)
		wantErrorResponse(t, err, wire.CodeRefused, "duplicate_request")
		ts.wantOneRefusalRecord(t, 0, "duplicate_request")
		if got := ts.issuanceCount(t); got != 1 {
			t.Fatalf("issuance rows = %d, want 1", got)
		}
	})
	t.Run("duplicate_request_race", func(t *testing.T) {
		ts := newTestSigner(t, signerOpts{})
		req := newRequest(t, "alice")
		var (
			wg    sync.WaitGroup
			resps [2]*wire.IssueResponse
			errs  [2]error
		)
		start := make(chan struct{})
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				resps[i], errs[i] = ts.issue(req)
			}()
		}
		close(start)
		wg.Wait()
		succeeded := 0
		for i := range 2 {
			if errs[i] == nil {
				succeeded++
				ts.verifyCert(t, resps[i], "alice")
				continue
			}
			wantErrorResponse(t, errs[i], wire.CodeRefused, "duplicate_request")
		}
		if succeeded != 1 {
			t.Fatalf("%d requests succeeded, want exactly 1 (errors %v)", succeeded, errs)
		}
		if got := ts.issuanceCount(t); got != 1 {
			t.Fatalf("issuance rows = %d, want 1", got)
		}
		ts.wantOneRefusalRecord(t, 0, "duplicate_request")
	})
	t.Run("sixteen_clients", func(t *testing.T) {
		ts := newTestSigner(t, signerOpts{})
		const n = 16
		reqs := make([]*wire.IssueRequest, n)
		for i := range reqs {
			reqs[i] = newRequest(t, "alice")
		}
		var (
			wg    sync.WaitGroup
			resps [n]*wire.IssueResponse
			errs  [n]error
		)
		start := make(chan struct{})
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				resps[i], errs[i] = ts.issue(reqs[i])
			}()
		}
		close(start)
		wg.Wait()
		seen := map[uint64]bool{}
		for i := range n {
			if errs[i] != nil {
				t.Fatalf("client %d: %v", i, errs[i])
			}
			c := ts.verifyCert(t, resps[i], "alice")
			if !bytes.Equal(c.Key.Marshal(), reqs[i].SubjectKey) {
				t.Fatalf("client %d received a certificate for another client's key", i)
			}
			if seen[c.Serial] {
				t.Fatalf("serial %d issued twice", c.Serial)
			}
			seen[c.Serial] = true
		}
		if got := ts.issuanceCount(t); got != n {
			t.Fatalf("issuance rows = %d, want %d", got, n)
		}
		if recs := ts.reasonRecords(); len(recs) != 0 {
			t.Fatalf("unexpected refusals: %+v", recs)
		}
	})
	t.Run("half_frame_close", func(t *testing.T) {
		ts := newTestSigner(t, signerOpts{})
		var (
			wg             sync.WaitGroup
			concurrentResp *wire.IssueResponse
			concurrentErr  error
		)
		wg.Add(1)
		go func() {
			defer wg.Done()
			concurrentResp, concurrentErr = ts.issue(newRequest(t, "alice"))
		}()
		conn, err := net.Dial("unix", ts.Socket)
		if err != nil {
			t.Fatal(err)
		}
		// A header announcing 100 bytes, then only 10, then close.
		if _, err := conn.Write(append([]byte{0, 0, 0, 100}, bytes.Repeat([]byte{1}, 10)...)); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		wg.Wait()
		if concurrentErr != nil {
			t.Fatalf("concurrent valid request: %v", concurrentErr)
		}
		ts.verifyCert(t, concurrentResp, "alice")
		ts.waitRefusalRecords(t, 1)
		ts.wantOneRefusalRecord(t, 0, "malformed_frame")
		resp, err := ts.issue(newRequest(t, "alice"))
		if err != nil {
			t.Fatalf("request after the half frame: %v", err)
		}
		ts.verifyCert(t, resp, "alice")
		if got := ts.issuanceCount(t); got != 2 {
			t.Fatalf("issuance rows = %d, want 2", got)
		}
	})
}

func TestSignerPeerAllowlist(t *testing.T) {
	t.Run("peer_not_allowed", func(t *testing.T) {
		uid := uint32(os.Getuid()) //nolint:gosec // G115: a uid fits uint32
		ts := newTestSigner(t, signerOpts{allowSet: true, allowUIDs: []uint32{uid + 1}})
		conn, err := net.Dial("unix", ts.Socket)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		// Nothing is written: the signer must close the connection without
		// waiting for a frame, and must send nothing back.
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("read: %v (the signer should have closed the connection)", err)
		}
		if len(got) != 0 {
			t.Fatalf("signer wrote %d bytes to a peer that is not allowed", len(got))
		}
		ts.waitRefusalRecords(t, 1)
		rec := ts.wantOneRefusalRecord(t, 0, "peer_not_allowed")
		if want := strconv.FormatUint(uint64(uid), 10); rec.Attrs["uid"] != want {
			t.Fatalf("record uid = %q, want %q", rec.Attrs["uid"], want)
		}
		if got := ts.issuanceCount(t); got != 0 {
			t.Fatalf("issuance rows = %d, want 0", got)
		}
	})
	t.Run("peer_allowed_by_gid", func(t *testing.T) {
		gid := uint32(os.Getgid()) //nolint:gosec // G115: a gid fits uint32
		ts := newTestSigner(t, signerOpts{allowSet: true, allowGIDs: []uint32{gid}})
		resp, err := ts.issue(newRequest(t, "alice"))
		if err != nil {
			t.Fatalf("peer in an allowed group: %v", err)
		}
		ts.verifyCert(t, resp, "alice")
	})
}

// copyFile copies src to dst. When optional is set, a missing src removes
// dst instead.
func copyFile(t *testing.T, src, dst string, optional bool) {
	t.Helper()
	data, err := os.ReadFile(src) //nolint:gosec // G304: test temp files
	if err != nil {
		if optional && errors.Is(err, os.ErrNotExist) {
			if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			return
		}
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil { //nolint:gosec // G703: test temp files
		t.Fatal(err)
	}
}

func TestSignerRestore(t *testing.T) {
	t.Run("restore_older_db", func(t *testing.T) {
		ts := newTestSigner(t, signerOpts{})
		var serials []uint64
		issueN := func(n int) {
			t.Helper()
			for range n {
				resp, err := ts.issue(newRequest(t, "alice"))
				if err != nil {
					t.Fatal(err)
				}
				serials = append(serials, ts.verifyCert(t, resp, "alice").Serial)
			}
		}
		issueN(5)
		ts.stop() // closing the only connection checkpoints the WAL
		backup := ts.dbPath + ".backup"
		copyFile(t, ts.dbPath, backup, false)
		copyFile(t, ts.dbPath+"-wal", backup+"-wal", true)
		ts.start()
		issueN(5)
		ts.stop()
		for _, suffix := range []string{"-wal", "-shm"} {
			if err := os.Remove(ts.dbPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
		}
		copyFile(t, backup, ts.dbPath, false)
		copyFile(t, backup+"-wal", ts.dbPath+"-wal", true)
		ts.start()
		if got := ts.lastSerial(t); got != serials[4] {
			t.Fatalf("restored high-water mark = %d, want the 5th serial %d", got, serials[4])
		}
		if got := ts.issuanceCount(t); got != 5 {
			t.Fatalf("restored issuance rows = %d, want 5", got)
		}
		resp, err := ts.issue(newRequest(t, "alice"))
		if err != nil {
			t.Fatalf("issue after restore: %v", err)
		}
		next := ts.verifyCert(t, resp, "alice").Serial
		for i := 1; i < len(serials); i++ {
			if serials[i] <= serials[i-1] {
				t.Fatalf("serials not strictly increasing: %v", serials)
			}
		}
		for i, s := range serials {
			if next <= s {
				t.Fatalf("serial after restore %d is not above earlier serial #%d (%d)", next, i+1, s)
			}
		}
	})
}
