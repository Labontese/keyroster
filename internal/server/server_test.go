package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/server/web"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// testRPID is the relying party of the test policies.
const testRPID = "keyroster.example"

// logBuffer is the recorder of server log lines: a bytes.Buffer behind a
// mutex, so a test can read it while handlers write. Every slog JSON
// record is one line.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Lines returns the complete lines written so far.
func (b *logBuffer) Lines() []string {
	s := b.String()
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

// newLogger returns a JSON logger that writes into a new logBuffer.
func newLogger() (*slog.Logger, *logBuffer) {
	buf := &logBuffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

// fakeSigner is the one test double of the signerAPI seam. It is safe for
// concurrent use. Each method has a settable result and a call counter,
// and a blocking hook can be armed for one method by name (hold).
//
// Every method calls enter(ctx, method) before it returns; a later plan
// that adds a method adds that step with the method's name and no second
// hook. A held call honours its ctx as a real signer call does: it
// returns ctx's error when ctx ends before release. A method reads its
// result when the call starts, so a call held in the hook returns the
// answer from before any later change.
//
// InstallDirectory has two modes. In forced mode (the default) it returns
// the result setInstall set. In chain mode (setChain) the fake behaves
// like the signer for the version chain: it accepts a version whose prev
// is the SHA-256 of the bytes it holds (the all-zero genesis prev when it
// holds none) and whose version is one more, holds the new bytes from then
// on, and reports them from Status (version, SHA-256, authorized) and
// GetDirectory; any other version gets the signer's refusal
// directory_version_chain. With loseAnswer set, chain mode accepts and
// holds the version and then returns a transport error, as when the
// signer commits and its reply is lost. Both modes keep the last request.
type fakeSigner struct {
	mu        sync.Mutex
	status    *wire.StatusResponse
	statusErr error
	dir       *wire.GetDirectoryResponse
	dirErr    error
	calls     map[string]int

	install     *wire.InstallDirectoryResponse
	installErr  error
	lastInstall *wire.InstallDirectoryRequest
	chain       bool   // chain mode
	held        []byte // chain mode: the installed directory, nil for none
	heldSigs    []byte
	heldVersion uint64
	leaf        uint64
	loseAnswer  bool
	// unauthorized: chain mode reports the held directory as not
	// authorized (DirectoryAuthorized false), as the signer does when the
	// directory no longer fits the policy in force.
	unauthorized bool

	// Login's settable result (setLogin) and the last request it got.
	login     *wire.IssueResponse
	loginErr  error
	lastLogin *wire.LoginIssueRequest

	// Revoke's and GetKRL's settable results and the last revoke request
	// (03-01).
	revoke     *wire.RevokeResponse
	revokeErr  error
	lastRevoke *wire.RevokeRequest
	krl        *wire.GetKRLResponse
	krlErr     error

	heldMethod string
	entered    chan struct{}
	gate       chan struct{}
}

func newFakeSigner(st *wire.StatusResponse) *fakeSigner {
	return &fakeSigner{status: st, dir: &wire.GetDirectoryResponse{}, calls: map[string]int{}}
}

// setStatus sets the next Status result.
func (f *fakeSigner) setStatus(st *wire.StatusResponse, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.statusErr = st, err
}

// setDirectory sets the next GetDirectory result.
func (f *fakeSigner) setDirectory(d *wire.GetDirectoryResponse, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dir, f.dirErr = d, err
}

// count returns the number of calls to method so far.
func (f *fakeSigner) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// hold arms the hook for method: each later call to method signals
// entered once and blocks until release, which also disarms the hook.
// Calls to any other method are not held.
func (f *fakeSigner) hold(method string) (entered <-chan struct{}, release func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heldMethod = method
	f.entered = make(chan struct{}, 16)
	f.gate = make(chan struct{})
	gate := f.gate
	var once sync.Once
	return f.entered, func() {
		once.Do(func() {
			f.mu.Lock()
			f.heldMethod = ""
			f.mu.Unlock()
			close(gate)
		})
	}
}

// enter is the hook step every fake method takes: it holds the call when
// the hook is armed for method, until release or the end of ctx (then it
// returns ctx's error), and returns nil at once otherwise.
func (f *fakeSigner) enter(ctx context.Context, method string) error {
	f.mu.Lock()
	if f.heldMethod != method {
		f.mu.Unlock()
		return nil
	}
	entered, gate := f.entered, f.gate
	f.mu.Unlock()
	entered <- struct{}{}
	select {
	case <-gate:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *fakeSigner) Status(ctx context.Context) (*wire.StatusResponse, error) {
	f.mu.Lock()
	f.calls["Status"]++
	st, err := f.status, f.statusErr
	if f.chain && st != nil {
		c := *st
		c.DirectoryVersion, c.DirectorySHA256, c.DirectoryAuthorized = 0, [32]byte{}, false
		if f.held != nil {
			c.DirectoryVersion, c.DirectorySHA256, c.DirectoryAuthorized = f.heldVersion, sha256.Sum256(f.held), !f.unauthorized
		}
		st = &c
	}
	f.mu.Unlock()
	if err := f.enter(ctx, "Status"); err != nil {
		return nil, err
	}
	return st, err
}

func (f *fakeSigner) GetDirectory(ctx context.Context) (*wire.GetDirectoryResponse, error) {
	f.mu.Lock()
	f.calls["GetDirectory"]++
	d, err := f.dir, f.dirErr
	if f.chain && err == nil {
		d = &wire.GetDirectoryResponse{}
		if f.held != nil {
			d = &wire.GetDirectoryResponse{Version: f.heldVersion, Directory: f.held, Sigs: f.heldSigs, Authorized: !f.unauthorized}
		}
	}
	f.mu.Unlock()
	if err := f.enter(ctx, "GetDirectory"); err != nil {
		return nil, err
	}
	return d, err
}

// statusNow returns the Status result set last.
func (f *fakeSigner) statusNow() *wire.StatusResponse {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

// setInstall sets forced mode's InstallDirectory result.
func (f *fakeSigner) setInstall(resp *wire.InstallDirectoryResponse, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chain, f.install, f.installErr = false, resp, err
}

// setChain switches to chain mode holding doc with sigs (nil doc: no
// directory installed), as if doc had been installed on the signer
// directly, without the server.
func (f *fakeSigner) setChain(doc, sigs []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chain, f.held, f.heldSigs, f.heldVersion = true, doc, sigs, 0
	if doc != nil {
		f.heldVersion = chainVersion(doc)
	}
}

// setLoseAnswer sets chain mode's loseAnswer switch.
func (f *fakeSigner) setLoseAnswer(lose bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.loseAnswer = lose
}

// heldDirectory returns the bytes chain mode holds.
func (f *fakeSigner) heldDirectory() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held
}

// lastInstallRequest returns the last request InstallDirectory was given.
func (f *fakeSigner) lastInstallRequest() *wire.InstallDirectoryRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastInstall
}

// chainVersion reads the version field of a directory document, 0 when
// it does not decode.
func chainVersion(doc []byte) uint64 {
	var v struct {
		Version uint64 `json:"version"`
		Prev    string `json:"prev"`
	}
	_ = json.Unmarshal(doc, &v)
	return v.Version
}

// errLostAnswer is chain mode's transport error under loseAnswer.
var errLostAnswer = errors.New("signerclient: receive: connection reset (the answer was lost)")

func (f *fakeSigner) InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	f.mu.Lock()
	f.calls["InstallDirectory"]++
	f.lastInstall = &wire.InstallDirectoryRequest{Directory: append([]byte(nil), req.Directory...), Sigs: append([]byte(nil), req.Sigs...)}
	chain, resp, err := f.chain, f.install, f.installErr
	f.mu.Unlock()
	if err := f.enter(ctx, "InstallDirectory"); err != nil {
		return nil, err
	}
	if !chain {
		return resp, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var next struct {
		Version uint64 `json:"version"`
		Prev    string `json:"prev"`
	}
	if json.Unmarshal(req.Directory, &next) != nil {
		return nil, &wire.ErrorResponse{Code: wire.CodeMalformed, Message: "directory_invalid"}
	}
	want := trust.GenesisPrev
	if f.held != nil {
		want = trust.SHA256Hex(f.held)
	}
	if next.Version != f.heldVersion+1 || next.Prev != want {
		return nil, &wire.ErrorResponse{Code: wire.CodeRefused, Message: "directory_version_chain"}
	}
	f.held, f.heldSigs, f.heldVersion = append([]byte(nil), req.Directory...), append([]byte(nil), req.Sigs...), next.Version
	f.leaf++
	if f.loseAnswer {
		return nil, errLostAnswer
	}
	return &wire.InstallDirectoryResponse{Version: next.Version, LeafIndex: f.leaf, SHA256: sha256.Sum256(req.Directory)}, nil
}

// setLogin sets Login's result.
func (f *fakeSigner) setLogin(resp *wire.IssueResponse, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.login, f.loginErr = resp, err
}

// setLoginRefused makes Login refuse with detail, as the signer does: a
// *wire.ErrorResponse with CodeRefused, the type signerclient returns
// (02-12-F22).
func (f *fakeSigner) setLoginRefused(detail string) {
	f.setLogin(nil, &wire.ErrorResponse{Code: wire.CodeRefused, Message: detail})
}

// lastLoginRequest returns the last request Login was given.
func (f *fakeSigner) lastLoginRequest() *wire.LoginIssueRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastLogin
}

func (f *fakeSigner) Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	f.mu.Lock()
	f.calls["Login"]++
	f.lastLogin = req
	resp, err := f.login, f.loginErr
	f.mu.Unlock()
	if err := f.enter(ctx, "Login"); err != nil {
		return nil, err
	}
	return resp, err
}

func (f *fakeSigner) Revoke(ctx context.Context, req *wire.RevokeRequest) (*wire.RevokeResponse, error) {
	f.mu.Lock()
	f.calls["Revoke"]++
	f.lastRevoke = req
	resp, err := f.revoke, f.revokeErr
	f.mu.Unlock()
	if err := f.enter(ctx, "Revoke"); err != nil {
		return nil, err
	}
	return resp, err
}

func (f *fakeSigner) GetKRL(ctx context.Context) (*wire.GetKRLResponse, error) {
	f.mu.Lock()
	f.calls["GetKRL"]++
	resp, err := f.krl, f.krlErr
	f.mu.Unlock()
	if err := f.enter(ctx, "GetKRL"); err != nil {
		return nil, err
	}
	if resp == nil && err == nil {
		resp = &wire.GetKRLResponse{}
	}
	return resp, err
}

// testClock is an injectable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// t0 is the start of every test clock.
var t0 = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

// newTestServer builds a Server on fake with an injected clock at t0, a
// recording logger and a fresh state database in a temporary directory,
// and returns the buffer the logger writes to.
func newTestServer(t *testing.T, fake *fakeSigner) (*Server, *testClock, *logBuffer) {
	t.Helper()
	return newTestServerLimits(t, fake, Limits{})
}

// newTestServerLimits is newTestServer with rate limits lim.
func newTestServerLimits(t *testing.T, fake *fakeSigner, lim Limits) (*Server, *testClock, *logBuffer) {
	t.Helper()
	clock := &testClock{now: t0}
	logger, buf := newLogger()
	s, err := newServer(Config{RPID: testRPID, Clock: clock.Now, Logger: logger, DB: openTestDB(t), Limits: lim}, fake)
	if err != nil {
		t.Fatal(err)
	}
	return s, clock, buf
}

// openTestDB opens a fresh server state database in a temporary directory.
func openTestDB(t *testing.T) *serverdb.DB {
	t.Helper()
	db, err := serverdb.Open(filepath.Join(t.TempDir(), "server.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// testPolicy returns a canonical version-1 policy; withRP adds the
// WebAuthn RP testRPID.
func testPolicy(t *testing.T, withRP bool) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	p := &trust.Policy{
		Version:     1,
		Prev:        trust.GenesisPrev,
		AdminQuorum: 1,
		Admins:      []trust.AdminKey{{Name: "alice", Key: trust.FormatKey(pub)}},
		CAProfiles: []trust.CAProfile{
			{Role: trust.RoleUser, MaxTTLSeconds: 43200, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleHost, MaxTTLSeconds: 2592000, DefaultExtensions: []string{}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleMachine, MaxTTLSeconds: 86400, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
		},
	}
	if withRP {
		p.WebAuthn = &trust.WebAuthnRP{RPID: testRPID, Origins: []string{"https://" + testRPID}}
	}
	data, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.ParsePolicy(data); err != nil {
		t.Fatalf("test policy does not parse: %v", err)
	}
	return data
}

// testStatus returns a Status for custody (every key) at directory
// version dir, with a policy that names testRPID.
func testStatus(t *testing.T, custody string, dir uint64) *wire.StatusResponse {
	t.Helper()
	st := &wire.StatusResponse{
		BundleVersion: 1,
		Bundle:        []byte(`{"bundle":"opaque to the server"}`),
		BundleSigs:    []byte("bundle sigs"),
		Policy:        testPolicy(t, true),
		PolicySigs:    []byte("policy sigs"),
	}
	for _, role := range []string{"user", "host", "machine", "ops", "log"} {
		st.Keys = append(st.Keys, wire.KeyStatus{Role: role, Alg: "ssh-ed25519", Custody: custody, Fingerprint: "SHA256:" + role})
	}
	if dir > 0 {
		st.DirectoryVersion = dir
		st.DirectorySHA256[0] = byte(dir & 0xff)
		st.DirectoryAuthorized = true
	}
	return st
}

// withDirectory returns a copy of st at directory version dir.
func withDirectory(st *wire.StatusResponse, dir uint64) *wire.StatusResponse {
	c := *st
	c.DirectoryVersion = dir
	c.DirectorySHA256 = [32]byte{byte(dir & 0xff)}
	c.DirectoryAuthorized = dir > 0
	return &c
}

// do sends one request through the Server's handler.
func do(s *Server, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://"+testRPID+target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// wantSecurityHeaders are the six headers every response carries.
var wantSecurityHeaders = map[string]string{
	"Content-Security-Policy":    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
	"Strict-Transport-Security":  "max-age=63072000",
	"Cross-Origin-Opener-Policy": "same-origin",
	"X-Content-Type-Options":     "nosniff",
	"Referrer-Policy":            "no-referrer",
	"Cache-Control":              "no-store",
}

func requireHeaders(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	for k, want := range wantSecurityHeaders {
		if got := rec.Header().Values(k); len(got) != 1 || got[0] != want {
			t.Errorf("%s: %s = %q, want exactly %q", what, k, got, want)
		}
	}
}

// requireUnavailable checks a fail-closed answer: 503, the signer
// unavailable body, and nothing from any status.
func requireUnavailable(t *testing.T, what string, rec *httptest.ResponseRecorder, html bool) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%s = %d, want 503:\n%s", what, rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if html {
		if !strings.Contains(body, "Signer unavailable") || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%s: not the error page:\n%s", what, body)
		}
	} else if strings.TrimSpace(body) != `{"error":"signer unavailable"}` {
		t.Fatalf("%s body = %q, want {\"error\":\"signer unavailable\"}", what, body)
	}
	for _, leak := range []string{testRPID, "kr-banner", custodytext.SoftwareCABanner([]string{"user"})[:30], "alice", "Directory version", "opaque to the server"} {
		if strings.Contains(body, leak) {
			t.Fatalf("%s carries status data %q:\n%s", what, leak, body)
		}
	}
	if v := rec.Header().Values(serverclient.CustodyHeader); len(v) != 0 {
		t.Fatalf("%s carries %s %q", what, serverclient.CustodyHeader, v)
	}
	requireHeaders(t, what, rec)
}

func TestServerStatus(t *testing.T) {
	t.Run("status_refresh_failure_fails_closed", func(t *testing.T) {
		fake := newFakeSigner(testStatus(t, "software", 0))
		s, clock, _ := newTestServer(t, fake)
		for _, p := range []string{"/", "/api/v1/trust", "/healthz"} {
			if rec := do(s, http.MethodGet, p, nil); rec.Code != http.StatusOK {
				t.Fatalf("t0 GET %s = %d", p, rec.Code)
			}
		}
		down := &wire.ErrorResponse{Code: wire.CodeUnavailable, Message: "trust_changed"}
		fake.setStatus(nil, down)
		clock.set(t0.Add(4 * time.Second))
		for _, p := range []string{"/", "/api/v1/trust", "/healthz"} {
			if rec := do(s, http.MethodGet, p, nil); rec.Code != http.StatusOK {
				t.Fatalf("t0+4s GET %s = %d, want 200 from the cache", p, rec.Code)
			}
		}
		clock.set(t0.Add(6 * time.Second))
		requireUnavailable(t, "t0+6s GET /api/v1/trust", do(s, http.MethodGet, "/api/v1/trust", nil), false)
		requireUnavailable(t, "t0+6s GET /healthz", do(s, http.MethodGet, "/healthz", nil), false)
		requireUnavailable(t, "t0+6s GET /", do(s, http.MethodGet, "/", nil), true)
		fake.setStatus(testStatus(t, "software", 0), nil)
		clock.set(t0.Add(7 * time.Second))
		if rec := do(s, http.MethodGet, "/", nil); rec.Code != http.StatusOK {
			t.Fatalf("t0+7s GET / = %d, want 200 after the signer is back", rec.Code)
		}
	})

	t.Run("drop_status_forces_refresh", func(t *testing.T) {
		st1 := testStatus(t, "agent", 1)
		fake := newFakeSigner(st1)
		s, _, _ := newTestServer(t, fake)
		page := func() *httptest.ResponseRecorder { return do(s, http.MethodGet, "/", nil) }
		dirOf := func(rec *httptest.ResponseRecorder) string {
			b := rec.Body.String()
			i := strings.Index(b, "<dt>Directory version</dt><dd>")
			if i < 0 {
				t.Fatalf("no directory version on the page:\n%s", b)
			}
			rest := b[i+len("<dt>Directory version</dt><dd>"):]
			return rest[:strings.Index(rest, "<")]
		}
		if rec := page(); rec.Code != http.StatusOK || dirOf(rec) != "1" || fake.count("Status") != 1 {
			t.Fatalf("first GET / = %d, directory %q, %d Status calls; want 200, 1, 1", rec.Code, dirOf(rec), fake.count("Status"))
		}
		fake.setStatus(withDirectory(st1, 2), nil)
		if rec := page(); dirOf(rec) != "1" || fake.count("Status") != 1 {
			t.Fatalf("control: GET / within the TTL shows directory %q after %d Status calls; want the cached 1 and no call", dirOf(rec), fake.count("Status"))
		}
		s.dropStatus()
		if rec := page(); rec.Code != http.StatusOK || dirOf(rec) != "2" || fake.count("Status") != 2 {
			t.Fatalf("GET / after dropStatus = %d, directory %q, %d Status calls; want 200, 2 and exactly one new call", rec.Code, dirOf(rec), fake.count("Status"))
		}
		fake.setStatus(nil, errors.New("signer down"))
		s.dropStatus()
		requireUnavailable(t, "GET / after dropStatus with the signer down", page(), true)
	})

	t.Run("drop_during_inflight_refresh", func(t *testing.T) {
		st1 := testStatus(t, "agent", 1)
		fake := newFakeSigner(st1)
		s, _, _ := newTestServer(t, fake)
		entered, release := fake.hold("Status")
		defer release()
		refreshed := make(chan *statusView, 1)
		go func() {
			v, err := s.currentStatus(context.Background())
			if err != nil {
				t.Error(err)
			}
			refreshed <- v
		}()
		<-entered // the refresh is inside the signer call
		dropped := make(chan struct{})
		go func() {
			s.dropStatus()
			close(dropped)
		}()
		select {
		case <-dropped:
			t.Fatal("dropStatus returned while a refresh was in flight; it must wait for the refresh's mutex")
		case <-time.After(50 * time.Millisecond):
		}
		fake.setStatus(withDirectory(st1, 2), nil)
		release()
		if v := <-refreshed; v == nil || v.raw.DirectoryVersion != 1 {
			t.Fatalf("the held refresh returned %+v, want the answer read before the change (directory 1)", v)
		}
		<-dropped
		v, err := s.currentStatus(context.Background())
		if err != nil || v.raw.DirectoryVersion != 2 || fake.count("Status") != 2 {
			t.Fatalf("currentStatus after the drop = %+v, %v after %d Status calls; want directory 2 from a new call", v, err, fake.count("Status"))
		}
	})

	t.Run("concurrent_callers_share_one_failed_refresh", func(t *testing.T) {
		// Callers that arrive while a refresh is in flight take its
		// result, a failure included; none of them starts a refresh of
		// its own after it (no queue of serial 3 s attempts).
		fake := newFakeSigner(nil)
		fake.setStatus(nil, errors.New("signer down"))
		s, _, _ := newTestServer(t, fake)
		entered, release := fake.hold("Status")
		defer release()
		const n = 8
		errs := make(chan error, n)
		call := func() {
			_, err := s.currentStatus(context.Background())
			errs <- err
		}
		go call()
		<-entered // the first refresh is inside the signer call
		for range n - 1 {
			go call()
		}
		time.Sleep(100 * time.Millisecond) // let the others join the refresh
		release()
		for range n {
			select {
			case err := <-errs:
				if err == nil {
					t.Fatal("a caller got a status from a failed refresh")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("a caller is still waiting after the refresh ended")
			}
		}
		if got := fake.count("Status"); got != 1 {
			t.Fatalf("%d concurrent callers made %d Status calls, want 1 shared refresh", n, got)
		}
	})

	t.Run("waiter_leaves_on_cancel", func(t *testing.T) {
		// A request whose client went away stops waiting for the refresh,
		// and a request already cancelled starts no signer call.
		fake := newFakeSigner(testStatus(t, "agent", 0))
		s, _, _ := newTestServer(t, fake)
		cancelled, cancelNow := context.WithCancel(context.Background())
		cancelNow()
		if _, err := s.currentStatus(cancelled); err == nil || fake.count("Status") != 0 {
			t.Fatalf("currentStatus with a cancelled context = %v after %d Status calls; want an error and no call", err, fake.count("Status"))
		}
		entered, release := fake.hold("Status")
		defer release()
		go func() { _, _ = s.currentStatus(context.Background()) }()
		<-entered
		ctx, cancel := context.WithCancel(context.Background())
		left := make(chan error, 1)
		go func() {
			_, err := s.currentStatus(ctx)
			left <- err
		}()
		time.Sleep(50 * time.Millisecond)
		cancel()
		select {
		case err := <-left:
			if err == nil {
				t.Fatal("a cancelled waiter got a status")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a cancelled waiter is still waiting for the held refresh")
		}
		release()
		if got := fake.count("Status"); got != 1 {
			t.Fatalf("%d Status calls, want 1", got)
		}
	})

	t.Run("refresh_survives_starter_cancel", func(t *testing.T) {
		// The refresh is detached from the request that started it: when
		// that caller goes away, a second caller waiting on the same
		// refresh still gets the signer's answer.
		fake := newFakeSigner(testStatus(t, "agent", 0))
		s, _, _ := newTestServer(t, fake)
		entered, release := fake.hold("Status")
		defer release()
		starter, cancelStarter := context.WithCancel(context.Background())
		defer cancelStarter()
		started := make(chan error, 1)
		go func() {
			_, err := s.currentStatus(starter)
			started <- err
		}()
		<-entered // the starter's refresh is inside the signer call
		type result struct {
			v   *statusView
			err error
		}
		waited := make(chan result, 1)
		go func() {
			v, err := s.currentStatus(context.Background())
			waited <- result{v, err}
		}()
		time.Sleep(50 * time.Millisecond) // let the second caller join the refresh
		cancelStarter()
		if err := <-started; err == nil {
			t.Fatal("the cancelled starter got a status")
		}
		select {
		case r := <-waited:
			t.Fatalf("the waiter returned %+v, %v before the signer answered: the refresh ended with the starter's cancel", r.v, r.err)
		case <-time.After(200 * time.Millisecond):
		}
		release()
		select {
		case r := <-waited:
			if r.err != nil || r.v == nil {
				t.Fatalf("the waiter got %+v, %v; want the status from the shared refresh", r.v, r.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the waiter is still waiting after release")
		}
		if got := fake.count("Status"); got != 1 {
			t.Fatalf("%d Status calls, want 1 shared refresh", got)
		}
	})

	t.Run("fake_hook_holds_only_armed_method", func(t *testing.T) {
		st := testStatus(t, "agent", 0)
		fake := newFakeSigner(st)
		ctx := context.Background()

		entered, release := fake.hold("GetDirectory")
		if got, err := fake.Status(ctx); got != st || err != nil {
			t.Fatalf("Status with the hook armed for GetDirectory = %v, %v", got, err)
		}
		select {
		case <-entered:
			t.Fatal("a Status call entered a hook armed for GetDirectory")
		default:
		}
		release()

		entered, release = fake.hold("Status")
		done := make(chan *wire.StatusResponse, 1)
		go func() {
			got, _ := fake.Status(ctx)
			done <- got
		}()
		<-entered
		select {
		case <-done:
			t.Fatal("a Status call held by the hook returned before release")
		case <-time.After(50 * time.Millisecond):
		}
		_ = fake.enter(ctx, "GetDirectory") // returns at once while Status is held
		select {
		case <-entered:
			t.Fatal("entered received a second value for one held call")
		default:
		}
		release()
		if got := <-done; got != st {
			t.Fatalf("released Status = %v, want its set result", got)
		}
		returned := make(chan struct{})
		go func() {
			_, _ = fake.Status(ctx)
			close(returned)
		}()
		select {
		case <-returned:
		case <-time.After(5 * time.Second):
			t.Fatal("Status after release is still held: release must disarm the hook")
		}
	})

	t.Run("rp_id_change_fails_closed", func(t *testing.T) {
		// The certificate holder checks every reload against the RP ID
		// the server started with, so a policy that names another RP ID
		// is refused until keyroster-server restarts.
		fake := newFakeSigner(testStatus(t, "agent", 0))
		s, clock, logs := newTestServer(t, fake)
		if rec := do(s, http.MethodGet, "/", nil); rec.Code != http.StatusOK {
			t.Fatalf("GET / = %d", rec.Code)
		}
		st := testStatus(t, "agent", 0)
		p, err := trust.ParsePolicy(st.Policy)
		if err != nil {
			t.Fatal(err)
		}
		p.WebAuthn = &trust.WebAuthnRP{RPID: "other.example", Origins: []string{"https://other.example"}}
		if st.Policy, err = p.Canonical(); err != nil {
			t.Fatal(err)
		}
		fake.setStatus(st, nil)
		clock.set(t0.Add(time.Minute))
		requireUnavailable(t, "GET / after an rp_id change", do(s, http.MethodGet, "/", nil), true)
		requireUnavailable(t, "GET /healthz after an rp_id change", do(s, http.MethodGet, "/healthz", nil), false)
		if !strings.Contains(logs.String(), "restart keyroster-server") || !strings.Contains(logs.String(), "other.example") {
			t.Fatalf("no log line naming the new RP ID and the restart:\n%s", logs)
		}
	})

	t.Run("non_token_custody_fails_closed", func(t *testing.T) {
		// A role or custody that is not a lowercase token is a failed
		// refresh: 503 and no custody header, never a header built from it.
		for _, bad := range []func(*wire.StatusResponse){
			func(st *wire.StatusResponse) { st.Keys[0].Custody = "Software" },
			func(st *wire.StatusResponse) { st.Keys[1].Role = "User" },
			func(st *wire.StatusResponse) { st.Keys[2].Custody = "agent\r\nX-Evil: 1" },
		} {
			st := testStatus(t, "agent", 0)
			bad(st)
			s, _, _ := newTestServer(t, newFakeSigner(st))
			requireUnavailable(t, "GET /healthz with a non-token custody report", do(s, http.MethodGet, "/healthz", nil), false)
			requireUnavailable(t, "GET / with a non-token custody report", do(s, http.MethodGet, "/", nil), true)
		}
		// Control: the same status unchanged is served.
		s, _, _ := newTestServer(t, newFakeSigner(testStatus(t, "agent", 0)))
		if rec := do(s, http.MethodGet, "/healthz", nil); rec.Code != http.StatusOK {
			t.Fatalf("control: GET /healthz = %d", rec.Code)
		}
	})

	t.Run("policy_without_rp_fails_closed", func(t *testing.T) {
		st := testStatus(t, "agent", 0)
		st.Policy = testPolicy(t, false)
		s, _, _ := newTestServer(t, newFakeSigner(st))
		requireUnavailable(t, "GET / without an RP", do(s, http.MethodGet, "/", nil), true)
		requireUnavailable(t, "GET /healthz without an RP", do(s, http.MethodGet, "/healthz", nil), false)
	})
}

func TestServerPages(t *testing.T) {
	t.Run("software_custody_banner", func(t *testing.T) {
		s, _, _ := newTestServer(t, newFakeSigner(testStatus(t, "software", 0)))
		rec := do(s, http.MethodGet, "/", nil)
		want := `<div class="kr-banner" role="alert">` + custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"}) + `</div>`
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("GET / = %d without the banner:\n%s", rec.Code, rec.Body)
		}
		if got := rec.Header().Get(serverclient.CustodyHeader); got != "user=software, host=software, machine=software, ops=software, log=software" {
			t.Fatalf("%s = %q", serverclient.CustodyHeader, got)
		}
	})
	t.Run("mixed_custody_names_software_roles", func(t *testing.T) {
		st := testStatus(t, "tpm", 0)
		st.Keys[4].Custody = "software"
		s, _, _ := newTestServer(t, newFakeSigner(st))
		rec := do(s, http.MethodGet, "/", nil)
		if !strings.Contains(rec.Body.String(), custodytext.SoftwareCABanner([]string{"log"})) {
			t.Fatalf("GET / does not name the log key:\n%s", rec.Body)
		}
	})
	t.Run("no_banner_without_software", func(t *testing.T) {
		s, _, _ := newTestServer(t, newFakeSigner(testStatus(t, "tpm", 0)))
		rec := do(s, http.MethodGet, "/", nil)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "kr-banner") || strings.Contains(rec.Body.String(), "EVALUATION ONLY") {
			t.Fatalf("GET / = %d with a banner:\n%s", rec.Code, rec.Body)
		}
	})
	t.Run("trust_document", func(t *testing.T) {
		st := testStatus(t, "agent", 3)
		s, _, _ := newTestServer(t, newFakeSigner(st))
		rec := do(s, http.MethodGet, "/api/v1/trust", nil)
		var doc serverclient.TrustResponse
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &doc) != nil {
			t.Fatalf("GET /api/v1/trust = %d:\n%s", rec.Code, rec.Body)
		}
		if !bytes.Equal(doc.Bundle, st.Bundle) || !bytes.Equal(doc.BundleSigs, st.BundleSigs) || !bytes.Equal(doc.Policy, st.Policy) ||
			!bytes.Equal(doc.PolicySigs, st.PolicySigs) || doc.BundleVersion != 1 || doc.DirectoryVersion != 3 || len(doc.Custody) != 5 ||
			doc.Custody[0] != (serverclient.KeyCustody{Role: "user", Alg: "ssh-ed25519", Custody: "agent", Fingerprint: "SHA256:user"}) {
			t.Fatalf("trust document = %+v", doc)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"bundle", "bundle_sigs", "policy", "policy_sigs", "bundle_version", "directory_version", "custody"} {
			if _, ok := raw[k]; !ok {
				t.Errorf("trust document lacks %q", k)
			}
		}
	})
}

func TestServerHeaders(t *testing.T) {
	fake := newFakeSigner(testStatus(t, "agent", 0))
	s, clock, _ := newTestServer(t, fake)
	for _, c := range []struct {
		method, target string
		hdr            map[string]string
		code           int
	}{
		{http.MethodGet, "/", nil, http.StatusOK},
		{http.MethodGet, "/api/v1/trust", nil, http.StatusOK},
		{http.MethodGet, "/healthz", nil, http.StatusOK},
		{http.MethodGet, "/static/app.css", nil, http.StatusOK},
		{http.MethodGet, "/static/missing.css", nil, http.StatusNotFound},
		{http.MethodGet, "/no/such/page", nil, http.StatusNotFound},
		{http.MethodPost, "/", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
	} {
		rec := do(s, c.method, c.target, c.hdr)
		if rec.Code != c.code {
			t.Errorf("%s %s = %d, want %d", c.method, c.target, rec.Code, c.code)
		}
		requireHeaders(t, c.method+" "+c.target, rec)
	}
	fake.setStatus(nil, errors.New("signer down"))
	clock.set(t0.Add(time.Minute))
	requireUnavailable(t, "GET / with the signer down", do(s, http.MethodGet, "/", nil), true)

	t.Run("cross_origin_protection", func(t *testing.T) {
		if rec := do(s, http.MethodPost, "/", map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
			t.Fatalf("cross-site POST = %d, want 403", rec.Code)
		}
		if rec := do(s, http.MethodPost, "/", map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusForbidden {
			t.Fatalf("POST with a foreign Origin = %d, want 403", rec.Code)
		}
		// Same origin passes the protection; the route then answers
		// 405, since no POST route exists yet.
		if rec := do(s, http.MethodPost, "/", map[string]string{"Sec-Fetch-Site": "same-origin"}); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("same-origin POST = %d, want 405 from the router (not 403)", rec.Code)
		}
	})

	t.Run("static_content_types", func(t *testing.T) {
		n := 0
		err := fs.WalkDir(web.FS, "static", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			n++
			want, ok := staticTypes[path.Ext(p)]
			if !ok {
				t.Errorf("embedded static file %s has no entry in staticTypes", p)
				return nil
			}
			rec := do(s, http.MethodGet, "/"+p, nil)
			if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != want {
				t.Errorf("GET /%s = %d %q, want 200 %q", p, rec.Code, rec.Header().Get("Content-Type"), want)
			}
			return nil
		})
		if err != nil || n == 0 {
			t.Fatalf("walk static: %v, %d files", err, n)
		}
		if rec := do(s, http.MethodGet, "/static/", nil); rec.Code != http.StatusNotFound {
			t.Fatalf("GET /static/ = %d, want 404 (no listing)", rec.Code)
		}
		if rec := do(s, http.MethodGet, "/static/app.txt", nil); rec.Code != http.StatusNotFound {
			t.Fatalf("GET /static/app.txt = %d, want 404 (unmapped extension)", rec.Code)
		}
	})
}
