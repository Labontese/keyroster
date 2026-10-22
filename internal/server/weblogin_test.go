package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// highSignInLimits keeps the sign-in limiters out of tests that are not
// about them.
var highSignInLimits = Limits{SignInPerMinute: 100000, SignInBurst: 100000, SignInUserPerMinute: 100000, SignInUserBurst: 100000}

// The fixed answers of the sign-in routes.
const (
	noUsableKey404 = `{"error":"no usable passkey for this user"}`
	signInFailed   = `{"error":"sign-in failed"}`
	signInLimited  = `{"error":"rate limited"}`
)

// signInEnv is a Server on a fakeSigner in chain mode, holding a directory
// in which alice (EdDSA, two passkeys) and bob (ES256) are active and
// alice holds role dev, and whose state database the test can inspect.
type signInEnv struct {
	s      *Server
	fake   *fakeSigner
	clock  *testClock
	log    *logBuffer
	dbPath string

	alice, alice2, bob *webauthntest.Authenticator
	doc                []byte // the directory the fake holds
}

// dirCred is a's credential as a directory binds it, with the backed-up
// (synced) flag set when synced.
func dirCred(a *webauthntest.Authenticator, synced bool) directory.Credential {
	c := a.Credential()
	return directory.Credential{ID: base64.RawURLEncoding.EncodeToString(c.ID), Alg: c.Alg, SPKI: base64.StdEncoding.EncodeToString(c.SPKI),
		BackupEligible: synced, BackedUp: synced}
}

// grantRole returns a mutation that grants the role name (principal
// role:name, max TTL ttl) to user.
func grantRole(name, user string, ttl uint64) func(d *directory.Directory) {
	return func(d *directory.Directory) {
		d.Roles = append(d.Roles, directory.Role{Name: name, Principals: []string{"role:" + name}, MaxTTLSeconds: ttl,
			Extensions: []string{}, Users: []string{user}, Groups: []string{}})
	}
}

// setStatus returns a mutation that sets user's status.
func setStatus(user, status string) func(d *directory.Directory) {
	return func(d *directory.Directory) {
		for i := range d.Users {
			if d.Users[i].Name == user {
				d.Users[i].Status = status
			}
		}
	}
}

func newSignInEnv(t *testing.T, lim Limits) *signInEnv {
	t.Helper()
	e := &signInEnv{
		alice:  newAuthenticator(t, webauthn.AlgEdDSA),
		alice2: newAuthenticator(t, webauthn.AlgES256),
		bob:    newAuthenticator(t, webauthn.AlgES256),
		clock:  &testClock{now: t0},
		fake:   newFakeSigner(testStatus(t, "agent", 0)),
		dbPath: filepath.Join(t.TempDir(), "server.db"),
	}
	db, err := serverdb.Open(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logger, buf := newLogger()
	e.log = buf
	if e.s, err = newServer(Config{RPID: testRPID, Clock: e.clock.Now, Logger: logger, DB: db, Limits: lim}, e.fake); err != nil {
		t.Fatal(err)
	}
	e.doc = successor(t, nil, func(d *directory.Directory) {
		bind("alice", dirCred(e.alice, true))(d)
		bind("alice", dirCred(e.alice2, false))(d)
		bind("bob", dirCred(e.bob, false))(d)
		grantRole("dev", "alice", 7200)(d)
	})
	e.fake.setChain(e.doc, testSigs)
	return e
}

// install makes the fake hold the successor of the current directory
// after mutate, as an install on the signer socket would, without the
// server; the clock then moves 6 s, past statusTTL, so the next request
// reads the new version (cross-plan audit: no dropStatus, no wall clock).
func (e *signInEnv) install(t *testing.T, mutate func(d *directory.Directory)) {
	t.Helper()
	e.doc = successor(t, e.doc, mutate)
	e.fake.setChain(e.doc, testSigs)
	e.advance(6 * time.Second)
}

func (e *signInEnv) advance(d time.Duration) { e.clock.set(e.clock.Now().Add(d)) }

// request sends one request through the Server's handler from addr (""
// for httptest's default) with the session cookie value cookie ("" for
// none) and the headers hdr.
func (e *signInEnv) request(method, target, body, addr, cookie string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "https://"+testRPID+target, strings.NewReader(body))
	if addr != "" {
		req.RemoteAddr = addr
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != "" {
		req.Header.Set("Cookie", sessionCookieName+"="+cookie)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.s.Handler().ServeHTTP(rec, req)
	return rec
}

// beginFrom sends a begin for user from addr.
func (e *signInEnv) beginFrom(t *testing.T, user, addr string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(signInBeginRequest{User: user})
	if err != nil {
		t.Fatal(err)
	}
	return e.request(http.MethodPost, signInBeginPath, string(body), addr, "", nil)
}

// mustBegin begins a sign-in for user and decodes the 200 answer.
func (e *signInEnv) mustBegin(t *testing.T, user string) signInBeginResponse {
	t.Helper()
	rec := e.beginFrom(t, user, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("begin %s = %d %s\nlog:\n%s", user, rec.Code, rec.Body, e.log)
	}
	var b signInBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

// challengeOf decodes a begin answer's challenge.
func challengeOf(t *testing.T, b signInBeginResponse) [32]byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(b.PublicKey.Challenge)
	if err != nil || len(raw) != 32 {
		t.Fatalf("challenge %q: %v", b.PublicKey.Challenge, err)
	}
	return [32]byte(raw)
}

// finishBodyFor is the finish body of assertion a for challengeID.
func finishBodyFor(t *testing.T, challengeID string, a webauthn.Assertion) string {
	t.Helper()
	body, err := json.Marshal(signInFinishRequest{
		ChallengeID:       challengeID,
		CredentialID:      base64.RawURLEncoding.EncodeToString(a.CredentialID),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(a.AuthenticatorData),
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(a.ClientDataJSON),
		Signature:         base64.RawURLEncoding.EncodeToString(a.Signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// finish sends a finish body from addr.
func (e *signInEnv) finish(body, addr string) *httptest.ResponseRecorder {
	return e.request(http.MethodPost, signInFinishPath, body, addr, "", nil)
}

// signIn runs a whole sign-in of user with auth and returns the session
// cookie value.
func (e *signInEnv) signIn(t *testing.T, user string, auth *webauthntest.Authenticator) string {
	t.Helper()
	b := e.mustBegin(t, user)
	rec := e.finish(finishBodyFor(t, b.ChallengeID, auth.Assert(testRPID, testOrigin, challengeOf(t, b))), "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"redirect":"/account"}` {
		t.Fatalf("finish %s = %d %s\nlog:\n%s", user, rec.Code, rec.Body, e.log)
	}
	return requireSetSession(t, rec)
}

// requireSetSession fails unless rec sets the session cookie with every
// flag, and returns its value.
func requireSetSession(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	sc := rec.Header().Values("Set-Cookie")
	if len(sc) != 1 || !strings.HasPrefix(sc[0], sessionCookieName+"=") {
		t.Fatalf("Set-Cookie = %q, want exactly one %s", sc, sessionCookieName)
	}
	for _, flag := range []string{"; Path=/", "; Max-Age=43200", "; HttpOnly", "; Secure", "; SameSite=Strict"} {
		if !strings.Contains(sc[0], flag) {
			t.Fatalf("Set-Cookie %q lacks %q", sc[0], flag)
		}
	}
	value, _, _ := strings.Cut(strings.TrimPrefix(sc[0], sessionCookieName+"="), ";")
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(value); err != nil || len(raw) != 32 {
		t.Fatalf("session ID %q is not 32 bytes of base64url", value)
	}
	return value
}

// openRaw opens the state database a second time, for inspection only.
func (e *signInEnv) openRaw(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", e.dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// sessionRows returns the number of session rows.
func (e *signInEnv) sessionRows(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.openRaw(t).QueryRow(`SELECT count(*) FROM sessions`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// requireRefused fails unless rec is the uniform 401 with no cookie, no
// session row exists, and the last sign-in log line has reason.
func (e *signInEnv) requireRefused(t *testing.T, what string, rec *httptest.ResponseRecorder, reason string) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != signInFailed {
		t.Fatalf("%s = %d %s, want 401 %s\nlog:\n%s", what, rec.Code, rec.Body, signInFailed, e.log)
	}
	if sc := rec.Header().Values("Set-Cookie"); len(sc) != 0 {
		t.Fatalf("%s set a cookie: %q", what, sc)
	}
	if n := e.sessionRows(t); n != 0 {
		t.Fatalf("%s left %d session rows, want 0", what, n)
	}
	if got := lastSignIn(t, e.log); got["reason"] != reason || got["event"] != eventSignInRefused {
		t.Fatalf("%s logged %v, want event %s reason %s", what, got, eventSignInRefused, reason)
	}
}

// signInLines returns the "web sign-in" log records.
func signInLines(t *testing.T, log *logBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range log.Lines() {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		if m["msg"] == "web sign-in" {
			out = append(out, m)
		}
	}
	return out
}

// lastSignIn returns the last "web sign-in" log record.
func lastSignIn(t *testing.T, log *logBuffer) map[string]any {
	t.Helper()
	lines := signInLines(t, log)
	if len(lines) == 0 {
		t.Fatalf("no web sign-in log line:\n%s", log)
	}
	return lines[len(lines)-1]
}

// requireNoPasskey fails unless rec is the uniform begin 404.
func requireNoPasskey(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != noUsableKey404 {
		t.Fatalf("%s = %d %s, want 404 %s", what, rec.Code, rec.Body, noUsableKey404)
	}
}

// TestSignInBegin: begin answers request options for an active directory
// user with bound credentials, and the identical 404 for every other name,
// whatever the server's own tables hold (AUTH-01, AUTH-02).
func TestSignInBegin(t *testing.T) {
	t.Run("options_from_directory", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		b := e.mustBegin(t, "alice")
		pk := b.PublicKey
		if pk.RPID != testRPID || pk.UserVerification != "required" || pk.Timeout != 60000 || len(pk.AllowCredentials) != 2 {
			t.Fatalf("options = %+v", pk)
		}
		want := map[string]bool{}
		for _, a := range []*webauthntest.Authenticator{e.alice, e.alice2} {
			want[base64.RawURLEncoding.EncodeToString(a.Credential().ID)] = true
		}
		for _, c := range pk.AllowCredentials {
			if c.Type != "public-key" || !want[c.ID] {
				t.Fatalf("allowCredentials %+v holds a credential that is not alice's", pk.AllowCredentials)
			}
		}
		challengeOf(t, b)
		if raw, err := base64.RawURLEncoding.Strict().DecodeString(b.ChallengeID); err != nil || len(raw) != 32 {
			t.Fatalf("challenge_id %q", b.ChallengeID)
		}
	})
	t.Run("unknown_user_uniform_404", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		requireNoPasskey(t, "begin carol", e.beginFrom(t, "carol", ""))
	})
	t.Run("pending_user_uniform_404", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		if err := e.s.db.CreatePendingUser(context.Background(), serverdb.PendingUser{Name: "carol", UserHandle: make([]byte, 32), InviteHash: []byte("invite"),
			InviteExpires: t0.Add(time.Hour), Created: t0, CreatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		requireNoPasskey(t, "begin of an invited user", e.beginFrom(t, "carol", ""))
	})
	t.Run("unapproved_user_uniform_404", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		ctx := context.Background()
		if err := e.s.db.CreatePendingUser(ctx, serverdb.PendingUser{Name: "carol", UserHandle: make([]byte, 32), InviteHash: []byte("invite"),
			InviteExpires: t0.Add(time.Hour), Created: t0, CreatedBy: "admin"}); err != nil {
			t.Fatal(err)
		}
		c := newAuthenticator(t, webauthn.AlgEdDSA).Credential()
		if err := e.s.db.BindPendingCredential(ctx, []byte("invite"), t0.UnixMicro(), serverdb.PendingCredential{
			ID: base64.RawURLEncoding.EncodeToString(c.ID), UserName: "carol", Alg: c.Alg, SPKI: c.SPKI}); err != nil {
			t.Fatal(err)
		}
		requireNoPasskey(t, "begin of a registered, unapproved user", e.beginFrom(t, "carol", ""))
	})
	t.Run("disabled_user_uniform_404", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		e.install(t, setStatus("bob", directory.StatusDisabled))
		requireNoPasskey(t, "begin of a disabled user", e.beginFrom(t, "bob", ""))
		if got := lastSignIn(t, e.log); got["event"] != eventBeginRefused || got["reason"] != reasonNoUsablePasskey || got["user"] != "bob" {
			t.Fatalf("logged %v", got)
		}
	})
	t.Run("nothing_installed_uniform_404", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		e.fake.setChain(nil, nil)
		e.advance(6 * time.Second)
		requireNoPasskey(t, "begin with no directory", e.beginFrom(t, "alice", ""))
	})
	t.Run("malformed_body_400", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		for _, body := range []string{"", "{", `{"user":"alice","x":1}`, `{"user":"alice"} {}`, `["alice"]`} {
			rec := e.request(http.MethodPost, signInBeginPath, body, "", "", nil)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("begin %q = %d %s, want 400", body, rec.Code, rec.Body)
			}
		}
		big := `{"user":"` + strings.Repeat("a", 2000) + `"}`
		if rec := e.request(http.MethodPost, signInBeginPath, big, "", "", nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("oversized begin = %d, want 400", rec.Code)
		}
	})
}

// TestSignInFinish: finish opens a session only for a fresh challenge of
// the user's own bound credential with a valid assertion; every other
// finish is the uniform 401 with no session row.
func TestSignInFinish(t *testing.T) {
	t.Run("signs_in", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		e.signIn(t, "alice", e.alice)
		if n := e.sessionRows(t); n != 1 {
			t.Fatalf("%d session rows, want 1", n)
		}
		if got := lastSignIn(t, e.log); got["event"] != eventSignInOK || got["user"] != "alice" {
			t.Fatalf("logged %v", got)
		}
	})
	// refusals builds each refused finish from a fresh begin for alice.
	refusals := []struct {
		name, reason string
		body         func(t *testing.T, e *signInEnv) string
	}{
		{"wrong_challenge_refused", "assertion_challenge", func(t *testing.T, e *signInEnv) string {
			a, b := e.mustBegin(t, "alice"), e.mustBegin(t, "alice")
			return finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, a)))
		}},
		{"other_users_credential_refused", reasonCredentialUnbound, func(t *testing.T, e *signInEnv) string {
			b := e.mustBegin(t, "alice")
			return finishBodyFor(t, b.ChallengeID, e.bob.Assert(testRPID, testOrigin, challengeOf(t, b)))
		}},
		{"uv_clear_refused", "assertion_user_verification", func(t *testing.T, e *signInEnv) string {
			b := e.mustBegin(t, "alice")
			return finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b), webauthntest.WithFlags(0x01)))
		}},
		{"origin_http_scheme_refused", "assertion_origin", func(t *testing.T, e *signInEnv) string {
			b := e.mustBegin(t, "alice")
			return finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, "http://"+testRPID, challengeOf(t, b)))
		}},
		{"origin_other_port_refused", "assertion_origin", func(t *testing.T, e *signInEnv) string {
			b := e.mustBegin(t, "alice")
			return finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin+":8443", challengeOf(t, b)))
		}},
		{"rp_id_hash_other_rp_refused", "assertion_rp_mismatch", func(t *testing.T, e *signInEnv) string {
			b := e.mustBegin(t, "alice")
			return finishBodyFor(t, b.ChallengeID, e.alice.Assert("other.example", testOrigin, challengeOf(t, b)))
		}},
		{"signature_bit_flip_refused", "assertion_signature", func(t *testing.T, e *signInEnv) string {
			b := e.mustBegin(t, "alice")
			a := e.alice.Assert(testRPID, testOrigin, challengeOf(t, b))
			a.Signature[len(a.Signature)/2] ^= 0x01
			return finishBodyFor(t, b.ChallengeID, a)
		}},
		{"type_create_refused", "assertion_type", func(t *testing.T, e *signInEnv) string {
			b := e.mustBegin(t, "alice")
			return finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b), webauthntest.WithType("webauthn.create")))
		}},
		{"unknown_challenge_refused", reasonChallengeNotFound, func(t *testing.T, e *signInEnv) string {
			_, id, err := randomID(32)
			if err != nil {
				t.Fatal(err)
			}
			return finishBodyFor(t, id, e.alice.Assert(testRPID, testOrigin, [32]byte{}))
		}},
		{"malformed_refused", reasonMalformed, func(t *testing.T, e *signInEnv) string {
			b := e.mustBegin(t, "alice")
			return strings.Replace(finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b))), `"signature":"`, `"signature":"!`, 1)
		}},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			e := newSignInEnv(t, highSignInLimits)
			e.requireRefused(t, c.name, e.finish(c.body(t, e), ""), c.reason)
		})
	}
	t.Run("challenge_replay_refused", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		b := e.mustBegin(t, "alice")
		body := finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b)))
		if rec := e.finish(body, ""); rec.Code != http.StatusOK {
			t.Fatalf("first finish = %d %s", rec.Code, rec.Body)
		}
		if _, err := e.openRaw(t).Exec(`DELETE FROM sessions`); err != nil {
			t.Fatal(err)
		}
		e.requireRefused(t, "the same finish again", e.finish(body, ""), reasonChallengeNotFound)
	})
	t.Run("challenge_expired_refused", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		b := e.mustBegin(t, "alice")
		e.advance(121 * time.Second)
		e.requireRefused(t, "a finish 121 s after begin", e.finish(finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b))), ""), reasonChallengeNotFound)
	})
	t.Run("challenge_used_by_refused_finish", func(t *testing.T) {
		// A refused finish consumes its challenge too: a second try with a
		// good assertion over it is refused.
		e := newSignInEnv(t, highSignInLimits)
		b := e.mustBegin(t, "alice")
		e.requireRefused(t, "bob's assertion", e.finish(finishBodyFor(t, b.ChallengeID, e.bob.Assert(testRPID, testOrigin, challengeOf(t, b))), ""), reasonCredentialUnbound)
		e.requireRefused(t, "alice's assertion after it", e.finish(finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b))), ""), reasonChallengeNotFound)
	})
	t.Run("disabled_between_begin_and_finish_refused", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		b := e.mustBegin(t, "alice")
		e.install(t, setStatus("alice", directory.StatusDisabled))
		e.requireRefused(t, "finish after a disable", e.finish(finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b))), ""), reasonUserNotActive)
	})
}

// TestSignInLimits: the sign-in route class (02-07's deferred row): a
// per-username limiter beside the per-client one, bounded, keyed only on
// valid names (for finish on the challenge's stored user) together with
// the client, so one client cannot lock another out (owner decision G1).
func TestSignInLimits(t *testing.T) {
	// distinct gives the i-th request its own client address, so only the
	// per-username limiter can refuse it.
	distinct := func(i int) string { return "198.51.100." + strconv.Itoa(i%250+1) + ":1234" }
	t.Run("eleventh_begin_for_one_user_429", func(t *testing.T) {
		// The per-client limit is lifted, so only the per-username bucket
		// of (alice, this client) can refuse.
		e := newSignInEnv(t, Limits{SignInPerMinute: 100000, SignInBurst: 100000})
		const client = "203.0.113.9:1234"
		for i := range 10 {
			if rec := e.beginFrom(t, "alice", client); rec.Code != http.StatusOK {
				t.Fatalf("begin %d = %d %s", i+1, rec.Code, rec.Body)
			}
		}
		rec := e.beginFrom(t, "alice", client)
		if rec.Code != http.StatusTooManyRequests || strings.TrimSpace(rec.Body.String()) != signInLimited || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("11th begin = %d %s, want 429", rec.Code, rec.Body)
		}
		if got := lastSignIn(t, e.log); got["event"] != eventRateLimited || got["reason"] != reasonPerUser || got["user"] != "alice" {
			t.Fatalf("logged %v", got)
		}
		// Another user from the same client is not affected.
		if rec := e.beginFrom(t, "bob", client); rec.Code != http.StatusOK {
			t.Fatalf("begin bob = %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("other_client_not_locked_out", func(t *testing.T) {
		// 02-10 pre-merge review, owner decision G1: an unauthenticated
		// client that drains alice's bucket from its own address, within
		// its per-client limit, does not keep alice from signing in from
		// another address. The attacker itself stays limited.
		e := newSignInEnv(t, Limits{})
		const attacker = "203.0.113.9:1234"
		for i := range 10 {
			if rec := e.beginFrom(t, "alice", attacker); rec.Code != http.StatusOK {
				t.Fatalf("attacker begin %d = %d %s", i+1, rec.Code, rec.Body)
			}
		}
		e.signIn(t, "alice", e.alice)
		// 3 s refill one per-client token (20/min) but only half a
		// per-username one (10/min), so the per-username bucket refuses.
		e.advance(3 * time.Second)
		if rec := e.beginFrom(t, "alice", attacker); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("attacker's 11th begin = %d %s, want 429", rec.Code, rec.Body)
		}
		if got := lastSignIn(t, e.log); got["reason"] != reasonPerUser || got["user"] != "alice" {
			t.Fatalf("logged %v", got)
		}
	})
	t.Run("per_client_limit", func(t *testing.T) {
		e := newSignInEnv(t, Limits{SignInUserPerMinute: 100000, SignInUserBurst: 100000})
		for i := range 10 {
			if rec := e.beginFrom(t, "carol"+strconv.Itoa(i), ""); rec.Code != http.StatusNotFound {
				t.Fatalf("begin %d = %d", i+1, rec.Code)
			}
		}
		if rec := e.beginFrom(t, "alice", ""); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("11th begin from one client = %d, want 429", rec.Code)
		}
		if got := lastSignIn(t, e.log); got["reason"] != reasonPerClient {
			t.Fatalf("logged %v", got)
		}
	})
	t.Run("global_backstop", func(t *testing.T) {
		e := newSignInEnv(t, Limits{SignInPerMinute: 1, SignInBurst: 1, SignInUserPerMinute: 100000, SignInUserBurst: 100000})
		for i := range 10 {
			if rec := e.beginFrom(t, "carol", distinct(i)); rec.Code != http.StatusNotFound {
				t.Fatalf("begin %d = %d, want 404", i+1, rec.Code)
			}
		}
		if rec := e.beginFrom(t, "carol", distinct(10)); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("begin past the global burst = %d, want 429", rec.Code)
		}
	})
	t.Run("finish_keyed_on_challenge_user", func(t *testing.T) {
		e := newSignInEnv(t, Limits{SignInPerMinute: 100000, SignInBurst: 100000})
		b := e.mustBegin(t, "alice")
		for i := range 9 {
			if rec := e.beginFrom(t, "alice", ""); rec.Code != http.StatusOK {
				t.Fatalf("begin %d = %d", i+2, rec.Code)
			}
		}
		// alice's bucket for this client is empty; the finish names no
		// user, its challenge does.
		rec := e.finish(finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b))), "")
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("finish with alice's bucket empty = %d %s, want 429", rec.Code, rec.Body)
		}
		if got := lastSignIn(t, e.log); got["user"] != "alice" || got["reason"] != reasonPerUser {
			t.Fatalf("logged %v", got)
		}
	})
	t.Run("username_limiter_bounded", func(t *testing.T) {
		e := newSignInEnv(t, Limits{SignInPerMinute: 100000, SignInBurst: 100000})
		if e.s.signInUserLimit.max != maxLimiterEntries || maxLimiterEntries != 10000 {
			t.Fatalf("per-username limiter cap %d, want %d (10 000)", e.s.signInUserLimit.max, maxLimiterEntries)
		}
		const smallCap = 40
		e.s.signInUserLimit.max = smallCap // the same map code; a small cap keeps the test fast
		for i := range 2 * smallCap {
			requireNoPasskey(t, "begin of an unknown name", e.beginFrom(t, "user"+strconv.Itoa(i), distinct(i)))
			if n := e.s.signInUserLimit.size(); n > smallCap {
				t.Fatalf("%d per-username entries after %d names, cap %d", n, i+1, smallCap)
			}
		}
		before := e.s.signInUserLimit.size()
		for _, name := range []string{"Alice", "a b", strings.Repeat("a", 65), "", "-alice", "alice\n"} {
			requireNoPasskey(t, "begin of "+strconv.Quote(name), e.beginFrom(t, name, ""))
			if got := lastSignIn(t, e.log); got["user"] != "" {
				t.Fatalf("an invalid name was logged as user %q", got["user"])
			}
		}
		if n := e.s.signInUserLimit.size(); n != before {
			t.Fatalf("invalid names changed the per-username map from %d to %d entries", before, n)
		}
	})
}

// TestSignInLog (signin_log_has_no_secrets, 02-10-F15): a sign-in, a
// refused finish, a begin 404, a 429 and a logout each log one line with
// event, user and reason, and no line holds the session ID, its SHA-256
// or a challenge.
func TestSignInLog(t *testing.T) {
	t.Run("signin_log_has_no_secrets", func(t *testing.T) {
		e := newSignInEnv(t, Limits{SignInPerMinute: 100000, SignInBurst: 100000})
		var secrets []string
		addChallenge := func(b signInBeginResponse) {
			secrets = append(secrets, b.PublicKey.Challenge, b.ChallengeID)
		}

		b := e.mustBegin(t, "alice")
		addChallenge(b)
		rec := e.finish(finishBodyFor(t, b.ChallengeID, e.alice.Assert(testRPID, testOrigin, challengeOf(t, b))), "")
		cookie := requireSetSession(t, rec)
		raw, _ := base64.RawURLEncoding.DecodeString(cookie)
		sum := sha256.Sum256(raw)
		secrets = append(secrets, cookie, hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:]),
			base64.RawStdEncoding.EncodeToString(sum[:]), base64.URLEncoding.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(sum[:]))

		b2 := e.mustBegin(t, "alice")
		addChallenge(b2)
		e.finish(finishBodyFor(t, b2.ChallengeID, e.bob.Assert(testRPID, testOrigin, challengeOf(t, b2))), "")
		e.beginFrom(t, "carol", "")
		for range 6 { // two begins and two finishes used 4 of alice's 10 tokens
			addChallenge(e.mustBegin(t, "alice"))
		}
		if rec := e.beginFrom(t, "alice", ""); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("begin past alice's limit = %d", rec.Code)
		}
		if rec := e.request(http.MethodPost, "/logout", "", "", cookie, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("logout = %d", rec.Code)
		}

		want := []struct{ event, reason, user string }{
			{eventSignInOK, reasonOK, "alice"},
			{eventSignInRefused, reasonCredentialUnbound, "alice"},
			{eventBeginRefused, reasonNoUsablePasskey, "carol"},
			{eventRateLimited, reasonPerUser, "alice"},
			{eventLogout, reasonOK, "alice"},
		}
		lines := signInLines(t, e.log)
		if len(lines) != len(want) {
			t.Fatalf("%d web sign-in lines, want %d:\n%s", len(lines), len(want), e.log)
		}
		for i, w := range want {
			l := lines[i]
			if l["event"] != w.event || l["reason"] != w.reason || l["user"] != w.user || l["client"] != "192.0.2.1" {
				t.Fatalf("line %d = %v, want event %s reason %s user %s client 192.0.2.1", i, l, w.event, w.reason, w.user)
			}
		}
		all := e.log.String()
		for _, s := range secrets {
			if s != "" && strings.Contains(all, s) {
				t.Fatalf("the log holds the secret %q:\n%s", s, all)
			}
		}
	})
}

// TestSignInNotAuthority: a web session never stands in for admin
// authentication (T-02-51).
func TestSignInNotAuthority(t *testing.T) {
	e := newSignInEnv(t, highSignInLimits)
	cookie := e.signIn(t, "alice", e.alice)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/admin/directory"},
		{http.MethodPost, "/api/v1/admin/directory"},
		{http.MethodPost, "/api/v1/admin/users"},
	} {
		rec := e.request(c.method, c.path, "{}", "", cookie, nil)
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != uniform401 {
			t.Fatalf("%s %s with a session = %d %s, want the uniform 401", c.method, c.path, rec.Code, rec.Body)
		}
	}
}
