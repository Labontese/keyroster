package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// The fixed answers of the login routes.
const (
	loginApprovalFailed = `{"error":"approval failed"}`
	loginNotRedeemable  = `{"error":"login not redeemable"}`
)

// loginPKCE is one CLI login's PKCE verifier, its S256 challenge and the
// loopback state.
type loginPKCE struct{ verifier, challenge, state string }

func newLoginPKCE(t *testing.T) loginPKCE {
	t.Helper()
	_, v, err := randomID(32)
	if err != nil {
		t.Fatal(err)
	}
	_, st, err := randomID(32)
	if err != nil {
		t.Fatal(err)
	}
	c := sha256.Sum256([]byte(v))
	return loginPKCE{verifier: v, challenge: base64.RawURLEncoding.EncodeToString(c[:]), state: st}
}

// loginRequest is a login request of user for role dev (principal
// role:dev, 1 h) with a fresh Ed25519 key, created at created.
func loginRequest(t *testing.T, user string, created time.Time) *wire.LoginIssueRequest {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	req := &wire.LoginIssueRequest{SubjectKey: k.Marshal(), Subject: user, Principals: []string{"role:dev"}, ValidForSeconds: 3600,
		CreatedAt: uint64(created.Unix())} //nolint:gosec // G115: a test time after 1970
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	return req
}

// beginBody is the begin body of req with p, method and port.
func beginBody(t *testing.T, req *wire.LoginIssueRequest, p loginPKCE, method string, port int) string {
	t.Helper()
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(loginBeginRequest{Request: b, CodeChallenge: p.challenge, CodeChallengeMethod: method, State: p.state, RedirectPort: port})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// loginRun is one login begun in a signInEnv.
type loginRun struct {
	req  *wire.LoginIssueRequest
	pkce loginPKCE
	id   string
	port int
}

// begin begins a login for req and requires 200.
func (e *signInEnv) beginLogin(t *testing.T, req *wire.LoginIssueRequest) *loginRun {
	t.Helper()
	l := &loginRun{req: req, pkce: newLoginPKCE(t), port: 49152}
	rec := e.request(http.MethodPost, loginBeginPath, beginBody(t, req, l.pkce, "S256", l.port), "", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin = %d %s\nlog:\n%s", rec.Code, rec.Body, e.log)
	}
	var ans loginBeginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
		t.Fatal(err)
	}
	if !loginIDRE.MatchString(ans.LoginID) || ans.ApprovalURL != testOrigin+"/login/"+ans.LoginID ||
		ans.ExpiresAt != int64(req.CreatedAt)+240 { //nolint:gosec // G115: a test time
		t.Fatalf("begin answer %+v", ans)
	}
	l.id = ans.LoginID
	return l
}

// assertionBody is the assertion route's body of a.
func assertionBody(t *testing.T, a webauthn.Assertion) string {
	t.Helper()
	body, err := json.Marshal(loginAssertionRequest{
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

// postAssertion posts a to l's assertion route.
func (e *signInEnv) postAssertion(t *testing.T, l *loginRun, a webauthn.Assertion) *httptest.ResponseRecorder {
	t.Helper()
	return e.request(http.MethodPost, loginAPIPrefix+l.id+"/assertion", assertionBody(t, a), "", "", nil)
}

// approve approves l with alice's passkey over the request digest and
// returns the code from the loopback redirect, after checking that the
// redirect is built only from the stored port and state.
func (e *signInEnv) approve(t *testing.T, l *loginRun) string {
	t.Helper()
	rec := e.postAssertion(t, l, e.alice.Assert(testRPID, testOrigin, l.req.Digest()))
	if rec.Code != http.StatusOK {
		t.Fatalf("assertion = %d %s\nlog:\n%s", rec.Code, rec.Body, e.log)
	}
	var ans struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ans); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(ans.Redirect)
	if err != nil || u.Scheme != "http" || u.Host != "127.0.0.1:49152" || u.Path != "/callback" || u.Query().Get("state") != l.pkce.state {
		t.Fatalf("redirect %q is not the loopback callback with the stored port and state", ans.Redirect)
	}
	code := u.Query().Get("code")
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(code); err != nil || len(raw) != 32 {
		t.Fatalf("code %q is not 32 bytes of base64url", code)
	}
	return code
}

// redeem posts code and verifier to l's redeem route from addr ("" for
// the default).
func (e *signInEnv) redeem(l *loginRun, code, verifier, addr string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(loginRedeemRequest{Code: code, CodeVerifier: verifier})
	return e.request(http.MethodPost, loginAPIPrefix+l.id+"/redeem", string(body), addr, "", nil)
}

// requireNotRedeemable fails unless rec is the uniform redeem 400.
func requireNotRedeemable(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest || strings.TrimSpace(rec.Body.String()) != loginNotRedeemable {
		t.Fatalf("%s = %d %s, want 400 %s", what, rec.Code, rec.Body, loginNotRedeemable)
	}
}

// requireRedeemed fails unless rec is a 200 carrying the fake's
// certificate and the custody header.
func requireRedeemed(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"certificate":"`+base64.StdEncoding.EncodeToString(testLoginCert)+`"}` {
		t.Fatalf("%s = %d %s, want 200 with the certificate", what, rec.Code, rec.Body)
	}
	if rec.Header().Get("Keyroster-Custody") == "" {
		t.Fatalf("%s: the 200 carries no custody header", what)
	}
}

// requireLastLogin fails unless the last "cli login" log line has event
// and reason.
func requireLastLogin(t *testing.T, e *signInEnv, event, reason string) {
	t.Helper()
	var last map[string]any
	for _, l := range e.log.Lines() {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		if m["msg"] == "cli login" {
			last = m
		}
	}
	if last == nil || last["event"] != event || last["reason"] != reason {
		t.Fatalf("last cli login line %v, want event %s reason %s", last, event, reason)
	}
}

// requireLoginCalls fails unless the fake signer's Login ran n times.
func requireLoginCalls(t *testing.T, e *signInEnv, n int) {
	t.Helper()
	if got := e.fake.count("Login"); got != n {
		t.Fatalf("signer Login calls = %d, want %d\nlog:\n%s", got, n, e.log)
	}
}

// loginStatus returns the stored status of login id.
func (e *signInEnv) loginStatus(t *testing.T, id string) string {
	t.Helper()
	var st string
	if err := e.openRaw(t).QueryRow(`SELECT status FROM login_sessions WHERE id = ?`, id).Scan(&st); err != nil {
		return "absent"
	}
	return st
}

// testLoginCert stands for the certificate the fake signer issues; the
// server forwards it without parsing.
var testLoginCert = []byte("certificate bytes")

func newLoginEnv(t *testing.T, lim Limits) *signInEnv {
	t.Helper()
	e := newSignInEnv(t, lim)
	e.fake.setLogin(&wire.IssueResponse{Cert: testLoginCert, Serial: 7}, nil)
	return e
}

// TestLoginOptions: the options of an active user with a bound passkey
// come from directory.Authorize; every other name gets the uniform 404.
func TestLoginOptions(t *testing.T) {
	e := newLoginEnv(t, highSignInLimits)
	rec := e.request(http.MethodGet, loginOptionsPath+"?user=alice", "", "", "", nil)
	if rec.Code != http.StatusOK || rec.Header().Get("Keyroster-Custody") == "" {
		t.Fatalf("options alice = %d %s", rec.Code, rec.Body)
	}
	var o loginOptionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	if o.User != "alice" || o.ServerTime != t0.Unix() || o.CAMaxTTLSeconds != 43200 || len(o.Roles) != 1 ||
		o.Roles[0].Name != "dev" || o.Roles[0].MaxTTLSeconds != 7200 || len(o.Roles[0].Principals) != 1 || o.Roles[0].Principals[0] != "role:dev" {
		t.Fatalf("options = %+v", o)
	}
	for _, name := range []string{"nobody", "Alice", "a%20b", ""} {
		requireNoPasskey(t, "options "+name, e.request(http.MethodGet, loginOptionsPath+"?user="+name, "", "", "", nil))
	}
	// bob holds no role: options answer with no roles; the CLI says so.
	rec = e.request(http.MethodGet, loginOptionsPath+"?user=bob", "", "", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"roles":[]`) {
		t.Fatalf("options bob = %d %s", rec.Code, rec.Body)
	}
}

// TestLoginBegin: begin stores a pending login only for a well-formed
// request without evidence, of an active user, within ±120 s of the
// server's clock, with PKCE S256, a 43-character challenge and state and
// a port of 1024 to 65535.
func TestLoginBegin(t *testing.T) {
	e := newLoginEnv(t, highSignInLimits)
	ok := func(t *testing.T) (*wire.LoginIssueRequest, loginPKCE) {
		return loginRequest(t, "alice", t0), newLoginPKCE(t)
	}
	post := func(body string) *httptest.ResponseRecorder {
		return e.request(http.MethodPost, loginBeginPath, body, "", "", nil)
	}
	requireBad := func(t *testing.T, what string, rec *httptest.ResponseRecorder) {
		t.Helper()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s = %d %s, want 400", what, rec.Code, rec.Body)
		}
	}
	t.Run("accepted", func(t *testing.T) {
		req, _ := ok(t)
		e.beginLogin(t, req)
	})
	t.Run("unknown_user_uniform_404", func(t *testing.T) {
		req, p := ok(t)
		req.Subject = "mallory"
		requireNoPasskey(t, "begin mallory", post(beginBody(t, req, p, "S256", 50000)))
	})
	t.Run("redirect_port_80", func(t *testing.T) {
		req, p := ok(t)
		requireBad(t, "port 80", post(beginBody(t, req, p, "S256", 80)))
	})
	t.Run("redirect_port_70000", func(t *testing.T) {
		req, p := ok(t)
		requireBad(t, "port 70000", post(beginBody(t, req, p, "S256", 70000)))
	})
	t.Run("code_challenge_42", func(t *testing.T) {
		req, p := ok(t)
		p.challenge = p.challenge[:42]
		requireBad(t, "challenge of 42", post(beginBody(t, req, p, "S256", 50000)))
	})
	t.Run("method_plain", func(t *testing.T) {
		req, p := ok(t)
		requireBad(t, "method plain", post(beginBody(t, req, p, "plain", 50000)))
	})
	t.Run("bad_state_refused_nothing_stored", func(t *testing.T) {
		// The state is concatenated into the loopback redirect unescaped,
		// so its format check is the only thing keeping '&', '#', '=' or
		// '+' out of that URL.
		rows := func() int {
			var n int
			if err := e.openRaw(t).QueryRow(`SELECT count(*) FROM login_sessions`).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		for name, mutate := range map[string]func(string) string{
			"state_42":        func(s string) string { return s[:42] },
			"state_ampersand": func(s string) string { return s[:20] + "&" + s[21:] },
			"state_plus":      func(s string) string { return s[:20] + "+" + s[21:] },
			"state_hash":      func(s string) string { return s[:20] + "#" + s[21:] },
			"state_padding":   func(s string) string { return s[:42] + "=" },
		} {
			req, p := ok(t)
			p.state = mutate(p.state)
			before := rows()
			rec := post(beginBody(t, req, p, "S256", 50000))
			requireBad(t, name, rec)
			if strings.TrimSpace(rec.Body.String()) != `{"error":"malformed request"}` {
				t.Fatalf("%s answered %s, want the malformed-request refusal", name, rec.Body)
			}
			if after := rows(); after != before {
				t.Fatalf("%s stored a login (%d rows, was %d)", name, after, before)
			}
		}
	})
	t.Run("created_121s_old_refused", func(t *testing.T) {
		req := loginRequest(t, "alice", t0.Add(-121*time.Second))
		rec := post(beginBody(t, req, newLoginPKCE(t), "S256", 50000))
		requireBad(t, "121 s old", rec)
		if !strings.Contains(rec.Body.String(), "120 s") {
			t.Fatalf("skew refusal %s does not name the window", rec.Body)
		}
		e.beginLogin(t, loginRequest(t, "alice", t0.Add(-119*time.Second))) // control
	})
	t.Run("evidence_refused", func(t *testing.T) {
		req, p := ok(t)
		req.Evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: []byte("x")}}
		requireBad(t, "evidence", post(beginBody(t, req, p, "S256", 50000)))
	})
	t.Run("malformed_request_bytes", func(t *testing.T) {
		_, p := ok(t)
		body, _ := json.Marshal(loginBeginRequest{Request: []byte("not a request"), CodeChallenge: p.challenge, CodeChallengeMethod: "S256", State: p.state, RedirectPort: 50000})
		requireBad(t, "malformed", post(string(body)))
	})
}

// approvalPageOf GETs l's approval page.
func (e *signInEnv) approvalPageOf(l *loginRun) *httptest.ResponseRecorder {
	return e.request(http.MethodGet, "/login/"+l.id, "", "", "", nil)
}

var pageOptionsRE = regexp.MustCompile(`data-options="([^"]*)"`)

// TestLoginApproval: the approval page shows the fingerprint of the key in
// the stored request bytes and carries options whose challenge is their
// digest; every refused assertion gets the same 401 and no code.
func TestLoginApproval(t *testing.T) {
	t.Run("page_shows_stored_fingerprint", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		req := loginRequest(t, "alice", t0)
		l := e.beginLogin(t, req)
		rec := e.approvalPageOf(l)
		if rec.Code != http.StatusOK {
			t.Fatalf("page = %d %s", rec.Code, rec.Body)
		}
		k, err := ssh.ParsePublicKey(req.SubjectKey)
		if err != nil {
			t.Fatal(err)
		}
		text := html.UnescapeString(rec.Body.String())
		for _, want := range []string{ssh.FingerprintSHA256(k), "Approve only if your terminal shows exactly this fingerprint", "role:dev", "all your roles", `role="alert"`} {
			if !strings.Contains(text, want) {
				t.Fatalf("the page lacks %q:\n%s", want, text)
			}
		}
		m := pageOptionsRE.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("no data-options:\n%s", rec.Body)
		}
		var o loginPageOptions
		if err := json.Unmarshal([]byte(html.UnescapeString(m[1])), &o); err != nil {
			t.Fatal(err)
		}
		d := req.Digest()
		if o.Challenge != base64.RawURLEncoding.EncodeToString(d[:]) || o.RPID != testRPID || o.UserVerification != "required" || len(o.AllowCredentials) != 2 {
			t.Fatalf("page options %+v do not carry the request digest and alice's credentials", o)
		}
	})
	t.Run("custody_banner_on_approval_page", func(t *testing.T) {
		// KEY-06: the software-custody banner is on the approval page, and
		// the custody header on the JSON answers the CLI reads.
		e := newLoginEnv(t, highSignInLimits)
		e.fake.setStatus(testStatus(t, "software", 0), nil)
		banner := `<div class="kr-banner" role="alert">` + custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"}) + `</div>`
		l := e.beginLogin(t, loginRequest(t, "alice", t0))
		if rec := e.approvalPageOf(l); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), banner) {
			t.Fatalf("approval page = %d without the banner:\n%s", rec.Code, rec.Body)
		}
		if rec := e.request(http.MethodGet, loginOptionsPath+"?user=alice", "", "", "", nil); !strings.Contains(rec.Header().Get("Keyroster-Custody"), "user=software") {
			t.Fatalf("options custody header = %q", rec.Header().Get("Keyroster-Custody"))
		}
	})
	t.Run("expired_or_redeemed_page_refused", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l := e.beginLogin(t, loginRequest(t, "alice", t0))
		code := e.approve(t, l)
		if rec := e.approvalPageOf(l); rec.Code != http.StatusNotFound {
			t.Fatalf("page of an approved login = %d", rec.Code)
		}
		requireRedeemed(t, "redeem", e.redeem(l, code, l.pkce.verifier, ""))
		if rec := e.approvalPageOf(l); rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "Run keyroster login again") {
			t.Fatalf("page of a redeemed login = %d %s", rec.Code, rec.Body)
		}
		l2 := e.beginLogin(t, loginRequest(t, "alice", e.clock.Now()))
		e.advance(241 * time.Second)
		if rec := e.approvalPageOf(l2); rec.Code != http.StatusNotFound {
			t.Fatalf("page of an expired login = %d", rec.Code)
		}
	})
	t.Run("assertion_refusal_body_uniform", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		var bodies []string
		for _, c := range []struct {
			name, sentinel string
			assert         func(l *loginRun) webauthn.Assertion
		}{
			{"wrong_challenge", "assertion_challenge", func(*loginRun) webauthn.Assertion {
				return e.alice.Assert(testRPID, testOrigin, [32]byte{1})
			}},
			{"other_users_credential", "credential_not_bound", func(l *loginRun) webauthn.Assertion {
				return e.bob.Assert(testRPID, testOrigin, l.req.Digest())
			}},
			{"uv_clear", "assertion_user_verification", func(l *loginRun) webauthn.Assertion {
				return e.alice.Assert(testRPID, testOrigin, l.req.Digest(), webauthntest.WithFlags(0x01))
			}},
			{"wrong_origin", "assertion_origin", func(l *loginRun) webauthn.Assertion {
				return e.alice.Assert(testRPID, "https://evil.example", l.req.Digest())
			}},
		} {
			l := e.beginLogin(t, loginRequest(t, "alice", e.clock.Now()))
			rec := e.postAssertion(t, l, c.assert(l))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s = %d %s, want 401", c.name, rec.Code, rec.Body)
			}
			if st := e.loginStatus(t, l.id); st != serverdb.LoginPending {
				t.Fatalf("%s left the login %s, want pending (no code issued)", c.name, st)
			}
			if strings.Contains(rec.Body.String(), c.sentinel) || !strings.Contains(e.log.String(), c.sentinel) {
				t.Fatalf("%s: the sentinel %s must be in the log only; body %s", c.name, c.sentinel, rec.Body)
			}
			bodies = append(bodies, rec.Body.String())
		}
		l := e.beginLogin(t, loginRequest(t, "alice", e.clock.Now()))
		e.advance(241 * time.Second)
		rec := e.postAssertion(t, l, e.alice.Assert(testRPID, testOrigin, l.req.Digest()))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expired = %d %s, want 401", rec.Code, rec.Body)
		}
		bodies = append(bodies, rec.Body.String())
		for i, b := range bodies {
			if strings.TrimSpace(b) != loginApprovalFailed {
				t.Fatalf("refusal %d body %q, want exactly %s", i, b, loginApprovalFailed)
			}
		}
		requireLoginCalls(t, e, 0)
	})
	t.Run("authenticator_data_refusal_logs_length_and_flags", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l := e.beginLogin(t, loginRequest(t, "alice", t0))
		a := e.alice.Assert(testRPID, testOrigin, l.req.Digest())
		a.AuthenticatorData = append(a.AuthenticatorData, 0xAA) // 38 bytes, no extension flag
		rec := e.postAssertion(t, l, a)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("assertion = %d", rec.Code)
		}
		if !strings.Contains(e.log.String(), `"authenticator_data_len":38`) || !strings.Contains(e.log.String(), `"authenticator_flags":"05"`) {
			t.Fatalf("the log lacks the authData length and flags:\n%s", e.log)
		}
	})
	t.Run("assertion_after_deadline_refused", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		late := e.beginLogin(t, loginRequest(t, "alice", t0))
		inTime := e.beginLogin(t, loginRequest(t, "alice", t0))
		e.clock.set(t0.Add(241 * time.Second))
		if rec := e.postAssertion(t, late, e.alice.Assert(testRPID, testOrigin, late.req.Digest())); rec.Code != http.StatusUnauthorized {
			t.Fatalf("assertion at +241 s = %d %s, want 401", rec.Code, rec.Body)
		}
		requireLastLogin(t, e, eventLoginApprove, reasonLoginExpired)
		if st := e.loginStatus(t, late.id); st != serverdb.LoginPending {
			t.Fatalf("the late login is %s, want pending (no code)", st)
		}
		e.clock.set(t0.Add(239 * time.Second))
		e.approve(t, inTime) // control
	})
	t.Run("code_capped_by_signer_window", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		a := e.beginLogin(t, loginRequest(t, "alice", t0))
		b := e.beginLogin(t, loginRequest(t, "alice", t0))
		e.clock.set(t0.Add(230 * time.Second))
		codeA, codeB := e.approve(t, a), e.approve(t, b)
		var exp int64
		if err := e.openRaw(t).QueryRow(`SELECT code_expires_us FROM login_sessions WHERE id = ?`, a.id).Scan(&exp); err != nil {
			t.Fatal(err)
		}
		if exp != t0.Add(290*time.Second).UnixMicro() {
			t.Fatalf("code_expires = %v, want CreatedAt + 290 s", time.UnixMicro(exp).Sub(t0))
		}
		e.clock.set(t0.Add(291 * time.Second))
		requireNotRedeemable(t, "redeem at +291 s", e.redeem(a, codeA, a.pkce.verifier, ""))
		requireLoginCalls(t, e, 0)
		// Control: past the session's own expiry (+240 s) an approved login
		// still redeems while its code is valid.
		e.clock.set(t0.Add(289 * time.Second))
		requireRedeemed(t, "redeem at +289 s", e.redeem(b, codeB, b.pkce.verifier, ""))
		requireLoginCalls(t, e, 1)
	})
}

// TestLoginRedeem: only the matching code and verifier of an approved,
// unexpired login reach the signer, once; nothing else burns the code.
// stallSigner wraps the test signer for redeem_status_stall: its Status
// moves the test clock forward by stall before it answers, as a slow
// currentStatus refresh would, and its Login records how much time its
// context had left on the real clock when it was called.
type stallSigner struct {
	signerAPI
	clock *testClock
	stall time.Duration

	mu          sync.Mutex
	statusCalls int
	loginLeft   time.Duration // time.Until(deadline) at the Login call
	hasDeadline bool
}

func (s *stallSigner) Status(ctx context.Context) (*wire.StatusResponse, error) {
	s.mu.Lock()
	s.statusCalls++
	s.mu.Unlock()
	s.clock.set(s.clock.Now().Add(s.stall))
	return s.signerAPI.Status(ctx)
}

func (s *stallSigner) Login(ctx context.Context, req *wire.LoginIssueRequest) (*wire.IssueResponse, error) {
	dl, ok := ctx.Deadline()
	s.mu.Lock()
	s.loginLeft, s.hasDeadline = time.Until(dl), ok
	s.mu.Unlock()
	return s.signerAPI.Login(ctx, req)
}

func TestLoginRedeem(t *testing.T) {
	approved := func(t *testing.T, e *signInEnv) (*loginRun, string) {
		t.Helper()
		l := e.beginLogin(t, loginRequest(t, "alice", e.clock.Now()))
		return l, e.approve(t, l)
	}
	t.Run("redeem_status_stall", func(t *testing.T) {
		// A login begun at t0 (its CreatedAt) and approved at t0+200 s has
		// a code valid to t0+290 s. The redeem reads the signer status,
		// which takes 3 s here; the clock is read again after it, and the
		// signer call gets a deadline no later than CreatedAt + 295 s
		// (03-02, C-IN-01). A code past its window after the stall is
		// refused before RedeemLogin, so it is not burnt.
		setup := func(t *testing.T, redeemAt time.Duration) (*signInEnv, *stallSigner, *loginRun, string) {
			t.Helper()
			e := newLoginEnv(t, highSignInLimits)
			l := e.beginLogin(t, loginRequest(t, "alice", t0))
			e.clock.set(t0.Add(200 * time.Second))
			code := e.approve(t, l)
			// Far past statusTTL, so the redeem's currentStatus refreshes.
			e.clock.set(t0.Add(redeemAt))
			sg := &stallSigner{signerAPI: e.fake, clock: e.clock, stall: 3 * time.Second}
			e.s.signer = sg
			return e, sg, l, code
		}
		requireStalled := func(t *testing.T, sg *stallSigner) {
			t.Helper()
			sg.mu.Lock()
			defer sg.mu.Unlock()
			if sg.statusCalls != 1 {
				t.Fatalf("Status calls during the redeem = %d, want 1 (the stall did not happen)", sg.statusCalls)
			}
		}
		t.Run("expired_after_stall_not_burnt", func(t *testing.T) {
			// Redeemed at +288 s, inside the code's window; after the 3 s
			// stall it is +291 s, past the code's +290 s.
			e, sg, l, code := setup(t, 288*time.Second)
			requireNotRedeemable(t, "redeem after the stall", e.redeem(l, code, l.pkce.verifier, ""))
			requireStalled(t, sg)
			requireLastLogin(t, e, eventLoginRedeem, reasonLoginExpired)
			requireLoginCalls(t, e, 0)
			if st := e.loginStatus(t, l.id); st != serverdb.LoginApproved {
				t.Fatalf("status after the refused redeem = %s, want %s (not burnt)", st, serverdb.LoginApproved)
			}
		})
		t.Run("inside_window_deadline", func(t *testing.T) {
			// Redeemed at +285 s, +288 s after the stall: the signer gets
			// a context with at most the 7 s left to CreatedAt + 295 s.
			e, sg, l, code := setup(t, 285*time.Second)
			requireRedeemed(t, "redeem inside the window", e.redeem(l, code, l.pkce.verifier, ""))
			requireStalled(t, sg)
			requireLoginCalls(t, e, 1)
			sg.mu.Lock()
			left, ok := sg.loginLeft, sg.hasDeadline
			sg.mu.Unlock()
			if !ok || left > 7*time.Second || left < 6*time.Second {
				t.Fatalf("the signer call had %v left (deadline set: %v), want at most 7 s, the time to CreatedAt + 295 s", left, ok)
			}
		})
		t.Run("deadline_passed_not_burnt", func(t *testing.T) {
			// A code stored as valid to +299 s (no handler writes one past
			// +290 s; this stands for any future change that would) and
			// redeemed at +294 s, +297 s after the stall: past CreatedAt +
			// 295 s, so it is refused unburnt although the code is valid.
			e, sg, l, code := setup(t, 294*time.Second)
			if _, err := e.openRaw(t).Exec(`UPDATE login_sessions SET code_expires_us = ? WHERE id = ?`, t0.Add(299*time.Second).UnixMicro(), l.id); err != nil {
				t.Fatal(err)
			}
			requireNotRedeemable(t, "redeem past the signer window", e.redeem(l, code, l.pkce.verifier, ""))
			requireStalled(t, sg)
			requireLastLogin(t, e, eventLoginRedeem, reasonLoginExpired)
			requireLoginCalls(t, e, 0)
			if st := e.loginStatus(t, l.id); st != serverdb.LoginApproved {
				t.Fatalf("status after the refused redeem = %s, want %s (not burnt)", st, serverdb.LoginApproved)
			}
		})
	})
	t.Run("redeems_with_stored_assertion", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		requireRedeemed(t, "redeem", e.redeem(l, code, l.pkce.verifier, ""))
		requireLoginCalls(t, e, 1)
		got := e.fake.lastLoginRequest()
		if got == nil || got.RequestID != l.req.RequestID || len(got.Evidence) != 1 || got.Evidence[0].Type != wire.EvidenceWebAuthnAssertion {
			t.Fatalf("the signer got %+v, want the stored request with one assertion", got)
		}
		if _, err := wire.ParseWebAuthnAssertion(got.Evidence[0].Blob); err != nil {
			t.Fatalf("evidence blob: %v", err)
		}
		if st := e.loginStatus(t, l.id); st != serverdb.LoginRedeemed {
			t.Fatalf("status after redeem = %s", st)
		}
	})
	t.Run("redeem_before_approval", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l := e.beginLogin(t, loginRequest(t, "alice", t0))
		_, fakeCode, _ := randomID(32)
		requireNotRedeemable(t, "before approval", e.redeem(l, fakeCode, l.pkce.verifier, ""))
		requireLoginCalls(t, e, 0)
	})
	t.Run("wrong_code", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		_, other, _ := randomID(32)
		requireNotRedeemable(t, "wrong code", e.redeem(l, other, l.pkce.verifier, ""))
		requireLoginCalls(t, e, 0)
		requireRedeemed(t, "control", e.redeem(l, code, l.pkce.verifier, ""))
	})
	t.Run("wrong_verifier", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		requireNotRedeemable(t, "wrong verifier", e.redeem(l, code, newLoginPKCE(t).verifier, ""))
		requireLoginCalls(t, e, 0)
		if st := e.loginStatus(t, l.id); st != serverdb.LoginApproved {
			t.Fatalf("a wrong verifier left the login %s, want approved (code not burnt)", st)
		}
		requireRedeemed(t, "correct verifier afterwards", e.redeem(l, code, l.pkce.verifier, ""))
		requireLoginCalls(t, e, 1)
	})
	t.Run("bad_verifier_format", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		v := l.pkce.verifier
		for _, bad := range []string{v[:42], v[:43] + "=", v[:20] + "+" + v[21:]} {
			requireNotRedeemable(t, "verifier "+bad, e.redeem(l, code, bad, ""))
			// Refused on its form, before any database access (02-12-F14).
			requireLastLogin(t, e, eventLoginRedeem, reasonLoginVerFmt)
			if st := e.loginStatus(t, l.id); st != serverdb.LoginApproved {
				t.Fatalf("verifier %q left the login %s", bad, st)
			}
		}
		requireLoginCalls(t, e, 0)
		requireRedeemed(t, "the code still redeems", e.redeem(l, code, v, ""))
	})
	t.Run("code_reuse", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		requireRedeemed(t, "first", e.redeem(l, code, l.pkce.verifier, ""))
		requireNotRedeemable(t, "second", e.redeem(l, code, l.pkce.verifier, ""))
		requireLoginCalls(t, e, 1)
	})
	t.Run("code_expired", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		e.advance(121 * time.Second)
		requireNotRedeemable(t, "after 121 s", e.redeem(l, code, l.pkce.verifier, ""))
		requireLastLogin(t, e, eventLoginRedeem, reasonLoginExpired)
		requireLoginCalls(t, e, 0)
	})
	t.Run("cross_login_code", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		a, codeA := approved(t, e)
		b, _ := approved(t, e)
		requireNotRedeemable(t, "A's code on B with B's verifier", e.redeem(b, codeA, b.pkce.verifier, ""))
		requireNotRedeemable(t, "A's code on B with A's verifier", e.redeem(b, codeA, a.pkce.verifier, ""))
		requireLoginCalls(t, e, 0)
		requireRedeemed(t, "A's own", e.redeem(a, codeA, a.pkce.verifier, ""))
	})
	t.Run("concurrent_redeem_once", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		var wg sync.WaitGroup
		recs := make([]*httptest.ResponseRecorder, 2)
		for i := range recs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				recs[i] = e.redeem(l, code, l.pkce.verifier, "")
			}()
		}
		wg.Wait()
		ok, refused := 0, 0
		for _, r := range recs {
			switch {
			case r.Code == http.StatusOK:
				ok++
			case r.Code == http.StatusBadRequest && strings.TrimSpace(r.Body.String()) == loginNotRedeemable:
				refused++
			}
		}
		if ok != 1 || refused != 1 {
			t.Fatalf("concurrent redeems: %d ok, %d refused, want 1 and 1", ok, refused)
		}
		requireLoginCalls(t, e, 1)
	})
	t.Run("signer_not_called_on_refusal", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		pending := e.beginLogin(t, loginRequest(t, "alice", t0))
		l, code := approved(t, e)
		_, other, _ := randomID(32)
		requireNotRedeemable(t, "pending", e.redeem(pending, code, pending.pkce.verifier, ""))
		requireNotRedeemable(t, "wrong code", e.redeem(l, other, l.pkce.verifier, ""))
		requireNotRedeemable(t, "wrong verifier", e.redeem(l, code, pending.pkce.verifier, ""))
		requireNotRedeemable(t, "malformed body", e.request(http.MethodPost, loginAPIPrefix+l.id+"/redeem", "{", "", "", nil))
		requireNotRedeemable(t, "bad id", e.request(http.MethodPost, loginAPIPrefix+"XYZ/redeem", `{}`, "", "", nil))
		requireLoginCalls(t, e, 0)
	})
	t.Run("signer_refusal_is_403_with_detail", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		e.fake.setLoginRefused("principals_mismatch")
		l, code := approved(t, e)
		rec := e.redeem(l, code, l.pkce.verifier, "")
		if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != `{"error":"principals_mismatch"}` {
			t.Fatalf("refused redeem = %d %s, want 403 with the detail", rec.Code, rec.Body)
		}
	})
	t.Run("signer_error_is_uniform_400", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		e.fake.setLogin(nil, errors.New("signerclient: connect: no such file"))
		l, code := approved(t, e)
		requireNotRedeemable(t, "signer connection error", e.redeem(l, code, l.pkce.verifier, ""))
	})
	t.Run("signer_unavailable_keeps_code", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		e.fake.setStatus(nil, errors.New("down"))
		e.advance(6 * time.Second)
		if rec := e.redeem(l, code, l.pkce.verifier, ""); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("redeem during an outage = %d %s, want 503", rec.Code, rec.Body)
		}
		if st := e.loginStatus(t, l.id); st != serverdb.LoginApproved {
			t.Fatalf("an outage burnt the code: status %s", st)
		}
		requireLoginCalls(t, e, 0)
	})
	t.Run("log_has_no_secrets", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		l, code := approved(t, e)
		requireRedeemed(t, "redeem", e.redeem(l, code, l.pkce.verifier, ""))
		for _, secret := range []string{code, l.pkce.verifier, l.pkce.state} {
			if strings.Contains(e.log.String(), secret) {
				t.Fatalf("the log holds a code, verifier or state:\n%s", e.log)
			}
		}
	})
	t.Run("create_login_reaps_expired", func(t *testing.T) {
		e := newLoginEnv(t, highSignInLimits)
		stale := e.beginLogin(t, loginRequest(t, "alice", t0)) // pending, expires at +240 s
		done, doneCode := approved(t, e)                       // redeemed below
		kept := e.beginLogin(t, loginRequest(t, "alice", t0))  // approved at +200 s, code to +290 s
		requireRedeemed(t, "redeem", e.redeem(done, doneCode, done.pkce.verifier, ""))
		e.clock.set(t0.Add(200 * time.Second))
		keptCode := e.approve(t, kept)
		e.clock.set(t0.Add(250 * time.Second))
		e.beginLogin(t, loginRequest(t, "alice", e.clock.Now())) // the next CreateLogin reaps
		for _, c := range []struct {
			id, want string
		}{{stale.id, "absent"}, {done.id, "absent"}, {kept.id, serverdb.LoginApproved}} {
			if st := e.loginStatus(t, c.id); st != c.want {
				t.Fatalf("after the reap login %s is %s, want %s", c.id, st, c.want)
			}
		}
		requireRedeemed(t, "the kept login still redeems", e.redeem(kept, keptCode, kept.pkce.verifier, ""))
	})
}

// TestLoginLimits: the login routes' per-user limit is keyed on the user
// and the client together (02-10 pre-merge review, owner decision G1), so
// one client draining a user's bucket does not refuse that user's login
// from another client.
func TestLoginLimits(t *testing.T) {
	e := newLoginEnv(t, Limits{SignInPerMinute: 1000, SignInBurst: 1000, SignInUserPerMinute: 2, SignInUserBurst: 2})
	options := func(addr string) int {
		return e.request(http.MethodGet, loginOptionsPath+"?user=alice", "", addr, "", nil).Code
	}
	t.Run("other_client_not_locked_out", func(t *testing.T) {
		for range 2 {
			if code := options("203.0.113.9:1234"); code != http.StatusOK {
				t.Fatalf("attacker's options within the burst = %d", code)
			}
		}
		if code := options("203.0.113.9:1234"); code != http.StatusTooManyRequests {
			t.Fatalf("attacker's third options = %d, want 429", code)
		}
		if code := options("198.51.100.7:1234"); code != http.StatusOK {
			t.Fatalf("alice's options from another client = %d, want 200", code)
		}
		if !strings.Contains(e.log.String(), `"reason":"per_user"`) {
			t.Fatalf("no per_user rate-limit line:\n%s", e.log)
		}
	})
	t.Run("per_client_charged_once", func(t *testing.T) {
		// The default per-client limit (burst 10) with a high per-user
		// limit: ten begins from one client pass and the eleventh is
		// refused, so a begin takes one per-client token, not two.
		e := newLoginEnv(t, Limits{SignInUserPerMinute: 100000, SignInUserBurst: 100000})
		for i := range 11 {
			req := loginRequest(t, "alice", e.clock.Now())
			rec := e.request(http.MethodPost, loginBeginPath, beginBody(t, req, newLoginPKCE(t), "S256", 50000), "203.0.113.20:1234", "", nil)
			want := http.StatusOK
			if i == 10 {
				want = http.StatusTooManyRequests
			}
			if rec.Code != want {
				t.Fatalf("begin #%d = %d %s, want %d", i+1, rec.Code, rec.Body, want)
			}
		}
	})
	t.Run("client_buckets_per_route", func(t *testing.T) {
		// Ten options drain one client's options bucket (burst 10); its
		// begin still passes, on the begin bucket.
		e := newLoginEnv(t, Limits{SignInUserPerMinute: 100000, SignInUserBurst: 100000})
		for i := range 11 {
			want := http.StatusOK
			if i == 10 {
				want = http.StatusTooManyRequests
			}
			if rec := e.request(http.MethodGet, loginOptionsPath+"?user=alice", "", "203.0.113.30:1234", "", nil); rec.Code != want {
				t.Fatalf("options #%d = %d, want %d", i+1, rec.Code, want)
			}
		}
		req := loginRequest(t, "alice", e.clock.Now())
		if rec := e.request(http.MethodPost, loginBeginPath, beginBody(t, req, newLoginPKCE(t), "S256", 50000), "203.0.113.30:1234", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("begin after drained options = %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("junk_on_every_route_leaves_others_open", func(t *testing.T) {
		// Two addresses spend their whole per-client burst on each of the
		// five routes with junk; a third client's login still passes,
		// because each route's global backstop is sized for that route
		// alone (02-12 pre-merge review).
		e := newLoginEnv(t, Limits{SignInUserPerMinute: 100000, SignInUserBurst: 100000})
		zeros := strings.Repeat("0", 32)
		junk := []struct{ method, path string }{
			{http.MethodGet, loginOptionsPath + "?user=nobody"},
			{http.MethodPost, loginBeginPath},
			{http.MethodGet, loginPagePrefix + zeros},
			{http.MethodPost, loginAPIPrefix + zeros + "/assertion"},
			{http.MethodPost, loginAPIPrefix + zeros + "/redeem"},
		}
		for _, addr := range []string{"203.0.113.41:1234", "203.0.113.42:1234"} {
			for _, j := range junk {
				for i := range 10 {
					if rec := e.request(j.method, j.path, "", addr, "", nil); rec.Code == http.StatusTooManyRequests {
						t.Fatalf("%s %s #%d from %s = 429 within its burst", j.method, j.path, i+1, addr)
					}
				}
			}
		}
		if rec := e.request(http.MethodGet, loginOptionsPath+"?user=alice", "", "198.51.100.43:1234", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("a third client's options = %d %s, want 200\nlog:\n%s", rec.Code, rec.Body, e.log)
		}
		req := loginRequest(t, "alice", e.clock.Now())
		if rec := e.request(http.MethodPost, loginBeginPath, beginBody(t, req, newLoginPKCE(t), "S256", 50000), "198.51.100.43:1234", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("a third client's begin = %d %s, want 200", rec.Code, rec.Body)
		}
	})
	t.Run("route_backstop_applies_per_route", func(t *testing.T) {
		// Ten addresses drain the options route's global backstop (burst
		// 100): an eleventh address's options is refused, while a begin
		// from it passes on the begin route's own backstop.
		e := newLoginEnv(t, Limits{SignInUserPerMinute: 100000, SignInUserBurst: 100000})
		for a := range 10 {
			addr := "203.0.113." + strconv.Itoa(50+a) + ":1234"
			for i := range 10 {
				if rec := e.request(http.MethodGet, loginOptionsPath+"?user=nobody", "", addr, "", nil); rec.Code == http.StatusTooManyRequests {
					t.Fatalf("options #%d from %s = 429 within its burst", i+1, addr)
				}
			}
		}
		if rec := e.request(http.MethodGet, loginOptionsPath+"?user=alice", "", "198.51.100.60:1234", "", nil); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("options past the route's backstop = %d, want 429", rec.Code)
		}
		req := loginRequest(t, "alice", e.clock.Now())
		if rec := e.request(http.MethodPost, loginBeginPath, beginBody(t, req, newLoginPKCE(t), "S256", 50000), "198.51.100.60:1234", "", nil); rec.Code != http.StatusOK {
			t.Fatalf("begin while the options backstop is drained = %d %s, want 200", rec.Code, rec.Body)
		}
	})
	t.Run("routes_have_own_buckets", func(t *testing.T) {
		// The drained options bucket does not refuse a begin.
		req := loginRequest(t, "alice", e.clock.Now())
		rec := e.request(http.MethodPost, loginBeginPath, beginBody(t, req, newLoginPKCE(t), "S256", 50000), "203.0.113.9:1234", "", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("begin after drained options = %d %s", rec.Code, rec.Body)
		}
	})
}
