//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// sessionCookieName is the web session cookie keyroster-server sets.
const sessionCookieName = "__Host-keyroster-session"

// webClient is a browser stand-in for env: one HTTP client that trusts
// only the test root, dials 127.0.0.1, keeps cookies in a jar and never
// follows a redirect, so a test sees every 303 itself.
type webClient struct {
	env *serverEnv
	c   *http.Client
}

func newWebClient(t *testing.T, env *serverEnv) *webClient {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(env.Port))
	tr := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: env.CA.pool(), ServerName: serverRPID},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &webClient{env: env, c: &http.Client{
		Transport:     tr,
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// do sends method path with body (nil: none) and headers hdr, the same
// origin's Origin header on every POST, as a browser sends it.
func (w *webClient) do(t *testing.T, method, path string, body []byte, hdr map[string]string) *response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, w.env.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", w.env.URL)
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := w.c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v\nserver log:\n%s", method, path, err, w.env.Stderr.String())
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return &response{code: resp.StatusCode, header: resp.Header, body: string(b)}
}

// signInBegin is the begin answer's shape.
type signInBegin struct {
	ChallengeID string `json:"challenge_id"`
	PublicKey   struct {
		Challenge        string `json:"challenge"`
		AllowCredentials []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"allowCredentials"`
		RPID             string `json:"rpId"`
		UserVerification string `json:"userVerification"`
		Timeout          int    `json:"timeout"`
	} `json:"publicKey"`
}

// begin starts a sign-in for user and returns the answer.
func (w *webClient) begin(t *testing.T, user string) *response {
	t.Helper()
	body, err := json.Marshal(map[string]string{"user": user})
	if err != nil {
		t.Fatal(err)
	}
	return w.do(t, http.MethodPost, "/api/v1/web/login/begin", body, nil)
}

// signIn runs the whole sign-in of user with auth: begin, an assertion
// over the server's challenge from the policy origin, finish. It returns
// the finish answer.
func (w *webClient) signIn(t *testing.T, user string, auth *webauthntest.Authenticator) *response {
	t.Helper()
	b := w.begin(t, user)
	if b.code != http.StatusOK {
		t.Fatalf("begin %s = %d %s\nserver log:\n%s", user, b.code, b.body, w.env.Stderr.String())
	}
	var opts signInBegin
	if err := json.Unmarshal([]byte(b.body), &opts); err != nil {
		t.Fatal(err)
	}
	cred := auth.Credential()
	if opts.PublicKey.RPID != serverRPID || opts.PublicKey.UserVerification != "required" || len(opts.PublicKey.AllowCredentials) != 1 ||
		opts.PublicKey.AllowCredentials[0].ID != base64.RawURLEncoding.EncodeToString(cred.ID) || opts.PublicKey.AllowCredentials[0].Type != "public-key" {
		t.Fatalf("begin %s options = %+v, want rpId %s, UV required and exactly the bound credential", user, opts.PublicKey, serverRPID)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(opts.PublicKey.Challenge)
	if err != nil || len(raw) != 32 {
		t.Fatalf("begin challenge %q is not 32 bytes of base64url: %v", opts.PublicKey.Challenge, err)
	}
	a := auth.Assert(serverRPID, w.env.URL, [32]byte(raw))
	body, err := json.Marshal(map[string]string{
		"challenge_id":       opts.ChallengeID,
		"credential_id":      base64.RawURLEncoding.EncodeToString(a.CredentialID),
		"authenticator_data": base64.RawURLEncoding.EncodeToString(a.AuthenticatorData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(a.ClientDataJSON),
		"signature":          base64.RawURLEncoding.EncodeToString(a.Signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return w.do(t, http.MethodPost, "/api/v1/web/login/finish", body, nil)
}

// requireSessionCookie fails unless the finish answer r set the session
// cookie with every flag, and returns its value.
func requireSessionCookie(t *testing.T, r *response) string {
	t.Helper()
	for _, sc := range r.header.Values("Set-Cookie") {
		if !strings.HasPrefix(sc, sessionCookieName+"=") {
			continue
		}
		for _, flag := range []string{"Path=/", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=43200"} {
			if !strings.Contains(sc, flag) {
				t.Fatalf("session Set-Cookie %q lacks %s", sc, flag)
			}
		}
		if strings.Contains(sc, "Domain=") {
			t.Fatalf("session Set-Cookie %q names a Domain", sc)
		}
		value, _, _ := strings.Cut(strings.TrimPrefix(sc, sessionCookieName+"="), ";")
		return value
	}
	t.Fatalf("finish set no %s cookie: %q", sessionCookieName, r.header.Values("Set-Cookie"))
	return ""
}

// requireToLogin fails unless r is a 303 to /login.
func requireToLogin(t *testing.T, what string, r *response) {
	t.Helper()
	if r.code != http.StatusSeeOther || r.header.Get("Location") != "/login" {
		t.Fatalf("%s = %d (Location %q), want 303 to /login:\n%s", what, r.code, r.header.Get("Location"), r.body)
	}
}

// installThroughServer writes doc, signed with env's admin key, as a
// directory proposal (directory.json and directory.json.sigs) and installs
// it with keyroster directory install, so it passes the server's install
// handler, which drops the status cache. It never installs on the signer
// socket directly.
func installThroughServer(t *testing.T, env *serverEnv, admin *cliEnv, doc []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "directory.json"), doc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "directory.json.sigs"), adminSign(t, env.Signer, directory.Namespace, doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := env.keyroster(t, admin, "", "directory", "install", dir); code != 0 {
		t.Fatalf("keyroster directory install: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
}

// TestWebSignInEndToEnd (AUTH-02): a user whose passkey an admin bound in
// the installed directory signs in to the web UI with it. The server
// verifies the assertion with internal/webauthn against the directory
// credential and the policy RP, sets the __Host- session cookie with every
// flag, and /account shows the user's role, principal and credential
// fingerprint. Logout ends the session. A soft authenticator stands in for
// the browser and the passkey; app.js itself is not run.
func TestWebSignInEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	for _, name := range []string{"admin1", "alice"} {
		auth, fp := enroll(t, env, admin, name, webauthn.AlgEdDSA)
		if code, out, errOut := env.keyroster(t, admin, "", "user", "approve", name, "--fingerprint", fp, "--yes"); code != 0 {
			t.Fatalf("user approve %s: exit %d:\nstdout:\n%s\nstderr:\n%s", name, code, out, errOut)
		}
		if name == "alice" {
			testWebSignIn(t, env, admin, auth, fp)
		}
	}
}

// testWebSignIn runs the sign-in steps for alice, bound with auth.
func testWebSignIn(t *testing.T, env *serverEnv, admin *cliEnv, alice *webauthntest.Authenticator, fp string) {
	// The successor that grants alice role ops (02-11's role commands are
	// not merged yet, so it is built with the directory package), installed
	// through the server.
	cur, d := signerDirectory(t, env)
	d.Version, d.Prev = cur.Version+1, trust.SHA256Hex(cur.Directory)
	d.Roles = append(d.Roles, directory.Role{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600,
		Extensions: []string{}, Users: []string{"alice"}, Groups: []string{}})
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	installThroughServer(t, env, admin, doc)

	w := newWebClient(t, env)
	if r := w.do(t, http.MethodGet, "/login", nil, nil); r.code != http.StatusOK || !strings.Contains(r.body, `id="kr-login"`) {
		t.Fatalf("GET /login = %d:\n%s", r.code, r.body)
	}
	requireToLogin(t, "GET /account before sign-in", w.do(t, http.MethodGet, "/account", nil, nil))

	fin := w.signIn(t, "alice", alice)
	if fin.code != http.StatusOK || strings.TrimSpace(fin.body) != `{"redirect":"/account"}` {
		t.Fatalf("finish = %d %s\nserver log:\n%s", fin.code, fin.body, env.Stderr.String())
	}
	cookie := requireSessionCookie(t, fin)

	acct := w.do(t, http.MethodGet, "/account", nil, nil)
	if acct.code != http.StatusOK {
		t.Fatalf("GET /account = %d:\n%s\nserver log:\n%s", acct.code, acct.body, env.Stderr.String())
	}
	// html/template escapes "+" in a fingerprint; compare the text.
	text := html.UnescapeString(acct.body)
	for _, want := range []string{"alice", "role:ops", fp, "3600 s", "Read only. Ask an admin to change roles or credentials."} {
		if !strings.Contains(text, want) {
			t.Fatalf("GET /account lacks %q:\n%s", want, acct.body)
		}
	}
	if strings.Contains(acct.body, "admin1") {
		t.Fatalf("GET /account shows another user's data:\n%s", acct.body)
	}
	requireSecurityHeaders(t, "GET /account", acct)

	out := w.do(t, http.MethodPost, "/logout", nil, nil)
	requireToLogin(t, "POST /logout", out)
	requireToLogin(t, "GET /account after logout", w.do(t, http.MethodGet, "/account", nil, nil))
	// The old cookie value, sent again by hand, opens nothing: the row is
	// gone, not only the browser's copy.
	requireToLogin(t, "GET /account with the logged-out cookie",
		w.do(t, http.MethodGet, "/account", nil, map[string]string{"Cookie": sessionCookieName + "=" + cookie}))
	if !strings.Contains(env.Stderr.String(), `"event":"signin_ok"`) || !strings.Contains(env.Stderr.String(), `"event":"logout"`) {
		t.Fatalf("the server log lacks the signin_ok and logout lines:\n%s", env.Stderr.String())
	}
	if strings.Contains(env.Stderr.String(), cookie) {
		t.Fatal("the server log holds the session cookie value")
	}
}
