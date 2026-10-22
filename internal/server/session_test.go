package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// account GETs /account with the session cookie value cookie.
func (e *signInEnv) account(cookie string) *httptest.ResponseRecorder {
	return e.request(http.MethodGet, "/account", "", "", cookie, nil)
}

// requireAccount fails unless /account answers 200 for cookie and its text
// holds every string of want; it returns the page text.
func (e *signInEnv) requireAccount(t *testing.T, what, cookie string, want ...string) string {
	t.Helper()
	rec := e.account(cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: GET /account = %d %s\nlog:\n%s", what, rec.Code, rec.Body, e.log)
	}
	text := html.UnescapeString(rec.Body.String())
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Fatalf("%s: GET /account lacks %q:\n%s", what, w, text)
		}
	}
	return text
}

// requireLoginRedirect fails unless rec is a 303 to /login.
func requireLoginRedirect(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("%s = %d (Location %q), want 303 to /login:\n%s", what, rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}

// requireEnded fails unless cookie's session is gone: /account redirects
// to /login, clears the cookie, and no session row is left.
func (e *signInEnv) requireEnded(t *testing.T, what, cookie string) {
	t.Helper()
	rec := e.account(cookie)
	requireLoginRedirect(t, what, rec)
	if sc := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(sc, sessionCookieName+"=;") || !strings.Contains(sc, "Max-Age=0") {
		t.Fatalf("%s: Set-Cookie %q does not clear the session cookie", what, sc)
	}
	if n := e.sessionRows(t); n != 0 {
		t.Fatalf("%s: %d session rows left, want 0", what, n)
	}
}

// fingerprint is a's credential fingerprint.
func fingerprint(a *webauthntest.Authenticator) string {
	return webauthn.Fingerprint(a.Credential().SPKI)
}

// TestSession: the session's expiry, its binding to the directory and the
// credential that opened it, its storage, and logout (AUTH-02, T-02-47,
// T-02-91).
func TestSession(t *testing.T) {
	t.Run("account_shows_own_data_only", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		text := e.requireAccount(t, "alice", cookie, "alice", "active", "role:dev", "7200 s (2h0m0s)", "Directory version",
			fingerprint(e.alice), fingerprint(e.alice2), "synced", "device-bound", "EdDSA", "ES256",
			"Read only. Ask an admin to change roles or credentials.", `action="/logout"`)
		if strings.Contains(text, "bob") || strings.Contains(text, fingerprint(e.bob)) {
			t.Fatalf("alice's account page shows bob's data:\n%s", text)
		}
		rec := e.account(cookie)
		requireHeaders(t, "GET /account", rec)
		if !strings.Contains(text, "Longest certificate</dt><dd>7200 s") {
			t.Fatalf("the TTL cap is not the role's 7200 s:\n%s", text)
		}
	})
	t.Run("ttl_cap_is_user_ca_cap", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		e.install(t, grantRole("long", "alice", 86400)) // above the user CA's 43200
		cookie := e.signIn(t, "alice", e.alice)
		e.requireAccount(t, "alice", cookie, "Longest certificate</dt><dd>7200 s")
		e.install(t, func(d *directory.Directory) {
			d.Roles = []directory.Role{{Name: "long", Principals: []string{"role:long"}, MaxTTLSeconds: 86400, Extensions: []string{}, Users: []string{"alice"}, Groups: []string{}}}
		})
		e.requireAccount(t, "alice with one long role", cookie, "Longest certificate</dt><dd>43200 s (12h0m0s)", "86400 s")
	})
	t.Run("no_roles_yet", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "bob", e.bob)
		e.requireAccount(t, "bob", cookie, "bob", "No roles yet.", "none: no roles yet", fingerprint(e.bob))
	})
	t.Run("stored_hash_only", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		raw, err := base64.RawURLEncoding.DecodeString(cookie)
		if err != nil {
			t.Fatal(err)
		}
		var (
			idHash, credID []byte
			user           string
			created, seen  int64
		)
		if err := e.openRaw(t).QueryRow(`SELECT id_hash, user_name, cred_id, created_us, last_seen_us FROM sessions`).Scan(&idHash, &user, &credID, &created, &seen); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if !bytes.Equal(idHash, sum[:]) || user != "alice" || !bytes.Equal(credID, e.alice.Credential().ID) || created != t0.UnixMicro() || seen != created {
			t.Fatalf("session row = %x %s %x %d %d, want SHA-256(id) alice alice's credential ID and t0", idHash, user, credID, created, seen)
		}
		var n int
		if err := e.openRaw(t).QueryRow(`SELECT count(*) FROM sessions WHERE id_hash = ? OR id_hash = ? OR instr(user_name, ?) > 0`, raw, []byte(cookie), cookie).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatal("the raw session ID is stored")
		}
	})
	t.Run("idle_expiry", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		e.advance(59 * time.Minute)
		e.requireAccount(t, "59 min idle", cookie)
		e.advance(61 * time.Minute)
		e.requireEnded(t, "61 min idle", cookie)
	})
	t.Run("absolute_expiry", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		for elapsed := 50 * time.Minute; elapsed <= 12*time.Hour; elapsed += 50 * time.Minute {
			e.advance(50 * time.Minute)
			e.requireAccount(t, "active session at "+elapsed.String(), cookie)
		}
		e.clock.set(t0.Add(12*time.Hour + time.Minute))
		e.requireEnded(t, "12 h 1 min after sign-in, used 10 min ago", cookie)
	})
	t.Run("touch_after_expiry_does_not_revive", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		ctx := context.Background()
		hash := sha256.Sum256([]byte("session"))
		id := e.alice.Credential().ID
		if err := e.s.db.CreateSession(ctx, hash[:], "alice", id, t0, sessionIdle, sessionAbsolute); err != nil {
			t.Fatal(err)
		}
		if _, _, err := e.s.db.TouchSession(ctx, hash[:], t0.Add(sessionIdle+time.Microsecond), sessionIdle, sessionAbsolute); !errors.Is(err, serverdb.ErrNotFound) {
			t.Fatalf("TouchSession at idle + 1 µs: %v, want ErrNotFound", err)
		}
		if n := e.sessionRows(t); n != 0 {
			t.Fatalf("%d session rows after the expired touch, want 0", n)
		}
		if _, _, err := e.s.db.TouchSession(ctx, hash[:], t0.Add(time.Minute), sessionIdle, sessionAbsolute); !errors.Is(err, serverdb.ErrNotFound) {
			t.Fatalf("TouchSession with an earlier now after expiry: %v, want ErrNotFound", err)
		}
		// The control: at exactly idle the session is extended, and its
		// last use never moves backwards.
		if err := e.s.db.CreateSession(ctx, hash[:], "alice", id, t0, sessionIdle, sessionAbsolute); err != nil {
			t.Fatal(err)
		}
		if u, c, err := e.s.db.TouchSession(ctx, hash[:], t0.Add(sessionIdle), sessionIdle, sessionAbsolute); err != nil || u != "alice" || !bytes.Equal(c, id) {
			t.Fatalf("TouchSession at exactly idle = %q %x %v", u, c, err)
		}
		if _, _, err := e.s.db.TouchSession(ctx, hash[:], t0, sessionIdle, sessionAbsolute); err != nil {
			t.Fatalf("TouchSession with an earlier now inside the window: %v", err)
		}
		var seen int64
		if err := e.openRaw(t).QueryRow(`SELECT last_seen_us FROM sessions`).Scan(&seen); err != nil || seen != t0.Add(sessionIdle).UnixMicro() {
			t.Fatalf("last_seen_us = %d (%v), want idle after t0", seen, err)
		}
	})
	t.Run("disabled_user_ends_session", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		e.install(t, setStatus("alice", directory.StatusDisabled))
		e.requireEnded(t, "after the disable", cookie)
		if got := lastSignIn(t, e.log); got["event"] != eventSessionEnded || got["reason"] != reasonUserNotActive || got["user"] != "alice" {
			t.Fatalf("logged %v", got)
		}
		// A re-enable does not bring the deleted session back.
		e.install(t, setStatus("alice", directory.StatusActive))
		requireLoginRedirect(t, "after the re-enable", e.account(cookie))
	})
	t.Run("credential_unbound_ends_session", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		first := e.signIn(t, "alice", e.alice)
		second := e.signIn(t, "alice", e.alice2)
		e.install(t, func(d *directory.Directory) {
			for i := range d.Users {
				if d.Users[i].Name == "alice" {
					d.Users[i].Credentials = []directory.Credential{dirCred(e.alice2, false)}
				}
			}
		})
		requireLoginRedirect(t, "the session of the removed credential", e.account(first))
		if got := lastSignIn(t, e.log); got["reason"] != reasonCredentialUnbound {
			t.Fatalf("logged %v", got)
		}
		text := e.requireAccount(t, "the session of the credential still bound", second, fingerprint(e.alice2))
		if strings.Contains(text, fingerprint(e.alice)) {
			t.Fatalf("the account page still lists the removed credential:\n%s", text)
		}
		if n := e.sessionRows(t); n != 1 {
			t.Fatalf("%d session rows, want 1 (the second)", n)
		}
	})
	t.Run("credential_moved_to_other_user_ends_session", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "bob", e.bob)
		e.install(t, func(d *directory.Directory) {
			bobCred := dirCred(e.bob, false)
			for i := range d.Users {
				if d.Users[i].Name == "bob" {
					d.Users[i].Credentials = []directory.Credential{dirCred(newAuthenticator(t, webauthn.AlgEdDSA), false)}
				}
			}
			bind("carol", bobCred)(d)
		})
		requireLoginRedirect(t, "bob's session after his credential moved to carol", e.account(cookie))
	})
	t.Run("role_change_keeps_session", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		text := e.requireAccount(t, "under v1", cookie, "role:dev", "Directory version</dt><dd>1<")
		if strings.Contains(text, "role:ops") {
			t.Fatal("v1 shows role:ops")
		}
		e.install(t, grantRole("ops", "alice", 3600))
		e.requireAccount(t, "under v2", cookie, "role:ops", "role:dev", "Directory version</dt><dd>2<", "Longest certificate</dt><dd>3600 s")
		if n := e.sessionRows(t); n != 1 {
			t.Fatalf("%d session rows, want 1", n)
		}
	})
	t.Run("signer_unavailable_fails_closed", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		st := e.fake.statusNow()
		e.fake.setStatus(st, errors.New("signer down"))
		e.advance(6 * time.Second)
		requireUnavailable(t, "GET /account during the outage", e.account(cookie), true)
		requireUnavailable(t, "begin during the outage", e.beginFrom(t, "alice", ""), false)
		if n := e.sessionRows(t); n != 1 {
			t.Fatalf("%d session rows during the outage, want 1: an outage is not a logout", n)
		}
		e.fake.setStatus(st, nil)
		e.requireAccount(t, "after the signer recovered", cookie, "alice")
	})
	t.Run("directory_read_failure_fails_closed", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		e.install(t, grantRole("ops", "alice", 3600))
		e.fake.mu.Lock()
		e.fake.chain = false
		e.fake.mu.Unlock()
		e.fake.setStatus(withDirectory(e.fake.statusNow(), 2), nil)
		e.fake.setDirectory(nil, errors.New("read failed"))
		requireUnavailable(t, "GET /account when the directory cannot be read", e.account(cookie), true)
		if n := e.sessionRows(t); n != 1 {
			t.Fatalf("%d session rows, want 1", n)
		}
	})
	t.Run("unknown_cookie_redirects", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		_, other, err := randomID(32)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []string{other, "not-base64!", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), ""} {
			requireLoginRedirect(t, "GET /account with cookie "+c, e.account(c))
		}
	})
	t.Run("logout", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		other := e.signIn(t, "alice", e.alice)
		rec := e.request(http.MethodPost, "/logout", "", "", cookie, map[string]string{"Origin": testOrigin, "Sec-Fetch-Site": "same-origin"})
		requireLoginRedirect(t, "POST /logout", rec)
		if sc := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(sc, sessionCookieName+"=;") || !strings.Contains(sc, "Max-Age=0") ||
			!strings.Contains(sc, "Secure") || !strings.Contains(sc, "Path=/") {
			t.Fatalf("logout Set-Cookie %q", sc)
		}
		requireLoginRedirect(t, "GET /account after logout", e.account(cookie))
		e.requireAccount(t, "alice's other session", other)
		if got := lastSignIn(t, e.log); got["event"] != eventLogout || got["user"] != "alice" {
			t.Fatalf("logged %v", got)
		}
	})
	t.Run("logout_during_outage", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		e.fake.setStatus(e.fake.statusNow(), errors.New("signer down"))
		e.advance(6 * time.Second)
		requireLoginRedirect(t, "POST /logout during an outage", e.request(http.MethodPost, "/logout", "", "", cookie, nil))
		if n := e.sessionRows(t); n != 0 {
			t.Fatalf("%d session rows after logout, want 0", n)
		}
	})
	t.Run("cross_site_logout_refused", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		cookie := e.signIn(t, "alice", e.alice)
		rec := e.request(http.MethodPost, "/logout", "", "", cookie, map[string]string{"Origin": "https://evil.example", "Sec-Fetch-Site": "cross-site"})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("cross-site POST /logout = %d, want 403", rec.Code)
		}
		requireHeaders(t, "cross-site POST /logout", rec)
		e.requireAccount(t, "after the refused logout", cookie, "alice")
		if n := e.sessionRows(t); n != 1 {
			t.Fatalf("%d session rows, want 1", n)
		}
	})
	t.Run("login_page", func(t *testing.T) {
		e := newSignInEnv(t, highSignInLimits)
		rec := e.request(http.MethodGet, "/login", "", "", "", nil)
		body := rec.Body.String()
		if rec.Code != http.StatusOK || !strings.Contains(body, `id="kr-login" data-begin="/api/v1/web/login/begin" data-finish="/api/v1/web/login/finish"`) ||
			!strings.Contains(body, `role="alert"`) || !strings.Contains(body, `<script src="/static/app.js" defer></script>`) || strings.Contains(body, "<script>") {
			t.Fatalf("GET /login = %d:\n%s", rec.Code, body)
		}
		requireHeaders(t, "GET /login", rec)
		e.fake.setStatus(e.fake.statusNow(), errors.New("signer down"))
		e.advance(6 * time.Second)
		requireUnavailable(t, "GET /login during an outage", e.request(http.MethodGet, "/login", "", "", "", nil), true)
	})
}
