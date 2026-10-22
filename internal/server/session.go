package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/Labontese/keyroster/internal/serverdb"
)

// The web session (02-10, RESEARCH V3): an opaque 32-byte random ID, sent
// only in this cookie and stored only as its SHA-256. A session lets its
// holder read their own account page and nothing else: no signer request,
// admin route or registration route reads it.
const (
	sessionCookieName = "__Host-keyroster-session"
	// sessionIdle ends a session unused for longer; sessionAbsolute ends
	// one this long after sign-in, used or not.
	sessionIdle     = time.Hour
	sessionAbsolute = 12 * time.Hour
	// sessionCookieMaxAge is the cookie's lifetime in seconds: the
	// absolute limit.
	sessionCookieMaxAge = int(sessionAbsolute / time.Second)
)

// sessionCookie is the session cookie carrying value: __Host- prefix,
// Path=/, Secure, HttpOnly, SameSite=Strict. maxAge -1 sends Max-Age=0,
// which deletes the cookie.
func sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// clearSessionCookie tells the browser to drop the session cookie.
func clearSessionCookie(w http.ResponseWriter) { http.SetCookie(w, sessionCookie("", -1)) }

// sessionHash returns the SHA-256 of the request's session ID, when the
// request carries a session cookie whose value is the unpadded base64url of
// exactly 32 bytes. present reports whether the request carried a session
// cookie at all. Nothing else is hashed or looked up.
func sessionHash(r *http.Request) (hash []byte, present bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(c.Value)
	if err != nil || len(raw) != signInRandomLen {
		return nil, true
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}

// webSession is a request's checked session: the user, the credential
// that opened the session, and the directory view the check used, which
// the handler renders from so the check and the page see one version.
type webSession struct {
	user   string
	credID []byte
	view   *directoryView
}

type sessionKey struct{}

// sessionFrom returns the session withSession put into ctx.
func sessionFrom(ctx context.Context) *webSession {
	ws, _ := ctx.Value(sessionKey{}).(*webSession)
	return ws
}

// withSession serves next only for a request with a live session whose
// user may still use it. In order:
//
//  1. the cookie must hold a well-formed session ID whose SHA-256 is a
//     session row; TouchSession extends it only within sessionIdle of its
//     last use and sessionAbsolute of its creation, and deletes it
//     otherwise;
//  2. the installed directory is read through currentDirectory, which
//     reads signer state only through currentStatus. If it cannot be read,
//     the answer is the 503 error page with nothing from stale data, and
//     the session row is kept: an outage is not a logout;
//  3. the user must still be active in that directory and the credential
//     that opened the session must still be bound to the user (02-10-F2);
//     otherwise the session row is deleted.
//
// A request without a usable session is redirected (303) to /login, and a
// cookie it carried is cleared. A role or group change that keeps the
// user active and the credential bound keeps the session: the next page
// shows the new access. A directory installed through this server is read
// on the next request, because its install handler drops the status
// cache; one installed on the signer socket directly is read within
// statusTTL (T-02-91).
func (s *Server) withSession(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		toLogin := func(dropCookie bool) {
			if dropCookie {
				clearSessionCookie(w)
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		}
		hash, present := sessionHash(r)
		if hash == nil {
			toLogin(present)
			return
		}
		ctx := r.Context()
		user, credID, err := s.db.TouchSession(ctx, hash, s.clock(), sessionIdle, sessionAbsolute)
		if errors.Is(err, serverdb.ErrNotFound) {
			toLogin(true)
			return
		}
		if err != nil {
			s.log.Error("session lookup", "err", err)
			s.internalErrorPage(w, "Something went wrong on the server. Try again in a moment.")
			return
		}
		view, err := s.currentDirectory(ctx)
		if err != nil {
			s.log.Warn("session check: directory unavailable", "err", err)
			s.signerUnavailable(w, true)
			return
		}
		if _, reason := view.boundCredential(user, credID); reason != "" {
			if _, err := s.db.DeleteSession(ctx, hash); err != nil && !errors.Is(err, serverdb.ErrNotFound) {
				s.log.Error("end session", "err", err)
				s.internalErrorPage(w, "Something went wrong on the server. Try again in a moment.")
				return
			}
			s.logSignIn(slog.LevelInfo, eventSessionEnded, reason, user, r)
			toLogin(true)
			return
		}
		next(w, r.WithContext(context.WithValue(ctx, sessionKey{}, &webSession{user: user, credID: credID, view: view})))
	})
}

// handleLogout serves POST /logout: it deletes the session row, clears the
// cookie and redirects (303) to /login. It needs no signer state, so it
// works during a signer outage. CrossOriginProtection (secure) refuses a
// cross-origin POST before it gets here.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	user, reason := "", reasonNoSession
	if hash, _ := sessionHash(r); hash != nil {
		u, err := s.db.DeleteSession(r.Context(), hash)
		switch {
		case err == nil:
			user, reason = u, reasonOK
		case !errors.Is(err, serverdb.ErrNotFound):
			s.log.Error("logout", "err", err)
			s.internalErrorPage(w, "Something went wrong on the server. You are not signed out yet; try again in a moment.")
			return
		}
	}
	clearSessionCookie(w)
	s.logSignIn(slog.LevelInfo, eventLogout, reason, user, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
