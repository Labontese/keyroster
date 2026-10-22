package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// The web sign-in routes (02-10).
const (
	signInBeginPath  = "/api/v1/web/login/begin"
	signInFinishPath = "/api/v1/web/login/finish"
)

const (
	// signInChallengeTTL is how long a begun sign-in may take before its
	// challenge is refused.
	signInChallengeTTL = 120 * time.Second
	// signInBrowserTimeout is the timeout the browser is given for the
	// ceremony, in milliseconds, well inside signInChallengeTTL.
	signInBrowserTimeout = 60000
	// signInRandomLen is the length of a challenge, a challenge ID and a
	// session ID, in random bytes.
	signInRandomLen = 32
)

// The body limits of the sign-in routes. Begin carries one user name. A
// finish carries four base64url fields: a credential ID of at most 1023
// bytes, 37 bytes of authenticator data, a clientDataJSON of a few
// hundred bytes and a signature of at most 512 bytes (RSA-4096); 16 KiB
// leaves room for a long clientDataJSON and bounds what the parsers see.
const (
	maxSignInBeginBody  = 1 << 10
	maxSignInFinishBody = 16 << 10
)

// The client answers of the sign-in routes: fixed texts. Every non-usable
// name gets the same begin refusal, and every refused finish the same
// finish refusal, whatever the reason; the reason is only logged.
var (
	errSignInNoPasskey = serverclient.APIError{Error: "no usable passkey for this user"}
	errSignInFailed    = serverclient.APIError{Error: "sign-in failed"}
	errSignInMalformed = serverclient.APIError{Error: "malformed request"}
	errSignInLimited   = serverclient.APIError{Error: "rate limited"}
	errSignInInternal  = serverclient.APIError{Error: "internal error"}
)

// The events and reason codes of the sign-in log line: closed lists. A
// reason never carries request text.
const (
	eventSignInOK      = "signin_ok"
	eventSignInRefused = "signin_refused" // a refused finish
	eventBeginRefused  = "begin_refused"
	eventRateLimited   = "rate_limited"
	eventLogout        = "logout"
	eventSessionEnded  = "session_ended"

	reasonOK                 = "ok"
	reasonNoUsablePasskey    = "no_usable_passkey"
	reasonPerClient          = "per_client"
	reasonPerUser            = "per_user"
	reasonMalformed          = "malformed"
	reasonSignInBodyTooLarge = "body_too_large"
	reasonChallengeNotFound  = "challenge_not_found"
	reasonUserNotActive      = "user_not_active"
	reasonCredentialUnbound  = "credential_not_bound" //nolint:gosec // G101: a log reason code, not a credential
	reasonSignInUnavailable  = "signer_unavailable"
	reasonSignInInternal     = "internal_error"
	reasonNoSession          = "no_session"
)

// verifyReasons names each internal/webauthn verification sentinel for
// the log: the step that refused the assertion.
var verifyReasons = []struct {
	err    error
	reason string
}{
	{webauthn.ErrCredentialID, "assertion_credential_id"},
	{webauthn.ErrAuthenticatorData, "assertion_authenticator_data"},
	{webauthn.ErrRPMismatch, "assertion_rp_mismatch"},
	{webauthn.ErrUserPresence, "assertion_user_presence"},
	{webauthn.ErrUserVerification, "assertion_user_verification"},
	{webauthn.ErrClientData, "assertion_client_data"},
	{webauthn.ErrType, "assertion_type"},
	{webauthn.ErrChallenge, "assertion_challenge"},
	{webauthn.ErrOrigin, "assertion_origin"},
	{webauthn.ErrCrossOrigin, "assertion_cross_origin"},
	{webauthn.ErrSignature, "assertion_signature"},
	{webauthn.ErrAlgorithm, "assertion_algorithm"},
	{webauthn.ErrPublicKey, "assertion_public_key"},
}

// verifyReason is the reason code of a VerifyAssertion error.
func verifyReason(err error) string {
	for _, v := range verifyReasons {
		if errors.Is(err, v.err) {
			return v.reason
		}
	}
	return "assertion_refused"
}

// logSignIn writes the one log line of a sign-in event (02-10-F15):
// message "web sign-in" with exactly event, reason, user and client, the
// address the request came from. user is a name that passed the directory
// user-name rule, or empty: a name the client typed that fails the rule is
// never logged. No session ID or its hash, challenge, challenge ID or
// assertion byte is ever passed in.
func (s *Server) logSignIn(level slog.Level, event, reason, user string, r *http.Request) {
	s.log.Log(context.Background(), level, "web sign-in", "event", event, "reason", reason, "user", user, "client", remoteIP(r))
}

// remoteIP is the address of r.RemoteAddr, without its port, or empty when
// it does not parse.
func remoteIP(r *http.Request) string {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return ap.Addr().Unmap().WithZone("").String()
}

// signInLimited answers a sign-in request one of the sign-in limiters
// refused: 429 with Retry-After, and one sign-in log line.
func (s *Server) signInLimited(w http.ResponseWriter, r *http.Request, l *limiter, reason, user string) {
	s.logSignIn(slog.LevelWarn, eventRateLimited, reason, user, r)
	w.Header().Set("Retry-After", strconv.Itoa(l.retryAfter()))
	s.writeJSON(w, nil, http.StatusTooManyRequests, errSignInLimited)
}

// readSignInBody reads the body of a sign-in request, at most limit bytes:
// a declared Content-Length over limit is refused at once, a body without
// one is read through http.MaxBytesReader. It returns the reason code of a
// failure.
func readSignInBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, string) {
	if r.ContentLength > limit {
		return nil, reasonSignInBodyTooLarge
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, reasonSignInBodyTooLarge
		}
		return nil, reasonMalformed
	}
	return body, ""
}

// decodeStrict decodes exactly one JSON value from body into v, refusing
// unknown fields and trailing data.
func decodeStrict(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// randomID returns n random bytes and their unpadded base64url form.
func randomID(n int) ([]byte, string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, "", err
	}
	return b, base64.RawURLEncoding.EncodeToString(b), nil
}

// activeUser returns name's entry in the view when the installed directory
// holds name as an active user. Nothing from the server's own tables is
// consulted: a pending or unapproved account is not in the directory.
func (e *directoryView) activeUser(name string) (*directory.User, bool) {
	if e.dir == nil {
		return nil, false
	}
	for i := range e.dir.Users {
		if e.dir.Users[i].Name == name {
			if e.dir.Users[i].Status != directory.StatusActive {
				return nil, false
			}
			return &e.dir.Users[i], true
		}
	}
	return nil, false
}

// boundCredential returns the credential with ID id when the installed
// directory binds it to name and name is active there. The reason code
// says which check refused.
func (e *directoryView) boundCredential(name string, id []byte) (webauthn.Credential, string) {
	if _, ok := e.activeUser(name); !ok {
		return webauthn.Credential{}, reasonUserNotActive
	}
	c, ok := e.dir.Credential(name, id)
	if !ok {
		return webauthn.Credential{}, reasonCredentialUnbound
	}
	return c, ""
}

// signInBeginRequest is the body of POST signInBeginPath.
type signInBeginRequest struct {
	User string `json:"user"`
}

// signInBeginResponse is the 200 answer of the sign-in begin: the
// challenge ID to send back with the assertion, and the request options
// for navigator.credentials.get, every byte string as unpadded base64url.
type signInBeginResponse struct {
	ChallengeID string        `json:"challenge_id"`
	PublicKey   signInOptions `json:"publicKey"`
}

type signInOptions struct {
	Challenge        string            `json:"challenge"`
	AllowCredentials []allowCredential `json:"allowCredentials"`
	RPID             string            `json:"rpId"`
	UserVerification string            `json:"userVerification"`
	Timeout          int               `json:"timeout"`
}

type allowCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// handleSignInBegin serves POST /api/v1/web/login/begin {"user"}. In order:
//
//  1. the per-client sign-in limiter (with its global backstop);
//  2. at most maxSignInBeginBody bytes, one strict JSON object;
//  3. a name that fails the directory user-name rule gets the uniform 404
//     at once, so it never creates a per-username limiter entry;
//  4. the per-username limiter;
//  5. the installed directory through currentDirectory (503 when it
//     cannot be read, nothing created);
//  6. the name must be an active user of that directory with at least one
//     bound credential, or the uniform 404: the same answer for an unknown
//     name, a pending or unapproved account, a disabled user and one
//     without a credential;
//  7. a random 32-byte challenge under a random challenge ID, stored for
//     signInChallengeTTL, and the request options with allowCredentials
//     the user's bound credentials and user verification required.
func (s *Server) handleSignInBegin(w http.ResponseWriter, r *http.Request) {
	now := s.clock()
	if !s.signInLimit.allow(clientKey(r), now) {
		s.signInLimited(w, r, s.signInLimit, reasonPerClient, "")
		return
	}
	body, reason := readSignInBody(w, r, maxSignInBeginBody)
	var req signInBeginRequest
	if reason == "" && decodeStrict(body, &req) != nil {
		reason = reasonMalformed
	}
	if reason != "" {
		s.logSignIn(slog.LevelInfo, eventBeginRefused, reason, "", r)
		s.writeJSON(w, nil, http.StatusBadRequest, errSignInMalformed)
		return
	}
	name := req.User
	if !directory.ValidUserName(name) {
		s.logSignIn(slog.LevelInfo, eventBeginRefused, reasonNoUsablePasskey, "", r)
		s.writeJSON(w, nil, http.StatusNotFound, errSignInNoPasskey)
		return
	}
	if !s.signInUserLimit.allow(name, now) {
		s.signInLimited(w, r, s.signInUserLimit, reasonPerUser, name)
		return
	}
	ctx := r.Context()
	view, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("sign-in: directory unavailable", "err", err)
		s.logSignIn(slog.LevelWarn, eventBeginRefused, reasonSignInUnavailable, name, r)
		s.signerUnavailable(w, false)
		return
	}
	var ids [][]byte
	if _, ok := view.activeUser(name); ok {
		ids = view.creds[name]
	}
	if len(ids) == 0 {
		s.logSignIn(slog.LevelInfo, eventBeginRefused, reasonNoUsablePasskey, name, r)
		s.writeJSON(w, nil, http.StatusNotFound, errSignInNoPasskey)
		return
	}
	id, challenge, err := s.newSignInChallenge(ctx, name, now)
	if err != nil {
		s.log.Error("sign-in begin", "err", err)
		s.logSignIn(slog.LevelError, eventBeginRefused, reasonSignInInternal, name, r)
		s.writeJSON(w, nil, http.StatusInternalServerError, errSignInInternal)
		return
	}
	opts := signInOptions{
		Challenge:        base64.RawURLEncoding.EncodeToString(challenge),
		AllowCredentials: make([]allowCredential, 0, len(ids)),
		RPID:             view.status.rp.RPID,
		UserVerification: "required",
		Timeout:          signInBrowserTimeout,
	}
	for _, c := range ids {
		opts.AllowCredentials = append(opts.AllowCredentials, allowCredential{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString(c)})
	}
	s.writeJSON(w, view.status, http.StatusOK, signInBeginResponse{ChallengeID: id, PublicKey: opts})
}

// newSignInChallenge stores a new random challenge for user under a new
// random challenge ID until now plus signInChallengeTTL.
func (s *Server) newSignInChallenge(ctx context.Context, user string, now time.Time) (id string, challenge []byte, err error) {
	if challenge, _, err = randomID(signInRandomLen); err != nil {
		return "", nil, err
	}
	if _, id, err = randomID(signInRandomLen); err != nil {
		return "", nil, err
	}
	if err := s.db.CreateChallenge(ctx, id, user, challenge, now.Add(signInChallengeTTL).UnixMicro(), now.UnixMicro()); err != nil {
		return "", nil, err
	}
	return id, challenge, nil
}

// signInFinishRequest is the body of POST signInFinishPath: the challenge
// ID from begin and the assertion navigator.credentials.get returned,
// every byte string as unpadded base64url.
type signInFinishRequest struct {
	ChallengeID       string `json:"challenge_id"`
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}

// assertion decodes the request's byte strings.
func (req *signInFinishRequest) assertion() (webauthn.Assertion, bool) {
	var a webauthn.Assertion
	for _, f := range []struct {
		in  string
		out *[]byte
	}{
		{req.CredentialID, &a.CredentialID},
		{req.AuthenticatorData, &a.AuthenticatorData},
		{req.ClientDataJSON, &a.ClientDataJSON},
		{req.Signature, &a.Signature},
	} {
		b, err := base64.RawURLEncoding.Strict().DecodeString(f.in)
		if err != nil || len(b) == 0 {
			return webauthn.Assertion{}, false
		}
		*f.out = b
	}
	return a, true
}

// validChallengeID reports whether id has the form randomID gives one: the
// unpadded base64url of signInRandomLen bytes. Nothing else is looked up.
func validChallengeID(id string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(id)
	return err == nil && len(b) == signInRandomLen
}

// handleSignInFinish serves POST /api/v1/web/login/finish. In order:
//
//  1. the per-client sign-in limiter;
//  2. at most maxSignInFinishBody bytes, one strict JSON object whose byte
//     strings decode and whose challenge ID has the form of one;
//  3. TakeChallenge consumes the challenge, once (absent, used or expired:
//     refused);
//  4. the per-username limiter, keyed on the user stored with the
//     challenge, never on client input;
//  5. the installed directory through currentDirectory (503 when it
//     cannot be read, nothing created);
//  6. the user must still be active there and the credential must be
//     bound to that user;
//  7. internal/webauthn.VerifyAssertion, the signer's own verifier,
//     against that credential, the policy's RP ID and origins and the
//     stored challenge;
//  8. a random 32-byte session ID, stored only as its SHA-256 with the user
//     and the credential ID, and sent once in the __Host- cookie.
//
// Every refusal answers 401 with the one fixed body, logged with its
// reason.
func (s *Server) handleSignInFinish(w http.ResponseWriter, r *http.Request) {
	now := s.clock()
	if !s.signInLimit.allow(clientKey(r), now) {
		s.signInLimited(w, r, s.signInLimit, reasonPerClient, "")
		return
	}
	refuse := func(reason, user string) {
		s.logSignIn(slog.LevelInfo, eventSignInRefused, reason, user, r)
		s.writeJSON(w, nil, http.StatusUnauthorized, errSignInFailed)
	}
	body, reason := readSignInBody(w, r, maxSignInFinishBody)
	if reason != "" {
		refuse(reason, "")
		return
	}
	var req signInFinishRequest
	if decodeStrict(body, &req) != nil || !validChallengeID(req.ChallengeID) {
		refuse(reasonMalformed, "")
		return
	}
	a, ok := req.assertion()
	if !ok {
		refuse(reasonMalformed, "")
		return
	}
	ctx := r.Context()
	user, challenge, err := s.db.TakeChallenge(ctx, req.ChallengeID, now)
	if errors.Is(err, serverdb.ErrNotFound) {
		refuse(reasonChallengeNotFound, "")
		return
	}
	if err == nil && len(challenge) != signInRandomLen {
		err = errors.New("stored challenge has the wrong length")
	}
	if err != nil {
		s.signInInternal(w, r, "", err)
		return
	}
	if !s.signInUserLimit.allow(user, now) {
		s.signInLimited(w, r, s.signInUserLimit, reasonPerUser, user)
		return
	}
	view, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("sign-in: directory unavailable", "err", err)
		s.logSignIn(slog.LevelWarn, eventSignInRefused, reasonSignInUnavailable, user, r)
		s.signerUnavailable(w, false)
		return
	}
	cred, reason := view.boundCredential(user, a.CredentialID)
	if reason != "" {
		refuse(reason, user)
		return
	}
	rp := view.status.rp
	if err := webauthn.VerifyAssertion(cred, rp.RPID, rp.Origins, [signInRandomLen]byte(challenge), a); err != nil {
		refuse(verifyReason(err), user)
		return
	}
	raw, value, err := randomID(signInRandomLen)
	if err != nil {
		s.signInInternal(w, r, user, err)
		return
	}
	hash := sha256.Sum256(raw)
	if err := s.db.CreateSession(ctx, hash[:], user, cred.ID, now, sessionIdle, sessionAbsolute); err != nil {
		s.signInInternal(w, r, user, err)
		return
	}
	http.SetCookie(w, sessionCookie(value, sessionCookieMaxAge))
	s.logSignIn(slog.LevelInfo, eventSignInOK, reasonOK, user, r)
	s.writeJSON(w, view.status, http.StatusOK, map[string]string{"redirect": "/account"})
}

// signInInternal answers a sign-in request that failed on the server's
// side with 500, logging the error itself apart from the sign-in line.
func (s *Server) signInInternal(w http.ResponseWriter, r *http.Request, user string, err error) {
	s.log.Error("sign-in finish", "err", err)
	s.logSignIn(slog.LevelError, eventSignInRefused, reasonSignInInternal, user, r)
	s.writeJSON(w, nil, http.StatusInternalServerError, errSignInInternal)
}

// handleLogin serves GET /login: the sign-in page, with the custody banner
// of the current status. The ceremony runs in app.js.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	v, err := s.currentStatus(r.Context())
	if err != nil {
		s.signerUnavailable(w, true)
		return
	}
	d := statusPage(v, "Sign in")
	d.RPID = v.rp.RPID
	d.BeginURL = signInBeginPath
	d.FinishURL = signInFinishPath
	s.renderPage(w, v, http.StatusOK, "login", d)
}
