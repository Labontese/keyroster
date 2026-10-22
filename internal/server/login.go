package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/wire"
)

// The CLI login routes (02-12): keyroster login reads the options, begins
// a login with its request, PKCE challenge, state and loopback port, the
// user approves the exact request on the approval page with a passkey,
// and the CLI redeems the code the page handed to its loopback. Only the
// redeem asks the signer for a certificate (mint at redemption).
const (
	loginOptionsPath = "/api/v1/login/options"
	loginBeginPath   = "/api/v1/login/begin"
	loginPagePrefix  = "/login/"
	loginAPIPrefix   = "/api/v1/login/"
)

// The login routes as the rate limiters name them: each has its own
// per-client buckets and its own global backstop (loginRoutes).
const (
	loginPageRoute      = loginPagePrefix + "{id}"
	loginAssertionRoute = loginAPIPrefix + "{id}/assertion"
	loginRedeemRoute    = loginAPIPrefix + "{id}/redeem"
)

// loginRoutes are the five login routes, each with its own login limiter.
var loginRoutes = []string{loginOptionsPath, loginBeginPath, loginPageRoute, loginAssertionRoute, loginRedeemRoute}

// newLoginLimits returns one limiter per login route with the sign-in
// values: per client, and a global backstop sized for that one route, so
// clients that drain one route's backstop leave the other routes open
// (02-12 pre-merge review).
func newLoginLimits(lim Limits) map[string]*limiter {
	m := make(map[string]*limiter, len(loginRoutes))
	for _, route := range loginRoutes {
		m[route] = newLimiter(lim.SignInPerMinute, lim.SignInBurst, globalFactor*lim.SignInPerMinute, globalFactor*lim.SignInBurst)
	}
	return m
}

// The timing of a login, all relative to the request's CreatedAt except
// the code's own lifetime (02-12-F15). The server and the signer share one
// host clock, so a code capped at CreatedAt + loginCodeCap always reaches
// the signer inside its ±300 s request window.
const (
	// loginBeginWindow is how far CreatedAt may lie from the server's
	// clock at begin. The CLI itself refuses more than 60 s of skew.
	loginBeginWindow = 120 * time.Second
	// loginApprovalWindow is how long after CreatedAt the page and the
	// assertion route accept the approval.
	loginApprovalWindow = 240 * time.Second
	// loginCodeTTL is how long a code is valid after the approval, and
	// loginCodeCap the latest it may be valid, after CreatedAt.
	loginCodeTTL = 120 * time.Second
	loginCodeCap = 290 * time.Second
	// loginBrowserTimeout is the WebAuthn timeout given to the browser,
	// in milliseconds.
	loginBrowserTimeout = 60000
)

// The body limits of the login routes. A begin carries one standard-base64
// LoginIssueRequest without evidence: a subject key of at most 8 KiB and
// at most a few KiB of names, so 64 KiB bounds it with room. An assertion
// carries what a sign-in finish does. A redeem carries two 43-character
// strings.
const (
	maxLoginBeginBody     = 64 << 10
	maxLoginAssertionBody = 16 << 10
	maxLoginRedeemBody    = 1 << 10
)

// The client answers of the login routes: fixed texts. The reason of a
// refusal is only logged.
var (
	errLoginNotFound      = serverclient.APIError{Error: "no usable passkey for this user"}
	errLoginMalformed     = serverclient.APIError{Error: "malformed request"}
	errLoginTimeSkew      = serverclient.APIError{Error: "the request time is more than 120 s from the server's clock"}
	errLoginApproval      = serverclient.APIError{Error: "approval failed"}
	errLoginNotRedeemable = serverclient.APIError{Error: "login not redeemable"}
	errLoginLimited       = serverclient.APIError{Error: "rate limited"}
	errLoginInternal      = serverclient.APIError{Error: "internal error"}
)

// The events and reason codes of the login log line: closed lists. A
// reason never carries request text, and no line ever holds a code, a
// code_verifier or a state.
const (
	eventLoginOptions  = "options"
	eventLoginBegin    = "begin"
	eventLoginPage     = "page"
	eventLoginApprove  = "approve"
	eventLoginRedeem   = "redeem"
	eventLoginLimited  = "rate_limited"
	reasonLoginExpired = "expired"
	reasonLoginState   = "not_pending"
	reasonLoginSkew    = "time_skew"
	reasonLoginParams  = "bad_parameters"
	reasonLoginEvid    = "evidence_present"
	reasonLoginCode    = "code_mismatch"
	reasonLoginPKCE    = "verifier_mismatch"
	reasonLoginVerFmt  = "verifier_format"
	reasonLoginRefused = "signer_refused"
	reasonLoginSigner  = "signer_failed"
	reasonLoginNoRow   = "not_found"
)

// loginIDRE is the form of a login ID: 16 random bytes in lowercase hex.
var loginIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// pkceRE is the form of a PKCE code_verifier, code_challenge and state:
// exactly 43 characters of the base64url alphabet, no padding (the
// unpadded encoding of 32 bytes).
var pkceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// logLogin writes the one log line of a login event: message "cli login"
// with exactly event, reason, user (a name that passed the user-name rule,
// or empty), the login ID (a server-made value, or empty) and the client.
func (s *Server) logLogin(level slog.Level, event, reason, user, id string, r *http.Request) {
	s.log.Log(context.Background(), level, "cli login", "event", event, "reason", reason, "user", user, "login_id", id, "client", remoteIP(r))
}

// loginClientAllow applies route's own login limiter (per client, with the
// route's global backstop) to a request for route, once per request at the
// top of each handler. loginUserAllow applies the per-user limiter
// once the user name is known. Each route has its own buckets: the key is
// the route and the client, or the route, the user name and the client
// (02-10 pre-merge review, owner decision G1: one client never drains
// another client's buckets). Both answer the 429 themselves and report
// whether the request may go on.
func (s *Server) loginClientAllow(w http.ResponseWriter, r *http.Request, route string, html bool) bool {
	l := s.loginLimit[route]
	if l.allow(route+" "+clientKey(r), s.clock()) {
		return true
	}
	s.loginLimited(w, r, l, reasonPerClient, "", "", html)
	return false
}

// loginUserAllow applies the per-user limiter to a request for route by
// user, a name that passed the user-name rule or the user stored with a
// login session; id is the login ID, if any, for the log line.
func (s *Server) loginUserAllow(w http.ResponseWriter, r *http.Request, route, user, id string) bool {
	if s.loginUserLimit.allow(route+" "+signInUserKey(user, r), s.clock()) {
		return true
	}
	s.loginLimited(w, r, s.loginUserLimit, reasonPerUser, user, id, false)
	return false
}

// loginLimited answers a login request that l refused: 429 with
// Retry-After, and one login log line.
func (s *Server) loginLimited(w http.ResponseWriter, r *http.Request, l *limiter, reason, user, id string, html bool) {
	s.logLogin(slog.LevelWarn, eventLoginLimited, reason, user, id, r)
	w.Header().Set("Retry-After", strconv.Itoa(l.retryAfter()))
	if html {
		s.renderPage(w, nil, http.StatusTooManyRequests, "error", pageData{
			Title:   "Too many requests",
			Message: "Too many requests from your address. Wait a moment and try again.",
		})
		return
	}
	s.writeJSON(w, nil, http.StatusTooManyRequests, errLoginLimited)
}

// loginUser returns name's directory credentials when the installed
// directory is authorized and holds name as an active user with at least
// one bound credential; otherwise nil.
func (e *directoryView) loginUser(name string) [][]byte {
	if _, ok := e.activeUser(name); !ok {
		return nil
	}
	return e.creds[name]
}

// LoginOptionsResponse is the 200 answer of GET loginOptionsPath: what the
// CLI needs to build the request the user approves. Nothing in it is
// authority; the signer recomputes everything (D-08). This unauthenticated
// disclosure of a valid user's roles, principals and TTL caps is accepted
// as T-02-105: the CLI must put exactly these values into the request the
// passkey signs.
type loginOptionsResponse struct {
	ServerTime      int64             `json:"server_time"`
	User            string            `json:"user"`
	CAMaxTTLSeconds uint64            `json:"ca_max_ttl_seconds"`
	Roles           []loginRoleOption `json:"roles"`
}

type loginRoleOption struct {
	Name          string   `json:"name"`
	Principals    []string `json:"principals"`
	MaxTTLSeconds uint64   `json:"max_ttl_seconds"`
	Extensions    []string `json:"extensions"`
}

// handleLoginOptions serves GET /api/v1/login/options?user=NAME. For an
// active user of the authorized directory with at least one bound
// credential it answers the server's time, the user CA's TTL cap and,
// computed with directory.Authorize (the signer's own D-08 grant), each
// of the user's roles with its principals, max TTL and extensions. Every
// other name gets the uniform 404.
func (s *Server) handleLoginOptions(w http.ResponseWriter, r *http.Request) {
	if !s.loginClientAllow(w, r, loginOptionsPath, false) {
		return
	}
	name := r.URL.Query().Get("user")
	if !directory.ValidUserName(name) {
		s.logLogin(slog.LevelInfo, eventLoginOptions, reasonNoUsablePasskey, "", "", r)
		s.writeJSON(w, nil, http.StatusNotFound, errLoginNotFound)
		return
	}
	if !s.loginUserAllow(w, r, loginOptionsPath, name, "") {
		return
	}
	view, err := s.currentDirectory(r.Context())
	if err != nil {
		s.log.Warn("login options: directory unavailable", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	if len(view.loginUser(name)) == 0 {
		s.logLogin(slog.LevelInfo, eventLoginOptions, reasonNoUsablePasskey, name, "", r)
		s.writeJSON(w, nil, http.StatusNotFound, errLoginNotFound)
		return
	}
	resp := loginOptionsResponse{
		ServerTime:      s.clock().Unix(),
		User:            name,
		CAMaxTTLSeconds: userCAMaxTTL(view.status.policy),
		Roles:           []loginRoleOption{},
	}
	all, err := view.dir.Authorize(name, nil)
	switch {
	case errors.Is(err, directory.ErrRoleNotGranted):
		// The user holds no role: the CLI says so.
	case err != nil:
		s.loginInternal(w, r, eventLoginOptions, name, "", err)
		return
	default:
		for _, rn := range all.Roles {
			g, err := view.dir.Authorize(name, []string{rn})
			if err != nil {
				s.loginInternal(w, r, eventLoginOptions, name, "", err)
				return
			}
			resp.Roles = append(resp.Roles, loginRoleOption{Name: rn, Principals: g.Principals, MaxTTLSeconds: g.MaxTTLSeconds, Extensions: g.Extensions})
		}
	}
	s.logLogin(slog.LevelInfo, eventLoginOptions, reasonOK, name, "", r)
	s.writeJSON(w, view.status, http.StatusOK, resp)
}

// loginBeginRequest is the body of POST loginBeginPath.
type loginBeginRequest struct {
	Request             []byte `json:"request"` // standard base64
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
	RedirectPort        int    `json:"redirect_port"`
}

// loginBeginResponse is the 200 answer of a begin.
type loginBeginResponse struct {
	LoginID     string `json:"login_id"`
	ApprovalURL string `json:"approval_url"`
	ExpiresAt   int64  `json:"expires_at"`
}

// requestKey parses the subject key of a login request: an SSH public
// key, never a certificate.
func requestKey(req *wire.LoginIssueRequest) (ssh.PublicKey, error) {
	pub, err := ssh.ParsePublicKey(req.SubjectKey)
	if err != nil {
		return nil, err
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return nil, errors.New("the subject key is a certificate")
	}
	return pub, nil
}

// createdAt is a request's CreatedAt as a time, clamped so a huge value
// cannot overflow.
func createdAt(req *wire.LoginIssueRequest) time.Time {
	return time.Unix(int64(min(req.CreatedAt, uint64(1)<<62)), 0) //nolint:gosec // G115: clamped below 2^63
}

// handleLoginBegin serves POST /api/v1/login/begin. In order: the
// per-client limiter; at most maxLoginBeginBody bytes of strict JSON; the
// request bytes parse as a LoginIssueRequest without evidence whose subject
// key is an SSH public key; a subject that fails the user-name rule gets
// the uniform 404 before the per-user limiter; the per-user limiter; the
// directory (an active user with a bound credential, else the uniform
// 404); CreatedAt within loginBeginWindow of the server's clock; PKCE
// method S256 with a 43-character challenge, a 43-character state and a
// port of 1024 to 65535. The session expires at CreatedAt +
// loginApprovalWindow. The approval URL's origin comes from
// requestOrigin, the policy origin matching the request's Host.
func (s *Server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.loginClientAllow(w, r, loginBeginPath, false) {
		return
	}
	refuse := func(code int, body serverclient.APIError, reason, user string) {
		s.logLogin(slog.LevelInfo, eventLoginBegin, reason, user, "", r)
		s.writeJSON(w, nil, code, body)
	}
	raw, reason := readSignInBody(w, r, maxLoginBeginBody)
	var in loginBeginRequest
	if reason == "" && decodeStrict(raw, &in) != nil {
		reason = reasonMalformed
	}
	if reason != "" {
		refuse(http.StatusBadRequest, errLoginMalformed, reason, "")
		return
	}
	req, err := wire.ParseLoginIssueRequest(in.Request)
	if err != nil {
		refuse(http.StatusBadRequest, errLoginMalformed, reasonMalformed, "")
		return
	}
	if len(req.Evidence) != 0 {
		refuse(http.StatusBadRequest, errLoginMalformed, reasonLoginEvid, "")
		return
	}
	if _, err := requestKey(req); err != nil {
		refuse(http.StatusBadRequest, errLoginMalformed, reasonMalformed, "")
		return
	}
	name := req.Subject
	if !directory.ValidUserName(name) {
		refuse(http.StatusNotFound, errLoginNotFound, reasonNoUsablePasskey, "")
		return
	}
	if !s.loginUserAllow(w, r, loginBeginPath, name, "") {
		return
	}
	view, err := s.currentDirectory(r.Context())
	if err != nil {
		s.log.Warn("login begin: directory unavailable", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	if len(view.loginUser(name)) == 0 {
		refuse(http.StatusNotFound, errLoginNotFound, reasonNoUsablePasskey, name)
		return
	}
	now := s.clock()
	created := createdAt(req)
	if d := now.Sub(created); d > loginBeginWindow || d < -loginBeginWindow {
		refuse(http.StatusBadRequest, errLoginTimeSkew, reasonLoginSkew, name)
		return
	}
	if in.CodeChallengeMethod != "S256" || !pkceRE.MatchString(in.CodeChallenge) || !pkceRE.MatchString(in.State) ||
		in.RedirectPort < 1024 || in.RedirectPort > 65535 {
		refuse(http.StatusBadRequest, errLoginMalformed, reasonLoginParams, name)
		return
	}
	idBytes, _, err := randomID(16)
	if err != nil {
		s.loginInternal(w, r, eventLoginBegin, name, "", err)
		return
	}
	id := hex.EncodeToString(idBytes)
	expires := created.Add(loginApprovalWindow)
	if err := s.db.CreateLogin(r.Context(), serverdb.LoginSession{
		ID: id, User: name, Request: in.Request, CodeChallenge: in.CodeChallenge, State: in.State,
		RedirectPort: in.RedirectPort, Created: created, Expires: expires,
	}, now); err != nil {
		s.loginInternal(w, r, eventLoginBegin, name, "", err)
		return
	}
	s.logLogin(slog.LevelInfo, eventLoginBegin, reasonOK, name, id, r)
	s.writeJSON(w, view.status, http.StatusOK, loginBeginResponse{
		LoginID:     id,
		ApprovalURL: requestOrigin(r, view.status.rp.Origins) + loginPagePrefix + id,
		ExpiresAt:   expires.Unix(),
	})
}

// loginPage is what login_approve.html shows. Fingerprint is computed by
// the server from the stored request bytes, the same bytes whose SHA-256
// is the WebAuthn challenge in Options.
type loginPage struct {
	Fingerprint  string
	User         string
	Roles        string
	Principals   []string
	TTL          string
	ExpiresAt    string
	ExpiresUnix  int64
	AssertionURL string
	Options      string // JSON: the publicKey request options
}

// loginPageOptions are the request options of the approval ceremony.
type loginPageOptions struct {
	Challenge        string            `json:"challenge"`
	AllowCredentials []allowCredential `json:"allowCredentials"`
	RPID             string            `json:"rpId"`
	UserVerification string            `json:"userVerification"`
	Timeout          int               `json:"timeout"`
}

// loginGone answers an approval page whose login is unknown, expired,
// approved or redeemed: the same error page for each.
func (s *Server) loginGone(w http.ResponseWriter, r *http.Request, reason, user, id string) {
	s.logLogin(slog.LevelInfo, eventLoginPage, reason, user, id, r)
	s.renderPage(w, nil, http.StatusNotFound, "error", pageData{
		Title:   "Login request not valid",
		Message: "This login request is not valid: it has expired, was already approved or used, or does not exist. Run keyroster login again.",
	})
}

// handleLoginPage serves GET /login/{id}: the approval page of a pending,
// unexpired login. It shows the SHA-256 fingerprint of the subject key it
// parses from the stored request bytes, the user, the requested roles,
// every principal, the TTL and the expiry, and carries the WebAuthn
// options whose challenge is SHA-256 of those same bytes. The page's
// script starts the ceremony only from the Approve button.
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.loginClientAllow(w, r, loginPageRoute, true) {
		return
	}
	if !loginIDRE.MatchString(id) {
		s.loginGone(w, r, reasonLoginNoRow, "", "")
		return
	}
	view, err := s.currentDirectory(r.Context())
	if err != nil {
		s.log.Warn("login page: directory unavailable", "err", err)
		s.signerUnavailable(w, true)
		return
	}
	l, err := s.db.Login(r.Context(), id)
	if errors.Is(err, serverdb.ErrNotFound) {
		s.loginGone(w, r, reasonLoginNoRow, "", id)
		return
	}
	if err != nil {
		s.log.Error("login page", "err", err)
		s.internalErrorPage(w, "The login request could not be read. Try again in a moment.")
		return
	}
	now := s.clock()
	switch {
	case l.Status != serverdb.LoginPending:
		s.loginGone(w, r, reasonLoginState, l.User, id)
		return
	case now.After(l.Expires):
		s.loginGone(w, r, reasonLoginExpired, l.User, id)
		return
	}
	creds := view.loginUser(l.User)
	req, err := wire.ParseLoginIssueRequest(l.Request)
	var pub ssh.PublicKey
	if err == nil {
		pub, err = requestKey(req)
	}
	if err != nil || len(creds) == 0 {
		s.loginGone(w, r, reasonNoUsablePasskey, l.User, id)
		return
	}
	digest := req.Digest()
	opts := loginPageOptions{
		Challenge:        base64.RawURLEncoding.EncodeToString(digest[:]),
		AllowCredentials: make([]allowCredential, 0, len(creds)),
		RPID:             view.status.rp.RPID,
		UserVerification: "required",
		Timeout:          loginBrowserTimeout,
	}
	for _, c := range creds {
		opts.AllowCredentials = append(opts.AllowCredentials, allowCredential{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString(c)})
	}
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		s.log.Error("login page options", "err", err)
		s.internalErrorPage(w, "The login request could not be shown. Try again in a moment.")
		return
	}
	roles := "all your roles"
	if len(req.Roles) > 0 {
		roles = strings.Join(req.Roles, ", ")
	}
	d := statusPage(view.status, "Approve keyroster login")
	d.Login = &loginPage{
		Fingerprint:  ssh.FingerprintSHA256(pub),
		User:         l.User,
		Roles:        roles,
		Principals:   req.Principals,
		TTL:          formatTTL(uint64(req.ValidForSeconds)),
		ExpiresAt:    l.Expires.UTC().Format("15:04:05 UTC"),
		ExpiresUnix:  l.Expires.Unix(),
		AssertionURL: loginAPIPrefix + id + "/assertion",
		Options:      string(optsJSON),
	}
	s.logLogin(slog.LevelInfo, eventLoginPage, reasonOK, l.User, id, r)
	s.renderPage(w, view.status, http.StatusOK, "login_approve", d)
}

// loginAssertionRequest is the body of POST /api/v1/login/{id}/assertion:
// what navigator.credentials.get returned, as unpadded base64url.
type loginAssertionRequest struct {
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}

// handleLoginAssertion serves POST /api/v1/login/{id}/assertion. In
// order: the per-client limiter; a well-formed ID and at most
// maxLoginAssertionBody bytes of strict JSON whose fields decode; the
// session (the per-user limiter is keyed on its stored user, never on
// client input); the session must be pending and unexpired; the directory
// must still bind the credential to that user; the assertion must verify
// with internal/webauthn against that credential, the policy's RP and
// origins and the SHA-256 of the stored request bytes (an early check;
// the signer verifies again at redeem). Then a 32-byte random code is
// stored as its SHA-256, valid until min(now + loginCodeTTL, CreatedAt +
// loginCodeCap), and the answer is the loopback URL built only from the
// stored port and state. Every refusal answers the same 401 body; the
// verifier's sentinel goes to the log only.
func (s *Server) handleLoginAssertion(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.loginClientAllow(w, r, loginAssertionRoute, false) {
		return
	}
	refuse := func(reason, user, lid string) {
		s.logLogin(slog.LevelInfo, eventLoginApprove, reason, user, lid, r)
		s.writeJSON(w, nil, http.StatusUnauthorized, errLoginApproval)
	}
	if !loginIDRE.MatchString(id) {
		refuse(reasonMalformed, "", "")
		return
	}
	raw, reason := readSignInBody(w, r, maxLoginAssertionBody)
	if reason != "" {
		refuse(reason, "", id)
		return
	}
	var in loginAssertionRequest
	if decodeStrict(raw, &in) != nil {
		refuse(reasonMalformed, "", id)
		return
	}
	a, ok := (&signInFinishRequest{CredentialID: in.CredentialID, AuthenticatorData: in.AuthenticatorData, ClientDataJSON: in.ClientDataJSON, Signature: in.Signature}).assertion()
	if !ok {
		refuse(reasonMalformed, "", id)
		return
	}
	ctx := r.Context()
	l, err := s.db.Login(ctx, id)
	if errors.Is(err, serverdb.ErrNotFound) {
		refuse(reasonLoginNoRow, "", id)
		return
	}
	if err != nil {
		s.loginInternal(w, r, eventLoginApprove, "", id, err)
		return
	}
	if !s.loginUserAllow(w, r, loginAssertionRoute, l.User, id) {
		return
	}
	now := s.clock()
	switch {
	case l.Status != serverdb.LoginPending:
		refuse(reasonLoginState, l.User, id)
		return
	case now.After(l.Expires):
		refuse(reasonLoginExpired, l.User, id)
		return
	}
	req, err := wire.ParseLoginIssueRequest(l.Request)
	if err != nil {
		s.loginInternal(w, r, eventLoginApprove, l.User, id, err)
		return
	}
	view, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("login approval: directory unavailable", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	cred, reason := view.boundCredential(l.User, a.CredentialID)
	if reason != "" {
		refuse(reason, l.User, id)
		return
	}
	rp := view.status.rp
	if err := webauthn.VerifyAssertion(cred, rp.RPID, rp.Origins, req.Digest(), a); err != nil {
		attrs := []any{"login_id", id, "sentinel", verifyReason(err)}
		if errors.Is(err, webauthn.ErrAuthenticatorData) {
			// Neither is secret; 02-14 records them per authenticator (A6).
			attrs = append(attrs, "authenticator_data_len", len(a.AuthenticatorData))
			if len(a.AuthenticatorData) > 32 {
				attrs = append(attrs, "authenticator_flags", fmt.Sprintf("%02x", a.AuthenticatorData[32]))
			}
		}
		s.log.Info("cli login assertion refused", attrs...)
		refuse(verifyReason(err), l.User, id)
		return
	}
	blob, err := (&wire.WebAuthnAssertion{CredentialID: a.CredentialID, AuthenticatorData: a.AuthenticatorData, ClientDataJSON: a.ClientDataJSON, Signature: a.Signature}).Marshal()
	if err != nil {
		refuse(reasonMalformed, l.User, id)
		return
	}
	code, codeText, err := randomID(signInRandomLen)
	if err != nil {
		s.loginInternal(w, r, eventLoginApprove, l.User, id, err)
		return
	}
	codeHash := sha256.Sum256(code)
	codeExpires := now.Add(loginCodeTTL)
	if limit := l.Created.Add(loginCodeCap); codeExpires.After(limit) {
		codeExpires = limit
	}
	switch err := s.db.ApproveLogin(ctx, id, blob, codeHash[:], codeExpires, now); {
	case errors.Is(err, serverdb.ErrNotFound):
		refuse(reasonLoginState, l.User, id)
		return
	case err != nil:
		s.loginInternal(w, r, eventLoginApprove, l.User, id, err)
		return
	}
	s.logLogin(slog.LevelInfo, eventLoginApprove, reasonOK, l.User, id, r)
	s.writeJSON(w, view.status, http.StatusOK, map[string]string{
		"redirect": "http://127.0.0.1:" + strconv.Itoa(l.RedirectPort) + "/callback?code=" + codeText + "&state=" + l.State,
	})
}

// loginRedeemRequest is the body of POST /api/v1/login/{id}/redeem.
type loginRedeemRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"code_verifier"`
}

// loginRedeemResponse is the 200 answer of a redeem: the certificate's
// wire bytes, standard base64.
type loginRedeemResponse struct {
	Certificate []byte `json:"certificate"`
}

// handleLoginRedeem serves POST /api/v1/login/{id}/redeem, the only
// handler that asks the signer for a login certificate. The checks run so
// that nothing but a matching code and verifier burns the code (02-12-F1,
// F14):
//
//  1. the per-client limiter; a well-formed ID; at most maxLoginRedeemBody
//     bytes of strict JSON; the code and the code_verifier exactly 43
//     base64url characters, before any database access;
//  2. the session; the per-user limiter on its stored user; status
//     approved, SHA-256(code) equal to the stored hash (constant time),
//     and the code unexpired;
//  3. base64url(SHA-256(code_verifier)) equal to the stored code_challenge
//     (constant time);
//  4. the signer's status, so a signer outage answers 503 before the burn;
//  5. RedeemLogin, the one conditional UPDATE that burns the code;
//  6. the stored request with the stored assertion as its evidence, sent
//     to the signer.
//
// A signer refusal answers 403 with the signer's detail; every other
// failure the uniform 400. The code, the verifier and the state are never
// logged; only SHA-256(code) is stored. A redeem whose answer is lost is
// not retried: the code is burnt and the signer refuses the request ID
// again (duplicate_request), so the user runs keyroster login again.
func (s *Server) handleLoginRedeem(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.loginClientAllow(w, r, loginRedeemRoute, false) {
		return
	}
	refuse := func(reason, user, lid string) {
		s.logLogin(slog.LevelInfo, eventLoginRedeem, reason, user, lid, r)
		s.writeJSON(w, nil, http.StatusBadRequest, errLoginNotRedeemable)
	}
	if !loginIDRE.MatchString(id) {
		refuse(reasonMalformed, "", "")
		return
	}
	raw, reason := readSignInBody(w, r, maxLoginRedeemBody)
	var in loginRedeemRequest
	if reason == "" && decodeStrict(raw, &in) != nil {
		reason = reasonMalformed
	}
	if reason != "" {
		refuse(reason, "", id)
		return
	}
	if !pkceRE.MatchString(in.CodeVerifier) {
		refuse(reasonLoginVerFmt, "", id)
		return
	}
	code, err := base64.RawURLEncoding.Strict().DecodeString(in.Code)
	if !pkceRE.MatchString(in.Code) || err != nil || len(code) != signInRandomLen {
		refuse(reasonMalformed, "", id)
		return
	}
	ctx := r.Context()
	l, err := s.db.Login(ctx, id)
	if errors.Is(err, serverdb.ErrNotFound) {
		refuse(reasonLoginNoRow, "", id)
		return
	}
	if err != nil {
		s.loginRedeemInternal(w, r, "", id, err)
		return
	}
	if !s.loginUserAllow(w, r, loginRedeemRoute, l.User, id) {
		return
	}
	now := s.clock()
	codeHash := sha256.Sum256(code)
	switch {
	case l.Status != serverdb.LoginApproved:
		refuse(reasonLoginState, l.User, id)
		return
	case subtle.ConstantTimeCompare(codeHash[:], l.CodeHash) != 1:
		refuse(reasonLoginCode, l.User, id)
		return
	case now.After(l.CodeExpires):
		refuse(reasonLoginExpired, l.User, id)
		return
	}
	challenge := sha256.Sum256([]byte(in.CodeVerifier))
	if subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(challenge[:])), []byte(l.CodeChallenge)) != 1 {
		refuse(reasonLoginPKCE, l.User, id)
		return
	}
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	switch err := s.db.RedeemLogin(ctx, id, codeHash[:], now); {
	case errors.Is(err, serverdb.ErrNotFound):
		refuse(reasonLoginState, l.User, id)
		return
	case err != nil:
		s.loginRedeemInternal(w, r, l.User, id, err)
		return
	}
	req, err := wire.ParseLoginIssueRequest(l.Request)
	if err != nil {
		s.loginRedeemInternal(w, r, l.User, id, err)
		return
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceWebAuthnAssertion, Blob: l.Assertion}}
	sctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
	defer cancel()
	resp, err := s.signer.Login(sctx, req)
	if err != nil {
		var refused *wire.ErrorResponse
		if errors.As(err, &refused) && refused.Code == wire.CodeRefused {
			s.logLogin(slog.LevelWarn, eventLoginRedeem, reasonLoginRefused, l.User, id, r)
			s.log.Warn("cli login refused by the signer", "login_id", id, "detail", refused.Message)
			s.writeJSON(w, nil, http.StatusForbidden, serverclient.APIError{Error: refused.Message})
			return
		}
		s.log.Warn("cli login: signer call failed", "login_id", id, "err", err)
		refuse(reasonLoginSigner, l.User, id)
		return
	}
	s.logLogin(slog.LevelInfo, eventLoginRedeem, reasonOK, l.User, id, r)
	s.writeJSON(w, v, http.StatusOK, loginRedeemResponse{Certificate: resp.Cert})
}

// loginInternal answers a login API request that failed on the server's
// side with 500.
func (s *Server) loginInternal(w http.ResponseWriter, r *http.Request, event, user, id string, err error) {
	s.log.Error("cli login", "event", event, "err", err)
	s.logLogin(slog.LevelError, event, reasonSignInInternal, user, id, r)
	s.writeJSON(w, nil, http.StatusInternalServerError, errLoginInternal)
}

// loginRedeemInternal answers a redeem that failed on the server's side:
// the uniform 400, as every redeem failure that is not a signer refusal.
func (s *Server) loginRedeemInternal(w http.ResponseWriter, r *http.Request, user, id string, err error) {
	s.log.Error("cli login redeem", "err", err)
	s.logLogin(slog.LevelError, eventLoginRedeem, reasonSignInInternal, user, id, r)
	s.writeJSON(w, nil, http.StatusBadRequest, errLoginNotRedeemable)
}
