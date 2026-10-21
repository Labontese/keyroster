package serverclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/adminauth"
)

// AdminUsersPath is the admin route that creates a pending account and
// its invite (keyroster user add).
const AdminUsersPath = "/api/v1/admin/users"

// The two 409 refusals of AdminUsersPath. The CLI compares a refusal with
// these exactly and then prints its own words; the server's text itself
// is never printed except as a PeerError excerpt.
const (
	AdminErrPending     = "already pending"
	AdminErrInDirectory = "already in directory"
)

// AdminErrNotPending is the 404 refusal of AdminPendingPath for a name
// that has no pending account.
const AdminErrNotPending = "not pending"

// AdminPendingPath is the admin route that lists the pending credentials
// of the pending account name (keyroster user pending). name must already
// satisfy directory.ValidUserName, whose alphabet needs no escaping.
func AdminPendingPath(name string) string { return AdminUsersPath + "/" + name + "/pending" }

// PendingCredential is one entry of the answer of AdminPendingPath: a
// passkey registered through an invite and not yet bound by an
// admin-signed directory. ID is the unpadded base64url credential ID, SPKI
// the standard base64 of the public key's SPKI DER, Fingerprint
// "SHA256:" and the unpadded base64 of SHA-256(SPKI DER), RegisteredAt RFC
// 3339. The CLI shows only values it re-derives from ID, Alg and SPKI.
type PendingCredential struct {
	ID             string `json:"id"`
	Alg            int64  `json:"alg"`
	SPKI           string `json:"spki"`
	Fingerprint    string `json:"fingerprint"`
	BackupEligible bool   `json:"backup_eligible"`
	BackedUp       bool   `json:"backed_up"`
	RegisteredAt   string `json:"registered_at"`
}

// AddUserRequest is the body of a POST to AdminUsersPath.
type AddUserRequest struct {
	Name     string `json:"name"`
	Reinvite bool   `json:"reinvite"`
}

// AddUserResponse is its 201 answer: the invite URL (a policy origin,
// "/enroll/" and the 43-character token) and its expiry in RFC 3339.
type AddUserResponse struct {
	Name      string `json:"name"`
	InviteURL string `json:"invite_url"`
	ExpiresAt string `json:"expires_at"`
}

// ErrAdminAuth is a 401 from an admin route: the server did not accept
// the request's admin signature (not a policy admin, a clock too far off,
// a replayed nonce, a server URL that is not one of the policy's webauthn
// origins; the server's log says which).
var ErrAdminAuth = errors.New("admin authentication failed")

// ErrAdminBodyTooLarge is a 413 from an admin route.
var ErrAdminBodyTooLarge = errors.New("the server refused the request body as too large")

// clockHint is how far the server's Date may differ from the local clock
// before a 401 names the difference.
const clockHint = 60 * time.Second

// maxRetryAfter bounds a Retry-After value the CLI repeats.
const maxRetryAfter = 3600

// HTTPError is a non-2xx answer other than 503. Its text is the URL, the
// status code and, when the body carried one, the server's error text as
// a PeerError excerpt; the full server text is only compared, never
// printed (APIErrorIs).
type HTTPError struct {
	// Code is the HTTP status code.
	Code       int
	date       string // the response's Date header
	retryAfter string // the response's Retry-After header
	api        string // the server's error text
	err        error
}

func (e *HTTPError) Error() string { return e.err.Error() }
func (e *HTTPError) Unwrap() error { return e.err }

// APIErrorIs reports whether the server's error text is exactly s.
func (e *HTTPError) APIErrorIs(s string) bool { return e.api != "" && e.api == s }

// AdminJSON sends an admin API request: in as the JSON body of method to
// path (a nil in sends no body, and the signature covers the SHA-256 of the
// empty body, as for a GET), signed with signer (in the CLI, agentSigner over the per-OS
// dialAgent, so the private key never leaves ssh-agent), and decodes a 2xx
// JSON answer into out. The signature covers the Client's canonical server
// URL (the origin the request is for, see adminauth), the exact
// request-target the request is sent with (its URL.RequestURI()), the
// body's SHA-256 and a new nonce, so a failed request is retried only by
// calling AdminJSON again; nothing resends old headers and the client has
// no transport-level retry.
//
// The refusals are stated in the CLI's own words: a 401 is ErrAdminAuth,
// with the clock difference when the server's Date differs from the local
// clock by more than a minute; a 413 is ErrAdminBodyTooLarge; a 429 says
// to wait. Any other non-2xx answer is an *HTTPError.
func (c *Client) AdminJSON(ctx context.Context, method, path string, in, out any, signer ssh.Signer) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	err := c.send(ctx, method, path, body, out, func(req *http.Request) error {
		h, err := adminauth.Sign(signer, c.base.String(), req.Method, req.URL.RequestURI(), body, time.Now())
		if err != nil {
			return fmt.Errorf("sign the admin request with %s: %w", ssh.FingerprintSHA256(signer.PublicKey()), err)
		}
		for k, vs := range h {
			req.Header[k] = vs
		}
		return nil
	})
	var he *HTTPError
	if !errors.As(err, &he) {
		return err
	}
	switch he.Code {
	case http.StatusUnauthorized:
		if d, ok := clockDifference(he.date, time.Now()); ok {
			return fmt.Errorf("%s%s: %w (your clock differs from the server by %ds)", c.base, path, ErrAdminAuth, int64(d/time.Second))
		}
		return fmt.Errorf("%s%s: %w", c.base, path, ErrAdminAuth)
	case http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%s%s: %w", c.base, path, ErrAdminBodyTooLarge)
	case http.StatusTooManyRequests:
		if n, err := strconv.Atoi(he.retryAfter); err == nil && n > 0 && n <= maxRetryAfter {
			return fmt.Errorf("%s%s: the server is rate-limiting requests from this address; try again in %d s", c.base, path, n)
		}
		return fmt.Errorf("%s%s: the server is rate-limiting requests from this address; try again later", c.base, path)
	}
	return err
}

// clockDifference returns how far the HTTP date differs from now, as an
// absolute value, and whether that is more than clockHint. Only the
// number reaches the user, never the header's text.
func clockDifference(date string, now time.Time) (time.Duration, bool) {
	if date == "" {
		return 0, false
	}
	t, err := http.ParseTime(date)
	if err != nil {
		return 0, false
	}
	d := t.Sub(now)
	if d < 0 {
		d = -d
	}
	return d, d > clockHint
}
