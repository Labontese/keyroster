package serverclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/adminauth"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/wire"
)

// AdminUsersPath is the admin route that creates a pending account and
// its invite (POST, keyroster user add) and lists the directory's users
// and the pending accounts (GET, keyroster user list).
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

// PendingAnswer is the 200 answer of AdminPendingPath: the state of the
// pending account's current invite and the passkeys registered with it.
type PendingAnswer struct {
	Invite      PendingInvite       `json:"invite"`
	Credentials []PendingCredential `json:"credentials"`
}

// The states of PendingInvite: a current invite that has not expired and
// has registered no passkey, one that expired unused, and one that
// registered its passkey.
const (
	InviteOpen    = "open"
	InviteExpired = "expired"
	InviteUsed    = "used"
)

// PendingInvite is the state of a pending account's current invite:
// State is InviteOpen, InviteExpired or InviteUsed, and ExpiresAt the RFC
// 3339 UTC time the invite expires or expired.
type PendingInvite struct {
	State     string `json:"state"`
	ExpiresAt string `json:"expires_at"`
}

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

// AdminDirectoryPath is the admin route of the installed directory: GET
// answers DirectoryAnswer, POST installs an InstallDirectoryRequest
// through the signer (02-09).
const AdminDirectoryPath = "/api/v1/admin/directory"

// DirectoryAnswer is the answer of a GET to AdminDirectoryPath: the
// signer's installed directory as the server mirrors it, version 0 with
// no bytes when none is installed. Directory and Sigs are standard base64
// with padding in JSON. Nothing in it is trusted by the CLI until it has
// verified Sigs against the admins of the root-verified policy.
type DirectoryAnswer struct {
	Version    uint64 `json:"version"`
	Directory  []byte `json:"directory"`
	Sigs       []byte `json:"sigs"`
	Authorized bool   `json:"authorized"`
}

// InstallDirectoryRequest is the body of a POST to AdminDirectoryPath: a
// directory version's canonical bytes and the admins' armored SSHSIG
// signatures over them, both standard base64 with padding in JSON.
type InstallDirectoryRequest struct {
	Directory []byte `json:"directory"`
	Sigs      []byte `json:"sigs"`
}

// InstallDirectoryAnswer is the 200 answer of a POST to
// AdminDirectoryPath: the installed version, the lowercase hex SHA-256 of
// its bytes and the index of the log leaf that recorded the install.
type InstallDirectoryAnswer struct {
	Version   uint64 `json:"version"`
	SHA256    string `json:"sha256"`
	LeafIndex uint64 `json:"leaf_index"`
}

// AdminRevokePath is the admin route of a revocation (POST, keyroster
// revoke): its body is a RevokeBody carrying the admin-signed
// wire.RevokeRequest, which the server forwards to the signer unchanged.
// The server holds no revocation authority (REVOKE-01, D-12).
const AdminRevokePath = "/api/v1/admin/revoke"

// KRLPath is the public route of the published KRL (GET): a KRLDocument,
// or 404 KRLErrNone when nothing is published yet.
const KRLPath = "/api/v1/krl"

// KRLErrNone is the 404 answer of KRLPath before the first publish.
const KRLErrNone = "no_krl"

// KRLMaxStale is how long keyroster-server serves a KRL it read from the
// signer before it reads it again: a KRL the signer changed other than
// by a revocation through that server reaches KRLPath at most this late.
const KRLMaxStale = 5 * time.Second

// RevokeBody is the body of a POST to AdminRevokePath: the RevokeRequest's
// wire bytes (wire.RevokeRequest.Marshal, evidence included), standard
// base64 with padding in JSON.
type RevokeBody struct {
	Request []byte `json:"request"`
}

// RevokeAnswer is the 200 answer of a POST to AdminRevokePath: the KRL
// version the signer published with the revocation and the indexes of its
// revoke and krl_publish log entries. For a subject revocation SerialCount
// is the number of certificates it resolved to and Serials the first
// wire.MaxRevokeAnswerSerials of their serials, ascending; both are empty
// for the other targets. The server copies them from the signer's
// wire.RevokeResponse; nothing in the answer is signed.
type RevokeAnswer struct {
	KRLVersion  uint64   `json:"krl_version"`
	RevokeLeaf  uint64   `json:"revoke_leaf"`
	PublishLeaf uint64   `json:"publish_leaf"`
	SerialCount uint32   `json:"serial_count"`
	Serials     []uint64 `json:"serials"`
}

// errBadRevokeAnswer refuses a revoke answer whose serials the signer
// would never send. It never repeats the server's text.
var errBadRevokeAnswer = errors.New("the revoke answer's serials are not a list the signer sends " +
	"(at most 4096, ascending and unique, exactly min(serial_count, 4096) of them)")

// UnmarshalJSON decodes a RevokeAnswer and applies wire.RevokeResponse's
// rule to its serials: at most wire.MaxRevokeAnswerSerials, ascending and
// unique, and exactly min(SerialCount, wire.MaxRevokeAnswerSerials) of
// them (so a count below the list is refused).
func (a *RevokeAnswer) UnmarshalJSON(b []byte) error {
	type plain RevokeAnswer
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	n := len(p.Serials)
	if n > wire.MaxRevokeAnswerSerials || uint64(n) != min(uint64(p.SerialCount), wire.MaxRevokeAnswerSerials) {
		return errBadRevokeAnswer
	}
	for i := 1; i < n; i++ {
		if p.Serials[i] <= p.Serials[i-1] {
			return errBadRevokeAnswer
		}
	}
	*a = RevokeAnswer(p)
	return nil
}

// KRLDocument is the 200 answer of KRLPath: the KRL bytes, the canonical
// manifest and the ops key's armored SSHSIG over it, each standard base64
// with padding in JSON. Its size is bounded by krl.MaxKRLResponse.
type KRLDocument struct {
	KRL      []byte `json:"krl"`
	Manifest []byte `json:"manifest"`
	Sig      []byte `json:"sig"`
}

// DecodeKRLDocument decodes one KRLDocument strictly (03-06b): at most
// krl.MaxKRLResponse bytes, one JSON object with exactly the three fields,
// each non-empty, and nothing after it but white space. keyroster-server
// reads its durable copy (krl-served.json) with it, and keyroster revoke
// recover every --krl document. Nothing in the result is trusted until
// krl.VerifyManifest has checked it.
func DecodeKRLDocument(data []byte) (*KRLDocument, error) {
	if len(data) > krl.MaxKRLResponse {
		return nil, fmt.Errorf("a KRL document of %d bytes, above %d", len(data), krl.MaxKRLResponse)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var doc KRLDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a KRL document: %w", decodeError(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("not a KRL document: data after the JSON object")
	}
	if len(doc.KRL) == 0 || len(doc.Manifest) == 0 || len(doc.Sig) == 0 {
		return nil, errors.New("not a KRL document: krl, manifest and sig are each required")
	}
	return &doc, nil
}

// The refusals of a POST to AdminDirectoryPath that the CLI tells apart.
// AdminErrNotPendingCredential (409) is the server's own: the version
// binds a credential that is not a pending credential of the user it
// binds it to. The others are the signer's reason codes, passed through:
// AdminErrVersionChain (409), AdminErrQuorum and AdminErrExceedsPolicy
// (403), AdminErrInvalid (400).
const (
	AdminErrNotPendingCredential = "credential_not_pending" //nolint:gosec // G101: a refusal reason code, not a credential
	AdminErrVersionChain         = "directory_version_chain"
	AdminErrQuorum               = "directory_quorum_not_met"
	AdminErrExceedsPolicy        = "directory_exceeds_policy"
	AdminErrInvalid              = "directory_invalid"
	// The installation binding refusals (D-04, 03-04), 403.
	AdminErrInstallationMissing  = "directory_installation_missing"
	AdminErrInstallationMismatch = "directory_installation_mismatch"
	AdminErrInstallationUnknown  = "directory_installation_unknown"
)

// UsersAnswer is the answer of a GET to AdminUsersPath: the users of the
// installed directory, as the server mirrors it, and the pending accounts
// of the server. It is the server's view; the CLI validates every field
// it prints, and keyroster directory show prints the admin-signed
// directory itself.
type UsersAnswer struct {
	DirectoryVersion uint64           `json:"directory_version"`
	Users            []DirectoryUser  `json:"users"`
	Pending          []PendingAccount `json:"pending"`
}

// DirectoryUser is one user of the installed directory: its name, status
// (active or disabled) and bound credentials.
type DirectoryUser struct {
	Name        string           `json:"name"`
	Status      string           `json:"status"`
	Credentials []UserCredential `json:"credentials"`
}

// UserCredential is one bound credential: the fingerprint of its key, its
// COSE algorithm and whether it is synced (backed up).
type UserCredential struct {
	Fingerprint string `json:"fingerprint"`
	Alg         int64  `json:"alg"`
	Synced      bool   `json:"synced"`
}

// PendingAccount is one pending account of the server: when its current
// invite expires (RFC 3339), whether it registered a passkey, and how
// many unapproved passkeys it holds.
type PendingAccount struct {
	Name            string `json:"name"`
	InviteExpiresAt string `json:"invite_expires_at"`
	InviteUsed      bool   `json:"invite_used"`
	Credentials     int    `json:"credentials"`
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

// RateLimited reports whether e is a 429 whose Retry-After is a whole
// number of seconds from 1 to an hour, and that number.
func (e *HTTPError) RateLimited() (int, bool) {
	if e.Code != http.StatusTooManyRequests {
		return 0, false
	}
	n, err := strconv.Atoi(e.retryAfter)
	if err != nil || n < 1 || n > maxRetryAfter {
		return 0, false
	}
	return n, true
}

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
	}, maxResponse)
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
