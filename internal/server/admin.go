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
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/adminauth"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/webauthn"
)

const (
	// maxAdminBody is the default body limit of an admin route: 1 MiB
	// plus 64 KiB. Only 02-09's directory install route names another
	// limit, through requireAdminLimit.
	maxAdminBody = 1<<20 + 64<<10

	// nonceRetention is how long an admin nonce is kept after its first
	// use. A signature stamped t is accepted only while the server clock
	// is within MaxSkew of t, so its first use is no earlier than
	// t - MaxSkew and its last possible use no later than t + MaxSkew:
	// at most 2 x MaxSkew after the first use. The extra second covers
	// the timestamp's whole-second resolution. A nonce row therefore
	// outlives every moment its signature can still be accepted, and a
	// purged nonce belongs to a request the time check refuses anyway
	// (02-07-R2-F2).
	nonceRetention = 2*adminauth.MaxSkew + time.Second

	// inviteTTL is how long an invite is valid (D-03).
	inviteTTL = 24 * time.Hour
	// inviteTokenBytes is the random length of an invite token and of a
	// WebAuthn user handle.
	inviteTokenBytes = 32
	// signerCallTimeout bounds one signer call made by a handler.
	signerCallTimeout = 10 * time.Second
	// pendingCleanupTimeout bounds the pending cleanup after an accepted
	// install, which runs detached from the request (handleInstallDirectory).
	pendingCleanupTimeout = 5 * time.Second
)

// errAdminAuth is the one body of every admin authentication failure.
var errAdminAuth = serverclient.APIError{Error: "admin authentication failed"}

// adminCtxKey keys the verified admin's name in a request context.
type adminCtxKey struct{}

// adminName returns the admin requireAdmin verified for ctx's request.
func adminName(ctx context.Context) string {
	n, _ := ctx.Value(adminCtxKey{}).(string)
	return n
}

// requireAdmin is requireAdminLimit with the default body limit
// maxAdminBody. Every admin route in this plan and in 02-08 uses it.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return s.requireAdminLimit(maxAdminBody, next)
}

// requireAdminLimit authenticates an admin API request before next runs.
// The handler reads no byte of the body before the signature has verified
// and never reads or buffers an unauthenticated body (02-07 pre-merge
// review, owner decision D2). net/http itself still reads some of it.
// Over HTTP/1.1 it may read up to 256 KiB of an unread body into
// io.Discard when the refusal is written, and a stalled body holds the
// connection until the server's ReadTimeout. Over HTTP/2, which the
// server negotiates by default, it copies every DATA frame of the open
// stream into a memory buffer whether or not the handler reads, up to the
// receive windows (by default 1 MiB per stream and 1 MiB per connection),
// frees that buffer when the handler returns and then resets the stream;
// there is no 256 KiB drain:
//
//  1. A request whose declared Content-Length is over limit gets 413 at
//     once: nothing is verified and no nonce is consumed. 413, not the
//     uniform 401, because an oversized body is not an authentication
//     failure; the limit is public and the check reads no secret.
//  2. The request's origin, "https://" + r.Host with a ":443" suffix
//     removed, must be exactly one of the webauthn origins of the
//     root-signed policy in the signer's current Status. That origin is
//     what the signature is checked against, so a request signed for
//     another deployment does not verify here (D1). Unlike requestOrigin
//     there is no fallback.
//  3. adminauth.Verify checks the headers: the signature over the origin,
//     the method, r.RequestURI (the raw request-target, never a decoded or
//     cleaned path), the body digest header, the timestamp and the nonce,
//     against the policy's admins. The server has no admin list of its
//     own.
//  4. Only then is the body read, through http.MaxBytesReader with limit.
//     A body that turns out larger gets 413, with the nonce unused.
//  5. The body's SHA-256 must equal the signed digest (adminauth.CheckBody).
//  6. The nonce is consumed before next runs, so a captured request cannot
//     be replayed while the first copy is still running. A failed admin
//     request is retried only by signing it again with a new nonce.
//
// Every authentication failure gets the same 401 body and a log line with
// a fixed reason; the signature, the digest, the Host header and the body
// are never logged. next sees the verified bytes as r.Body and the admin's
// name in the request context.
func (s *Server) requireAdminLimit(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > limit {
			s.adminBodyTooLarge(w, r, limit)
			return
		}
		v, err := s.currentStatus(r.Context())
		if err != nil {
			s.signerUnavailable(w, false)
			return
		}
		origin := "https://" + strings.TrimSuffix(r.Host, ":443")
		if !slices.Contains(v.rp.Origins, origin) {
			s.log.Warn("admin authentication failed", "route", r.Pattern, "client", clientKey(r), "reason", "request origin is not a policy origin")
			s.writeJSON(w, v, http.StatusUnauthorized, errAdminAuth)
			return
		}
		now := s.clock()
		admin, nonce, digest, err := adminauth.Verify(r.Header, origin, r.Method, r.RequestURI, now, v.policy.Admins)
		if err != nil {
			s.log.Warn("admin authentication failed", "route", r.Pattern, "client", clientKey(r), "reason", err.Error())
			s.writeJSON(w, v, http.StatusUnauthorized, errAdminAuth)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				s.adminBodyTooLarge(w, r, limit)
				return
			}
			s.log.Warn("admin request body unreadable", "route", r.Pattern, "err", err)
			s.writeJSON(w, nil, http.StatusBadRequest, serverclient.APIError{Error: "bad request"})
			return
		}
		if err := adminauth.CheckBody(digest, body); err != nil {
			s.log.Warn("admin authentication failed", "route", r.Pattern, "client", clientKey(r), "admin", admin, "reason", err.Error())
			s.writeJSON(w, v, http.StatusUnauthorized, errAdminAuth)
			return
		}
		if err := s.db.UseNonce(r.Context(), nonce, now.Add(nonceRetention), now); err != nil {
			if errors.Is(err, serverdb.ErrNonceUsed) {
				s.log.Warn("admin authentication failed", "route", r.Pattern, "client", clientKey(r), "admin", admin, "reason", "nonce already used (replay)")
				s.writeJSON(w, v, http.StatusUnauthorized, errAdminAuth)
				return
			}
			s.log.Error("admin nonce", "err", err)
			s.writeJSON(w, v, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminCtxKey{}, admin)))
	})
}

// adminBodyTooLarge answers an admin request whose body is over limit.
func (s *Server) adminBodyTooLarge(w http.ResponseWriter, r *http.Request, limit int64) {
	s.log.Warn("admin request body too large", "route", r.Pattern, "limit", limit)
	s.writeJSON(w, nil, http.StatusRequestEntityTooLarge, serverclient.APIError{Error: "request body too large"})
}

// handleAddUser creates a pending account, or replaces its invite, and
// returns the invite URL. The account is not authority: the signer's
// directory is unchanged, so it cannot sign in or obtain a certificate
// until an admin-signed directory binds a credential (D-03).
//
// It looks the name up in a fixed order, first in pending_users and then
// in the installed directory, and decides with the pending check first:
//   - without reinvite, a pending name or a directory name is refused 409;
//   - with reinvite and a pending row, ReplaceInvite gives the row a new
//     token and keeps its user handle (also for a directory user whose
//     extra-passkey invite is still open); it never inserts;
//   - with reinvite and no pending row, a directory user gets a new
//     pending row for one additional credential, with a fresh handle;
//   - with reinvite and the name in neither place, it is a plain add.
//
// The lookups and the insert are separate statements, so two adds for one
// new name can both pass the lookups; the pending_users primary key
// decides, and the loser gets the same 409 as a pending name. A reinvite
// holds pendingMu from its lookups through its write, so a directory
// install never runs between them (02-09-R2-F1).
func (s *Server) handleAddUser(w http.ResponseWriter, r *http.Request) {
	var req serverclient.AddUserRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		s.writeAdminError(w, r, http.StatusBadRequest, "malformed request")
		return
	}
	if !directory.ValidUserName(req.Name) {
		s.writeAdminError(w, r, http.StatusBadRequest, "invalid user name")
		return
	}
	ctx := r.Context()
	if req.Reinvite {
		// A reinvite discards the pending credential a directory install
		// may be about to bind: it waits for an install in flight, from
		// before its lookups until its row is written, and an install
		// waits for it (pendingMu, 02-09-R2-F1). A plain add discards
		// nothing an install checks and does not take the lock.
		s.pendingMu.Lock()
		defer s.pendingMu.Unlock()
	}
	pending, err := s.db.PendingUser(ctx, req.Name)
	if err != nil && !errors.Is(err, serverdb.ErrNotFound) {
		s.log.Error("read pending account", "err", err)
		s.writeAdminError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	dir, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Error("read the installed directory", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	v := dir.status
	inDirectory := dir.users[req.Name]
	switch {
	case !req.Reinvite && pending != nil:
		s.writeAdminError(w, r, http.StatusConflict, serverclient.AdminErrPending)
		return
	case !req.Reinvite && inDirectory:
		s.writeAdminError(w, r, http.StatusConflict, serverclient.AdminErrInDirectory)
		return
	}

	token, hash, err := newInviteToken()
	if err != nil {
		s.log.Error("invite token", "err", err)
		s.writeAdminError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	now := s.clock()
	expires := now.Add(inviteTTL)
	if pending != nil {
		// Reinvite of a pending row: replace its token in place.
		if err := s.db.ReplaceInvite(ctx, req.Name, hash, expires.UnixMicro()); err != nil {
			s.log.Error("replace invite", "name", req.Name, "err", err)
			s.writeAdminError(w, r, http.StatusInternalServerError, "internal error")
			return
		}
	} else {
		handle := make([]byte, inviteTokenBytes)
		if _, err := rand.Read(handle); err != nil {
			s.log.Error("user handle", "err", err)
			s.writeAdminError(w, r, http.StatusInternalServerError, "internal error")
			return
		}
		err := s.db.CreatePendingUser(ctx, serverdb.PendingUser{
			Name: req.Name, UserHandle: handle, InviteHash: hash, InviteExpires: expires,
			Created: now, CreatedBy: adminName(ctx),
		})
		if errors.Is(err, serverdb.ErrExists) {
			// Another add for this name won the insert after our lookup.
			s.writeAdminError(w, r, http.StatusConflict, serverclient.AdminErrPending)
			return
		}
		if err != nil {
			s.log.Error("create pending account", "name", req.Name, "err", err)
			s.writeAdminError(w, r, http.StatusInternalServerError, "internal error")
			return
		}
	}
	s.log.Info("invite created", "name", req.Name, "admin", adminName(ctx), "reinvite", req.Reinvite,
		"replaced", pending != nil, "in_directory", inDirectory, "expires", expires.UTC().Format(time.RFC3339))
	s.writeJSON(w, v, http.StatusCreated, serverclient.AddUserResponse{
		Name:      req.Name,
		InviteURL: requestOrigin(r, v.rp.Origins) + "/enroll/" + token,
		ExpiresAt: expires.UTC().Format(time.RFC3339),
	})
}

// handlePendingCredentials serves GET /api/v1/admin/users/{name}/pending:
// the state of the pending account's current invite (open, expired or
// used, under the server clock and the comparison the invite lookup
// uses, with its expiry) and the credentials the account registered
// through its invite that no admin-signed directory binds yet, with the
// same fingerprint the registration page showed the user. A name with no
// pending account is 404 not pending. Nothing here is authority: the
// admin compares the fingerprint out of band and binds the credential
// with a signed directory (02-09).
func (s *Server) handlePendingCredentials(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !directory.ValidUserName(name) {
		s.writeAdminError(w, r, http.StatusBadRequest, "invalid user name")
		return
	}
	ctx := r.Context()
	// One snapshot: a reinvite or a registration committing between
	// separate reads would give an answer no state ever held (02-08
	// pre-merge review).
	st, err := s.db.PendingState(ctx, name)
	if err != nil {
		if errors.Is(err, serverdb.ErrNotFound) {
			s.writeAdminError(w, r, http.StatusNotFound, serverclient.AdminErrNotPending)
			return
		}
		s.log.Error("read pending account", "err", err)
		s.writeAdminError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	invite := serverclient.PendingInvite{State: serverclient.InviteOpen, ExpiresAt: st.User.InviteExpires.UTC().Format(time.RFC3339)}
	switch {
	case st.InviteUsed:
		invite.State = serverclient.InviteUsed
	case st.User.InviteExpires.UnixMicro() <= s.clock().UnixMicro():
		// PendingUserByInvite's invite_expires_us > now, negated.
		invite.State = serverclient.InviteExpired
	}
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	out := make([]serverclient.PendingCredential, 0, len(st.Credentials))
	for _, c := range st.Credentials {
		out = append(out, serverclient.PendingCredential{
			ID:             c.ID,
			Alg:            c.Alg,
			SPKI:           base64.StdEncoding.EncodeToString(c.SPKI),
			Fingerprint:    webauthn.Fingerprint(c.SPKI),
			BackupEligible: c.BackupEligible,
			BackedUp:       c.BackedUp,
			RegisteredAt:   c.Registered.UTC().Format(time.RFC3339),
		})
	}
	s.log.Info("pending credentials listed", "name", name, "admin", adminName(ctx), "count", len(out), "invite", invite.State)
	s.writeJSON(w, v, http.StatusOK, serverclient.PendingAnswer{Invite: invite, Credentials: out})
}

// writeAdminError answers an admin request that passed requireAdmin with
// code and msg, with the custody header of a current status when there is
// one.
func (s *Server) writeAdminError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	v, err := s.currentStatus(r.Context())
	if err != nil {
		v = nil
	}
	s.writeJSON(w, v, code, serverclient.APIError{Error: msg})
}

// newInviteToken returns a 32-byte random invite token, base64url without
// padding (43 characters), and its SHA-256, the only form that is stored.
func newInviteToken() (token string, hash []byte, err error) {
	raw := make([]byte, inviteTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// requestOrigin picks the policy origin an invite or approval link names:
// the one equal to "https://" + r.Host (a ":443" suffix removed), so the
// link points at the port the admin reached, and otherwise the first of
// origins in sorted order. Every candidate is a policy origin, so the
// choice cannot weaken the signer's origin check; a forged Host changes at
// most which listed origin the link names (T-02-96).
func requestOrigin(r *http.Request, origins []string) string {
	want := "https://" + strings.TrimSuffix(r.Host, ":443")
	if slices.Contains(origins, want) {
		return want
	}
	sorted := slices.Sorted(slices.Values(origins))
	if len(sorted) == 0 {
		return ""
	}
	return sorted[0]
}
