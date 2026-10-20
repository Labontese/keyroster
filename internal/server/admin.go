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
	"sync"
	"time"

	"github.com/Labontese/keyroster/internal/adminauth"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
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
//
//  1. The whole body is read through http.MaxBytesReader with limit, before
//     any signature work: the SSHSIG covers the body's SHA-256, so it must
//     be read first, and limit bounds that read. A body over the limit gets
//     413 at once; nothing is verified and no nonce is consumed. 413, not
//     the uniform 401, because an oversized body is not an authentication
//     failure; the limit is public and the check reads no secret.
//  2. adminauth.Verify checks the signature over r.RequestURI (the raw
//     request-target, never a decoded or cleaned path) against the admins
//     of the root-signed policy in the signer's current Status. The server
//     has no admin list of its own.
//  3. The nonce is consumed before next runs, so a captured request cannot
//     be replayed while the first copy is still running. A failed admin
//     request is retried only by signing it again with a new nonce.
//
// Every authentication failure gets the same 401 body and a specific log
// line; the signature and the body are never logged. next sees the
// verified bytes as r.Body and the admin's name in the request context.
func (s *Server) requireAdminLimit(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				s.log.Warn("admin request body too large", "route", r.Pattern, "limit", limit)
				s.writeJSON(w, nil, http.StatusRequestEntityTooLarge, serverclient.APIError{Error: "request body too large"})
				return
			}
			s.log.Warn("admin request body unreadable", "route", r.Pattern, "err", err)
			s.writeJSON(w, nil, http.StatusBadRequest, serverclient.APIError{Error: "bad request"})
			return
		}
		v, err := s.currentStatus(r.Context())
		if err != nil {
			s.signerUnavailable(w, false)
			return
		}
		now := s.clock()
		admin, nonce, err := adminauth.Verify(r.Header, r.Method, r.RequestURI, body, now, v.policy.Admins)
		if err != nil {
			s.log.Warn("admin authentication failed", "route", r.Pattern, "client", clientKey(r), "reason", err.Error())
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
// decides, and the loser gets the same 409 as a pending name.
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
	pending, err := s.db.PendingUser(ctx, req.Name)
	if err != nil && !errors.Is(err, serverdb.ErrNotFound) {
		s.log.Error("read pending account", "err", err)
		s.writeAdminError(w, r, http.StatusInternalServerError, "internal error")
		return
	}
	v, err := s.currentStatus(ctx)
	if err != nil {
		s.signerUnavailable(w, false)
		return
	}
	users, err := s.installedUsers(ctx, v)
	if err != nil {
		s.log.Error("read the installed directory", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	inDirectory := users[req.Name]
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

// dirUsers is the user names of one installed directory version, keyed
// by that version and the SHA-256 of its canonical bytes.
type dirUsers struct {
	version uint64
	sha256  [32]byte
	users   map[string]bool
}

// dirCache holds the last directory read whose version and hash matched
// the signer's Status. A directory reply can be 1 MiB and costs about
// 4.4 MiB of allocation, so it is not read again while the Status reports
// the same version and hash.
type dirCache struct {
	mu    sync.Mutex
	entry *dirUsers
}

// installedUsers returns the user names of the signer's installed
// directory, read with GetDirectory. A cached read is used only while v
// reports exactly its version and hash; a fresh read is cached only when
// it matches v. A directory that does not parse is an error, never "no
// such user".
func (s *Server) installedUsers(ctx context.Context, v *statusView) (map[string]bool, error) {
	s.dir.mu.Lock()
	e := s.dir.entry
	s.dir.mu.Unlock()
	if e != nil && e.version == v.raw.DirectoryVersion && e.sha256 == v.raw.DirectorySHA256 {
		return e.users, nil
	}
	cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
	defer cancel()
	resp, err := s.signer.GetDirectory(cctx)
	if err != nil {
		return nil, err
	}
	fresh := &dirUsers{version: resp.Version, users: map[string]bool{}}
	if resp.Version != 0 {
		d, err := directory.Parse(resp.Directory)
		if err != nil {
			return nil, err
		}
		for _, u := range d.Users {
			fresh.users[u.Name] = true
		}
		fresh.sha256 = sha256.Sum256(resp.Directory)
	}
	if fresh.version == v.raw.DirectoryVersion && fresh.sha256 == v.raw.DirectorySHA256 {
		s.dir.mu.Lock()
		s.dir.entry = fresh
		s.dir.mu.Unlock()
	}
	return fresh.users, nil
}
