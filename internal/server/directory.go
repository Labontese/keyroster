package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/wire"
)

const (
	// directoryInstallEnvelope is what the JSON object of an install
	// request adds around its two base64 fields: braces, the two keys,
	// quotes and separators, with room to spare.
	directoryInstallEnvelope = 256

	// maxDirectoryInstallBody is the one body limit of POST
	// AdminDirectoryPath, the only admin route that does not use
	// maxAdminBody. It is the padded standard base64 length (4 x ceil(n/3))
	// of wire.MaxDirectoryFrame bytes plus directoryInstallEnvelope:
	// 1 485 568 + 256 = 1 485 824 bytes with today's constants. Every
	// install the signer's frame can carry has Directory plus Sigs below
	// wire.MaxDirectoryFrame bytes, and two separately encoded base64
	// fields are at most 4 bytes longer than one field of their combined
	// length, so every install the signer could accept fits (a directory of
	// exactly wire.MaxDirectory bytes with 64 KiB of signatures is
	// 1 485 514 bytes as JSON). What installs is still decided by the
	// signer's own caps; this limit only bounds what the server reads.
	//
	// requireAdminLimit applies it in its verify-before-body order (02-07
	// pre-merge review, owner decision D2): a declared Content-Length over
	// it gets 413 before any signature work, with the nonce unused; a body
	// sent without a length is read only after the admin signature has
	// verified, and one that turns out larger gets 413, the nonce still
	// unused. The handler never reads an unauthenticated body, so this
	// limit bounds the read of a verified admin's request only.
	maxDirectoryInstallBody = 4*((wire.MaxDirectoryFrame+2)/3) + directoryInstallEnvelope
)

// errMirrorStale means the signer's directory could not be read in the
// version its Status reports: GetDirectory failed, or returned bytes whose
// SHA-256 is not the one Status reported. The mirror then serves nothing.
var errMirrorStale = errors.New("the signer's directory does not match its status")

// directoryView is the signer's installed directory as the server mirrors
// it, checked against the Status it was read under: the version, the
// SHA-256, canonical bytes and signatures, the parsed document, and the
// lookups the handlers need. Version 0 (nothing installed) has no bytes,
// a nil dir and empty lookups. A view is read-only once returned.
type directoryView struct {
	status     *statusView // the Status the view was checked against
	version    uint64
	sha256     [32]byte
	doc, sigs  []byte
	dir        *directory.Directory // nil at version 0
	authorized bool                 // from status, as of that Status
	users      map[string]bool
	// creds holds each user's credential IDs as raw bytes, for the
	// registration's excludeCredentials.
	creds map[string][][]byte
	// credIDs holds every credential ID of the directory, as the string
	// of its raw bytes, for the registration's duplicate check (bytes
	// compared, never a client's text form; 02-08-F10) and the install's
	// newlyBound.
	credIDs map[string]bool
}

// dirMirror holds the directory bytes, signatures and parsed document of
// one SHA-256, the last that matched the signer's Status. It keeps no
// status, TTL or grace window of its own: currentStatus is the one cache.
// A directory reply can be 1 MiB and costs about 4.4 MiB of allocation,
// so it is not read again while Status reports the same SHA-256.
type dirMirror struct {
	mu    sync.Mutex // never held across a signer call or with Server.mu
	entry *directoryView
}

// currentDirectory is the one way a handler reads the installed
// directory. It reads signer state only through currentStatus, and fails
// closed:
//   - a currentStatus error is returned as is;
//   - a Status at directory version 0 gives an empty view, with no signer
//     call;
//   - a Status whose directory SHA-256 equals the held entry's gives the
//     held entry;
//   - otherwise the held entry is dropped first, and GetDirectory is
//     asked. A failure, or bytes whose SHA-256 (or version) is not what
//     Status reported, is errMirrorStale with nothing held, never the
//     previous version. A mismatch also drops the status cache, since that
//     Status is then known to be out of date, so the next request reads
//     Status afresh. An install that landed between the Status read and
//     the fetch therefore fails that one request closed.
//
// The install handler does not write the mirror. It drops the status
// cache after every install (dropStatus), and the mirror follows the
// SHA-256 of the next Status. Only a version installed without this
// server, on the signer socket directly, waits for the status entry to
// age out (statusTTL).
func (s *Server) currentDirectory(ctx context.Context) (*directoryView, error) {
	v, err := s.currentStatus(ctx)
	if err != nil {
		return nil, err
	}
	if v.raw.DirectoryVersion == 0 {
		return &directoryView{status: v, users: map[string]bool{}, creds: map[string][][]byte{}, credIDs: map[string]bool{}}, nil
	}
	s.mirror.mu.Lock()
	e := s.mirror.entry
	if e != nil && e.sha256 == v.raw.DirectorySHA256 && e.version == v.raw.DirectoryVersion {
		s.mirror.mu.Unlock()
		return e.under(v), nil
	}
	s.mirror.entry = nil
	s.mirror.mu.Unlock()

	cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
	defer cancel()
	resp, err := s.signer.GetDirectory(cctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMirrorStale, err)
	}
	if resp.Version != v.raw.DirectoryVersion || sha256.Sum256(resp.Directory) != v.raw.DirectorySHA256 {
		s.dropStatus()
		return nil, fmt.Errorf("%w: status reports version %d, the signer served version %d with another SHA-256", errMirrorStale, v.raw.DirectoryVersion, resp.Version)
	}
	fresh, err := newDirectoryView(resp)
	if err != nil {
		return nil, err
	}
	s.mirror.mu.Lock()
	s.mirror.entry = fresh
	s.mirror.mu.Unlock()
	return fresh.under(v), nil
}

// under returns a copy of e checked against the Status v: the lookups are
// shared, the status and authorization are v's.
func (e *directoryView) under(v *statusView) *directoryView {
	c := *e
	c.status = v
	c.authorized = v.raw.DirectoryAuthorized
	return &c
}

// newDirectoryView parses a GetDirectory answer at a version above 0. A
// directory that does not parse is an error, never "no such user".
func newDirectoryView(resp *wire.GetDirectoryResponse) (*directoryView, error) {
	d, err := directory.Parse(resp.Directory)
	if err != nil {
		return nil, fmt.Errorf("installed directory: %w", err)
	}
	e := &directoryView{
		version: resp.Version, sha256: sha256.Sum256(resp.Directory),
		doc: resp.Directory, sigs: resp.Sigs, dir: d,
		users: map[string]bool{}, creds: map[string][][]byte{}, credIDs: map[string]bool{},
	}
	for _, u := range d.Users {
		e.users[u.Name] = true
		for _, c := range u.Credentials {
			// Parse validated every ID as canonical unpadded base64url.
			id, err := base64.RawURLEncoding.Strict().DecodeString(c.ID)
			if err != nil {
				return nil, fmt.Errorf("installed directory: credential id: %w", err)
			}
			e.creds[u.Name] = append(e.creds[u.Name], id)
			e.credIDs[string(id)] = true
		}
	}
	return e, nil
}

// handleGetDirectory serves GET /api/v1/admin/directory: the installed
// directory's version, canonical bytes, signatures and authorization, as
// the mirror holds them. The CLI trusts none of it before it has verified
// the signatures against the root-verified policy's admins.
func (s *Server) handleGetDirectory(w http.ResponseWriter, r *http.Request) {
	view, err := s.currentDirectory(r.Context())
	if err != nil {
		s.log.Warn("directory read failed", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	s.writeJSON(w, view.status, http.StatusOK, serverclient.DirectoryAnswer{
		Version: view.version, Directory: view.doc, Sigs: view.sigs, Authorized: view.authorized,
	})
}

// handleListUsers serves GET /api/v1/admin/users: the installed
// directory's users with their credentials' fingerprints, and the pending
// accounts. It is the server's view; keyroster directory show prints the
// admin-signed directory itself.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	view, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("directory read failed", "err", err)
		s.signerUnavailable(w, false)
		return
	}
	pending, err := s.db.ListPending(ctx)
	if err != nil {
		s.log.Error("list pending accounts", "err", err)
		s.writeJSON(w, view.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
		return
	}
	ans := serverclient.UsersAnswer{DirectoryVersion: view.version, Users: []serverclient.DirectoryUser{}, Pending: []serverclient.PendingAccount{}}
	if view.dir != nil {
		for _, u := range view.dir.Users {
			du := serverclient.DirectoryUser{Name: u.Name, Status: u.Status, Credentials: []serverclient.UserCredential{}}
			for _, c := range u.Credentials {
				// Parse validated the SPKI as canonical standard base64.
				spki, err := base64.StdEncoding.DecodeString(c.SPKI)
				if err != nil {
					s.log.Error("installed directory credential", "err", err)
					s.writeJSON(w, view.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
					return
				}
				du.Credentials = append(du.Credentials, serverclient.UserCredential{Fingerprint: webauthn.Fingerprint(spki), Alg: c.Alg, Synced: c.BackedUp})
			}
			ans.Users = append(ans.Users, du)
		}
	}
	for _, p := range pending {
		ans.Pending = append(ans.Pending, serverclient.PendingAccount{
			Name: p.Name, InviteExpiresAt: p.InviteExpires.UTC().Format(time.RFC3339), InviteUsed: p.InviteUsed, Credentials: p.Credentials,
		})
	}
	s.log.Info("users listed", "admin", adminName(ctx), "directory_version", view.version, "users", len(ans.Users), "pending", len(ans.Pending))
	s.writeJSON(w, view.status, http.StatusOK, ans)
}

// handleInstallDirectory serves POST /api/v1/admin/directory: it forwards
// an admin-signed directory version to the signer unchanged, under
// pendingMu, in five steps:
//
//  1. Base: the installed directory from currentDirectory. If that fails,
//     503 and nothing is forwarded.
//  2. newlyBound: the credential IDs the posted version binds and the base
//     does not, each with its user, and bound, every binding of the posted
//     version. A document that does not parse has neither and is still
//     forwarded, so the signer refuses it as directory_invalid and logs
//     the refusal.
//  3. Pending check: every newly bound credential must be a pending
//     credential of the user it is bound to, with the same algorithm and
//     key, or 409 credential_not_pending and nothing is forwarded. Once a
//     reinvite has returned, no install through this server binds the
//     credential it discarded, even when the passkey registered after it
//     reuses the discarded credential's ID. The check only
//     ever refuses; a pending row grants nothing (D-03).
//  4. Forward, then dropStatus as soon as InstallDirectory returns,
//     whatever it returned, so the next request reads the signer's state.
//  5. On success, DeleteBound with bound, on a context detached from the
//     request's cancellation (a client that hung up must not leave the
//     approved passkey pending). A cleanup failure is logged as
//     pending_cleanup_failed and the install is still reported (200): the
//     signer has installed the version. The next accepted install removes
//     what was left.
//
// pendingMu orders this handler against a reinvite (handleAddUser): one
// runs after the other, never inside the other's check, forward and
// cleanup (02-09-R2-F1). It is always the outermost lock. Steps 1 and 2 are
// inside it too, so a second install that waited is refused by the
// signer's version chain, not by a misleading credential_not_pending.
func (s *Server) handleInstallDirectory(w http.ResponseWriter, r *http.Request) {
	var req serverclient.InstallDirectoryRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		s.writeAdminError(w, r, http.StatusBadRequest, "malformed request")
		return
	}
	// The signer's message caps: a request outside them cannot be framed,
	// so it is refused here as malformed rather than as a signer failure.
	if len(req.Directory) == 0 || len(req.Directory) > wire.MaxDirectory || len(req.Sigs) == 0 || len(req.Sigs) > wire.MaxDirectorySigs {
		s.writeAdminError(w, r, http.StatusBadRequest, "malformed request")
		return
	}
	ctx := r.Context()
	admin := adminName(ctx)

	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	base, err := s.currentDirectory(ctx)
	if err != nil {
		s.log.Warn("directory install: base unavailable", "admin", admin, "err", err)
		s.signerUnavailable(w, false)
		return
	}
	bound, newlyBound := directoryBindings(req.Directory, base)
	for _, b := range newlyBound {
		pc, err := s.db.PendingCredentialByID(ctx, b.ID)
		if errors.Is(err, serverdb.ErrNotFound) || (err == nil && (pc.UserName != b.User || pc.Alg != b.Alg || !bytes.Equal(pc.SPKI, b.SPKI))) {
			// 409 credential_not_pending, forwarding nothing.
			s.log.Warn("directory install refused", "admin", admin, "reason", serverclient.AdminErrNotPendingCredential, "user", b.User)
			s.writeJSON(w, base.status, http.StatusConflict, serverclient.APIError{Error: serverclient.AdminErrNotPendingCredential})
			return
		}
		if err != nil {
			s.log.Error("read pending credential", "err", err)
			s.writeJSON(w, base.status, http.StatusInternalServerError, serverclient.APIError{Error: "internal error"})
			return
		}
	}

	cctx, cancel := context.WithTimeout(ctx, signerCallTimeout)
	defer cancel()
	resp, err := s.signer.InstallDirectory(cctx, &wire.InstallDirectoryRequest{Directory: req.Directory, Sigs: req.Sigs})
	s.dropStatus()
	if err != nil {
		var refused *wire.ErrorResponse
		if errors.As(err, &refused) {
			code := installRefusalStatus(refused)
			s.log.Warn("directory install refused", "admin", admin, "reason", refused.Message)
			if code == http.StatusServiceUnavailable {
				s.signerUnavailable(w, false)
				return
			}
			s.writeJSON(w, base.status, code, serverclient.APIError{Error: refused.Message})
			return
		}
		// The outcome is unknown: the signer may have installed the
		// version. No cleanup; the next accepted install removes what this
		// one would have (DeleteBound covers every binding).
		s.log.Error("directory install: signer call failed, outcome unknown", "admin", admin, "err", err)
		s.signerUnavailable(w, false)
		return
	}
	// The signer has installed the version: the cleanup runs even when the
	// client has gone away meanwhile, bounded by its own timeout.
	dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), pendingCleanupTimeout)
	defer dcancel()
	if err := s.db.DeleteBound(dctx, bound, s.clock().UnixMicro()); err != nil {
		s.log.Error("pending_cleanup_failed", "version", resp.Version, "err", err)
	}
	sum := hex.EncodeToString(resp.SHA256[:])
	s.log.Info("directory installed", "admin", admin, "version", resp.Version, "sha256", sum, "leaf_index", resp.LeafIndex, "newly_bound", len(newlyBound))
	s.writeJSON(w, base.status, http.StatusOK, serverclient.InstallDirectoryAnswer{Version: resp.Version, SHA256: sum, LeafIndex: resp.LeafIndex})
}

// installRefusalStatus maps a signer refusal of an install to the HTTP
// status the CLI tells apart: 409 for directory_version_chain, 400 for a
// malformed document, 403 for every other refusal, and 503 for a signer
// that could not decide (unavailable or internal).
func installRefusalStatus(e *wire.ErrorResponse) int {
	switch {
	case e.Code == wire.CodeRefused && e.Message == serverclient.AdminErrVersionChain:
		return http.StatusConflict
	case e.Code == wire.CodeMalformed:
		return http.StatusBadRequest
	case e.Code == wire.CodeRefused:
		return http.StatusForbidden
	}
	return http.StatusServiceUnavailable
}

// directoryBindings returns every binding of the posted document (bound)
// and the ones whose credential ID the base does not hold (newlyBound),
// each with the user that holds it in the posted version and its
// algorithm and key (SPKI DER). newlyBound is a
// subset of bound. A document that does not parse has neither.
func directoryBindings(doc []byte, base *directoryView) (bound, newlyBound []serverdb.Binding) {
	d, err := directory.Parse(doc)
	if err != nil {
		return nil, nil
	}
	for _, u := range d.Users {
		for _, c := range u.Credentials {
			// Parse validated every SPKI as canonical standard base64; a
			// key that did not decode would stay nil and match no pending
			// credential.
			spki, _ := base64.StdEncoding.Strict().DecodeString(c.SPKI)
			b := serverdb.Binding{ID: c.ID, User: u.Name, Alg: c.Alg, SPKI: spki}
			bound = append(bound, b)
			// Parse validated every ID as canonical unpadded base64url.
			id, err := base64.RawURLEncoding.Strict().DecodeString(c.ID)
			if err != nil || !base.credIDs[string(id)] {
				newlyBound = append(newlyBound, b)
			}
		}
	}
	return bound, newlyBound
}
