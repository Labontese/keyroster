package server

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/Labontese/keyroster/internal/serverdb"
)

// inviteTokenLen is the length of an invite token: 32 bytes as unpadded
// base64url.
const inviteTokenLen = 43

// handleEnroll serves GET /enroll/{token}: the invite page of a pending
// account whose current invite has not expired. An unknown, expired or
// replaced token gets the same "invite not valid" page with 404. The token
// is looked up only as its SHA-256 and is never logged; the page carries
// Referrer-Policy no-referrer (secure), so it does not leak to another
// site. The page has no script yet; 02-08 adds the registration ceremony.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	v, err := s.currentStatus(r.Context())
	if err != nil {
		s.signerUnavailable(w, true)
		return
	}
	token := r.PathValue("token")
	if !validInviteToken(token) {
		s.inviteNotValid(w, v)
		return
	}
	sum := sha256.Sum256([]byte(token))
	u, err := s.db.PendingUserByInvite(r.Context(), sum[:], s.clock())
	if errors.Is(err, serverdb.ErrNotFound) {
		s.inviteNotValid(w, v)
		return
	}
	if err != nil {
		s.log.Error("read invite", "err", err)
		s.renderPage(w, v, http.StatusInternalServerError, "error", pageData{Title: "Error", Message: "Something went wrong. Try again later."})
		return
	}
	d := statusPage(v, "Invite for "+u.Name)
	d.User = u.Name
	d.RPID = v.rp.RPID
	d.Expires = u.InviteExpires.UTC().Format(time.RFC3339)
	s.renderPage(w, v, http.StatusOK, "enroll", d)
}

// inviteNotValid is the one answer to every token that does not open an
// invite.
func (s *Server) inviteNotValid(w http.ResponseWriter, v *statusView) {
	d := statusPage(v, "Invite not valid")
	d.Message = "This invite link is not valid. It may have expired or been replaced by a newer one. Ask your admin for a new invite."
	s.renderPage(w, v, http.StatusNotFound, "error", d)
}

// validInviteToken reports whether t has the form of an invite token, so
// nothing else is hashed and looked up.
func validInviteToken(t string) bool {
	if len(t) != inviteTokenLen {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(t)
	return err == nil && len(raw) == inviteTokenBytes && base64.RawURLEncoding.EncodeToString(raw) == t
}
