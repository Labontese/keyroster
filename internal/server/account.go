package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// accountPage is what account.html shows: the signed-in user's own entry
// of the installed directory, read only.
type accountPage struct {
	Name             string
	Status           string
	DirectoryVersion uint64
	Roles            []accountRole
	// TTLCap is the longest certificate a login can get: the smallest of
	// the roles' max TTLs and the user CA's (empty without roles).
	TTLCap      string
	Credentials []accountCredential
}

type accountRole struct {
	Name       string
	Principals []string
	MaxTTL     string
}

type accountCredential struct {
	Fingerprint string
	Algorithm   string
	Kind        string // "synced" (backed up) or "device-bound"
}

// formatTTL writes a TTL in seconds as "3600 s (1h0m0s)".
func formatTTL(seconds uint64) string {
	d := time.Duration(seconds) * time.Second //nolint:gosec // G115: directory and policy TTLs are at most 2^32 s
	return strconv.FormatUint(seconds, 10) + " s (" + d.String() + ")"
}

// userCAMaxTTL is the policy's user CA max TTL, 0 when it names none.
func userCAMaxTTL(p *trust.Policy) uint64 {
	for _, c := range p.CAProfiles {
		if c.Role == trust.RoleUser {
			return c.MaxTTLSeconds
		}
	}
	return 0
}

// newAccountPage builds the account page of user from the directory view
// withSession checked: Authorize(user, nil) for the roles and principals
// (a user without roles shows none), each role's own principals and max
// TTL, the TTL cap, and each bound credential's fingerprint, algorithm and
// backup state.
func newAccountPage(view *directoryView, user string) (*accountPage, error) {
	u, ok := view.activeUser(user)
	if !ok {
		return nil, errors.New("account: user not active in the checked directory")
	}
	page := &accountPage{Name: u.Name, Status: u.Status, DirectoryVersion: view.version}
	g, err := view.dir.Authorize(user, nil)
	switch {
	case errors.Is(err, directory.ErrRoleNotGranted):
	case err != nil:
		return nil, err
	default:
		for _, rn := range g.Roles {
			i := slices.IndexFunc(view.dir.Roles, func(r directory.Role) bool { return r.Name == rn })
			if i < 0 {
				return nil, errors.New("account: granted role not in the directory")
			}
			r := view.dir.Roles[i]
			page.Roles = append(page.Roles, accountRole{Name: r.Name, Principals: r.Principals, MaxTTL: formatTTL(r.MaxTTLSeconds)})
		}
		ttl := g.MaxTTLSeconds
		if ca := userCAMaxTTL(view.status.policy); ca > 0 && ca < ttl {
			ttl = ca
		}
		page.TTLCap = formatTTL(ttl)
	}
	for _, c := range u.Credentials {
		// Parse validated the SPKI as canonical standard base64.
		spki, err := base64.StdEncoding.Strict().DecodeString(c.SPKI)
		if err != nil {
			return nil, err
		}
		kind := "device-bound"
		if c.BackedUp {
			kind = "synced"
		}
		page.Credentials = append(page.Credentials, accountCredential{Fingerprint: webauthn.Fingerprint(spki), Algorithm: algName(c.Alg), Kind: kind})
	}
	return page, nil
}

// handleAccount serves GET /account behind withSession: the signed-in
// user's own name, status, roles with their principals and max TTLs, the
// TTL cap, the directory version and the bound credentials, from the
// directory view the session check used. It shows no other user's data
// and offers no admin action; the only form is logout.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	ws := sessionFrom(r.Context())
	page, err := newAccountPage(ws.view, ws.user)
	if err != nil {
		s.log.Error("account page", "err", err)
		s.internalErrorPage(w, "Something went wrong on the server. Try again in a moment.")
		return
	}
	v := ws.view.status
	d := statusPage(v, "Your account")
	d.RPID = v.rp.RPID
	d.Account = page
	s.renderPage(w, v, http.StatusOK, "account", d)
}
