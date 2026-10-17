package directory

import (
	"encoding/base64"
	"fmt"
	"slices"

	"github.com/Labontese/keyroster/internal/webauthn"
)

// Grant is what a directory grants a user for one login (D-08): the
// selected roles, the union of their principals and extensions, and the
// smallest of their max TTLs. Every list is sorted.
type Grant struct {
	Roles         []string
	Principals    []string
	MaxTTLSeconds uint64
	Extensions    []string
}

// Authorize computes the grant of user for the requested roles: the
// requested subset of the user's effective roles (direct and via groups),
// or all of them when roles is empty. An unknown user is ErrUnknownUser, a
// disabled one ErrUserDisabled, a requested role the user does not hold
// (or a user holding no role) ErrRoleNotGranted.
func (d *Directory) Authorize(user string, roles []string) (Grant, error) {
	idx := slices.IndexFunc(d.Users, func(u User) bool { return u.Name == user })
	if idx < 0 {
		return Grant{}, ErrUnknownUser
	}
	if d.Users[idx].Status != StatusActive {
		return Grant{}, ErrUserDisabled
	}
	effective, err := d.userRoles(user)
	if err != nil {
		return Grant{}, err
	}
	selected := effective
	if len(roles) > 0 {
		selected = make([]string, 0, len(roles))
		for _, r := range roles {
			if !slices.Contains(effective, r) {
				return Grant{}, fmt.Errorf("%w: %q", ErrRoleNotGranted, r)
			}
			if !slices.Contains(selected, r) {
				selected = append(selected, r)
			}
		}
		slices.Sort(selected)
	}
	if len(selected) == 0 {
		return Grant{}, fmt.Errorf("%w: the user holds no role", ErrRoleNotGranted)
	}
	g := Grant{Roles: slices.Clone(selected)}
	principals, extensions := map[string]bool{}, map[string]bool{}
	for _, rn := range selected {
		r := d.Roles[slices.IndexFunc(d.Roles, func(r Role) bool { return r.Name == rn })]
		for _, p := range r.Principals {
			principals[p] = true
		}
		for _, e := range r.Extensions {
			extensions[e] = true
		}
		if g.MaxTTLSeconds == 0 || r.MaxTTLSeconds < g.MaxTTLSeconds {
			g.MaxTTLSeconds = r.MaxTTLSeconds
		}
	}
	g.Principals = sortedKeys(principals)
	g.Extensions = sortedKeys(extensions)
	return g, nil
}

// Credential returns the credential with ID id bound to user, if any.
func (d *Directory) Credential(user string, id []byte) (webauthn.Credential, bool) {
	idx := slices.IndexFunc(d.Users, func(u User) bool { return u.Name == user })
	if idx < 0 || len(id) == 0 {
		return webauthn.Credential{}, false
	}
	want := base64.RawURLEncoding.EncodeToString(id)
	for _, c := range d.Users[idx].Credentials {
		if c.ID != want {
			continue
		}
		spki, err := base64.StdEncoding.Strict().DecodeString(c.SPKI)
		if err != nil {
			return webauthn.Credential{}, false
		}
		return webauthn.Credential{ID: append([]byte(nil), id...), Alg: c.Alg, SPKI: spki}, true
	}
	return webauthn.Credential{}, false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
