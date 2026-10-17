// Package directory is the admin-signed directory document (D-01): the
// users, their bound WebAuthn credentials, groups, roles and host groups.
// A directory version is canonical JSON, chained to its predecessor by
// SHA-256, and authoritative only when at least the root-signed policy's
// admin quorum signed it with SSHSIG under Namespace. The signer installs
// it online and computes principals and TTL caps from it (D-08).
//
// The package imports only the standard library, internal/trust,
// internal/cert, internal/webauthn and golang.org/x/crypto/ssh: it is in
// the signer's dependency graph and must stay network-less.
package directory

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// Namespace is the SSHSIG namespace of admin signatures over a directory.
const Namespace = "keyroster/directory/v1"

// Limits of a directory.
const (
	// MaxRolesPerUser bounds a user's effective roles (direct and via
	// groups), which bounds the roles field of a kr2 key ID.
	MaxRolesPerUser = 16
	// MaxRolePrincipals bounds the principals one role grants.
	MaxRolePrincipals = 32
	// MinRoleTTLSeconds is the shortest role max TTL.
	MinRoleTTLSeconds = 60
	// maxCredentialID is the longest credential ID (W3C WebAuthn: 1023).
	maxCredentialID = 1023
)

// User statuses.
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// Errors.
var (
	ErrInvalid        = errors.New("directory: invalid document")
	ErrQuorum         = errors.New("directory: admin quorum not met")
	ErrChain          = errors.New("directory: version or prev hash breaks the chain")
	ErrPolicy         = errors.New("directory: exceeds the policy in force")
	ErrUnknownUser    = errors.New("directory: unknown user")
	ErrUserDisabled   = errors.New("directory: user disabled")
	ErrRoleNotGranted = errors.New("directory: role not granted to the user")
)

// Directory is one version of the directory document. Every list is
// non-null, sorted and duplicate-free (Sort puts them in order).
type Directory struct {
	Version    uint64      `json:"version"`
	Prev       string      `json:"prev"`
	Users      []User      `json:"users"`
	Groups     []Group     `json:"groups"`
	Roles      []Role      `json:"roles"`
	HostGroups []HostGroup `json:"host_groups"`
}

// User is a directory user and the WebAuthn credentials bound to it.
type User struct {
	Name        string       `json:"name"`
	Status      string       `json:"status"`
	Credentials []Credential `json:"credentials"`
}

// Credential is one bound WebAuthn credential: ID (unpadded base64url),
// COSE algorithm, SPKI DER (standard base64) and the backup-eligible and
// backed-up flags recorded at registration (D-05).
type Credential struct {
	ID             string `json:"id"`
	Alg            int64  `json:"alg"`
	SPKI           string `json:"spki"`
	BackupEligible bool   `json:"backup_eligible"`
	BackedUp       bool   `json:"backed_up"`
}

// Group is a named set of users.
type Group struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// Role maps users and groups to principals, with its own max TTL and the
// extensions a certificate under it may request.
type Role struct {
	Name          string   `json:"name"`
	Principals    []string `json:"principals"`
	MaxTTLSeconds uint64   `json:"max_ttl_seconds"`
	Extensions    []string `json:"extensions"`
	Users         []string `json:"users"`
	Groups        []string `json:"groups"`
}

// HostGroup maps each local account of a set of hosts to the roles whose
// principals it accepts.
type HostGroup struct {
	Name     string       `json:"name"`
	Accounts []AccountMap `json:"accounts"`
}

// AccountMap is one local account and the roles it accepts.
type AccountMap struct {
	Account string   `json:"account"`
	Roles   []string `json:"roles"`
}

var (
	nameRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	roleRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)
	accountRE = regexp.MustCompile(`^[a-z_][a-z0-9_.-]{0,31}$`)
)

// Parse decodes a canonical directory and validates it.
func Parse(data []byte) (*Directory, error) {
	var d Directory
	if err := trust.DecodeStrict(data, &d); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

// Canonical returns the canonical encoding of d (the bytes admins sign).
func (d *Directory) Canonical() ([]byte, error) { return trust.CanonicalJSON(d) }

// Sort puts every list of d in canonical order and replaces nil lists by
// empty ones, so a builder produces the same bytes whatever order it added
// entries in. It does not remove duplicates; Validate refuses them.
func (d *Directory) Sort() {
	d.Users = nonNil(d.Users)
	d.Groups = nonNil(d.Groups)
	d.Roles = nonNil(d.Roles)
	d.HostGroups = nonNil(d.HostGroups)
	sort.SliceStable(d.Users, func(i, j int) bool { return d.Users[i].Name < d.Users[j].Name })
	for i := range d.Users {
		u := &d.Users[i]
		u.Credentials = nonNil(u.Credentials)
		sort.SliceStable(u.Credentials, func(a, b int) bool { return u.Credentials[a].ID < u.Credentials[b].ID })
	}
	sort.SliceStable(d.Groups, func(i, j int) bool { return d.Groups[i].Name < d.Groups[j].Name })
	for i := range d.Groups {
		d.Groups[i].Members = sortedStrings(d.Groups[i].Members)
	}
	sort.SliceStable(d.Roles, func(i, j int) bool { return d.Roles[i].Name < d.Roles[j].Name })
	for i := range d.Roles {
		r := &d.Roles[i]
		r.Principals = sortedStrings(r.Principals)
		r.Extensions = sortedStrings(r.Extensions)
		r.Users = sortedStrings(r.Users)
		r.Groups = sortedStrings(r.Groups)
	}
	sort.SliceStable(d.HostGroups, func(i, j int) bool { return d.HostGroups[i].Name < d.HostGroups[j].Name })
	for i := range d.HostGroups {
		h := &d.HostGroups[i]
		h.Accounts = nonNil(h.Accounts)
		sort.SliceStable(h.Accounts, func(a, b int) bool { return h.Accounts[a].Account < h.Accounts[b].Account })
		for j := range h.Accounts {
			h.Accounts[j].Roles = sortedStrings(h.Accounts[j].Roles)
		}
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func sortedStrings(s []string) []string {
	s = nonNil(s)
	slices.Sort(s)
	return s
}

// Validate checks every structural rule of a directory (see the package
// documentation and the 02-01 plan): version and chain fields, name
// grammars, credentials (strict encodings, supported algorithm, a key that
// parses for it, IDs unique across the document), role principals and
// TTLs, sorted duplicate-free non-null lists, references that resolve, a
// credential for every active user, and per-user role and principal
// bounds.
func (d *Directory) Validate() error {
	if d.Version < 1 {
		return fmt.Errorf("%w: version must be >= 1", ErrInvalid)
	}
	if !isHash(d.Prev) {
		return fmt.Errorf("%w: prev must be 64 lowercase hex digits", ErrInvalid)
	}
	if d.Version == 1 && d.Prev != trust.GenesisPrev {
		return fmt.Errorf("%w: a version 1 directory must have an all-zero prev", ErrInvalid)
	}
	if d.Users == nil || d.Groups == nil || d.Roles == nil || d.HostGroups == nil {
		return fmt.Errorf("%w: users, groups, roles and host_groups must be arrays, not null", ErrInvalid)
	}

	users := map[string]*User{}
	credIDs := map[string]bool{}
	if err := checkSorted("users", names(d.Users, func(u User) string { return u.Name })); err != nil {
		return err
	}
	for i := range d.Users {
		u := &d.Users[i]
		if !nameRE.MatchString(u.Name) {
			return fmt.Errorf("%w: user %q: invalid name", ErrInvalid, u.Name)
		}
		if u.Status != StatusActive && u.Status != StatusDisabled {
			return fmt.Errorf("%w: user %s: status %q (want active or disabled)", ErrInvalid, u.Name, u.Status)
		}
		if u.Credentials == nil {
			return fmt.Errorf("%w: user %s: credentials must be an array, not null", ErrInvalid, u.Name)
		}
		if err := checkSorted("user "+u.Name+" credentials", names(u.Credentials, func(c Credential) string { return c.ID })); err != nil {
			return err
		}
		for _, c := range u.Credentials {
			if err := c.validate(); err != nil {
				return fmt.Errorf("user %s: %w", u.Name, err)
			}
			if credIDs[c.ID] {
				return fmt.Errorf("%w: credential %s is bound more than once", ErrInvalid, c.ID)
			}
			credIDs[c.ID] = true
		}
		if u.Status == StatusActive && len(u.Credentials) == 0 {
			return fmt.Errorf("%w: active user %s has no credential", ErrInvalid, u.Name)
		}
		users[u.Name] = u
	}

	groups := map[string]*Group{}
	if err := checkSorted("groups", names(d.Groups, func(g Group) string { return g.Name })); err != nil {
		return err
	}
	for i := range d.Groups {
		g := &d.Groups[i]
		if !nameRE.MatchString(g.Name) {
			return fmt.Errorf("%w: group %q: invalid name", ErrInvalid, g.Name)
		}
		if err := checkRefs("group "+g.Name+" members", g.Members, func(n string) bool { return users[n] != nil }); err != nil {
			return err
		}
		groups[g.Name] = g
	}

	roles := map[string]*Role{}
	if err := checkSorted("roles", names(d.Roles, func(r Role) string { return r.Name })); err != nil {
		return err
	}
	for i := range d.Roles {
		r := &d.Roles[i]
		if !roleRE.MatchString(r.Name) {
			return fmt.Errorf("%w: role %q: invalid name", ErrInvalid, r.Name)
		}
		if len(r.Principals) == 0 || len(r.Principals) > MaxRolePrincipals {
			return fmt.Errorf("%w: role %s: needs 1 to %d principals", ErrInvalid, r.Name, MaxRolePrincipals)
		}
		if err := cert.ValidatePrincipals(r.Principals); err != nil {
			return fmt.Errorf("%w: role %s: %w", ErrInvalid, r.Name, err)
		}
		if err := checkSorted("role "+r.Name+" principals", r.Principals); err != nil {
			return err
		}
		if r.MaxTTLSeconds < MinRoleTTLSeconds {
			return fmt.Errorf("%w: role %s: max_ttl_seconds must be >= %d", ErrInvalid, r.Name, MinRoleTTLSeconds)
		}
		if err := checkRefs("role "+r.Name+" extensions", r.Extensions, func(e string) bool { return e != "" }); err != nil {
			return err
		}
		if err := checkRefs("role "+r.Name+" users", r.Users, func(n string) bool { return users[n] != nil }); err != nil {
			return err
		}
		if err := checkRefs("role "+r.Name+" groups", r.Groups, func(n string) bool { return groups[n] != nil }); err != nil {
			return err
		}
		roles[r.Name] = r
	}

	if err := checkSorted("host_groups", names(d.HostGroups, func(h HostGroup) string { return h.Name })); err != nil {
		return err
	}
	for _, h := range d.HostGroups {
		if !nameRE.MatchString(h.Name) {
			return fmt.Errorf("%w: host group %q: invalid name", ErrInvalid, h.Name)
		}
		if h.Accounts == nil {
			return fmt.Errorf("%w: host group %s: accounts must be an array, not null", ErrInvalid, h.Name)
		}
		if err := checkSorted("host group "+h.Name+" accounts", names(h.Accounts, func(a AccountMap) string { return a.Account })); err != nil {
			return err
		}
		for _, a := range h.Accounts {
			if !accountRE.MatchString(a.Account) {
				return fmt.Errorf("%w: host group %s: invalid account %q", ErrInvalid, h.Name, a.Account)
			}
			if err := checkRefs("host group "+h.Name+" account "+a.Account+" roles", a.Roles, func(n string) bool { return roles[n] != nil }); err != nil {
				return err
			}
		}
	}

	effective, err := d.roleGrants()
	if err != nil {
		return err
	}
	for _, u := range d.Users {
		principals := map[string]bool{}
		for _, rn := range effective[u.Name] {
			for _, p := range roles[rn].Principals {
				principals[p] = true
			}
		}
		if len(principals) > cert.MaxPrincipals {
			return fmt.Errorf("%w: user %s would get %d principals (at most %d)", ErrInvalid, u.Name, len(principals), cert.MaxPrincipals)
		}
	}
	return nil
}

// validate checks one credential. The ID and SPKI must be the re-encoding
// of their decoded bytes (the strict decoders still skip CR and LF), so
// each credential has exactly one text form and the uniqueness check
// compares canonical strings (T-02-77).
func (c Credential) validate() error {
	id, err := base64.RawURLEncoding.Strict().DecodeString(c.ID)
	if err != nil || len(id) == 0 || len(id) > maxCredentialID || base64.RawURLEncoding.EncodeToString(id) != c.ID {
		return fmt.Errorf("%w: credential id %q is not 1 to %d bytes of unpadded base64url", ErrInvalid, c.ID, maxCredentialID)
	}
	switch c.Alg {
	case webauthn.AlgES256, webauthn.AlgEdDSA, webauthn.AlgRS256:
	default:
		return fmt.Errorf("%w: credential %s: algorithm %d (want -7, -8 or -257)", ErrInvalid, c.ID, c.Alg)
	}
	spki, err := base64.StdEncoding.Strict().DecodeString(c.SPKI)
	if err != nil || len(spki) == 0 || base64.StdEncoding.EncodeToString(spki) != c.SPKI {
		return fmt.Errorf("%w: credential %s: spki is not standard base64", ErrInvalid, c.ID)
	}
	if _, err := webauthn.ParsePublicKey(c.Alg, spki); err != nil {
		return fmt.Errorf("%w: credential %s: %w", ErrInvalid, c.ID, err)
	}
	return nil
}

// roleGrants returns, for every user a role grants directly or through a
// group, the sorted names of those roles, each once. It refuses
// (ErrInvalid) as soon as one user holds more than MaxRolesPerUser roles.
// That bounds the work by the size of d instead of users times roles
// (T-02-12): a role visits each of its users once and the members of each
// of its groups once, and every role listing a non-empty group grants each
// member one more role, so at most MaxRolesPerUser + 1 roles visit a group
// before the refusal.
func (d *Directory) roleGrants() (map[string][]string, error) {
	members := make(map[string][]string, len(d.Groups))
	for _, g := range d.Groups {
		members[g.Name] = g.Members
	}
	out := map[string][]string{}
	for _, r := range d.Roles {
		grant := func(user string) error {
			held := out[user]
			if n := len(held); n > 0 && held[n-1] == r.Name {
				return nil // already granted by this role
			}
			if len(held) == MaxRolesPerUser {
				return fmt.Errorf("%w: user %s has more than %d roles", ErrInvalid, user, MaxRolesPerUser)
			}
			out[user] = append(held, r.Name)
			return nil
		}
		for _, u := range r.Users {
			if err := grant(u); err != nil {
				return nil, err
			}
		}
		for _, g := range r.Groups {
			for _, u := range members[g] {
				if err := grant(u); err != nil {
					return nil, err
				}
			}
		}
	}
	return out, nil // d.Roles is sorted, so every list is too
}

// userRoles is roleGrants for the one user Authorize serves, which the
// signer runs under its lock for every login: one scan of d for that
// user, not every user's roles (T-02-12). Same result and the same
// MaxRolesPerUser refusal as roleGrants (TestUserRolesMatchesRoleGrants).
func (d *Directory) userRoles(user string) ([]string, error) {
	inGroup := map[string]bool{}
	for _, g := range d.Groups {
		if slices.Contains(g.Members, user) {
			inGroup[g.Name] = true
		}
	}
	var out []string
	for _, r := range d.Roles {
		if !slices.Contains(r.Users, user) && !slices.ContainsFunc(r.Groups, func(g string) bool { return inGroup[g] }) {
			continue
		}
		if len(out) == MaxRolesPerUser {
			return nil, fmt.Errorf("%w: user %s has more than %d roles", ErrInvalid, user, MaxRolesPerUser)
		}
		out = append(out, r.Name)
	}
	return out, nil // d.Roles is sorted, so out is too
}

// checkSorted requires list to be sorted and duplicate-free.
func checkSorted(what string, list []string) error {
	for i := 1; i < len(list); i++ {
		switch {
		case list[i-1] == list[i]:
			return fmt.Errorf("%w: %s: duplicate %q", ErrInvalid, what, list[i])
		case list[i-1] > list[i]:
			return fmt.Errorf("%w: %s must be sorted", ErrInvalid, what)
		}
	}
	return nil
}

// checkRefs requires list to be a non-null, sorted, duplicate-free list
// whose every entry passes ok.
func checkRefs(what string, list []string, ok func(string) bool) error {
	if list == nil {
		return fmt.Errorf("%w: %s must be an array, not null", ErrInvalid, what)
	}
	if err := checkSorted(what, list); err != nil {
		return err
	}
	for _, v := range list {
		if !ok(v) {
			return fmt.Errorf("%w: %s: unknown or invalid entry %q", ErrInvalid, what, v)
		}
	}
	return nil
}

func names[T any](list []T, name func(T) string) []string {
	out := make([]string, len(list))
	for i, v := range list {
		out[i] = name(v)
	}
	return out
}

// isHash reports whether s is 64 lowercase hex digits.
func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
