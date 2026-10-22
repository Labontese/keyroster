package directory

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Labontese/keyroster/internal/webauthn"
)

// Diff returns the changes from old to next as human-readable lines, the
// text an admin reads before signing next (T-02-43). A nil old means
// genesis: everything in next is added. The order is fixed: users, then
// credentials, groups, roles and host groups; within each kind by name,
// with a removal before an addition of the same name. Lines start with
// "+" (added), "-" (removed) or "~" (a user's status changed); a group,
// role or host group that changed shows as its old line removed and its
// new line added, each with all of its members, principals or accounts.
//
// Every value printed comes from a directory that passed Validate, so
// names are from the directory's own name grammars. A credential is shown
// by the fingerprint of its key ("SHA256:" and the unpadded base64 of
// SHA-256 over the SPKI DER), the same text the registration page showed
// the user, then by a digest of its ID and both backup flags, so a change
// of its ID or of a flag alone never shows as two identical lines.
func Diff(old, next *Directory) []string {
	if old == nil {
		old = &Directory{}
	}
	var out []string
	oldUsers, newUsers := byName(old.Users, func(u User) string { return u.Name }), byName(next.Users, func(u User) string { return u.Name })
	for _, n := range unionNames(oldUsers, newUsers) {
		o, inOld := oldUsers[n]
		u, inNew := newUsers[n]
		switch {
		case !inNew:
			out = append(out, fmt.Sprintf("- user %s (%s)", n, o.Status))
		case !inOld:
			out = append(out, fmt.Sprintf("+ user %s (%s)", n, u.Status))
		case o.Status != u.Status:
			out = append(out, fmt.Sprintf("~ user %s %s -> %s", n, o.Status, u.Status))
		}
	}
	for _, n := range unionNames(oldUsers, newUsers) {
		oldCreds := byName(oldUsers[n].Credentials, func(c Credential) string { return c.ID })
		newCreds := byName(newUsers[n].Credentials, func(c Credential) string { return c.ID })
		var removed, added []string
		for _, id := range unionNames(oldCreds, newCreds) {
			o, inOld := oldCreds[id]
			c, inNew := newCreds[id]
			switch {
			case !inNew:
				removed = append(removed, "- credential "+n+" "+credentialText(o))
			case !inOld:
				added = append(added, "+ credential "+n+" "+credentialText(c))
			case o != c:
				removed = append(removed, "- credential "+n+" "+credentialText(o))
				added = append(added, "+ credential "+n+" "+credentialText(c))
			}
		}
		slices.Sort(removed)
		slices.Sort(added)
		out = append(append(out, removed...), added...)
	}
	out = append(out, diffNamed("group", old.Groups, next.Groups, func(g Group) string { return g.Name }, groupText)...)
	out = append(out, diffNamed("role", old.Roles, next.Roles, func(r Role) string { return r.Name }, roleText)...)
	out = append(out, diffNamed("host_group", old.HostGroups, next.HostGroups, func(h HostGroup) string { return h.Name }, hostGroupText)...)
	return out
}

// diffNamed diffs one list of named entries whose whole content is its
// text: an entry whose text changed is removed and added again.
func diffNamed[T any](kind string, old, next []T, name func(T) string, text func(T) string) []string {
	o, n := byName(old, name), byName(next, name)
	var out []string
	for _, k := range unionNames(o, n) {
		a, inOld := o[k]
		b, inNew := n[k]
		if inOld && inNew && text(a) == text(b) {
			continue
		}
		if inOld {
			out = append(out, "- "+kind+" "+text(a))
		}
		if inNew {
			out = append(out, "+ "+kind+" "+text(b))
		}
	}
	return out
}

// credentialText is a credential as Diff shows it: fingerprint, algorithm,
// the digest of its ID (credentialIDDigest), whether the passkey may be
// backed up and whether it is synced (backed up).
func credentialText(c Credential) string {
	fp := "(spki not base64)"
	if spki, err := base64.StdEncoding.Strict().DecodeString(c.SPKI); err == nil {
		fp = webauthn.Fingerprint(spki)
	}
	return fmt.Sprintf("%s %s id-sha256=%s backup_eligible=%t synced=%t", fp, AlgName(c.Alg), credentialIDDigest(c.ID), c.BackupEligible, c.BackedUp)
}

// credentialIDDigest is the first 128 bits, in hex, of SHA-256 over a
// credential's canonical ID text. An ID can be up to 1023 bytes, too long
// for a diff line, and a prefix of it would not do: whoever writes a
// version chooses the new ID, so it could share any prefix with the old.
func credentialIDDigest(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:16])
}

// AlgName is the name of a credential's COSE algorithm: EdDSA, ES256 or
// RS256, or "COSE n" for any other.
func AlgName(alg int64) string {
	switch alg {
	case webauthn.AlgEdDSA:
		return "EdDSA"
	case webauthn.AlgES256:
		return "ES256"
	case webauthn.AlgRS256:
		return "RS256"
	}
	return fmt.Sprintf("COSE %d", alg)
}

func groupText(g Group) string {
	return fmt.Sprintf("%s members=[%s]", g.Name, strings.Join(g.Members, " "))
}

func roleText(r Role) string {
	exts := make([]string, len(r.Extensions))
	for i, e := range r.Extensions {
		exts[i] = displayText(e)
	}
	return fmt.Sprintf("%s principals=[%s] max_ttl_seconds=%d extensions=[%s] users=[%s] groups=[%s]",
		r.Name, strings.Join(r.Principals, " "), r.MaxTTLSeconds, strings.Join(exts, " "),
		strings.Join(r.Users, " "), strings.Join(r.Groups, " "))
}

// displayText is s as Diff prints free text (a role's extensions, the one
// field no name grammar covers): as it is when every byte is printable
// ASCII other than space, '"' and '\', else Go-quoted in ASCII, so no
// control byte or escape sequence reaches the admin's terminal and no
// value can pass for two.
func displayText(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f || c == '"' || c == '\\' {
			return strconv.QuoteToASCII(s)
		}
	}
	return s
}

func hostGroupText(h HostGroup) string {
	accounts := make([]string, len(h.Accounts))
	for i, a := range h.Accounts {
		accounts[i] = a.Account + ":" + strings.Join(a.Roles, ",")
	}
	return fmt.Sprintf("%s accounts=[%s]", h.Name, strings.Join(accounts, " "))
}

func byName[T any](list []T, name func(T) string) map[string]T {
	m := make(map[string]T, len(list))
	for _, v := range list {
		m[name(v)] = v
	}
	return m
}

// unionNames returns the keys of a and b, sorted, each once.
func unionNames[T any](a, b map[string]T) []string {
	out := make([]string, 0, len(a)+len(b))
	for k := range a {
		out = append(out, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}
