//go:build linux

package apply

import (
	"path/filepath"
	"strings"
)

// matchPattern is OpenSSH's match_pattern: s matches pattern, where *
// matches any run of characters and ? any one character.
func matchPattern(s, pattern string) bool {
	for {
		if pattern == "" {
			return s == ""
		}
		switch pattern[0] {
		case '*':
			pattern = pattern[1:]
			if pattern == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if matchPattern(s[i:], pattern) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
		default:
			if s == "" || s[0] != pattern[0] {
				return false
			}
		}
		s, pattern = s[1:], pattern[1:]
	}
}

// matchPatternList is OpenSSH's match_pattern_list: 1 when s matches a
// pattern of the comma-separated list, -1 when it matches a negated one
// (!pattern; a negated match wins), 0 when it matches none.
func matchPatternList(s, list string) int {
	got := 0
	for _, p := range strings.Split(list, ",") {
		neg := strings.HasPrefix(p, "!")
		if neg {
			p = p[1:]
		}
		if p == "" || !matchPattern(s, p) {
			continue
		}
		if neg {
			return -1
		}
		got = 1
	}
	return got
}

// Excluded applies sshd's AllowUsers, DenyUsers, AllowGroups and
// DenyGroups (auth.c allowed_user, in its order) from the sshd -T -C dump
// d for account, and returns why the account is or may be refused, or ""
// when it is not. A user@host entry depends on the client's address, which
// the agent does not know, so it "may" exclude. Groups come from
// root/etc/passwd and root/etc/group; an account they do not list (NSS,
// LDAP) is reported only when group rules exist. Report only (D-07): the
// agent never edits these settings.
func Excluded(d Dump, account, root string) string {
	user := func(entry string) (bool, bool) { // matches the user part, and has a host part
		u, _, host := strings.Cut(entry, "@")
		return matchPattern(account, u), host
	}
	for _, e := range d["denyusers"] {
		if m, host := user(e); m && !host {
			return "DenyUsers " + e + " refuses it"
		} else if m {
			return "DenyUsers " + e + " refuses it from matching client hosts"
		}
	}
	if allow := d["allowusers"]; len(allow) > 0 {
		definite, maybe := false, ""
		for _, e := range allow {
			m, host := user(e)
			if m && !host {
				definite = true
				break
			}
			if m && maybe == "" {
				maybe = e
			}
		}
		switch {
		case definite:
		case maybe != "":
			return "AllowUsers admits it only as " + maybe + ", from matching client hosts"
		default:
			return "AllowUsers (" + strings.Join(allow, " ") + ") does not list it"
		}
	}
	deny, allow := d["denygroups"], d["allowgroups"]
	if len(deny) == 0 && len(allow) == 0 {
		return ""
	}
	groups, ok := accountGroups(root, account)
	if !ok {
		return "AllowGroups or DenyGroups is set and " + account + " is not in " + filepath.Join(root, "etc", "passwd") + ", so its groups are unknown here"
	}
	for _, e := range deny {
		for _, g := range groups {
			if matchPatternList(g, e) == 1 {
				return "DenyGroups " + e + " refuses its group " + g
			}
		}
	}
	if len(allow) > 0 {
		for _, e := range allow {
			for _, g := range groups {
				if matchPatternList(g, e) == 1 {
					return ""
				}
			}
		}
		return "AllowGroups (" + strings.Join(allow, " ") + ") lists none of its groups (" + strings.Join(groups, ", ") + ")"
	}
	return ""
}

// accountGroups is the names of account's primary group (from
// /etc/passwd) and of every group /etc/group lists it in; false when
// /etc/passwd does not list the account.
func accountGroups(root, account string) ([]string, bool) {
	passwd, err := readSmall(filepath.Join(root, "etc", "passwd"), 4<<20)
	if err != nil {
		return nil, false
	}
	gid := ""
	for _, l := range strings.Split(string(passwd), "\n") {
		f := strings.Split(l, ":")
		if len(f) >= 4 && f[0] == account {
			gid = f[3]
			break
		}
	}
	if gid == "" {
		return nil, false
	}
	group, err := readSmall(filepath.Join(root, "etc", "group"), 4<<20)
	if err != nil {
		return nil, false
	}
	var out []string
	for _, l := range strings.Split(string(group), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 4 {
			continue
		}
		member := f[2] == gid
		for _, m := range strings.Split(f[3], ",") {
			if m == account {
				member = true
			}
		}
		if member {
			out = append(out, f[0])
		}
	}
	return out, true
}
