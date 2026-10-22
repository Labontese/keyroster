package directory

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Labontese/keyroster/internal/trust"
)

// Errors of the principals renderer.
var (
	// ErrUnknownHostGroup is a host group the directory does not define,
	// most likely a mistyped name.
	ErrUnknownHostGroup = errors.New("directory: unknown host group")
	// ErrNoDirectory is a nil directory: none is installed yet, so there is
	// no host group to render for.
	ErrNoDirectory = errors.New("directory: no directory is installed")
)

// AccountPrincipals returns the sorted, de-duplicated union of the
// principals of the roles that host group hostGroup maps account to. In a
// known host group, an account with no entry, or an entry with an empty
// role list, gets an empty, non-nil list and no error: it is a valid state
// that grants nothing. An unknown host group is ErrUnknownHostGroup, a nil
// d ErrNoDirectory, and a host group or account name outside the
// directory's grammars ErrInvalid (02-11-F2).
func AccountPrincipals(d *Directory, hostGroup, account string) ([]string, error) {
	if d == nil {
		return nil, ErrNoDirectory
	}
	// Both names go into the header line; one that is not in the
	// directory's grammars (a newline, a '#') could forge a principal line.
	if !ValidGroupName(hostGroup) {
		return nil, fmt.Errorf("%w: host group name %q", ErrInvalid, hostGroup)
	}
	if !ValidAccountName(account) {
		return nil, fmt.Errorf("%w: account name %q (1 to 32 characters a-z, 0-9, '_', '.' or '-', starting with a letter or '_'; lowercase only)", ErrInvalid, account)
	}
	hi := slices.IndexFunc(d.HostGroups, func(h HostGroup) bool { return h.Name == hostGroup })
	if hi < 0 {
		return nil, fmt.Errorf("%w: %s", ErrUnknownHostGroup, hostGroup)
	}
	set := map[string]bool{}
	for _, a := range d.HostGroups[hi].Accounts {
		if a.Account != account {
			continue
		}
		for _, rn := range a.Roles {
			ri := slices.IndexFunc(d.Roles, func(r Role) bool { return r.Name == rn })
			if ri < 0 {
				// Validate refuses this; a directory built around it is not
				// rendered.
				return nil, fmt.Errorf("%w: host group %s account %s maps unknown role %s", ErrInvalid, hostGroup, account, rn)
			}
			for _, p := range d.Roles[ri].Principals {
				set[p] = true
			}
		}
	}
	return sortedKeys(set), nil
}

// RenderPrincipalsFile returns the AuthorizedPrincipalsFile of account in
// hostGroup: two '#' header lines (sshd ignores them), the second naming
// the directory version and the lowercase hex SHA-256 of d.Canonical(),
// then AccountPrincipals one per line, each ending in a newline. With no
// principals the file is the two header lines only, and sshd accepts no
// keyroster certificate for the account. This is the one renderer: the
// CLI uses it now and the Phase 3 agent will use it (D-07).
func RenderPrincipalsFile(d *Directory, hostGroup, account string) ([]byte, error) {
	principals, err := AccountPrincipals(d, hostGroup, account)
	if err != nil {
		return nil, err
	}
	canonical, err := d.Canonical()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("# keyroster: generated AuthorizedPrincipalsFile; do not edit\n")
	fmt.Fprintf(&b, "# host group %s, account %s, directory version %d sha256 %s\n", hostGroup, account, d.Version, trust.SHA256Hex(canonical))
	for _, p := range principals {
		b.WriteString(p + "\n")
	}
	return []byte(b.String()), nil
}
