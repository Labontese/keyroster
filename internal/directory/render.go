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
	// ErrUnknownHost is a host the directory does not name, or names as
	// disabled.
	ErrUnknownHost = errors.New("directory: unknown or disabled host")
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
// CLI and the agent use it, the agent through PrincipalsRenderer (D-07).
func RenderPrincipalsFile(d *Directory, hostGroup, account string) ([]byte, error) {
	return NewPrincipalsRenderer(d).File(hostGroup, account)
}

// PrincipalsRenderer renders the principals files of one directory. It
// canonicalises and hashes the directory once, for its first file, where
// a RenderPrincipalsFile call per file would do so for every file: a host
// group of n accounts costs n canonical encodings of the whole directory
// otherwise. d must not change while the renderer is in use, and the
// renderer is not safe for concurrent use.
type PrincipalsRenderer struct {
	d   *Directory
	sum string // trust.SHA256Hex(d.Canonical()); "" until the first file
}

// NewPrincipalsRenderer returns the renderer for d.
func NewPrincipalsRenderer(d *Directory) *PrincipalsRenderer {
	return &PrincipalsRenderer{d: d}
}

// File is RenderPrincipalsFile(d, hostGroup, account), byte for byte, with
// the same errors in the same order: AccountPrincipals' first, then the
// canonical encoding's.
func (r *PrincipalsRenderer) File(hostGroup, account string) ([]byte, error) {
	principals, err := AccountPrincipals(r.d, hostGroup, account)
	if err != nil {
		return nil, err
	}
	if r.sum == "" {
		canonical, err := r.d.Canonical()
		if err != nil {
			return nil, err
		}
		r.sum = trust.SHA256Hex(canonical)
	}
	var b strings.Builder
	b.WriteString("# keyroster: generated AuthorizedPrincipalsFile; do not edit\n")
	fmt.Fprintf(&b, "# host group %s, account %s, directory version %d sha256 %s\n", hostGroup, account, r.d.Version, r.sum)
	for _, p := range principals {
		b.WriteString(p + "\n")
	}
	return []byte(b.String()), nil
}

// HostPrincipals returns the AuthorizedPrincipalsFile of account on the
// host hostName: RenderPrincipalsFile for the host's one host group
// (D-11). It is the file that host's agent writes. A host the directory
// does not name, or names as disabled, is ErrUnknownHost; a host name
// outside the user name grammar ErrInvalid. There is no second renderer.
func HostPrincipals(d *Directory, hostName, account string) ([]byte, error) {
	if d == nil {
		return nil, ErrNoDirectory
	}
	if !ValidUserName(hostName) {
		return nil, fmt.Errorf("%w: host name %q", ErrInvalid, hostName)
	}
	h, ok := d.HostByName(hostName)
	if !ok || h.Status != StatusActive {
		return nil, fmt.Errorf("%w: %s", ErrUnknownHost, hostName)
	}
	return RenderPrincipalsFile(d, h.HostGroup, account)
}
