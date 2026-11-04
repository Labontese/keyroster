package directory

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/Labontese/keyroster/internal/trust"
)

// Render caps, F07 (03-08h). They are the host agent's generation caps
// (internal/agent/apply defines its caps as these constants), so the
// signer, which refuses at install what would break them
// (CheckRenderable), and the agent cannot drift apart.
const (
	// MaxPrincipalsFile is the most bytes one principals file may have as
	// the host agent renders it. The agent refuses a generation with a
	// larger file before anything is written, because it could not read
	// the file back (generation_too_large).
	MaxPrincipalsFile = 64 << 10
	// MaxAccounts is the most principals files, one per account of the
	// host's host group, that one generation of the host agent may hold.
	MaxAccounts = 4096
	// MaxHostGroupAccounts is the most accounts one host group may map at
	// install (Q-G3): half of MaxAccounts, because an intermediate
	// generation holds the union of two versions' accounts, so the move
	// between any two accepted versions still fits MaxAccounts.
	MaxHostGroupAccounts = MaxAccounts / 2
)

// Errors of the principals renderer.
var (
	// ErrUnrenderable is a directory whose principals files host agents
	// could not render within their caps (CheckRenderable).
	ErrUnrenderable = errors.New("directory: host agents cannot render it")
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
	b.WriteString(principalsHeader(hostGroup, account, r.d.Version, r.sum))
	for _, p := range principals {
		b.WriteString(p + "\n")
	}
	return []byte(b.String()), nil
}

// principalsHeader is the two '#' header lines of the principals file of
// account in hostGroup, for directory version and the hex SHA-256 sha of
// its canonical bytes. File writes through it, and CheckRenderable sizes
// files with it, so the two cannot drift (F07 (03-08h)).
func principalsHeader(hostGroup, account string, version uint64, sha string) string {
	return "# keyroster: generated AuthorizedPrincipalsFile; do not edit\n" +
		fmt.Sprintf("# host group %s, account %s, directory version %d sha256 %s\n", hostGroup, account, version, sha)
}

// sizer sizes the principals files of one directory without rendering
// them, F07 (03-08h): each file as RenderPrincipalsFile would write it
// with the widest version, math.MaxUint64 (20 digits), so a file's size
// does not change when the version gains a digit (Q-G7). It indexes the
// roles by name and every distinct principal by number once, so sizing
// an account costs one pass over its roles' principals, deduplicated by
// number without sorting, and none over the host group (owner decision
// (2026-11-04), execution stop at Task 1). It is not safe for concurrent
// use.
type sizer struct {
	sha   string             // trust.SHA256Hex of the directory's canonical bytes
	roles map[string][]int32 // role name to its principals' numbers
	plen  []int              // principal number to its length
	seen  []uint32           // principal number to the stamp of the last account counting it
	stamp uint32
}

// newSizer indexes d, whose canonical bytes hash to sha.
func newSizer(d *Directory, sha string) *sizer {
	z := &sizer{sha: sha, roles: make(map[string][]int32, len(d.Roles))}
	number := map[string]int32{}
	for _, r := range d.Roles {
		ids := make([]int32, 0, len(r.Principals))
		for _, p := range r.Principals {
			id, ok := number[p]
			if !ok {
				id = int32(len(z.plen)) //nolint:gosec // G115: a directory's principals number far below 2^31
				number[p] = id
				z.plen = append(z.plen, len(p))
			}
			ids = append(ids, id)
		}
		z.roles[r.Name] = ids
	}
	z.seen = make([]uint32, len(z.plen))
	return z
}

// fileSize is the size of the principals file of account a in hostGroup:
// the header principalsHeader writes at the widest version, then each
// distinct principal of a's roles and its newline, exactly
// len(RenderPrincipalsFile) at that version. A name outside the
// directory's grammars, or an unknown role, is ErrInvalid, as
// AccountPrincipals refuses them.
func (z *sizer) fileSize(hostGroup string, a AccountMap) (int, error) {
	if !ValidGroupName(hostGroup) {
		return 0, fmt.Errorf("%w: host group name %q", ErrInvalid, hostGroup)
	}
	if !ValidAccountName(a.Account) {
		return 0, fmt.Errorf("%w: account name %q", ErrInvalid, a.Account)
	}
	z.stamp++
	if z.stamp == 0 { // wrapped: no stamp may match an older account's
		clear(z.seen)
		z.stamp = 1
	}
	n := len(principalsHeader(hostGroup, a.Account, math.MaxUint64, z.sha))
	for _, rn := range a.Roles {
		ids, ok := z.roles[rn]
		if !ok {
			return 0, fmt.Errorf("%w: host group %s account %s maps unknown role %s", ErrInvalid, hostGroup, a.Account, rn)
		}
		for _, id := range ids {
			if z.seen[id] != z.stamp {
				z.seen[id] = z.stamp
				n += z.plen[id] + 1
			}
		}
	}
	return n, nil
}

// CheckRenderable refuses (ErrUnrenderable) a directory d that host agents
// could not render within their generation caps, F07 (03-08h). installed
// is the directory in force where d is offered, nil when none is
// installed yet. It runs only when a directory is offered for install,
// never on stored state: a directory installed before this rule stays in
// force and renders as before.
//
// The bounds are the host agent's: every host group maps at most
// MaxHostGroupAccounts accounts, half of MaxAccounts, so the intermediate
// generation between two accepted versions, which holds the union of
// their accounts, still fits; and every account's principals file is at
// most MaxPrincipalsFile bytes. Files are sized as RenderPrincipalsFile
// would write them at the widest version, 20 digits, so a file accepted
// once stays within the cap at every later version. An intermediate
// principals file is a subset of the target's lines under a header that
// is not longer than any real header, so it fits too.
//
// The non-growth exception (Q-G7): nothing may grow beyond the installed
// version. A host group above the account bound is accepted when installed
// has a host group of that name and every one of the group's accounts is
// in it (a subset, not a count); a principals file above the size bound
// is accepted when the same host group's and account's file in installed,
// sized the same way, is at least as large. A host group or account with
// no installed counterpart always meets the bounds. Hosts at the installed
// version therefore keep rendering, so disabling and removing users
// always install; a host further behind can still meet an intermediate
// above its caps, and relies on the agent's KRL-alone pass (03-08d).
//
// A host moved to another host group (owner decision (2026-11-04),
// execution stop at Task 1): an active host of d that shares a host key,
// or, with a key installed does not know, its name (R-2 and C-2, owner
// decisions (2026-11-04), pre-merge review and fix-round check of PR #84),
// with an active host of installed in another host group would move,
// on its agent, through an intermediate holding the principals files of both
// groups' accounts, each a subset of its target file under a header that
// is not longer. Such a move is refused when that union is above
// MaxAccounts, or when a file of the new group is above MaxPrincipalsFile:
// the host never rendered the new group, so no exception applies. With
// both groups within MaxHostGroupAccounts the union always fits; the rule
// bites only with an above-share installed group (Q-G7).
func CheckRenderable(d, installed *Directory) error {
	if d == nil {
		return ErrNoDirectory
	}
	canonical, err := d.Canonical()
	if err != nil {
		return err
	}
	z := newSizer(d, trust.SHA256Hex(canonical))
	var iz *sizer // installed's, made on first need
	installedSizer := func() (*sizer, error) {
		if iz == nil {
			c, err := installed.Canonical()
			if err != nil {
				return nil, err
			}
			iz = newSizer(installed, trust.SHA256Hex(c))
		}
		return iz, nil
	}
	// aboveBound is, per host group of d, an account whose file is above
	// MaxPrincipalsFile ("" for none), for the moved-host check.
	aboveBound := make(map[string]string, len(d.HostGroups))
	var installedGroups map[string]int // indexed once (R-1, pre-merge review of PR #84)
	if installed != nil {
		installedGroups = hostGroupIndex(installed)
	}
	for _, h := range d.HostGroups {
		// The installed counterpart is looked up first: a group or account
		// it does not have gets no exception.
		var was map[string]int // installed account name to its index
		var old *HostGroup
		if installed != nil {
			if i, ok := installedGroups[h.Name]; ok {
				old = &installed.HostGroups[i]
				was = make(map[string]int, len(old.Accounts))
				for j, a := range old.Accounts {
					was[a.Account] = j
				}
			}
		}
		if n := len(h.Accounts); n > MaxHostGroupAccounts && !subset(h.Accounts, was) {
			return fmt.Errorf("%w: host group %s maps %d accounts, above %d", ErrUnrenderable, h.Name, n, MaxHostGroupAccounts)
		}
		for _, a := range h.Accounts {
			size, err := z.fileSize(h.Name, a)
			if err != nil {
				return fmt.Errorf("directory: host group %s account %s: %w", h.Name, a.Account, err)
			}
			if size <= MaxPrincipalsFile {
				continue
			}
			if aboveBound[h.Name] == "" {
				aboveBound[h.Name] = a.Account
			}
			if j, ok := was[a.Account]; ok {
				iz, err := installedSizer()
				if err != nil {
					return err
				}
				before, err := iz.fileSize(h.Name, old.Accounts[j])
				if err != nil {
					return fmt.Errorf("directory: installed host group %s account %s: %w", h.Name, a.Account, err)
				}
				if size <= before {
					continue
				}
			}
			return fmt.Errorf("%w: host group %s account %s: principals file of %d bytes, above %d", ErrUnrenderable, h.Name, a.Account, size, MaxPrincipalsFile)
		}
	}
	if installed == nil {
		return nil
	}
	return checkMoves(d, installed, installedGroups, aboveBound)
}

// hostGroupIndex maps each host group name of d to its index in
// d.HostGroups: the first index for a repeated name, as slices.IndexFunc
// finds it (Validate refuses repeated names; CheckRenderable does not
// rely on it).
func hostGroupIndex(d *Directory) map[string]int {
	index := make(map[string]int, len(d.HostGroups))
	for i, h := range d.HostGroups {
		if _, ok := index[h.Name]; !ok {
			index[h.Name] = i
		}
	}
	return index
}

// checkMoves refuses (ErrUnrenderable) a version d that moves a host from
// its host group in installed to another host group whose move its agent
// could not make within its caps (CheckRenderable). A host is the same
// when an active entry of d and an active entry of installed share a host
// key, as the agent finds its entry by its host keys, or, when the entry
// of d has a key no active entry of installed holds, a name (R-2 and C-2,
// owner decisions (2026-11-04), pre-merge review and fix-round check of
// PR #84), as the agent keeps its last host's principals by name when its
// keys match no entry (RenderFallback, host_keys_rotated): a version that
// replaces a host's keys and moves it shares no key with installed. A
// host renamed and rekeyed in one version is not found. A disabled entry renders no
// principals files on either side. installedGroups is
// hostGroupIndex(installed). The union of a move is counted once per pair
// of host groups (R-1, pre-merge review of PR #84).
func checkMoves(d, installed *Directory, installedGroups map[string]int, aboveBound map[string]string) error {
	u := moveUnions{installed: installed, d: d, from: installedGroups, to: hostGroupIndex(d), fromSets: map[string]map[string]bool{}, toSets: map[string]map[string]bool{}, counts: map[[2]string]int{}}
	byKey := map[string]*Host{}
	byName := map[string]*Host{} // the first active entry of a name, as HostByName finds it
	for i := range installed.Hosts {
		if o := &installed.Hosts[i]; o.Status == StatusActive {
			for _, k := range o.Keys {
				byKey[k] = o
			}
			if _, ok := byName[o.Name]; !ok {
				byName[o.Name] = o
			}
		}
	}
	for _, h := range d.Hosts {
		if h.Status != StatusActive {
			continue
		}
		// The installed entries of h's keys, in their order, then the one
		// of h's name when h has a key no active installed host holds (a
		// possible rekey; C-2, owner decision (2026-11-04), fix-round
		// check of PR #84). A host whose every key is known is found by
		// its keys, as its agent finds it.
		olds := make([]*Host, 0, len(h.Keys)+1)
		fresh := false
		for _, k := range h.Keys {
			if o, ok := byKey[k]; ok {
				olds = append(olds, o)
			} else {
				fresh = true
			}
		}
		if o, ok := byName[h.Name]; ok && fresh {
			olds = append(olds, o)
		}
		for _, o := range olds {
			if o.HostGroup == h.HostGroup {
				continue
			}
			if acc := aboveBound[h.HostGroup]; acc != "" {
				return fmt.Errorf("%w: host %s moves from host group %s to %s, whose account %s has a principals file above %d bytes", ErrUnrenderable, h.Name, o.HostGroup, h.HostGroup, acc, MaxPrincipalsFile)
			}
			if n := u.count(o.HostGroup, h.HostGroup); n > MaxAccounts {
				return fmt.Errorf("%w: host %s moves from host group %s to %s, %d accounts in the move, above %d", ErrUnrenderable, h.Name, o.HostGroup, h.HostGroup, n, MaxAccounts)
			}
		}
	}
	return nil
}

// moveUnions counts the accounts of host moves, from a host group of
// installed to a host group of d, once per (from, to) pair: the principals
// files of the intermediate generation a host moving between them holds.
// from and to are hostGroupIndex of installed and d; a group either does
// not define counts no accounts.
type moveUnions struct {
	installed, d *Directory
	from, to     map[string]int
	fromSets     map[string]map[string]bool // from group name to its account names
	toSets       map[string]map[string]bool // to group name to its account names
	counts       map[[2]string]int          // (from, to) to count's answer
}

// count is the number of distinct accounts of host group from in installed
// and host group to in d when it is above MaxAccounts, and at most
// MaxAccounts otherwise. When the two groups' lists add up to at most
// MaxAccounts the union cannot be larger, so nothing is counted;
// otherwise each group's account set is built once, for its first pair,
// and the smaller set's accounts not in the larger are counted (C-1,
// fix-round check of PR #84), so a pair costs the smaller group's size.
func (u *moveUnions) count(from, to string) int {
	key := [2]string{from, to}
	if n, ok := u.counts[key]; ok {
		return n
	}
	var fromAccounts, toAccounts []AccountMap
	if i, ok := u.from[from]; ok {
		fromAccounts = u.installed.HostGroups[i].Accounts
	}
	if i, ok := u.to[to]; ok {
		toAccounts = u.d.HostGroups[i].Accounts
	}
	n := len(fromAccounts) + len(toAccounts)
	if n > MaxAccounts {
		small, large := accountSet(u.fromSets, from, fromAccounts), accountSet(u.toSets, to, toAccounts)
		if len(small) > len(large) {
			small, large = large, small
		}
		n = len(large)
		for a := range small {
			if !large[a] {
				n++
			}
		}
	}
	u.counts[key] = n
	return n
}

// accountSet is sets[name], the account names of accounts, built on first
// use.
func accountSet(sets map[string]map[string]bool, name string, accounts []AccountMap) map[string]bool {
	set, ok := sets[name]
	if !ok {
		set = make(map[string]bool, len(accounts))
		for _, a := range accounts {
			set[a.Account] = true
		}
		sets[name] = set
	}
	return set
}

// subset reports whether every account of accounts is in was. A nil was
// (no installed counterpart) holds none.
func subset(accounts []AccountMap, was map[string]int) bool {
	if was == nil {
		return false
	}
	for _, a := range accounts {
		if _, ok := was[a.Account]; !ok {
			return false
		}
	}
	return true
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
