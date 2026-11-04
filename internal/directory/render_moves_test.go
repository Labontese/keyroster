package directory

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// moveNames is prefix<from>, prefix<from+1>, ... n names of four digits.
func moveNames(prefix string, from, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%04d", prefix, from+i)
	}
	return out
}

// moveGroup is host group name with the accounts names, each mapping ops.
func moveGroup(name string, names ...[]string) HostGroup {
	h := HostGroup{Name: name, Accounts: []AccountMap{}}
	for _, ns := range names {
		for _, n := range ns {
			h.Accounts = append(h.Accounts, AccountMap{Account: n, Roles: []string{"ops"}})
		}
	}
	return h
}

// moveDir is a directory of version v with role ops (one principal), the
// host groups and the hosts. CheckRenderable needs no more: it is built
// directly, not through Parse.
func moveDir(v uint64, groups []HostGroup, hosts []Host) *Directory {
	d := &Directory{
		Version:    v,
		Prev:       strings.Repeat("0", 64),
		Roles:      []Role{{Name: "ops", Principals: []string{"ops"}, MaxTTLSeconds: 3600}},
		HostGroups: groups,
		Hosts:      hosts,
	}
	d.Sort()
	return d
}

// moveHosts is n active hosts h0000, h0001, ... in host group group, each
// with keys host keys (short synthetic strings: CheckRenderable does not
// parse them).
func moveHosts(n, keys int, group string) []Host {
	out := make([]Host, n)
	for i := range out {
		out[i] = Host{Name: fmt.Sprintf("h%04d", i), HostGroup: group, Principals: []string{"h"}, Status: StatusActive}
		for k := range keys {
			out[i].Keys = append(out[i].Keys, fmt.Sprintf("ssh-ed25519 k%04d-%d", i, k))
		}
	}
	return out
}

// TestCheckRenderableFastEnough (R-1, pre-merge review of PR #84): the
// moved-host check and the host group lookup are about linear in the
// directory's size, so CheckRenderable stays within 2 s, under -race too,
// for the shapes that took seconds under the signer's lock. No t.Parallel:
// the wall-clock bound must not share the CPU with the package's parallel
// tests.
func TestCheckRenderableFastEnough(t *testing.T) {
	timed := func(t *testing.T, name string, d, installed *Directory) {
		t.Helper()
		start := time.Now()
		err := CheckRenderable(d, installed)
		took := time.Since(start)
		t.Logf("%s: %v (race %v)", name, took, raceEnabled)
		if err != nil {
			t.Fatalf("%s: CheckRenderable = %v, want it accepted", name, err)
		}
		if took > 2*time.Second {
			t.Fatalf("%s took %v, above 2 s", name, took)
		}
	}
	lab := moveNames("u", 0, 3000)
	t.Run("hosts_moved_into_group_within_share", func(t *testing.T) {
		// 5000 hosts of 4 keys each move from lab (3000 accounts, above
		// the share) to web (1000): 4000 accounts in the move.
		groups := func() []HostGroup {
			return []HostGroup{moveGroup("lab", lab), moveGroup("web", moveNames("w", 0, 1000))}
		}
		installed := moveDir(1, groups(), moveHosts(5000, 4, "lab"))
		timed(t, "5000 hosts of 4 keys from lab (3000) to web (1000)", moveDir(2, groups(), moveHosts(5000, 4, "web")), installed)
	})
	t.Run("hosts_moved_into_overlapping_group", func(t *testing.T) {
		// web maps 1100 accounts, 100 of them lab's: 4100 accounts in the
		// two groups, 4000 in their union, which fits.
		groups := func() []HostGroup {
			return []HostGroup{moveGroup("lab", lab), moveGroup("web", lab[2900:], moveNames("w", 0, 1000))}
		}
		installed := moveDir(1, groups(), moveHosts(5000, 4, "lab"))
		timed(t, "5000 hosts of 4 keys from lab (3000) to web (1100, 100 shared)", moveDir(2, groups(), moveHosts(5000, 4, "web")), installed)
	})
	t.Run("many_host_groups", func(t *testing.T) {
		// 30000 host groups with no accounts in both versions.
		groups := func() []HostGroup {
			out := make([]HostGroup, 30000)
			for i := range out {
				out[i] = HostGroup{Name: fmt.Sprintf("g%05d", i), Accounts: []AccountMap{}}
			}
			return out
		}
		d := moveDir(2, groups(), nil)
		c, err := d.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if len(c) > wire.MaxDirectory {
			t.Fatalf("the directory is %d bytes, above wire.MaxDirectory (%d)", len(c), wire.MaxDirectory)
		}
		t.Logf("%d host groups, %d bytes", len(d.HostGroups), len(c))
		timed(t, "30000 host groups in both versions", d, moveDir(1, groups(), nil))
	})
}

// moveOne is a directory of version v with the host groups and host h1
// in host group in with keys keys.
func moveOne(v uint64, groups []HostGroup, in string, keys ...string) *Directory {
	return moveDir(v, groups, []Host{{Name: "h1", HostGroup: in, Keys: keys, Principals: []string{"h1"}, Status: StatusActive}})
}

// TestMoveUnion (R-1, pre-merge review of PR #84): a move's union is
// counted per pair of host groups (installed's from, the offered to), and
// the sum of the two groups' sizes stands in for it only while it is
// within MaxAccounts.
func TestMoveUnion(t *testing.T) {
	lab := moveNames("u", 0, 3000)
	t.Run("per_group_pair", func(t *testing.T) {
		// h0 moves to web from db (fits), h1 from lab (3000 + 1097
		// accounts, above MaxAccounts).
		groups := func() []HostGroup {
			return []HostGroup{moveGroup("db", moveNames("d", 0, 10)), moveGroup("lab", lab), moveGroup("web", moveNames("w", 0, MaxAccounts-3000+1))}
		}
		installed := moveDir(1, groups(), []Host{
			{Name: "h0", HostGroup: "db", Keys: []string{"k0"}, Principals: []string{"h0"}, Status: StatusActive},
			{Name: "h1", HostGroup: "lab", Keys: []string{"k1"}, Principals: []string{"h1"}, Status: StatusActive},
		})
		offered := moveDir(2, groups(), []Host{
			{Name: "h0", HostGroup: "web", Keys: []string{"k0"}, Principals: []string{"h0"}, Status: StatusActive},
			{Name: "h1", HostGroup: "web", Keys: []string{"k1"}, Principals: []string{"h1"}, Status: StatusActive},
		})
		err := CheckRenderable(offered, installed)
		if !errors.Is(err, ErrUnrenderable) || !strings.Contains(err.Error(), "host h1 moves from host group lab to web, 4097 accounts") {
			t.Fatalf("CheckRenderable = %v, want h1's move from lab refused with 4097 accounts", err)
		}
	})
	t.Run("overlap_at_cap_accepted", func(t *testing.T) {
		// web maps 1097 accounts, one of them lab's: 4097 in the two
		// groups, MaxAccounts in their union.
		groups := func() []HostGroup {
			return []HostGroup{moveGroup("lab", lab), moveGroup("web", lab[2999:], moveNames("w", 0, MaxAccounts-3000))}
		}
		if err := CheckRenderable(moveOne(2, groups(), "web", "k1"), moveOne(1, groups(), "lab", "k1")); err != nil {
			t.Fatalf("CheckRenderable = %v, want the move of %d accounts accepted", err, MaxAccounts)
		}
	})
}

// movePair is an installed directory and an offered version for the
// equivalence check: host groups a to d of sizes around the share and the
// cap, drawn as runs of one pool of account names so that groups overlap
// by varying amounts, a few accounts with a file above MaxPrincipalsFile,
// and hosts with 1 to 4 keys drawn from a small pool (so keys repeat
// across hosts), some disabled, some in a group the other version does
// not define, some renamed. seed varies the draw.
func movePair(seed uint64) (installed, offered *Directory) {
	x := seed*6364136223846793005 + 1442695040888963407
	next := func(n int) int { // a deterministic draw in [0, n)
		x = x*6364136223846793005 + 1442695040888963407
		return int((x >> 33) % uint64(n)) //nolint:gosec // G115: n is small and positive
	}
	pool := moveNames("u", 0, 5000)
	sizes := []int{0, 1, 100, 1048, 1096, 1097, 2000, 2048, 2049, 3000, 4096}
	roles := []Role{{Name: "ops", Principals: []string{"ops"}, MaxTTLSeconds: 3600}}
	var big []string // the roles of a file above MaxPrincipalsFile
	for r := range 17 {
		ps := make([]string, MaxRolePrincipals)
		for i := range ps {
			ps[i] = fmt.Sprintf("b%02d%02d", r, i) + strings.Repeat("x", 123)
		}
		roles = append(roles, Role{Name: fmt.Sprintf("big%02d", r), Principals: ps, MaxTTLSeconds: 3600})
		big = append(big, roles[len(roles)-1].Name)
	}
	group := func(name string, choices []int, bigFile bool) HostGroup {
		size := choices[next(len(choices))]
		off := next(len(pool) - size + 1)
		h := HostGroup{Name: name, Accounts: []AccountMap{}}
		for _, n := range pool[off : off+size] {
			h.Accounts = append(h.Accounts, AccountMap{Account: n, Roles: []string{"ops"}})
		}
		if bigFile && size > 0 {
			a := &h.Accounts[next(size)]
			a.Roles = append(a.Roles, big...)
		}
		return h
	}
	names := []string{"a", "b", "c", "d"}
	var ig, og []HostGroup
	for _, n := range names {
		if next(5) > 0 {
			ig = append(ig, group(n, sizes, next(3) == 0))
		}
	}
	for _, n := range names {
		i := slices.IndexFunc(ig, func(h HostGroup) bool { return h.Name == n })
		switch c := next(5); {
		case c <= 1 && i >= 0: // as installed
			og = append(og, HostGroup{Name: n, Accounts: slices.Clone(ig[i].Accounts)})
		case c == 2 && i >= 0: // a run of installed's accounts
			acc := ig[i].Accounts
			lo := next(len(acc) + 1)
			og = append(og, HostGroup{Name: n, Accounts: slices.Clone(acc[lo : lo+next(len(acc)-lo+1)])})
		case c <= 3: // new accounts, at most one above the share
			og = append(og, group(n, sizes[:9], false))
		}
	}
	keyPool := moveNames("ssh-ed25519 k", 0, 12)
	host := func(name string) Host {
		h := Host{Name: name, Principals: []string{"h"}, Status: StatusActive}
		if next(5) == 0 {
			h.Status = StatusDisabled
		}
		h.HostGroup = append(slices.Clone(names), "zz")[next(len(names)+1)]
		for range 1 + next(4) {
			h.Keys = append(h.Keys, keyPool[next(len(keyPool))])
		}
		return h
	}
	var ih, oh []Host
	for i := range 6 {
		ih = append(ih, host(fmt.Sprintf("h%d", i)))
	}
	// Offered: each installed host again, mostly with its keys, some
	// renamed, in a drawn group, and one more host.
	for _, o := range ih {
		h := host(o.Name)
		if next(4) == 0 {
			h.Name = "r" + o.Name
		}
		if next(3) > 0 {
			h.Keys = slices.Clone(o.Keys)
		}
		oh = append(oh, h)
	}
	oh = append(oh, host("h9"))
	installed = &Directory{Version: 1, Prev: strings.Repeat("0", 64), Roles: roles, HostGroups: ig, Hosts: ih}
	offered = &Directory{Version: 2, Prev: strings.Repeat("0", 64), Roles: slices.Clone(roles), HostGroups: og, Hosts: oh}
	installed.Sort()
	offered.Sort()
	return installed, offered
}

// TestCheckRenderableMatchesReference (R-1): CheckRenderable gives exactly
// the answers of checkRenderableRef, the implementation before R-1, which
// looks host groups up by a scan and counts a move's union once per
// matching host key: accept or refuse, and the same error text, so the
// same first failing host. The draws must reach every kind of answer.
func TestCheckRenderableMatchesReference(t *testing.T) {
	kinds := map[string]int{}
	for seed := range uint64(48) {
		installed, offered := movePair(seed)
		got, want := CheckRenderable(offered, installed), checkRenderableRef(offered, installed)
		if (got == nil) != (want == nil) || (got != nil && got.Error() != want.Error()) {
			t.Fatalf("seed %d: CheckRenderable = %v, the reference %v", seed, got, want)
		}
		switch {
		case got == nil:
			kinds["accepted"]++
		case strings.Contains(got.Error(), "accounts in the move"):
			kinds["move union"]++
		case strings.Contains(got.Error(), " moves from "):
			kinds["move file"]++
		default:
			kinds["other"]++
		}
	}
	t.Logf("answers: %v", kinds)
	for _, k := range []string{"accepted", "move union", "move file", "other"} {
		if kinds[k] == 0 {
			t.Fatalf("no draw answered %q (%v): the check does not cover it", k, kinds)
		}
	}
}

// checkRenderableRef is CheckRenderable, checkMoves and unionAccounts as
// they were before R-1 (pre-merge review of PR #84), the reference for
// TestCheckRenderableMatchesReference.
func checkRenderableRef(d, installed *Directory) error {
	if d == nil {
		return ErrNoDirectory
	}
	canonical, err := d.Canonical()
	if err != nil {
		return err
	}
	z := newSizer(d, trust.SHA256Hex(canonical))
	var iz *sizer
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
	aboveBound := make(map[string]string, len(d.HostGroups))
	for _, h := range d.HostGroups {
		var was map[string]int
		var old *HostGroup
		if installed != nil {
			if i := slices.IndexFunc(installed.HostGroups, func(x HostGroup) bool { return x.Name == h.Name }); i >= 0 {
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
	byKey := map[string]*Host{}
	for i := range installed.Hosts {
		if o := &installed.Hosts[i]; o.Status == StatusActive {
			for _, k := range o.Keys {
				byKey[k] = o
			}
		}
	}
	unionRef := func(from, to string) int {
		set := map[string]bool{}
		for _, dg := range []struct {
			d    *Directory
			name string
		}{{installed, from}, {d, to}} {
			if i := slices.IndexFunc(dg.d.HostGroups, func(x HostGroup) bool { return x.Name == dg.name }); i >= 0 {
				for _, a := range dg.d.HostGroups[i].Accounts {
					set[a.Account] = true
				}
			}
		}
		return len(set)
	}
	for _, h := range d.Hosts {
		if h.Status != StatusActive {
			continue
		}
		for _, k := range h.Keys {
			o, ok := byKey[k]
			if !ok || o.HostGroup == h.HostGroup {
				continue
			}
			if acc := aboveBound[h.HostGroup]; acc != "" {
				return fmt.Errorf("%w: host %s moves from host group %s to %s, whose account %s has a principals file above %d bytes", ErrUnrenderable, h.Name, o.HostGroup, h.HostGroup, acc, MaxPrincipalsFile)
			}
			if n := unionRef(o.HostGroup, h.HostGroup); n > MaxAccounts {
				return fmt.Errorf("%w: host %s moves from host group %s to %s, %d accounts in the move, above %d", ErrUnrenderable, h.Name, o.HostGroup, h.HostGroup, n, MaxAccounts)
			}
		}
	}
	return nil
}
