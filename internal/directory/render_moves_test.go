package directory

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
	"golang.org/x/crypto/ssh"
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
	t.Run("hosts_from_many_groups_into_above_share_group", func(t *testing.T) {
		// C-1 (fix-round check, PR #84): installed (above the share, Q-G7)
		// has big, 4096 accounts, and 3700 groups of one of big's
		// accounts, each with one host. The offered version keeps big and
		// moves every host into it: 3700 pairs of 4097 accounts in the
		// two groups, 4096 in their union. Valid and within
		// wire.MaxDirectory.
		bigNames := moveNames("u", 0, MaxAccounts)
		groups := []HostGroup{moveGroup("big", bigNames)}
		var from, to []Host
		for i := range 3700 {
			name := fmt.Sprintf("g%05d", i)
			groups = append(groups, moveGroup(name, bigNames[i:i+1]))
			h := Host{Name: fmt.Sprintf("h%05d", i), HostGroup: name, Keys: []string{realKey(t, i)}, Principals: []string{fmt.Sprintf("h%05d", i)}, Status: StatusActive}
			from = append(from, h)
			h.HostGroup = "big"
			to = append(to, h)
		}
		installed := moveDir(1, groups, from)
		offered := moveDir(2, slices.Clone(groups), to)
		for _, d := range []*Directory{installed, offered} {
			c, err := d.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if len(c) > wire.MaxDirectory {
				t.Fatalf("version %d is %d bytes, above wire.MaxDirectory (%d)", d.Version, len(c), wire.MaxDirectory)
			}
			if _, err := Parse(c); err != nil {
				t.Fatalf("version %d does not parse: %v", d.Version, err)
			}
			t.Logf("version %d: %d bytes", d.Version, len(c))
		}
		timed(t, "3700 hosts from 3700 one-account groups into big (4096)", offered, installed)
	})
}

// realKey is the trust.FormatKey form of a deterministic Ed25519 key for i.
func realKey(t *testing.T, i int) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	binary.BigEndian.PutUint32(seed, uint32(i)+1) //nolint:gosec // G115: i is small and positive
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(pub)
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
	t.Run("same_source_two_targets", func(t *testing.T) {
		// C-3 (fix-round check of PR #84): h0 moves from lab to db
		// (3000 + 1096, fits) and h1 from lab to web (3000 + 1097).
		groups := func() []HostGroup {
			return []HostGroup{moveGroup("db", moveNames("d", 0, MaxAccounts-3000)), moveGroup("lab", lab), moveGroup("web", moveNames("w", 0, MaxAccounts-3000+1))}
		}
		installed := moveDir(1, groups(), []Host{
			{Name: "h0", HostGroup: "lab", Keys: []string{"k0"}, Principals: []string{"h0"}, Status: StatusActive},
			{Name: "h1", HostGroup: "lab", Keys: []string{"k1"}, Principals: []string{"h1"}, Status: StatusActive},
		})
		offered := moveDir(2, groups(), []Host{
			{Name: "h0", HostGroup: "db", Keys: []string{"k0"}, Principals: []string{"h0"}, Status: StatusActive},
			{Name: "h1", HostGroup: "web", Keys: []string{"k1"}, Principals: []string{"h1"}, Status: StatusActive},
		})
		err := CheckRenderable(offered, installed)
		if !errors.Is(err, ErrUnrenderable) || !strings.Contains(err.Error(), "host h1 moves from host group lab to web, 4097 accounts") {
			t.Fatalf("CheckRenderable = %v, want h1's move to web refused with 4097 accounts", err)
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

// TestMoveByName (R-2, owner decision (2026-11-04), pre-merge review of
// PR #84): an active host of the offered version and an active host of
// installed with the same name in different host groups are a move, also
// when no host key is shared: a version that replaces a host's keys and
// moves it leaves the agent on its last-good principals (host_keys_rotated)
// until sshd's keys change, and then it meets the intermediate of both
// groups.
func TestMoveByName(t *testing.T) {
	lab := moveNames("u", 0, 3000)
	groups := func(web int) []HostGroup {
		return []HostGroup{moveGroup("lab", lab), moveGroup("web", moveNames("w", 0, web))}
	}
	t.Run("rekeyed_and_moved_above_cap_refused", func(t *testing.T) {
		err := CheckRenderable(moveOne(2, groups(MaxAccounts-3000+1), "web", "k2"), moveOne(1, groups(MaxAccounts-3000+1), "lab", "k1"))
		if !errors.Is(err, ErrUnrenderable) || !strings.Contains(err.Error(), "host h1 moves from host group lab to web, 4097 accounts") {
			t.Fatalf("CheckRenderable = %v, want h1's move refused with 4097 accounts", err)
		}
	})
	t.Run("rekeyed_and_moved_at_cap_accepted", func(t *testing.T) {
		if err := CheckRenderable(moveOne(2, groups(MaxAccounts-3000), "web", "k2"), moveOne(1, groups(MaxAccounts-3000), "lab", "k1")); err != nil {
			t.Fatalf("CheckRenderable = %v, want the move of %d accounts accepted", err, MaxAccounts)
		}
	})
	t.Run("disabled_installed_host_not_a_move", func(t *testing.T) {
		// A disabled entry renders no principals files, so the agent
		// holds none of lab's.
		installed := moveOne(1, groups(MaxAccounts-3000+1), "lab", "k1")
		installed.Hosts[0].Status = StatusDisabled
		if err := CheckRenderable(moveOne(2, groups(MaxAccounts-3000+1), "web", "k2"), installed); err != nil {
			t.Fatalf("CheckRenderable = %v, want it accepted", err)
		}
	})
	// C-2 (owner decision (2026-11-04), fix-round check of PR #84): the
	// name counts only for a host with a key no active installed host
	// holds, a possible rekey. A host whose every key is known is found
	// by its keys, as its agent finds it. Installed: x (k1) in lab, y (k2)
	// in web, 4097 accounts together.
	host := func(name, group string, keys ...string) Host {
		return Host{Name: name, HostGroup: group, Keys: keys, Principals: []string{name}, Status: StatusActive}
	}
	xy := moveDir(1, groups(MaxAccounts-3000+1), []Host{host("x", "lab", "k1"), host("y", "web", "k2")})
	t.Run("names_swapped_accepted", func(t *testing.T) {
		// Each host keeps its group and keys under the other's name.
		offered := moveDir(2, groups(MaxAccounts-3000+1), []Host{host("x", "web", "k2"), host("y", "lab", "k1")})
		if err := CheckRenderable(offered, xy); err != nil {
			t.Fatalf("CheckRenderable = %v, want it accepted: no host moves", err)
		}
	})
	t.Run("renamed_onto_removed_name_accepted", func(t *testing.T) {
		// y is removed, and x takes its name, in lab with k1.
		offered := moveDir(2, groups(MaxAccounts-3000+1), []Host{host("y", "lab", "k1")})
		if err := CheckRenderable(offered, xy); err != nil {
			t.Fatalf("CheckRenderable = %v, want it accepted: no host moves", err)
		}
	})
	t.Run("known_and_fresh_key_refused", func(t *testing.T) {
		// y now lists x's k1 and a fresh key, in lab. x's agent finds y in
		// lab, no move. y's agent (sshd k2) finds no entry, keeps web's
		// files by name (host_keys_rotated), and meets web with lab once
		// sshd has the fresh key.
		offered := moveDir(2, groups(MaxAccounts-3000+1), []Host{host("y", "lab", "k1", "k3")})
		err := CheckRenderable(offered, xy)
		if !errors.Is(err, ErrUnrenderable) || !strings.Contains(err.Error(), "host y moves from host group web to lab, 4097 accounts") {
			t.Fatalf("CheckRenderable = %v, want y's move from web refused with 4097 accounts", err)
		}
	})
}

// TestMoveGroupsAndKeys (R-3, pre-merge review of PR #84): a move's union
// is installed's from group with the offered to group, each as its own
// version defines it, and every key of both entries counts. h1 moves from
// lab (3000 accounts) to web unless a case says otherwise.
func TestMoveGroupsAndKeys(t *testing.T) {
	lab := moveNames("u", 0, 3000)
	above := MaxAccounts - 3000 + 1 // web's size that puts the move above MaxAccounts
	refusedMove := func(t *testing.T, d, installed *Directory, want string) {
		t.Helper()
		err := CheckRenderable(d, installed)
		if !errors.Is(err, ErrUnrenderable) || !strings.Contains(err.Error(), want) {
			t.Fatalf("CheckRenderable = %v, want ErrUnrenderable with %q", err, want)
		}
	}
	t.Run("target_grown_in_offered_refused", func(t *testing.T) {
		// web maps 500 accounts in installed (the move would fit) and
		// 1097 in the offered version, which the agent renders.
		installed := moveOne(1, []HostGroup{moveGroup("lab", lab), moveGroup("web", moveNames("w", 0, 500))}, "lab", "k1")
		offered := moveOne(2, []HostGroup{moveGroup("lab", lab), moveGroup("web", moveNames("w", 0, above))}, "web", "k1")
		refusedMove(t, offered, installed, "host h1 moves from host group lab to web, 4097 accounts")
	})
	t.Run("source_shrunk_in_offered_refused", func(t *testing.T) {
		// The offered lab keeps 2000 of its accounts (the move would fit),
		// but the agent leaves installed's lab, all 3000 of them.
		installed := moveOne(1, []HostGroup{moveGroup("lab", lab), moveGroup("web", moveNames("w", 0, 2000))}, "lab", "k1")
		offered := moveOne(2, []HostGroup{moveGroup("lab", lab[:2000]), moveGroup("web", moveNames("w", 0, 2000))}, "web", "k1")
		refusedMove(t, offered, installed, "host h1 moves from host group lab to web, 5000 accounts")
	})
	groups := func() []HostGroup {
		return []HostGroup{moveGroup("db", moveNames("d", 0, 10)), moveGroup("lab", lab), moveGroup("web", moveNames("w", 0, above))}
	}
	t.Run("shared_key_last_of_four_refused", func(t *testing.T) {
		// Renamed (so its name finds nothing) and three keys replaced: the
		// one key both versions list sorts last in both.
		installed := moveOne(1, groups(), "lab", "k1a", "k1b", "k1c", "k9")
		offered := moveDir(2, groups(), []Host{{Name: "h2", HostGroup: "web", Keys: []string{"k2a", "k2b", "k2c", "k9"}, Principals: []string{"h2"}, Status: StatusActive}})
		refusedMove(t, offered, installed, "host h2 moves from host group lab to web, 4097 accounts")
	})
	t.Run("second_matching_host_refused", func(t *testing.T) {
		// h3's first key was x's, in db (the move fits), its second y's,
		// in lab.
		installed := moveDir(1, groups(), []Host{
			{Name: "x", HostGroup: "db", Keys: []string{"ka"}, Principals: []string{"x"}, Status: StatusActive},
			{Name: "y", HostGroup: "lab", Keys: []string{"kb"}, Principals: []string{"y"}, Status: StatusActive},
		})
		offered := moveDir(2, groups(), []Host{{Name: "h3", HostGroup: "web", Keys: []string{"ka", "kb"}, Principals: []string{"h3"}, Status: StatusActive}})
		refusedMove(t, offered, installed, "host h3 moves from host group lab to web, 4097 accounts")
	})
}

// movePair is an installed directory and an offered version for the
// equivalence check: host groups a to d of sizes around the share and the
// cap, drawn as runs of one pool of account names so that groups overlap
// by varying amounts, a few accounts with a file above MaxPrincipalsFile,
// and hosts with 1 to 4 keys drawn from a pool of 40, some disabled, some
// in a group the other version does not define, some renamed. Each
// version's key sets are as Validate requires them, no key twice in a
// host or on two hosts (C-2, fix-round check of PR #84); across the
// versions a key may move to another host. seed varies the draw.
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
	keyPool := moveNames("ssh-ed25519 k", 0, 40)
	// keys draws 1 to 4 keys of keyPool that used does not hold, and marks
	// them used: at most 7 hosts of 4 keys draw from 40.
	keys := func(used map[string]bool) []string {
		var out []string
		for n := 1 + next(4); len(out) < n; {
			if k := keyPool[next(len(keyPool))]; !used[k] {
				used[k] = true
				out = append(out, k)
			}
		}
		return out
	}
	host := func(name string) Host {
		h := Host{Name: name, Principals: []string{name}, Status: StatusActive}
		if next(5) == 0 {
			h.Status = StatusDisabled
		}
		h.HostGroup = append(slices.Clone(names), "zz")[next(len(names)+1)]
		return h
	}
	var ih, oh []Host
	installedKeys := map[string]bool{}
	for i := range 6 {
		h := host(fmt.Sprintf("h%d", i))
		h.Keys = keys(installedKeys)
		ih = append(ih, h)
	}
	// Offered: each installed host again, two in three with its keys
	// (marked first, so no drawn key takes them), some renamed, in a
	// drawn group, and one more host.
	offeredKeys := map[string]bool{}
	kept := make([]bool, len(ih))
	for i, o := range ih {
		if kept[i] = next(3) > 0; kept[i] {
			for _, k := range o.Keys {
				offeredKeys[k] = true
			}
		}
	}
	for i, o := range ih {
		h := host(o.Name)
		if next(4) == 0 {
			h.Name = "r" + o.Name
			h.Principals = []string{h.Name}
		}
		if kept[i] {
			h.Keys = slices.Clone(o.Keys)
		} else {
			h.Keys = keys(offeredKeys)
		}
		oh = append(oh, h)
	}
	h9 := host("h9")
	h9.Keys = keys(offeredKeys)
	oh = append(oh, h9)
	installed = &Directory{Version: 1, Prev: strings.Repeat("0", 64), Roles: roles, HostGroups: ig, Hosts: ih}
	offered = &Directory{Version: 2, Prev: strings.Repeat("0", 64), Roles: slices.Clone(roles), HostGroups: og, Hosts: oh}
	installed.Sort()
	offered.Sort()
	return installed, offered
}

// TestCheckRenderableMatchesReference (R-1): CheckRenderable gives exactly
// the answers of checkRenderableRef, the implementation before R-1, which
// looks host groups up by a scan and counts a move's union once per
// matching host, with R-2's match by name added (for a host with a fresh
// key, C-2): accept or refuse, and
// the same error text, so the same first failing host. The draws must
// reach every kind of answer.
func TestCheckRenderableMatchesReference(t *testing.T) {
	kinds := map[string]int{}
	for seed := range uint64(96) {
		installed, offered := movePair(seed)
		for _, d := range []*Directory{installed, offered} {
			owner := map[string]string{}
			for _, h := range d.Hosts {
				for _, k := range h.Keys {
					if o, dup := owner[k]; dup {
						t.Fatalf("seed %d, version %d: key %s on %s and %s, which Validate refuses", seed, d.Version, k, o, h.Name)
					}
					owner[k] = h.Name
				}
			}
		}
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
// they were before R-1 (pre-merge review of PR #84), with R-2's match by
// name added as a scan, for a host with a key no active installed host
// lists (C-2), the reference for
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
		var olds []*Host
		for _, k := range h.Keys {
			if o, ok := byKey[k]; ok {
				olds = append(olds, o)
			}
		}
		fresh := slices.ContainsFunc(h.Keys, func(k string) bool {
			return !slices.ContainsFunc(installed.Hosts, func(o Host) bool { return o.Status == StatusActive && slices.Contains(o.Keys, k) })
		})
		if i := slices.IndexFunc(installed.Hosts, func(o Host) bool { return o.Status == StatusActive && o.Name == h.Name }); fresh && i >= 0 {
			olds = append(olds, &installed.Hosts[i])
		}
		for _, o := range olds {
			if o.HostGroup == h.HostGroup {
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
