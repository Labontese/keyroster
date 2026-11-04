//go:build linux

package apply

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
)

// rdir is a directory of version v with users alice and bob (both
// active), role ops (one principal), the roles extra, and host groups.
// CheckRenderable and the renderer need no more: rdir is built directly,
// not through Parse.
func rdir(v uint64, extra []directory.Role, groups ...directory.HostGroup) *directory.Directory {
	d := &directory.Directory{
		Version: v,
		Prev:    strings.Repeat("0", 64),
		Users: []directory.User{
			{Name: "alice", Status: directory.StatusActive, Credentials: []directory.Credential{}},
			{Name: "bob", Status: directory.StatusActive, Credentials: []directory.Credential{}},
		},
		Groups:     []directory.Group{},
		Roles:      append([]directory.Role{{Name: "ops", Principals: []string{"ops"}, MaxTTLSeconds: 3600, Users: []string{"alice", "bob"}}}, extra...),
		HostGroups: groups,
	}
	d.Sort()
	return d
}

// disabled is a copy of d at version v with bob disabled: a change that
// leaves every principals file's lines as they are.
func disabled(d *directory.Directory, v uint64) *directory.Directory {
	c := *d
	c.Version = v
	c.Users = []directory.User{d.Users[0], d.Users[1]}
	c.Users[1].Status = directory.StatusDisabled
	return &c
}

// rgroup is host group name with the accounts names, each mapping ops
// and the roles roles.
func rgroup(name string, names []string, roles ...string) directory.HostGroup {
	h := directory.HostGroup{Name: name, Accounts: make([]directory.AccountMap, 0, len(names))}
	for _, n := range names {
		h.Accounts = append(h.Accounts, directory.AccountMap{Account: n, Roles: append([]string{"ops"}, roles...)})
	}
	return h
}

// rnames is prefix0000, prefix0001, ... n names.
func rnames(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%04d", prefix, i)
	}
	return out
}

// sized returns roles prefix00, prefix01, ... whose principals, with
// role ops, make the principals file of account in hostGroup exactly
// size bytes as RenderPrincipalsFile writes it at the widest version,
// math.MaxUint64: principals of 128 characters, the last tuned to the
// remainder.
func sized(t *testing.T, prefix, hostGroup, account string, size int) []directory.Role {
	t.Helper()
	base := widest(t, rdir(1, nil, rgroup(hostGroup, []string{account})), hostGroup, account)
	const full = 129 // a 128-character principal and its newline
	var ps []string
	for rest := size - base; rest > 0; {
		head := fmt.Sprintf("%s%04d", prefix, len(ps))
		minLine := len(head) + 1
		n := min(rest, full)
		if r := rest - n; r > 0 && r < minLine {
			n = rest - minLine
		}
		if n < minLine {
			t.Fatalf("sized: %d bytes cannot be made from principals of at least %d bytes", size-base, minLine)
		}
		ps = append(ps, head+strings.Repeat("x", n-1-len(head)))
		rest -= n
	}
	var roles []directory.Role
	for i := 0; i < len(ps); i += directory.MaxRolePrincipals {
		roles = append(roles, directory.Role{Name: fmt.Sprintf("%s%02d", prefix, len(roles)), Principals: ps[i:min(i+directory.MaxRolePrincipals, len(ps))], MaxTTLSeconds: 3600})
	}
	return roles
}

// roleNames is the names of roles.
func roleNames(roles []directory.Role) []string {
	out := make([]string, len(roles))
	for i, r := range roles {
		out[i] = r.Name
	}
	return out
}

// atVersion is a copy of d at version v.
func atVersion(d *directory.Directory, v uint64) *directory.Directory {
	c := *d
	c.Version = v
	return &c
}

// widest is the length of the principals file of account in hostGroup
// as RenderPrincipalsFile writes it for d at the widest version.
func widest(t *testing.T, d *directory.Directory, hostGroup, account string) int {
	t.Helper()
	file, err := directory.RenderPrincipalsFile(atVersion(d, math.MaxUint64), hostGroup, account)
	if err != nil {
		t.Fatal(err)
	}
	return len(file)
}

// rgen is the generation's principals files of host group hostGroup of d,
// as Render writes them: PrincipalsDir/<account>, through
// directory.PrincipalsRenderer (byte for byte RenderPrincipalsFile).
func rgen(t *testing.T, d *directory.Directory, hostGroup string) *Generation {
	t.Helper()
	g := &Generation{Files: map[string][]byte{}}
	r := directory.NewPrincipalsRenderer(d)
	for _, h := range d.HostGroups {
		if h.Name != hostGroup {
			continue
		}
		for _, a := range h.Accounts {
			file, err := r.File(hostGroup, a.Account)
			if err != nil {
				t.Fatal(err)
			}
			g.Files[PrincipalsDir+"/"+a.Account] = file
		}
	}
	return g
}

// wantUnrenderable requires err to be ErrUnrenderable naming every one of
// names.
func wantUnrenderable(t *testing.T, err error, names ...string) {
	t.Helper()
	if !errors.Is(err, directory.ErrUnrenderable) {
		t.Fatalf("CheckRenderable = %v, want ErrUnrenderable", err)
	}
	for _, n := range names {
		if !strings.Contains(err.Error(), n) {
			t.Fatalf("CheckRenderable = %v, want it to name %q", err, n)
		}
	}
}

// accept requires CheckRenderable(d, installed) to accept d.
func accept(t *testing.T, d, installed *directory.Directory) {
	t.Helper()
	if err := directory.CheckRenderable(d, installed); err != nil {
		t.Fatalf("CheckRenderable = %v, want it accepted", err)
	}
}

// TestRenderable (F07 (03-08h)): the signer's install-time rule
// (directory.CheckRenderable) and the agent's generation caps (checkLimits)
// agree. A directory the rule accepts renders within the caps, its
// intermediate generation included, at every version; at the boundary the
// rule refuses what the agent would refuse, and is stricter only by the
// width of the version number in the header. Above the caps, nothing may
// grow beyond the installed version (Q-G7).
func TestRenderable(t *testing.T) {
	t.Run("at_share_fits_target_and_intermediate", func(t *testing.T) {
		d1 := rdir(1, nil, rgroup("lab", rnames("a", directory.MaxHostGroupAccounts)))
		d2 := rdir(2, nil, rgroup("lab", rnames("b", directory.MaxHostGroupAccounts)))
		accept(t, d1, nil)
		accept(t, d2, nil)
		g1, g2 := rgen(t, d1, "lab"), rgen(t, d2, "lab")
		for _, g := range []*Generation{g1, g2} {
			if err := checkLimits(g); err != nil {
				t.Fatalf("checkLimits(target) = %v", err)
			}
		}
		m, collapsed := Intermediate(g1, g2)
		if collapsed || len(m.Files) != directory.MaxAccounts {
			t.Fatalf("Intermediate holds %d files (collapsed %v), want %d", len(m.Files), collapsed, directory.MaxAccounts)
		}
		if err := checkLimits(m); err != nil {
			t.Fatalf("checkLimits(intermediate) = %v", err)
		}
	})

	// at is a directory of version v whose host group lab maps root,
	// with a principals file of size bytes at the widest version.
	at := func(t *testing.T, v uint64, size int) *directory.Directory {
		t.Helper()
		roles := sized(t, "p", "lab", "root", size)
		d := rdir(v, roles, rgroup("lab", []string{"root"}, roleNames(roles)...))
		if got := widest(t, d, "lab", "root"); got != size {
			t.Fatalf("lab/root is %d bytes at the widest version, want %d", got, size)
		}
		return d
	}
	t.Run("file_at_cap_accepted", func(t *testing.T) {
		d := at(t, 1, directory.MaxPrincipalsFile)
		accept(t, d, nil)
		g := rgen(t, atVersion(d, math.MaxUint64), "lab")
		if n := len(g.Files[PrincipalsDir+"/root"]); n != directory.MaxPrincipalsFile {
			t.Fatalf("the file is %d bytes at version MaxUint64, want %d", n, directory.MaxPrincipalsFile)
		}
		if err := checkLimits(g); err != nil {
			t.Fatalf("checkLimits = %v, want the file at the cap accepted", err)
		}
	})
	t.Run("file_one_byte_above_cap_refused", func(t *testing.T) {
		d := at(t, 1, directory.MaxPrincipalsFile+1)
		wantUnrenderable(t, directory.CheckRenderable(d, nil), "lab", "root")
		if err := checkLimits(rgen(t, atVersion(d, math.MaxUint64), "lab")); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("checkLimits = %v, want ErrGenerationTooLarge", err)
		}
	})
	t.Run("stricter_than_agent_by_header_width_only", func(t *testing.T) {
		d := at(t, 1, directory.MaxPrincipalsFile+1)
		g := rgen(t, d, "lab")
		if n := len(g.Files[PrincipalsDir+"/root"]); n != directory.MaxPrincipalsFile+1-19 {
			t.Fatalf("the file is %d bytes at version 1, want %d: 19 digits fewer than the widest", n, directory.MaxPrincipalsFile+1-19)
		}
		if err := checkLimits(g); err != nil {
			t.Fatalf("checkLimits = %v at version 1, want accepted", err)
		}
		wantUnrenderable(t, directory.CheckRenderable(d, nil), "lab", "root")
	})
	t.Run("accounts_above_share_refused", func(t *testing.T) {
		d := rdir(1, nil, rgroup("lab", rnames("u", directory.MaxHostGroupAccounts+1)))
		wantUnrenderable(t, directory.CheckRenderable(d, nil), "lab", fmt.Sprint(directory.MaxHostGroupAccounts+1))
	})
	t.Run("intermediate_header_not_longer", func(t *testing.T) {
		d := &directory.Directory{Version: 1, Roles: []directory.Role{}, HostGroups: []directory.HostGroup{{Name: "a", Accounts: []directory.AccountMap{{Account: "a", Roles: []string{}}}}}}
		shortest, err := directory.RenderPrincipalsFile(d, "a", "a")
		if err != nil {
			t.Fatal(err)
		}
		if len(intermediateHeader) > len(shortest) {
			t.Fatalf("intermediateHeader is %d bytes, longer than the shortest real header (%d bytes)", len(intermediateHeader), len(shortest))
		}
	})
	t.Run("check_renderable_is_fast_enough", func(t *testing.T) {
		// No t.Parallel: the wall-clock bound must not share the CPU with
		// the package's parallel tests. It bounds the work the signer does
		// under its lock.
		big := sized(t, "p", "lab", rnames("u", 1)[0], 60<<10)
		names := roleNames(big)
		timed := func(name string, d, installed *directory.Directory) {
			start := time.Now()
			accept(t, d, installed)
			took := time.Since(start)
			t.Logf("%s: %v", name, took)
			if took > 2*time.Second {
				t.Fatalf("%s took %v, above 2 s", name, took)
			}
		}
		share := rdir(2, big, rgroup("lab", rnames("u", directory.MaxHostGroupAccounts), names...))
		timed("normal path, 2048 accounts of about 60 KiB", share, atVersion(share, 1))
		// The exception path for accounts: 4096 accounts of about 60 KiB
		// in both versions, a subset of the installed group.
		agentCap := rdir(1, big, rgroup("lab", rnames("u", directory.MaxAccounts), names...))
		timed("exception path, 4096 accounts of about 60 KiB in both versions", disabled(agentCap, 2), agentCap)
		// The exception path for files too: every file above the bound and
		// unchanged, so every group and file is sized in both versions.
		above := sized(t, "q", "lab", rnames("u", 1)[0], directory.MaxPrincipalsFile+1024)
		installed := rdir(1, above, rgroup("lab", rnames("u", directory.MaxAccounts), roleNames(above)...))
		timed("exception path, 4096 accounts above the bound in both versions", disabled(installed, 2), installed)
	})

	// The non-growth cases (Q-G7): installed host group lab maps 3000
	// accounts, above the share and within the agent's 4096.
	const installedAccounts = 3000
	lab := rnames("u", installedAccounts)
	inst := rdir(1, nil, rgroup("lab", lab))
	t.Run("under_cap_rule_unchanged_with_installed", func(t *testing.T) {
		under := rdir(1, nil, rgroup("lab", append([]string{"root"}, rnames("u", 10)...)))
		wantUnrenderable(t, directory.CheckRenderable(rdir(2, nil, rgroup("lab", rnames("u", directory.MaxHostGroupAccounts+1))), under), "lab")
		wantUnrenderable(t, directory.CheckRenderable(at(t, 2, directory.MaxPrincipalsFile+1), under), "lab", "root")
	})
	// fits requires the move from installed to d to fit the agent's caps.
	fits := func(t *testing.T, installed, d *directory.Directory) {
		t.Helper()
		m, _ := Intermediate(rgen(t, installed, "lab"), rgen(t, d, "lab"))
		if err := checkLimits(m); err != nil {
			t.Fatalf("checkLimits(intermediate) = %v", err)
		}
	}
	t.Run("above_cap_disable_accepted", func(t *testing.T) {
		d := disabled(inst, 2)
		accept(t, d, inst)
		fits(t, inst, d)
	})
	t.Run("above_cap_remove_accepted", func(t *testing.T) {
		d := rdir(2, nil, rgroup("lab", lab[1:]))
		accept(t, d, inst)
		fits(t, inst, d)
	})
	t.Run("above_cap_growth_refused", func(t *testing.T) {
		wantUnrenderable(t, directory.CheckRenderable(rdir(2, nil, rgroup("lab", append(append([]string{}, lab...), "w0000"))), inst), "lab", fmt.Sprint(installedAccounts+1))
	})
	t.Run("above_cap_swap_refused", func(t *testing.T) {
		swapped := append(append([]string{}, lab[1:]...), "w0000")
		wantUnrenderable(t, directory.CheckRenderable(rdir(2, nil, rgroup("lab", swapped)), inst), "lab", fmt.Sprint(installedAccounts))
	})
	t.Run("new_group_above_share_refused", func(t *testing.T) {
		d := rdir(2, nil, rgroup("lab", lab), rgroup("web", rnames("w", directory.MaxHostGroupAccounts+1)))
		wantUnrenderable(t, directory.CheckRenderable(d, inst), "web")
	})
	t.Run("new_group_file_above_bound_refused", func(t *testing.T) {
		roles := sized(t, "p", "web", "root", directory.MaxPrincipalsFile+1)
		d := rdir(2, roles, rgroup("lab", lab), rgroup("web", []string{"root"}, roleNames(roles)...))
		d.HostGroups[1].Accounts = append(d.HostGroups[1].Accounts, directory.AccountMap{Account: "zz", Roles: []string{"ops"}})
		err := directory.CheckRenderable(d, inst)
		wantUnrenderable(t, err, "web", "root")
		if errors.Is(err, directory.ErrUnknownHostGroup) {
			t.Fatalf("CheckRenderable = %v, want no installed-side ErrUnknownHostGroup", err)
		}
	})
	// fileAbove is installed version v whose lab maps the 3000 accounts
	// and root, root's file size bytes at the widest version.
	fileAbove := func(t *testing.T, v uint64, size int) *directory.Directory {
		t.Helper()
		roles := sized(t, "p", "lab", "root", size)
		d := rdir(v, roles, rgroup("lab", lab))
		d.HostGroups[0].Accounts = append(d.HostGroups[0].Accounts, directory.AccountMap{Account: "root", Roles: append([]string{"ops"}, roleNames(roles)...)})
		if got := widest(t, d, "lab", "root"); got != size {
			t.Fatalf("lab/root is %d bytes at the widest version, want %d", got, size)
		}
		return d
	}
	// grown is d at version v with one more principal for root.
	grown := func(d *directory.Directory, v uint64) *directory.Directory {
		c := disabled(d, v)
		c.Roles = append(append([]directory.Role{}, d.Roles...), directory.Role{Name: "zz", Principals: []string{"zz"}, MaxTTLSeconds: 3600})
		c.HostGroups = []directory.HostGroup{{Name: "lab", Accounts: append([]directory.AccountMap{}, d.HostGroups[0].Accounts...)}}
		root := &c.HostGroups[0].Accounts[len(c.HostGroups[0].Accounts)-1]
		root.Roles = append(append([]string{}, root.Roles...), "zz")
		return c
	}
	t.Run("above_cap_file_not_grown_accepted", func(t *testing.T) {
		installed := fileAbove(t, 1, 70<<10)
		accept(t, disabled(installed, 2), installed)
	})
	t.Run("above_cap_file_grown_refused", func(t *testing.T) {
		installed := fileAbove(t, 1, 70<<10)
		wantUnrenderable(t, directory.CheckRenderable(grown(installed, 2), installed), "lab", "root")
	})
	t.Run("rendered_file_above_cap_refused", func(t *testing.T) {
		installed := fileAbove(t, 1, directory.MaxPrincipalsFile)
		accept(t, disabled(installed, 2), installed)
		offered := fileAbove(t, 2, directory.MaxPrincipalsFile+1)
		wantUnrenderable(t, directory.CheckRenderable(offered, installed), "lab", "root")
	})
	// The version-digit cases (Q-G7): a file at the agent's cap as
	// RenderPrincipalsFile writes it at version from (before this
	// release), unchanged at version from+1, which has one more digit.
	for _, from := range []uint64{9, 99} {
		t.Run(fmt.Sprintf("rollover_%d_to_%d_file_at_cap_accepted", from, from+1), func(t *testing.T) {
			digits := len(fmt.Sprint(uint64(math.MaxUint64))) - len(fmt.Sprint(from))
			installed := fileAbove(t, from, directory.MaxPrincipalsFile+digits)
			if n := len(rgen(t, installed, "lab").Files[PrincipalsDir+"/root"]); n != directory.MaxPrincipalsFile {
				t.Fatalf("lab/root is %d bytes at version %d, want %d (the agent's cap)", n, from, directory.MaxPrincipalsFile)
			}
			accept(t, disabled(installed, from+1), installed)
		})
	}
	// A host moved to another host group (owner decision (2026-11-04),
	// execution stop at Task 1). On the agent the move from lab to the
	// target group goes through Intermediate(lab's generation, the
	// target's), which checkCandidate checks with checkLimits; the signer
	// refuses exactly when that check would fail.
	movedTo := func(t *testing.T, to directory.HostGroup, roles []directory.Role) (*directory.Directory, *directory.Directory) {
		t.Helper()
		host := func(v uint64, group string, groups ...directory.HostGroup) *directory.Directory {
			d := rdir(v, roles, groups...)
			d.Hosts = []directory.Host{{Name: "h1", HostGroup: group, Keys: []string{"ssh-ed25519 h1"}, Principals: []string{"h1"}, Status: directory.StatusActive}}
			return d
		}
		return host(1, "lab", rgroup("lab", lab), to), host(2, to.Name, rgroup("lab", lab), to)
	}
	agentMove := func(t *testing.T, installed, offered *directory.Directory, to string) error {
		t.Helper()
		target := rgen(t, offered, to)
		if err := checkLimits(target); err != nil {
			return err
		}
		m, _ := Intermediate(rgen(t, installed, "lab"), target)
		return checkLimits(m)
	}
	t.Run("host_moved_union_above_cap_refused", func(t *testing.T) {
		to := rgroup("web", rnames("w", directory.MaxAccounts-installedAccounts+1))
		installed, offered := movedTo(t, to, nil)
		wantUnrenderable(t, directory.CheckRenderable(offered, installed), "h1", "lab", "web", fmt.Sprint(directory.MaxAccounts+1))
		if err := agentMove(t, installed, offered, "web"); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("the agent's move = %v, want ErrGenerationTooLarge", err)
		}
		if err := directory.CheckRenderable(disabled(installed, 2), installed); err != nil {
			t.Fatalf("CheckRenderable without the move = %v, want it accepted: the move decides", err)
		}
	})
	t.Run("host_moved_union_at_cap_accepted", func(t *testing.T) {
		to := rgroup("web", rnames("w", directory.MaxAccounts-installedAccounts))
		installed, offered := movedTo(t, to, nil)
		accept(t, offered, installed)
		if err := agentMove(t, installed, offered, "web"); err != nil {
			t.Fatalf("the agent's move = %v, want it to fit", err)
		}
	})
	t.Run("host_moved_to_file_above_bound_refused", func(t *testing.T) {
		// web/root is above the bound, accepted for web's hosts because
		// the installed web/root is as large (Q-G7); h1 never rendered it.
		roles := sized(t, "p", "web", "root", directory.MaxPrincipalsFile+1)
		to := rgroup("web", []string{"root"}, roleNames(roles)...)
		installed, offered := movedTo(t, to, roles)
		if err := directory.CheckRenderable(disabled(installed, 2), installed); err != nil {
			t.Fatalf("CheckRenderable without the move = %v, want it accepted", err)
		}
		wantUnrenderable(t, directory.CheckRenderable(offered, installed), "h1", "web", "root")
		if err := agentMove(t, atVersion(installed, math.MaxUint64), atVersion(offered, math.MaxUint64), "web"); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("the agent's move at the widest version = %v, want ErrGenerationTooLarge", err)
		}
	})
	t.Run("rollover_file_within_bound_stays_within_cap", func(t *testing.T) {
		installed := fileAbove(t, 9, directory.MaxPrincipalsFile)
		offered := disabled(installed, 10)
		accept(t, offered, installed)
		if err := checkLimits(rgen(t, offered, "lab")); err != nil {
			t.Fatalf("checkLimits(version 10) = %v, want the file within 64 KiB", err)
		}
	})
}
