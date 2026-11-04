package directory

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/trust"
)

// variedDirectory is a directory of version v whose roles draw
// overlapping principals of many lengths (1 to 128 characters) from one
// pool, and whose host groups, with names of different lengths, map
// accounts to different role lists: none, one, several overlapping, two
// with the same principals, and all. seed varies the draw.
func variedDirectory(v, seed uint64) *Directory {
	x := seed*6364136223846793005 + 1442695040888963407
	next := func(n int) int { // a deterministic draw in [0, n)
		x = x*6364136223846793005 + 1442695040888963407
		return int((x >> 33) % uint64(n)) //nolint:gosec // G115: n is small and positive
	}
	pool := make([]string, 300)
	for i := range pool {
		head := fmt.Sprintf("p%03d", i)
		pool[i] = head + strings.Repeat("y", next(129-len(head)))
	}
	d := &Directory{Version: v, Prev: strings.Repeat("0", 64)}
	for r := range 24 {
		set := map[string]bool{}
		for range 1 + next(MaxRolePrincipals) {
			set[pool[next(len(pool))]] = true
		}
		ps := sortedKeys(set)
		d.Roles = append(d.Roles, Role{Name: fmt.Sprintf("r%02d", r), Principals: ps, MaxTTLSeconds: 3600})
	}
	// Two roles with the same principals.
	d.Roles = append(d.Roles, Role{Name: "twin", Principals: d.Roles[0].Principals, MaxTTLSeconds: 3600})
	all := make([]string, 0, len(d.Roles))
	for _, r := range d.Roles {
		all = append(all, r.Name)
	}
	for g, name := range []string{"a", "lab", "web-frontends", strings.Repeat("g", 64)} {
		h := HostGroup{Name: name, Accounts: []AccountMap{
			{Account: "empty", Roles: []string{}},
			{Account: "one", Roles: []string{"r03"}},
			{Account: "twins", Roles: []string{"r00", "twin"}},
			{Account: "zall", Roles: all},
			{Account: strings.Repeat("_", 32), Roles: []string{"r01", "r02", "r03"}},
		}}
		for a := range 20 + g {
			var roles []string
			for range next(8) {
				roles = append(roles, d.Roles[next(len(d.Roles))].Name)
			}
			h.Accounts = append(h.Accounts, AccountMap{Account: fmt.Sprintf("u%03d", a), Roles: roles})
		}
		d.HostGroups = append(d.HostGroups, h)
	}
	d.Sort()
	return d
}

// TestSizerMatchesRender (F07 (03-08h), owner decision (2026-11-04),
// execution stop at Task 1): the sizer CheckRenderable uses gives every
// account's principals file exactly the length RenderPrincipalsFile
// writes at the widest version: principalsHeader at math.MaxUint64 and
// the directory's SHA-256, then AccountPrincipals one per line. The
// directories are not uniform: accounts map different, overlapping role
// lists, so deduplication decides the sizes.
func TestSizerMatchesRender(t *testing.T) {
	deduped := 0
	for seed := range uint64(8) {
		d := variedDirectory(7+seed*13, seed)
		canonical, err := d.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		sha := trust.SHA256Hex(canonical)
		z := newSizer(d, sha)
		widest := *d
		widest.Version = math.MaxUint64
		for _, h := range d.HostGroups {
			for _, a := range h.Accounts {
				got, err := z.fileSize(h.Name, a)
				if err != nil {
					t.Fatal(err)
				}
				principals, err := AccountPrincipals(d, h.Name, a.Account)
				if err != nil {
					t.Fatal(err)
				}
				want := len(principalsHeader(h.Name, a.Account, math.MaxUint64, sha))
				lines := 0
				for _, p := range principals {
					want += len(p) + 1
				}
				for _, rn := range a.Roles {
					for _, r := range d.Roles {
						if r.Name == rn {
							lines += len(r.Principals)
						}
					}
				}
				if lines > len(principals) {
					deduped++
				}
				file, err := RenderPrincipalsFile(&widest, h.Name, a.Account)
				if err != nil {
					t.Fatal(err)
				}
				if got != want || got != len(file) {
					t.Fatalf("seed %d, %s/%s: sizer %d bytes, want %d (rendered at the widest version: %d)", seed, h.Name, a.Account, got, want, len(file))
				}
			}
		}
	}
	if deduped == 0 {
		t.Fatal("no account maps overlapping principals: the test does not exercise deduplication")
	}
	t.Logf("%d accounts whose roles overlap", deduped)
}
