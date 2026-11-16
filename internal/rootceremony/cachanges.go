package rootceremony

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/Labontese/keyroster/internal/trust"
)

// CAChanges is the CA-change section of a successor, for the root holders
// to read before they sign (03-12b): the one line "CA entries: unchanged"
// when no CA entry of next differs from prev's, else one line per entry
// that differs, in the bundle's order (role, then generation),
//
//	CA <role> gen <N> <fingerprint>: <old> -> <new>
//
// where the fingerprint is the SHA256 fingerprint of the entry's key, old
// is the state in prev or "none" for an added entry, and new is the state
// in next or "removed" for an entry next lacks (which the chain rule
// refuses, so only a direct call prints it).
func CAChanges(prev, next *trust.Bundle) string {
	type ref struct {
		role int
		gen  uint32
	}
	roleIndex := func(role string) int {
		return slices.Index([]string{trust.RoleUser, trust.RoleHost, trust.RoleMachine}, role)
	}
	index := func(b *trust.Bundle) map[ref]trust.CAEntry {
		m := map[ref]trust.CAEntry{}
		for _, ca := range b.CAs {
			m[ref{roleIndex(ca.Role), ca.Generation}] = ca
		}
		return m
	}
	before, after := index(prev), index(next)
	var refs []ref
	for r := range before {
		refs = append(refs, r)
	}
	for r := range after {
		if _, ok := before[r]; !ok {
			refs = append(refs, r)
		}
	}
	slices.SortFunc(refs, func(x, y ref) int {
		if c := cmp.Compare(x.role, y.role); c != 0 {
			return c
		}
		return cmp.Compare(x.gen, y.gen)
	})
	var w strings.Builder
	for _, r := range refs {
		old, inPrev := before[r]
		cur, inNext := after[r]
		if inPrev && inNext && old == cur {
			continue
		}
		from, to, e := "none", "removed", cur
		if inPrev {
			from = old.State
		}
		if inNext {
			to = cur.State
		} else {
			e = old
		}
		fp, _ := describe(e.Key)
		fmt.Fprintf(&w, "CA %s gen %d %s: %s -> %s\n", e.Role, e.Generation, fp, from, to)
	}
	if w.Len() == 0 {
		return "CA entries: unchanged\n"
	}
	return w.String()
}

// RootSetLine is the root-set line of a successor (03-12b): "Root set:
// unchanged" when prev and next list the same root keys (by wire encoding,
// in any order), else "Root set: CHANGED (added N, removed M)". It
// compares keys only: a change of the threshold shows in Summary's "Root
// keys (threshold N of M)" line.
func RootSetLine(prev, next *trust.Bundle) string {
	keys := func(b *trust.Bundle) map[string]bool {
		m := map[string]bool{}
		for _, r := range b.Root.Keys {
			if pub, err := trust.ParseKey(r.Key); err == nil {
				m[string(pub.Marshal())] = true
			} else {
				m[r.Key] = true
			}
		}
		return m
	}
	before, after := keys(prev), keys(next)
	added, removed := 0, 0
	for k := range after {
		if !before[k] {
			added++
		}
	}
	for k := range before {
		if !after[k] {
			removed++
		}
	}
	if added == 0 && removed == 0 {
		return "Root set: unchanged\n"
	}
	return fmt.Sprintf("Root set: CHANGED (added %d, removed %d)\n", added, removed)
}
