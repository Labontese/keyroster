package rootceremony

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

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
//
// A line whose new state is draining also names the entry's trusted_until,
// and the line of a switch, whose old state is active, the advised install
// time (03-12e2):
//
//	CA <role> gen <N> <fingerprint>: active -> draining, trusted until <t>; install by <i> (advice)
//
// i is next's issued_at plus the allowance, which is t minus
// trust.DrainFloor of next's issued_at and the role's max_ttl_seconds in
// prevPol (prev's policy) and in nextPol (next's), the floor the chain rule
// and BuildSuccessor use. "install by" is the time by which the signer must
// stop issuing with the old key, by the signer's clock; it is advice and
// never a refusal. See installBy for when it cannot be given.
func CAChanges(prev, next *trust.Bundle, prevPol, nextPol *trust.Policy) string {
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
		fmt.Fprintf(&w, "CA %s gen %d %s: %s -> %s", e.Role, e.Generation, fp, from, to)
		if to == "draining" {
			fmt.Fprintf(&w, ", trusted until %s", e.TrustedUntil)
			if from == "active" {
				w.WriteString("; install by " + installBy(next.IssuedAt, e, prevPol, nextPol))
			}
		}
		w.WriteString("\n")
	}
	if w.Len() == 0 {
		return "CA entries: unchanged\n"
	}
	return w.String()
}

// installBy is the advice of a switch's line (03-12e2): "<i> (advice)",
// with i the successor's issued_at plus the allowance, trusted_until minus
// the floor. A nil policy, a role with no profile in either policy, a
// floor that cannot be computed, or a trusted_until that does not parse or
// lies below the floor print "unknown (advice)"; an allowance above
// trust.MaxDrainAllowance, which only a hand-built successor carries (root
// sign caps the flag, and the chain rule bounds trusted_until from below
// only), says that root sign never builds it and that it is not to be
// installed or distributed. It does not say that the signer refuses it:
// the signer's upper bound is measured from its install clock, so it
// accepts such an allowance up to the cap plus 300 s plus the time between
// issued_at and the install, and the host agents enforce no cap at all, so
// the cap is the root holders' check. None of them is a refusal.
func installBy(issuedAt string, e trust.CAEntry, prevPol, nextPol *trust.Policy) string {
	const unknown = "unknown (advice)"
	ttlPrev, okPrev := trust.RoleMaxTTL(prevPol, e.Role)
	ttlNext, okNext := trust.RoleMaxTTL(nextPol, e.Role)
	if !okPrev || !okNext {
		return unknown
	}
	floor, err := trust.DrainFloor(issuedAt, ttlPrev, ttlNext)
	if err != nil {
		return unknown
	}
	until, err := time.Parse(trust.TimeFormat, e.TrustedUntil)
	if err != nil || until.Unix() < 0 || uint64(until.Unix()) < floor { //nolint:gosec // G115: not negative, checked first
		return unknown
	}
	allowance := uint64(until.Unix()) - floor //nolint:gosec // G115: not negative, checked above
	if allowance > uint64(trust.MaxDrainAllowance/time.Second) {
		return "unknown (advice: the allowance " + seconds(allowance) + " is above the cap of " + trust.MaxDrainAllowance.String() + ", which root sign never builds; do not install or distribute this bundle)"
	}
	// DrainFloor parsed issuedAt, so the error is nil.
	issued, _ := time.Parse(trust.TimeFormat, issuedAt)
	return issued.Add(time.Duration(allowance)*time.Second).UTC().Format(trust.TimeFormat) + " (advice)" //nolint:gosec // G115: at most the cap's seconds
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
