package trust

import (
	"fmt"
	"slices"
	"time"
)

// ActiveCA returns b's active CA entry for role, or the zero entry when b
// has none (03-12b).
func ActiveCA(b *Bundle, role string) CAEntry {
	for _, ca := range b.CAs {
		if ca.Role == role && ca.State == "active" {
			return ca
		}
	}
	return CAEntry{}
}

// IssuingCAs returns b's active and next CA entries for role, in
// generation order: the keys that may sign for the role. A retired entry
// is never among them, so an aborted next key answers for nobody
// (03-12b).
func IssuingCAs(b *Bundle, role string) []CAEntry {
	var out []CAEntry
	for _, ca := range b.CAs {
		if ca.Role == role && (ca.State == "active" || ca.State == "next") {
			out = append(out, ca)
		}
	}
	slices.SortStableFunc(out, func(x, y CAEntry) int {
		switch {
		case x.Generation < y.Generation:
			return -1
		case x.Generation > y.Generation:
			return 1
		}
		return 0
	})
	return out
}

// TrustedAt reports whether the entry's key is trusted at t (03-12c).
func (CAEntry) TrustedAt(_ time.Time) bool { return false }

// TrustedCAs returns b's entries of role that are trusted at t, in
// generation order (03-12c).
func TrustedCAs(_ *Bundle, _ string, _ time.Time) []CAEntry { return nil }

// UserCAKeysFile is the agent's user_ca_keys for b at t (03-12c).
func UserCAKeysFile(_ *Bundle, _ time.Time) ([]byte, error) { return nil, nil }

// UserCAKeysFileExcept is UserCAKeysFile without the entries skip names
// (03-12c).
func UserCAKeysFileExcept(_ *Bundle, _ time.Time, _ func(CAEntry) bool) ([]byte, error) {
	return nil, nil
}

// checkCATransitions is the chain rule for CA entries (03-12b). Entries
// are never removed, so next lists every generation prev lists, and for
// each of user, host and machine, compared by generation, next may differ
// from prev in at most one of these ways:
//
//   - not at all;
//   - one entry is added, in state next, at a generation above every
//     generation the role has in prev (retired ones included), while the
//     role has no next entry in prev, with a key that equals no key of
//     prev (any CA entry in any state, the ops key, the log key, any root
//     key) and no key added for another role in this successor;
//   - one next entry becomes retired (an abort) with every other field
//     unchanged.
//
// Anything else is ErrVersionChain naming the role and the generation. The
// count of a role's changes is checked before any addition's own
// conditions, so a role with two changes always reports the count.
// checkSuccessorChain runs it for the signer, every agent, audit, root
// sign --prev and trust verify --prev; the client commands that only
// verify a served bundle against the pins run no chain rule. 03-12e adds
// the switch here, and the policy parameters when its rule needs them.
// Both bundles must already be structurally valid.
func checkCATransitions(prev, next *Bundle) error {
	prevKeys := map[string]bool{}
	addKey := func(where, key string) error {
		pub, err := ParseKey(key)
		if err != nil {
			return fmt.Errorf("%w: previous bundle %s: %w", ErrInvalid, where, err)
		}
		prevKeys[string(pub.Marshal())] = true
		return nil
	}
	for _, ca := range prev.CAs {
		if err := addKey("CA "+ca.Role, ca.Key); err != nil {
			return err
		}
	}
	if err := addKey("ops key", prev.OpsKey.Key); err != nil {
		return err
	}
	if err := addKey("log key", prev.Log.Key); err != nil {
		return err
	}
	for _, rk := range prev.Root.Keys {
		if err := addKey("root key", rk.Key); err != nil {
			return err
		}
	}
	added := map[string]bool{}
	for _, role := range caRoles {
		if err := checkRoleTransition(role, prev, next, prevKeys, added); err != nil {
			return err
		}
	}
	return nil
}

// checkRoleTransition applies checkCATransitions's rule to one role. added
// collects the keys this successor adds, across roles.
func checkRoleTransition(role string, prev, next *Bundle, prevKeys, added map[string]bool) error {
	refuse := func(gen uint32, reason string) error {
		return fmt.Errorf("%w: CA %s generation %d: %s", ErrVersionChain, role, gen, reason)
	}
	var after []CAEntry
	for _, ca := range next.CAs {
		if ca.Role == role {
			after = append(after, ca)
		}
	}
	// Each entry of prev is matched with next's entry of the same
	// generation, an identical one first, so that a successor that repeats
	// a generation (which Validate refuses before this rule runs in
	// production) shows as an addition, not as a change. What is left of
	// next is added.
	used := make([]bool, len(after))
	match := func(old CAEntry) int {
		for _, identical := range []bool{true, false} {
			for j, cur := range after {
				if !used[j] && cur.Generation == old.Generation && (!identical || cur == old) {
					used[j] = true
					return j
				}
			}
		}
		return -1
	}
	var maxGen uint32
	hasNext := false
	var changes []uint32
	for _, old := range prev.CAs {
		if old.Role != role {
			continue
		}
		maxGen = max(maxGen, old.Generation)
		if old.State == "next" {
			hasNext = true
		}
		j := match(old)
		if j < 0 {
			return refuse(old.Generation, "an entry is removed")
		}
		cur := after[j]
		if cur == old {
			continue
		}
		aborted := old
		aborted.State = "retired"
		if old.State != "next" || cur != aborted {
			return refuse(old.Generation, "an entry changes (only a next entry may become retired)")
		}
		changes = append(changes, old.Generation)
	}
	var additions []CAEntry
	for j, ca := range after {
		if !used[j] {
			additions = append(additions, ca)
			changes = append(changes, ca.Generation)
		}
	}
	if len(changes) > 1 {
		return refuse(slices.Min(changes), "more than one change for this role")
	}
	for _, ca := range additions {
		if ca.State != "next" {
			return refuse(ca.Generation, "a new entry must be next")
		}
		if hasNext {
			return refuse(ca.Generation, "the role already has a next entry")
		}
		if ca.Generation <= maxGen {
			return refuse(ca.Generation, "the generation is not above every earlier generation of the role")
		}
		pub, err := ParseKey(ca.Key)
		if err != nil {
			return fmt.Errorf("%w: CA %s generation %d: %w", ErrInvalid, role, ca.Generation, err)
		}
		k := string(pub.Marshal())
		if prevKeys[k] {
			return refuse(ca.Generation, "the key equals a key of the previous bundle")
		}
		if added[k] {
			return refuse(ca.Generation, "the key is added twice in this successor")
		}
		added[k] = true
	}
	return nil
}
