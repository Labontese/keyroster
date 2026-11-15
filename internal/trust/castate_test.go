package trust

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Seeds of the CA keys the CA-transition cases add (P-256, as the golden
// CA keys are).
const (
	seedCANext   = 60
	seedCANext2  = 61
	seedCAOther  = 63
	seedCARotate = 64
)

// caAt is a CA entry for role in the golden CA shape (P-256, vtpm) with
// the key of seed, in state at generation gen.
func caAt(t *testing.T, role string, seed byte, state string, gen uint32) CAEntry {
	t.Helper()
	return CAEntry{Role: role, Key: keyOf(p256Key(t, seed)), Alg: ssh.KeyAlgoECDSA256, Custody: "vtpm", State: state, Generation: gen}
}

// goldenCA is the golden bundle's generation 1 entry of role.
func goldenCA(t *testing.T, role string) CAEntry {
	t.Helper()
	seed := map[string]byte{RoleUser: seedUserCA, RoleHost: seedHostCA, RoleMachine: seedMachCA}[role]
	return caAt(t, role, seed, "active", 1)
}

// caPair returns the golden bundle with the user entries prevUser, and a
// copy of it with the user entries nextUser; the host and machine entries
// are the golden ones in both, unless edit changes next.
func caPair(t *testing.T, prevUser, nextUser []CAEntry, edit func(prev, next *Bundle)) (prev, next *Bundle) {
	t.Helper()
	policy := mustCanonical(t, goldenPolicy(t))
	prev = goldenBundle(t, policy)
	rest := slices.Clone(prev.CAs[1:])
	prev.CAs = append(slices.Clone(prevUser), rest...)
	n := *prev
	n.Root.Keys = slices.Clone(prev.Root.Keys)
	n.CAs = append(slices.Clone(nextUser), slices.Clone(rest)...)
	next = &n
	if edit != nil {
		edit(prev, next)
	}
	return prev, next
}

// mustChainRefusal requires err to be ErrVersionChain naming the role, the
// generation and the reason of the output contract (03-12b).
func mustChainRefusal(t *testing.T, err error, role string, gen int, reason string) {
	t.Helper()
	if !errors.Is(err, ErrVersionChain) {
		t.Fatalf("err = %v, want ErrVersionChain", err)
	}
	where := fmt.Sprintf("CA %s generation %d: ", role, gen)
	if !strings.Contains(err.Error(), where+reason) {
		t.Fatalf("err = %q, want it to hold %q", err, where+reason)
	}
}

// TestCATransitions (03-12b): the chain rule for CA entries accepts per
// role no change, one next entry added, or one next entry aborted, and
// refuses everything else with ErrVersionChain naming the role, the
// generation and the reason.
func TestCATransitions(t *testing.T) {
	u1 := goldenCA(t, RoleUser)
	const (
		reasonRemoved  = "an entry is removed"
		reasonChanges  = "an entry changes (only a next entry may become retired)"
		reasonNotNext  = "a new entry must be next"
		reasonHasNext  = "the role already has a next entry"
		reasonNotAbove = "the generation is not above every earlier generation of the role"
		reasonPrevKey  = "the key equals a key of the previous bundle"
		reasonTwice    = "the key is added twice in this successor"
		reasonCount    = "more than one change for this role"
	)
	for _, c := range []struct {
		name       string
		prev, next []CAEntry
		edit       func(prev, next *Bundle)
		role       string
		gen        int
		reason     string // "" accepts
	}{
		{name: "unchanged_ok",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2), caAt(t, RoleUser, seedCANext2, "next", 3)},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2), caAt(t, RoleUser, seedCANext2, "next", 3)}},
		{name: "add_next_ok",
			prev: []CAEntry{u1},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)}},
		{name: "add_second_next_refused",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2), caAt(t, RoleUser, seedCANext2, "next", 3)},
			role: RoleUser, gen: 3, reason: reasonHasNext},
		{name: "next_key_equal_retired_key_refused",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2)},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2), caAt(t, RoleUser, seedCANext, "next", 3)},
			role: RoleUser, gen: 3, reason: reasonPrevKey},
		{name: "next_key_equal_other_role_key_refused",
			prev: []CAEntry{u1},
			next: []CAEntry{u1, caAt(t, RoleUser, seedHostCA, "next", 2)},
			role: RoleUser, gen: 2, reason: reasonPrevKey},
		{name: "next_key_equal_prev_root_refused",
			prev: []CAEntry{u1},
			next: []CAEntry{u1, caAt(t, RoleUser, seedRootB, "next", 2)},
			// The successor's root set no longer lists root B.
			edit: func(_, next *Bundle) { next.Root.Keys = next.Root.Keys[:1] },
			role: RoleUser, gen: 2, reason: reasonPrevKey},
		{name: "next_keys_equal_across_roles_refused",
			prev: []CAEntry{u1},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			edit: func(_, next *Bundle) {
				next.CAs = slices.Insert(next.CAs, 3, caAt(t, RoleHost, seedCANext, "next", 2))
			},
			role: RoleHost, gen: 2, reason: reasonTwice},
		{name: "add_active_refused",
			prev: []CAEntry{u1},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "active", 2)},
			role: RoleUser, gen: 2, reason: reasonNotNext},
		{name: "abort_next_ok",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2)}},
		{name: "abort_active_refused",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			next: []CAEntry{caAt(t, RoleUser, seedUserCA, "retired", 1), caAt(t, RoleUser, seedCANext, "next", 2)},
			role: RoleUser, gen: 1, reason: reasonChanges},
		{name: "abort_changes_key_refused",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext2, "retired", 2)},
			role: RoleUser, gen: 2, reason: reasonChanges},
		{name: "retired_back_to_next_refused",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2)},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			role: RoleUser, gen: 2, reason: reasonChanges},
		{name: "entry_removed_refused",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2)},
			next: []CAEntry{u1},
			role: RoleUser, gen: 2, reason: reasonRemoved},
		{name: "custody_changed_refused",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			next: []CAEntry{u1, func() CAEntry { e := caAt(t, RoleUser, seedCANext, "next", 2); e.Custody = "software"; return e }()},
			role: RoleUser, gen: 2, reason: reasonChanges},
		{name: "active_key_changed_refused",
			prev: []CAEntry{u1},
			next: []CAEntry{caAt(t, RoleUser, seedCARotate, "active", 1)},
			role: RoleUser, gen: 1, reason: reasonChanges},
		{name: "two_transitions_one_role_refused",
			prev: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2), caAt(t, RoleUser, seedCANext2, "next", 3)},
			role: RoleUser, gen: 2, reason: reasonCount},
		{name: "two_additions_one_role_refused",
			// The one input no other condition refuses: only the count of
			// the role's changes can.
			prev: []CAEntry{u1},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2), caAt(t, RoleUser, seedCANext2, "next", 3)},
			role: RoleUser, gen: 2, reason: reasonCount},
		{name: "two_roles_one_change_each_ok",
			prev: []CAEntry{u1},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 2)},
			edit: func(prev, next *Bundle) {
				prev.CAs = slices.Insert(prev.CAs, 2, caAt(t, RoleHost, seedCAOther, "next", 2))
				next.CAs = slices.Insert(next.CAs, 3, caAt(t, RoleHost, seedCAOther, "retired", 2))
			}},
		{name: "generation_gap_ok",
			prev: []CAEntry{u1},
			next: []CAEntry{u1, caAt(t, RoleUser, seedCANext, "next", 5)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			prev, next := caPair(t, c.prev, c.next, c.edit)
			err := checkCATransitions(prev, next)
			if c.reason == "" {
				if err != nil {
					t.Fatalf("checkCATransitions: %v, want nil", err)
				}
				return
			}
			mustChainRefusal(t, err, c.role, c.gen, c.reason)
		})
	}
	t.Run("next_generation_not_above_prev_refused", func(t *testing.T) {
		// Equal to the previous maximum: a repeated generation, which
		// Validate refuses first in production, so only a direct call
		// reaches the rule with it.
		prev, next := caPair(t,
			[]CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2)},
			[]CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2), caAt(t, RoleUser, seedCANext2, "next", 2)}, nil)
		mustChainRefusal(t, checkCATransitions(prev, next), RoleUser, 2, reasonNotAbove)
		// Below it, in the order Validate requires.
		prev, next = caPair(t,
			[]CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 3)},
			[]CAEntry{u1, caAt(t, RoleUser, seedCANext2, "next", 2), caAt(t, RoleUser, seedCANext, "retired", 3)}, nil)
		if err := next.Validate(); err != nil {
			t.Fatalf("the successor does not validate: %v", err)
		}
		mustChainRefusal(t, checkCATransitions(prev, next), RoleUser, 2, reasonNotAbove)
	})
	t.Run("installation_id_new_with_next_ok", func(t *testing.T) {
		// The previous bundle has no installation ID; the successor adds
		// one and a next entry, through checkSuccessorChain (the combined
		// ceremony of 03-15).
		policy := mustCanonical(t, goldenPolicy(t))
		prev := goldenBundle(t, policy)
		prevBytes := mustCanonical(t, prev)
		next := *prev
		next.Version, next.Prev, next.IssuedAt = 2, SHA256Hex(prevBytes), rotationIssued
		next.InstallationID = "0123456789abcdef0123456789abcdef"
		next.CAs = slices.Insert(slices.Clone(prev.CAs), 1, caAt(t, RoleUser, seedCANext, "next", 2))
		if err := next.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := checkSuccessorChain(prev, prevBytes, policy, &next, policy); err != nil {
			t.Fatalf("checkSuccessorChain: %v, want nil", err)
		}
	})
}

// TestActiveCA (03-12b).
func TestActiveCA(t *testing.T) {
	b, _ := caPair(t, []CAEntry{caAt(t, RoleUser, seedCANext, "retired", 1), caAt(t, RoleUser, seedUserCA, "active", 2), caAt(t, RoleUser, seedCANext2, "next", 3)}, nil, nil)
	t.Run("returns_the_active_entry", func(t *testing.T) {
		if got, want := ActiveCA(b, RoleUser), caAt(t, RoleUser, seedUserCA, "active", 2); got != want {
			t.Fatalf("ActiveCA = %+v, want %+v", got, want)
		}
	})
	t.Run("zero_for_unknown_role", func(t *testing.T) {
		if got := ActiveCA(b, "ops"); got != (CAEntry{}) {
			t.Fatalf("ActiveCA(ops) = %+v, want the zero entry", got)
		}
	})
}

// TestIssuingCAs (03-12b): the active and next entries of a role, in
// generation order, never a retired one.
func TestIssuingCAs(t *testing.T) {
	u1 := goldenCA(t, RoleUser)
	b, _ := caPair(t, []CAEntry{u1, caAt(t, RoleUser, seedCANext, "retired", 2), caAt(t, RoleUser, seedCANext2, "next", 3)}, nil, nil)
	t.Run("active_and_next_by_generation", func(t *testing.T) {
		got := IssuingCAs(b, RoleUser)
		if want := []CAEntry{u1, caAt(t, RoleUser, seedCANext2, "next", 3)}; !slices.Equal(got, want) {
			t.Fatalf("IssuingCAs = %+v, want %+v", got, want)
		}
	})
	t.Run("retired_excluded", func(t *testing.T) {
		for _, role := range caRoles {
			for _, ca := range IssuingCAs(b, role) {
				if ca.State == "retired" {
					t.Fatalf("IssuingCAs(%s) holds the retired generation %d", role, ca.Generation)
				}
			}
		}
	})
}

// TestSuccessorChainRunsCARule (03-12b): checkSuccessorChain itself runs
// the CA rule, so the signer, every agent, audit and the ceremony tool
// refuse the same CA changes.
func TestSuccessorChainRunsCARule(t *testing.T) {
	policy := mustCanonical(t, goldenPolicy(t))
	prev := goldenBundle(t, policy)
	prevBytes := mustCanonical(t, prev)
	next := *prev
	next.Version, next.Prev, next.IssuedAt = 2, SHA256Hex(prevBytes), rotationIssued
	next.CAs = slices.Clone(prev.CAs)
	next.CAs[0] = caAt(t, RoleUser, seedCARotate, "active", 1)
	if err := next.Validate(); err != nil {
		t.Fatal(err)
	}
	_, err := checkSuccessorChain(prev, prevBytes, policy, &next, policy)
	mustChainRefusal(t, err, RoleUser, 1, "an entry changes (only a next entry may become retired)")
}
