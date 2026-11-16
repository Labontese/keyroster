package trust

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

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
	// The draining cases (03-12c) start from a hand-built previous bundle
	// whose user role holds g1 draining (until drainEnd) and g2 active.
	// 03-12b's rule already compares whole entries, so they pin the owner
	// decisions the format makes expressible: the end is immutable, there
	// is no draining-to-retired move, no draining entry can be created and
	// no entry is removed.
	d1 := drainingAt(t, RoleUser, seedCARotate, 1, drainEnd)
	a2 := caAt(t, RoleUser, seedCANext, "active", 2)
	d1Other := drainingAt(t, RoleUser, seedCARotate, 1, "2026-10-27T00:00:00Z")
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
		{name: "draining_unchanged_ok",
			prev: []CAEntry{d1, a2},
			next: []CAEntry{d1, a2}},
		{name: "draining_kept_with_next_added_ok",
			prev: []CAEntry{d1, a2},
			next: []CAEntry{d1, a2, caAt(t, RoleUser, seedCANext2, "next", 3)}},
		{name: "draining_trusted_until_changed_refused",
			prev: []CAEntry{d1, a2},
			next: []CAEntry{d1Other, a2},
			role: RoleUser, gen: 1, reason: reasonChanges},
		{name: "draining_to_retired_refused",
			// The retired entry carries no trusted_until, the form Validate
			// allows.
			prev: []CAEntry{d1, a2},
			next: []CAEntry{caAt(t, RoleUser, seedCARotate, "retired", 1), a2},
			role: RoleUser, gen: 1, reason: reasonChanges},
		{name: "draining_to_active_refused",
			prev: []CAEntry{d1, a2},
			next: []CAEntry{caAt(t, RoleUser, seedCARotate, "active", 1), a2},
			role: RoleUser, gen: 1, reason: reasonChanges},
		{name: "active_to_draining_refused",
			prev: []CAEntry{d1, a2},
			next: []CAEntry{d1, drainingAt(t, RoleUser, seedCANext, 2, drainEnd)},
			role: RoleUser, gen: 2, reason: reasonChanges},
		{name: "new_draining_refused",
			prev: []CAEntry{d1, a2},
			next: []CAEntry{d1, a2, drainingAt(t, RoleUser, seedCANext2, 3, drainEnd)},
			role: RoleUser, gen: 3, reason: reasonNotNext},
		{name: "draining_removed_refused",
			prev: []CAEntry{d1, a2},
			next: []CAEntry{a2},
			role: RoleUser, gen: 1, reason: reasonRemoved},
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

// drainEnd is the end of the draining entries of the 03-12c cases.
const drainEnd = "2026-10-20T00:00:00Z"

// drainingAt is caAt in state draining with the end end (03-12c).
func drainingAt(t *testing.T, role string, seed byte, gen uint32, end string) CAEntry {
	t.Helper()
	e := caAt(t, role, seed, "draining", gen)
	e.TrustedUntil = end
	return e
}

// mustTime parses a TimeFormat time.
func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	at, err := time.Parse(TimeFormat, s)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// TestTrustedAt (03-12c): active and next entries are always trusted, a
// draining one strictly before its end, a retired one never, and a
// draining one whose end does not parse never.
func TestTrustedAt(t *testing.T) {
	end := mustTime(t, drainEnd)
	d := drainingAt(t, RoleUser, seedCANext, 2, drainEnd)
	times := []time.Time{{}, end.Add(-time.Hour), end, end.Add(1000 * time.Hour)}
	t.Run("active_and_next_always", func(t *testing.T) {
		for _, state := range []string{"active", "next"} {
			ca := caAt(t, RoleUser, seedCANext, state, 2)
			for _, at := range times {
				if !ca.TrustedAt(at) {
					t.Fatalf("a %s entry is not trusted at %v", state, at)
				}
			}
		}
	})
	t.Run("retired_never", func(t *testing.T) {
		ca := caAt(t, RoleUser, seedCANext, "retired", 2)
		ca.TrustedUntil = drainEnd
		for _, at := range times {
			if ca.TrustedAt(at) {
				t.Fatalf("a retired entry is trusted at %v", at)
			}
		}
	})
	t.Run("draining_before_the_end_by_1s", func(t *testing.T) {
		if !d.TrustedAt(end.Add(-time.Second)) {
			t.Fatal("a draining entry is not trusted 1 s before its end")
		}
	})
	t.Run("draining_before_the_end_by_1ns", func(t *testing.T) {
		if !d.TrustedAt(end.Add(-time.Nanosecond)) {
			t.Fatal("a draining entry is not trusted 1 ns before its end")
		}
	})
	t.Run("draining_at_the_end_false", func(t *testing.T) {
		if d.TrustedAt(end) {
			t.Fatal("a draining entry is trusted at its end")
		}
	})
	t.Run("draining_after_the_end_false", func(t *testing.T) {
		if d.TrustedAt(end.Add(time.Second)) {
			t.Fatal("a draining entry is trusted after its end")
		}
	})
	t.Run("unparsable_end_untrusted", func(t *testing.T) {
		for _, bad := range []string{"", "2026-10-20 00:00:00", "2026-10-20T00:00:00.5Z", "2026-10-20T02:00:00+02:00"} {
			e := d
			e.TrustedUntil = bad
			if e.TrustedAt(end.Add(-1000 * time.Hour)) {
				t.Fatalf("a draining entry whose end is %q is trusted", bad)
			}
		}
	})
}

// rotationUsers is a user role with one entry in each state: retired g1,
// draining g2 (ending at drainEnd), active g3 and next g4 (03-12c).
func rotationUsers(t *testing.T) []CAEntry {
	t.Helper()
	return []CAEntry{
		caAt(t, RoleUser, seedCAOther, "retired", 1),
		drainingAt(t, RoleUser, seedCANext, 2, drainEnd),
		caAt(t, RoleUser, seedUserCA, "active", 3),
		caAt(t, RoleUser, seedCANext2, "next", 4),
	}
}

// TestTrustedCAs (03-12c): the entries of one role trusted at a time, by
// generation.
func TestTrustedCAs(t *testing.T) {
	end := mustTime(t, drainEnd)
	u := rotationUsers(t)
	b, _ := caPair(t, u, nil, nil)
	t.Run("by_generation", func(t *testing.T) {
		if got, want := TrustedCAs(b, RoleUser, end.Add(-time.Hour)), u[1:]; !slices.Equal(got, want) {
			t.Fatalf("TrustedCAs = %+v, want %+v", got, want)
		}
	})
	t.Run("draining_dropped_at_the_end", func(t *testing.T) {
		if got, want := TrustedCAs(b, RoleUser, end), u[2:]; !slices.Equal(got, want) {
			t.Fatalf("TrustedCAs at the end = %+v, want %+v", got, want)
		}
	})
	t.Run("retired_never", func(t *testing.T) {
		only, _ := caPair(t, []CAEntry{caAt(t, RoleUser, seedCAOther, "retired", 1), caAt(t, RoleUser, seedUserCA, "active", 2)}, nil, nil)
		if got, want := TrustedCAs(only, RoleUser, end), []CAEntry{caAt(t, RoleUser, seedUserCA, "active", 2)}; !slices.Equal(got, want) {
			t.Fatalf("TrustedCAs = %+v, want %+v", got, want)
		}
	})
	t.Run("roles_are_separate", func(t *testing.T) {
		for role, want := range map[string][]CAEntry{RoleHost: {goldenCA(t, RoleHost)}, RoleMachine: {goldenCA(t, RoleMachine)}} {
			if got := TrustedCAs(b, role, end.Add(-time.Hour)); !slices.Equal(got, want) {
				t.Fatalf("TrustedCAs(%s) = %+v, want %+v", role, got, want)
			}
		}
	})
}

// TestUserCAKeysFile (03-12c): the agent's user_ca_keys is one plain key
// line per trusted entry, user role then machine role, each by
// generation.
func TestUserCAKeysFile(t *testing.T) {
	end := mustTime(t, drainEnd)
	u := rotationUsers(t)
	m1, m2 := goldenCA(t, RoleMachine), caAt(t, RoleMachine, seedCARotate, "next", 2)
	b, _ := caPair(t, u, nil, func(prev, _ *Bundle) { prev.CAs = append(prev.CAs, m2) })
	text := func(entries ...CAEntry) []byte {
		var out []byte
		for _, e := range entries {
			out = append(out, e.Key+"\n"...)
		}
		return out
	}
	t.Run("user_then_machine_by_generation", func(t *testing.T) {
		got, err := UserCAKeysFile(b, end.Add(-time.Hour))
		if want := text(u[1], u[2], u[3], m1, m2); err != nil || string(got) != string(want) {
			t.Fatalf("UserCAKeysFile = %q, %v, want %q", got, err, want)
		}
	})
	t.Run("draining_dropped_at_the_end", func(t *testing.T) {
		got, err := UserCAKeysFile(b, end)
		if want := text(u[2], u[3], m1, m2); err != nil || string(got) != string(want) {
			t.Fatalf("UserCAKeysFile at the end = %q, %v, want %q", got, err, want)
		}
	})
	t.Run("plain_lines_only", func(t *testing.T) {
		got, err := UserCAKeysFile(b, end.Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		s := string(got)
		if !strings.HasSuffix(s, "\n") || strings.HasSuffix(s, "\n\n") || strings.Contains(s, "#") {
			t.Fatalf("the file %q must end in exactly one newline and hold no comment", s)
		}
		lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
		if len(lines) != 5 {
			t.Fatalf("the file has %d lines, want 5: %q", len(lines), s)
		}
		for _, l := range lines {
			_, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(l))
			if err != nil || comment != "" || len(options) != 0 || len(rest) != 0 {
				t.Fatalf("line %q: comment %q, options %q, rest %q, %v; want a plain key line", l, comment, options, rest, err)
			}
		}
	})
	t.Run("except_skips_entries", func(t *testing.T) {
		got, err := UserCAKeysFileExcept(b, end.Add(-time.Hour), func(e CAEntry) bool { return e.Role == RoleUser && e.Generation == 3 })
		if want := text(u[1], u[3], m1, m2); err != nil || string(got) != string(want) {
			t.Fatalf("UserCAKeysFileExcept = %q, %v, want %q", got, err, want)
		}
	})
	t.Run("error_for_an_unparsable_key", func(t *testing.T) {
		bad := slices.Clone(u)
		bad[2].Key = "ecdsa-sha2-nistp256 not-a-key"
		nb, _ := caPair(t, bad, nil, nil)
		got, err := UserCAKeysFile(nb, end.Add(-time.Hour))
		if err == nil || got != nil {
			t.Fatalf("UserCAKeysFile of a key that does not parse = %q, %v; want an error and no bytes", got, err)
		}
	})
}
