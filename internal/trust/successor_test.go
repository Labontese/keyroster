package trust

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Seeds of the successor fixture's extra roots (rootA is the golden root A,
// rootC is seedRootC from verify_test.go).
const (
	seedSuccRootB = 51
	seedSuccRootD = 52
)

// rotation is the homelab rotation shape: a previous bundle with roots
// {A, B} at threshold 1 and its v1 policy, rotated to roots {C, D} at
// threshold 1.
type rotation struct {
	a, b, c, d ssh.Signer
	prev       *Bundle
	prevBytes  []byte
	policy     []byte
}

const rotationIssued = "2026-10-06T00:00:00Z"

func newRotation(t *testing.T) *rotation {
	t.Helper()
	r := &rotation{a: edKey(t, seedRootA), b: edKey(t, seedSuccRootB), c: edKey(t, seedRootC), d: edKey(t, seedSuccRootD)}
	r.policy = mustCanonical(t, goldenPolicy(t))
	r.prev = goldenBundle(t, r.policy)
	r.prev.Root = RootSet{Keys: rootKeysOf(r.a, r.b), Threshold: 1}
	r.prevBytes = mustCanonical(t, r.prev)
	return r
}

func rootKeysOf(signers ...ssh.Signer) []RootKey {
	out := make([]RootKey, 0, len(signers))
	for _, s := range signers {
		out = append(out, RootKey{Key: keyOf(s), Custody: "software"})
	}
	return out
}

// policyV2 returns a v2 policy chained to r.policy (a shorter user TTL),
// edited by edit.
func (r *rotation) policyV2(t *testing.T, edit func(p *Policy)) []byte {
	t.Helper()
	p := goldenPolicy(t)
	p.CAProfiles[0].MaxTTLSeconds = 3600
	p.Version, p.Prev = 2, SHA256Hex(r.policy)
	edit(p)
	return mustCanonical(t, p)
}

// verify signs next and policy with signers and runs VerifySuccessor
// against r's previous bundle and policy.
func (r *rotation) verify(t *testing.T, prevCanonical, prevPolicy, next, policy []byte, signers ...ssh.Signer) error {
	t.Helper()
	_, _, err := VerifySuccessor(r.prev, prevCanonical, prevPolicy, next, signAll(t, NamespaceBundle, next, signers...),
		policy, signAll(t, NamespacePolicy, policy, signers...))
	return err
}

func TestBuildSuccessor(t *testing.T) {
	r := newRotation(t)

	t.Run("round_trip_unchanged_policy", func(t *testing.T) {
		next, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, SuccessorOptions{Roots: rootKeysOf(r.c, r.d), Threshold: 1, Policy: r.policy, IssuedAt: rotationIssued, InstallationID: ""})
		if err != nil {
			t.Fatal(err)
		}
		if next.Version != 2 || next.Prev != SHA256Hex(r.prevBytes) || next.IssuedAt != rotationIssued || next.PolicySHA256 != SHA256Hex(r.policy) {
			t.Fatalf("successor header = v%d prev %s issued %s policy %s", next.Version, next.Prev, next.IssuedAt, next.PolicySHA256)
		}
		doc := mustCanonical(t, next)
		if err := r.verify(t, r.prevBytes, r.policy, doc, r.policy, r.a, r.c); err != nil {
			t.Fatalf("signed by previous root A and new root C: %v", err)
		}
		if err := r.verify(t, r.prevBytes, r.policy, doc, r.policy, r.c, r.d); !errors.Is(err, ErrThreshold) {
			t.Fatalf("signed by the new roots only: err = %v, want %v", err, ErrThreshold)
		}
		if err := r.verify(t, r.prevBytes, r.policy, doc, r.policy, r.a, r.b); !errors.Is(err, ErrThreshold) {
			t.Fatalf("signed by the previous roots only: err = %v, want %v", err, ErrThreshold)
		}
	})

	t.Run("round_trip_chained_policy", func(t *testing.T) {
		policy := r.policyV2(t, func(*Policy) {})
		next, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, SuccessorOptions{Roots: rootKeysOf(r.c, r.d), Threshold: 1, Policy: policy, IssuedAt: rotationIssued, InstallationID: ""})
		if err != nil {
			t.Fatal(err)
		}
		if err := r.verify(t, r.prevBytes, r.policy, mustCanonical(t, next), policy, r.a, r.c); err != nil {
			t.Fatalf("chained v2 policy signed by A and C: %v", err)
		}
	})

	t.Run("carries_online_keys", func(t *testing.T) {
		r := newRotation(t) // its own fixture: the alias check edits it
		next, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, SuccessorOptions{Roots: rootKeysOf(r.c, r.d), Threshold: 1, Policy: r.policy, IssuedAt: rotationIssued, InstallationID: ""})
		if err != nil {
			t.Fatal(err)
		}
		for _, pair := range [][2]any{{next.CAs, r.prev.CAs}, {next.OpsKey, r.prev.OpsKey}, {next.Log, r.prev.Log}} {
			if got, want := mustCanonical(t, pair[0]), mustCanonical(t, pair[1]); !bytes.Equal(got, want) {
				t.Fatalf("successor carries %s, previous bundle %s", got, want)
			}
		}
		// The CA entries are a copy: editing the successor's never edits
		// the previous bundle's.
		next.CAs[0].State = "retired"
		if r.prev.CAs[0].State != "active" {
			t.Fatal("the successor's CA entries alias the previous bundle's")
		}
	})

	sameVersionChanged := func() []byte {
		p := goldenPolicy(t)
		p.CAProfiles[0].MaxTTLSeconds = 3600
		return mustCanonical(t, p)
	}()
	refusals := []struct {
		name          string
		prevCanonical []byte // nil means r.prevBytes
		prevPolicy    []byte // nil means r.policy
		roots         []RootKey
		policy        []byte // nil means r.policy
		issuedAt      string // "" means rotationIssued
		want          error
		wantText      string
	}{
		{name: "prev_canonical_differs", prevCanonical: append(bytes.Clone(r.prevBytes[:len(r.prevBytes)-1]), ' ', '\n'), want: ErrVersionChain},
		// policy equals prevPolicy, so only the prevPolicy hash check can
		// refuse it.
		{name: "prev_policy_hash_mismatch", prevPolicy: sameVersionChanged, policy: sameVersionChanged, want: ErrVersionChain},
		{name: "policy_same_version_changed", policy: sameVersionChanged, want: ErrVersionChain},
		{name: "policy_version_plus_two", policy: r.policyV2(t, func(p *Policy) { p.Version = 3 }), want: ErrVersionChain},
		{name: "policy_wrong_prev", policy: r.policyV2(t, func(p *Policy) { p.Prev = SHA256Hex([]byte("another policy")) }), want: ErrVersionChain},
		{name: "issued_before_prev", issuedAt: "2026-10-04T00:00:00Z", want: ErrVersionChain, wantText: "clock"},
		{name: "admin_is_new_root", policy: r.policyV2(t, func(p *Policy) {
			p.Admins = append(p.Admins, AdminKey{Name: "carol", Key: keyOf(r.c)})
		}), want: ErrKeyIsRoot},
		{name: "admin_is_previous_root", policy: r.policyV2(t, func(p *Policy) {
			p.Admins = append(p.Admins, AdminKey{Name: "bob", Key: keyOf(r.b)})
		}), want: ErrKeyIsRoot},
		// G-WR-01: root A, software in the bundle in force, is carried into
		// the successor relabelled piv. The key and its exposure are
		// unchanged, so the label would launder it into a hardware claim.
		{name: "carried_root_changes_custody", roots: []RootKey{{Key: keyOf(r.a), Custody: "piv"}, {Key: keyOf(r.c), Custody: "software"}},
			want: ErrCustody, wantText: "changes custody from software to piv"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			prevCanonical, prevPolicy, policy, issuedAt := r.prevBytes, r.policy, r.policy, rotationIssued
			if tc.prevCanonical != nil {
				prevCanonical = tc.prevCanonical
			}
			if tc.prevPolicy != nil {
				prevPolicy = tc.prevPolicy
			}
			if tc.policy != nil {
				policy = tc.policy
			}
			if tc.issuedAt != "" {
				issuedAt = tc.issuedAt
			}
			roots := rootKeysOf(r.c, r.d)
			if tc.roots != nil {
				roots = tc.roots
			}
			b, err := BuildSuccessor(r.prev, prevCanonical, prevPolicy, SuccessorOptions{Roots: roots, Threshold: 1, Policy: policy, IssuedAt: issuedAt, InstallationID: ""})
			if !errors.Is(err, tc.want) || b != nil {
				t.Fatalf("BuildSuccessor: bundle %v, err = %v, want %v", b, err, tc.want)
			}
			if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
				t.Fatalf("BuildSuccessor error %q does not mention %q", err, tc.wantText)
			}
			// The bundle the builder refused, assembled by hand and signed
			// by both root sets, is refused by the verifier the same way.
			next := mustCanonical(t, &Bundle{
				Version: r.prev.Version + 1, Prev: SHA256Hex(prevCanonical), IssuedAt: issuedAt,
				Root: RootSet{Keys: roots, Threshold: 1}, CAs: r.prev.CAs, OpsKey: r.prev.OpsKey, Log: r.prev.Log,
				PolicySHA256: SHA256Hex(policy),
			})
			if err := r.verify(t, prevCanonical, prevPolicy, next, policy, r.a, r.c); !errors.Is(err, tc.want) {
				t.Fatalf("VerifySuccessor: err = %v, want %v", err, tc.want)
			}
		})
	}

	for _, tc := range []struct {
		name      string
		threshold uint32
	}{{"threshold_zero", 0}, {"threshold_above_roots", 3}} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, SuccessorOptions{Roots: rootKeysOf(r.c, r.d), Threshold: tc.threshold, Policy: r.policy, IssuedAt: rotationIssued, InstallationID: ""})
			if !errors.Is(err, ErrInvalid) || b != nil {
				t.Fatalf("bundle %v, err = %v, want %v", b, err, ErrInvalid)
			}
		})
	}
}

// caRotation is a rotation fixture whose previous bundle holds the user
// entries users (the host and machine entries are the golden ones), with
// prevBytes re-encoded.
func caRotation(t *testing.T, users ...CAEntry) *rotation {
	t.Helper()
	r := newRotation(t)
	r.prev.CAs = append(slices.Clone(users), r.prev.CAs[1:]...)
	if err := r.prev.Validate(); err != nil {
		t.Fatal(err)
	}
	r.prevBytes = mustCanonical(t, r.prev)
	return r
}

// buildCA builds r's successor under the previous roots and policy with the
// given CA changes.
func (r *rotation) buildCA(next []CAEntry, retire []CARef) (*Bundle, error) {
	return BuildSuccessor(r.prev, r.prevBytes, r.policy, SuccessorOptions{
		Roots: r.prev.Root.Keys, Threshold: 1, Policy: r.policy, IssuedAt: rotationIssued, CANext: next, CARetire: retire,
	})
}

// TestBuildSuccessorCAChanges (03-12b): BuildSuccessor adds each CANext
// entry as next in generation order and retires each CARetire reference,
// and refuses what the chain rule and Validate refuse.
func TestBuildSuccessorCAChanges(t *testing.T) {
	u1 := goldenCA(t, RoleUser)
	t.Run("adds_next_in_order", func(t *testing.T) {
		r := caRotation(t, u1)
		add := caAt(t, RoleUser, seedCANext, "active", 2) // the builder sets next
		b, err := r.buildCA([]CAEntry{add}, nil)
		if err != nil {
			t.Fatalf("BuildSuccessor: %v", err)
		}
		want := caAt(t, RoleUser, seedCANext, "next", 2)
		if len(b.CAs) != 4 || b.CAs[0] != u1 || b.CAs[1] != want || b.CAs[2].Role != RoleHost {
			t.Fatalf("successor CAs %+v, want the next user entry right after generation 1", b.CAs)
		}
		if err := b.Validate(); err != nil {
			t.Fatalf("the successor does not validate: %v", err)
		}
		// Before an entry of higher generation: inserted in order, the
		// result validates, and only the chain rule refuses it.
		r = caRotation(t, u1, caAt(t, RoleUser, seedCANext2, "retired", 3))
		_, err = r.buildCA([]CAEntry{caAt(t, RoleUser, seedCANext, "next", 2)}, nil)
		if errors.Is(err, ErrCARole) {
			t.Fatalf("generation 2 below a held 3 was not inserted in order: %v", err)
		}
		mustChainRefusal(t, err, RoleUser, 2, "the generation is not above every earlier generation of the role")
	})
	t.Run("retires_next", func(t *testing.T) {
		r := caRotation(t, u1, caAt(t, RoleUser, seedCANext, "next", 2))
		b, err := r.buildCA(nil, []CARef{{Role: RoleUser, Generation: 2}})
		if err != nil {
			t.Fatalf("BuildSuccessor: %v", err)
		}
		if got, want := b.CAs[1], caAt(t, RoleUser, seedCANext, "retired", 2); got != want {
			t.Fatalf("aborted entry %+v, want %+v", got, want)
		}
		if r.prev.CAs[1].State != "next" {
			t.Fatal("the abort edited the previous bundle's entry")
		}
	})
	t.Run("retire_of_active_refused", func(t *testing.T) {
		r := caRotation(t, u1, caAt(t, RoleUser, seedCANext, "next", 2))
		b, err := r.buildCA(nil, []CARef{{Role: RoleUser, Generation: 1}})
		if b != nil {
			t.Fatalf("BuildSuccessor built %+v", b)
		}
		mustChainRefusal(t, err, RoleUser, 1, "only a next entry can be retired")
	})
	t.Run("retire_of_unknown_refused", func(t *testing.T) {
		r := caRotation(t, u1, caAt(t, RoleUser, seedCANext, "next", 2))
		b, err := r.buildCA(nil, []CARef{{Role: RoleUser, Generation: 9}})
		if b != nil {
			t.Fatalf("BuildSuccessor built %+v", b)
		}
		mustChainRefusal(t, err, RoleUser, 9, "no such entry")
	})
	t.Run("next_key_equal_prev_key_refused", func(t *testing.T) {
		// Validate runs first in the builder and refuses the duplicate key.
		r := caRotation(t, u1)
		b, err := r.buildCA([]CAEntry{caAt(t, RoleUser, seedHostCA, "next", 2)}, nil)
		if b != nil || !errors.Is(err, ErrDuplicateKey) {
			t.Fatalf("BuildSuccessor = %+v, %v; want ErrDuplicateKey", b, err)
		}
	})
	t.Run("next_generation_not_above_refused", func(t *testing.T) {
		r := caRotation(t, u1, caAt(t, RoleUser, seedCANext2, "retired", 3))
		// Strictly below the role's maximum, inserted in order: Validate
		// passes and the chain rule refuses.
		b, err := r.buildCA([]CAEntry{caAt(t, RoleUser, seedCANext, "next", 2)}, nil)
		if b != nil {
			t.Fatalf("BuildSuccessor built %+v", b)
		}
		mustChainRefusal(t, err, RoleUser, 2, "the generation is not above every earlier generation of the role")
		// Equal to a held one: Validate's ordering rule refuses it first.
		b, err = r.buildCA([]CAEntry{caAt(t, RoleUser, seedCANext, "next", 3)}, nil)
		if b != nil || !errors.Is(err, ErrCARole) || !strings.Contains(err.Error(), "entries must be ordered") {
			t.Fatalf("BuildSuccessor = %+v, %v; want ErrCARole, entries must be ordered", b, err)
		}
	})
}

// buildSwitch builds r's successor under the previous roots and policy
// that switches roles with allowance, adding next as next entries
// (03-12e).
func (r *rotation) buildSwitch(roles []string, allowance time.Duration, next []CAEntry) (*Bundle, error) {
	return BuildSuccessor(r.prev, r.prevBytes, r.policy, SuccessorOptions{
		Roots: r.prev.Root.Keys, Threshold: 1, Policy: r.policy, IssuedAt: rotationIssued,
		CANext: next, CASwitch: roles, DrainAllowance: allowance,
	})
}

// TestBuildSuccessorSwitch (03-12e): BuildSuccessor's CASwitch makes a
// role's next entry active and its active entry draining until the switch
// floor (issued_at plus the larger max_ttl_seconds plus 300 s) plus the
// allowance, which must be a whole number of seconds from 0 to
// MaxDrainAllowance; its output verifies as a successor.
func TestBuildSuccessorSwitch(t *testing.T) {
	u1, n2 := goldenCA(t, RoleUser), caAt(t, RoleUser, seedCANext, "next", 2)
	issued, err := time.Parse(TimeFormat, rotationIssued)
	if err != nil {
		t.Fatal(err)
	}
	// floor is the switch floor of role under the golden policy, both
	// policies being the same.
	floor := func(t *testing.T, role string) time.Time {
		t.Helper()
		ttl, ok := RoleMaxTTL(goldenPolicy(t), role)
		if !ok {
			t.Fatalf("the golden policy has no %s profile", role)
		}
		return issued.Add(time.Duration(ttl+300) * time.Second) //nolint:gosec // G115: a policy TTL
	}
	// switched requires role's generation 1 draining until end and its
	// generation 2 active, with key, algorithm and custody unchanged.
	switched := func(t *testing.T, b *Bundle, role string, end time.Time, prev []CAEntry) {
		t.Helper()
		for _, old := range prev {
			if old.Role != role {
				continue
			}
			want := old
			switch old.State {
			case "active":
				want.State, want.TrustedUntil = "draining", end.UTC().Format(TimeFormat)
			case "next":
				want.State = "active"
			}
			i := slices.IndexFunc(b.CAs, func(c CAEntry) bool { return c.Role == role && c.Generation == old.Generation })
			if i < 0 || b.CAs[i] != want {
				t.Fatalf("CA %s generation %d after the switch: %+v, want %+v", role, old.Generation, b.CAs, want)
			}
		}
	}
	t.Run("allowance_is_added", func(t *testing.T) {
		r := caRotation(t, u1, n2)
		b, err := r.buildSwitch([]string{RoleUser}, 90*time.Second, nil)
		if err != nil {
			t.Fatalf("BuildSuccessor: %v", err)
		}
		switched(t, b, RoleUser, floor(t, RoleUser).Add(90*time.Second), r.prev.CAs)
	})
	t.Run("no_next_entry_refused", func(t *testing.T) {
		r := caRotation(t, u1)
		b, err := r.buildSwitch([]string{RoleUser}, 0, nil)
		if b != nil || !errors.Is(err, ErrVersionChain) || !strings.Contains(err.Error(), "CA user: no next entry to switch to") {
			t.Fatalf("BuildSuccessor = %+v, %v; want ErrVersionChain, no next entry to switch to", b, err)
		}
	})
	for _, tc := range []struct {
		name      string
		allowance time.Duration
	}{
		{"allowance_above_cap_refused", MaxDrainAllowance + time.Second},
		{"negative_allowance_refused", -time.Second},
		{"sub_second_allowance_refused", 1500 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := caRotation(t, u1, n2)
			b, err := r.buildSwitch([]string{RoleUser}, tc.allowance, nil)
			if b != nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), MaxDrainAllowance.String()) {
				t.Fatalf("BuildSuccessor with allowance %s = %+v, %v; want ErrInvalid naming the cap %s", tc.allowance, b, err, MaxDrainAllowance)
			}
		})
	}
	t.Run("two_roles_in_one_successor", func(t *testing.T) {
		r := caRotation(t, u1, n2)
		r.prev.CAs = slices.Insert(r.prev.CAs, 3, caAt(t, RoleHost, seedCAOther, "next", 2))
		if err := r.prev.Validate(); err != nil {
			t.Fatal(err)
		}
		r.prevBytes = mustCanonical(t, r.prev)
		b, err := r.buildSwitch([]string{RoleUser, RoleHost}, 0, nil)
		if err != nil {
			t.Fatalf("BuildSuccessor: %v", err)
		}
		switched(t, b, RoleUser, floor(t, RoleUser), r.prev.CAs)
		switched(t, b, RoleHost, floor(t, RoleHost), r.prev.CAs)
	})
	t.Run("switch_and_next_in_one_role_refused", func(t *testing.T) {
		r := caRotation(t, u1, n2)
		b, err := r.buildSwitch([]string{RoleUser}, 0, []CAEntry{caAt(t, RoleUser, seedCANext2, "next", 3)})
		if b != nil || (!errors.Is(err, ErrInvalid) && !errors.Is(err, ErrVersionChain)) {
			t.Fatalf("BuildSuccessor = %+v, %v; want a refusal", b, err)
		}
	})
	t.Run("output_verifies_as_a_successor", func(t *testing.T) {
		r := caRotation(t, u1, n2)
		b, err := r.buildSwitch([]string{RoleUser}, 0, nil)
		if err != nil {
			t.Fatalf("BuildSuccessor: %v", err)
		}
		switched(t, b, RoleUser, floor(t, RoleUser), r.prev.CAs)
		if err := r.verify(t, r.prevBytes, r.policy, mustCanonical(t, b), r.policy, r.a); err != nil {
			t.Fatalf("VerifySuccessor of the switch at its floor: %v", err)
		}
	})
}
