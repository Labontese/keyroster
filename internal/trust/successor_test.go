package trust

import (
	"bytes"
	"errors"
	"strings"
	"testing"

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
		next, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, rootKeysOf(r.c, r.d), 1, r.policy, rotationIssued)
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
		next, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, rootKeysOf(r.c, r.d), 1, policy, rotationIssued)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.verify(t, r.prevBytes, r.policy, mustCanonical(t, next), policy, r.a, r.c); err != nil {
			t.Fatalf("chained v2 policy signed by A and C: %v", err)
		}
	})

	t.Run("carries_online_keys", func(t *testing.T) {
		r := newRotation(t) // its own fixture: the alias check edits it
		next, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, rootKeysOf(r.c, r.d), 1, r.policy, rotationIssued)
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
			b, err := BuildSuccessor(r.prev, prevCanonical, prevPolicy, roots, 1, policy, issuedAt)
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
			b, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, rootKeysOf(r.c, r.d), tc.threshold, r.policy, rotationIssued)
			if !errors.Is(err, ErrInvalid) || b != nil {
				t.Fatalf("bundle %v, err = %v, want %v", b, err, ErrInvalid)
			}
		})
	}
}
