package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
)

// Seeds of keys that are not golden roots.
const (
	seedAttacker = 99
	seedRootC    = 50
)

func fp(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }

// goldenPins are the fingerprints of the golden roots A and B.
func goldenPins(t testing.TB) []string {
	t.Helper()
	return []string{fp(edKey(t, seedRootA)), fp(p256Key(t, seedRootB))}
}

// signAll returns the concatenated SSHSIG signatures of signers over doc.
func signAll(t testing.TB, namespace string, doc []byte, signers ...ssh.Signer) []byte {
	t.Helper()
	var out []byte
	for _, s := range signers {
		sig, err := sshsig.Sign(rand.Reader, s, namespace, doc)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, sig...)
	}
	return out
}

// genesisInput is one VerifyGenesisBundle call.
type genesisInput struct {
	bundle, bundleSigs, policy, policySigs []byte
	pins                                   []string
	threshold                              int
}

func TestVerifyGenesisBundle(t *testing.T) {
	rootA, rootB, attacker := edKey(t, seedRootA), p256Key(t, seedRootB), edKey(t, seedAttacker)
	policy := mustCanonical(t, goldenPolicy(t))
	oneOfTwo := mustCanonical(t, goldenBundle(t, policy))
	twoOfTwoB := goldenBundle(t, policy)
	twoOfTwoB.Root.Threshold = 2
	twoOfTwo := mustCanonical(t, twoOfTwoB)
	pins := goldenPins(t)
	polSigs := func(signers ...ssh.Signer) []byte { return signAll(t, NamespacePolicy, policy, signers...) }

	otherPolicy := goldenPolicy(t)
	otherPolicy.CAProfiles[0].MaxTTLSeconds = 3600
	wrongHash := goldenBundle(t, mustCanonical(t, otherPolicy))
	wrongHashDoc := mustCanonical(t, wrongHash)

	selfListed := goldenBundle(t, policy)
	selfListed.Root = RootSet{Keys: []RootKey{{Key: keyOf(attacker), Custody: "software"}}, Threshold: 1}
	selfListedDoc := mustCanonical(t, selfListed)

	version2 := goldenBundle(t, policy)
	version2.Version, version2.Prev = 2, SHA256Hex(oneOfTwo)
	version2Doc := mustCanonical(t, version2)

	// B-CR-01: root B (which does not even sign) listed as an admin.
	rootAdmin := goldenPolicy(t)
	rootAdmin.Admins = append(rootAdmin.Admins, AdminKey{Name: "root-b", Key: keyOf(rootB)})
	rootAdminPolicy := mustCanonical(t, rootAdmin)
	rootAdminDoc := mustCanonical(t, goldenBundle(t, rootAdminPolicy))

	tests := []struct {
		name string
		in   genesisInput
		want error // nil: accepted
	}{
		{"one_of_two_accepted", genesisInput{oneOfTwo, signAll(t, NamespaceBundle, oneOfTwo, rootA), policy, polSigs(rootA), pins, 1}, nil},
		{"two_of_two_accepted", genesisInput{twoOfTwo, signAll(t, NamespaceBundle, twoOfTwo, rootA, rootB), policy, polSigs(rootB, rootA), pins, 2}, nil},
		{"self_listed_root_refused", genesisInput{selfListedDoc, signAll(t, NamespaceBundle, selfListedDoc, attacker), policy, polSigs(attacker), pins, 1}, ErrPins},
		{"pins_differ_from_root_set_refused", genesisInput{oneOfTwo, signAll(t, NamespaceBundle, oneOfTwo, rootA), policy, polSigs(rootA), pins[:1], 1}, ErrPins},
		{"extra_pin_refused", genesisInput{oneOfTwo, signAll(t, NamespaceBundle, oneOfTwo, rootA), policy, polSigs(rootA), append(slices.Clone(pins), fp(attacker)), 1}, ErrPins},
		{"duplicate_pin_refused", genesisInput{oneOfTwo, signAll(t, NamespaceBundle, oneOfTwo, rootA), policy, polSigs(rootA), []string{pins[0], pins[0], pins[1]}, 1}, ErrPins},
		{"threshold_differs_from_bundle_refused", genesisInput{oneOfTwo, signAll(t, NamespaceBundle, oneOfTwo, rootA, rootB), policy, polSigs(rootA, rootB), pins, 2}, ErrPins},
		{"threshold_two_one_signature_refused", genesisInput{twoOfTwo, signAll(t, NamespaceBundle, twoOfTwo, rootA), policy, polSigs(rootA, rootB), pins, 2}, ErrThreshold},
		{"same_root_twice_counts_once", genesisInput{twoOfTwo, signAll(t, NamespaceBundle, twoOfTwo, rootB, rootB), policy, polSigs(rootA, rootB), pins, 2}, ErrThreshold},
		{"non_pinned_signer_does_not_count", genesisInput{twoOfTwo, signAll(t, NamespaceBundle, twoOfTwo, rootA, attacker), policy, polSigs(rootA, rootB), pins, 2}, ErrThreshold},
		{"wrong_namespace_does_not_count", genesisInput{twoOfTwo, append(signAll(t, NamespaceBundle, twoOfTwo, rootA), signAll(t, NamespacePolicy, twoOfTwo, rootB)...), policy, polSigs(rootA, rootB), pins, 2}, ErrThreshold},
		{"policy_signature_as_bundle_signature_does_not_count", genesisInput{twoOfTwo, append(signAll(t, NamespaceBundle, twoOfTwo, rootA), polSigs(rootB)...), policy, polSigs(rootA, rootB), pins, 2}, ErrThreshold},
		{"policy_signed_by_too_few_roots_refused", genesisInput{twoOfTwo, signAll(t, NamespaceBundle, twoOfTwo, rootA, rootB), policy, polSigs(rootA), pins, 2}, ErrThreshold},
		{"policy_signed_only_by_non_pinned_refused", genesisInput{oneOfTwo, signAll(t, NamespaceBundle, oneOfTwo, rootA), policy, polSigs(attacker), pins, 1}, ErrThreshold},
		{"policy_hash_mismatch_refused", genesisInput{wrongHashDoc, signAll(t, NamespaceBundle, wrongHashDoc, rootA), policy, polSigs(rootA), pins, 1}, ErrPolicyHash},
		{"version_2_is_not_genesis", genesisInput{version2Doc, signAll(t, NamespaceBundle, version2Doc, rootA), policy, polSigs(rootA), pins, 1}, ErrVersionChain},
		{"root_as_policy_admin_refused", genesisInput{rootAdminDoc, signAll(t, NamespaceBundle, rootAdminDoc, rootA), rootAdminPolicy,
			signAll(t, NamespacePolicy, rootAdminPolicy, rootA), pins, 1}, ErrKeyIsRoot},
		{"malformed_signature_file_refused", genesisInput{oneOfTwo, []byte("not a signature\n"), policy, polSigs(rootA), pins, 1}, sshsig.ErrMalformed},
		{"pin_not_a_fingerprint_refused", genesisInput{oneOfTwo, signAll(t, NamespaceBundle, oneOfTwo, rootA), policy, polSigs(rootA), []string{"MD5:00", pins[1]}, 1}, ErrPins},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			b, p, err := VerifyGenesisBundle(in.bundle, in.bundleSigs, in.policy, in.policySigs, in.pins, in.threshold)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if b == nil || p == nil || b.Version != 1 || p.Version != 1 {
					t.Fatalf("accepted but returned %v, %v", b, p)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if b != nil || p != nil {
				t.Fatal("refused but returned documents")
			}
		})
	}
}

func TestCountPinnedSigners(t *testing.T) {
	rootA, rootB, attacker := edKey(t, seedRootA), p256Key(t, seedRootB), edKey(t, seedAttacker)
	doc := []byte("doc\n")
	pinned := map[string]ssh.PublicKey{fp(rootA): rootA.PublicKey(), fp(rootB): rootB.PublicKey()}
	sigs := signAll(t, NamespaceBundle, doc, rootB, attacker, rootA, rootB, rootA)
	got, err := CountPinnedSigners(doc, sigs, NamespaceBundle, pinned)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{fp(rootA), fp(rootB)}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("signers = %v, want %v (each pinned root once, attacker ignored)", got, want)
	}
	if got, _ := CountPinnedSigners(doc, sigs, NamespacePolicy, pinned); len(got) != 0 {
		t.Fatalf("signatures counted under the wrong namespace: %v", got)
	}
	if got, _ := CountPinnedSigners([]byte("other\n"), sigs, NamespaceBundle, pinned); len(got) != 0 {
		t.Fatalf("signatures counted for another document: %v", got)
	}
	// A pin map whose key does not match its fingerprint is a caller bug.
	bad := map[string]ssh.PublicKey{fp(rootA): attacker.PublicKey()}
	if _, err := CountPinnedSigners(doc, sigs, NamespaceBundle, bad); err == nil {
		t.Fatal("inconsistent pin map accepted")
	}
}

// successorFixture is a previous bundle (roots: rootA, threshold 1) and a
// policy, from which successor bundles are derived.
type successorFixture struct {
	prev         *Bundle
	prevBytes    []byte
	policy       []byte
	rootA, rootC ssh.Signer
}

func newSuccessorFixture(t *testing.T) *successorFixture {
	t.Helper()
	f := &successorFixture{rootA: edKey(t, seedRootA), rootC: edKey(t, seedRootC)}
	f.policy = mustCanonical(t, goldenPolicy(t))
	f.prev = goldenBundle(t, f.policy)
	f.prev.Root = RootSet{Keys: []RootKey{{Key: keyOf(f.rootA), Custody: "software"}}, Threshold: 1}
	f.prevBytes = mustCanonical(t, f.prev)
	return f
}

// next returns version prev+1 with prev's hash, issued a day later, whose
// root set is roots.
func (f *successorFixture) next(t *testing.T, roots ...ssh.Signer) *Bundle {
	t.Helper()
	b := goldenBundle(t, f.policy)
	b.Version = f.prev.Version + 1
	b.Prev = SHA256Hex(f.prevBytes)
	b.IssuedAt = "2026-10-06T00:00:00Z"
	b.Root = RootSet{Threshold: 1}
	for _, r := range roots {
		b.Root.Keys = append(b.Root.Keys, RootKey{Key: keyOf(r), Custody: "software"})
	}
	return b
}

func TestVerifySuccessor(t *testing.T) {
	f := newSuccessorFixture(t)
	rotated := mustCanonical(t, f.next(t, f.rootC))
	unchanged := mustCanonical(t, f.next(t, f.rootA))
	jump := f.next(t, f.rootC)
	jump.Version = 3
	jumpDoc := mustCanonical(t, jump)
	wrongPrev := f.next(t, f.rootC)
	wrongPrev.Prev = SHA256Hex([]byte("another bundle"))
	wrongPrevDoc := mustCanonical(t, wrongPrev)
	earlier := f.next(t, f.rootC)
	earlier.IssuedAt = "2026-10-04T00:00:00Z"
	earlierDoc := mustCanonical(t, earlier)
	pol := func(signers ...ssh.Signer) []byte { return signAll(t, NamespacePolicy, f.policy, signers...) }

	tests := []struct {
		name             string
		next, nextSigs   []byte
		policySigs       []byte
		want             error
		prevCanonicalAlt []byte
	}{
		{name: "old_and_new_roots_accepted", next: rotated, nextSigs: signAll(t, NamespaceBundle, rotated, f.rootA, f.rootC), policySigs: pol(f.rootC, f.rootA)},
		{name: "unchanged_roots_accepted", next: unchanged, nextSigs: signAll(t, NamespaceBundle, unchanged, f.rootA), policySigs: pol(f.rootA)},
		{name: "version_jump_refused", next: jumpDoc, nextSigs: signAll(t, NamespaceBundle, jumpDoc, f.rootA, f.rootC), policySigs: pol(f.rootA, f.rootC), want: ErrVersionChain},
		{name: "prev_hash_mismatch_refused", next: wrongPrevDoc, nextSigs: signAll(t, NamespaceBundle, wrongPrevDoc, f.rootA, f.rootC), policySigs: pol(f.rootA, f.rootC), want: ErrVersionChain},
		{name: "issued_before_prev_refused", next: earlierDoc, nextSigs: signAll(t, NamespaceBundle, earlierDoc, f.rootA, f.rootC), policySigs: pol(f.rootA, f.rootC), want: ErrVersionChain},
		{name: "signed_only_by_new_roots_refused", next: rotated, nextSigs: signAll(t, NamespaceBundle, rotated, f.rootC), policySigs: pol(f.rootA, f.rootC), want: ErrThreshold},
		{name: "signed_only_by_old_roots_after_root_change_refused", next: rotated, nextSigs: signAll(t, NamespaceBundle, rotated, f.rootA), policySigs: pol(f.rootA, f.rootC), want: ErrThreshold},
		{name: "policy_signed_only_by_new_roots_refused", next: rotated, nextSigs: signAll(t, NamespaceBundle, rotated, f.rootA, f.rootC), policySigs: pol(f.rootC), want: ErrThreshold},
		{name: "policy_signed_only_by_old_roots_refused", next: rotated, nextSigs: signAll(t, NamespaceBundle, rotated, f.rootA, f.rootC), policySigs: pol(f.rootA), want: ErrThreshold},
		{name: "prev_canonical_differs_from_prev_refused", next: rotated, nextSigs: signAll(t, NamespaceBundle, rotated, f.rootA, f.rootC), policySigs: pol(f.rootA, f.rootC),
			want: ErrVersionChain, prevCanonicalAlt: append(bytes.Clone(f.prevBytes[:len(f.prevBytes)-1]), ' ', '\n')},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prevBytes := f.prevBytes
			if tc.prevCanonicalAlt != nil {
				prevBytes = tc.prevCanonicalAlt
			}
			b, p, err := VerifySuccessor(f.prev, prevBytes, f.policy, tc.next, tc.nextSigs, f.policy, tc.policySigs)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if b == nil || p == nil || b.Version != f.prev.Version+1 {
					t.Fatalf("accepted but returned %v, %v", b, p)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifySuccessorPolicyChain (A-WR-02, B-WR-01, C-WR-05): a successor's
// policy is either byte-identical to the policy in force or the next
// version chained to it by its SHA-256, so pol=N names exactly one policy.
func TestVerifySuccessorPolicyChain(t *testing.T) {
	f := newSuccessorFixture(t)
	changed := func(edit func(p *Policy)) []byte {
		p := goldenPolicy(t)
		p.CAProfiles[0].MaxTTLSeconds = 3600
		p.Version, p.Prev = 2, SHA256Hex(f.policy)
		edit(p)
		return mustCanonical(t, p)
	}
	tests := []struct {
		name       string
		policy     []byte
		prevPolicy []byte // nil means f.policy
		want       error
	}{
		{name: "unchanged_policy_accepted", policy: f.policy},
		{name: "next_version_chained_accepted", policy: changed(func(*Policy) {})},
		{name: "same_version_different_policy_refused", policy: changed(func(p *Policy) { p.Version, p.Prev = 1, GenesisPrev }), want: ErrVersionChain},
		{name: "version_jump_refused", policy: changed(func(p *Policy) { p.Version = 3 }), want: ErrVersionChain},
		{name: "wrong_prev_refused", policy: changed(func(p *Policy) { p.Prev = SHA256Hex([]byte("another policy")) }), want: ErrVersionChain},
		{name: "prev_policy_not_the_bundles_refused", policy: changed(func(*Policy) {}), prevPolicy: changed(func(p *Policy) { p.Version = 5 }), want: ErrVersionChain},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := goldenBundle(t, tc.policy)
			next.Version, next.Prev, next.IssuedAt = f.prev.Version+1, SHA256Hex(f.prevBytes), "2026-10-06T00:00:00Z"
			next.Root = f.prev.Root
			doc := mustCanonical(t, next)
			prevPolicy := f.policy
			if tc.prevPolicy != nil {
				prevPolicy = tc.prevPolicy
			}
			b, p, err := VerifySuccessor(f.prev, f.prevBytes, prevPolicy, doc, signAll(t, NamespaceBundle, doc, f.rootA),
				tc.policy, signAll(t, NamespacePolicy, tc.policy, f.rootA))
			if tc.want == nil {
				if err != nil || b == nil || p == nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestVerifySuccessorAdminNotRoot (B-CR-01, KEY-07): a successor's policy
// may not list a root as an admin: neither one of the successor's roots,
// nor a root it retires, nor an existing admin the successor makes a root.
func TestVerifySuccessorAdminNotRoot(t *testing.T) {
	f := newSuccessorFixture(t)
	admin := edKey(t, seedAdmin) // the golden policy's admin alice
	_, fresh, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	freshAdmin, err := ssh.NewSignerFromKey(fresh)
	if err != nil {
		t.Fatal(err)
	}
	// policyV2 is the next policy version, chained to f.policy, with one
	// more admin.
	policyV2 := func(extra ssh.Signer) []byte {
		p := goldenPolicy(t)
		p.Version, p.Prev = 2, SHA256Hex(f.policy)
		p.Admins = append(p.Admins, AdminKey{Name: "bob", Key: keyOf(extra)})
		return mustCanonical(t, p)
	}
	tests := []struct {
		name   string
		roots  []ssh.Signer
		policy []byte
		want   error
	}{
		{name: "fresh_admin_accepted", roots: []ssh.Signer{f.rootC}, policy: policyV2(freshAdmin)},
		{name: "admin_is_new_root_refused", roots: []ssh.Signer{f.rootC}, policy: policyV2(f.rootC), want: ErrKeyIsRoot},
		{name: "admin_is_retired_root_refused", roots: []ssh.Signer{f.rootC}, policy: policyV2(f.rootA), want: ErrKeyIsRoot},
		{name: "unchanged_policy_admin_made_root_refused", roots: []ssh.Signer{f.rootA, admin}, policy: f.policy, want: ErrKeyIsRoot},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := f.next(t, tc.roots...)
			next.PolicySHA256 = SHA256Hex(tc.policy)
			doc := mustCanonical(t, next)
			signers := append([]ssh.Signer{f.rootA}, tc.roots...)
			b, p, err := VerifySuccessor(f.prev, f.prevBytes, f.policy, doc, signAll(t, NamespaceBundle, doc, signers...),
				tc.policy, signAll(t, NamespacePolicy, tc.policy, signers...))
			if tc.want == nil {
				if err != nil || b == nil || p == nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if b != nil || p != nil {
				t.Fatal("refused but returned documents")
			}
		})
	}
}

// TestMatchPins: the anchor rule shared by VerifyGenesisBundle, trust
// verify --prev and audit verify. A bundle matches only its exact root set
// at its exact threshold; every other pin set is refused with the sentinel
// VerifyGenesisBundle returns for it.
func TestMatchPins(t *testing.T) {
	policy := mustCanonical(t, goldenPolicy(t))
	b := goldenBundle(t, policy) // roots A and B, threshold 1
	pins := goldenPins(t)
	attacker := edKey(t, seedAttacker)
	tests := []struct {
		name      string
		pins      []string
		threshold int
		want      error // nil: matches
		// badPins: the pin list or threshold is wrong on its own, so
		// CheckPins refuses it without a bundle.
		badPins bool
	}{
		{"exact_set_at_its_threshold", pins, 1, nil, false},
		{"exact_set_reordered", []string{pins[1], pins[0]}, 1, nil, false},
		{"missing_pin", pins[:1], 1, ErrPins, false},
		{"extra_pin", append(slices.Clone(pins), fp(attacker)), 1, ErrPins, false},
		{"other_root_in_place_of_one", []string{pins[0], fp(attacker)}, 1, ErrPins, false},
		{"threshold_differs_from_bundle", pins, 2, ErrPins, false},
		{"threshold_zero", pins, 0, ErrThreshold, true},
		{"threshold_above_pins", pins, 3, ErrThreshold, true},
		{"pin_repeated", []string{pins[0], pins[0], pins[1]}, 1, ErrPins, true},
		{"malformed_pin", []string{"MD5:00", pins[1]}, 1, ErrPins, true},
		{"no_pins", nil, 1, ErrPins, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := MatchPins(b, tc.pins, tc.threshold)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("MatchPins refused the bundle's own root set: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if pinErr := CheckPins(tc.pins, tc.threshold); (pinErr != nil) != tc.badPins {
				t.Fatalf("CheckPins = %v, want an error only for a malformed pin list or threshold", pinErr)
			}
		})
	}
}
