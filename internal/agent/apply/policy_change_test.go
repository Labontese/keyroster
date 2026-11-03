//go:build linux

package apply

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// rotationNext is fixture.rotation with a next user CA key next added to
// the successor bundle, so that the CA keys a host renders show which
// bundle is in force (F03 (03-08f)).
func (f *fixture) rotationNext(prev *trust.Bundle, prevDoc, prevPolicyDoc []byte, prevPolicy *trust.Policy, admins []trust.AdminKey, issuedAt string, next ssh.Signer) (*trust.Bundle, spool.Doc, spool.Doc) {
	f.t.Helper()
	p := *prevPolicy
	p.Version, p.Prev, p.Admins = prevPolicy.Version+1, trust.SHA256Hex(prevPolicyDoc), admins
	polDoc := mustCanonical(f.t, &p)
	b, err := trust.BuildSuccessor(prev, prevDoc, prevPolicyDoc, prev.Root.Keys, 1, polDoc, issuedAt, testInstallation)
	if err != nil {
		f.t.Fatal(err)
	}
	b.CAs = slices.Insert(b.CAs, 1, trust.CAEntry{Role: trust.RoleUser, Key: trust.FormatKey(next.PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "next", Generation: 2})
	doc := mustCanonical(f.t, b)
	if _, err := trust.ParseBundle(doc); err != nil {
		f.t.Fatalf("rotation bundle with a next CA: %v", err)
	}
	return b, spool.Doc{Body: doc, Sigs: f.rootSign(trust.NamespaceBundle, doc)}, spool.Doc{Body: polDoc, Sigs: f.rootSign(trust.NamespacePolicy, polDoc)}
}

// adminRemovedHost is a host whose stored directory the policy in force
// no longer authorizes (F03 (03-08f)), as adminRemoved leaves it.
type adminRemovedHost struct {
	*testHost
	bob    ssh.Signer // policy 2's only admin (seedKey 11)
	next   ssh.Signer // bundle 2's next user CA (seedKey 31)
	b2     *trust.Bundle
	serial uint64  // the serial the KRL offered with bundle 2 revokes
	r      *Report // the third apply's report
	err    error   // and its error
}

// adminRemoved builds the lagging host of F03 (03-08f), with its spool in
// <state>/spool so accepted.json lands in the production outbox:
//
//  1. bundle 1, policy 1 (admin alice, the fixture's admin, quorum 1) and
//     directory 1 with role:ops installed;
//  2. alice's directory 2, which grants role:evil to deploy, applied;
//  3. bundle 2 offered, whose policy 2 names bob alone and which adds a
//     next user CA, with a newer KRL revoking serial 4242, and applied.
//
// It returns the host after step 3 with that apply's report and error. On
// the code of 03-08f, accepted/ then holds bundle 2 over alice's directory
// 2, which policy 2 does not authorize. h.dirs holds directories 1 and 2.
func adminRemoved(t *testing.T) *adminRemovedHost {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	spoolInState(t, h)
	h.installed("role:ops")
	h.publishDir(h.spec("role:evil"))
	if r := h.mustApply(); r.DirectoryVersion != 2 || !slices.Equal(h.principals("deploy"), []string{"role:evil"}) {
		t.Fatalf("alice's directory 2: %+v, principals %v", r, h.principals("deploy"))
	}
	a := &adminRemovedHost{testHost: h, bob: seedKey(t, 11), next: seedKey(t, 31), serial: 4242}
	var d2, p2 spool.Doc
	a.b2, d2, p2 = f.rotationNext(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(a.bob.PublicKey())}}, "2026-10-02T00:00:00Z", a.next)
	h.state.Bundles[2], h.state.Policies[2] = d2, p2
	h.publishKRL(a.serial)
	a.r, a.err = h.apply()
	return a
}

// TestDirectoryUnderPolicyInForce is F03 (03-08f): a host checks its
// stored directory again under the root-signed policy in force on every
// verification, renders no principals from one that policy's admin quorum
// did not sign, reports directory_not_authorized, asks the server for its
// current directory, and takes the new admins' directory at the same
// version standalone.
func TestDirectoryUnderPolicyInForce(t *testing.T) {
	t.Run("lagging_host_admin_removed_principals_dropped", func(t *testing.T) {
		t.Parallel()
		a := adminRemoved(t)
		h := a.testHost
		if !errors.Is(a.err, state.ErrDirUnauthorized) {
			t.Errorf("apply 3: %v, want directory_not_authorized", a.err)
		}
		if p := filepath.Join(h.l.Current(), PrincipalsDir, "deploy"); h.exists(p) {
			t.Errorf("current still holds a principals file: %v", h.principals("deploy"))
		}
		if ca := h.file(CAFile); !strings.Contains(ca, trust.FormatKey(a.next.PublicKey())) {
			t.Errorf("current's user_ca_keys is not bundle 2's: %q", ca)
		}
		if !h.krlRevokes(h.l.Current(), a.serial) {
			t.Errorf("current does not revoke serial %d", a.serial)
		}
		if a.r.BundleVersion != 2 || !a.r.DirectoryUnauthorized {
			t.Errorf("report: bundle %d, directory_unauthorized %t; want 2, true", a.r.BundleVersion, a.r.DirectoryUnauthorized)
		}
		if got := readAccepted(t, h); got.Directory != 0 {
			t.Errorf("accepted.json names directory %d, want 0", got.Directory)
		}
		if s, err := h.accepted(); err != nil || s.DirectoryVersion != 2 || s.BundleVersion != 2 {
			t.Errorf("accepted/: %+v (%v), want bundle 2 over directory 2", s, err)
		}
		if t.Failed() {
			t.FailNow()
		}
		// The idle run every 60 s: nothing new, the same refusal, nothing
		// changed, and accepted.json still asks from 0.
		cur := h.current()
		r, err := h.apply()
		if !errors.Is(err, state.ErrDirUnauthorized) || !r.NoOp || !r.DirectoryUnauthorized || h.current() != cur {
			t.Fatalf("the idle run: %v, %+v, current %d (was %d); want directory_not_authorized, a no-op", err, r, h.current(), cur)
		}
		if got := readAccepted(t, h); got.Directory != 0 {
			t.Fatalf("after the idle run accepted.json names directory %d, want 0", got.Directory)
		}
		// Bob's directory 2: other bytes at the same version, chained to
		// version 1, taken standalone.
		s := h.spec("role:bob")
		s.signer = a.bob
		bob2 := h.f.directory(h.dirs[0].Body, s)
		h.dirs[1], h.state.Directories[2] = bob2, bob2
		r, err = h.apply()
		if err != nil || r.DirectoryUnauthorized {
			t.Fatalf("bob's directory 2: %v, %+v", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:bob"}) {
			t.Fatalf("principals of deploy %v, want bob's [role:bob]", got)
		}
		if got := readAccepted(t, h); got.Directory != 2 {
			t.Fatalf("accepted.json names directory %d, want 2", got.Directory)
		}
	})
}

// rootSigs is the concatenated SSHSIG blocks of signers over doc under
// namespace, a .sigs file as signers append to it (F02 (03-08f)).
func rootSigs(t testing.TB, namespace string, doc []byte, signers ...ssh.Signer) []byte {
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

// rootSuccessor builds bundle prev.Version+1 over the root set roots at
// threshold with the fixture's policy unchanged (trust.BuildSuccessor),
// and its bundle signatures by signers (F02 (03-08f)).
func (f *fixture) rootSuccessor(prev *trust.Bundle, prevDoc []byte, roots []ssh.Signer, threshold uint32, issuedAt string, signers ...ssh.Signer) (*trust.Bundle, spool.Doc) {
	f.t.Helper()
	var rk []trust.RootKey
	for _, r := range roots {
		rk = append(rk, trust.RootKey{Key: trust.FormatKey(r.PublicKey()), Custody: "software"})
	}
	b, err := trust.BuildSuccessor(prev, prevDoc, f.policyDoc, rk, threshold, f.policyDoc, issuedAt, testInstallation)
	if err != nil {
		f.t.Fatal(err)
	}
	doc := mustCanonical(f.t, b)
	return b, spool.Doc{Body: doc, Sigs: rootSigs(f.t, trust.NamespaceBundle, doc, signers...)}
}

// rootHop is one successor of TestRootRotationUnchangedPolicy: its root
// set and threshold, who signs the bundle, and who signs the policy
// signatures delivered with it (bundle-<N>.policy.sigs; nil writes none).
type rootHop struct {
	roots     []ssh.Signer
	threshold uint32
	bundleBy  []ssh.Signer
	policyBy  []ssh.Signer
}

// offerHops offers the successors hops above the newest bundle h's state
// offers (from, its document prevDoc), each with its delivered policy
// signatures, as fetch.writeState spools them, and returns the newest.
func offerHops(t *testing.T, h *testHost, from *trust.Bundle, prevDoc []byte, hops ...rootHop) (*trust.Bundle, []byte) {
	t.Helper()
	if h.state.BundlePolicySigs == nil {
		h.state.BundlePolicySigs = map[uint64][]byte{}
	}
	b, doc := from, prevDoc
	for i, hop := range hops {
		nb, d := h.f.rootSuccessor(b, doc, hop.roots, hop.threshold, fmt.Sprintf("2026-10-%02dT00:00:00Z", 2+i), hop.bundleBy...)
		h.state.Bundles[nb.Version] = d
		if hop.policyBy != nil {
			h.state.BundlePolicySigs[nb.Version] = rootSigs(t, trust.NamespacePolicy, h.f.policyDoc, hop.policyBy...)
		}
		b, doc = nb, d.Body
	}
	return b, doc
}

// rootKeys are the new roots of TestRootRotationUnchangedPolicy: C, D and
// E (seedKey 21, 22 and 23), B (seedKey 24) and a key that is no root (X,
// seedKey 25).
func rootKeys(t *testing.T) (c, d, e, b, x ssh.Signer) {
	return seedKey(t, 21), seedKey(t, 22), seedKey(t, 23), seedKey(t, 24), seedKey(t, 25)
}

// rotatedHost is an installed host offered bundle 2 over the new root set
// {C} at threshold 1, the policy unchanged, both documents signed by A
// (the fixture's root) and C, with the policy signatures delivered with
// bundle 2 and a newer KRL revoking serial 31 (F02 (03-08f)).
func rotatedHost(t *testing.T) (*testHost, *trust.Bundle, []byte) {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	h.installed("role:ops")
	c, _, _, _, _ := rootKeys(t)
	b2, d2 := offerHops(t, h, f.bundle, f.bundleDoc, rootHop{roots: []ssh.Signer{c}, threshold: 1, bundleBy: []ssh.Signer{f.root, c}, policyBy: []ssh.Signer{f.root, c}})
	h.publishKRL(31)
	return h, b2, d2
}

// threeHops is an installed host offered {A}→{C}→{D}→{E} in one capture,
// each step signed by its previous and its new root, each bundle with its
// own delivered policy signatures (F02 (03-08f)).
func threeHops(t *testing.T) *testHost {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	h.installed("role:ops")
	c, d, e, _, _ := rootKeys(t)
	offerHops(t, h, f.bundle, f.bundleDoc,
		rootHop{roots: []ssh.Signer{c}, threshold: 1, bundleBy: []ssh.Signer{f.root, c}, policyBy: []ssh.Signer{f.root, c}},
		rootHop{roots: []ssh.Signer{d}, threshold: 1, bundleBy: []ssh.Signer{c, d}, policyBy: []ssh.Signer{c, d}},
		rootHop{roots: []ssh.Signer{e}, threshold: 1, bundleBy: []ssh.Signer{d, e}, policyBy: []ssh.Signer{d, e}})
	return h
}

// mustAcceptedBundle requires accepted/ to hold bundle version want.
func mustAcceptedBundle(t *testing.T, h *testHost, want uint64) *state.Stored {
	t.Helper()
	s, err := h.accepted()
	if err != nil || s == nil || s.BundleVersion != want {
		t.Fatalf("accepted/ %+v (%v), want bundle %d", s, err, want)
	}
	return s
}

// TestRootRotationUnchangedPolicy is F02 (03-08f): a root rotation or a
// raised threshold that carries the policy over unchanged verifies with
// the policy signatures delivered with each bundle, in one hop or several,
// so the retired roots stop anchoring the host; the union of signature
// files never lowers a threshold, and accepted/ stores one admitted file.
func TestRootRotationUnchangedPolicy(t *testing.T) {
	t.Run("one_hop_new_roots", func(t *testing.T) {
		t.Parallel()
		h, _, _ := rotatedHost(t)
		r, err := h.apply()
		if err != nil || r.BundleVersion != 2 {
			t.Fatalf("the rotation to {C}: %v, %+v; want bundle 2", err, r)
		}
		mustAcceptedBundle(t, h, 2)
		if !h.krlRevokes(h.l.Current(), 31) {
			t.Fatalf("the KRL offered with the rotation is not in force")
		}
	})
	t.Run("one_hop_with_directory_in_same_capture", func(t *testing.T) {
		t.Parallel()
		h, _, _ := rotatedHost(t)
		h.publishDir(h.spec("role:ops", "role:two"))
		r, err := h.apply()
		if err != nil || r.BundleVersion != 2 || r.DirectoryVersion != 2 {
			t.Fatalf("the rotation with directory 2: %v, %+v; want bundle 2, directory 2", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops", "role:two"}) {
			t.Fatalf("principals %v, want directory 2's", got)
		}
	})
	t.Run("three_hops_in_one_capture", func(t *testing.T) {
		t.Parallel()
		h := threeHops(t)
		r, err := h.apply()
		if err != nil || r.BundleVersion != 4 {
			t.Fatalf("three hops: %v, %+v; want bundle 4", err, r)
		}
		mustAcceptedBundle(t, h, 4)
	})
	t.Run("spool_without_per_bundle_sigs_one_hop", func(t *testing.T) {
		t.Parallel()
		// A fetcher from before 03-08f spools no bundle-2.policy.sigs; its
		// policy-1.json.sigs holds the last bundle item's, A and C.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		c, _, _, _, _ := rootKeys(t)
		offerHops(t, h, f.bundle, f.bundleDoc, rootHop{roots: []ssh.Signer{c}, threshold: 1, bundleBy: []ssh.Signer{f.root, c}})
		h.state.Policies[1] = spool.Doc{Body: f.policyDoc, Sigs: rootSigs(t, trust.NamespacePolicy, f.policyDoc, f.root, c)}
		if r, err := h.apply(); err != nil || r.BundleVersion != 2 {
			t.Fatalf("the rotation through policy-1.json.sigs: %v, %+v; want bundle 2", err, r)
		}
		mustAcceptedBundle(t, h, 2)
	})
	t.Run("union_never_lowers_threshold", func(t *testing.T) {
		t.Parallel()
		// {C, D} at threshold 2: C's block twice, a block by X, which is no
		// root, and the stored A count C once, below 2.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		c, d, _, _, x := rootKeys(t)
		offerHops(t, h, f.bundle, f.bundleDoc, rootHop{roots: []ssh.Signer{c, d}, threshold: 2, bundleBy: []ssh.Signer{f.root, c, d}})
		h.state.BundlePolicySigs[2] = rootSigs(t, trust.NamespacePolicy, f.policyDoc, c, c, x, f.root)
		_, err := h.apply()
		if !errors.Is(err, state.ErrBundle) || !strings.Contains(err.Error(), "policy (new roots) signed by 1 of 2 roots, need 2") {
			t.Fatalf("apply: %v, want bundle_not_verified with policy (new roots) signed by 1 of 2 roots, need 2", err)
		}
		mustAcceptedBundle(t, h, 1)
	})
	t.Run("malformed_delivered_sigs_change_nothing", func(t *testing.T) {
		t.Parallel()
		malformed := []byte("not an SSHSIG block\n")
		// The same roots: the stored signatures pass, as today.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		offerHops(t, h, f.bundle, f.bundleDoc, rootHop{roots: []ssh.Signer{f.root}, threshold: 1, bundleBy: []ssh.Signer{f.root}})
		h.state.BundlePolicySigs[2] = malformed
		if r, err := h.apply(); err != nil || r.BundleVersion != 2 {
			t.Fatalf("same roots with a malformed delivered file: %v, %+v; want bundle 2", err, r)
		}
		if s := mustAcceptedBundle(t, h, 2); !bytes.Equal(s.PolicySigs, f.policySigs) {
			t.Fatalf("accepted/'s policy signatures are not the stored ones")
		}
		// A rotation to {C} whose offered policy file holds only A: the
		// malformed file adds nothing, and the rotation is refused.
		f2 := newFixture(t)
		h2 := newTestHost(t, f2)
		h2.installed("role:ops")
		c, _, _, _, _ := rootKeys(t)
		offerHops(t, h2, f2.bundle, f2.bundleDoc, rootHop{roots: []ssh.Signer{c}, threshold: 1, bundleBy: []ssh.Signer{f2.root, c}})
		h2.state.BundlePolicySigs[2] = malformed
		if _, err := h2.apply(); !errors.Is(err, state.ErrBundle) || !strings.Contains(err.Error(), "policy (new roots) signed by 0 of 1 roots, need 1") {
			t.Fatalf("the rotation with a malformed delivered file: %v, want bundle_not_verified, policy (new roots) signed by 0 of 1", err)
		}
		mustAcceptedBundle(t, h2, 1)
	})
	t.Run("malformed_delivered_sigs_not_stored", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		c, d, _, _, _ := rootKeys(t)
		b2, d2 := offerHops(t, h, f.bundle, f.bundleDoc, rootHop{roots: []ssh.Signer{c}, threshold: 1, bundleBy: []ssh.Signer{f.root, c}})
		h.state.BundlePolicySigs[2] = []byte("not an SSHSIG block\n")
		offered := rootSigs(t, trust.NamespacePolicy, f.policyDoc, f.root, c)
		h.state.Policies[1] = spool.Doc{Body: f.policyDoc, Sigs: offered}
		if r, err := h.apply(); err != nil || r.BundleVersion != 2 {
			t.Fatalf("the rotation through the offered policy file: %v, %+v; want bundle 2", err, r)
		}
		if s := mustAcceptedBundle(t, h, 2); !bytes.Equal(s.PolicySigs, offered) {
			t.Fatalf("accepted/'s policy signatures are not the offered file:\n%s", s.PolicySigs)
		}
		// The next hop's plain check starts from what was stored: a parse
		// error there would never reach the union.
		offerHops(t, h, b2, d2, rootHop{roots: []ssh.Signer{d}, threshold: 1, bundleBy: []ssh.Signer{c, d}, policyBy: []ssh.Signer{c, d}})
		if r, err := h.apply(); err != nil || r.BundleVersion != 3 {
			t.Fatalf("the next hop {C}→{D}: %v, %+v; want bundle 3", err, r)
		}
	})
	t.Run("retired_root_fork_refused_after_rotation", func(t *testing.T) {
		t.Parallel()
		h, b2, d2 := rotatedHost(t)
		if r, err := h.apply(); err != nil || r.BundleVersion != 2 {
			t.Fatalf("the rotation to {C}: %v, %+v; want bundle 2", err, r)
		}
		// 3' keeps A as its root and is signed by A alone, the retired root.
		offerHops(t, h, b2, d2, rootHop{roots: []ssh.Signer{h.f.root}, threshold: 1, bundleBy: []ssh.Signer{h.f.root}, policyBy: []ssh.Signer{h.f.root}})
		if _, err := h.apply(); !errors.Is(err, state.ErrBundle) || !strings.Contains(err.Error(), "bundle (previous roots) signed by 0 of 1") {
			t.Fatalf("the retired root's fork: %v, want bundle_not_verified, bundle (previous roots) signed by 0 of 1", err)
		}
		mustAcceptedBundle(t, h, 2)
		// The contrast: a host still on {A} accepts a fork 2' that A alone
		// signed.
		f2 := newFixture(t)
		h2 := newTestHost(t, f2)
		h2.installed("role:ops")
		offerHops(t, h2, f2.bundle, f2.bundleDoc, rootHop{roots: []ssh.Signer{f2.root}, threshold: 1, bundleBy: []ssh.Signer{f2.root}, policyBy: []ssh.Signer{f2.root}})
		if r, err := h2.apply(); err != nil || r.BundleVersion != 2 {
			t.Fatalf("a host on {A} and the fork 2': %v, %+v; want bundle 2", err, r)
		}
	})
	t.Run("same_roots_unchanged_policy_accepted", func(t *testing.T) {
		t.Parallel()
		// The 03-12/03-13 shape: the plain check passes, and accepted/
		// stores the stored signatures, whatever was delivered.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		c, _, _, _, _ := rootKeys(t)
		offerHops(t, h, f.bundle, f.bundleDoc, rootHop{roots: []ssh.Signer{f.root}, threshold: 1, bundleBy: []ssh.Signer{f.root}, policyBy: []ssh.Signer{f.root, c}})
		if r, err := h.apply(); err != nil || r.BundleVersion != 2 {
			t.Fatalf("same roots: %v, %+v; want bundle 2", err, r)
		}
		if s := mustAcceptedBundle(t, h, 2); !bytes.Equal(s.PolicySigs, f.policySigs) {
			t.Fatalf("accepted/'s policy signatures are not the stored ones:\n%s", s.PolicySigs)
		}
	})
	t.Run("growing_root_set_second_root_signs_policy", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		c, _, _, b, _ := rootKeys(t)
		offerHops(t, h, f.bundle, f.bundleDoc,
			rootHop{roots: []ssh.Signer{f.root, b}, threshold: 1, bundleBy: []ssh.Signer{f.root, b}, policyBy: []ssh.Signer{f.root, b}},
			rootHop{roots: []ssh.Signer{f.root, b, c}, threshold: 1, bundleBy: []ssh.Signer{b}, policyBy: []ssh.Signer{b}})
		if r, err := h.apply(); err != nil || r.BundleVersion != 3 {
			t.Fatalf("{A}→{A,B}→{A,B,C}: %v, %+v; want bundle 3", err, r)
		}
		mustAcceptedBundle(t, h, 3)
	})
	t.Run("stored_policy_sigs_stay_bounded", func(t *testing.T) {
		t.Parallel()
		h := threeHops(t)
		if r, err := h.apply(); err != nil || r.BundleVersion != 4 {
			t.Fatalf("three hops: %v, %+v; want bundle 4", err, r)
		}
		if s := mustAcceptedBundle(t, h, 4); !bytes.Equal(s.PolicySigs, h.state.BundlePolicySigs[4]) {
			t.Fatalf("accepted/'s policy signatures (%d bytes) are not bundle-4.policy.sigs (%d bytes)", len(s.PolicySigs), len(h.state.BundlePolicySigs[4]))
		}
	})
}
