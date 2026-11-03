//go:build linux

package apply

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

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

// bobDir is a directory of a's policy-2 admin bob after prev, granting
// principals to deploy (F03 (03-08f)).
func (a *adminRemovedHost) bobDir(prev []byte, s dirSpec) spool.Doc {
	a.t.Helper()
	s.signer = a.bob
	return a.f.directory(prev, s)
}

// persistedUnauthorized is the state a host could hold before F03
// (03-08f), built through the test fixtures: alice's directory 2 (role:evil)
// is installed under bundle 1, then accepted/'s bundle and policy are
// replaced with bundle 2's, whose policy 2 names bob alone (seedKey 11),
// and saved with state.LoadStored and Save. current still renders
// [role:evil]. The spool offers bundle 2 and policy 2, as the fetcher left
// them.
func persistedUnauthorized(t *testing.T) (*testHost, *trust.Bundle, spool.Doc, spool.Doc) {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	spoolInState(t, h)
	h.installed("role:ops")
	h.publishDir(h.spec("role:evil"))
	h.mustApply()
	bob := seedKey(t, 11)
	b2, d2, p2 := f.rotation(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, "2026-10-02T00:00:00Z")
	s, err := h.accepted()
	if err != nil {
		t.Fatal(err)
	}
	s.Bundle, s.BundleSigs, s.Policy, s.PolicySigs, s.BundleVersion = d2.Body, d2.Sigs, p2.Body, p2.Sigs, 2
	fd, err := spool.OpenDir(h.l.State(state.AcceptedDir))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := s.Save(h.l, fd, nil); err != nil {
		t.Fatal(err)
	}
	h.state.Bundles[2], h.state.Policies[2] = d2, p2
	if a, err := h.accepted(); err != nil || a.BundleVersion != 2 || a.DirectoryVersion != 2 {
		t.Fatalf("the persisted state: accepted/ %+v (%v)", a, err)
	}
	if got := h.principals("deploy"); !slices.Equal(got, []string{"role:evil"}) {
		t.Fatalf("the persisted state renders %v, want [role:evil]", got)
	}
	return h, b2, d2, p2
}

// acceptedSnapshots is the entries of accepted/ with current.json's bytes:
// a commit stages a new snapshot and renames the pointer (F03 (03-08f)).
func acceptedSnapshots(t *testing.T, h *testHost) string {
	t.Helper()
	es, err := os.ReadDir(h.l.State(state.AcceptedDir))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	ptr, err := os.ReadFile(h.l.State(state.AcceptedDir, "current.json"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(names, ",") + "|" + string(ptr)
}

// noPrincipals fails t when current holds a principals file for deploy.
func noPrincipals(t *testing.T, h *testHost, what string) {
	t.Helper()
	if p := filepath.Join(h.l.Current(), PrincipalsDir, "deploy"); h.exists(p) {
		t.Fatalf("%s: current holds a principals file for deploy: %v", what, h.principals("deploy"))
	}
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
	t.Run("new_admins_next_version_accepted_standalone", func(t *testing.T) {
		t.Parallel()
		// Bob's directory 3 chains to bob's own 2, never to alice's 2, and
		// is taken standalone: the newest the current quorum signed.
		a := adminRemoved(t)
		h := a.testHost
		bob2 := a.bobDir(h.dirs[0].Body, h.spec("role:bob"))
		h.state.Directories[3] = a.bobDir(bob2.Body, h.spec("role:bob", "role:three"))
		r, err := h.apply()
		if err != nil || r.DirectoryUnauthorized || r.DirectoryVersion != 3 {
			t.Fatalf("bob's directory 3: %v, %+v; want it accepted standalone", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:bob", "role:three"}) {
			t.Fatalf("principals of deploy %v, want bob's directory 3", got)
		}
		if got := readAccepted(t, h); got.Directory != 3 {
			t.Fatalf("accepted.json names directory %d, want 3", got.Directory)
		}
	})
	t.Run("same_capture_hold_then_dropped", func(t *testing.T) {
		t.Parallel()
		// PR #67's hold, kept: one capture offers bundle 2 (policy 2: bob)
		// and alice's directory 2. The first apply holds the bundle at 1 and
		// renders alice's directory; the second moves to bundle 2, under
		// which that directory is not authorized. Directory 2 only narrows
		// directory 1, so apply 1 has no widening wait whose poll would take
		// bundle 2 in the same run.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops", "role:evil")
		h.publishDir(h.spec("role:evil"))
		next := seedKey(t, 31)
		_, d2, p2 := f.rotationNext(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(seedKey(t, 11).PublicKey())}}, "2026-10-02T00:00:00Z", next)
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		r, err := h.apply()
		if err != nil || !r.BundleHeld || r.BundleVersion != 1 || r.DirectoryVersion != 2 {
			t.Fatalf("apply 1: %v, %+v; want the hold at bundle 1 with directory 2", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:evil"}) {
			t.Fatalf("apply 1 renders %v, want alice's directory 2 under the held bundle 1", got)
		}
		r, err = h.apply()
		if !errors.Is(err, state.ErrDirUnauthorized) || r.BundleVersion != 2 || !r.DirectoryUnauthorized {
			t.Fatalf("apply 2: %v, %+v; want bundle 2 with directory_not_authorized", err, r)
		}
		noPrincipals(t, h, "apply 2")
		if ca := h.file(CAFile); !strings.Contains(ca, trust.FormatKey(next.PublicKey())) {
			t.Fatalf("current's user_ca_keys is not bundle 2's: %q", ca)
		}
	})
	t.Run("rotation_first_then_removed_admin_refused", func(t *testing.T) {
		t.Parallel()
		// Bundle 2 (policy 2: bob alone) first: alice's directory 1 is no
		// longer authorized. Alice's directory 2, signed by the removed
		// admin, then joins the unauthorized state; nothing of hers renders.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		_, d2, p2 := f.rotation(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(seedKey(t, 11).PublicKey())}}, "2026-10-02T00:00:00Z")
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		r, err := h.apply()
		if !errors.Is(err, state.ErrDirUnauthorized) || r.BundleVersion != 2 {
			t.Fatalf("apply 1: %v, %+v; want bundle 2 with directory_not_authorized", err, r)
		}
		noPrincipals(t, h, "apply 1")
		h.publishDir(h.spec("role:evil"))
		h.publishKRL(77)
		r, err = h.apply()
		if !errors.Is(err, state.ErrDirUnauthorized) || !errors.Is(err, state.ErrDir) {
			t.Fatalf("apply 2: %v, want directory_not_authorized joined with directory_not_verified", err)
		}
		noPrincipals(t, h, "apply 2")
		if r.BundleVersion != 2 || !h.krlRevokes(h.l.Current(), 77) {
			t.Fatalf("apply 2: %+v, revokes 77 %t; want bundle 2 and the KRL landed", r, h.krlRevokes(h.l.Current(), 77))
		}
		mustAcceptedBundle(t, h, 2)
	})
	t.Run("admin_set_unchanged_rotation_keeps_directory", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		_, d2, p2 := f.rotation(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z")
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		r, err := h.apply()
		if err != nil || r.DirectoryUnauthorized || r.BundleVersion != 2 {
			t.Fatalf("a rotation that keeps alice: %v, %+v", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops"}) {
			t.Fatalf("principals of deploy %v, want [role:ops] kept", got)
		}
	})
	t.Run("persisted_unauthorized_state_dropped_on_noop_capture", func(t *testing.T) {
		t.Parallel()
		h, _, _, _ := persistedUnauthorized(t)
		r, err := h.apply()
		if !errors.Is(err, state.ErrDirUnauthorized) || !r.DirectoryUnauthorized {
			t.Fatalf("apply 1 with nothing new: %v, %+v; want directory_not_authorized", err, r)
		}
		noPrincipals(t, h, "apply 1 with nothing new")
		cur, gens, snap := h.current(), h.genCount(), acceptedSnapshots(t, h)
		r, err = h.apply()
		if !errors.Is(err, state.ErrDirUnauthorized) || !r.NoOp || !r.DirectoryUnauthorized {
			t.Fatalf("apply 2 with nothing new: %v, %+v; want directory_not_authorized, a no-op", err, r)
		}
		if h.current() != cur || h.genCount() != gens || acceptedSnapshots(t, h) != snap {
			t.Fatalf("apply 2 committed: current %d (was %d), %d generations (was %d), accepted/ %s (was %s)", h.current(), cur, h.genCount(), gens, acceptedSnapshots(t, h), snap)
		}
		noPrincipals(t, h, "apply 2 with nothing new")
	})
	t.Run("refused_bundle_step_still_checks_directory", func(t *testing.T) {
		t.Parallel()
		// The persisted state with a bundle chain gap (4 without 3) and a
		// newer KRL: the KRL lands alone (D-R2, KRLAlone), and the KRL-alone
		// state is checked under the policy in force too.
		h, b2, d2, p2 := persistedUnauthorized(t)
		b3, d3 := h.f.successorUnder(b2, d2.Body, p2.Body, "2026-10-03T00:00:00Z")
		_, d4 := h.f.successorUnder(b3, d3.Body, p2.Body, "2026-10-04T00:00:00Z")
		h.state.Bundles[4] = d4
		h.publishKRL(88)
		r, err := h.apply()
		if !errors.Is(err, state.ErrBundleChainGap) || !errors.Is(err, state.ErrDirUnauthorized) || !r.DirectoryUnauthorized {
			t.Fatalf("apply: %v, %+v; want bundle_chain_gap joined with directory_not_authorized", err, r)
		}
		noPrincipals(t, h, "the KRL-alone state")
		if !h.krlRevokes(h.l.Current(), 88) {
			t.Fatal("the KRL did not land alone")
		}
	})
	t.Run("stored_version_above_new_admins_needs_reset", func(t *testing.T) {
		t.Parallel()
		// Owner decision Q-F03b: alice's directory 5 under policy 1. The
		// spool holds only versions below 5 (the fetcher's dropAbove), so
		// nothing the new admins sign below 5 is taken until reset-directory.
		f := newFixture(t)
		h := newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		for range 4 {
			h.publishDir(h.spec("role:ops", "role:five"))
		}
		if r := h.mustApply(); r.DirectoryVersion != 5 {
			t.Fatalf("alice's directory 5: %+v", r)
		}
		bob := seedKey(t, 11)
		next := seedKey(t, 31)
		_, d2, p2 := f.rotationNext(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, "2026-10-02T00:00:00Z", next)
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		h.resetSpool()
		h.state.Directories = map[uint64]spool.Doc{4: h.dirs[3]}
		r, err := h.apply()
		if !errors.Is(err, state.ErrDirUnauthorized) || !errors.Is(err, state.ErrDirOlder) || r.BundleVersion != 2 {
			t.Fatalf("apply 1: %v, %+v; want bundle 2, directory_not_authorized joined with directory_older", err, r)
		}
		noPrincipals(t, h, "apply 1")
		s := h.spec("role:bob")
		s.signer = bob
		bob2 := f.directory(h.dirs[0].Body, s)
		h.resetSpool()
		h.state.Directories = map[uint64]spool.Doc{2: bob2}
		if _, err := h.apply(); !errors.Is(err, state.ErrDirUnauthorized) {
			t.Fatalf("bob's directory 2 below the stored 5: %v, want directory_not_authorized", err)
		}
		noPrincipals(t, h, "bob's directory 2 below the stored 5")
		if _, err := ResetDirectory(h.l, h.spool); err != nil {
			t.Fatalf("reset-directory: %v", err)
		}
		h.state.Directories = map[uint64]spool.Doc{2: bob2}
		r, err = h.apply()
		if err != nil || r.DirectoryVersion != 2 || r.DirectoryUnauthorized {
			t.Fatalf("after reset-directory: %v, %+v; want bob's directory 2", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:bob"}) {
			t.Fatalf("principals of deploy %v, want bob's [role:bob]", got)
		}
	})
	t.Run("same_version_other_bytes_refused_as_fork", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		h.publishDir(h.spec("role:ops", "role:two"))
		h.mustApply()
		// Another directory 2 that alice, the current quorum, signed.
		h.state.Directories[2] = f.directory(h.dirs[0].Body, h.spec("role:ops", "role:other"))
		h.publishKRL(91)
		r, err := h.apply()
		if !errors.Is(err, state.ErrDirFork) || errors.Is(err, state.ErrDirUnauthorized) {
			t.Fatalf("a same-number directory with other bytes: %v, want directory_fork", err)
		}
		if !h.krlRevokes(h.l.Current(), 91) || r.KRLVersion != f.krlVersion {
			t.Fatalf("the KRL was not applied alone: %+v", r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops", "role:two"}) {
			t.Fatalf("principals of deploy %v, want the accepted directory 2's", got)
		}
	})
	t.Run("same_version_unsigned_bytes_not_verified", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		h.publishDir(h.spec("role:ops", "role:two"))
		h.mustApply()
		// Another directory 2, signed by a key that is no admin.
		s := h.spec("role:ops", "role:other")
		s.signer = seedKey(t, 41)
		h.state.Directories[2] = f.directory(h.dirs[0].Body, s)
		h.publishKRL(92)
		r, err := h.apply()
		if !errors.Is(err, state.ErrDir) || errors.Is(err, state.ErrDirFork) {
			t.Fatalf("a same-number directory without the quorum: %v, want directory_not_verified, not directory_fork", err)
		}
		if !h.krlRevokes(h.l.Current(), 92) || r.KRLVersion != f.krlVersion {
			t.Fatalf("the KRL was not applied alone: %+v", r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops", "role:two"}) {
			t.Fatalf("principals of deploy %v, want the accepted directory 2's", got)
		}
	})
	t.Run("recorded_authorized_directory_keeps_the_record_raise", func(t *testing.T) {
		t.Parallel()
		// Owner decision O-2 (c): bob's directory 3, above the caps, is
		// accepted standalone and recorded for its content. The chain base
		// is the record's directory 3, which policy 2 authorizes, so
		// accepted.json keeps the record's raise and the chain goes on.
		a := adminRemoved(t)
		h := a.testHost
		s3 := h.spec("role:bob")
		s3.bulkRoles = 17
		bob3 := a.bobDir(h.dirs[1].Body, s3)
		h.dirs = append(h.dirs, bob3)
		h.state.Directories[3] = bob3
		h.publishKRL(93)
		r, err := h.apply()
		if !errors.Is(err, ErrGenerationTooLarge) || !errors.Is(err, state.ErrDirUnauthorized) || !r.DirectoryUnauthorized {
			t.Fatalf("apply 1: %v, %+v; want generation_too_large joined with directory_not_authorized", err, r)
		}
		mustRecord(t, h, 0, 3)
		noPrincipals(t, h, "the KRL-alone state over accepted/")
		if !h.krlRevokes(h.l.Current(), 93) {
			t.Fatal("the KRL did not land alone")
		}
		if got := readAccepted(t, h); got.Directory != 3 {
			t.Fatalf("accepted.json names directory %d, want the record's 3", got.Directory)
		}
		d4 := a.bobDir(bob3.Body, h.spec("role:bob4"))
		d5 := a.bobDir(d4.Body, h.spec("role:bob5"))
		h.dirs = append(h.dirs, d4, d5)
		h.state.Directories[4], h.state.Directories[5] = d4, d5
		r, err = h.apply()
		if err != nil || r.DirectoryVersion != 5 || r.DirectoryUnauthorized {
			t.Fatalf("apply 2: %v, %+v; want directory 5 from the record's 3", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:bob5"}) {
			t.Fatalf("principals of deploy %v, want directory 5's", got)
		}
		if got := readAccepted(t, h); got.Directory != 5 {
			t.Fatalf("accepted.json names directory %d, want 5", got.Directory)
		}
		if recordExists(t, h) {
			t.Fatal("the unapplied record is still there")
		}
	})
	t.Run("recorded_bundle_over_unauthorized_directory_reports_directory_0", func(t *testing.T) {
		t.Parallel()
		// Owner decision O-2 (c): the record's bundle 2 rotates the policy
		// to bob over alice's directory 2, so the chain base is unauthorized
		// and accepted.json asks from directory 0. The server's current
		// directory, bob's 2, then recovers the host from the record.
		f := newFixture(t)
		h := newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		h.publishDir(h.spec("role:ops"))
		h.mustApply()
		key := seedKey(t, 32)
		d2, p2 := f.rotationDropping(f.bundle, f.bundleDoc, "2026-10-02T00:00:00Z", key, nil)
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		line := trust.FormatKey(key.PublicKey())
		h.run.rejectCA = func(l string) bool { return l == line }
		r, err := h.apply()
		if !errors.Is(err, ErrCALineRejected) || errors.Is(err, state.ErrDirUnauthorized) || r.DirectoryUnauthorized {
			t.Fatalf("apply 1: %v, %+v; want ca_line_rejected alone", err, r)
		}
		mustRecord(t, h, 2, 0)
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops"}) {
			t.Fatalf("apply 1 renders %v, want alice's [role:ops] under bundle 1", got)
		}
		if a := readAccepted(t, h); a.Bundle != 2 || a.Directory != 0 {
			t.Fatalf("accepted.json bundle %d, directory %d; want 2, 0", a.Bundle, a.Directory)
		}
		h.run.rejectCA = nil
		s := h.spec("role:bob")
		s.signer = seedKey(t, 12) // rotationDropping's bob
		bob2 := f.directory(h.dirs[0].Body, s)
		h.dirs[1], h.state.Directories[2] = bob2, bob2
		r, err = h.apply()
		if err != nil || r.BundleVersion != 2 || r.DirectoryVersion != 2 {
			t.Fatalf("apply 2: %v, %+v; want bundle 2 with bob's directory 2", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:bob"}) {
			t.Fatalf("principals of deploy %v, want bob's [role:bob]", got)
		}
		if a := readAccepted(t, h); a.Bundle != 2 || a.Directory != 2 {
			t.Fatalf("accepted.json bundle %d, directory %d; want 2, 2", a.Bundle, a.Directory)
		}
		if recordExists(t, h) {
			t.Fatal("the unapplied record is still there")
		}
	})
	t.Run("unauthorized_hold_then_chain_refusal_keeps_the_verified_bundle", func(t *testing.T) {
		t.Parallel()
		// Plan check 3, M-2: alice's directory 2, on a re-made directory 1,
		// holds the capture at bundle 1 and is then refused for its chain.
		// The hold is undone: bundle 2 stays, with its CA keys and no
		// principals.
		holdThenRefused(t, state.ErrDir, func(h *testHost) {
			remade := h.f.directory(nil, h.spec("role:remade"))
			h.state.Directories[2] = h.f.directory(remade.Body, h.spec("role:evil"))
		})
	})
	t.Run("unauthorized_hold_then_other_refusals_keep_the_verified_bundle", func(t *testing.T) {
		t.Parallel()
		// PR #82 review, D-2 (a): each converted refusal after the hold
		// undoes it, so bundle 2's CA keys render.
		t.Run("directory_installation", func(t *testing.T) {
			t.Parallel()
			holdThenRefused(t, state.ErrDirInstall, func(h *testHost) {
				s := h.spec("role:evil")
				s.install = "fedcba9876543210fedcba9876543210"
				h.state.Directories[2] = h.f.directory(h.dirs[0].Body, s)
			})
		})
		t.Run("directory_chain_gap", func(t *testing.T) {
			t.Parallel()
			holdThenRefused(t, state.ErrDirChainGap, func(h *testHost) {
				d2 := h.f.directory(h.dirs[0].Body, h.spec("role:evil"))
				h.state.Directories[3] = h.f.directory(d2.Body, h.spec("role:evil"))
			})
		})
		t.Run("directory_holds_another_version", func(t *testing.T) {
			t.Parallel()
			holdThenRefused(t, state.ErrDir, func(h *testHost) {
				d2 := h.f.directory(h.dirs[0].Body, h.spec("role:evil"))
				h.state.Directories[2] = h.f.directory(d2.Body, h.spec("role:evil"))
			})
		})
	})
	t.Run("widening_directory_with_rotation_supersedes_into_bundle_2", func(t *testing.T) {
		t.Parallel()
		// PR #82 review, D-2 (c): directory 1 is [role:ops]; one capture
		// offers alice's directory 2 [role:ops, role:evil], which widens
		// it, and bundle 2 (policy 2: bob). Apply 1 holds at bundle 1 and
		// waits to widen; the wait's poll takes bundle 2, under which
		// alice's directories are not authorized. role:evil never renders,
		// and the report does not say a bundle is held.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		next := seedKey(t, 31)
		_, d2, p2 := f.rotationNext(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(seedKey(t, 11).PublicKey())}}, "2026-10-02T00:00:00Z", next)
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		h.publishDir(h.spec("role:ops", "role:evil"))
		sleeps := 0
		h.clock.onSleep = func(time.Duration) {
			sleeps++
			if slices.Contains(h.principals("deploy"), "role:evil") {
				t.Errorf("during the wait current renders %v", h.principals("deploy"))
			}
		}
		r, err := h.apply()
		if !errors.Is(err, state.ErrDirUnauthorized) || r.BundleVersion != 2 || !r.DirectoryUnauthorized || r.Intermediate == 0 || sleeps == 0 {
			t.Fatalf("apply: %v, %+v (%d sleeps); want bundle 2 with directory_not_authorized after a widening wait", err, r, sleeps)
		}
		if r.BundleHeld {
			t.Errorf("the report says a bundle is held while bundle 2 is in force")
		}
		noPrincipals(t, h, "apply")
		if ca := h.file(CAFile); !strings.Contains(ca, trust.FormatKey(next.PublicKey())) {
			t.Fatalf("current's user_ca_keys is not bundle 2's: %q", ca)
		}
		if b, err := os.ReadFile(h.l.State(statusFile)); err != nil || strings.Contains(string(b), `"bundle_held":true`) { //nolint:gosec // test fixture
			t.Errorf("status.json (%v) says a bundle is held while bundle 2 is in force: %s", err, b)
		}
	})
}

// holdThenRefused is plan check 3's M-2 shape (PR #82 review, D-2 (a)): an
// installed host offered bundle 2 (policy 2: bob alone, with a next user
// CA) and, through offer, a newest directory of alice's that holds the
// capture at bundle 1 and is then refused with want. The refusal joins
// directory_not_authorized, and the hold is undone: bundle 2 and its CA
// keys are in force, with no principals, and the KRL lands.
func holdThenRefused(t *testing.T, want error, offer func(h *testHost)) {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	h.installed("role:ops")
	next := seedKey(t, 31)
	_, d2, p2 := f.rotationNext(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(seedKey(t, 11).PublicKey())}}, "2026-10-02T00:00:00Z", next)
	h.state.Bundles[2], h.state.Policies[2] = d2, p2
	offer(h)
	h.publishKRL(94)
	r, err := h.apply()
	if !errors.Is(err, state.ErrDirUnauthorized) || !errors.Is(err, want) {
		t.Fatalf("apply: %v, want directory_not_authorized joined with %v", err, want)
	}
	if r.BundleVersion != 2 || r.BundleHeld {
		t.Fatalf("report: bundle %d, held %t; want 2, not held", r.BundleVersion, r.BundleHeld)
	}
	noPrincipals(t, h, "apply")
	mustAcceptedBundle(t, h, 2)
	if ca := h.file(CAFile); !strings.Contains(ca, trust.FormatKey(next.PublicKey())) {
		t.Fatalf("current's user_ca_keys is not bundle 2's: %q", ca)
	}
	if !h.krlRevokes(h.l.Current(), 94) {
		t.Fatal("the KRL did not land")
	}
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
	t.Run("bundle_sigs_never_united", func(t *testing.T) {
		t.Parallel()
		// PR #82 review, D-2 (b): C's policy signature sits only in
		// bundle-2.json.sigs, beside A's and C's bundle signatures. The
		// bundle check skips it, and the policy union never reads that
		// file, so the rotation to {C} is refused.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		c, _, _, _, _ := rootKeys(t)
		offerHops(t, h, f.bundle, f.bundleDoc, rootHop{roots: []ssh.Signer{c}, threshold: 1, bundleBy: []ssh.Signer{f.root, c}})
		d2 := h.state.Bundles[2]
		d2.Sigs = append(slices.Clone(d2.Sigs), rootSigs(t, trust.NamespacePolicy, f.policyDoc, c)...)
		h.state.Bundles[2] = d2
		if _, err := h.apply(); !errors.Is(err, state.ErrBundle) || !strings.Contains(err.Error(), "policy (new roots) signed by 0 of 1 roots, need 1") {
			t.Fatalf("apply: %v, want bundle_not_verified, policy (new roots) signed by 0 of 1", err)
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
