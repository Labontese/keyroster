//go:build linux

package apply

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
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
