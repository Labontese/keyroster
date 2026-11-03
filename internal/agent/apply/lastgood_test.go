//go:build linux

package apply

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

// evilHost is an installed host whose last-good renders alice's directory
// 2, which grants role:evil to deploy, under bundle 1 (policy 1: alice),
// with bob (seedKey 11) and bundle 2's next user CA (seedKey 31) at hand
// (PR #82 review, D-1).
type evilHost struct {
	*testHost
	bob, next ssh.Signer
}

func newEvilHost(t *testing.T, inState bool) *evilHost {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	if inState {
		spoolInState(t, h)
	}
	h.installed("role:ops")
	h.publishDir(h.spec("role:evil"))
	if r := h.mustApply(); r.DirectoryVersion != 2 || !slices.Equal(h.principals("deploy"), []string{"role:evil"}) {
		t.Fatalf("alice's directory 2: %+v, principals %v", r, h.principals("deploy"))
	}
	return &evilHost{testHost: h, bob: seedKey(t, 11), next: seedKey(t, 31)}
}

// offerBobBundle offers bundle 2, whose policy 2 names bob alone and which
// adds the next user CA.
func (e *evilHost) offerBobBundle() {
	e.t.Helper()
	f := e.f
	_, d2, p2 := f.rotationNext(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(e.bob.PublicKey())}}, "2026-10-02T00:00:00Z", e.next)
	e.state.Bundles[2], e.state.Policies[2] = d2, p2
}

// bobSpec is a spec of bob's for deploy listing web1 under a key that is
// not this host's (seedKey 77).
func (e *evilHost) bobSpec(principals ...string) dirSpec {
	s := e.spec(principals...)
	s.signer = e.bob
	s.hostKeys = []ssh.PublicKey{seedKey(e.t, 77).PublicKey()}
	return s
}

// trustOnlyWithNext requires current to hold the next user CA (seedKey 31), a KRL
// revoking serial and no principals file for deploy.
func (e *evilHost) trustOnlyWithNext(what string, serial uint64) {
	e.t.Helper()
	noPrincipals(e.t, e.testHost, what)
	if ca := e.file(CAFile); !strings.Contains(ca, trust.FormatKey(e.next.PublicKey())) {
		e.t.Fatalf("%s: current's user_ca_keys is not bundle 2's: %q", what, ca)
	}
	if !e.krlRevokes(e.l.Current(), serial) {
		e.t.Fatalf("%s: current does not revoke serial %d", what, serial)
	}
}

// TestLastGoodPrincipalsUnderPolicyInForce is PR #82 review D-1: when
// RenderFallback would keep last-good's principals (host_keys_rotated,
// host_keys_disagree, or no accepted directory), it keeps them only while
// the policy in force authorizes the directory they were rendered from;
// otherwise the host gets the trust files alone, with the KRL, and the
// host status is still reported.
func TestLastGoodPrincipalsUnderPolicyInForce(t *testing.T) {
	t.Run("recovery_with_rotated_host_keys_keeps_no_principals", func(t *testing.T) {
		t.Parallel()
		// One capture: bundle 2 (policy 2: bob) and bob's directory 2,
		// which lists web1 under another key. Bob's directory is taken
		// standalone, but last-good's role:evil comes from alice's.
		e := newEvilHost(t, false)
		e.offerBobBundle()
		bob2 := e.f.directory(e.dirs[0].Body, e.bobSpec("role:bob"))
		e.dirs[1], e.state.Directories[2] = bob2, bob2
		e.publishKRL(95)
		r, err := e.apply()
		if err != nil || r.BundleVersion != 2 || r.DirectoryVersion != 2 || r.HostStatus != HostKeysRotated || r.DirectoryUnauthorized {
			t.Fatalf("apply: %v, %+v; want bundle 2, bob's directory 2, host_keys_rotated", err, r)
		}
		e.trustOnlyWithNext("apply", 95)
		r, err = e.apply()
		if err != nil || !r.NoOp {
			t.Fatalf("the idle run: %v, %+v; want a no-op", err, r)
		}
		e.trustOnlyWithNext("the idle run", 95)
	})
	t.Run("recovery_with_disagreeing_host_keys_keeps_no_principals", func(t *testing.T) {
		t.Parallel()
		// The same capture, but bob's directory lists this host's two keys
		// under web1 and web2.
		e := newEvilHost(t, false)
		key := filepath.Join(t.TempDir(), "ssh_host_ecdsa_key")
		writeFile(t, key, []byte("private key placeholder\n"))
		second := seedKey(t, 15).PublicKey()
		writeFile(t, key+".pub", ssh.MarshalAuthorizedKey(second))
		e.run.extraHostKeys = []string{key}
		e.offerBobBundle()
		s := e.spec("role:bob")
		s.signer = e.bob
		s.extraHost = &directory.Host{Name: "web2", HostGroup: "lab", Keys: []string{trust.FormatKey(second)}, Principals: []string{"web2"}, Status: directory.StatusActive}
		bob2 := e.f.directory(e.dirs[0].Body, s)
		e.dirs[1], e.state.Directories[2] = bob2, bob2
		e.publishKRL(96)
		r, err := e.apply()
		if err != nil || r.BundleVersion != 2 || r.HostStatus != HostKeysDisagree {
			t.Fatalf("apply: %v, %+v; want bundle 2, host_keys_disagree", err, r)
		}
		e.trustOnlyWithNext("apply", 96)
	})
	t.Run("record_path_rotated_host_keys_keeps_no_principals", func(t *testing.T) {
		t.Parallel()
		// Bob's directory 3 is taken standalone with bundle 2 but is too
		// large: the record holds both, and the KRL lands over accepted/
		// (bundle 1, alice's directory 2). Bob's directory 4 then chains
		// from the record, whose directory policy 2 authorizes, and lists
		// web1 under another key. last-good is still alice's role:evil.
		e := newEvilHost(t, true)
		e.offerBobBundle()
		s3 := e.spec("role:bob")
		s3.signer, s3.bulkRoles = e.bob, 17
		bob3 := e.f.directory(e.dirs[1].Body, s3)
		e.dirs = append(e.dirs, bob3)
		e.state.Directories[3] = bob3
		e.publishKRL(97)
		if _, err := e.apply(); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("apply 1: %v, want generation_too_large", err)
		}
		mustRecord(t, e.testHost, 2, 3)
		bob4 := e.f.directory(bob3.Body, e.bobSpec("role:bob4"))
		e.dirs = append(e.dirs, bob4)
		e.state.Directories[4] = bob4
		r, err := e.apply()
		if err != nil || r.BundleVersion != 2 || r.DirectoryVersion != 4 || r.HostStatus != HostKeysRotated {
			t.Fatalf("apply 2: %v, %+v; want bundle 2, bob's directory 4, host_keys_rotated", err, r)
		}
		e.trustOnlyWithNext("apply 2", 97)
	})
	t.Run("widening_wait_supersede_keeps_no_principals", func(t *testing.T) {
		t.Parallel()
		// Directory 1 is alice's [role:ops, role:evil]. Bundle 2 (policy 2:
		// bob) and bob's directory 2 [role:ops, role:new] go through the
		// narrowing step and wait to widen. During the wait bob's directory
		// 3 lists web1 under another key: the poll's capture chains from
		// the pending target (bob's 2), and last-good is alice's.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops", "role:evil")
		e := &evilHost{testHost: h, bob: seedKey(t, 11), next: seedKey(t, 31)}
		e.offerBobBundle()
		s := h.spec("role:ops", "role:new")
		s.signer = e.bob
		bob2 := f.directory(h.dirs[0].Body, s)
		h.dirs = append(h.dirs, bob2)
		h.state.Directories[2] = bob2
		h.publishKRL(98)
		polled := false
		h.clock.onSleep = func(time.Duration) {
			if polled {
				return
			}
			polled = true
			bob3 := f.directory(bob2.Body, e.bobSpec("role:bob3"))
			h.dirs = append(h.dirs, bob3)
			h.state.Directories[3] = bob3
			h.write()
		}
		r, err := h.apply()
		if !polled || err != nil || r.BundleVersion != 2 || r.DirectoryVersion != 3 || r.HostStatus != HostKeysRotated {
			t.Fatalf("apply: %v, %+v (polled %t); want bundle 2, bob's directory 3, host_keys_rotated", err, r, polled)
		}
		e.trustOnlyWithNext("apply", 98)
	})
	t.Run("reset_directory_then_rotation_keeps_no_principals", func(t *testing.T) {
		t.Parallel()
		// reset-directory while alice's directory 2 is authorized, then
		// bundle 2 (policy 2: bob) before any directory: no directory is
		// accepted (F08 (03-08d)), and policy 2 does not authorize the
		// directory last-good's role:evil came from.
		e := newEvilHost(t, true)
		if _, err := ResetDirectory(e.l, e.spool); err != nil {
			t.Fatalf("reset-directory: %v", err)
		}
		e.state.Directories = map[uint64]spool.Doc{}
		e.offerBobBundle()
		e.publishKRL(99)
		r, err := e.apply()
		if !errors.Is(err, errNoDirectory) || r.BundleVersion != 2 {
			t.Fatalf("apply: %v, %+v; want bundle 2 with no directory accepted", err, r)
		}
		e.trustOnlyWithNext("apply", 99)
	})
	t.Run("kept_principals_then_admin_removed_keeps_none", func(t *testing.T) {
		t.Parallel()
		// Policy 2 names alice and bob. Bob's directory 3 lists web1 under
		// another key, so last-good keeps alice's role:evil from directory
		// 2. Policy 3 then names bob alone: bob's directory 3 is still
		// authorized, but the directory role:evil came from is not.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		e := &evilHost{testHost: h, bob: seedKey(t, 11), next: seedKey(t, 31)}
		bobAdmin := trust.AdminKey{Name: "bob", Key: trust.FormatKey(e.bob.PublicKey())}
		b2, d2, p2 := f.rotation(f.bundle, f.bundleDoc, f.policyDoc, f.policy, append(slices.Clone(f.policy.Admins), bobAdmin), "2026-10-02T00:00:00Z")
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		h.mustApply()
		h.publishDir(h.spec("role:evil"))
		h.mustApply()
		h.publishDir(e.bobSpec("role:bob"))
		if r := h.mustApply(); r.HostStatus != HostKeysRotated || !slices.Equal(h.principals("deploy"), []string{"role:evil"}) {
			t.Fatalf("bob's directory 3: %+v, principals %v; want host_keys_rotated keeping role:evil", r, h.principals("deploy"))
		}
		pol2, err := trust.ParsePolicy(p2.Body)
		if err != nil {
			t.Fatal(err)
		}
		_, d3, p3 := f.rotationNext(b2, d2.Body, p2.Body, pol2, []trust.AdminKey{bobAdmin}, "2026-10-03T00:00:00Z", e.next)
		h.state.Bundles[3], h.state.Policies[3] = d3, p3
		h.publishKRL(100)
		r, err := h.apply()
		if err != nil || r.BundleVersion != 3 || r.HostStatus != HostKeysRotated {
			t.Fatalf("policy 3: %v, %+v; want bundle 3, host_keys_rotated", err, r)
		}
		e.trustOnlyWithNext("policy 3", 100)
	})
	t.Run("kept_principals_across_rotations_keeping_admins_stay", func(t *testing.T) {
		t.Parallel()
		// The controls of the two cases above: a rotation whose policy
		// authorizes the same directories keeps principals last-good kept
		// from an earlier directory (host_keys_rotated), and after
		// reset-directory (F08 (03-08d)) the principals current holds.
		f := newFixture(t)
		h := newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		s := h.spec("role:ops", "role:x")
		s.hostKeys = []ssh.PublicKey{seedKey(t, 77).PublicKey()}
		h.publishDir(s)
		if r := h.mustApply(); r.HostStatus != HostKeysRotated || !slices.Equal(h.principals("deploy"), []string{"role:ops"}) {
			t.Fatalf("directory 2: %+v, principals %v; want host_keys_rotated keeping role:ops", r, h.principals("deploy"))
		}
		b2, d2, p2 := f.rotation(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z")
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		if r, err := h.apply(); err != nil || r.BundleVersion != 2 || r.HostStatus != HostKeysRotated || !slices.Equal(h.principals("deploy"), []string{"role:ops"}) {
			t.Fatalf("policy 2, alice kept: %v, %+v, principals %v; want role:ops kept", err, r, h.principals("deploy"))
		}
		if _, err := ResetDirectory(h.l, h.spool); err != nil {
			t.Fatalf("reset-directory: %v", err)
		}
		h.state.Directories = map[uint64]spool.Doc{}
		pol2, err := trust.ParsePolicy(p2.Body)
		if err != nil {
			t.Fatal(err)
		}
		_, d3, p3 := f.rotation(b2, d2.Body, p2.Body, pol2, f.policy.Admins, "2026-10-03T00:00:00Z")
		h.state.Bundles[3], h.state.Policies[3] = d3, p3
		if r, err := h.apply(); !errors.Is(err, errNoDirectory) || r.BundleVersion != 3 || !slices.Equal(h.principals("deploy"), []string{"role:ops"}) {
			t.Fatalf("policy 3 after reset-directory: %v, %+v, principals %v; want role:ops kept", err, r, h.principals("deploy"))
		}
	})
	t.Run("authorized_directory_across_rotation_keeps_principals", func(t *testing.T) {
		t.Parallel()
		// The control: a rotation that keeps alice, with her directory 2
		// listing web1 under another key in the same capture. Directory 1,
		// which last-good's role:ops came from, stays authorized, so
		// last-good's principals are kept, as before D-1.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		_, d2, p2 := f.rotation(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z")
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		s := h.spec("role:ops", "role:x")
		s.hostKeys = []ssh.PublicKey{seedKey(t, 77).PublicKey()}
		h.publishDir(s)
		r, err := h.apply()
		if err != nil || r.BundleVersion != 2 || r.HostStatus != HostKeysRotated {
			t.Fatalf("apply: %v, %+v; want bundle 2, host_keys_rotated", err, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops"}) {
			t.Fatalf("principals of deploy %v, want last-good's [role:ops] kept", got)
		}
	})
}
