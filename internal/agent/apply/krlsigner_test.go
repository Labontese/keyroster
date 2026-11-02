//go:build linux

package apply

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// successorUnder builds and root-signs bundle version prev.Version+1 under
// polDoc, prev's policy, kept (03-08k): f.successor holds only for bundles
// under the fixture's genesis policy.
func (f *fixture) successorUnder(prev *trust.Bundle, prevDoc, polDoc []byte, issuedAt string) (*trust.Bundle, spool.Doc) {
	f.t.Helper()
	b, err := trust.BuildSuccessor(prev, prevDoc, polDoc, prev.Root.Keys, 1, polDoc, issuedAt, testInstallation)
	if err != nil {
		f.t.Fatal(err)
	}
	doc := mustCanonical(f.t, b)
	return b, spool.Doc{Body: doc, Sigs: f.rootSign(trust.NamespaceBundle, doc)}
}

// rotated is opsRotated's shape: a host at directory 1 with KRL 5 (version
// v5) in force, signed by the fixture's ops key k1, and bundle 2 offered, a
// root-signed successor of bundle 1 under the same admins that replaces the
// ops key with k2.
type rotated struct {
	h      *testHost
	b2     *trust.Bundle
	d2, p2 spool.Doc
	k1, k2 ssh.Signer
	v5     uint64
}

func opsRotated(t *testing.T) rotated {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	withOutbox(t, h)
	h.installed("role:ops")
	h.publishKRL(5)
	h.mustApply()
	x := rotated{h: h, k1: f.ops, k2: seedKey(t, 22), v5: f.krlVersion}
	x.b2, x.d2, x.p2 = f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z", x.k2)
	h.state.Bundles[2], h.state.Policies[2] = x.d2, x.p2
	return x
}

// mustUnchanged checks that an apply installed nothing: current, the
// generation count and accepted/'s bundle, directory and KRL are the ones
// read before it.
func mustUnchanged(t *testing.T, h *testHost, gen uint64, gens int, before *state.Stored) {
	t.Helper()
	if h.current() != gen || h.genCount() != gens {
		t.Fatalf("something was installed: current %d (was %d), %d generations (was %d)", h.current(), gen, h.genCount(), gens)
	}
	a, err := h.accepted()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bundle, before.Bundle) || !bytes.Equal(a.Directory, before.Directory) || !bytes.Equal(a.KRL, before.KRL) || !bytes.Equal(a.KRLManifest, before.KRLManifest) || !bytes.Equal(a.KRLSig, before.KRLSig) {
		t.Fatalf("accepted/ changed: bundle %d (was %d), directory %d (was %d), KRL %d (was %d)", a.BundleVersion, before.BundleVersion, a.DirectoryVersion, before.DirectoryVersion, a.KRLVersion, before.KRLVersion)
	}
}

// mustAcceptedBundle1 checks that accepted/ still holds the original bundle 1
// and directory dir, and that the CA file holds bundle 1's user CA line.
func mustAcceptedBundle1(t *testing.T, h *testHost, dir uint64) {
	t.Helper()
	a, err := h.accepted()
	if err != nil || a.BundleVersion != 1 || !bytes.Equal(a.Bundle, h.f.bundleDoc) || a.DirectoryVersion != dir {
		t.Fatalf("accepted/ %+v (%v), want the original bundle 1 and directory %d", a, err, dir)
	}
	if !strings.Contains(h.file(CAFile), trust.FormatKey(h.f.user.PublicKey())) {
		t.Fatalf("the CA file does not hold bundle 1's user CA line:\n%s", h.file(CAFile))
	}
}

// recordBelowWait is TestSpoolWindowWideningWait's recordAbove shape for
// this file (03-08k). KRL 5, signed by the fixture's ops key K1, is applied
// first: the swap the widening apply waits after. Bundle 2 keeps the policy
// and adds a next CA x; bundle 3 rotates the policy to admin bob, drops x
// and adds a CA line ssh-keygen refuses, and with recordOps names recordOps
// as its ops key. Apply 1 records {Bundle: 3}. With aboveOps, bundle 4 is a
// root-signed successor of bundle 3 under the next policy (admin bob kept)
// that names aboveOps, and verifies in full. Directory 2, signed under bundle
// 1's policy, widens deploy to role:q, so the next apply holds at the bundle
// in force below the record and waits.
func recordBelowWait(t *testing.T, recordOps, aboveOps ssh.Signer) *testHost {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	spoolInState(t, h)
	h.installed("role:ops")
	h.clock.advance(time.Hour)
	h.publishKRL(5)
	h.mustApply()
	b2, d2 := f.successorNextUnder(f.bundle, f.bundleDoc, f.policyDoc, "2026-10-02T00:00:00Z", seedKey(t, 25))
	rejected := seedKey(t, 21)
	d3, p2 := f.rotationDropping(b2, d2.Body, "2026-10-03T00:00:00Z", rejected, recordOps)
	h.state.Bundles[2], h.state.Bundles[3], h.state.Policies[2] = d2, d3, p2
	line := trust.FormatKey(rejected.PublicKey())
	h.run.rejectCA = func(l string) bool { return l == line }
	if _, err := h.apply(); !errors.Is(err, ErrCALineRejected) {
		t.Fatalf("apply 1: %v, want ca_line_rejected", err)
	}
	mustRecord(t, h, 3, 0)
	if aboveOps != nil {
		b3, err := trust.ParseBundle(d3.Body)
		if err != nil {
			t.Fatal(err)
		}
		pol2, err := trust.ParsePolicy(p2.Body)
		if err != nil {
			t.Fatal(err)
		}
		_, d4, p3 := f.rotationOps(b3, d3.Body, p2.Body, pol2, pol2.Admins, "2026-10-04T00:00:00Z", aboveOps)
		h.state.Bundles[4], h.state.Policies[3] = d4, p3
	}
	h.publishDir(h.spec("role:ops", "role:q"))
	return h
}

// TestKRLSigner (03-08k) decides which signed KRL a host takes when the
// newest KRL and the bundles the host knows name different ops keys: a KRL
// lands when the bundle in force or a fully verified successor authorises
// it, and no other KRL lands.
func TestKRLSigner(t *testing.T) {
	t.Run("successor_signed_krl_then_no_new_krl_is_a_noop", func(t *testing.T) {
		t.Parallel()
		x := opsRotated(t)
		h := x.h
		s := h.spec("role:ops")
		s.bulkRoles = 17
		h.publishDir(s)
		h.f.ops = x.k2
		h.publishKRL(6)
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) || !h.krlRevokes(h.l.Current(), 6) {
			t.Fatalf("apply 1: %v, revokes 6 %t; want generation_too_large with KRL 6 applied alone", err, h.krlRevokes(h.l.Current(), 6))
		}
		gen, gens := h.current(), h.genCount()
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) || errors.Is(err, state.ErrKRL) {
			t.Fatalf("apply 2 with no newer KRL: %v, want generation_too_large alone", err)
		}
		if h.current() != gen || h.genCount() != gens || !h.krlRevokes(h.l.Current(), 6) {
			t.Fatalf("apply 2 changed something: current %d (was %d), %d generations (was %d)", h.current(), gen, h.genCount(), gens)
		}
	})
	t.Run("successor_signed_krl_after_a_refused_directory_lands_alone", func(t *testing.T) {
		t.Parallel()
		// Q2: the bundle chain verified in full, and Verify refused the
		// directory step.
		x := opsRotated(t)
		h := x.h
		s := h.spec("role:ops")
		s.signer = seedKey(t, 14)
		h.publishDir(s)
		h.f.ops = x.k2
		h.publishKRL(6)
		r, err := h.apply()
		if !errors.Is(err, state.ErrDir) || errors.Is(err, state.ErrKRL) {
			t.Fatalf("a directory no policy signed: %v, want directory_not_verified alone", err)
		}
		mustKRLAlone(t, h, r, 6, 1, "directory_not_verified")
		mustAcceptedBundle1(t, h, 1)
	})
	t.Run("successor_signed_krl_after_a_refused_bundle_step_is_refused", func(t *testing.T) {
		t.Parallel()
		// Q2's limit: bundle 2 verifies, bundle 3 does not, so the capture's
		// bundle step is refused and bundle 2 authorises nothing.
		x := opsRotated(t)
		h := x.h
		_, d3 := h.f.successorUnder(x.b2, x.d2.Body, x.p2.Body, "2026-10-03T00:00:00Z")
		d3.Sigs = x.d2.Sigs
		h.state.Bundles[3] = d3
		h.f.ops = x.k2
		h.publishKRL(6)
		gen, gens := h.current(), h.genCount()
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.apply(); !errors.Is(err, state.ErrBundle) || !errors.Is(err, state.ErrKRL) {
			t.Fatalf("a refused bundle step: %v, want bundle_not_verified and krl_not_verified", err)
		}
		mustUnchanged(t, h, gen, gens, before)
	})
	t.Run("successor_signed_krl_needs_a_verified_successor", func(t *testing.T) {
		t.Parallel()
		// Bundle 3 is offered without bundle 2: a bundle that was only
		// offered never authorises a KRL.
		x := opsRotated(t)
		h := x.h
		pol2, err := trust.ParsePolicy(x.p2.Body)
		if err != nil {
			t.Fatal(err)
		}
		k3 := seedKey(t, 23)
		_, d3, p3 := h.f.rotationOps(x.b2, x.d2.Body, x.p2.Body, pol2, pol2.Admins, "2026-10-03T00:00:00Z", k3)
		delete(h.state.Bundles, 2)
		h.state.Bundles[3], h.state.Policies[3] = d3, p3
		h.f.ops = k3
		h.publishKRL(6)
		gen, gens := h.current(), h.genCount()
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.apply(); !errors.Is(err, state.ErrBundleChainGap) || !errors.Is(err, state.ErrKRL) {
			t.Fatalf("a bundle chain gap: %v, want bundle_chain_gap and krl_not_verified", err)
		}
		mustUnchanged(t, h, gen, gens, before)
	})
	t.Run("record_signed_krl_during_a_wait_lands", func(t *testing.T) {
		t.Parallel()
		// The record's bundle 3 names K2, and KRL 8 is signed by K2. A poll
		// reads from the record, and its capture brings nothing beyond it:
		// its KRL step verifies KRL 8 under bundle 3, and the KRL-alone
		// pass, which fails under bundle 1, takes it under the capture's
		// fully verified bundle 3.
		runWait(t, waitCase{
			build:   func(t *testing.T) *testHost { return recordBelowWait(t, seedKey(t, 22), nil) },
			publish: func(h *testHost) { h.f.ops = seedKey(h.t, 22); h.publishKRL(5, 8) },
			want:    waitWant{bundle: 1, dir: 2, lands: true, revoked: []uint64{5, 8}, record: 3},
		}, "poll", "forward")
	})

	// --- the KRL step ---
	t.Run("retired_key_krl_on_the_krl_step_is_refused", func(t *testing.T) {
		t.Parallel()
		x := opsRotated(t)
		h := x.h
		h.publishDir(h.spec("role:ops", "role:q"))
		h.publishKRL(5, 6)
		gen, gens := h.current(), h.genCount()
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		for i := 1; i <= 2; i++ {
			// Apply 2 has no newer KRL: the refused KRL never became the
			// stored one, so the skip rules do not pass it.
			_, err := h.apply()
			if !errors.Is(err, state.ErrKRLSignerRetired) || errors.Is(err, state.ErrKRL) || !strings.Contains(err.Error(), "bundle version 1") || !strings.Contains(err.Error(), "bundle version 2") {
				t.Fatalf("apply %d: %v, want krl_signer_retired naming bundle versions 1 and 2", i, err)
			}
			mustUnchanged(t, h, gen, gens, before)
			if !h.krlRevokes(h.l.Current(), 5) || h.krlRevokes(h.l.Current(), 6) {
				t.Fatalf("apply %d: the KRL in force changed", i)
			}
			if la := outboxStatus(t, h).LastApply; la == nil || la.Result != heartbeat.ResultRefused {
				t.Fatalf("apply %d: last_apply %+v, want refused", i, la)
			}
			if recordExists(t, h) {
				t.Fatalf("apply %d recorded the refused capture", i)
			}
		}
		h.f.ops = x.k2
		h.publishKRL(5, 6, 7)
		r, err := h.apply()
		if a, aerr := h.accepted(); err != nil || aerr != nil || a.BundleVersion != 2 || a.DirectoryVersion != 2 || a.KRLVersion != h.f.krlVersion || !h.krlRevokes(h.l.Current(), 7) {
			t.Fatalf("apply 3 with the new key's KRL: %v, %+v, accepted %+v (%v)", err, r, a, aerr)
		}
	})
	t.Run("krl_third_key_under_changed_bundle_not_retired", func(t *testing.T) {
		t.Parallel()
		x := opsRotated(t)
		h := x.h
		h.f.ops = seedKey(t, 24)
		h.publishKRL(5, 6)
		gen, gens := h.current(), h.genCount()
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.apply(); !errors.Is(err, state.ErrKRL) || !errors.Is(err, krl.ErrSigner) || errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("a KRL no known key signed: %v, want krl_not_verified for its signer", err)
		}
		mustUnchanged(t, h, gen, gens, before)
	})
	t.Run("first_install_krl_refusal_unchanged", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.publishDir(h.spec("role:ops"))
		h.f.ops = seedKey(t, 24)
		h.publishKRL(6)
		if _, err := h.apply(); !errors.Is(err, state.ErrKRL) || !errors.Is(err, krl.ErrSigner) || errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("a first install with a KRL no key signed: %v, want krl_not_verified", err)
		}
		if h.current() != 0 || h.exists(h.l.LastGood()) {
			t.Fatalf("a refused first install installed something: current %d, last-good %d", h.current(), h.lastGood())
		}
	})
	t.Run("krl_the_new_bundle_authorises_applies_with_it", func(t *testing.T) {
		t.Parallel()
		x := opsRotated(t)
		h := x.h
		h.f.ops = x.k2
		h.publishKRL(5, 6)
		r, err := h.apply()
		if a, aerr := h.accepted(); err != nil || aerr != nil || a.BundleVersion != 2 || a.KRLVersion != h.f.krlVersion || !h.krlRevokes(h.l.Current(), 6) {
			t.Fatalf("bundle 2 with a KRL its ops key signed: %v, %+v, accepted %+v (%v)", err, r, a, aerr)
		}
	})
	t.Run("unchanged_krl_under_a_rotated_bundle_installs", func(t *testing.T) {
		t.Parallel()
		// A rotation's usual shape: the spool's newest KRL is the one in
		// force, signed by the old key. The skip rules come first, so a KRL
		// the host already accepted is never refused for its signer.
		x := opsRotated(t)
		h := x.h
		r, err := h.apply()
		if a, aerr := h.accepted(); err != nil || aerr != nil || a.BundleVersion != 2 || a.KRLVersion != x.v5 || !h.krlRevokes(h.l.Current(), 5) {
			t.Fatalf("bundle 2 with KRL 5 unchanged: %v, %+v, accepted %+v (%v)", err, r, a, aerr)
		}
	})

	// --- the KRL-alone pass ---
	t.Run("retired_key_krl_after_a_refused_directory_is_refused", func(t *testing.T) {
		t.Parallel()
		x := opsRotated(t)
		h := x.h
		s := h.spec("role:ops")
		s.signer = seedKey(t, 14)
		h.publishDir(s)
		h.publishKRL(6)
		gen, gens := h.current(), h.genCount()
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.apply(); !errors.Is(err, state.ErrDir) || !errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("a refused directory and a retired-key KRL: %v, want directory_not_verified and krl_signer_retired", err)
		}
		mustUnchanged(t, h, gen, gens, before)
		if !h.krlRevokes(h.l.Current(), 5) {
			t.Fatal("serial 5 is no longer revoked")
		}
	})
	t.Run("retired_key_krl_after_a_refused_bundle_step_is_refused", func(t *testing.T) {
		t.Parallel()
		// Bundle 2, verified before the refused bundle 3, is known: it
		// retired the old key.
		x := opsRotated(t)
		h := x.h
		_, d3 := h.f.successorUnder(x.b2, x.d2.Body, x.p2.Body, "2026-10-03T00:00:00Z")
		d3.Sigs = x.d2.Sigs
		h.state.Bundles[3] = d3
		h.publishKRL(6)
		gen, gens := h.current(), h.genCount()
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.apply(); !errors.Is(err, state.ErrBundle) || !errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("a refused bundle step and a retired-key KRL: %v, want bundle_not_verified and krl_signer_retired", err)
		}
		mustUnchanged(t, h, gen, gens, before)
	})
	t.Run("rotated_back_key_is_current", func(t *testing.T) {
		t.Parallel()
		// Q4: bundle 3 names the original key again.
		x := opsRotated(t)
		h := x.h
		pol2, err := trust.ParsePolicy(x.p2.Body)
		if err != nil {
			t.Fatal(err)
		}
		_, d3, p3 := h.f.rotationOps(x.b2, x.d2.Body, x.p2.Body, pol2, pol2.Admins, "2026-10-03T00:00:00Z", x.k1)
		h.state.Bundles[3], h.state.Policies[3] = d3, p3
		s := h.spec("role:ops")
		s.signer = seedKey(t, 14)
		h.publishDir(s)
		h.publishKRL(5, 6)
		r, err := h.apply()
		if !errors.Is(err, state.ErrDir) || errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("a key named again: %v, want directory_not_verified alone", err)
		}
		mustKRLAlone(t, h, r, 6, 1, "directory_not_verified")
		mustAcceptedBundle1(t, h, 1)
	})

	// --- held ---
	t.Run("held_bundle_krl_signed_by_the_newest_key_lands_with_the_held_step", func(t *testing.T) {
		t.Parallel()
		x := heldShape(t, false)
		h := x.h
		h.f.ops = x.k2
		h.publishKRL(5, 6)
		r, err := h.apply()
		if err != nil || r.BundleVersion != 2 || r.DirectoryVersion != 65 || !r.BundleHeld || !h.krlRevokes(h.l.Current(), 6) {
			t.Fatalf("apply 1: %v, %+v, revokes 6 %t; want bundle 2, directory 65, held, KRL 6", err, r, h.krlRevokes(h.l.Current(), 6))
		}
		r, err = h.apply()
		if err != nil || r.BundleVersion != 3 || r.DirectoryVersion != 67 || r.KRLVersion != h.f.krlVersion || !h.krlRevokes(h.l.Current(), 6) {
			t.Fatalf("apply 2: %v, %+v; want bundle 3, directory 67, KRL 6", err, r)
		}
	})
	t.Run("held_step_krl_signed_by_a_retired_key_is_refused", func(t *testing.T) {
		t.Parallel()
		x := heldShape(t, false)
		h := x.h
		h.publishKRL(6)
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		r, err := h.apply()
		if !errors.Is(err, state.ErrKRLSignerRetired) || r.BundleVersion != 2 || r.DirectoryVersion != 65 || !r.BundleHeld {
			t.Fatalf("apply 1: %v, %+v; want the held step (bundle 2, directory 65) and krl_signer_retired", err, r)
		}
		mustKRLBytes(t, h, before, x.v5)
		if la := outboxStatus(t, h).LastApply; la == nil || la.Result != heartbeat.ResultRefused {
			t.Fatalf("apply 1: last_apply %+v, want refused", la)
		}
		if _, err := h.apply(); !errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("apply 2 with no newer KRL: %v, want krl_signer_retired", err)
		}
		if a, err := h.accepted(); err != nil || a.BundleVersion != 2 {
			t.Fatalf("apply 2 installed something: accepted %+v (%v)", a, err)
		}
		mustKRLBytes(t, h, before, x.v5)
		h.f.ops = x.k2
		h.publishKRL(5, 6, 7)
		r, err = h.apply()
		if err != nil || r.BundleVersion != 3 || r.DirectoryVersion != 67 || r.KRLVersion != h.f.krlVersion || !h.krlRevokes(h.l.Current(), 7) {
			t.Fatalf("apply 3 with the new key's KRL: %v, %+v; want bundle 3, directory 67, KRL 7", err, r)
		}
	})
	t.Run("retired_in_force_key_krl_under_a_held_step_is_refused", func(t *testing.T) {
		t.Parallel()
		// P differs from F: bundle 2 replaced K1 with K2, and bundle 3 keeps
		// K2 and rotates the admins.
		x := heldShape(t, true)
		h := x.h
		h.publishKRL(5, 6)
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		r, err := h.apply()
		if !errors.Is(err, state.ErrKRLSignerRetired) || r.BundleVersion != 2 || r.DirectoryVersion != 65 || !r.BundleHeld || r.KRLVersion != x.v5 {
			t.Fatalf("apply 1: %v, %+v; want the held step (bundle 2, directory 65) with KRL 5 and krl_signer_retired", err, r)
		}
		mustKRLBytes(t, h, before, x.v5)
		if la := outboxStatus(t, h).LastApply; la == nil || la.Result != heartbeat.ResultRefused {
			t.Fatalf("apply 1: last_apply %+v, want refused", la)
		}
		h.f.ops = x.k2
		h.publishKRL(5, 6, 7)
		r, err = h.apply()
		if err != nil || r.BundleVersion != 3 || r.DirectoryVersion != 67 || r.KRLVersion != h.f.krlVersion || !h.krlRevokes(h.l.Current(), 7) {
			t.Fatalf("apply 2 with the new key's KRL: %v, %+v; want bundle 3, directory 67, KRL 7", err, r)
		}
	})
	t.Run("retired_key_krl_held_at_the_in_force_bundle_below_the_record_is_refused", func(t *testing.T) {
		t.Parallel()
		// TestSpoolWindow/policy_rotation_below_the_recorded_bundle's newOps
		// shape: the record's bundle 3 names K2, and the capture is held at
		// the bundle in force (P = F = bundle 1), whose key K1 signed KRL 7.
		f := newFixture(t)
		h := newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		h.publishKRL(5)
		h.mustApply()
		v5 := f.krlVersion
		bob := seedKey(t, 12)
		b2, d2, p2 := f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, "2026-10-02T00:00:00Z", seedKey(t, 22))
		h.state.Bundles[2], h.state.Policies[2] = d2, p2
		next := seedKey(t, 21)
		_, d3 := f.successorNextUnder(b2, d2.Body, p2.Body, "2026-10-03T00:00:00Z", next)
		h.state.Bundles[3] = d3
		line := trust.FormatKey(next.PublicKey())
		h.run.rejectCA = func(l string) bool { return l == line }
		if _, err := h.apply(); !errors.Is(err, ErrCALineRejected) {
			t.Fatalf("apply 1: %v, want ca_line_rejected", err)
		}
		mustRecord(t, h, 3, 0)
		for range spool.MaxVersionsPerKind {
			h.publishDir(h.spec("role:ops"))
		}
		h.publishKRL(7)
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		r, err := h.apply()
		if !errors.Is(err, state.ErrKRLSignerRetired) || r.BundleVersion != 1 || r.DirectoryVersion != 65 || !r.BundleHeld {
			t.Fatalf("apply 2: %v, %+v; want directory 65 held under bundle 1 and krl_signer_retired", err, r)
		}
		mustKRLBytes(t, h, before, v5)
		mustRecord(t, h, 3, 0)
	})

	// --- a poll from the record ---
	t.Run("retired_key_krl_during_a_wait_from_the_record_is_refused", func(t *testing.T) {
		t.Parallel()
		// The record's bundle 3 names K2, and KRL 8 is signed by the key in
		// force, K1, which bundle 3 retired. In poll, the KRL step refuses
		// KRL 8 before the KRL-alone call; in forward, the held step commits
		// without it.
		runWait(t, waitCase{
			build:   func(t *testing.T) *testHost { return recordBelowWait(t, seedKey(t, 22), nil) },
			publish: func(h *testHost) { h.publishKRL(5, 8) },
			want:    waitWant{bundle: 1, dir: 2, revoked: []uint64{5}, kept: []uint64{8}, record: 3, retired: true},
		}, "poll", "forward")
	})

	// --- the record (03-08j) ---
	t.Run("successor_from_the_record_after_a_refused_bundle_step_above_it", func(t *testing.T) {
		t.Parallel()
		// The record's bundle 2 names K2 and verified in full when it was
		// recorded; bundle 3 above it is refused, so it authorises KRL 6.
		x := recordedRotation(t)
		h := x.h
		_, d3 := h.f.successorUnder(x.b2, x.d2.Body, x.p2.Body, "2026-10-03T00:00:00Z")
		d3.Sigs = x.d2.Sigs
		h.state.Bundles[3] = d3
		h.f.ops = x.k2
		h.publishKRL(5, 6)
		r, err := h.apply()
		if !errors.Is(err, state.ErrBundle) || errors.Is(err, state.ErrKRL) {
			t.Fatalf("apply 2: %v, want bundle_not_verified alone", err)
		}
		mustKRLAlone(t, h, r, 6, 1, "bundle_not_verified")
		mustAcceptedBundle1(t, h, 1)
		mustRecord(t, h, 2, 2)
	})
	t.Run("record_successor_dropped_by_a_verified_bundle_above_it_is_refused", func(t *testing.T) {
		t.Parallel()
		// Bundle 3 replaces the record's key K2 with K3 and verifies; bundle
		// 4 is refused. The record's bundle authorises nothing (fail closed).
		x := recordedRotation(t)
		h := x.h
		pol2, err := trust.ParsePolicy(x.p2.Body)
		if err != nil {
			t.Fatal(err)
		}
		b3, d3, p3 := h.f.rotationOps(x.b2, x.d2.Body, x.p2.Body, pol2, pol2.Admins, "2026-10-03T00:00:00Z", seedKey(t, 23))
		_, d4 := h.f.successorUnder(b3, d3.Body, p3.Body, "2026-10-04T00:00:00Z")
		d4.Sigs = d3.Sigs
		h.state.Bundles[3], h.state.Bundles[4], h.state.Policies[3] = d3, d4, p3
		h.f.ops = x.k2
		h.publishKRL(5, 6)
		gen, gens := h.current(), h.genCount()
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.apply(); !errors.Is(err, state.ErrBundle) || !errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("apply 2: %v, want bundle_not_verified and krl_signer_retired", err)
		}
		mustUnchanged(t, h, gen, gens, before)
		mustRecord(t, h, 2, 2)
	})

	// --- a poll during a widening wait ---
	t.Run("retired_key_krl_during_a_wait_is_refused", func(t *testing.T) {
		t.Parallel()
		// No record. Bundle 2 retired K1, and is known in a poll only from
		// the pending capture.
		runWait(t, waitCase{
			build:   heldWait,
			publish: func(h *testHost) { h.publishKRL(5, 7) },
			during:  withholdAbovePending,
			want:    waitWant{bundle: 1, dir: 1 + spool.MaxVersionsPerKind, revoked: []uint64{5}, kept: []uint64{7}, retired: true},
		}, "poll", "forward")
	})
	t.Run("successor_signed_krl_during_a_wait_lands", func(t *testing.T) {
		t.Parallel()
		// No record. KRL 8 is signed by bundle 2's key K2; in a poll, bundle
		// 2 is the successor carried from the pending capture.
		runWait(t, waitCase{
			build:   heldWait,
			publish: func(h *testHost) { h.f.ops = seedKey(h.t, 22); h.publishKRL(5, 8) },
			during:  withholdAbovePending,
			want:    waitWant{bundle: 1, dir: 1 + spool.MaxVersionsPerKind, lands: true, revoked: []uint64{5, 8}},
		}, "poll", "forward")
	})
	t.Run("retired_key_krl_during_a_wait_above_the_record_is_refused", func(t *testing.T) {
		t.Parallel()
		// The record's bundle 3 keeps K1, and bundle 4 above it, verified by
		// the widening apply, names K2. In a poll bundle 4 is known only
		// from the pending capture: the higher of the record's bundle and
		// the pending capture's.
		runWait(t, waitCase{
			build:   func(t *testing.T) *testHost { return recordBelowWait(t, nil, seedKey(t, 22)) },
			publish: func(h *testHost) { h.publishKRL(5, 8) },
			during: func(_ *testing.T, h *testHost) {
				delete(h.state.Bundles, 4)
				delete(h.state.Policies, 3)
			},
			want: waitWant{bundle: 1, dir: 2, revoked: []uint64{5}, kept: []uint64{8}, record: 3, retired: true},
		}, "poll", "forward")
	})
	t.Run("retired_key_krl_after_a_krl_alone_supersede_is_refused", func(t *testing.T) {
		t.Parallel()
		// KRLAlone's Verified inherits fullyVerified: a poll's generation
		// is refused for its content, its KRL-alone pass lands KRL 8 under
		// the carried successor (bundle 2) and supersedes the pending
		// target, and a later poll, verified against that KRL-alone state,
		// still knows bundle 2 and refuses KRL 9, which K1 signed.
		h := heldWait(t)
		var log strings.Builder
		h.cfg.Log = &log
		k1 := h.f.ops
		sleeps, published9 := 0, false
		h.clock.onSleep = func(time.Duration) {
			sleeps++
			switch {
			case sleeps == 1:
				withholdAbovePending(t, h)
				s := h.spec("role:ops", "role:q")
				s.bulkRoles = 17
				h.publishDir(s)
				h.f.ops = seedKey(t, 22)
				h.publishKRL(5, 8)
				h.resetSpool()
				h.write()
			case !published9 && strings.Contains(log.String(), "a newer state arrived during the wait"):
				published9 = true
				h.f.ops = k1
				h.publishKRL(5, 8, 9)
				h.resetSpool()
				h.write()
			}
		}
		_, err := h.apply()
		if !published9 {
			t.Fatalf("the KRL-alone state never superseded the pending target (%d sleeps): %v\n%s", sleeps, err, log.String())
		}
		if !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("apply: %v, want generation_too_large\n%s", err, log.String())
		}
		if a, aerr := h.accepted(); aerr != nil || a.BundleVersion != 1 || a.DirectoryVersion != 1+spool.MaxVersionsPerKind {
			t.Fatalf("accepted/ %+v (%v), want bundle 1 and directory %d", a, aerr, 1+spool.MaxVersionsPerKind)
		}
		if !h.krlRevokes(h.l.Current(), 8) || h.krlRevokes(h.l.Current(), 9) {
			t.Fatalf("current revokes 8 %t, 9 %t; want KRL 8, not KRL 9\n%s", h.krlRevokes(h.l.Current(), 8), h.krlRevokes(h.l.Current(), 9), log.String())
		}
		if !strings.Contains(log.String(), "krl_signer_retired") {
			t.Fatalf("the wait did not log krl_signer_retired:\n%s", log.String())
		}
	})

	// --- what an earlier poll of the same wait verified (PR #80 review) ---
	t.Run("retired_key_krl_after_a_same_bytes_poll_is_refused", func(t *testing.T) {
		t.Parallel()
		// Poll 1 verifies bundle 2, which only rotates the ops key, so its
		// generation is the pending target's bytes and it supersedes
		// nothing. Poll 2 no longer offers bundle 2 and offers KRL 6, which
		// K1 signed: the wait still knows bundle 2.
		w := newPollWait(t)
		h := w.h
		before := mustAcceptedNow(t, h)
		log, err := runPolls(t, h,
			func() { w.offer(true) },
			func() { w.offer(false); h.publishKRL(5, 6) })
		mustWaitOutcome(t, h, err, log, before.KRLVersion, waitWant{bundle: 1, dir: 2, revoked: []uint64{5}, kept: []uint64{6}, retired: true})
	})
	t.Run("retired_key_krl_after_a_krl_alone_poll_with_nothing_newer_is_refused", func(t *testing.T) {
		t.Parallel()
		// Poll 1 verifies bundle 2 in full, its directory 3 is refused, and
		// its KRL-alone pass finds no newer KRL, so it supersedes nothing.
		w := newPollWait(t)
		h := w.h
		before := mustAcceptedNow(t, h)
		log, err := runPolls(t, h,
			func() {
				w.offer(true)
				s := h.spec("role:ops", "role:q")
				s.signer = seedKey(t, 31)
				h.publishDir(s)
			},
			func() { w.offer(false); w.dropAbove(2); h.publishKRL(5, 6) })
		// A KRL-alone pass with nothing newer logs nothing; directory 2
		// staying in force shows that directory 3 was refused.
		mustWaitOutcome(t, h, err, log, before.KRLVersion, waitWant{bundle: 1, dir: 2, revoked: []uint64{5}, kept: []uint64{6}, retired: true})
	})
	t.Run("retired_key_krl_after_a_refused_poll_is_refused", func(t *testing.T) {
		t.Parallel()
		// Poll 1 verifies bundle 2 in full and refuses KRL 6, which K1
		// signed (krl_signer_retired on the KRL step). Poll 2 no longer
		// offers bundle 2, and KRL 6 is still the newest.
		w := newPollWait(t)
		h := w.h
		before := mustAcceptedNow(t, h)
		log, err := runPolls(t, h,
			func() { w.offer(true); h.publishKRL(5, 6) },
			func() { w.offer(false) })
		mustWaitOutcome(t, h, err, log, before.KRLVersion, waitWant{bundle: 1, dir: 2, revoked: []uint64{5}, kept: []uint64{6}, retired: true})
		if n := strings.Count(log, "krl_signer_retired"); n < 3 {
			t.Fatalf("krl_signer_retired logged %d times, want every poll:\n%s", n, log)
		}
	})
	t.Run("retired_key_krl_after_a_poll_from_the_record_is_refused", func(t *testing.T) {
		t.Parallel()
		// recordBelowWait's record branch: bundle 4 (K2), above the
		// record's bundle 3 (K1), is offered only at poll 1, which reads
		// from the record and supersedes nothing. Poll 2 no longer offers
		// it and offers KRL 8, which K1 signed.
		h := recordBelowWait(t, nil, seedKey(t, 22))
		d4, p3 := h.state.Bundles[4], h.state.Policies[3]
		delete(h.state.Bundles, 4)
		delete(h.state.Policies, 3)
		before := mustAcceptedNow(t, h)
		log, err := runPolls(t, h,
			func() { h.state.Bundles[4], h.state.Policies[3] = d4, p3 },
			func() { delete(h.state.Bundles, 4); delete(h.state.Policies, 3); h.publishKRL(5, 8) })
		mustWaitOutcome(t, h, err, log, before.KRLVersion, waitWant{bundle: 1, dir: 2, revoked: []uint64{5}, kept: []uint64{8}, record: 3, retired: true})
	})
	t.Run("krl_alone_supersede_keeps_what_an_earlier_poll_verified", func(t *testing.T) {
		t.Parallel()
		// Poll 1 learns bundle 2 (K2) as in the same-bytes case. Poll 2
		// no longer offers it; its directory 3 is above the caps, and KRL
		// 8 is signed by K2. The KRL lands alone under bundle 2, the
		// successor an earlier poll verified, and supersedes the pending
		// target. A later poll, verified against that KRL-alone state,
		// still knows bundle 2 and refuses KRL 9, which K1 signed.
		w := newPollWait(t)
		h := w.h
		var log strings.Builder
		h.cfg.Log = &log
		sleeps, published9 := 0, false
		h.clock.onSleep = func(time.Duration) {
			sleeps++
			switch {
			case sleeps == 1:
				w.offer(true)
			case sleeps == 2:
				w.offer(false)
				s := h.spec("role:ops", "role:q")
				s.bulkRoles = 17
				h.publishDir(s)
				h.f.ops = w.k2
				h.publishKRL(5, 8)
			case !published9 && strings.Contains(log.String(), "a newer state arrived during the wait"):
				published9 = true
				h.f.ops = w.k1
				h.publishKRL(5, 8, 9)
			default:
				return
			}
			h.resetSpool()
			h.write()
		}
		_, err := h.apply()
		if !published9 {
			t.Fatalf("KRL 8 never superseded the pending target (%d sleeps): %v\n%s", sleeps, err, log.String())
		}
		if !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("apply: %v, want generation_too_large\n%s", err, log.String())
		}
		if a, aerr := h.accepted(); aerr != nil || a.BundleVersion != 1 || a.DirectoryVersion != 2 {
			t.Fatalf("accepted/ %+v (%v), want bundle 1 and directory 2", a, aerr)
		}
		if !h.krlRevokes(h.l.Current(), 8) || h.krlRevokes(h.l.Current(), 9) {
			t.Fatalf("current revokes 8 %t, 9 %t; want KRL 8, not KRL 9\n%s", h.krlRevokes(h.l.Current(), 8), h.krlRevokes(h.l.Current(), 9), log.String())
		}
		if !strings.Contains(log.String(), "krl_signer_retired") {
			t.Fatalf("the wait did not log krl_signer_retired:\n%s", log.String())
		}
		// Poll 2's content refusal (directory 3 above the caps) records
		// nothing: only forward's own pass, before the wait, records
		// (recordUnapplied), as host-setup.md says.
		if recordExists(t, h) {
			t.Fatalf("a poll's content refusal wrote %s:\n%s", state.UnappliedFile, log.String())
		}
	})
	t.Run("fork_at_the_carried_version_does_not_replace_it", func(t *testing.T) {
		t.Parallel()
		// Poll 1 learns bundle 2 (K2). Poll 2 offers a root-signed fork of
		// version 2 naming K3 instead, a directory 3 that is refused, so
		// the KRL is taken alone under bundle 1, and KRL 7, which K3
		// signed. The fork is at the carried version, so it does not
		// replace bundle 2, and nothing authorises KRL 7.
		w := newPollWait(t)
		h := w.h
		k3 := seedKey(t, 23)
		_, fd2, fp2 := h.f.rotationOps(h.f.bundle, h.f.bundleDoc, h.f.policyDoc, h.f.policy, h.f.policy.Admins, "2026-10-05T00:00:00Z", k3)
		before := mustAcceptedNow(t, h)
		log, err := runPolls(t, h,
			func() { w.offer(true) },
			func() {
				h.state.Bundles[2], h.state.Policies[2] = fd2, fp2
				s := h.spec("role:ops", "role:q")
				s.signer = seedKey(t, 31)
				h.publishDir(s)
				h.f.ops = k3
				h.publishKRL(5, 7)
			})
		mustWaitOutcome(t, h, err, log, before.KRLVersion, waitWant{bundle: 1, dir: 2, revoked: []uint64{5}, kept: []uint64{7}})
		if !strings.Contains(log, "directory_not_verified") || !strings.Contains(log, "krl_not_verified") {
			t.Fatalf("poll 2 did not refuse directory 3 and KRL 7:\n%s", log)
		}
	})

	// --- the boundary ---
	t.Run("retired_key_krl_after_the_bundle_is_withheld_lands_as_on_main", func(t *testing.T) {
		t.Parallel()
		// The withholding-server residual's boundary: once the spool no
		// longer offers bundle 2, the host no longer knows it, and the KRL
		// the retired key signed is taken as on main.
		x := opsRotated(t)
		h := x.h
		h.publishDir(h.spec("role:ops", "role:q"))
		h.publishKRL(5, 6)
		if _, err := h.apply(); !errors.Is(err, state.ErrKRLSignerRetired) || recordExists(t, h) {
			t.Fatalf("apply 1: %v, want krl_signer_retired and no record", err)
		}
		delete(h.state.Bundles, 2)
		delete(h.state.Policies, 2)
		delete(h.state.Directories, 2)
		h.resetSpool()
		h.write()
		if _, err := h.apply(); err != nil {
			t.Fatalf("apply 2 without bundle 2: %v, want nil", err)
		}
		if a, err := h.accepted(); err != nil || a.BundleVersion != 1 || a.KRLVersion != h.f.krlVersion || !h.krlRevokes(h.l.Current(), 5) || !h.krlRevokes(h.l.Current(), 6) {
			t.Fatalf("apply 2: accepted %+v (%v), want bundle 1 with KRL 6", a, err)
		}
	})

	// --- the narrow fallback ---
	t.Run("krl_other_error_under_changed_bundle_keeps_its_error", func(t *testing.T) {
		t.Parallel()
		x := opsRotated(t)
		h := x.h
		h.f.ops = x.k2
		v, files := h.f.krl([]uint64{5, 6}, nil, "fedcba9876543210fedcba9876543210")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		_, err := h.apply()
		if !errors.Is(err, state.ErrKRL) || !errors.Is(err, krl.ErrInstallation) || !strings.Contains(err.Error(), "the manifest is for another installation") || errors.Is(err, krl.ErrSigner) || errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("a KRL for another installation: %v, want main's krl_not_verified naming the installation", err)
		}
	})
	t.Run("krl_in_force_key_for_another_installation_keeps_the_first_error", func(t *testing.T) {
		t.Parallel()
		// K1 signed it for another installation: F fails for the
		// installation, and the error stays the one under bundle 2.
		x := opsRotated(t)
		h := x.h
		v, files := h.f.krl([]uint64{5, 6}, nil, "fedcba9876543210fedcba9876543210")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		gen, gens := h.current(), h.genCount()
		before, err := h.accepted()
		if err != nil {
			t.Fatal(err)
		}
		_, err = h.apply()
		if !errors.Is(err, state.ErrKRL) || !errors.Is(err, krl.ErrSigner) || errors.Is(err, krl.ErrInstallation) || errors.Is(err, state.ErrKRLSignerRetired) {
			t.Fatalf("a K1 KRL for another installation: %v, want krl_not_verified for its signer under bundle 2", err)
		}
		mustUnchanged(t, h, gen, gens, before)
	})
}

// heldShape is TestApply/catch_up_across_policy_rotation's window (03-08k)
// on a host with KRL 5 (version v5, signed by k1) in force: bundle 2, bundle
// 3 rotating the admins to bob, directories 2-65 signed by the original
// admin and two more by bob widening deploy to role:q. The first capture
// holds at bundle 2 below bundle 3. Without inForceRotated, bundle 2 keeps
// the policy and k1, and bundle 3 replaces k1 with k2 (P's key k1, which N
// dropped). With inForceRotated, bundle 2 replaces k1 with k2 under the same
// admins, and bundle 3 keeps k2 (P differs from F).
func heldShape(t *testing.T, inForceRotated bool) rotated {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	withOutbox(t, h)
	h.installed("role:ops")
	h.publishKRL(5)
	h.mustApply()
	x := rotated{h: h, k1: f.ops, k2: seedKey(t, 22), v5: f.krlVersion}
	bob := []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(seedKey(t, 12).PublicKey())}}
	var d3, p3 spool.Doc
	if inForceRotated {
		x.b2, x.d2, x.p2 = f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z", x.k2)
		pol2, err := trust.ParsePolicy(x.p2.Body)
		if err != nil {
			t.Fatal(err)
		}
		_, d3, p3 = f.rotation(x.b2, x.d2.Body, x.p2.Body, pol2, bob, "2026-10-03T00:00:00Z")
		h.state.Policies[2], h.state.Policies[3] = x.p2, p3
	} else {
		x.b2, x.d2 = f.successor(f.bundle, f.bundleDoc, "2026-10-02T00:00:00Z")
		_, d3, p3 = f.rotationOps(x.b2, x.d2.Body, f.policyDoc, f.policy, bob, "2026-10-03T00:00:00Z", x.k2)
		h.state.Policies[2] = p3
	}
	h.state.Bundles[2], h.state.Bundles[3] = x.d2, d3
	for range spool.MaxVersionsPerKind {
		h.publishDir(h.spec("role:ops"))
	}
	for range 2 {
		s := h.spec("role:ops", "role:q")
		s.signer = seedKey(t, 12)
		h.publishDir(s)
	}
	return x
}

// mustKRLBytes checks that accepted/'s KRL, manifest and signature are the
// bytes read before the apply, with KRL version v5, and that current
// revokes serial 5 and neither 6 nor 7.
func mustKRLBytes(t *testing.T, h *testHost, before *state.Stored, v5 uint64) {
	t.Helper()
	a, err := h.accepted()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.KRL, before.KRL) || !bytes.Equal(a.KRLManifest, before.KRLManifest) || !bytes.Equal(a.KRLSig, before.KRLSig) || a.KRLVersion != v5 {
		t.Fatalf("accepted/'s KRL changed: version %d, want %d with the same bytes", a.KRLVersion, v5)
	}
	if !h.krlRevokes(h.l.Current(), 5) || h.krlRevokes(h.l.Current(), 6) || h.krlRevokes(h.l.Current(), 7) {
		t.Fatalf("the KRL in force changed: revokes 5 %t, 6 %t, 7 %t", h.krlRevokes(h.l.Current(), 5), h.krlRevokes(h.l.Current(), 6), h.krlRevokes(h.l.Current(), 7))
	}
}

// waitCase is one wait case of the truth "a poll decides a KRL as forward
// does" (03-08k). build brings a host to just before its widening apply,
// publish publishes the case's KRL, and during is the rest of the wait's
// first-sleep hook, which then empties and rewrites the spool. In subtest
// poll the KRL is published at the first sleep, so only a poll sees it; in
// subtest forward it is published before the widening apply, so forward
// decides it, and it stays in the spool through the wait. Both subtests
// end under one assertion, mustWaitOutcome.
type waitCase struct {
	build   func(t *testing.T) *testHost
	publish func(h *testHost)
	during  func(t *testing.T, h *testHost)
	want    waitWant
}

// waitWant is a wait case's expected end: accepted/'s bundle and directory
// versions, whether the case's KRL is in force (otherwise the KRL in force
// before the apply stays), the serials current revokes and those it does
// not, the record's bundle part (0: no record), and whether
// krl_signer_retired is named in the apply's error or the wait's log.
type waitWant struct {
	bundle, dir    uint64
	lands, retired bool
	revoked, kept  []uint64
	record         uint64
}

// runWait runs c's shape once per mode, "poll" and "forward".
func runWait(t *testing.T, c waitCase, modes ...string) {
	t.Helper()
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := c.build(t)
			before, err := h.accepted()
			if err != nil {
				t.Fatal(err)
			}
			var log strings.Builder
			h.cfg.Log = &log
			if mode == "forward" {
				c.publish(h)
			}
			sleeps := 0
			h.clock.onSleep = func(time.Duration) {
				if sleeps++; sleeps != 1 {
					return
				}
				if mode == "poll" {
					c.publish(h)
				}
				if c.during != nil {
					c.during(t, h)
				}
				h.resetSpool()
				h.write()
			}
			r, err := h.apply()
			if sleeps == 0 {
				t.Fatalf("the widening apply did not wait: %v (report %+v)", err, r)
			}
			mustWaitOutcome(t, h, err, log.String(), before.KRLVersion, c.want)
		})
	}
}

// mustWaitOutcome is the one assertion of both subtests of a wait case.
func mustWaitOutcome(t *testing.T, h *testHost, err error, log string, inForce uint64, w waitWant) {
	t.Helper()
	named := err != nil && strings.Contains(err.Error(), "krl_signer_retired") || strings.Contains(log, "krl_signer_retired")
	if named != w.retired {
		t.Fatalf("krl_signer_retired named %t, want %t: apply %v\n%s", named, w.retired, err, log)
	}
	if err != nil && (!w.retired || !errors.Is(err, state.ErrKRLSignerRetired)) {
		t.Fatalf("apply: %v, want nil or krl_signer_retired\n%s", err, log)
	}
	a, aerr := h.accepted()
	if aerr != nil {
		t.Fatal(aerr)
	}
	krlVersion := inForce
	if w.lands {
		krlVersion = h.f.krlVersion
	}
	if a.BundleVersion != w.bundle || a.DirectoryVersion != w.dir || a.KRLVersion != krlVersion {
		t.Fatalf("accepted/ bundle %d, directory %d, KRL %d; want %d, %d, %d\n%s", a.BundleVersion, a.DirectoryVersion, a.KRLVersion, w.bundle, w.dir, krlVersion, log)
	}
	for _, s := range w.revoked {
		if !h.krlRevokes(h.l.Current(), s) {
			t.Fatalf("current does not revoke %d\n%s", s, log)
		}
	}
	for _, s := range w.kept {
		if h.krlRevokes(h.l.Current(), s) {
			t.Fatalf("current revokes %d\n%s", s, log)
		}
	}
	if w.record != 0 {
		mustRecord(t, h, w.record, 0)
	} else if recordExists(t, h) {
		t.Fatal("an unapplied record exists")
	}
}

// recordedRotation is opsRotated with the spool in the state directory and
// a directory 2 above the caps: apply 1 is refused (generation_too_large)
// with no newer KRL and records {Bundle: 2, Directory: 2} (03-08k).
func recordedRotation(t *testing.T) rotated {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	spoolInState(t, h)
	h.installed("role:ops")
	h.publishKRL(5)
	h.mustApply()
	x := rotated{h: h, k1: f.ops, k2: seedKey(t, 22), v5: f.krlVersion}
	x.b2, x.d2, x.p2 = f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z", x.k2)
	h.state.Bundles[2], h.state.Policies[2] = x.d2, x.p2
	s := h.spec("role:ops")
	s.bulkRoles = 17
	h.publishDir(s)
	if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) {
		t.Fatalf("apply 1: %v, want generation_too_large", err)
	}
	mustRecord(t, h, 2, 2)
	return x
}

// heldWait is the window of TestApply/catch_up_across_policy_rotation's
// newOps=true row with no record, before a widening apply that waits
// (03-08k). KRL 5, signed by the fixture's ops key K1, is applied first:
// the swap the widening apply waits after. Directories 2-68, signed by the
// original admin, widen deploy to role:q; bundle 2 rotates the admins to
// bob and the ops key to K2; directories 69 and 70 are signed by bob. The
// capture is held at the bundle in force (directory 65 under bundle 1) and
// widens, so the apply waits; nothing is refused, so nothing is recorded.
func heldWait(t *testing.T) *testHost {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	withOutbox(t, h)
	h.installed("role:ops")
	h.clock.advance(time.Hour)
	h.publishKRL(5)
	h.mustApply()
	for range spool.MaxVersionsPerKind + 3 {
		h.publishDir(h.spec("role:ops", "role:q"))
	}
	bob := seedKey(t, 12)
	_, d2, p2 := f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, "2026-10-02T00:00:00Z", seedKey(t, 22))
	h.state.Bundles[2], h.state.Policies[2] = d2, p2
	for range 2 {
		s := h.spec("role:ops", "role:q")
		s.signer = bob
		h.publishDir(s)
	}
	return h
}

// withholdAbovePending removes bundle 2 and every directory above heldWait's
// pending target (directory 65) from the offered state, so a poll knows
// bundle 2 only from the pending capture.
func withholdAbovePending(_ *testing.T, h *testHost) {
	delete(h.state.Bundles, 2)
	delete(h.state.Policies, 2)
	for v := range h.state.Directories {
		if v > 1+spool.MaxVersionsPerKind {
			delete(h.state.Directories, v)
		}
	}
	h.dirs = h.dirs[:1+spool.MaxVersionsPerKind]
}

// pollWait is the wait of the PR #80 review's cases: KRL 5, signed by K1,
// is applied first, then directory 2 widens deploy to role:q, so the next
// apply waits with bundle 1 in force and records nothing. Bundle 2 (d2,
// p2) is a root-signed successor of bundle 1 under the same admins that
// only replaces the ops key with K2, so directory 2 verifies under it and
// a capture with it renders the pending target's bytes. It is not offered
// until a case's poll offers it.
type pollWait struct {
	h      *testHost
	d2, p2 spool.Doc
	k1, k2 ssh.Signer
}

func newPollWait(t *testing.T) pollWait {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	withOutbox(t, h)
	h.installed("role:ops")
	h.clock.advance(time.Hour)
	h.publishKRL(5)
	h.mustApply()
	h.publishDir(h.spec("role:ops", "role:q"))
	w := pollWait{h: h, k1: f.ops, k2: seedKey(t, 22)}
	_, w.d2, w.p2 = f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z", w.k2)
	return w
}

// offer offers bundle 2 and its policy, or withdraws them.
func (w pollWait) offer(on bool) {
	if on {
		w.h.state.Bundles[2], w.h.state.Policies[2] = w.d2, w.p2
		return
	}
	delete(w.h.state.Bundles, 2)
	delete(w.h.state.Policies, 2)
}

// dropAbove withdraws every directory above version v.
func (w pollWait) dropAbove(v uint64) {
	for d := range w.h.state.Directories {
		if d > v {
			delete(w.h.state.Directories, d)
		}
	}
	w.h.dirs = w.h.dirs[:v]
}

// mustAcceptedNow is accepted/ as it is before the widening apply.
func mustAcceptedNow(t *testing.T, h *testHost) *state.Stored {
	t.Helper()
	a, err := h.accepted()
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// runPolls runs the widening apply with steps[i] at the wait's sleep i+1,
// each followed by a rewrite of the spool, so that poll i+1 sees what step
// i offers, and returns the apply's log and error. It fails when the apply
// slept fewer times than there are steps, and requires a later sleep after
// the last step, so that a poll sees that step's spool.
func runPolls(t *testing.T, h *testHost, steps ...func()) (string, error) {
	t.Helper()
	var log strings.Builder
	h.cfg.Log = &log
	sleeps := 0
	h.clock.onSleep = func(time.Duration) {
		if sleeps++; sleeps > len(steps) {
			return
		}
		steps[sleeps-1]()
		h.resetSpool()
		h.write()
	}
	_, err := h.apply()
	if sleeps <= len(steps) {
		t.Fatalf("the widening apply slept %d times, want more than %d: %v\n%s", sleeps, len(steps), err, log.String())
	}
	return log.String(), err
}
