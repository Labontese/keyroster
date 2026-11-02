//go:build linux

package apply

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
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
		t.Run("poll", func(t *testing.T) {
			t.Parallel()
			// The record's bundle 3 names K2. A poll reads from the record,
			// and its capture brings nothing beyond it: its KRL step verifies
			// KRL 8 under bundle 3, and the KRL-alone pass, which fails under
			// bundle 1, takes it under the capture's fully verified bundle 3.
			k2 := seedKey(t, 22)
			h := recordBelowWait(t, k2, nil)
			var log strings.Builder
			h.cfg.Log = &log
			sleeps := 0
			h.clock.onSleep = func(time.Duration) {
				if sleeps++; sleeps != 1 {
					return
				}
				h.f.ops = k2
				h.publishKRL(5, 8)
				h.resetSpool()
				h.write()
			}
			r, err := h.apply()
			if sleeps == 0 {
				t.Fatal("apply 2 did not wait")
			}
			if err != nil {
				t.Fatalf("apply 2: %v (report %+v)\n%s", err, r, log.String())
			}
			mustAcceptedBundle1(t, h, 2)
			if !h.krlRevokes(h.l.Current(), 5) || !h.krlRevokes(h.l.Current(), 8) {
				t.Fatalf("KRL 8 did not land during the wait: revokes 5 %t, 8 %t\n%s", h.krlRevokes(h.l.Current(), 5), h.krlRevokes(h.l.Current(), 8), log.String())
			}
			if a, err := h.accepted(); err != nil || a.KRLVersion != h.f.krlVersion {
				t.Fatalf("accepted/ KRL version %+v (%v), want %d", a, err, h.f.krlVersion)
			}
			if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops", "role:q"}) {
				t.Fatalf("principals %v, want the widened [role:ops role:q]", got)
			}
			mustRecord(t, h, 3, 0)
		})
	})
}
