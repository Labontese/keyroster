//go:build linux

package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

// publishRun publishes the directory versions after the newest one up to
// last, each carrying role:ops and role:old; the versions in over are made
// above the generation caps (bulkRoles 17), as a window's newest version
// the host cannot apply.
func publishRun(h *testHost, last uint64, over ...uint64) {
	h.t.Helper()
	for v := uint64(len(h.dirs)) + 1; v <= last; v++ {
		s := h.spec("role:ops", "role:old")
		if slices.Contains(over, v) {
			s.bulkRoles = 17
		}
		h.publishDir(s)
	}
}

// refusedWindow is the PR #76 review F8 shape: directory 1 grants role:ops
// and role:old, directories 2-64 the same, 65 the same above the caps (the
// newest of the window an apply reads past directory 1), and, with fixed,
// 66 only role:ops. KRL 6 is published.
func refusedWindow(t *testing.T, fixed bool) *testHost {
	t.Helper()
	h := newTestHost(t, newFixture(t))
	spoolInState(t, h)
	h.installed("role:ops", "role:old")
	publishRun(h, 65, 65)
	if fixed {
		h.publishDir(h.spec("role:ops"))
	}
	h.publishKRL(6)
	return h
}

// recordFile is the unapplied record's path.
func recordFile(h *testHost) string { return h.l.State(state.UnappliedFile) }

func recordExists(t *testing.T, h *testHost) bool {
	t.Helper()
	_, err := os.Lstat(recordFile(h))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// mustRefusedKRLAlone checks an apply whose window-newest directory was
// refused for its content: it reports want, current revokes serial, the
// principals and accepted/'s directory stay at directory dir.
func mustRefusedKRLAlone(t *testing.T, h *testHost, r *Report, err error, want error, serial, dir uint64, principals ...string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("apply: %v, want %v (report %+v)", err, want, r)
	}
	if !h.krlRevokes(h.l.Current(), serial) {
		t.Fatalf("the KRL was not applied alone: current does not revoke %d", serial)
	}
	if got := h.principals("deploy"); !slices.Equal(got, principals) {
		t.Fatalf("principals %v, want %v", got, principals)
	}
	if a, aerr := h.accepted(); aerr != nil || a.DirectoryVersion != dir {
		t.Fatalf("accepted directory %+v (%v), want version %d", a, aerr, dir)
	}
}

// recordedWindow is refusedWindow's apply 1: directory 65 refused for its
// size and recorded, KRL 6 applied alone.
func recordedWindow(t *testing.T, fixed bool) *testHost {
	t.Helper()
	h := refusedWindow(t, fixed)
	r, err := h.apply()
	mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 6, 1, "role:old", "role:ops")
	mustRecord(t, h, 0, 65)
	return h
}

// bundleRecorded is the bundle case's apply 1: bundle 2, a root-signed
// successor, adds a next user CA whose line the host's ssh-keygen refuses,
// and the apply records {Bundle: 2}.
func bundleRecorded(t *testing.T) *testHost {
	t.Helper()
	h := newTestHost(t, newFixture(t))
	spoolInState(t, h)
	h.installed("role:ops")
	next := seedKey(t, 21)
	_, b2 := h.f.successorWithNext(h.f.bundle, h.f.bundleDoc, next)
	h.state.Bundles[2] = b2
	line := trust.FormatKey(next.PublicKey())
	h.run.rejectCA = func(l string) bool { return l == line }
	r, err := h.apply()
	if !errors.Is(err, ErrCALineRejected) {
		t.Fatalf("bundle 2 with a refused CA line: %v, want ca_line_rejected", err)
	}
	mustRecord(t, h, 2, 0)
	if r.Unapplied == nil || *r.Unapplied != (Unapplied{Bundle: 2}) {
		t.Fatalf("apply 1: Unapplied %+v, want {Bundle: 2}", r.Unapplied)
	}
	return h
}

// readRecord is the versions of the record's parts (0: no such part) and
// whether the record exists.
func readRecord(t *testing.T, h *testHost) (bundle, dir uint64, ok bool) {
	t.Helper()
	b, err := os.ReadFile(recordFile(h))
	if errors.Is(err, os.ErrNotExist) {
		return 0, 0, false
	}
	if err != nil {
		t.Fatal(err)
	}
	u, err := state.ParseUnapplied(b)
	if err != nil {
		t.Fatalf("%s: %v", state.UnappliedFile, err)
	}
	if u.Bundle != nil {
		tb, err := trust.ParseBundle(u.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		bundle = tb.Version
	}
	if u.Directory != nil {
		d, err := directory.Parse(u.Directory)
		if err != nil {
			t.Fatal(err)
		}
		dir = d.Version
	}
	return bundle, dir, true
}

// mustRecord checks that the record exists with exactly these parts.
func mustRecord(t *testing.T, h *testHost, bundle, dir uint64) {
	t.Helper()
	b, d, ok := readRecord(t, h)
	if !ok || b != bundle || d != dir {
		t.Fatalf("record: exists %v, bundle %d, directory %d; want bundle %d, directory %d", ok, b, d, bundle, dir)
	}
}

// successorNextUnder is successorWithNext under the policy polDoc (kept
// from prev) and issued at issuedAt.
func (f *fixture) successorNextUnder(prev *trust.Bundle, prevDoc, polDoc []byte, issuedAt string, key ssh.Signer) (*trust.Bundle, spool.Doc) {
	f.t.Helper()
	b, err := trust.BuildSuccessor(prev, prevDoc, polDoc, prev.Root.Keys, 1, polDoc, issuedAt, testInstallation)
	if err != nil {
		f.t.Fatal(err)
	}
	b.CAs = slices.Insert(b.CAs, 1, trust.CAEntry{Role: trust.RoleUser, Key: trust.FormatKey(key.PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "next", Generation: 2})
	doc := mustCanonical(f.t, b)
	if _, err := trust.ParseBundle(doc); err != nil {
		f.t.Fatalf("successor bundle with a next CA: %v", err)
	}
	return b, spool.Doc{Body: doc, Sigs: f.rootSign(trust.NamespaceBundle, doc)}
}

// successorWithout is f.successor that also drops every next CA entry.
func (f *fixture) successorWithout(prev *trust.Bundle, prevDoc []byte, issuedAt string) (*trust.Bundle, spool.Doc) {
	f.t.Helper()
	b, err := trust.BuildSuccessor(prev, prevDoc, f.policyDoc, prev.Root.Keys, 1, f.policyDoc, issuedAt, testInstallation)
	if err != nil {
		f.t.Fatal(err)
	}
	b.CAs = slices.DeleteFunc(b.CAs, func(c trust.CAEntry) bool { return c.State == "next" })
	doc := mustCanonical(f.t, b)
	if _, err := trust.ParseBundle(doc); err != nil {
		f.t.Fatalf("successor bundle without the next CA: %v", err)
	}
	return b, spool.Doc{Body: doc, Sigs: f.rootSign(trust.NamespaceBundle, doc)}
}

// TestSpoolWindow (PR #76 review F8 (03-08j)): a host whose read window
// ends at a verified version it cannot apply records that version as
// unapplied, reads past it at the next apply and installs the next version
// it can, while the KRL applies alone meanwhile.
func TestSpoolWindow(t *testing.T) {
	t.Run("refused_window_newest_then_fix_applies", func(t *testing.T) {
		t.Parallel()
		h := refusedWindow(t, true)
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 6, 1, "role:old", "role:ops")
		if !r.SpoolMore {
			t.Errorf("apply 1: SpoolMore false, want true (directory 66 is past the window)")
		}
		if r.Unapplied == nil || *r.Unapplied != (Unapplied{Directory: 65}) {
			t.Errorf("apply 1: Unapplied %+v, want {Directory: 65}", r.Unapplied)
		}
		if !recordExists(t, h) {
			t.Errorf("apply 1 wrote no %s", state.UnappliedFile)
		}
		r, err = h.apply()
		if err != nil {
			t.Fatalf("apply 2: %v, want directory 66 installed (report %+v)", err, r)
		}
		if got := h.principals("deploy"); r.DirectoryVersion != 66 || !slices.Equal(got, []string{"role:ops"}) {
			t.Fatalf("apply 2: directory %d, principals %v, want 66 and [role:ops]", r.DirectoryVersion, got)
		}
		if r.BundleHeld || r.Unapplied != nil {
			t.Fatalf("apply 2: BundleHeld %v, Unapplied %+v, want false and nil", r.BundleHeld, r.Unapplied)
		}
		if recordExists(t, h) {
			t.Fatalf("the commit of directory 66 passed the record, but %s is still there", state.UnappliedFile)
		}
	})
	t.Run("window_control_within_reach", func(t *testing.T) {
		t.Parallel()
		// The review's control: refused at 64, inside the window, so the
		// first apply already reads the fixed 65.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops", "role:old")
		publishRun(h, 64, 64)
		h.publishDir(h.spec("role:ops"))
		h.publishKRL(6)
		r := h.mustApply()
		if got := h.principals("deploy"); r.DirectoryVersion != 65 || !slices.Equal(got, []string{"role:ops"}) {
			t.Fatalf("directory %d, principals %v, want 65 and [role:ops]", r.DirectoryVersion, got)
		}
		if recordExists(t, h) || r.Unapplied != nil {
			t.Fatalf("an apply that installed the fix wrote a record (%+v)", r.Unapplied)
		}
	})
	t.Run("refused_run_longer_than_a_window_reaches_fix", func(t *testing.T) {
		t.Parallel()
		// Two refused windows in a row: 65 and 129 are each a window's
		// newest version, 130 is fixed.
		h := newTestHost(t, newFixture(t))
		spoolInState(t, h)
		h.installed("role:ops", "role:old")
		publishRun(h, 129, 65, 129)
		h.publishDir(h.spec("role:ops"))
		h.publishKRL(6)
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 6, 1, "role:old", "role:ops")
		mustRecord(t, h, 0, 65)
		r, err = h.apply()
		mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 6, 1, "role:old", "role:ops")
		mustRecord(t, h, 0, 129)
		r, err = h.apply()
		if got := h.principals("deploy"); err != nil || r.DirectoryVersion != 130 || !slices.Equal(got, []string{"role:ops"}) {
			t.Fatalf("apply 3: %v, directory %d, principals %v; want 130 and [role:ops]", err, r.DirectoryVersion, got)
		}
		if _, _, ok := readRecord(t, h); ok {
			t.Fatalf("the record outlived the commit of directory 130")
		}
	})
	t.Run("unchanged_spool_still_refused", func(t *testing.T) {
		t.Parallel()
		// Nothing newer than the record: the apply renders the record
		// again and reports the refusal, never ok.
		h := recordedWindow(t, false)
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 6, 1, "role:old", "role:ops")
		if s := outboxStatus(t, h); s.LastApply == nil || s.LastApply.Result != heartbeat.ResultRefused {
			t.Fatalf("last_apply %+v, want result refused", s.LastApply)
		}
		mustRecord(t, h, 0, 65)
	})
	t.Run("bundle_ca_line_window_newest_then_fixed_bundle_applies", func(t *testing.T) {
		t.Parallel()
		// Bundles 2-64 are root-signed successors, 65 adds a next CA whose
		// line ssh-keygen refuses (the window's newest), and 66 drops that
		// entry again.
		h := newTestHost(t, newFixture(t))
		spoolInState(t, h)
		h.installed("role:ops")
		cur, curDoc := h.f.bundle, h.f.bundleDoc
		for v := uint64(2); v <= 64; v++ {
			var d spool.Doc
			cur, d = h.f.successor(cur, curDoc, fmt.Sprintf("2026-10-01T%02d:%02d:00Z", v/60, v%60))
			h.state.Bundles[v], curDoc = d, d.Body
		}
		next := seedKey(t, 21)
		b65, d65 := h.f.successorWithNext(cur, curDoc, next)
		h.state.Bundles[65] = d65
		_, d66 := h.f.successorWithout(b65, d65.Body, "2026-10-03T00:00:00Z")
		h.state.Bundles[66] = d66
		line := trust.FormatKey(next.PublicKey())
		h.run.rejectCA = func(l string) bool { return l == line }
		h.publishKRL(6)
		r, err := h.apply()
		if !errors.Is(err, ErrCALineRejected) {
			t.Fatalf("apply 1: %v, want ca_line_rejected", err)
		}
		mustKRLAlone(t, h, r, 6, 1, "ca_line_rejected")
		if r.Unapplied == nil || *r.Unapplied != (Unapplied{Bundle: 65}) {
			t.Fatalf("apply 1: Unapplied %+v, want {Bundle: 65}", r.Unapplied)
		}
		r, err = h.apply()
		if a, aerr := h.accepted(); err != nil || r.BundleVersion != 66 || aerr != nil || a.BundleVersion != 66 || strings.Contains(h.file(CAFile), line) {
			t.Fatalf("apply 2: %v, %+v; want bundle 66 in force without the refused line", err, r)
		}
	})
	t.Run("recorded_state_installed_when_the_host_accepts_it", func(t *testing.T) {
		t.Parallel()
		h := bundleRecorded(t)
		h.run.rejectCA = nil
		r, err := h.apply()
		if a, aerr := h.accepted(); err != nil || r.BundleVersion != 2 || aerr != nil || a.BundleVersion != 2 {
			t.Fatalf("apply 2 on the unchanged spool: %v, %+v; want bundle 2 installed", err, r)
		}
		if _, _, ok := readRecord(t, h); ok {
			t.Fatalf("the record outlived the commit of bundle 2")
		}
	})
	t.Run("krl_only_the_recorded_bundle_signs_waits", func(t *testing.T) {
		t.Parallel()
		// The recorded bundle replaces the ops key; a KRL only the new key
		// signs is verified against the bundle in force, and refused.
		f := newFixture(t)
		h := newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		newOps := seedKey(t, 22)
		_, b2, p2 := f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z", newOps)
		h.state.Bundles[2], h.state.Policies[2] = b2, p2
		s := h.spec("role:ops")
		s.bulkRoles = 17
		h.publishDir(s)
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("apply 1: %v, want generation_too_large", err)
		}
		mustRecord(t, h, 2, 2)
		f.ops = newOps
		h.publishKRL(6)
		gen, gens := h.current(), h.genCount()
		_, err := h.apply()
		if !errors.Is(err, ErrGenerationTooLarge) || !errors.Is(err, state.ErrKRL) {
			t.Fatalf("apply 2: %v, want generation_too_large and krl_not_verified", err)
		}
		if h.current() != gen || h.genCount() != gens || h.krlRevokes(h.l.Current(), 6) {
			t.Fatalf("something was installed: current %d (was %d), %d generations (was %d)", h.current(), gen, h.genCount(), gens)
		}
	})
	// policyRotated is the shape of TestApply/catch_up_across_policy_rotation
	// below a recorded bundle: bundle 2 rotates the policy (a new admin, and
	// with newOps a new ops key), bundle 3 adds a CA line ssh-keygen refuses
	// and is recorded, then directories 2-65 arrive under bundle 1's policy
	// (65 above the caps with over) and KRL 7.
	policyRotated := func(t *testing.T, newOps, over bool) *testHost {
		t.Helper()
		f := newFixture(t)
		h := newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		bob := seedKey(t, 12)
		var ops ssh.Signer
		if newOps {
			ops = seedKey(t, 13)
		}
		b2, d2, p2 := f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, "2026-10-02T00:00:00Z", ops)
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
		for v := uint64(2); v <= 65; v++ {
			s := h.spec("role:ops")
			if over && v == 65 {
				s.bulkRoles = 17
			}
			h.publishDir(s)
		}
		if newOps {
			f.ops = ops
		}
		h.publishKRL(7)
		return h
	}
	t.Run("policy_rotation_below_the_recorded_bundle", func(t *testing.T) {
		t.Parallel()
		for _, newOps := range []bool{false, true} {
			h := policyRotated(t, newOps, false)
			r, err := h.apply()
			if err != nil || r.DirectoryVersion != 65 || r.BundleVersion != 1 || !r.BundleHeld {
				t.Fatalf("newOps %t: apply 2: %v, %+v; want directory 65 under bundle 1, held", newOps, err, r)
			}
			if newOps && r.KRLVersion == h.f.krlVersion {
				t.Fatalf("newOps %t: the KRL the new ops key signed was taken under bundle 1", newOps)
			}
			if !newOps && !h.krlRevokes(h.l.Current(), 7) {
				t.Fatalf("newOps %t: KRL 7 was not applied", newOps)
			}
			mustRecord(t, h, 3, 0)
		}
	})
	t.Run("held_content_refusal_keeps_the_records_bundle", func(t *testing.T) {
		t.Parallel()
		h := policyRotated(t, false, true)
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 7, 1, "role:ops")
		mustRecord(t, h, 3, 65)
	})
	t.Run("fork_after_the_record_refused", func(t *testing.T) {
		t.Parallel()
		// A re-made, renderable 65' and a 66' on it: 66' does not chain to
		// the recorded 65, so nothing but the KRL is installed.
		h := recordedWindow(t, false)
		remade := h.f.directory(h.dirs[63].Body, h.spec("role:ops"))
		h.state.Directories[65] = remade
		h.state.Directories[66] = h.f.directory(remade.Body, h.spec("role:ops"))
		h.publishKRL(6, 7)
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, state.ErrDir, 7, 1, "role:old", "role:ops")
		if r.BundleHeld {
			t.Fatalf("BundleHeld set by a directory-only record")
		}
		mustRecord(t, h, 0, 65)
		b, err := os.ReadFile(recordFile(h))
		if err != nil {
			t.Fatal(err)
		}
		if u, err := state.ParseUnapplied(b); err != nil || string(u.Directory) != string(h.dirs[64].Body) {
			t.Fatalf("the record no longer holds the original 65 (%v)", err)
		}
	})
	t.Run("bundle_fork_after_the_record_takes_the_krl_against_accepted", func(t *testing.T) {
		t.Parallel()
		// The record holds bundle 2, which would render now; a 3' built on
		// a re-made 2' does not chain to it, and the KRL is taken against
		// accepted/'s bundle 1.
		h := bundleRecorded(t)
		h.run.rejectCA = nil
		b2r, d2r := h.f.successor(h.f.bundle, h.f.bundleDoc, "2026-10-01T12:00:00Z")
		_, d3r := h.f.successor(b2r, d2r.Body, "2026-10-03T00:00:00Z")
		h.state.Bundles[3] = d3r
		h.publishKRL(6)
		r, err := h.apply()
		if !errors.Is(err, state.ErrBundle) {
			t.Fatalf("apply 2: %v, want bundle_not_verified", err)
		}
		mustKRLAlone(t, h, r, 6, 1, "bundle_not_verified")
		if a, aerr := h.accepted(); aerr != nil || a.BundleVersion != 1 {
			t.Fatalf("accepted bundle %+v (%v), want 1", a, aerr)
		}
		mustRecord(t, h, 2, 0)
	})
	t.Run("withheld_record_version_does_not_roll_back", func(t *testing.T) {
		t.Parallel()
		// The spool loses 65 and offers a 66 whose signatures do not
		// verify: 64 is never installed.
		h := recordedWindow(t, false)
		for _, n := range []string{"directory-65.json", "directory-65.json.sigs"} {
			if err := os.Remove(filepath.Join(h.spool, n)); err != nil {
				t.Fatal(err)
			}
		}
		delete(h.state.Directories, 65)
		s := h.spec("role:ops")
		s.signer = seedKey(t, 30)
		h.publishDir(s)
		h.publishKRL(6, 7)
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, state.ErrDir, 7, 1, "role:old", "role:ops")
		mustRecord(t, h, 0, 65)
	})
	t.Run("spool_copy_of_the_recorded_version_ignored", func(t *testing.T) {
		t.Parallel()
		// The spool's 65 is a re-made 65'; 66 chains to the recorded 65,
		// whose bytes stay the chain's base.
		h := recordedWindow(t, false)
		h.state.Directories[65] = h.f.directory(h.dirs[63].Body, h.spec("role:ops", "role:remade"))
		h.state.Directories[66] = h.f.directory(h.dirs[64].Body, h.spec("role:ops"))
		r, err := h.apply()
		if got := h.principals("deploy"); err != nil || r.DirectoryVersion != 66 || !slices.Equal(got, []string{"role:ops"}) {
			t.Fatalf("apply 2: %v, directory %d, principals %v; want 66 and [role:ops]", err, r.DirectoryVersion, got)
		}
	})
	t.Run("damaged_record_dropped", func(t *testing.T) {
		t.Parallel()
		h := recordedWindow(t, false)
		if err := os.WriteFile(recordFile(h), []byte(`{"bundle":`), 0o600); err != nil {
			t.Fatal(err)
		}
		var log strings.Builder
		h.cfg.Log = &log
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 6, 1, "role:old", "role:ops")
		if !strings.Contains(log.String(), "WARNING "+state.UnappliedFile+" dropped") {
			t.Fatalf("no warning names the damaged record:\n%s", log.String())
		}
		mustRecord(t, h, 0, 65)
	})
	t.Run("removed_record_reads_from_accepted", func(t *testing.T) {
		t.Parallel()
		h := recordedWindow(t, false)
		if err := os.Remove(recordFile(h)); err != nil {
			t.Fatal(err)
		}
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 6, 1, "role:old", "role:ops")
		mustRecord(t, h, 0, 65)
	})
	t.Run("removed_record_takes_the_remade_bundle_chain", func(t *testing.T) {
		t.Parallel()
		// signer-install.md's remedy: a re-made chain 2', 3' is refused
		// while the record holds bundle 2, and installed after root
		// removes the record.
		h := bundleRecorded(t)
		h.run.rejectCA = nil
		b2r, d2r := h.f.successor(h.f.bundle, h.f.bundleDoc, "2026-10-01T12:00:00Z")
		_, d3r := h.f.successor(b2r, d2r.Body, "2026-10-03T00:00:00Z")
		h.state.Bundles[2], h.state.Bundles[3] = d2r, d3r
		h.publishKRL(6)
		r, err := h.apply()
		if !errors.Is(err, state.ErrBundle) {
			t.Fatalf("apply 2: %v, want bundle_not_verified", err)
		}
		mustKRLAlone(t, h, r, 6, 1, "bundle_not_verified")
		if a, aerr := h.accepted(); aerr != nil || a.BundleVersion != 1 {
			t.Fatalf("accepted bundle %+v (%v), want 1", a, aerr)
		}
		if err := os.Remove(recordFile(h)); err != nil {
			t.Fatal(err)
		}
		r, err = h.apply()
		if a, aerr := h.accepted(); err != nil || r.BundleVersion != 3 || aerr != nil || a.BundleVersion != 3 {
			t.Fatalf("apply 3 after removing the record: %v, %+v; want bundle 3' installed", err, r)
		}
	})
	t.Run("fetcher_cursor_follows_the_record", func(t *testing.T) {
		t.Parallel()
		h := recordedWindow(t, true)
		if a := readAccepted(t, h); a.Bundle != 1 || a.Directory != 65 {
			t.Fatalf("accepted.json %+v, want bundle 1 and the recorded directory 65", a)
		}
		if a, err := AcceptedVersions(h.l); err != nil || a.Directory != 1 {
			t.Fatalf("AcceptedVersions %+v (%v), want directory 1", a, err)
		}
		h.mustApply()
		if a := readAccepted(t, h); a.Directory != 66 {
			t.Fatalf("accepted.json %+v after the fix, want directory 66", a)
		}
	})
	t.Run("reset_directory_drops_the_records_directory", func(t *testing.T) {
		t.Parallel()
		h := recordedWindow(t, true)
		// A reset that stops after its first steps (a spool that cannot
		// be opened) stands in for a crash there.
		if _, err := ResetDirectory(h.l, h.l.State("missing-spool")); err == nil {
			t.Fatalf("a reset with a missing spool succeeded")
		}
		if a, err := h.accepted(); err != nil || a.Directory != nil {
			t.Fatalf("accepted/ after the interrupted reset: %+v (%v), want no directory", a, err)
		}
		if _, _, ok := readRecord(t, h); ok {
			t.Fatalf("the interrupted reset left the record's directory as the chain base")
		}
		if _, err := ResetDirectory(h.l, h.cfg.Spool); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := readRecord(t, h); ok {
			t.Fatalf("the reset left the record")
		}
		if a := readAccepted(t, h); a.Directory != 0 {
			t.Fatalf("accepted.json %+v after the reset, want directory 0", a)
		}
	})
	t.Run("reset_directory_keeps_the_records_bundle", func(t *testing.T) {
		t.Parallel()
		h := bundleRecorded(t)
		if _, err := ResetDirectory(h.l, h.cfg.Spool); err != nil {
			t.Fatal(err)
		}
		mustRecord(t, h, 2, 0)
		if a := readAccepted(t, h); a.Bundle != 2 {
			t.Fatalf("accepted.json %+v after the reset, want the recorded bundle 2", a)
		}
	})
	t.Run("no_record_after_a_verify_refusal_or_a_dry_run", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		spoolInState(t, h)
		h.installed("role:ops")
		h.state.Bundles[3] = spool.Doc{Body: []byte(`{}`), Sigs: []byte("sigs")}
		h.publishKRL(7)
		if _, err := h.apply(); !errors.Is(err, state.ErrBundleChainGap) {
			t.Fatalf("a bundle chain gap: %v, want bundle_chain_gap", err)
		}
		if _, _, ok := readRecord(t, h); ok {
			t.Fatalf("a Verify refusal wrote a record")
		}
		d := refusedWindow(t, true)
		d.cfg.DryRun = true
		gen, gens := d.current(), d.genCount()
		if _, err := d.apply(); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("dry run: %v, want generation_too_large", err)
		}
		if _, _, ok := readRecord(t, d); ok || d.current() != gen || d.genCount() != gens {
			t.Fatalf("the dry run changed something: record %v, current %d (was %d), %d generations (was %d)", ok, d.current(), gen, d.genCount(), gens)
		}
		if a, err := d.accepted(); err != nil || a.DirectoryVersion != 1 {
			t.Fatalf("accepted/ after the dry run: %+v (%v)", a, err)
		}
	})
	t.Run("record_write_failure_keeps_the_krl", func(t *testing.T) {
		t.Parallel()
		// A non-empty directory at the record's path: the write fails, and
		// the KRL still lands alone.
		h := refusedWindow(t, true)
		if err := os.Mkdir(recordFile(h), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(recordFile(h), "x"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		var log strings.Builder
		h.cfg.Log = &log
		r, err := h.apply()
		mustRefusedKRLAlone(t, h, r, err, ErrGenerationTooLarge, 6, 1, "role:old", "role:ops")
		if !strings.Contains(log.String(), "WARNING writing "+recordFile(h)) {
			t.Fatalf("no warning names the record write:\n%s", log.String())
		}
	})
	t.Run("status_reports_unapplied", func(t *testing.T) {
		t.Parallel()
		h := refusedWindow(t, true)
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("apply 1: %v, want generation_too_large", err)
		}
		s := outboxStatus(t, h)
		if s.Unapplied == nil || *s.Unapplied != (heartbeat.Unapplied{Directory: 65}) || s.Directory.Version != 1 {
			t.Fatalf("status after apply 1: unapplied %+v, directory in force %d; want {directory: 65} and 1", s.Unapplied, s.Directory.Version)
		}
		h.mustApply()
		if s := outboxStatus(t, h); s.Unapplied != nil {
			t.Fatalf("status after the fix: unapplied %+v, want none", s.Unapplied)
		}
	})
}
