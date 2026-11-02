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
	"time"

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

// rotationDropping is the next bundle after prev, which is under the
// fixture's policy, rotating the policy to admin bob: it drops every next
// CA entry of prev and adds one for key (a line the host's ssh-keygen can
// be made to refuse). It returns the bundle and the rotated policy.
func (f *fixture) rotationDropping(prev *trust.Bundle, prevDoc []byte, issuedAt string, key ssh.Signer) (bundle, policy spool.Doc) {
	f.t.Helper()
	bob := seedKey(f.t, 12)
	_, _, p := f.rotationOps(prev, prevDoc, f.policyDoc, f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, issuedAt, nil)
	b, err := trust.BuildSuccessor(prev, prevDoc, f.policyDoc, prev.Root.Keys, 1, p.Body, issuedAt, testInstallation)
	if err != nil {
		f.t.Fatal(err)
	}
	b.CAs = slices.DeleteFunc(b.CAs, func(c trust.CAEntry) bool { return c.State == "next" })
	b.CAs = slices.Insert(b.CAs, 1, trust.CAEntry{Role: trust.RoleUser, Key: trust.FormatKey(key.PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "next", Generation: 2})
	doc := mustCanonical(f.t, b)
	if _, err := trust.ParseBundle(doc); err != nil {
		f.t.Fatalf("rotated bundle: %v", err)
	}
	return spool.Doc{Body: doc, Sigs: f.rootSign(trust.NamespaceBundle, doc)}, p
}

// mustHeldBelowRecord checks the end of a widening wait below a recorded
// bundle: accepted/ holds the original bundle 1 and directory dir, the
// record still holds recorded (its original bytes), the CA line removed is
// in no trust file, the widened principals are in force, no poll rendered
// the record (no ca_line_rejected in log), and with krl current revokes it.
func mustHeldBelowRecord(t *testing.T, h *testHost, recorded spool.Doc, dir uint64, removed string, krl uint64, log string) {
	t.Helper()
	a, err := h.accepted()
	if err != nil || a.BundleVersion != 1 || !slices.Equal(a.Bundle, h.f.bundleDoc) || a.DirectoryVersion != dir {
		t.Fatalf("accepted/ %+v (%v), want the original bundle 1 and directory %d", a, err, dir)
	}
	b, err := os.ReadFile(recordFile(h))
	if err != nil {
		t.Fatalf("the record is gone: %v", err)
	}
	if u, err := state.ParseUnapplied(b); err != nil || !slices.Equal(u.Bundle, recorded.Body) {
		t.Fatalf("the record no longer holds the recorded bundle's bytes (%v)", err)
	}
	if strings.Contains(h.file(CAFile), removed) {
		t.Fatalf("the CA line the recorded bundle removed is in force:\n%s", h.file(CAFile))
	}
	if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops", "role:q"}) {
		t.Fatalf("principals %v, want the widened [role:ops role:q]", got)
	}
	if n := strings.Count(log, "ca_line_rejected"); n != 0 {
		t.Fatalf("the wait rendered the recorded bundle %d times:\n%s", n, log)
	}
	if krl != 0 && !h.krlRevokes(h.l.Current(), krl) {
		t.Fatalf("the KRL published during the wait did not land: current does not revoke %d", krl)
	}
}

// TestSpoolWindowWideningWait (PR #78 review, 03-08j): a widening wait
// whose pending target is held at the bundle in force, below a recorded
// bundle, reads and chains its polls from the record, as forward does. An
// older bundle below the record never supersedes the target, a re-made
// chain or a spool copy at the record's version is refused, the record
// survives, and a KRL published during the wait still lands.
func TestSpoolWindowWideningWait(t *testing.T) {
	// recordAbove: bundle 2 keeps the policy and adds a next CA x, bundle
	// 3 rotates the policy, drops x and adds a CA line ssh-keygen refuses,
	// so apply 1 records {Bundle: 3} and takes KRL 7 alone. Directory 2,
	// signed under bundle 1's policy, widens deploy to role:q: apply 2
	// holds at bundle 1 and waits.
	recordAbove := func(t *testing.T) (h *testHost, b2 *trust.Bundle, d2, d3 spool.Doc, x string) {
		t.Helper()
		f := newFixture(t)
		h = newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		xKey := seedKey(t, 25)
		b2, d2 = f.successorNextUnder(f.bundle, f.bundleDoc, f.policyDoc, "2026-10-02T00:00:00Z", xKey)
		rejected := seedKey(t, 21)
		d3, p2 := f.rotationDropping(b2, d2.Body, "2026-10-03T00:00:00Z", rejected)
		h.state.Bundles[2], h.state.Bundles[3], h.state.Policies[2] = d2, d3, p2
		line := trust.FormatKey(rejected.PublicKey())
		h.run.rejectCA = func(l string) bool { return l == line }
		h.clock.advance(time.Hour)
		h.publishKRL(7)
		if _, err := h.apply(); !errors.Is(err, ErrCALineRejected) {
			t.Fatalf("apply 1: %v, want ca_line_rejected", err)
		}
		mustRecord(t, h, 3, 0)
		h.publishDir(h.spec("role:ops", "role:q"))
		return h, b2, d2, d3, trust.FormatKey(xKey.PublicKey())
	}
	for _, c := range []struct {
		name string
		// during changes the spool at the wait's first poll.
		during  func(t *testing.T, h *testHost, b2 *trust.Bundle, d2 spool.Doc)
		dir     uint64
		krl     uint64
		wantErr error
	}{
		{name: "nothing_new"},
		{name: "remade_chain", krl: 8, wantErr: state.ErrBundle, during: func(t *testing.T, h *testHost, _ *trust.Bundle, _ spool.Doc) {
			// A signer restore lost bundles 2 and 3 and re-made 2' and 3'
			// on bundle 1 (3' rotates to the same policy 2), and a 4'
			// under policy 2 without 3''s next CA. All of them render.
			b2r, d2r := h.f.successor(h.f.bundle, h.f.bundleDoc, "2026-10-04T00:00:00Z")
			d3r, p2 := h.f.rotationDropping(b2r, d2r.Body, "2026-10-04T01:00:00Z", seedKey(t, 26))
			b3r, err := trust.ParseBundle(d3r.Body)
			if err != nil {
				t.Fatal(err)
			}
			b4r, err := trust.BuildSuccessor(b3r, d3r.Body, p2.Body, b3r.Root.Keys, 1, p2.Body, "2026-10-04T02:00:00Z", testInstallation)
			if err != nil {
				t.Fatal(err)
			}
			b4r.CAs = slices.DeleteFunc(b4r.CAs, func(c trust.CAEntry) bool { return c.State == "next" })
			doc4 := mustCanonical(t, b4r)
			d4r := spool.Doc{Body: doc4, Sigs: h.f.rootSign(trust.NamespaceBundle, doc4)}
			h.state.Bundles[2], h.state.Bundles[3], h.state.Bundles[4] = d2r, d3r, d4r
		}},
		{name: "remade_chain_under_the_old_policy", krl: 8, wantErr: state.ErrPolicyMissing, during: func(_ *testing.T, h *testHost, _ *trust.Bundle, _ spool.Doc) {
			// As remade_chain with 2', 3' and 4' all under bundle 1's
			// policy, which a capture read from the record's floor (policy
			// 2) does not hold: 4' is refused before its chain check.
			b2r, d2r := h.f.successor(h.f.bundle, h.f.bundleDoc, "2026-10-04T00:00:00Z")
			b3r, d3r := h.f.successor(b2r, d2r.Body, "2026-10-04T01:00:00Z")
			_, d4r := h.f.successor(b3r, d3r.Body, "2026-10-04T02:00:00Z")
			h.state.Bundles[2], h.state.Bundles[3], h.state.Bundles[4] = d2r, d3r, d4r
		}},
		{name: "record_version_withheld", krl: 8, wantErr: state.ErrBundleOlder, during: func(t *testing.T, h *testHost, _ *trust.Bundle, _ spool.Doc) {
			for _, n := range []string{"bundle-3.json", "bundle-3.json.sigs"} {
				if err := os.Remove(filepath.Join(h.spool, n)); err != nil {
					t.Fatal(err)
				}
			}
			delete(h.state.Bundles, 3)
		}},
		{name: "fork_at_the_record_version", krl: 8, during: func(_ *testing.T, h *testHost, b2 *trust.Bundle, d2 spool.Doc) {
			// The spool's 3 becomes a renderable 3' on the original 2.
			_, d3r := h.f.successorWithout(b2, d2.Body, "2026-10-04T00:00:00Z")
			h.state.Bundles[3] = d3r
		}},
		{name: "newer_directory_under_the_policy_in_force", dir: 3, krl: 8, during: func(_ *testing.T, h *testHost, _ *trust.Bundle, _ spool.Doc) {
			// Bundle 2 carries the quorum of directory 3 too: the poll
			// holds at bundle 1 again, never at bundle 2.
			h.publishDir(h.spec("role:ops", "role:q"))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h, b2, d2, d3, x := recordAbove(t)
			var log strings.Builder
			h.cfg.Log = &log
			sleeps := 0
			h.clock.onSleep = func(time.Duration) {
				if sleeps++; sleeps != 1 {
					return
				}
				if c.during != nil {
					c.during(t, h, b2, d2)
				}
				if c.krl != 0 {
					h.publishKRL(7, c.krl)
				}
				h.write()
			}
			r, err := h.apply()
			if sleeps == 0 {
				t.Fatalf("apply 2 did not wait")
			}
			if c.wantErr == nil && err != nil || c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Fatalf("apply 2: %v, want %v (report %+v)", err, c.wantErr, r)
			}
			mustHeldBelowRecord(t, h, d3, max(c.dir, 2), x, c.krl, log.String())
		})
	}
	t.Run("older_bundle_at_the_window_boundary", func(t *testing.T) {
		t.Parallel()
		// Bundles 2-64 are root-signed successors, 65 adds a next CA x, 66
		// rotates the policy, drops x and adds a line ssh-keygen refuses.
		// With x refused too, apply 1 records 65 and apply 2 66. Then x is
		// accepted, and directory 2 under bundle 1's policy widens deploy:
		// apply 3 holds at bundle 1 and waits. Read from bundle 1, a poll's
		// window would end at 65, which now renders.
		f := newFixture(t)
		h := newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		cur, curDoc := f.bundle, f.bundleDoc
		for v := uint64(2); v <= 64; v++ {
			var d spool.Doc
			cur, d = f.successor(cur, curDoc, fmt.Sprintf("2026-10-01T%02d:%02d:00Z", v/60, v%60))
			h.state.Bundles[v], curDoc = d, d.Body
		}
		xKey := seedKey(t, 25)
		b65, d65 := f.successorNextUnder(cur, curDoc, f.policyDoc, "2026-10-02T00:00:00Z", xKey)
		rejected := seedKey(t, 21)
		d66, p2 := f.rotationDropping(b65, d65.Body, "2026-10-03T00:00:00Z", rejected)
		h.state.Bundles[65], h.state.Bundles[66], h.state.Policies[2] = d65, d66, p2
		x := trust.FormatKey(xKey.PublicKey())
		refuse := map[string]bool{x: true, trust.FormatKey(rejected.PublicKey()): true}
		h.run.rejectCA = func(l string) bool { return refuse[l] }
		h.clock.advance(time.Hour)
		h.publishKRL(7)
		for i, want := range []uint64{65, 66} {
			if _, err := h.apply(); !errors.Is(err, ErrCALineRejected) {
				t.Fatalf("apply %d: %v, want ca_line_rejected", i+1, err)
			}
			mustRecord(t, h, want, 0)
		}
		delete(refuse, x)
		h.publishDir(h.spec("role:ops", "role:q"))
		var log strings.Builder
		h.cfg.Log = &log
		sleeps := 0
		h.clock.onSleep = func(time.Duration) { sleeps++ }
		if r, err := h.apply(); err != nil || sleeps == 0 {
			t.Fatalf("apply 3: %v after %d sleeps, want the widened directory 2 under bundle 1 (report %+v)", err, sleeps, r)
		}
		mustHeldBelowRecord(t, h, d66, 2, x, 0, log.String())
	})
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
		var log strings.Builder
		h.cfg.Log = &log
		r, err = h.apply()
		if err != nil {
			t.Fatalf("apply 2: %v, want directory 66 installed (report %+v)", err, r)
		}
		if !strings.Contains(log.String(), state.UnappliedFile+": the accepted bundle 1 and directory 66 have passed it") {
			t.Errorf("no log line names the removal of the passed record:\n%s", log.String())
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
			t.Run(fmt.Sprintf("newOps=%t", newOps), func(t *testing.T) {
				t.Parallel()
				h := policyRotated(t, newOps, false)
				r, err := h.apply()
				if err != nil || r.DirectoryVersion != 65 || r.BundleVersion != 1 || !r.BundleHeld {
					t.Fatalf("apply 2: %v, %+v; want directory 65 under bundle 1, held", err, r)
				}
				if newOps && r.KRLVersion == h.f.krlVersion {
					t.Fatalf("the KRL the new ops key signed was taken under bundle 1")
				}
				if !newOps && !h.krlRevokes(h.l.Current(), 7) {
					t.Fatalf("KRL 7 was not applied")
				}
				mustRecord(t, h, 3, 0)
			})
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
		// signer-install.md's remedy for a recorded bundle 2 that a signer
		// restore lost, re-made as 2' (and 3'). The spool is left as the
		// fetcher leaves it (PR #78 review): the original 2 stays until it
		// is removed, a fetcher asking from bundle 2 receives only what is
		// above 2, and 2' arrives only from a fetch from bundle 1.
		for _, top := range []uint64{2, 3} {
			t.Run(fmt.Sprintf("remade_up_to_%d", top), func(t *testing.T) {
				t.Parallel()
				h := bundleRecorded(t)
				b2r, d2r := h.f.successor(h.f.bundle, h.f.bundleDoc, "2026-10-01T12:00:00Z")
				_, d3r := h.f.successor(b2r, d2r.Body, "2026-10-03T00:00:00Z")
				remade := map[uint64]spool.Doc{2: d2r, 3: d3r}
				if top == 3 {
					h.state.Bundles[3] = d3r
				}
				h.publishKRL(6)
				// Removing the record alone does not converge.
				if err := os.Remove(recordFile(h)); err != nil {
					t.Fatal(err)
				}
				r, err := h.apply()
				if top == 2 {
					// The original 2 is verified, refused and recorded
					// again, and accepted.json names it again.
					mustKRLAlone(t, h, r, 6, 1, "ca_line_rejected")
					if !errors.Is(err, ErrCALineRejected) {
						t.Fatalf("apply with the record removed: %v, want ca_line_rejected", err)
					}
					mustRecord(t, h, 2, 0)
					if a := readAccepted(t, h); a.Bundle != 2 {
						t.Fatalf("accepted.json %+v, want the recorded bundle 2 again", a)
					}
				} else {
					// 3' does not chain onto the original 2.
					mustKRLAlone(t, h, r, 6, 1, "bundle_not_verified")
					if !errors.Is(err, state.ErrBundle) {
						t.Fatalf("apply with the record removed: %v, want bundle_not_verified", err)
					}
				}
				// The remedy: the spool's bundle files above the accepted
				// bundle 1, then the record. An apply in between finds no
				// lost bundle to record again.
				for v := uint64(2); v <= top; v++ {
					for _, n := range []string{fmt.Sprintf("bundle-%d.json", v), fmt.Sprintf("bundle-%d.json.sigs", v)} {
						if err := os.Remove(filepath.Join(h.spool, n)); err != nil {
							t.Fatal(err)
						}
					}
					delete(h.state.Bundles, v)
				}
				r, err = h.apply()
				if top == 2 {
					if !errors.Is(err, state.ErrBundleOlder) {
						t.Fatalf("apply between the remedy's steps: %v, want bundle_older", err)
					}
					mustRecord(t, h, 2, 0)
				} else if err != nil || !r.NoOp {
					t.Fatalf("apply between the remedy's steps: %v, %+v; want a no-op", err, r)
				}
				if err := os.Remove(recordFile(h)); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				if r, err := h.apply(); err != nil || !r.NoOp {
					t.Fatalf("apply before the next poll: %v, %+v; want a no-op", err, r)
				}
				if a := readAccepted(t, h); a.Bundle != 1 {
					t.Fatalf("accepted.json %+v after the remedy, want bundle 1", a)
				}
				// The fetch from bundle 1 brings the re-made chain.
				for v := uint64(2); v <= top; v++ {
					h.state.Bundles[v] = remade[v]
				}
				r, err = h.apply()
				if a, aerr := h.accepted(); err != nil || aerr != nil || a.BundleVersion != top || !slices.Equal(a.Bundle, remade[top].Body) {
					t.Fatalf("apply after the fetch: %v, %+v; want the re-made bundle %d installed", err, r, top)
				}
				if _, _, ok := readRecord(t, h); ok {
					t.Fatalf("a record outlived the re-made chain's install")
				}
			})
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
		// be opened) stands in for a crash there. Its log names the
		// recorded directory it dropped (PR #78 review).
		var log strings.Builder
		if _, err := resetDirectory(h.l, h.l.State("missing-spool"), &log); err == nil {
			t.Fatalf("a reset with a missing spool succeeded")
		}
		want := fmt.Sprintf("removed %s (it held directory version 65, SHA-256 %s, ahead of the accepted directory version 1)", recordFile(h), trust.SHA256Hex(h.dirs[64].Body))
		if !strings.Contains(log.String(), want) {
			t.Fatalf("the reset's log does not name the dropped record:\n%s\nwant %s", log.String(), want)
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
	t.Run("reset_directory_logs_what_it_drops_from_the_record", func(t *testing.T) {
		t.Parallel()
		// PR #78 review: a record with both parts is rewritten without its
		// directory part, and a damaged record is removed, each with a log
		// line.
		f := newFixture(t)
		h := newTestHost(t, f)
		spoolInState(t, h)
		h.installed("role:ops")
		_, b2, p2 := f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z", seedKey(t, 22))
		h.state.Bundles[2], h.state.Policies[2] = b2, p2
		s := h.spec("role:ops")
		s.bulkRoles = 17
		h.publishDir(s)
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("apply 1: %v, want generation_too_large", err)
		}
		mustRecord(t, h, 2, 2)
		var log strings.Builder
		if _, err := resetDirectory(h.l, h.cfg.Spool, &log); err != nil {
			t.Fatal(err)
		}
		mustRecord(t, h, 2, 0)
		want := fmt.Sprintf("rewrote %s without its directory part (it held directory version 2, SHA-256 %s, ahead of the accepted directory version 1); its bundle version 2 stays recorded", recordFile(h), trust.SHA256Hex(h.dirs[1].Body))
		if !strings.Contains(log.String(), want) {
			t.Fatalf("the reset's log:\n%s\nwant %s", log.String(), want)
		}
		if err := os.WriteFile(recordFile(h), []byte(`{"bundle":`), 0o600); err != nil {
			t.Fatal(err)
		}
		log.Reset()
		if _, err := resetDirectory(h.l, h.cfg.Spool, &log); err != nil {
			t.Fatal(err)
		}
		if _, _, ok := readRecord(t, h); ok {
			t.Fatalf("the reset left the damaged record")
		}
		if !strings.Contains(log.String(), "WARNING "+recordFile(h)+" removed: "+state.ErrUnapplied.Error()) {
			t.Fatalf("no warning names the damaged record the reset removed:\n%s", log.String())
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
		// The record's SHA-256 per kind is computed from its own bytes
		// (PR #78 review, fix round 2).
		s := outboxStatus(t, h)
		want := heartbeat.Unapplied{Directory: 65, DirectorySHA256: trust.SHA256Hex(h.dirs[64].Body)}
		if s.Unapplied == nil || *s.Unapplied != want || s.Directory.Version != 1 {
			t.Fatalf("status after apply 1: unapplied %+v, directory in force %d; want %+v and 1", s.Unapplied, s.Directory.Version, want)
		}
		h.mustApply()
		if s := outboxStatus(t, h); s.Unapplied != nil {
			t.Fatalf("status after the fix: unapplied %+v, want none", s.Unapplied)
		}
		b := bundleRecorded(t)
		want = heartbeat.Unapplied{Bundle: 2, BundleSHA256: trust.SHA256Hex(b.state.Bundles[2].Body)}
		if s := outboxStatus(t, b); s.Unapplied == nil || *s.Unapplied != want {
			t.Fatalf("status with a recorded bundle: unapplied %+v, want %+v", s.Unapplied, want)
		}
	})
	t.Run("passed_record_removed_by_the_next_apply", func(t *testing.T) {
		t.Parallel()
		// A record the commit passed but did not remove (a crash between
		// the commit and dropPassedRecord) is removed by the next apply's
		// load, with a log line (PR #78 review, fix round 2).
		h := recordedWindow(t, true)
		old, err := os.ReadFile(recordFile(h))
		if err != nil {
			t.Fatal(err)
		}
		h.mustApply()
		if err := os.WriteFile(recordFile(h), old, 0o600); err != nil { //nolint:gosec // test fixture: the record's own earlier bytes
			t.Fatal(err)
		}
		var log strings.Builder
		h.cfg.Log = &log
		if r, err := h.apply(); err != nil || !r.NoOp {
			t.Fatalf("apply after the restored record: %v, %+v; want a no-op", err, r)
		}
		if recordExists(t, h) {
			t.Fatalf("the passed record is still there")
		}
		if want := "removed " + recordFile(h) + ": no part of it is ahead of the accepted state"; !strings.Contains(log.String(), want) {
			t.Fatalf("no log line names the removal:\n%s\nwant %s", log.String(), want)
		}
	})
}
