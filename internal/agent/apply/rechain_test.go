//go:build linux

package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestKRLAlone is owner decision D-R2 (PR #71 review F5): a capture whose
// directory or bundle step is refused still installs its KRL, verified
// against the bundle in force, and only the KRL: the directory, the
// principals and the bundle stay as accepted, and the refusal is reported.
// Revocations only narrow what sshd accepts, so they never wait for a chain
// that does not verify (a signer restore that re-made a version this host
// had accepted, for example).
func TestKRLAlone(t *testing.T) {
	t.Run("directory_rechain_refused_krl_applied", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.publishKRL(5)
		h.mustApply()
		// Version 2, accepted here, is lost in a signer restore; the
		// signer re-makes a different version 2 and builds version 3 on it.
		// The spool still holds the lost version 2 the fetcher got first.
		h.publishDir(h.spec("role:ops", "role:lost"))
		h.mustApply()
		remade := h.f.directory(h.dirs[0].Body, h.spec("role:ops", "role:remade"))
		next := h.f.directory(remade.Body, h.spec("role:ops", "role:next"))
		h.state.Directories[3] = next
		h.publishKRL(5, 6)
		gen := h.current()
		r, err := h.apply()
		if !errors.Is(err, state.ErrDir) {
			t.Fatalf("a directory that does not chain to the accepted version: %v, want directory_not_verified reported", err)
		}
		if !h.krlRevokes(h.l.Current(), 6) || h.current() == gen || r.KRLVersion != h.f.krlVersion {
			t.Fatalf("the newer KRL was not applied alone: revokes 6 %t, current %d (was %d), %+v", h.krlRevokes(h.l.Current(), 6), h.current(), gen, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:lost", "role:ops"}) || r.DirectoryVersion != 2 {
			t.Fatalf("the refused chain changed the principals %v or the directory version %d", got, r.DirectoryVersion)
		}
		if v, err := InstalledKRLVersion(h.l); err != nil || v != h.f.krlVersion {
			t.Fatalf("installed KRL version %d (%v), want %d", v, err, h.f.krlVersion)
		}
		if len(r.Errors) == 0 {
			t.Fatal("the report does not name the directory refusal")
		}
	})
	t.Run("bundle_step_refused_krl_applied", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		// Bundle version 3 with no version 2 between: a gap.
		h.state.Bundles[3] = spool.Doc{Body: []byte(`{}`), Sigs: []byte("sigs")}
		h.publishKRL(7)
		r, err := h.apply()
		if !errors.Is(err, state.ErrBundleChainGap) {
			t.Fatalf("a bundle chain gap: %v, want bundle_chain_gap reported", err)
		}
		if !h.krlRevokes(h.l.Current(), 7) || r.BundleVersion != 1 {
			t.Fatalf("the KRL was not applied alone: revokes 7 %t, %+v", h.krlRevokes(h.l.Current(), 7), r)
		}
	})
	t.Run("krl_refused_too_changes_nothing", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.state.Bundles[3] = spool.Doc{Body: []byte(`{}`), Sigs: []byte("sigs")}
		v, files := h.f.krl([]uint64{8}, nil, "fedcba9876543210fedcba9876543210")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		gen := h.current()
		if _, err := h.apply(); !errors.Is(err, state.ErrBundleChainGap) || !errors.Is(err, state.ErrKRL) {
			t.Fatalf("a refused bundle and a refused KRL: %v, want both", err)
		}
		if h.current() != gen || h.krlRevokes(h.l.Current(), 8) {
			t.Fatal("a refused KRL was installed")
		}
	})
	t.Run("oversize_principals_file_krl_applied", func(t *testing.T) {
		t.Parallel()
		// F07 (03-08d): a verified directory whose principals file renders
		// above the generation cap is refused before anything is written,
		// and the capture's KRL, verified again against the accepted
		// bundle, is applied alone.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.publishKRL(5)
		h.mustApply()
		s := h.spec("role:ops")
		s.bulkRoles = 17
		h.publishDir(s)
		h.publishKRL(5, 6)
		r, err := h.apply()
		if !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("an oversize principals file: %v, want generation_too_large reported", err)
		}
		mustKRLAlone(t, h, r, 6, 1, "generation_too_large")
	})
	t.Run("too_many_accounts_krl_applied", func(t *testing.T) {
		t.Parallel()
		// F07 (03-08d): host group lab maps one account more than a
		// generation may hold principals files for.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.publishKRL(5)
		h.mustApply()
		s := h.spec("role:ops")
		s.accounts = append(s.accounts, accountNames("u", maxAccounts)...)
		h.publishDir(s)
		h.publishKRL(5, 6)
		r, err := h.apply()
		if !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("%d accounts: %v, want generation_too_large reported", maxAccounts+1, err)
		}
		mustKRLAlone(t, h, r, 6, 1, "generation_too_large")
	})
	t.Run("intermediate_union_too_large_krl_applied", func(t *testing.T) {
		t.Parallel()
		// F07 (03-08d): versions 2 and 3 each hold maxAccounts principals
		// files, but version 3 renames one account, and the intermediate
		// Transition would install between them holds the accounts of both
		// sides. It is refused before anything is written.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		s := h.spec("role:ops")
		s.accounts = append(s.accounts, accountNames("u", maxAccounts-1)...)
		h.publishDir(s)
		h.publishKRL(5)
		h.mustApply()
		renamed := h.spec("role:ops")
		renamed.accounts = append(renamed.accounts, accountNames("u", maxAccounts-2)...)
		renamed.accounts = append(renamed.accounts, "w0001")
		h.publishDir(renamed)
		h.publishKRL(5, 6)
		gens := h.genCount()
		r, err := h.apply()
		if !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("an intermediate above the cap: %v, want generation_too_large reported", err)
		}
		mustKRLAlone(t, h, r, 6, 2, "generation_too_large")
		if h.genCount() != gens+1 {
			t.Fatalf("%d generations, want %d: only the KRL-alone generation is new", h.genCount(), gens+1)
		}
		for _, n := range genNumbers(t, h) {
			if h.exists(filepath.Join(h.l.Gen(n), PrincipalsDir, "w0001")) {
				t.Fatalf("generation %d holds version 3's renamed account", n)
			}
		}
	})
	t.Run("intermediate_checked_with_the_kept_krl", func(t *testing.T) {
		t.Parallel()
		// checkCandidate runs after keepKRL, so the intermediate it checks
		// is the one Transition computes. Here current holds a KRL that a
		// rollback kept and accepted/ does not, and version 3 renames a
		// header-only account while widening deploy: with the kept KRL the
		// move collapses into one widening swap; with the verified (older)
		// KRL its intermediate would hold the accounts of both sides.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		s := h.spec("role:ops")
		s.bare = accountNames("u", maxAccounts-1)
		h.publishDir(s)
		h.mustApply()
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.setStall(true)
		h.publishKRL(7)
		if _, err := h.apply(); !errors.Is(err, ErrSelfTest) || !h.krlRevokes(h.l.Current(), 7) {
			t.Fatalf("the failed apply of KRL 7: %v", err)
		}
		h.sshd.setStall(false)
		h.resetSpool()
		h.state.KRLs = map[uint64]spool.KRLFiles{}
		wider := h.spec("role:ops", "role:q")
		wider.bare = append(accountNames("u", maxAccounts-2), "w0001")
		h.publishDir(wider)
		r, err := h.apply()
		if err != nil || r.DirectoryVersion != 3 || !slices.Equal(h.principals("deploy"), []string{"role:ops", "role:q"}) || !h.krlRevokes(h.l.Current(), 7) {
			t.Fatalf("a widening that collapses with the kept KRL: %v, %+v, principals %v", err, r, h.principals("deploy"))
		}
	})
	t.Run("ca_line_rejected_krl_applied", func(t *testing.T) {
		t.Parallel()
		// F07 (03-08d): a root-signed successor bundle adds a next user CA
		// whose line the host's ssh-keygen refuses; the KRL-alone
		// generation keeps the accepted bundle's CA lines.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		next := seedKey(t, 21)
		_, b2 := h.f.successorWithNext(h.f.bundle, h.f.bundleDoc, next)
		h.state.Bundles[2] = b2
		line := trust.FormatKey(next.PublicKey())
		h.run.rejectCA = func(l string) bool { return l == line }
		h.publishKRL(6)
		r, err := h.apply()
		if !errors.Is(err, ErrCALineRejected) {
			t.Fatalf("a CA line ssh-keygen refuses: %v, want ca_line_rejected reported", err)
		}
		mustKRLAlone(t, h, r, 6, 1, "ca_line_rejected")
		if a, err := h.accepted(); err != nil || r.BundleVersion != 1 || a.BundleVersion != 1 || strings.Contains(h.file(CAFile), line) {
			t.Fatalf("the refused bundle was taken: report %d, accepted %+v (%v)", r.BundleVersion, a, err)
		}
	})
	t.Run("ops_key_changed_krl_waits", func(t *testing.T) {
		t.Parallel()
		// F07 (03-08d): the successor bundle replaces the ops key, and the
		// KRL is signed by the new one. Its generation is refused (an
		// oversize directory), so the bundle is not applied, and the KRL,
		// verified again against the accepted bundle, is refused too:
		// nothing is installed. The fallback never reuses a KRL that only
		// the refused capture's bundle verifies.
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		newOps := seedKey(t, 22)
		_, b2, p2 := f.rotationOps(f.bundle, f.bundleDoc, f.policyDoc, f.policy, f.policy.Admins, "2026-10-02T00:00:00Z", newOps)
		h.state.Bundles[2], h.state.Policies[2] = b2, p2
		s := h.spec("role:ops")
		s.bulkRoles = 17
		h.publishDir(s)
		f.ops = newOps
		h.publishKRL(6)
		gen, gens := h.current(), h.genCount()
		_, err := h.apply()
		if !errors.Is(err, ErrGenerationTooLarge) || !errors.Is(err, state.ErrKRL) {
			t.Fatalf("a KRL only the refused bundle verifies: %v, want generation_too_large and krl_not_verified", err)
		}
		if h.current() != gen || h.genCount() != gens || h.krlRevokes(h.l.Current(), 6) {
			t.Fatalf("something was installed: current %d (was %d), %d generations (was %d)", h.current(), gen, h.genCount(), gens)
		}
	})
	t.Run("refusal_without_newer_krl_is_noop", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		gen, gens := h.current(), h.genCount()
		s := h.spec("role:ops")
		s.bulkRoles = 17
		h.publishDir(s)
		r, err := h.apply()
		if !errors.Is(err, ErrGenerationTooLarge) || !r.NoOp || h.current() != gen || h.genCount() != gens {
			t.Fatalf("an oversize directory and no newer KRL: %v, %+v, current %d (was %d), %d generations (was %d)", err, r, h.current(), gen, h.genCount(), gens)
		}
	})
	t.Run("superseded_during_wait_krl_applied", func(t *testing.T) {
		t.Parallel()
		// F07 (03-08d): during a widening wait the spool gains an oversize
		// directory and a newer KRL. The superseding generation is the
		// pending target's directory with the newer KRL, verified against
		// the pending target's bundle.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		h.publishKRL(7)
		h.mustApply() // a swap just now: the widening apply must wait
		h.publishDir(h.spec("role:ops", "role:q"))
		published := false
		h.clock.onSleep = func(time.Duration) {
			if !published {
				published = true
				s := h.spec("role:ops", "role:q")
				s.bulkRoles = 17
				h.publishDir(s)
				h.publishKRL(7, 99)
				h.write()
			}
		}
		r, err := h.apply()
		if !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("an oversize superseding directory: %v, want generation_too_large reported", err)
		}
		if !h.krlRevokes(h.l.Current(), 99) || !slices.Equal(h.principals("deploy"), []string{"role:ops", "role:q"}) || r.DirectoryVersion != 2 || h.lastGood() != h.current() {
			t.Fatalf("the pending target with the newer KRL is not committed: revokes 99 %t, principals %v, %+v", h.krlRevokes(h.l.Current(), 99), h.principals("deploy"), r)
		}
		if a, err := h.accepted(); err != nil || a.DirectoryVersion != 2 || a.KRLVersion != h.f.krlVersion {
			t.Fatalf("accepted after the wait: %+v, %v", a, err)
		}
	})
	t.Run("selftest_failure_after_swap_keeps_new_krl", func(t *testing.T) {
		t.Parallel()
		// After a swap, a rollback already keeps the newest KRL
		// (RollbackTarget): no KRL-alone pass is needed there.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.setStall(true)
		h.publishDir(h.spec("role:ops", "role:q"))
		h.publishKRL(6)
		r, err := h.apply()
		if !errors.Is(err, ErrSelfTest) || !r.Rollback {
			t.Fatalf("self-test failure: %v, %+v", err, r)
		}
		if !h.krlRevokes(h.l.Current(), 6) || !slices.Equal(h.principals("deploy"), []string{"role:ops"}) {
			t.Fatalf("the rollback: revokes 6 %t, principals %v", h.krlRevokes(h.l.Current(), 6), h.principals("deploy"))
		}
	})
	t.Run("failed_runs_do_not_grow_gen", func(t *testing.T) {
		t.Parallel()
		// F07 (03-08d): every rollback ends with commit's retention cleanup.
		// Each failed run leaves its target generation; without the cleanup
		// gen/ grows by one per run.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.setStall(true)
		var counts []int
		for i := range keepGenerations + 3 {
			h.publishDir(h.spec("role:ops", fmt.Sprintf("role:q%d", i)))
			if _, err := h.apply(); !errors.Is(err, ErrSelfTest) {
				t.Fatalf("run %d: %v, want self_test_failed", i, err)
			}
			counts = append(counts, h.genCount())
		}
		n := len(counts)
		if counts[n-1] > keepGenerations+2 || counts[n-1] > counts[n-4] {
			t.Fatalf("generations after each failed run %v: want at most %d, and no growth over the last three runs", counts, keepGenerations+2)
		}
	})
	t.Run("unvalidated_intermediate_discarded", func(t *testing.T) {
		t.Parallel()
		// F07 (03-08d): Transition discards an intermediate it installed but
		// could not validate (here ssh-keygen -Q fails from its second call,
		// the intermediate's, after the target's passed).
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		gens := h.genCount()
		queries := 0
		h.run.onQuery = func() {
			if queries++; queries >= 2 {
				h.run.queryCode = 255
			}
		}
		h.publishDir(h.spec("role:q"))
		h.publishKRL(6)
		if _, err := h.apply(); !errors.Is(err, ErrKRLRejected) || queries < 2 {
			t.Fatalf("an intermediate ssh-keygen refuses: %v after %d queries, want krl_rejected_by_ssh_keygen", err, queries)
		}
		if h.genCount() != gens+1 {
			t.Fatalf("%d generations, want %d: the unvalidated intermediate stayed", h.genCount(), gens+1)
		}
	})
	t.Run("first_install_refusal_stands", func(t *testing.T) {
		t.Parallel()
		// With nothing accepted there is no bundle to verify a KRL against.
		h := newTestHost(t, newFixture(t))
		s := h.spec("role:ops")
		s.bulkRoles = 17
		h.publishDir(s)
		h.publishKRL(6)
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) || h.exists(h.l.Current()) || h.exists(h.l.DropIn()) {
			t.Fatalf("an oversize first install: %v, current %t", err, h.exists(h.l.Current()))
		}
	})
}

// accountNames is n account names prefix0000, prefix0001, ...
func accountNames(prefix string, n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("%s%04d", prefix, i))
	}
	return out
}

// genNumbers is the numbers of the generation directories in gen/.
func genNumbers(t *testing.T, h *testHost) []uint64 {
	t.Helper()
	entries, err := os.ReadDir(h.l.GenDir())
	if err != nil {
		t.Fatal(err)
	}
	var out []uint64
	for _, e := range entries {
		if n, err := strconv.ParseUint(e.Name(), 10, 64); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// successorWithNext is successor with a next user CA entry for key added.
func (f *fixture) successorWithNext(prev *trust.Bundle, prevDoc []byte, key ssh.Signer) (*trust.Bundle, spool.Doc) {
	f.t.Helper()
	b, err := trust.BuildSuccessor(prev, prevDoc, f.policyDoc, prev.Root.Keys, 1, f.policyDoc, "2026-10-02T00:00:00Z", testInstallation)
	if err != nil {
		f.t.Fatal(err)
	}
	// The entries are ordered by role (user first), then generation.
	b.CAs = slices.Insert(b.CAs, 1, trust.CAEntry{Role: trust.RoleUser, Key: trust.FormatKey(key.PublicKey()), Alg: ssh.KeyAlgoED25519, Custody: "software", State: "next", Generation: 2})
	doc := mustCanonical(f.t, b)
	if _, err := trust.ParseBundle(doc); err != nil {
		f.t.Fatalf("successor bundle with a next CA: %v", err)
	}
	return b, spool.Doc{Body: doc, Sigs: f.rootSign(trust.NamespaceBundle, doc)}
}

// mustKRLAlone checks the end of a KRL-alone apply (F07 (03-08d)): current
// revokes serial, deploy keeps role:ops, the accepted and reported directory
// version stays dir, the installed KRL is the newest published one, and the
// report names the refusal want.
func mustKRLAlone(t *testing.T, h *testHost, r *Report, serial, dir uint64, want string) {
	t.Helper()
	if !h.krlRevokes(h.l.Current(), serial) {
		t.Fatalf("the newer KRL was not applied alone: current does not revoke %d (%+v)", serial, r)
	}
	if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops"}) || r.DirectoryVersion != dir {
		t.Fatalf("the refused capture changed the principals %v or the reported directory version %d", got, r.DirectoryVersion)
	}
	if a, err := h.accepted(); err != nil || a.DirectoryVersion != dir {
		t.Fatalf("accepted directory after the KRL-alone apply: %+v, %v, want version %d", a, err, dir)
	}
	if v, err := InstalledKRLVersion(h.l); err != nil || v != h.f.krlVersion {
		t.Fatalf("installed KRL version %d (%v), want %d", v, err, h.f.krlVersion)
	}
	if !strings.Contains(strings.Join(r.Errors, "; "), want) {
		t.Fatalf("the report's errors %q do not name %s", r.Errors, want)
	}
}

// spoolInState moves h's spool to the production place, <state>/spool,
// where paths.Allowed lets the applier remove files (ResetDirectory).
func spoolInState(t *testing.T, h *testHost) {
	t.Helper()
	if err := os.Mkdir(h.l.Spool(), 0o750); err != nil { //nolint:gosec // the spool's mode
		t.Fatal(err)
	}
	if err := os.Mkdir(h.l.Outbox(), 0o750); err != nil { //nolint:gosec // the outbox's mode
		t.Fatal(err)
	}
	h.spool, h.cfg.Spool = h.l.Spool(), h.l.Spool()
}

// TestResetDirectory is the root-run re-bootstrap of owner decision D-R2
// (PR #71 review F5): on a host whose accepted directory a signer restore
// lost, keyroster-agent reset-directory drops it and the spool's directory
// files, so the next apply takes the re-made chain's newest version as a
// first install does, and nothing unsigned.
func TestResetDirectory(t *testing.T) {
	// diverged is a host that accepted directory version 2, which the
	// signer then lost and re-made; version 3 builds on the re-made 2.
	diverged := func(t *testing.T) (*testHost, spool.Doc) {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		spoolInState(t, h)
		h.installed("role:ops")
		h.publishDir(h.spec("role:ops", "role:lost"))
		h.mustApply()
		remade := h.f.directory(h.dirs[0].Body, h.spec("role:ops", "role:remade"))
		next := h.f.directory(remade.Body, h.spec("role:ops", "role:next"))
		h.state.Directories[3] = next
		if _, err := h.apply(); !errors.Is(err, state.ErrDir) {
			t.Fatalf("the re-made chain: %v, want directory_not_verified", err)
		}
		return h, next
	}
	t.Run("drops_the_lost_version_and_takes_the_remade_chain", func(t *testing.T) {
		t.Parallel()
		h, next := diverged(t)
		r, err := ResetDirectory(h.l, h.spool)
		if err != nil || r.Version != 2 || r.SHA256 != trust.SHA256Hex(h.dirs[1].Body) {
			t.Fatalf("reset-directory: %v, %+v", err, r)
		}
		for _, n := range []string{"directory-1.json", "directory-2.json", "directory-3.json", "directory-3.json.sigs"} {
			if !slices.Contains(r.SpoolRemoved, n) {
				t.Errorf("reset-directory left %s in the spool (removed %v)", n, r.SpoolRemoved)
			}
		}
		if a := readAccepted(t, h); a.Directory != 0 || a.Bundle != 1 {
			t.Fatalf("accepted.json after the reset: %+v, want directory 0", a)
		}
		// The fetcher then spools the server's current directory only.
		h.state.Directories = map[uint64]spool.Doc{3: next}
		r2, err := h.apply()
		if err != nil || r2.DirectoryVersion != 3 {
			t.Fatalf("the apply after the reset: %v, %+v", err, r2)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:next", "role:ops"}) {
			t.Fatalf("principals %v after the re-made chain", got)
		}
		if a := readAccepted(t, h); a.Directory != 3 {
			t.Fatalf("accepted.json after the apply: %+v", a)
		}
	})
	t.Run("an_unsigned_directory_is_still_refused", func(t *testing.T) {
		t.Parallel()
		h, next := diverged(t)
		if _, err := ResetDirectory(h.l, h.spool); err != nil {
			t.Fatal(err)
		}
		forged := next
		forged.Sigs = []byte("not a signature")
		h.state.Directories = map[uint64]spool.Doc{3: forged}
		if _, err := h.apply(); !errors.Is(err, state.ErrDir) {
			t.Fatalf("an unsigned directory after the reset: %v, want directory_not_verified", err)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:lost", "role:ops"}) {
			t.Fatalf("principals %v, want the last good ones kept", got)
		}
	})
	t.Run("spool_outside_the_agents_paths_refused", func(t *testing.T) {
		t.Parallel()
		h, _ := diverged(t)
		other := t.TempDir()
		if err := os.WriteFile(filepath.Join(other, "directory-1.json"), []byte("d"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if _, err := ResetDirectory(h.l, other); err == nil {
			t.Fatal("reset-directory accepted a spool outside the agent's paths")
		}
		if _, err := os.Stat(filepath.Join(other, "directory-1.json")); err != nil {
			t.Fatalf("the file outside the agent's paths is gone: %v", err)
		}
		if a, err := AcceptedVersions(h.l); err != nil || a.Directory != 2 {
			t.Fatalf("the refused reset changed the accepted directory: %+v, %v", a, err)
		}
	})
	t.Run("refused_while_an_apply_is_unfinished", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		spoolInState(t, h)
		h.installed("role:ops")
		h.publishDir(h.spec("role:ops", "role:web"))
		h.cfg.Fault = func(p string) error {
			if p == "self-test" {
				return &crash{point: p}
			}
			return nil
		}
		if _, err := h.apply(); !isCrash(err) {
			t.Fatalf("the crash: %v", err)
		}
		if _, err := ResetDirectory(h.l, h.spool); !errors.Is(err, ErrResetPending) {
			t.Fatalf("reset-directory over an unfinished apply: %v, want reset_apply_unfinished", err)
		}
	})
	t.Run("reset_without_last_good_refusal_stands", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		spoolInState(t, h)
		if _, err := ResetDirectory(h.l, h.spool); err != nil {
			t.Fatal(err)
		}
		h.publishKRL(5)
		if _, err := h.apply(); !errors.Is(err, ErrHostNotInDirectory) || h.exists(h.l.Current()) || h.exists(h.l.DropIn()) {
			t.Fatalf("no directory and no last-good: %v, current %t", err, h.exists(h.l.Current()))
		}
	})
}

// readAccepted reads the outbox's accepted.json.
func readAccepted(t *testing.T, h *testHost) enroll.Accepted {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.l.Outbox(), enroll.AcceptedFile))
	if err != nil {
		t.Fatal(err)
	}
	var a enroll.Accepted
	if err := trust.DecodeStrict(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}
