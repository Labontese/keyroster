//go:build linux

package apply

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestApplyTracer drives the whole sequence against the fake sshd: a
// first install (drop-in, one reload, self-test), a revocation (one
// narrowing swap, no reload), and a change that revokes and adds at once
// (intermediate, then the final swap LoginGraceTime + 5 s later).
func TestApplyTracer(t *testing.T) {
	f := newFixture(t)
	h := newTestHost(t, f)
	r := h.installed("role:ops")
	if !r.Reloaded || r.Intermediate != 0 || r.SelfTest != "pass" || h.run.reloads != 1 {
		t.Fatalf("first install: %+v, %d reloads", r, h.run.reloads)
	}
	if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops"}) {
		t.Fatalf("principals = %v", got)
	}
	first := h.current()

	h.publishKRL(7)
	r = h.mustApply()
	if r.Reloaded || r.Intermediate != 0 || h.run.reloads != 1 || h.current() == first {
		t.Fatalf("revocation: %+v, %d reloads, current %d", r, h.run.reloads, h.current())
	}

	start := h.clock.Boottime()
	h.publishKRL(7, 8)
	h.publishDir(h.spec("role:ops", "role:q"))
	r = h.mustApply()
	if r.Intermediate == 0 || r.Reloaded || r.WaitedMS < int64(120+5)*1000 {
		t.Fatalf("mixed change: %+v", r)
	}
	if waited := h.clock.Boottime() - start; waited < 125*time.Second {
		t.Fatalf("the clock moved %v, want at least LoginGraceTime + 5 s", waited)
	}
	if got := h.principals("deploy"); !slices.Equal(got, []string{"role:ops", "role:q"}) {
		t.Fatalf("principals after the mixed change = %v", got)
	}
	if h.lastGood() != h.current() {
		t.Fatalf("last-good %d, current %d", h.lastGood(), h.current())
	}
}

// crash is an injected crash: the run stops at that point and does
// nothing more, as a killed process would.
type crash struct{ point string }

func (c *crash) Error() string       { return "injected crash at " + c.point }
func (c *crash) InjectedCrash() bool { return true }

// faultLog records every fault point a run passes and crashes at the
// k-th (0: never).
type faultLog struct {
	mu     sync.Mutex
	points []string
	k      int
	onHit  func(point string)
}

func (f *faultLog) hook(point string) error {
	f.mu.Lock()
	f.points = append(f.points, point)
	n, hit := len(f.points), f.onHit
	f.mu.Unlock()
	if hit != nil {
		hit(point)
	}
	if f.k > 0 && n == f.k {
		return &crash{point: point}
	}
	return nil
}

// resetSpool empties the spool directory.
func (h *testHost) resetSpool() {
	h.t.Helper()
	entries, err := os.ReadDir(h.spool)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(h.spool, e.Name())); err != nil {
			h.t.Fatal(err)
		}
	}
}

// genCount is the number of generation directories.
func (h *testHost) genCount() int {
	h.t.Helper()
	entries, err := os.ReadDir(h.l.GenDir())
	if err != nil {
		h.t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if _, err := strconv.ParseUint(e.Name(), 10, 64); err == nil {
			n++
		}
	}
	return n
}

func (h *testHost) exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// krlRevokes reports whether the revoked.krl of generation dir revokes
// serial under the user CA.
func (h *testHost) krlRevokes(dir string, serial uint64) bool {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, KRLFile)) //nolint:gosec // test fixture
	if err != nil {
		h.t.Fatal(err)
	}
	if len(b) == 0 {
		return false
	}
	p, err := krl.Parse(b)
	if err != nil {
		h.t.Fatal(err)
	}
	return p.RevokesSerial(h.f.user.PublicKey().Marshal(), serial)
}

// engine is a bare engine on h's layout, for the swap-level tests.
func (h *testHost) engine() *engine {
	h.t.Helper()
	fd, err := spool.OpenDir(h.l.StateDir)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { _ = unix.Close(fd) })
	cfg := h.cfg
	e := &engine{cfg: cfg, l: h.l, clock: h.clock, report: &Report{}, stateFd: fd, grace: 120, rawGrace: 120}
	e.loadLastSwap(false, h.exists(h.l.Current()))
	return e
}

// gen writes a generation with the given principals for deploy and KRL
// bytes, through the engine, and returns it.
func (h *testHost) gen(e *engine, krlBytes []byte, principals ...string) *Generation {
	h.t.Helper()
	cur, _, err := e.readCurrent()
	if err != nil || cur == nil {
		h.t.Fatalf("readCurrent: %v", err)
	}
	g := &Generation{Files: map[string][]byte{}}
	for k, v := range cur.Files {
		g.Files[k] = v
	}
	var b strings.Builder
	b.WriteString("# keyroster: test\n")
	for _, p := range principals {
		b.WriteString(p + "\n")
	}
	g.Files[PrincipalsDir+"/deploy"] = []byte(b.String())
	if krlBytes != nil {
		g.Files[KRLFile] = krlBytes
	}
	g.N = e.allocGeneration()
	if err := e.installGeneration(g); err != nil {
		h.t.Fatal(err)
	}
	return g
}

func readMarker(t *testing.T, h *testHost) *marker {
	t.Helper()
	b, err := os.ReadFile(h.l.State(pendingFile)) //nolint:gosec // test fixture
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var m marker
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return &m
}

// successor builds and root-signs bundle version prev.Version+1 (same
// keys and policy).
func (f *fixture) successor(prev *trust.Bundle, prevDoc []byte, issuedAt string) (*trust.Bundle, spool.Doc) {
	f.t.Helper()
	b, err := trust.BuildSuccessor(prev, prevDoc, f.policyDoc, prev.Root.Keys, 1, f.policyDoc, issuedAt, testInstallation)
	if err != nil {
		f.t.Fatal(err)
	}
	doc := mustCanonical(f.t, b)
	return b, spool.Doc{Body: doc, Sigs: f.rootSign(trust.NamespaceBundle, doc)}
}

// TestApply covers the apply sequence's edges (Task 3 of 03-05): versions
// and documents, candidate checks, self-test and rollback, the two-step
// swap and its timing rule, the monotone-swap check, the LoginGraceTime
// bound, crash recovery, the operator's recovery, PR #57's cases, and
// retention and state.
func TestApply(t *testing.T) {
	// --- versions and documents ---
	t.Run("equal_version_noop", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		gens, cur := h.genCount(), h.current()
		before, _ := os.ReadDir(h.l.State(state.AcceptedDir))
		var stamps []time.Time
		for _, e := range before {
			fi, _ := e.Info()
			stamps = append(stamps, fi.ModTime())
		}
		time.Sleep(10 * time.Millisecond)
		r, err := h.apply()
		if err != nil || !r.NoOp || h.genCount() != gens || h.current() != cur {
			t.Fatalf("equal versions: %+v, %v, %d gens (was %d)", r, err, h.genCount(), gens)
		}
		after, _ := os.ReadDir(h.l.State(state.AcceptedDir))
		for i, e := range after {
			if fi, _ := e.Info(); !fi.ModTime().Equal(stamps[i]) {
				t.Fatalf("accepted/%s was rewritten", e.Name())
			}
		}
	})
	t.Run("equal_version_does_not_repair_drift", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		drifted := filepath.Join(h.l.Gen(h.current()), PrincipalsDir, "deploy")
		if err := os.WriteFile(drifted, []byte("role:hand-edited\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		if r, err := h.apply(); err != nil || !r.NoOp {
			t.Fatalf("apply: %+v, %v", r, err)
		}
		if b, _ := os.ReadFile(drifted); string(b) != "role:hand-edited\n" { //nolint:gosec // test fixture
			t.Fatalf("an equal-version apply rewrote the drifted file: %q", b)
		}
	})
	t.Run("older_bundle_refused", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		h := newTestHost(t, f)
		_, v2 := f.successor(f.bundle, f.bundleDoc, "2026-10-02T00:00:00Z")
		h.state.Bundles[2] = v2
		h.installed("role:ops")
		h.resetSpool()
		delete(h.state.Bundles, 2)
		if _, err := h.apply(); !errors.Is(err, state.ErrBundleOlder) {
			t.Fatalf("bundle 1 after bundle 2: %v, want bundle_older", err)
		}
	})
	t.Run("bundle_chain_gap_refused", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t)
		h := newTestHost(t, f)
		h.installed("role:ops")
		b2, v2 := f.successor(f.bundle, f.bundleDoc, "2026-10-02T00:00:00Z")
		_, v3 := f.successor(b2, v2.Body, "2026-10-03T00:00:00Z")
		h.state.Bundles[3] = v3
		cur := h.current()
		if _, err := h.apply(); !errors.Is(err, state.ErrBundleChainGap) || h.current() != cur {
			t.Fatalf("bundle 3 without 2: %v, want bundle_chain_gap", err)
		}
		h.state.Bundles[2] = v2
		if r := h.mustApply(); r.BundleVersion != 3 {
			t.Fatalf("bundles 2 and 3: %+v", r)
		}
	})
	t.Run("directory_other_installation_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		s := h.spec("role:ops")
		s.install = "ffffffffffffffffffffffffffffffff"
		h.publishDir(s)
		if _, err := h.apply(); !errors.Is(err, state.ErrDirInstall) || h.exists(h.l.Current()) {
			t.Fatalf("a directory for another installation: %v, want directory_installation and nothing installed", err)
		}
	})
	t.Run("krl_other_installation_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		v, files := h.f.krl([]uint64{7}, nil, "ffffffffffffffffffffffffffffffff")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		cur := h.current()
		if _, err := h.apply(); !errors.Is(err, state.ErrKRL) || !errors.Is(err, krl.ErrInstallation) || h.current() != cur {
			t.Fatalf("a KRL for another installation: %v, want krl_not_verified (installation)", err)
		}
	})
	t.Run("host_not_in_directory_keeps_last_good", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		cur := h.current()
		s := h.spec("role:ops", "role:x")
		s.hostKeys = []ssh.PublicKey{h.f.mach.PublicKey()}
		h.publishDir(s)
		r, err := h.apply()
		if !errors.Is(err, ErrHostNotInDirectory) || h.current() != cur || h.lastGood() != cur || len(r.UnmatchedHostKeys) != 1 {
			t.Fatalf("a directory without this host: %+v, %v", r, err)
		}
		s = h.spec("role:ops", "role:x")
		s.status = "disabled"
		h.publishDir(s)
		if _, err := h.apply(); !errors.Is(err, ErrHostNotInDirectory) || h.current() != cur {
			t.Fatalf("a disabled host: %v", err)
		}
	})
	t.Run("oversize_generation_refused_before_install", func(t *testing.T) {
		t.Parallel()
		// PR #67 review: a valid directory can map enough roles to one
		// account to render a principals file above the cap readGeneration
		// reads with; installed, it would fail every later apply.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		cur, gens := h.current(), h.genCount()
		s := h.spec("role:ops")
		s.bulkRoles = 17
		h.publishDir(s)
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) || h.current() != cur || h.genCount() != gens {
			t.Fatalf("an oversize principals file: %v, current %d (was %d), %d gens (was %d)", err, h.current(), cur, h.genCount(), gens)
		}
		h.publishDir(h.spec("role:ops", "role:q"))
		if r, err := h.apply(); err != nil || r.DirectoryVersion != 3 {
			t.Fatalf("the next apply after the refusal: %+v, %v", r, err)
		}
	})
	t.Run("empty_krl_installed", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		v, files := h.f.krl(nil, nil, "")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		r := h.mustApply()
		if r.KRLVersion != v || h.file(KRLFile) != string(files.KRL) {
			t.Fatalf("an empty KRL: %+v", r)
		}
	})
	t.Run("catch_up_beyond_one_capture", func(t *testing.T) {
		t.Parallel()
		// A host more than spool.MaxVersionsPerKind directory versions
		// behind converges over several applies: each capture reads the
		// versions just above what it accepted, so the chain is never cut.
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		for range spool.MaxVersionsPerKind + 6 {
			h.publishDir(h.spec("role:ops"))
		}
		total := uint64(len(h.dirs))
		r := h.mustApply()
		if r.DirectoryVersion != 1+spool.MaxVersionsPerKind {
			t.Fatalf("first apply reached directory version %d, want %d", r.DirectoryVersion, 1+spool.MaxVersionsPerKind)
		}
		if r = h.mustApply(); r.DirectoryVersion != total {
			t.Fatalf("second apply reached directory version %d, want %d", r.DirectoryVersion, total)
		}
		if r = h.mustApply(); !r.NoOp {
			t.Fatalf("third apply: %+v, want a no-op", r)
		}
	})
	t.Run("render_once_from_newest", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		gens := h.genCount()
		h.publishDir(h.spec("role:ops", "role:a"))
		h.publishDir(h.spec("role:ops", "role:a", "role:b"))
		h.publishDir(h.spec("role:ops", "role:a", "role:b", "role:c"))
		r := h.mustApply()
		if r.DirectoryVersion != 4 || h.genCount() != gens+1 || !slices.Equal(h.principals("deploy"), []string{"role:a", "role:b", "role:c", "role:ops"}) {
			t.Fatalf("three versions behind: %+v, %d generations (was %d)", r, h.genCount(), gens)
		}
	})

	// --- candidate checks ---
	t.Run("ca_line_rejected_by_keygen_not_installed", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		cur, gens := h.current(), h.genCount()
		machine := trust.FormatKey(h.f.mach.PublicKey())
		h.run.rejectCA = func(line string) bool { return line == machine }
		h.publishKRL(7)
		if _, err := h.apply(); !errors.Is(err, ErrCALineRejected) || h.current() != cur || h.genCount() != gens {
			t.Fatalf("a CA line ssh-keygen refuses: %v, current %d, %d gens", err, h.current(), h.genCount())
		}
	})
	t.Run("keygen_query_error_not_installed", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		cur := h.current()
		h.run.queryCode = 255
		h.publishKRL(7)
		if _, err := h.apply(); !errors.Is(err, ErrKRLRejected) || h.current() != cur {
			t.Fatalf("ssh-keygen -Q refusing the KRL: %v", err)
		}
	})
	t.Run("krl_drops_key_entry_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		v, files := h.f.krl(nil, []ssh.PublicKey{h.f.mach.PublicKey()}, "")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		h.mustApply()
		cur := h.current()
		v, files = h.f.krl([]uint64{7}, nil, "")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		if _, err := h.apply(); !errors.Is(err, ErrKRLDropsKeyEntry) || h.current() != cur {
			t.Fatalf("a KRL that drops an explicit key: %v", err)
		}
	})

	// --- self-test and rollback ---
	t.Run("sshd_t_failure_rolls_back_dropin", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		cur := h.current()
		// Someone removed the drop-in: the next apply writes it again, and
		// sshd -t refuses the result.
		if err := os.Remove(h.l.DropIn()); err != nil {
			t.Fatal(err)
		}
		h.run.sshdTestErr = "/etc/ssh/sshd_config line 1: Bad configuration option"
		h.publishKRL(7)
		r, err := h.apply()
		if !errors.Is(err, ErrSSHDTest) || !r.Rollback || h.current() != cur || h.exists(h.l.DropIn()) || readMarker(t, h) != nil {
			t.Fatalf("sshd -t failure: %+v, %v, current %d, drop-in %t", r, err, h.current(), h.exists(h.l.DropIn()))
		}
	})
	t.Run("selftest_failure_rolls_back", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		cur := h.current()
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.stop()
		start := h.clock.Boottime()
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		r, err := h.apply()
		if !errors.Is(err, ErrSelfTest) || !r.Rollback || h.current() != cur || h.lastGood() != cur || readMarker(t, h) != nil {
			t.Fatalf("self-test failure: %+v, %v", r, err)
		}
		// B removes role:old and adds role:q: forward and back both pass an
		// intermediate, each with a full wait.
		if waited := h.clock.Boottime() - start; waited < 2*125*time.Second {
			t.Fatalf("forward and rollback waited %v together, want two LoginGraceTime + 5 s waits", waited)
		}
		if !slices.Equal(h.principals("deploy"), []string{"role:old", "role:ops"}) {
			t.Fatalf("principals after the rollback = %v", h.principals("deploy"))
		}
	})
	t.Run("first_install_selftest_failure_removes_dropin", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.stop()
		h.publishDir(h.spec("role:ops"))
		r, err := h.apply()
		if !errors.Is(err, ErrFirstInstallFailed) || !r.Rollback || h.exists(h.l.DropIn()) || h.exists(h.l.Current()) || readMarker(t, h) != nil {
			t.Fatalf("first install failure: %+v, %v", r, err)
		}
		if h.run.reloads != 2 {
			t.Fatalf("%d reloads, want 2 (install and undo)", h.run.reloads)
		}
	})
	t.Run("selftest_handshake_deadline", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.sshd.setStall(true)
		e := h.engine()
		e.cfg.SelfTestTimeout = 200 * time.Millisecond
		start := time.Now()
		err := e.selfTest(context.Background(), ParseDump([]byte(h.run.dump())), []ssh.PublicKey{h.sshd.pub})
		if !errors.Is(err, ErrSelfTest) || time.Since(start) > time.Second {
			t.Fatalf("a stalled sshd: %v after %v, want a failure within 1 s", err, time.Since(start))
		}
	})
	t.Run("non_loopback_listener_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.run.listen = []string{"192.0.2.10:22", "[2001:db8::1]:22"}
		h.publishDir(h.spec("role:ops"))
		if _, err := h.apply(); !errors.Is(err, ErrNoLoopbackListener) {
			t.Fatalf("sshd only on non-loopback addresses: %v, want no_loopback_listener", err)
		}
		// PR #67 review: refused before the drop-in is written, so sshd is
		// never reloaded for a host the self-test cannot reach.
		if h.run.reloads != 0 || h.exists(h.l.DropIn()) || h.exists(h.l.Current()) || readMarker(t, h) != nil {
			t.Fatalf("after the refusal: %d reloads, drop-in %t, current %t", h.run.reloads, h.exists(h.l.DropIn()), h.exists(h.l.Current()))
		}
		if got, err := loopbackTargets(ParseDump([]byte("listenaddress 0.0.0.0:2222\nlistenaddress [::]:2222\nlistenaddress 192.0.2.20:22\n"))); err != nil || !slices.Equal(got, []string{"127.0.0.1:2222", "[::1]:2222"}) {
			t.Fatalf("wildcards: %v, %v", got, err)
		}
	})

	// --- two-step swap and timing rule ---
	t.Run("two_step_order_and_wait", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		type swapAt struct {
			at       time.Duration
			step     string
			accepted int
		}
		var swaps []swapAt
		fl := &faultLog{onHit: func(p string) {
			if p == "swap" {
				m := readMarker(t, h)
				h.sshd.mu.Lock()
				swaps = append(swaps, swapAt{h.clock.Boottime(), m.Step, h.sshd.accepted})
				h.sshd.mu.Unlock()
			}
		}}
		h.cfg.Fault = fl.hook
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		before := h.sshd.accepted
		h.mustApply()
		if len(swaps) != 2 || swaps[0].step != "intermediate" || swaps[1].step != "final" {
			t.Fatalf("swaps %+v, want the intermediate step then the final one", swaps)
		}
		if gap := swaps[1].at - swaps[0].at; gap < 125*time.Second {
			t.Fatalf("%v between the swaps, want at least LoginGraceTime + 5 s", gap)
		}
		if swaps[1].accepted != before || h.sshd.accepted == before {
			t.Fatalf("self-test connections: %d before, %d at the final swap, %d after; want the self-test only after the final swap", before, swaps[1].accepted, h.sshd.accepted)
		}
	})
	t.Run("login_grace_read_from_sshd_T", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		h.run.grace = "7"
		h.installed("role:ops")
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		if r := h.mustApply(); r.LoginGraceS != 7 || r.WaitedMS != 12000 {
			t.Fatalf("logingracetime 7: %+v, want a 12 s wait", r)
		}
	})
	t.Run("login_grace_unbounded_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.run.grace = "0"
		h.publishDir(h.spec("role:ops"))
		before, _ := os.ReadDir(h.l.StateDir)
		if _, err := h.apply(); !errors.Is(err, ErrLoginGraceUnbounded) {
			t.Fatalf("logingracetime 0: %v, want login_grace_unbounded", err)
		}
		after, _ := os.ReadDir(h.l.StateDir)
		if len(after) != len(before) || h.exists(h.l.KeyrosterDir()) {
			t.Fatalf("the refusal wrote: state %v -> %v", before, after)
		}
	})
	t.Run("login_grace_unknown_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.run.grace = "2m"
		h.publishDir(h.spec("role:ops"))
		if _, err := h.apply(); !errors.Is(err, ErrLoginGraceUnknown) {
			t.Fatalf("logingracetime 2m: %v, want login_grace_unknown", err)
		}
	})
	t.Run("narrowing_swap_immediate", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(10 * time.Second)
		start := h.clock.Boottime()
		h.publishKRL(7)
		if r := h.mustApply(); r.WaitedMS != 0 || h.clock.Boottime() != start {
			t.Fatalf("a revocation 10 s after a swap waited: %+v", r)
		}
	})
	t.Run("widening_swap_waits_since_last_swap", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		h.publishKRL(7)
		h.mustApply()
		t0 := h.clock.Boottime()
		h.clock.advance(60 * time.Second)
		h.publishDir(h.spec("role:ops", "role:q"))
		r := h.mustApply()
		if got := h.clock.Boottime() - t0; got != 125*time.Second || r.Intermediate != 0 || r.WaitedMS != 125000 {
			t.Fatalf("an add-only apply 60 s after a revocation swapped %v after it (%+v), want 125 s", got, r)
		}
	})
	t.Run("last_swap_survives_restart", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		h.publishKRL(7)
		h.mustApply()
		t0 := h.clock.Boottime()
		var rec swapRecord
		b, err := os.ReadFile(h.l.State(lastSwapFile)) //nolint:gosec // test fixture
		if err != nil || json.Unmarshal(b, &rec) != nil || rec.BootID != "boot-1" || time.Duration(rec.BoottimeNS) != t0 || rec.Generation != uint64(h.current()) {
			t.Fatalf("last_swap.json = %s (%v)", b, err)
		}
		// Each Apply is a fresh engine: the record alone carries the time.
		h.clock.advance(100 * time.Second)
		h.publishDir(h.spec("role:ops", "role:q"))
		h.mustApply()
		if got := h.clock.Boottime() - t0; got != 125*time.Second {
			t.Fatalf("after a restart the widening swap came %v after the last one, want 125 s", got)
		}
	})
	t.Run("other_boot_no_wait", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.publishKRL(7)
		h.mustApply()
		h.clock.mu.Lock()
		h.clock.boot = "boot-2"
		h.clock.mu.Unlock()
		start := h.clock.Boottime()
		h.publishDir(h.spec("role:ops", "role:q"))
		if r := h.mustApply(); r.WaitedMS != 0 || h.clock.Boottime() != start {
			t.Fatalf("another boot waited: %+v", r)
		}
	})
	t.Run("pending_marker_means_full_wait", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		cur := uint64(h.current())
		b := mustCanonical(t, marker{From: cur, To: cur, Step: "final", Deadline: "2026-10-26T12:00:00Z"})
		if err := os.WriteFile(h.l.State(pendingFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		start := h.clock.Boottime()
		h.publishDir(h.spec("role:ops", "role:q"))
		r := h.mustApply()
		if got := h.clock.Boottime() - start; !r.Recovered || got != 125*time.Second {
			t.Fatalf("a run that starts with a pending marker waited %v (%+v), want the full 125 s", got, r)
		}
	})

	// --- monotone swaps ---
	t.Run("widening_swap_with_other_krl_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		e := h.engine()
		_, files := h.f.krl([]uint64{9}, nil, "")
		g := h.gen(e, files.KRL, "role:ops", "role:q")
		cur := h.current()
		if err := e.swapCurrent(context.Background(), g, swapChecked); !errors.Is(err, ErrSwapNotMonotone) || h.current() != cur {
			t.Fatalf("a widening swap that changes the KRL: %v, current %d", err, h.current())
		}
	})
	t.Run("swap_adding_and_removing_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		e := h.engine()
		g := h.gen(e, nil, "role:q")
		cur := h.current()
		if err := e.swapCurrent(context.Background(), g, swapChecked); !errors.Is(err, ErrSwapNotMonotone) || h.current() != cur {
			t.Fatalf("a swap that adds and removes: %v", err)
		}
	})
	t.Run("narrowing_swap_may_change_krl", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops", "role:q")
		e := h.engine()
		_, files := h.f.krl([]uint64{9}, nil, "")
		g := h.gen(e, files.KRL, "role:ops")
		start := h.clock.Boottime()
		if err := e.swapCurrent(context.Background(), g, swapChecked); err != nil || uint64(h.current()) != g.N || h.clock.Boottime() != start {
			t.Fatalf("a narrowing swap with a new KRL: %v, current %d", err, h.current())
		}
	})

	// --- the LoginGraceTime bound ---
	t.Run("login_grace_max_kept_after_lowering", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.run.grace = "600"
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		h.publishKRL(7)
		h.mustApply()
		h.run.grace = "120" // lowered on disk, no reload by the agent
		t0 := h.clock.Boottime()
		h.publishDir(h.spec("role:ops", "role:q"))
		r := h.mustApply()
		if got := h.clock.Boottime() - t0; r.LoginGraceS != 600 || got != 605*time.Second {
			t.Fatalf("after lowering to 120 without a reload: bound %d, waited %v; want 600 and 605 s", r.LoginGraceS, got)
		}
	})
	t.Run("login_grace_prev_max_until_own_reload_window_ends", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		e := h.engine()
		if b, _ := e.observeLoginGrace(600, false); b != 600 {
			t.Fatalf("bound %d", b)
		}
		if b, _ := e.observeLoginGrace(120, true); b != 600 {
			t.Fatalf("right after the agent's own reload at 120: bound %d, want 600", b)
		}
		h.clock.advance(604 * time.Second)
		if b, _ := e.observeLoginGrace(120, false); b != 600 {
			t.Fatalf("604 s after the reload: bound %d, want 600", b)
		}
		h.clock.advance(2 * time.Second)
		if b, _ := e.observeLoginGrace(120, false); b != 120 {
			t.Fatalf("606 s after the reload: bound %d, want 120", b)
		}
	})
	t.Run("login_grace_raised_used_at_once", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		e := h.engine()
		_, _ = e.observeLoginGrace(120, false)
		if b, _ := e.observeLoginGrace(300, false); b != 300 {
			t.Fatalf("raised to 300: bound %d", b)
		}
		fd, _ := spool.OpenDir(h.l.StateDir)
		defer func() { _ = unix.Close(fd) }()
		if b, err := ObserveLoginGrace(h.l, h.clock, fd, 120); err != nil || b != 300 {
			t.Fatalf("ObserveLoginGrace(120) after 300: %d, %v; want 300", b, err)
		}
	})
	t.Run("last_swap_records_bound", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.run.grace = "450"
		h.installed("role:ops")
		var rec swapRecord
		b, _ := os.ReadFile(h.l.State(lastSwapFile)) //nolint:gosec // test fixture
		if json.Unmarshal(b, &rec) != nil || rec.LoginGrace != 450 {
			t.Fatalf("last_swap.json = %s, want login_grace_s 450", b)
		}
	})

	// --- crash recovery ---
	crashRun := func(h *testHost, k int) (*Report, error) {
		fl := &faultLog{k: k}
		h.cfg.Fault = fl.hook
		defer func() { h.cfg.Fault = nil }()
		return h.apply()
	}
	t.Run("crash_at_intermediate_back_through_transition", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		lg := h.current()
		old := h.state
		h.state = cloneState(old)
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		// Fault points of the forward move: marker, swap (to M), marker,
		// swap (to B). Crash at the final swap: current names M.
		if _, err := crashRun(h, 4); !isCrash(err) || readMarker(t, h).Step != "final" {
			t.Fatalf("crash: %v", err)
		}
		mid := h.current()
		if mid == lg {
			t.Fatal("current did not move to the intermediate")
		}
		h.resetSpool()
		h.state = old
		start := h.clock.Boottime()
		r := h.mustApply()
		if !r.Recovered || h.current() != lg || readMarker(t, h) != nil {
			t.Fatalf("recovery: %+v, current %d", r, h.current())
		}
		if got := h.clock.Boottime() - start; got < 125*time.Second {
			t.Fatalf("recovery's widening step came %v after start, want the full interval", got)
		}
	})
	t.Run("crash_during_recovery_transition", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		lg := h.current()
		old := h.state
		h.state = cloneState(old)
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		if _, err := crashRun(h, 4); !isCrash(err) {
			t.Fatal(err)
		}
		h.resetSpool()
		h.state = old
		// Recovery: Transition(M, L) = marker, swap (to M_r), marker, swap.
		// Crash at its final swap: current names M_r.
		if _, err := crashRun(h, 4); !isCrash(err) {
			t.Fatalf("crash in recovery: %v", err)
		}
		if h.current() == lg {
			t.Fatal("recovery did not stop at its intermediate")
		}
		r, err := h.apply()
		if err != nil || errors.Is(err, ErrPendingStateUnknown) || h.current() != lg || readMarker(t, h) != nil || !r.Recovered {
			t.Fatalf("second recovery: %+v, %v, current %d", r, err, h.current())
		}
	})
	t.Run("crash_during_rollback_transition", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		lg := h.current()
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.stop()
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		// Forward: marker, swap, marker, swap, self-test; then rollback:
		// marker, swap (to M'), marker <- crash.
		if _, err := crashRun(h, 8); !isCrash(err) {
			t.Fatalf("crash in rollback: %v", err)
		}
		if h.current() == lg {
			t.Fatal("the rollback did not reach its intermediate")
		}
		h.resetSpool()
		h.state = h.f.genesis()
		h.state.Directories[1] = h.dirs[0]
		r, err := h.apply()
		if err != nil || h.current() != lg || readMarker(t, h) != nil || !r.Recovered {
			t.Fatalf("recovery of a crashed rollback: %+v, %v", r, err)
		}
	})
	t.Run("crash_anywhere_recovers", func(t *testing.T) {
		t.Parallel()
		// Fault injection at every durable step of every planned
		// sequence (a forward two-step move, a collapsed swap, a rollback,
		// and recovery itself, nested two levels deep): repeated recovery
		// always ends at last-good, or at the target once the crash came
		// after the commit, never pending_state_unknown (checker
		// iteration 2).
		type sequence struct {
			name     string
			selfFail bool
			change   func(h *testHost)
		}
		seqs := []sequence{
			{"two_step", false, func(h *testHost) { h.publishKRL(7); h.publishDir(h.spec("role:ops", "role:q")) }},
			{"collapsed", false, func(h *testHost) { h.publishKRL(7) }},
			{"rollback", true, func(h *testHost) { h.publishKRL(7); h.publishDir(h.spec("role:ops", "role:q")) }},
		}
		for _, seq := range seqs {
			t.Run(seq.name, func(t *testing.T) {
				t.Parallel()
				runs := 0
				crashRun := func(h *testHost, k int) (*Report, error) {
					fl := &faultLog{k: k}
					h.cfg.Fault = fl.hook
					defer func() { h.cfg.Fault = nil }()
					return h.apply()
				}
				for k := 1; ; k++ {
					done := false
					for j := 0; j <= 8; j++ {
						h := newTestHost(t, newFixture(t))
						h.installed("role:old", "role:ops")
						lg := h.current()
						if seq.selfFail {
							h.cfg.SelfTestTimeout = 100 * time.Millisecond
							h.sshd.stop()
						}
						seq.change(h)
						_, err := crashRun(h, k)
						if !isCrash(err) {
							done = true // k is past the sequence's last fault point
							break
						}
						target := h.current()
						// Recovery alone: the spool offers nothing newer, so
						// no run after it moves forward again.
						h.resetSpool()
						h.state = h.f.genesis()
						nested := false
						if j > 0 {
							_, err := crashRun(h, j)
							if err != nil && !isCrash(err) {
								t.Fatalf("%s k=%d j=%d: second run: %v", seq.name, k, j, err)
							}
							nested = isCrash(err)
						}
						_, err = h.apply()
						runs++
						if errors.Is(err, ErrPendingStateUnknown) {
							t.Fatalf("%s k=%d j=%d: pending_state_unknown", seq.name, k, j)
						}
						if readMarker(t, h) != nil || h.current() != h.lastGood() || (h.current() != lg && h.current() != target) {
							t.Fatalf("%s k=%d j=%d: current %d, last-good %d (was %d, crash target %d), marker %+v, err %v", seq.name, k, j, h.current(), h.lastGood(), lg, target, readMarker(t, h), err)
						}
						if j > 0 && !nested {
							break // the recovery run has no j-th fault point
						}
					}
					if done {
						break
					}
				}
				t.Logf("%s: %d crash-and-recover runs", seq.name, runs)
			})
		}
	})
	t.Run("foreign_layout_stuck_alert", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		foreign := t.TempDir()
		if err := os.WriteFile(filepath.Join(foreign, KRLFile), nil, 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		repoint(t, h.l.Current(), foreign)
		h.publishKRL(7)
		r, err := h.apply()
		if !errors.Is(err, ErrPendingStateUnknown) || r.Stuck != "pending_state_unknown" {
			t.Fatalf("a foreign current: %+v, %v", r, err)
		}
		if target, _ := os.Readlink(h.l.Current()); target != foreign {
			t.Fatalf("current was swapped: %s", target)
		}
		var st struct {
			Stuck string `json:"stuck"`
		}
		b, _ := os.ReadFile(h.l.State(statusFile)) //nolint:gosec // test fixture
		if json.Unmarshal(b, &st) != nil || st.Stuck != "pending_state_unknown" {
			t.Fatalf("status.json = %s", b)
		}
	})
	t.Run("recover_to_last_good_flag", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		repoint(t, h.l.LastGood(), "gen/999")
		h.cfg.RecoverToLastGood = true
		if _, err := h.apply(); !errors.Is(err, ErrLastGoodInvalid) {
			t.Fatalf("a dangling last-good: %v, want last_good_invalid", err)
		}
	})
	t.Run("recover_dangling_current", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		lg := h.current()
		repoint(t, h.l.Current(), "gen/999")
		if _, err := h.apply(); !errors.Is(err, ErrPendingStateUnknown) {
			t.Fatalf("a dangling current: %v", err)
		}
		h.cfg.RecoverToLastGood = true
		start := h.clock.Boottime()
		r, err := h.apply()
		if err != nil || h.current() != lg || r.Stuck != "" || h.clock.Boottime() != start {
			t.Fatalf("recover: %+v, %v", r, err)
		}
		h.cfg.RecoverToLastGood = false
		if _, err := h.apply(); err != nil {
			t.Fatalf("the next ordinary apply: %v", err)
		}
	})
	t.Run("recover_missing_krl_current", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		lg := h.current()
		foreign := t.TempDir()
		if err := os.WriteFile(filepath.Join(foreign, CAFile), []byte(trust.FormatKey(h.f.mach.PublicKey())+"\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		repoint(t, h.l.Current(), foreign)
		h.cfg.RecoverToLastGood = true
		start := h.clock.Boottime()
		if _, err := h.apply(); err != nil || h.current() != lg || h.clock.Boottime() != start {
			t.Fatalf("recover from a current without revoked.krl: %v, current %d", err, h.current())
		}
	})
	t.Run("recover_foreign_readable_current_via_intermediate", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		lg := h.current()
		// X lacks role:old, which last-good has, and has another KRL:
		// neither a narrowing nor a widening swap reaches last-good alone.
		foreign := copyGen(t, h.l.Gen(uint64(lg)), func(dir string) {
			_, files := h.f.krl([]uint64{9}, nil, "")
			writeFile(t, filepath.Join(dir, KRLFile), files.KRL)
			writeFile(t, filepath.Join(dir, PrincipalsDir, "deploy"), []byte("role:ops\n"))
		})
		repoint(t, h.l.Current(), foreign)
		h.cfg.RecoverToLastGood = true
		start := h.clock.Boottime()
		r, err := h.apply()
		if err != nil || h.current() != lg || r.Stuck != "" {
			t.Fatalf("recover from a readable foreign current: %+v, %v", r, err)
		}
		if got := h.clock.Boottime() - start; got < 125*time.Second {
			t.Fatalf("recovery reached last-good %v after start, want the widening step after the bound", got)
		}
	})
	t.Run("recover_foreign_adds_and_removes", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		lg := h.current()
		foreign := copyGen(t, h.l.Gen(uint64(lg)), func(dir string) {
			ca, _ := os.ReadFile(filepath.Join(dir, CAFile)) //nolint:gosec // test fixture
			writeFile(t, filepath.Join(dir, CAFile), append(ca, []byte(trust.FormatKey(h.f.host.PublicKey())+"\n")...))
			writeFile(t, filepath.Join(dir, PrincipalsDir, "deploy"), []byte("role:ops\n"))
		})
		repoint(t, h.l.Current(), foreign)
		h.cfg.RecoverToLastGood = true
		if r, err := h.apply(); err != nil || h.current() != lg || errors.Is(err, ErrSwapNotMonotone) {
			t.Fatalf("recover from a foreign current that adds a CA key and drops a principal: %+v, %v", r, err)
		}
	})
	t.Run("crash_after_final_swap_two_step_back", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		lg := h.current()
		old := cloneState(h.state)
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		// marker, swap, marker, swap, self-test <- crash: current names B.
		if _, err := crashRun(h, 5); !isCrash(err) {
			t.Fatal(err)
		}
		h.resetSpool()
		h.state = old
		start := h.clock.Boottime()
		if r := h.mustApply(); !r.Rollback || h.current() != lg {
			t.Fatalf("recovery from B: %+v", r)
		}
		if got := h.clock.Boottime() - start; got < 125*time.Second {
			t.Fatalf("B -> L took %v, want a two-step move with a full wait", got)
		}
	})
	t.Run("crash_between_final_marker_and_swap", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		lg := h.current()
		old := cloneState(h.state)
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		if _, err := crashRun(h, 4); !isCrash(err) {
			t.Fatal(err)
		}
		if m := readMarker(t, h); m.Step != "final" || uint64(h.current()) != m.Intermediate {
			t.Fatalf("marker %+v, current %d", m, h.current())
		}
		h.resetSpool()
		h.state = old
		if r := h.mustApply(); !r.Recovered || h.current() != lg {
			t.Fatalf("recovery from M: %+v", r)
		}
	})
	t.Run("crash_in_rollback_intermediate_waits_then_last_good", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:old", "role:ops")
		lg := h.current()
		old := cloneState(h.state)
		h.cfg.SelfTestTimeout = 100 * time.Millisecond
		h.sshd.stop()
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		if _, err := crashRun(h, 8); !isCrash(err) {
			t.Fatal(err)
		}
		h.resetSpool()
		h.state = old
		start := h.clock.Boottime()
		if r, _ := h.apply(); h.current() != lg || !r.Recovered {
			t.Fatalf("recovery from the rollback's intermediate: %+v, current %d", r, h.current())
		}
		if got := h.clock.Boottime() - start; got < 125*time.Second {
			t.Fatalf("M' -> L took %v, want the full interval", got)
		}
	})
	t.Run("crash_after_swap_rolled_back_on_start", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		lg := h.current()
		old := cloneState(h.state)
		h.publishKRL(7)
		// Collapsed: marker, swap, self-test <- crash (killed before the
		// self-test).
		if _, err := crashRun(h, 3); !isCrash(err) || readMarker(t, h) == nil || h.current() == lg {
			t.Fatalf("crash: %v", err)
		}
		h.resetSpool()
		h.state = old
		if r := h.mustApply(); !r.Recovered || h.current() != lg || readMarker(t, h) != nil {
			t.Fatalf("start after a killed run: %+v", r)
		}
	})
	t.Run("crash_during_first_install_recovered", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.publishDir(h.spec("role:ops"))
		// marker, swap, marker (dropin_changed), dropin, reload <- crash:
		// drop-in written, sshd not reloaded.
		if _, err := crashRun(h, 5); !isCrash(err) || !h.exists(h.l.DropIn()) {
			t.Fatalf("crash: %v", err)
		}
		if m := readMarker(t, h); m == nil || m.From != 0 || !m.DropInChanged {
			t.Fatalf("marker %+v", m)
		}
		h.resetSpool()
		h.state = h.f.genesis() // nothing to install: recovery alone
		r, _ := h.apply()
		if !r.Recovered || !r.Rollback || h.exists(h.l.DropIn()) || h.exists(h.l.Current()) || readMarker(t, h) != nil {
			t.Fatalf("first-install recovery: %+v", r)
		}
	})

	// --- PR #57 review ---
	t.Run("revocation_during_widening_wait_applied_at_once", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		h.publishKRL(7)
		h.mustApply() // a swap just now: the add-only apply must wait
		h.publishDir(h.spec("role:ops", "role:q"))
		var wrote time.Duration
		var revokedAt time.Duration = -1
		h.clock.onSleep = func(time.Duration) {
			if wrote == 0 {
				wrote = h.clock.Boottime()
				h.publishKRL(7, 99)
				h.write()
			}
		}
		fl := &faultLog{onHit: func(p string) {
			if p != "swap" || revokedAt >= 0 {
				return
			}
			if m := readMarker(t, h); m != nil && m.Intermediate != 0 && m.Step == "intermediate" && h.krlRevokes(h.l.Gen(m.Intermediate), 99) {
				revokedAt = h.clock.Boottime()
			}
		}}
		h.cfg.Fault = fl.hook
		t0 := h.clock.Boottime()
		h.mustApply()
		if revokedAt < 0 || revokedAt-wrote > 5*time.Second {
			t.Fatalf("the revocation arrived at %v and was swapped in at %v; want within one poll", wrote-t0, revokedAt-t0)
		}
		if !h.krlRevokes(h.l.Current(), 99) || !slices.Equal(h.principals("deploy"), []string{"role:ops", "role:q"}) {
			t.Fatal("B2 (the revocation and role:q) is not current")
		}
		if h.clock.Boottime()-revokedAt < 125*time.Second {
			t.Fatalf("B2's widening swap came %v after its narrowing step", h.clock.Boottime()-revokedAt)
		}
	})
	t.Run("collapse_with_real_render_headers", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		start := h.clock.Boottime()
		h.publishDir(h.spec("role:ops", "role:q"))
		if r := h.mustApply(); r.Intermediate != 0 || h.clock.Boottime() != start {
			t.Fatalf("a pure addition after a quiet period: %+v, want one immediate swap", r)
		}
		h.publishKRL(7)
		if r := h.mustApply(); r.Intermediate != 0 {
			t.Fatalf("a pure revocation: %+v", r)
		}
		// An absent principals file equals a header-only one.
		header := []byte("# keyroster: generated AuthorizedPrincipalsFile; do not edit\n# host group lab, account x\n")
		from := &Generation{Files: map[string][]byte{KRLFile: nil, CAFile: []byte("")}}
		to := &Generation{Files: map[string][]byte{KRLFile: nil, CAFile: []byte(""), PrincipalsDir + "/x": header}}
		if _, collapsed := Intermediate(from, to); !collapsed {
			t.Fatal("absent and header-only principals files differ in classified content")
		}
	})

	// --- retention and state ---
	t.Run("cleanup_keeps_current_last_good_and_pending", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		e := h.engine()
		for range 9 {
			h.gen(e, nil, "role:ops")
		}
		repoint(t, h.l.LastGood(), paths.GenLink(3))
		repoint(t, h.l.Current(), paths.GenLink(4))
		b := mustCanonical(t, marker{From: 4, To: 6, Intermediate: 5, Step: "final", Deadline: "2026-10-26T12:00:00Z"})
		if err := os.WriteFile(h.l.State(pendingFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		e.cleanup()
		for _, n := range []uint64{3, 4, 5, 6, 7, 8, 9, 10} {
			if !h.exists(h.l.Gen(n)) {
				t.Fatalf("generation %d was removed", n)
			}
		}
		for _, n := range []uint64{1, 2} {
			if h.exists(h.l.Gen(n)) || h.exists(h.l.State(generationsDir, recordName(n))) {
				t.Fatalf("generation %d was kept", n)
			}
		}
	})
	t.Run("concurrent_apply_serialised", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.clock.advance(time.Hour)
		h.publishKRL(7)
		h.mustApply()
		h.publishDir(h.spec("role:ops", "role:q"))
		h.write()
		second := make(chan *Report, 1)
		started := false
		h.clock.onSleep = func(time.Duration) {
			if started {
				return
			}
			started = true
			go func() {
				cfg := h.cfg
				cfg.Fault = nil
				r, _ := Apply(context.Background(), cfg, h.l)
				second <- r
			}()
			select {
			case <-second:
				t.Error("the second apply finished while the first held the lock")
			case <-time.After(300 * time.Millisecond):
			}
		}
		if _, err := Apply(context.Background(), h.cfg, h.l); err != nil {
			t.Fatal(err)
		}
		if r := <-second; r == nil || !r.NoOp {
			t.Fatalf("the second apply after the first: %+v, want an equal-version no-op", r)
		}
	})
	t.Run("state_dir_group_writable_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		if err := os.Chmod(h.l.StateDir, 0o770); err != nil { //nolint:gosec // the refusal under test
			t.Fatal(err)
		}
		h.publishDir(h.spec("role:ops"))
		if _, err := h.apply(); !errors.Is(err, ErrStateDirUnsafe) {
			t.Fatalf("a group-writable state directory: %v", err)
		}
	})
	t.Run("state_dir_symlink_refused", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		link := filepath.Join(t.TempDir(), "state-link")
		if err := os.Symlink(h.l.StateDir, link); err != nil {
			t.Fatal(err)
		}
		h.l.StateDir = link
		h.publishDir(h.spec("role:ops"))
		if _, err := h.apply(); !errors.Is(err, ErrStateDirUnsafe) {
			t.Fatalf("a symlinked state directory: %v", err)
		}
	})
	t.Run("spool_replaced_after_read_not_installed", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		v, files := h.f.krl([]uint64{7}, nil, "")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		_, other := h.f.krl([]uint64{7, 8, 9}, nil, "")
		h.run.onQuery = func() {
			// The fetcher replaces the KRL while the applier validates.
			writeFile(t, filepath.Join(h.spool, fmt.Sprintf("krl-%d.krl", v)), other.KRL)
		}
		h.mustApply()
		if h.file(KRLFile) != string(files.KRL) {
			t.Fatal("the installed KRL is not the verified one")
		}
	})
}

func cloneState(s spool.State) spool.State {
	c := spool.State{Bundles: map[uint64]spool.Doc{}, Policies: map[uint64]spool.Doc{}, Directories: map[uint64]spool.Doc{}, KRLs: map[uint64]spool.KRLFiles{}}
	for k, v := range s.Bundles {
		c.Bundles[k] = v
	}
	for k, v := range s.Policies {
		c.Policies[k] = v
	}
	for k, v := range s.Directories {
		c.Directories[k] = v
	}
	for k, v := range s.KRLs {
		c.KRLs[k] = v
	}
	return c
}

// repoint replaces the link at path with one to target.
func repoint(t *testing.T, path, target string) {
	t.Helper()
	_ = os.Remove(path)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}

// copyGen copies a generation directory to a new directory outside gen/
// and lets edit change it.
func copyGen(t *testing.T, from string, edit func(dir string)) string {
	t.Helper()
	dir := t.TempDir()
	g, err := readGeneration(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, PrincipalsDir), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	for name, b := range g.Files {
		writeFile(t, filepath.Join(dir, name), b)
	}
	edit(dir)
	return dir
}

// TestGenerationModesUnderUmask (PR #67 review): sshd opens the
// AuthorizedPrincipalsFile as the target user, so the keyroster tree must
// be traversable and its files readable by everyone whatever the umask of
// the process that runs the applier. Not parallel: the umask is
// process-wide.
func TestGenerationModesUnderUmask(t *testing.T) {
	h := newTestHost(t, newFixture(t))
	old := unix.Umask(0o077)
	defer unix.Umask(old)
	h.installed("role:ops")
	gen := h.l.Gen(h.current())
	for path, want := range map[string]os.FileMode{
		h.l.KeyrosterDir():                0o755,
		h.l.GenDir():                      0o755,
		gen:                               0o755,
		filepath.Join(gen, PrincipalsDir): 0o755,
		filepath.Join(gen, PrincipalsDir, "deploy"): 0o644,
		filepath.Join(gen, CAFile):                  0o644,
		filepath.Join(gen, KRLFile):                 0o644,
		h.l.DropIn():                                0o644,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s has mode %04o under umask 077, want %04o", path, got, want)
		}
	}
}

// TestHostKeys (PR #67 review): sshd -T lists its default HostKey paths
// whether or not the keys exist, and sshd skips the missing ones; so does
// hostKeys. A key whose private half exists needs its .pub, and at least
// one key must be found.
func TestHostKeys(t *testing.T) {
	dir := t.TempDir()
	signer := seedKey(t, 9)
	ed := filepath.Join(dir, "ssh_host_ed25519_key")
	writeFile(t, ed, []byte("private key placeholder\n"))
	writeFile(t, ed+".pub", ssh.MarshalAuthorizedKey(signer.PublicKey()))
	dump := func(names ...string) Dump {
		var b strings.Builder
		for _, n := range names {
			b.WriteString("hostkey " + filepath.Join(dir, n) + "\n")
		}
		return ParseDump([]byte(b.String()))
	}
	keys, err := hostKeys(dump("ssh_host_rsa_key", "ssh_host_ecdsa_key", "ssh_host_ed25519_key"))
	if err != nil || len(keys) != 1 || !slices.Equal(keys[0].Marshal(), signer.PublicKey().Marshal()) {
		t.Fatalf("default paths with only the Ed25519 key present: %v, %v", keys, err)
	}
	if _, err := hostKeys(dump("ssh_host_rsa_key", "ssh_host_ecdsa_key")); err == nil {
		t.Fatal("no host key present: no error")
	}
	writeFile(t, filepath.Join(dir, "ssh_host_ecdsa_key"), []byte("private key placeholder\n"))
	if _, err := hostKeys(dump("ssh_host_ecdsa_key", "ssh_host_ed25519_key")); err == nil {
		t.Fatal("a present private key without its .pub: no error")
	}
}

// TestSelfTestLoopbackFamilies (PR #67 review): with the default
// AddressFamily any, sshd -T lists [::]:port beside 0.0.0.0:port even
// when IPv6 is disabled, so ::1 can be unreachable (EADDRNOTAVAIL with
// disable_ipv6 on lo, EAFNOSUPPORT without IPv6 in the kernel). An
// unreachable ::1 is skipped; every reachable target must pass, at least
// one must, and 127.0.0.1 is never skipped.
func TestSelfTestLoopbackFamilies(t *testing.T) {
	h := newTestHost(t, newFixture(t))
	port := strconv.Itoa(h.sshd.port)
	unavailable := func(errno syscall.Errno) func(ctx context.Context, network, addr string) (net.Conn, error) {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			if strings.HasPrefix(addr, "[::1]") || strings.HasPrefix(addr, "127.0.0.9") {
				return nil, &net.OpError{Op: "dial", Net: network, Err: os.NewSyscallError("connect", errno)}
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}
	}
	run := func(listen []string, dial func(context.Context, string, string) (net.Conn, error), v6off bool) error {
		e := h.engine()
		e.cfg.SelfTestTimeout = 500 * time.Millisecond
		e.dial, e.ipv6Off = dial, func() bool { return v6off }
		var b strings.Builder
		for _, l := range listen {
			b.WriteString("listenaddress " + l + "\n")
		}
		return e.selfTest(context.Background(), ParseDump([]byte(b.String())), []ssh.PublicKey{h.sshd.pub})
	}
	both := []string{"[::]:" + port, "0.0.0.0:" + port}
	for _, errno := range []syscall.Errno{syscall.EADDRNOTAVAIL, syscall.EAFNOSUPPORT} {
		if err := run(both, unavailable(errno), false); err != nil {
			t.Errorf("[::] and 0.0.0.0 with ::1 failing %v: %v, want a pass on 127.0.0.1", errno, err)
		}
	}
	hang := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "[::1]") {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	if err := run(both, hang, true); err != nil {
		t.Errorf("IPv6 disabled on lo: %v, want ::1 not dialed and a pass", err)
	}
	if err := run([]string{"[::]:" + port}, unavailable(syscall.EADDRNOTAVAIL), false); !errors.Is(err, ErrSelfTest) {
		t.Errorf("only ::1, unreachable: %v, want self_test_failed (never a pass with no target)", err)
	}
	if err := run([]string{"[::]:" + port, "127.0.0.9:" + port}, unavailable(syscall.EADDRNOTAVAIL), false); !errors.Is(err, ErrSelfTest) {
		t.Errorf("EADDRNOTAVAIL on an IPv4 loopback target: %v, want self_test_failed", err)
	}
	h.sshd.stop()
	if err := run(both, unavailable(syscall.EADDRNOTAVAIL), false); !errors.Is(err, ErrSelfTest) {
		t.Errorf("::1 unreachable and nothing on 127.0.0.1: %v, want self_test_failed", err)
	}
}

// TestSelfTestIPv6DisabledHost runs the real dialer where IPv6 is
// disabled on lo; it is skipped elsewhere. Run it as root in a network
// namespace: unshare -n sh -c 'ip link set lo up; echo 1 >
// /proc/sys/net/ipv6/conf/lo/disable_ipv6; ./apply.test -test.run
// TestSelfTestIPv6DisabledHost -test.v'.
func TestSelfTestIPv6DisabledHost(t *testing.T) {
	if b, err := os.ReadFile("/proc/sys/net/ipv6/conf/lo/disable_ipv6"); err != nil || strings.TrimSpace(string(b)) != "1" {
		t.Skip("IPv6 is enabled on lo")
	}
	h := newTestHost(t, newFixture(t))
	port := strconv.Itoa(h.sshd.port)
	e := h.engine()
	e.ipv6Off = func() bool { return false } // dial ::1 for real: the kernel answers EADDRNOTAVAIL
	if err := e.selfTest(context.Background(), ParseDump([]byte("listenaddress [::]:"+port+"\nlistenaddress 0.0.0.0:"+port+"\n")), []ssh.PublicKey{h.sshd.pub}); err != nil {
		t.Fatalf("real dial with IPv6 disabled on lo: %v", err)
	}
}

// TestReloadSignal (PR #67 review): the signal strategy sends SIGHUP only
// to a process that runs the configured sshd binary; a PidFile naming
// another process (stale after sshd died and its PID was reused) is
// refused and that process is left alone.
func TestReloadSignal(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	dir := t.TempDir()
	sshd := filepath.Join(dir, "sshd")
	copyBin := func() {
		b, err := os.ReadFile(sleep) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(sshd)
		if err := os.WriteFile(sshd, b, 0o755); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	copyBin()
	pidFile := filepath.Join(dir, "sshd.pid")
	dump := ParseDump([]byte("pidfile " + pidFile + "\n"))
	start := func(bin string) (*exec.Cmd, chan error) {
		c := exec.Command(bin, "30") //nolint:gosec // test fixture
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- c.Wait() }()
		t.Cleanup(func() { _ = c.Process.Kill() })
		writeFile(t, pidFile, []byte(strconv.Itoa(c.Process.Pid)+"\n"))
		return c, done
	}
	hungUp := func(done chan error) bool {
		select {
		case err := <-done:
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGHUP {
					return true
				}
			}
			t.Fatalf("the process ended otherwise: %v", err)
		case <-time.After(500 * time.Millisecond):
		}
		return false
	}

	_, done := start(sleep)
	if err := reloadSignal(sshd, dump); !errors.Is(err, ErrReload) {
		t.Errorf("a PidFile naming a process that is not %s: %v, want reload_failed", sshd, err)
	}
	if hungUp(done) {
		t.Error("the process that is not sshd got SIGHUP")
	}

	_, done = start(sshd)
	if err := reloadSignal(sshd, dump); err != nil {
		t.Errorf("the configured sshd: %v", err)
	}
	if !hungUp(done) {
		t.Error("sshd did not get SIGHUP")
	}

	// An upgrade replaced the binary under a running sshd: /proc/<pid>/exe
	// names the old file, "(deleted)", at the configured path.
	_, done = start(sshd)
	copyBin()
	if err := reloadSignal(sshd, dump); err != nil {
		t.Errorf("sshd running a replaced binary: %v", err)
	}
	if !hungUp(done) {
		t.Error("sshd running a replaced binary did not get SIGHUP")
	}

	c, done := start(sshd)
	_ = c.Process.Kill()
	<-done
	if err := reloadSignal(sshd, dump); !errors.Is(err, ErrReload) {
		t.Errorf("a PidFile naming a process that has exited: %v, want reload_failed", err)
	}
}
