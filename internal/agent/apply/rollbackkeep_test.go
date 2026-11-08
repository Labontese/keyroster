//go:build linux

package apply

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// The tests of 03-10d, Task 1: once a removal has landed, no rollback of
// an in-flight apply, no start-up recovery and no fallback render grants
// it again (RollbackKeeping); only the operator's --recover-to-last-good
// goes to last-good (owner decision Q1 = A, 2026-11-08).

// krlBytes is an empty KRL of the given version (0: no KRL).
func krlBytes(t testing.TB, version uint64) []byte {
	t.Helper()
	if version == 0 {
		return nil
	}
	b, err := krl.Encode(krl.Set{}, version, time.Unix(int64(version), 0)) //nolint:gosec // G115: a test version
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// caLines are three CA key lines for the pure tests.
func caLines(t testing.TB) []string {
	t.Helper()
	return []string{trust.FormatKey(seedKey(t, 41).PublicKey()), trust.FormatKey(seedKey(t, 42).PublicKey()), trust.FormatKey(seedKey(t, 43).PublicKey())}
}

// pureGen is a generation N with the CA lines ca, deploy's principals and
// a KRL of version v (0: none), under header.
func pureGen(t testing.TB, n uint64, header string, v uint64, ca []string, principals ...string) *Generation {
	t.Helper()
	g := &Generation{N: n, Files: map[string][]byte{}}
	var c strings.Builder
	for _, l := range ca {
		c.WriteString(l + "\n")
	}
	g.Files[CAFile] = []byte(c.String())
	var p strings.Builder
	p.WriteString(header)
	for _, l := range principals {
		p.WriteString(l + "\n")
	}
	g.Files[PrincipalsDir+"/deploy"] = []byte(p.String())
	if b := krlBytes(t, v); b != nil {
		g.Files[KRLFile] = b
	}
	return g
}

const renderHeader = "# keyroster: generated AuthorizedPrincipalsFile; do not edit\n"

// deployLines is the non-comment lines of g's principals file for deploy,
// in file order.
func deployLines(g *Generation) []string {
	var out []string
	for _, l := range lines(g.Files[PrincipalsDir+"/deploy"]) {
		if k, ok := principalLine(l); ok {
			out = append(out, k)
		}
	}
	return out
}

func TestRollbackKeeping(t *testing.T) {
	ca := caLines(t)
	t.Run("pure_addition_over_last_good_base_is_last_good", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca[:2], "role:a", "role:b")
		cur := pureGen(t, 7, renderHeader, 1, ca[:2], "role:a", "role:b", "role:c")
		base := pureGen(t, 4, renderHeader, 1, ca[:2], "role:a", "role:b")
		got := RollbackKeeping(cur, lg, []*Generation{base})
		if want := RollbackTarget(cur, lg); !sameBytes(got, want) || got.N != lg.N {
			t.Fatalf("got N %d %q, want RollbackTarget N %d", got.N, got.Files, lg.N)
		}
	})
	t.Run("pure_addition_over_kept_base_is_base", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca[:2], "role:a", "role:c")
		base := pureGen(t, 5, intermediateHeader, 2, ca[:2], "role:a")
		cur := pureGen(t, 7, renderHeader, 2, ca[:2], "role:a", "role:c")
		got := RollbackKeeping(cur, lg, []*Generation{base})
		if !sameContent(got, base) || slices.Contains(deployLines(got), "role:c") || got.N != 0 {
			t.Fatalf("got N %d principals %v, want the base's content", got.N, deployLines(got))
		}
	})
	t.Run("pure_narrowing_stays", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca, "role:a", "role:b", "role:c")
		cur := pureGen(t, 7, renderHeader, 2, ca[:2], "role:a", "role:b")
		got := RollbackKeeping(cur, lg, []*Generation{lg})
		if !sameContent(got, cur) {
			t.Fatalf("got %v, want current's lines with the newest KRL", deployLines(got))
		}
	})
	t.Run("mixed_is_intersection", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca, "role:a", "role:b", "role:c")
		cur := pureGen(t, 7, renderHeader, 1, []string{ca[1], ca[2]}, "role:b", "role:c", "role:e")
		base := pureGen(t, 5, renderHeader, 1, []string{ca[2], ca[1], ca[0]}, "role:c", "role:b", "role:a")
		got := RollbackKeeping(cur, lg, []*Generation{base})
		if p := deployLines(got); !slices.Equal(p, []string{"role:c", "role:b"}) {
			t.Fatalf("principals %v, want [role:c role:b] in the first bound's order", p)
		}
		if !strings.HasPrefix(string(got.Files[PrincipalsDir+"/deploy"]), intermediateHeader) {
			t.Fatalf("principals file %q lacks the intermediate header", got.Files[PrincipalsDir+"/deploy"])
		}
		if c := string(got.Files[CAFile]); c != ca[2]+"\n"+ca[1]+"\n" {
			t.Fatalf("CA file %q", c)
		}
		noBounds := RollbackKeeping(cur, lg, nil)
		if p := deployLines(noBounds); !slices.Equal(p, []string{"role:b", "role:c"}) {
			t.Fatalf("no bounds: principals %v, want last-good's order", p)
		}
	})
	t.Run("base_bounds_the_result", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca[:1], "role:a", "role:c")
		cur := pureGen(t, 7, renderHeader, 1, ca[:1], "role:a", "role:c")
		base := pureGen(t, 5, intermediateHeader, 1, ca[:1], "role:a")
		if p := deployLines(RollbackKeeping(cur, lg, []*Generation{base})); !slices.Equal(p, []string{"role:a"}) {
			t.Fatalf("principals %v, want role:c bounded out", p)
		}
	})
	t.Run("every_bound_applies", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca[:1], "role:a", "role:b", "role:c")
		cur := pureGen(t, 7, renderHeader, 1, ca[:1], "role:a", "role:b", "role:c")
		from := pureGen(t, 5, renderHeader, 1, ca[:1], "role:a", "role:b")
		to := pureGen(t, 6, renderHeader, 1, ca[:1], "role:a", "role:c")
		if p := deployLines(RollbackKeeping(cur, lg, []*Generation{from, to})); !slices.Equal(p, []string{"role:a"}) {
			t.Fatalf("principals %v, want only what every bound holds", p)
		}
	})
	t.Run("newest_krl_kept", func(t *testing.T) {
		for _, c := range []struct{ lg, cur, bound, want uint64 }{{1, 2, 1, 2}, {1, 1, 3, 3}, {3, 1, 2, 3}, {0, 2, 0, 2}, {2, 0, 0, 2}} {
			lg := pureGen(t, 4, renderHeader, c.lg, ca[:1], "role:a")
			cur := pureGen(t, 7, renderHeader, c.cur, ca[:1], "role:a")
			b := pureGen(t, 5, renderHeader, c.bound, ca[:1], "role:a")
			if got := krlVersion(RollbackKeeping(cur, lg, []*Generation{b})); got != c.want {
				t.Fatalf("%+v: KRL version %d", c, got)
			}
		}
	})
	t.Run("matches_independent_oracle", func(t *testing.T) {
		// An oracle from parsed lines and plain map intersection, not
		// through covers, lineSet or Intermediate.
		universe := []string{"role:a", "role:b", "role:c", "role:d", "role:e", "role:f"}
		seed := uint64(0x9e3779b97f4a7c15)
		next := func() uint64 { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed }
		pick := func() (ps, cs []string, v uint64) {
			m := next()
			for i, p := range universe {
				if m&(1<<i) != 0 {
					ps = append(ps, p)
				}
			}
			for i, c := range ca {
				if m&(1<<(8+i)) != 0 {
					cs = append(cs, c)
				}
			}
			return ps, cs, (m >> 16) % 4
		}
		parsed := func(b []byte, comment string) map[string]bool {
			out := map[string]bool{}
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, comment) {
					out[l] = true
				}
			}
			return out
		}
		for i := range 2000 {
			var gens []*Generation
			var vers []uint64
			for j := range 2 + int(next()%4) { // last-good, cur and up to three bounds
				ps, cs, v := pick()
				gens = append(gens, pureGen(t, uint64(j+1), renderHeader, v, cs, ps...))
				vers = append(vers, v)
			}
			lg, cur, bounds := gens[0], gens[1], gens[2:]
			got := RollbackKeeping(cur, lg, bounds)
			for _, name := range []string{PrincipalsDir + "/deploy", CAFile} {
				want := parsed(lg.Files[name], "#")
				for _, g := range gens[1:] {
					have := parsed(g.Files[name], "#")
					for k := range want {
						if !have[k] {
							delete(want, k)
						}
					}
				}
				if g := parsed(got.Files[name], "#"); len(g) != len(want) || !func() bool {
					for k := range want {
						if !g[k] {
							return false
						}
					}
					return true
				}() {
					t.Fatalf("tuple %d %s: got %v, want %v", i, name, g, want)
				}
			}
			if v := krlVersion(got); v != slices.Max(vers) {
				t.Fatalf("tuple %d: KRL version %d, want %d of %v", i, v, slices.Max(vers), vers)
			}
		}
	})
	t.Run("host_fields_are_last_goods", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca[:1], "role:a", "role:b")
		lg.Host, lg.HostStatus = "web1", HostKeysRotated
		cur := pureGen(t, 7, renderHeader, 1, ca[:1], "role:a")
		cur.Host, cur.HostStatus = "web2", ""
		if got := RollbackKeeping(cur, lg, nil); got.Host != "web1" || got.HostStatus != HostKeysRotated {
			t.Fatalf("host %q status %q", got.Host, got.HostStatus)
		}
	})
	t.Run("no_bounds_is_last_good", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca[:1], "role:a", "role:b")
		cur := pureGen(t, 7, renderHeader, 1, ca[:1], "role:a", "role:b", "role:c")
		if got := RollbackKeeping(cur, lg, nil); !sameBytes(got, lg) || got.N != lg.N {
			t.Fatalf("got N %d %v, want last-good itself", got.N, deployLines(got))
		}
	})
	t.Run("nil_cur_is_bounds_and_last_good", func(t *testing.T) {
		lg := pureGen(t, 4, renderHeader, 1, ca[:1], "role:a", "role:b")
		b := pureGen(t, 5, renderHeader, 2, ca[:1], "role:b", "role:c")
		got := RollbackKeeping(nil, lg, []*Generation{b})
		if p := deployLines(got); !slices.Equal(p, []string{"role:b"}) || krlVersion(got) != 2 {
			t.Fatalf("principals %v KRL %d", p, krlVersion(got))
		}
	})
}

// TestAtRollbackTarget pins the start check (apply.go atRollbackTarget):
// a kept state counts, by classified content.
func TestAtRollbackTarget(t *testing.T) {
	// setup installs last-good {role:a, role:b} with KRL 7 and returns a
	// link to it and a function that installs another generation.
	setup := func(t *testing.T) (*testHost, link, func(krlV uint64, header string, principals ...string) link) {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		h.publishKRL(7)
		h.installed("role:a", "role:b")
		e := h.engine()
		lg, err := e.resolveLink(h.l.LastGood())
		if err != nil {
			t.Fatal(err)
		}
		mk := func(krlV uint64, header string, principals ...string) link {
			g, _, err := e.readCurrent()
			if err != nil {
				t.Fatal(err)
			}
			n := &Generation{Files: map[string][]byte{}}
			for k, v := range g.Files {
				n.Files[k] = v
			}
			var b strings.Builder
			b.WriteString(header)
			for _, p := range principals {
				b.WriteString(p + "\n")
			}
			n.Files[PrincipalsDir+"/deploy"] = []byte(b.String())
			if krlV != 0 {
				_, files := h.f.krl([]uint64{krlV}, nil, "")
				n.Files[KRLFile] = files.KRL
			}
			n.N = e.allocGeneration()
			if err := e.installGeneration(n); err != nil {
				t.Fatal(err)
			}
			return link{kind: linkAgent, n: n.N, dir: h.l.Gen(n.N)}
		}
		return h, lg, mk
	}
	t.Run("kept_state_is_a_rollback_target", func(t *testing.T) {
		_, lg, mk := setup(t)
		if !atRollbackTarget(mk(9, intermediateHeader, "role:a"), lg) {
			t.Fatal("a kept state inside last-good with a newer KRL does not count")
		}
	})
	t.Run("content_equal_but_bytes_differ_counts", func(t *testing.T) {
		_, lg, mk := setup(t)
		if !atRollbackTarget(mk(9, "# another header\n# a comment\n", "role:b", "# between", "role:a"), lg) {
			t.Fatal("a reused generation that differs only in header and comment lines does not count")
		}
	})
	t.Run("plain_target_still_counts", func(t *testing.T) {
		_, lg, mk := setup(t)
		if !atRollbackTarget(mk(9, renderHeader, "role:a", "role:b"), lg) {
			t.Fatal("RollbackTarget's content does not count")
		}
	})
	t.Run("a_wider_current_is_not_a_target", func(t *testing.T) {
		_, lg, mk := setup(t)
		if atRollbackTarget(mk(9, intermediateHeader, "role:a", "role:z"), lg) {
			t.Fatal("a current holding a line last-good lacks counts")
		}
	})
	t.Run("older_krl_is_not_a_target", func(t *testing.T) {
		h, lg, mk := setup(t)
		// A generation with no KRL is older than last-good's KRL 7.
		l := mk(0, intermediateHeader, "role:a")
		g, err := readGeneration(l.dir)
		if err != nil {
			t.Fatal(err)
		}
		delete(g.Files, KRLFile)
		g.N = h.engine().allocGeneration()
		if err := h.engine().installGeneration(g); err != nil {
			t.Fatal(err)
		}
		if atRollbackTarget(link{kind: linkAgent, n: g.N, dir: h.l.Gen(g.N)}, lg) {
			t.Fatal("a current with an older KRL counts")
		}
	})
}

// atKept reports whether last-good names lg and current's classified
// content is RollbackKeeping(current, last-good, no bounds): a kept state
// (the twin of atRollback for 03-10d).
func (h *testHost) atKept(lg uint64) bool {
	h.t.Helper()
	if h.lastGood() != lg {
		return false
	}
	c, err := readGeneration(h.l.Gen(h.current()))
	if err != nil {
		return false
	}
	l, err := readGeneration(h.l.Gen(lg))
	return err == nil && sameContent(c, RollbackKeeping(c, l, nil))
}

var errInjected = errors.New("injected failure")

// failer is a Fault hook that fails the n-th call of a point (a point
// ending in ':' matches as a prefix) once, with a plain error, counting
// only while armed; arm, when not nil, arms it at the first call of that
// point. It records every point it sees.
type failer struct {
	mu     sync.Mutex
	point  string
	n      int
	armAt  string
	armed  bool
	seen   int
	fired  bool
	points []string
	onFire func()
}

func (f *failer) match(p, want string) bool {
	if strings.HasSuffix(want, ":") {
		return strings.HasPrefix(p, want)
	}
	return p == want
}

func (f *failer) hook(p string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.points = append(f.points, p)
	if !f.armed && f.armAt != "" && p == f.armAt {
		f.armed = true
		return nil
	}
	if !f.armed || f.fired || !f.match(p, f.point) {
		return nil
	}
	f.seen++
	if f.seen == f.n {
		f.fired = true
		if f.onFire != nil {
			f.onFire()
		}
		return errInjected
	}
	return nil
}

func (f *failer) arm() {
	f.mu.Lock()
	f.armed = true
	f.mu.Unlock()
}

func (f *failer) didFire() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fired
}

// keepHost is a host whose deploy account has principals, first
// installed, with the probe gate off (probes false: the default harness
// and a short listener test) or on with a usable pair (gateHost, ready).
func keepHost(t *testing.T, probes bool, principals ...string) *testHost {
	t.Helper()
	return keepHostIn(t, probes, nil, principals...)
}

// keepHostIn is keepHost with prep run on the new host before its first
// install (nil: none).
func keepHostIn(t *testing.T, probes bool, prep func(*testHost), principals ...string) *testHost {
	t.Helper()
	h := newTestHost(t, newFixture(t))
	if prep != nil {
		prep(h)
	}
	if probes {
		h.gateOn()
		h.installed(principals...)
		h.ready()
		return h
	}
	h.cfg.SelfTestTimeout = 300 * time.Millisecond
	h.installed(principals...)
	return h
}

// landWithPair gives a probes-on host a fresh usable pair and applies
// until role:b is in force (at most three rounds: the pair's KRL lands
// first); role:a is never in force on the way.
func landWithPair(t *testing.T, h *testHost, probes bool) {
	t.Helper()
	if probes {
		p := h.seedPair(10*time.Minute, false)
		h.listMach(p.Negative.Serial)
	}
	for range 3 {
		r, err := h.apply()
		if slices.Contains(h.principals("deploy"), "role:a") {
			t.Fatalf("role:a in force again: %v, %+v", err, r)
		}
		if slices.Contains(h.principals("deploy"), "role:b") {
			if err != nil {
				t.Fatalf("role:b landed with an error: %v", err)
			}
			return
		}
	}
	t.Fatalf("role:b never landed: principals %v", h.principals("deploy"))
}

// bothProbes runs f as name/probes_off and name/probes_on.
func bothProbes(t *testing.T, name string, f func(t *testing.T, probes bool)) {
	t.Run(name, func(t *testing.T) {
		t.Parallel()
		for _, p := range []bool{false, true} {
			sub := map[bool]string{false: "probes_off", true: "probes_on"}[p]
			t.Run(sub, func(t *testing.T) {
				t.Parallel()
				f(t, p)
			})
		}
	})
}

// recoverOnly runs the next Apply's start alone: it crashes the run at
// the first fault point after the recovery's clear-marker, so forward
// commits nothing. It fails the test when no recovery ran. Every fault
// point checks that current never holds absent.
func recoverOnly(t *testing.T, h *testHost, absent ...string) *Report {
	t.Helper()
	return recoverOnlyAfter(t, h, absent, absent)
}

// recoverOnlyAfter is recoverOnly with the lines absent during the
// recovery (during) and after it (after) given apart: a current that a
// double failure left at the failed target holds them before.
func recoverOnlyAfter(t *testing.T, h *testHost, during, after []string) *Report {
	t.Helper()
	var mu sync.Mutex
	cleared, bad := false, ""
	h.cfg.Fault = func(p string) error {
		for _, a := range during {
			if slices.Contains(h.principals("deploy"), a) {
				mu.Lock()
				bad = a + " at " + p
				mu.Unlock()
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if cleared {
			return &crash{point: p}
		}
		if p == "clear-marker" {
			cleared = true
		}
		return nil
	}
	r, err := h.apply()
	h.cfg.Fault = nil
	if !r.Recovered || (err != nil && !isCrash(err)) {
		t.Fatalf("the next start: recovered %t, %v", r.Recovered, err)
	}
	if bad != "" {
		t.Fatalf("%s was in force during the recovery", bad)
	}
	for _, a := range after {
		if slices.Contains(h.principals("deploy"), a) {
			t.Fatalf("%s in force after the recovery: %v", a, h.principals("deploy"))
		}
	}
	return r
}

// mixedSite publishes the mixed change {role:a, role:x} -> {role:x,
// role:b} with fault as the Fault hook and runs it.
func mixedSite(h *testHost, fault func(string) error) (*Report, error) {
	h.cfg.Fault = fault
	h.publishDir(h.spec("role:x", "role:b"))
	r, err := h.apply()
	h.cfg.Fault = nil
	return r, err
}

// mustKeptSite requires an after-final-swap failure: the error, a
// rollback, current's principals exactly role:x, last-good and accepted/
// unchanged; then the next apply with the injector spent lands role:b,
// keeps role:a absent and does not recover.
func mustKeptSite(t *testing.T, h *testHost, r *Report, err error, lg, accepted uint64) {
	t.Helper()
	if err == nil || !r.Rollback {
		t.Fatalf("the failed run: %v, rollback %t", err, r.Rollback)
	}
	mustPrincipals(t, h, "role:x")
	if h.lastGood() != lg || h.acceptedDir() != accepted || readMarker(t, h) != nil {
		t.Fatalf("last-good %d (was %d), accepted/ directory %d (was %d), marker %+v", h.lastGood(), lg, h.acceptedDir(), accepted, readMarker(t, h))
	}
	r = h.mustApply()
	if r.Recovered {
		t.Fatalf("the next apply recovered a kept state: %+v", r)
	}
	mustPrincipals(t, h, "role:b", "role:x")
}

// afterSwapSites are the four after-final-swap sites (03-10d Task 1):
// each returns the failed run's report and error.
var afterSwapSites = []struct {
	name string
	run  func(t *testing.T, h *testHost, probes bool) (*Report, error)
}{
	{"transition_error", func(t *testing.T, h *testHost, _ bool) (*Report, error) {
		f := &failer{point: "swap", n: 2, armed: true}
		r, err := mixedSite(h, f.hook)
		if !f.didFire() || !errors.Is(err, errInjected) {
			t.Fatalf("the final swap did not fail: %v", err)
		}
		// Current stays on M, the kept content: the rollback makes no swap.
		if n := strings.Count(strings.Join(f.points, " "), "swap"); n != 2 {
			t.Fatalf("%d swap fault points %v, want forward's two and none for the rollback", n, f.points)
		}
		return r, err
	}},
	{"write_dropin_error", func(t *testing.T, h *testHost, _ bool) (*Report, error) {
		appendFile(t, h.l.DropIn(), "# edited by hand\n")
		f := &failer{point: "dropin", n: 1, armed: true}
		r, err := mixedSite(h, f.hook)
		if !f.didFire() || !errors.Is(err, errInjected) {
			t.Fatalf("the drop-in write did not fail: %v", err)
		}
		return r, err
	}},
	{"activate_dropin_error", func(t *testing.T, h *testHost, _ bool) (*Report, error) {
		appendFile(t, h.l.DropIn(), "# edited by hand\n")
		f := &failer{point: "reload", n: 1, armed: true}
		r, err := mixedSite(h, f.hook)
		if !f.didFire() || !errors.Is(err, errInjected) {
			t.Fatalf("the activation did not fail: %v", err)
		}
		return r, err
	}},
	{"self_test_failure", func(t *testing.T, h *testHost, _ bool) (*Report, error) {
		h.sshd.setStall(true)
		r, err := mixedSite(h, nil)
		h.sshd.setStall(false)
		if !errors.Is(err, ErrSelfTest) {
			t.Fatalf("the listener test did not fail: %v", err)
		}
		return r, err
	}},
}

// settleSite runs the mixed change on a probes-on host whose positive
// probe is refused; onProbe runs once, at that refused answer.
func settleSite(t *testing.T, h *testHost, fault func(string) error, onProbe func()) (*Report, error) {
	t.Helper()
	once := false
	h.cfg.probeQuery = func(context.Context, ProbeTarget, *ssh.Certificate, time.Time) (ProbeOutcome, error) {
		if !once {
			once = true
			if onProbe != nil {
				onProbe()
			}
		}
		return ProbeRefused, nil
	}
	r, err := mixedSite(h, fault)
	h.cfg.probeQuery = h.sshdProbe
	return r, err
}

// mustSettleRolledBack requires a settle or gate site that rolled back:
// role:a and role:b absent, last-good unchanged, the next round held for
// hold, and once the clock passes the back-off role:b lands; role:a is
// absent in every round.
func mustSettleRolledBack(t *testing.T, h *testHost, r *Report, err error, lg uint64, hold string) {
	t.Helper()
	if err == nil || !r.Rollback {
		t.Fatalf("the failed run: %v, rollback %t", err, r.Rollback)
	}
	if p := h.principals("deploy"); slices.Contains(p, "role:a") || slices.Contains(p, "role:b") {
		t.Fatalf("principals %v", p)
	}
	if h.lastGood() != lg {
		t.Fatalf("last-good %d, was %d", h.lastGood(), lg)
	}
	r, err = h.apply()
	mustHeld(t, h, r, err, hold)
	if slices.Contains(h.principals("deploy"), "role:a") {
		t.Fatalf("role:a in force in the held round: %v", h.principals("deploy"))
	}
	h.clock.advance(ProbeBackoffMax + time.Minute)
	if hold != "failure_backoff" {
		h.writePasswd("root:x:0:0:root:/root:/bin/bash\n" + probeLogin + "\n")
	}
	landWithPair(t, h, true)
	mustPrincipals(t, h, "role:b", "role:x")
}

// blockFirstKeygen is a Runner that blocks the first ssh-keygen after it
// is armed until the context ends, then passes every call to next.
type blockFirstKeygen struct {
	next   Runner
	mu     sync.Mutex
	armed  bool
	done   bool
	keygen string
}

func (b *blockFirstKeygen) Run(ctx context.Context, c execsite.Cmd) (Result, error) {
	b.mu.Lock()
	block := b.armed && !b.done && c.Path() == b.keygen
	if block {
		b.done = true
	}
	b.mu.Unlock()
	if block {
		<-ctx.Done()
		return Result{}, ctx.Err()
	}
	return b.next.Run(ctx, c)
}

func TestRollbackSites(t *testing.T) {
	t.Run("every_forward_call_keeps", func(t *testing.T) {
		t.Parallel()
		everyForwardCallKeeps(t)
	})
	for _, s := range afterSwapSites {
		bothProbes(t, s.name, func(t *testing.T, probes bool) {
			h := keepHost(t, probes, "role:a", "role:x")
			lg, acc := h.lastGood(), h.acceptedDir()
			r, err := s.run(t, h, probes)
			mustKeptSite(t, h, r, err, lg, acc)
		})
	}
	bothProbes(t, "next_apply_does_not_recover_a_kept_state", func(t *testing.T, probes bool) {
		for _, s := range afterSwapSites {
			h := keepHost(t, probes, "role:a", "role:x")
			if _, err := s.run(t, h, probes); err == nil {
				t.Fatalf("%s: no failure", s.name)
			}
			mustPrincipals(t, h, "role:x")
			if r, err := h.apply(); err != nil || r.Recovered {
				t.Fatalf("%s: the next start: %v, recovered %t", s.name, err, r.Recovered)
			}
			if slices.Contains(h.principals("deploy"), "role:a") {
				t.Fatalf("%s: role:a in force again", s.name)
			}
		}
	})
	bothProbes(t, "commit_stage_error", func(t *testing.T, probes bool) {
		h := keepHost(t, probes, "role:a", "role:x")
		lg := h.lastGood()
		old := cloneState(h.state)
		f := &failer{point: "accepted:", n: 1}
		if probes {
			h.cfg.probeQuery = func(ctx context.Context, pt ProbeTarget, c *ssh.Certificate, d time.Time) (ProbeOutcome, error) {
				f.arm()
				return h.sshdProbe(ctx, pt, c, d)
			}
		} else {
			f.armAt = "self-test"
		}
		r, err := mixedSite(h, f.hook)
		h.cfg.probeQuery = h.sshdProbe
		if !f.didFire() || !errors.Is(err, errInjected) || r.Rollback || readMarker(t, h) == nil {
			t.Fatalf("the commit's stage: %v, rollback %t, marker %+v", err, r.Rollback, readMarker(t, h))
		}
		mustPrincipals(t, h, "role:b", "role:x")
		next := h.state
		h.resetSpool()
		h.state = old
		recoverOnly(t, h, "role:a")
		mustPrincipals(t, h, "role:x")
		if h.lastGood() != lg || readMarker(t, h) != nil {
			t.Fatalf("last-good %d (was %d), marker %+v", h.lastGood(), lg, readMarker(t, h))
		}
		h.state = next
		h.mustApply()
		mustPrincipals(t, h, "role:b", "role:x")
	})
	t.Run("settle_commit_error", func(t *testing.T) {
		t.Parallel()
		h := keepHost(t, true, "role:a", "role:x")
		lg := h.lastGood()
		f := &failer{point: "accepted:", n: 1}
		r, err := settleSite(t, h, f.hook, f.arm)
		if !f.didFire() || !errors.Is(err, errInjected) || readMarker(t, h) == nil {
			t.Fatalf("settle's commit: %v, rollback %t, marker %+v", err, r.Rollback, readMarker(t, h))
		}
		mustPrincipals(t, h, "role:x")
		recoverOnly(t, h, "role:a", "role:b")
		if h.lastGood() != lg {
			t.Fatalf("last-good %d, was %d", h.lastGood(), lg)
		}
	})
	t.Run("settle_validate_error", func(t *testing.T) {
		t.Parallel()
		h := keepHost(t, true, "role:a", "role:x")
		lg := h.lastGood()
		armed := false
		h.run.rejectCA = func(string) bool {
			if armed {
				armed = false
				return true
			}
			return false
		}
		var mid, tgt uint64
		r, err := settleSite(t, h, nil, func() {
			mid, tgt = readMarker(t, h).Intermediate, h.current()
			if err := os.RemoveAll(h.l.Gen(mid)); err != nil {
				t.Error(err)
			}
			h.run.mu.Lock()
			armed = true
			h.run.mu.Unlock()
		})
		if !errors.Is(err, ErrCALineRejected) {
			t.Fatalf("settle's validate did not fail: %v", err)
		}
		// preN is gone, so the keeping rollback installed the kept content
		// as a new generation (rollbackTarget's install branch).
		if c := h.current(); c == mid || c == tgt || c == lg || c < tgt || mid == 0 {
			t.Fatalf("current %d: want a new generation, not M %d, T %d or last-good %d", c, mid, tgt, lg)
		}
		mustSettleRolledBack(t, h, r, err, lg, "failure_backoff")
	})
	t.Run("settle_validate_timeout", func(t *testing.T) {
		t.Parallel()
		h := keepHost(t, true, "role:a", "role:x")
		lg := h.lastGood()
		b := &blockFirstKeygen{next: h.run, keygen: h.cfg.SSHKeygen}
		h.cfg.Exec = b
		once := false
		h.cfg.probeQuery = func(context.Context, ProbeTarget, *ssh.Certificate, time.Time) (ProbeOutcome, error) {
			if !once {
				once = true
				if err := os.RemoveAll(h.l.Gen(readMarker(t, h).Intermediate)); err != nil {
					t.Error(err)
				}
				b.mu.Lock()
				b.armed = true
				b.mu.Unlock()
			}
			return ProbeRefused, nil
		}
		h.publishDir(h.spec("role:x", "role:b"))
		h.write()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		r, err := Apply(ctx, h.cfg, h.l)
		cancel()
		h.cfg.probeQuery, h.cfg.Exec = h.sshdProbe, h.run
		if !b.done || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("settle's validate did not time out: %v", err)
		}
		mustSettleRolledBack(t, h, r, err, lg, "failure_backoff")
	})
	for _, p := range []string{"marker", "swap"} {
		t.Run("settle_"+p+"_error", func(t *testing.T) {
			t.Parallel()
			h := keepHost(t, true, "role:a", "role:x")
			lg := h.lastGood()
			f := &failer{point: p, n: 1}
			r, err := settleSite(t, h, f.hook, f.arm)
			if !f.didFire() || !errors.Is(err, errInjected) {
				t.Fatalf("settle's %s did not fail: %v", p, err)
			}
			mustSettleRolledBack(t, h, r, err, lg, "failure_backoff")
		})
	}
	t.Run("gate_superseded_error", func(t *testing.T) {
		t.Parallel()
		h := keepHost(t, true, "role:a", "role:x", "role:y")
		lg := h.lastGood()
		h.writeRootFile("bin/sh", []byte("#!/bin/false\n"), 0o755)
		machine := trust.FormatKey(h.f.mach.PublicKey())
		armed, n := false, 0
		h.run.rejectCA = func(line string) bool {
			if armed && line == machine {
				// The 1st is the superseding capture's own validate
				// (pollSpool), the 2nd the held intermediate's.
				if n++; n == 2 {
					armed = false
					return true
				}
			}
			return false
		}
		fired := false
		h.clock.onSleep = func(time.Duration) {
			if fired {
				return
			}
			fired = true
			h.publishDir(h.spec("role:x", "role:b"))
			h.write()
			h.writePasswd(probeAccountShell("/bin/sh"))
			h.run.mu.Lock()
			armed = true
			h.run.mu.Unlock()
		}
		h.publishDir(h.spec("role:x", "role:y", "role:b"))
		r, err := h.apply()
		h.clock.onSleep = nil
		if !fired || !errors.Is(err, ErrCALineRejected) {
			t.Fatalf("the held intermediate's validate did not fail: fired %t, %v", fired, err)
		}
		if p := h.principals("deploy"); !slices.Equal(p, []string{"role:x", "role:y"}) {
			t.Fatalf("principals %v, want the first pass's intermediate", p)
		}
		mustSettleRolledBack(t, h, r, err, lg, shellNotNologin)
	})
	t.Run("double_failure_next_start_keeps_removal", func(t *testing.T) {
		t.Parallel()
		variants := []struct {
			name string
			run  func(t *testing.T, h *testHost) (*Report, error)
		}{
			{"transition", func(t *testing.T, h *testHost) (*Report, error) {
				h.sshd.setStall(true)
				f := &failer{point: "swap", n: 1, armAt: "self-test"}
				r, err := mixedSite(h, f.hook)
				h.sshd.setStall(false)
				if !f.didFire() {
					t.Fatal("the rollback's swap did not fail")
				}
				return r, err
			}},
			{"restore_dropin", func(t *testing.T, h *testHost) (*Report, error) {
				appendFile(t, h.l.DropIn(), "# edited by hand\n")
				set := &failer{point: "swap", n: 1, armAt: "reload"}
				set.onFire = func() {
					h.run.mu.Lock()
					h.run.sshdTestErr = "injected sshd -t failure"
					h.run.mu.Unlock()
				}
				reload := &failer{point: "reload", n: 1, armed: true}
				r, err := mixedSite(h, func(p string) error {
					_ = set.hook(p) // arms at reload; at the next swap it sets sshdTestErr and lets the swap go on
					return reload.hook(p)
				})
				h.run.mu.Lock()
				h.run.sshdTestErr = ""
				h.run.mu.Unlock()
				if !reload.didFire() || !set.didFire() || !errors.Is(err, ErrSSHDTest) {
					t.Fatalf("restoreDropIn's sshd -t did not fail: %v", err)
				}
				return r, err
			}},
			{"clear_marker", func(t *testing.T, h *testHost) (*Report, error) {
				h.sshd.setStall(true)
				f := &failer{point: "clear-marker", n: 1, armed: true}
				r, err := mixedSite(h, f.hook)
				h.sshd.setStall(false)
				if !f.didFire() {
					t.Fatal("the rollback's clear-marker did not fail")
				}
				return r, err
			}},
		}
		for _, v := range variants {
			bothProbes(t, v.name, func(t *testing.T, probes bool) {
				h := keepHost(t, probes, "role:a", "role:x")
				lg := h.lastGood()
				q := len(h.probeQueries())
				r, err := v.run(t, h)
				if err == nil || !r.Rollback || readMarker(t, h) == nil || slices.Contains(h.principals("deploy"), "role:a") {
					t.Fatalf("the double failure: %v, rollback %t, marker %+v, principals %v", err, r.Rollback, readMarker(t, h), h.principals("deploy"))
				}
				recoverOnly(t, h, "role:a")
				mustPrincipals(t, h, "role:x")
				if h.lastGood() != lg || len(h.probeQueries()) != q || readMarker(t, h) != nil {
					t.Fatalf("after the recovery: last-good %d (was %d), %d probe queries (was %d)", h.lastGood(), lg, len(h.probeQueries()), q)
				}
				landWithPair(t, h, probes)
				mustPrincipals(t, h, "role:b", "role:x")
			})
		}
	})
	t.Run("double_failure_after_kept_base_keeps_readd_out", func(t *testing.T) {
		t.Parallel()
		h := keptBase(t, true, []string{"role:a", "role:c"}, []string{"role:a", "role:b"})
		k0 := h.current()
		h.sshd.setStall(true)
		f := &failer{point: "swap", n: 1, armAt: "self-test"}
		h.cfg.Fault = f.hook
		h.publishDir(h.spec("role:a", "role:c"))
		r, err := h.apply()
		h.cfg.Fault = nil
		h.sshd.setStall(false)
		if !f.didFire() || err == nil || !r.Rollback {
			t.Fatalf("round 2: fired %t, %v", f.didFire(), err)
		}
		m := readMarker(t, h)
		if m == nil || m.From != h.current() || m.To != k0 {
			t.Fatalf("the rollback's marker %+v, current %d, want {T2, K0 %d}", m, h.current(), k0)
		}
		// By content T2 lies inside last-good and passes the start check:
		// only the pending marker sends it to recover.
		e := lockedEngine(h)
		cur, err1 := e.resolveLink(h.l.Current())
		lgl, err2 := e.resolveLink(h.l.LastGood())
		if err1 != nil || err2 != nil || !atRollbackTarget(cur, lgl) {
			t.Fatalf("T2 does not pass atRollbackTarget by content: %v, %v", err1, err2)
		}
		recoverOnlyAfter(t, h, nil, []string{"role:c"})
		mustPrincipals(t, h, "role:a")
	})
	t.Run("crash_at_settle_swap_on_kept_base_keeps_readd_out", func(t *testing.T) {
		t.Parallel()
		h := keptBase(t, true, []string{"role:a", "role:c", "role:e"}, []string{"role:a", "role:e", "role:b"})
		probed := false
		h.cfg.probeQuery = func(context.Context, ProbeTarget, *ssh.Certificate, time.Time) (ProbeOutcome, error) {
			probed = true
			return ProbeRefused, nil
		}
		h.cfg.Fault = func(p string) error {
			if probed && p == "swap" {
				return &crash{point: p}
			}
			return nil
		}
		h.publishDir(h.spec("role:c", "role:e"))
		_, err := h.apply()
		h.cfg.Fault, h.cfg.probeQuery = nil, h.sshdProbe
		if !isCrash(err) || readMarker(t, h) == nil {
			t.Fatalf("the crash at settle's swap: %v", err)
		}
		recoverOnlyAfter(t, h, nil, []string{"role:a", "role:c"})
		mustPrincipals(t, h, "role:e")
	})
	t.Run("unreadable_marker_generation_fails_closed", func(t *testing.T) {
		t.Parallel()
		h := keepHost(t, false, "role:a", "role:x")
		lg := h.lastGood()
		fl := &faultLog{k: 5}
		r, err := mixedSite(h, fl.hook)
		m := readMarker(t, h)
		if !isCrash(err) || m == nil || m.Intermediate == 0 || h.current() != m.To {
			t.Fatalf("the crash at the self-test: %v, %+v, marker %+v", err, r, m)
		}
		tgt := h.current()
		if err := os.RemoveAll(h.l.Gen(m.Intermediate)); err != nil {
			t.Fatal(err)
		}
		r, err = h.apply()
		if !errors.Is(err, ErrPendingStateUnknown) || r.Stuck != "pending_state_unknown" || h.current() != tgt || h.lastGood() != lg {
			t.Fatalf("the next start: %v, stuck %q, current %d (was %d), last-good %d (was %d)", err, r.Stuck, h.current(), tgt, h.lastGood(), lg)
		}
	})
	t.Run("crash_recovery_keeps_removal", func(t *testing.T) {
		t.Parallel()
		crashRecoveryKeepsRemoval(t)
	})
	t.Run("operator_recover_still_goes_to_last_good", func(t *testing.T) {
		t.Parallel()
		h := keepHost(t, false, "role:a", "role:x")
		h.publishKRL(7)
		fl := &faultLog{k: 5}
		if _, err := mixedSite(h, fl.hook); !isCrash(err) {
			t.Fatalf("the crash: %v", err)
		}
		h.cfg.RecoverToLastGood = true
		_, err := h.apply()
		h.cfg.RecoverToLastGood = false
		if err != nil {
			t.Fatalf("--recover-to-last-good: %v", err)
		}
		mustPrincipals(t, h, "role:a", "role:x")
		if !h.krlRevokes(h.l.Current(), 7) || !h.atRollback(h.lastGood()) {
			t.Fatal("the operator's recovery did not keep the newer KRL at RollbackTarget")
		}
	})
	t.Run("superseded_readd_fails_keeps_readd_out", func(t *testing.T) {
		t.Parallel()
		for _, v := range []struct {
			name   string
			probes bool
		}{{"listener_site", false}, {"settle_probe_failure", true}} {
			t.Run(v.name, func(t *testing.T) {
				t.Parallel()
				h := keepHost(t, v.probes, "role:a", "role:x")
				lg := h.lastGood()
				if v.probes {
					h.scriptProbes(ProbeRefused)
				}
				fired := false
				h.clock.onSleep = func(time.Duration) {
					if fired {
						return
					}
					fired = true
					h.publishDir(h.spec("role:a", "role:b", "role:x"))
					h.write()
					if !v.probes {
						h.sshd.setStall(true)
					}
				}
				h.publishDir(h.spec("role:a", "role:b"))
				r, err := h.apply()
				h.clock.onSleep = nil
				h.sshd.setStall(false)
				if !fired || err == nil || !r.Rollback {
					t.Fatalf("the superseded run: fired %t, %v", fired, err)
				}
				mustPrincipals(t, h, "role:a")
				if h.lastGood() != lg {
					t.Fatalf("last-good %d, was %d", h.lastGood(), lg)
				}
			})
		}
	})
	t.Run("kept_state_then_readd_and_add_fails_keeps_readd_out", func(t *testing.T) {
		t.Parallel()
		t.Run("listener_site", func(t *testing.T) {
			t.Parallel()
			h := keptBase(t, false, []string{"role:a", "role:c", "role:e"}, []string{"role:a", "role:e", "role:b"})
			h.sshd.setStall(true)
			h.publishDir(h.spec("role:a", "role:c", "role:d"))
			_, err := h.apply()
			h.sshd.setStall(false)
			if !errors.Is(err, ErrSelfTest) {
				t.Fatalf("round 2: %v", err)
			}
			mustPrincipals(t, h, "role:a")
		})
		t.Run("settle_probe_failure", func(t *testing.T) {
			t.Parallel()
			h := keptBase(t, true, []string{"role:a", "role:c", "role:e"}, []string{"role:a", "role:e", "role:b"})
			h.scriptProbes(ProbeRefused)
			h.publishDir(h.spec("role:a", "role:c", "role:d"))
			r, err := h.apply()
			mustFailed(t, h, r, err, ErrProbePositiveRefused)
			mustPrincipals(t, h, "role:a")
			l, rerr := readGeneration(h.l.Gen(h.lastGood()))
			if rerr != nil || !slices.Equal(deployLines(l), []string{"role:a"}) || h.lastGood() != h.current() {
				t.Fatalf("last-good %d holds %v (%v), current %d", h.lastGood(), deployLines(l), rerr, h.current())
			}
		})
		t.Run("settle_probe_failure_collapsed", func(t *testing.T) {
			t.Parallel()
			h := keptBase(t, true, []string{"role:a", "role:c"}, []string{"role:a", "role:b"})
			k0 := h.current()
			h.scriptProbes(ProbeRefused)
			h.publishDir(h.spec("role:a", "role:c", "role:d"))
			r, err := h.apply()
			mustFailed(t, h, r, err, ErrProbePositiveRefused)
			mustPrincipals(t, h, "role:a")
			if h.current() != k0 {
				t.Fatalf("current %d, want the kept base %d", h.current(), k0)
			}
		})
	})
	bothProbes(t, "pure_addition_failure_goes_back_to_base", func(t *testing.T, probes bool) {
		// After a normal base: back to last-good itself.
		h := keepHost(t, probes, "role:a")
		lg := h.lastGood()
		h.sshd.setStall(true)
		h.publishDir(h.spec("role:a", "role:b"))
		_, err := h.apply()
		h.sshd.setStall(false)
		if !errors.Is(err, ErrSelfTest) || h.current() != lg {
			t.Fatalf("after a normal base: %v, current %d, last-good %d", err, h.current(), lg)
		}
		// After a kept base: back to the kept base's generation.
		h = keptBase(t, probes, []string{"role:a", "role:c"}, []string{"role:a", "role:b"})
		k0 := h.current()
		h.sshd.setStall(true)
		h.publishDir(h.spec("role:a", "role:d"))
		_, err = h.apply()
		h.sshd.setStall(false)
		if !errors.Is(err, ErrSelfTest) || h.current() != k0 {
			t.Fatalf("after a kept base: %v, current %d, want %d", err, h.current(), k0)
		}
		mustPrincipals(t, h, "role:a")
	})
	bothProbes(t, "pure_narrowing_failure_keeps_removal", func(t *testing.T, probes bool) {
		h := keepHost(t, probes, "role:a", "role:x")
		lg := h.lastGood()
		appendFile(t, h.l.DropIn(), "# edited by hand\n")
		h.sshd.setStall(true)
		h.publishDir(h.spec("role:x"))
		r, err := h.apply()
		h.sshd.setStall(false)
		if !errors.Is(err, ErrSelfTest) || !r.Rollback || h.lastGood() != lg {
			t.Fatalf("the narrowing: %v, %+v", err, r)
		}
		mustPrincipals(t, h, "role:x")
		if same, err := lockedEngine(h).dropInIsWanted(); err != nil || !same {
			t.Fatalf("the drop-in was not restored to the agent's: %t, %v", same, err)
		}
	})
	bothProbes(t, "kept_state_start_failure_keeps_removal", func(t *testing.T, probes bool) {
		h := keptBase(t, probes, []string{"role:a", "role:x"}, []string{"role:x", "role:b"})
		cur, lg := h.current(), h.lastGood()
		// A validate refusal that is not a CA line (the KRL query fails):
		// forward returns it before its first swap (apply.go, the
		// candidate's validate).
		h.run.mu.Lock()
		h.run.queryCode = 2
		h.run.mu.Unlock()
		h.publishDir(h.spec("role:a", "role:x", "role:q"))
		h.publishKRL(91)
		_, err := h.apply()
		h.run.mu.Lock()
		h.run.queryCode = 0
		h.run.mu.Unlock()
		if err == nil || h.current() != cur || h.lastGood() != lg {
			t.Fatalf("the refused candidate: %v, current %d (was %d), last-good %d (was %d)", err, h.current(), cur, h.lastGood(), lg)
		}
		mustPrincipals(t, h, "role:x")
	})
	bothProbes(t, "keys_rotated_render_after_kept_rollback_keeps_removal", func(t *testing.T, probes bool) {
		h := keptBase(t, probes, []string{"role:a", "role:x"}, []string{"role:x", "role:b"})
		s := h.spec("role:a", "role:x")
		s.hostKeys = []ssh.PublicKey{h.f.mach.PublicKey()}
		h.publishDir(s)
		r, err := h.apply()
		if err != nil || r.HostStatus != HostKeysRotated {
			t.Fatalf("the rotated render: %v, %+v", err, r)
		}
		mustPrincipals(t, h, "role:x")
	})
	bothProbes(t, "no_directory_render_after_kept_rollback_keeps_removal", func(t *testing.T, probes bool) {
		h := keptBaseIn(t, probes, func(h *testHost) { spoolInState(t, h) }, []string{"role:a", "role:x"}, []string{"role:x", "role:b"})
		lgStatus := ""
		if rec, err := lockedEngine(h).readRecord(h.lastGood()); err == nil {
			lgStatus = rec.HostStatus
		}
		if _, err := ResetDirectory(h.l, h.spool); err != nil {
			t.Fatalf("reset-directory: %v", err)
		}
		h.state.Directories = map[uint64]spool.Doc{}
		h.publishKRL(77)
		r, err := h.apply()
		if !errors.Is(err, errNoDirectory) || r.HostStatus != lgStatus {
			t.Fatalf("the render with no directory: %v, %+v", err, r)
		}
		mustPrincipals(t, h, "role:x")
	})
	bothProbes(t, "krl_alone_after_kept_rollback_keeps_removal", func(t *testing.T, probes bool) {
		// D10: a capture whose directory render is refused as content
		// (generation_too_large) takes the KRL-alone pass against accepted/,
		// which still holds last-good's directory; only its KRL moves on.
		h := keptBase(t, probes, []string{"role:a", "role:x"}, []string{"role:x", "role:b"})
		lg0 := h.lastGood()
		s := h.spec("role:a", "role:x")
		s.bulkRoles = 17
		h.publishDir(s)
		h.publishKRL(93)
		var seen []string
		h.cfg.Fault = func(string) error {
			if slices.Contains(h.principals("deploy"), "role:a") {
				seen = append(seen, "current")
			}
			if l, err := readGeneration(h.l.Gen(h.lastGood())); err == nil && slices.Contains(deployLines(l), "role:a") && h.lastGood() != lg0 {
				seen = append(seen, "last-good")
			}
			return nil
		}
		_, err := h.apply()
		h.cfg.Fault = nil
		if !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("the oversize directory: %v, want generation_too_large reported", err)
		}
		mustPrincipals(t, h, "role:x")
		if !h.krlRevokes(h.l.Current(), 93) || len(seen) != 0 {
			t.Fatalf("KRL 93 in force %t; role:a in force at %v", h.krlRevokes(h.l.Current(), 93), seen)
		}
		if l, err := readGeneration(h.l.Gen(h.lastGood())); err != nil || (h.lastGood() != lg0 && slices.Contains(deployLines(l), "role:a")) {
			t.Fatalf("last-good %d widened to role:a: %v", h.lastGood(), err)
		}
	})
	t.Run("hostcert_and_probe_steps_not_blocked_by_kept_state", func(t *testing.T) {
		t.Parallel()
		h := keptBase(t, true, []string{"role:a", "role:x"}, []string{"role:x", "role:b"})
		if h.current() == h.lastGood() || readMarker(t, h) != nil {
			t.Fatal("no kept state")
		}
		pr, err := ProbeCerts(context.Background(), h.cfg, h.l)
		if err != nil || pr.Hold == hostcert.HoldApplyUnfinished {
			t.Fatalf("ProbeCerts on a kept state: %v, %+v", err, pr)
		}
		hr, err := HostCerts(context.Background(), h.cfg, h.l)
		if hr != nil && hr.Hold == hostcert.HoldApplyUnfinished {
			t.Fatalf("HostCerts on a kept state: %v, %+v", err, hr)
		}
	})
	t.Run("second_round_does_not_commit_untested_current", func(t *testing.T) {
		t.Parallel()
		h := keepHost(t, false, "role:a", "role:x")
		lg := h.lastGood()
		h.sshd.setStall(true)
		h.publishDir(h.spec("role:x"))
		if _, err := h.apply(); !errors.Is(err, ErrSelfTest) {
			t.Fatalf("round 1: %v", err)
		}
		kept := h.current()
		if kept == lg || !h.atKept(lg) {
			t.Fatal("round 1 left no kept state")
		}
		_, err := h.apply()
		h.sshd.setStall(false)
		if err == nil || h.lastGood() != lg || h.current() != kept {
			t.Fatalf("round 2: %v, last-good %d (was %d), current %d (was %d)", err, h.lastGood(), lg, h.current(), kept)
		}
	})
	t.Run("kept_state_commit_needs_listener_test", func(t *testing.T) {
		t.Parallel()
		h := keepHost(t, false, "role:a", "role:x")
		lg := h.lastGood()
		h.sshd.setStall(true)
		h.publishDir(h.spec("role:x"))
		if _, err := h.apply(); !errors.Is(err, ErrSelfTest) {
			t.Fatalf("round 1: %v", err)
		}
		kept := h.current()
		if kept == lg {
			t.Fatal("no kept state")
		}
		h.sshd.setStall(false)
		one := listenerConnections(t)
		before := h.sshd.acceptedNow()
		r := h.mustApply()
		if got := h.sshd.acceptedNow() - before; got != one || r.SelfTest != "pass" || h.lastGood() != kept || h.current() != kept {
			t.Fatalf("the commit: %d connections (one listener test is %d), %+v, last-good %d, current %d (kept %d)", got, one, r, h.lastGood(), h.current(), kept)
		}
	})
	t.Run("held_round_failure_keeps_removal", func(t *testing.T) {
		t.Parallel()
		heldRounds(t, false)
	})
	t.Run("held_round_runs_one_listener_test", func(t *testing.T) {
		t.Parallel()
		t.Run("probes_on", func(t *testing.T) {
			t.Parallel()
			heldRounds(t, true)
		})
	})
}

// keptBase brings a host with principals lg to a kept state: the mixed
// change to round1 fails its listener test, so current keeps lg's lines
// that round1 also holds (a kept state that is not last-good).
func keptBase(t *testing.T, probes bool, lg, round1 []string) *testHost {
	t.Helper()
	return keptBaseIn(t, probes, nil, lg, round1)
}

// keptBaseIn is keptBase with prep run on the new host before its first
// install.
func keptBaseIn(t *testing.T, probes bool, prep func(*testHost), lg, round1 []string) *testHost {
	t.Helper()
	h := keepHostIn(t, probes, prep, lg...)
	l := h.lastGood()
	h.sshd.setStall(true)
	h.publishDir(h.spec(round1...))
	_, err := h.apply()
	h.sshd.setStall(false)
	if !errors.Is(err, ErrSelfTest) || h.lastGood() != l || h.current() == l || !h.atKept(l) {
		t.Fatalf("the kept base: %v, current %d, last-good %d (was %d)", err, h.current(), h.lastGood(), l)
	}
	return h
}

// acceptedNow is the number of connections the fake sshd accepted.
func (s *fakeSSHD) acceptedNow() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// listenerConnections is the number of connections one listener test
// makes to the fake sshd: a pure narrowing with probes off runs exactly
// one.
func listenerConnections(t *testing.T) int {
	t.Helper()
	h := keepHost(t, false, "role:a", "role:x")
	before := h.sshd.acceptedNow()
	h.publishDir(h.spec("role:x"))
	if r := h.mustApply(); r.SelfTest != "pass" {
		t.Fatalf("the reference narrowing: %+v", r)
	}
	n := h.sshd.acceptedNow() - before
	if n == 0 {
		t.Fatal("a listener test made no connection")
	}
	return n
}

// heldRounds is the held round of 03-10c (deviation 9) on a kept state
// (D5): the drop-in removed, a mixed change published. Round 1 is held
// sshd_override, lands the narrowing part and fails its listener test;
// round 2 is held again, repairs the drop-in and commits the collapsed
// intermediate with one listener test; round 3 lands role:b. With count,
// it checks only round 2's listener tests.
func heldRounds(t *testing.T, count bool) {
	t.Helper()
	h := keepHost(t, true, "role:a", "role:x")
	lg := h.lastGood()
	if err := os.Remove(h.l.DropIn()); err != nil {
		t.Fatal(err)
	}
	h.sshd.setStall(true)
	h.publishDir(h.spec("role:x", "role:b"))
	r, err := h.apply()
	h.sshd.setStall(false)
	if !errors.Is(err, ErrSelfTest) || !r.Rollback || h.heldNow() != "sshd_override" || h.exists(h.l.DropIn()) {
		t.Fatalf("round 1: %v, rollback %t, held %q, drop-in present %t", err, r.Rollback, h.heldNow(), h.exists(h.l.DropIn()))
	}
	mustPrincipals(t, h, "role:x")
	m1 := h.current()
	if h.lastGood() != lg || m1 == lg {
		t.Fatalf("round 1: current %d, last-good %d (was %d)", m1, h.lastGood(), lg)
	}
	h.clock.advance(time.Minute)
	one := 0
	if count {
		one = listenerConnections(t)
	}
	before := h.sshd.acceptedNow()
	r, err = h.apply()
	got := h.sshd.acceptedNow() - before
	mustHeld(t, h, r, err, "sshd_override")
	mustPrincipals(t, h, "role:x")
	if r.Recovered || h.lastGood() != m1 || h.current() != m1 || !h.exists(h.l.DropIn()) {
		t.Fatalf("round 2: %+v, current %d, last-good %d, want %d", r, h.current(), h.lastGood(), m1)
	}
	if count {
		if got != one {
			t.Fatalf("round 2 made %d connections; one listener test makes %d", got, one)
		}
		return
	}
	h.mustApply()
	mustPrincipals(t, h, "role:b", "role:x")
}

// probeAccountShell is the passwd fixture with the probe account's shell
// set to shell.
func probeAccountShell(shell string) string {
	return "root:x:0:0:root:/root:/bin/bash\n" + strings.Replace(probeLogin, "/usr/sbin/nologin", shell, 1) + "\n"
}

// crashRecoveryKeepsRemoval crashes a mixed change (role:old removed,
// role:q added) at every fault point of forward, and of the rollback
// after a failed listener test, and checks the next start (D8).
func crashRecoveryKeepsRemoval(t *testing.T) {
	t.Helper()
	newHost := func(t *testing.T) (*testHost, spool.State) {
		h := newTestHost(t, newFixture(t))
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.installed("role:old", "role:ops")
		old := cloneState(h.state)
		h.publishKRL(7)
		h.publishDir(h.spec("role:ops", "role:q"))
		return h, old
	}
	points := func(t *testing.T, stall bool) []string {
		h, _ := newHost(t)
		fl := &faultLog{}
		h.cfg.Fault = fl.hook
		h.sshd.setStall(stall)
		_, _ = h.apply()
		return fl.points
	}
	for _, sc := range []struct {
		name  string
		stall bool
	}{{"forward", false}, {"rollback", true}} {
		ps := points(t, sc.stall)
		commitAt := 0 // the commit marker's write: points after it finish the commit
		for i, p := range ps {
			if p == "self-test" {
				for j := i + 1; j < len(ps); j++ {
					if ps[j] == "marker" {
						commitAt = j + 1
						break
					}
				}
				break
			}
		}
		start := 1
		if sc.stall {
			start = slices.Index(ps, "self-test") + 2
		}
		for k := start; k <= len(ps); k++ {
			t.Run(sc.name+"_"+strconv.Itoa(k)+"_"+strings.ReplaceAll(ps[k-1], ":", "_"), func(t *testing.T) {
				t.Parallel()
				h, _ := newHost(t)
				lg := h.lastGood()
				h.sshd.setStall(sc.stall)
				fl := &faultLog{k: k}
				h.cfg.Fault = fl.hook
				_, err := h.apply()
				h.cfg.Fault = nil
				h.sshd.setStall(false)
				if !isCrash(err) {
					t.Fatalf("no crash at %d: %v", k, err)
				}
				marker := readMarker(t, h) != nil
				switch {
				case k <= 2:
					r := h.mustApply()
					if r.Recovered != marker {
						t.Fatalf("recovered %t with marker %t", r.Recovered, marker)
					}
				case !sc.stall && commitAt != 0 && k > commitAt:
					recoverOnly(t, h, "role:old")
					if h.current() != h.lastGood() {
						t.Fatalf("the commit was not finished: current %d, last-good %d", h.current(), h.lastGood())
					}
					h.mustApply()
				default:
					if !marker {
						t.Fatalf("no marker after a crash at %d", k)
					}
					recoverOnly(t, h, "role:old")
					if !h.atKept(lg) {
						t.Fatalf("not at the kept content: current %d, last-good %d (was %d), principals %v", h.current(), h.lastGood(), lg, h.principals("deploy"))
					}
					h.mustApply()
				}
				mustPrincipals(t, h, "role:ops", "role:q")
			})
		}
	}
}

// everyForwardCallKeeps is the structural rule of 03-10d Task 1: every
// call of rollbackAs, backToLastGood and rollbackTarget keeps removals,
// except the one plain call in recoverToLastGood (owner decision Q1 = A).
func everyForwardCallKeeps(t *testing.T) {
	t.Helper()
	keepArg := map[string]int{"rollbackAs": 3, "backToLastGood": 2, "rollbackTarget": 4}
	wantCalls := map[string]int{"rollbackAs": 1, "backToLastGood": 2, "rollbackTarget": 2}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files, calls, plain, rollbackTargets := 0, map[string]int{}, 0, 0
	for _, d := range entries {
		n := d.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(".", n), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files++
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := fd.Name.Name
			direct := map[*ast.SelectorExpr]bool{}
			var plainIfEnd token.Pos
			if fn == "rollbackTarget" && len(fd.Body.List) > 0 {
				if is, ok := fd.Body.List[0].(*ast.IfStmt); ok {
					if id, ok := is.Cond.(*ast.Ident); ok && id.Name == "keep" && len(is.Body.List) > 0 {
						if _, ok := is.Body.List[len(is.Body.List)-1].(*ast.ReturnStmt); ok {
							plainIfEnd = is.End()
						}
					}
				}
			}
			if fn == "rollbackAs" || fn == "backToLastGood" {
				ast.Inspect(fd.Body, func(x ast.Node) bool {
					if as, ok := x.(*ast.AssignStmt); ok {
						for _, l := range as.Lhs {
							if id, ok := l.(*ast.Ident); ok && id.Name == "keep" {
								t.Errorf("%s assigns to keep at %s", fn, fset.Position(as.Pos()))
							}
						}
					}
					return true
				})
			}
			ast.Inspect(fd.Body, func(x ast.Node) bool {
				ce, ok := x.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == "RollbackTarget" {
					rollbackTargets++
					if fn != "rollbackTarget" || plainIfEnd == 0 || ce.Pos() < plainIfEnd {
						t.Errorf("RollbackTarget called outside rollbackTarget's plain branch, in %s at %s", fn, fset.Position(ce.Pos()))
					}
				}
				se, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				i, named := keepArg[se.Sel.Name]
				if !named {
					return true
				}
				direct[se] = true
				calls[se.Sel.Name]++
				pos := fset.Position(ce.Pos())
				if len(ce.Args) <= i {
					t.Errorf("%s at %s has no keep argument", se.Sel.Name, pos)
					return true
				}
				id, _ := ce.Args[i].(*ast.Ident)
				switch {
				case id == nil:
					t.Errorf("%s at %s: keep is not an identifier", se.Sel.Name, pos)
				case fn == "rollbackAs" || fn == "backToLastGood":
					if id.Name != "keep" || !hasParam(fd, "keep") {
						t.Errorf("%s at %s in %s passes %s, not its own keep", se.Sel.Name, pos, fn, id.Name)
					}
				case id.Name == "false" && fn == "recoverToLastGood":
					plain++
				case id.Name != "true":
					t.Errorf("%s at %s in %s passes %s", se.Sel.Name, pos, fn, id.Name)
				}
				return true
			})
			ast.Inspect(fd.Body, func(x ast.Node) bool {
				if se, ok := x.(*ast.SelectorExpr); ok && !direct[se] {
					if _, named := keepArg[se.Sel.Name]; named {
						t.Errorf("%s used as a method value in %s at %s", se.Sel.Name, fn, fset.Position(se.Pos()))
					}
				}
				return true
			})
		}
	}
	if files < 10 {
		t.Fatalf("parsed %d files: the wrong directory", files)
	}
	for name, want := range wantCalls {
		if calls[name] != want {
			t.Errorf("%d calls of %s, want %d", calls[name], name, want)
		}
	}
	if plain != 1 {
		t.Errorf("%d plain calls in recoverToLastGood, want exactly 1", plain)
	}
	if rollbackTargets != 1 {
		t.Errorf("%d calls of RollbackTarget, want 1 (rollbackTarget's plain branch)", rollbackTargets)
	}
}

func hasParam(fd *ast.FuncDecl, name string) bool {
	for _, f := range fd.Type.Params.List {
		for _, n := range f.Names {
			if n.Name == name {
				return true
			}
		}
	}
	return false
}
