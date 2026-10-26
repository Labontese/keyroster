//go:build linux

package apply

import (
	"slices"
	"testing"
	"time"
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
