//go:build linux

package signer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/tlog"
)

// serveKRL serves e's signer on a socket in a short temporary directory,
// with krlLoop's ticker replaced by tick. It returns once krlLoop has
// started, which is after Serve's own start-up check, and the function
// that stops Serve and waits for it.
func serveKRL(t *testing.T, e *logEnv, tick chan time.Time) (stop func()) {
	t.Helper()
	dir, err := os.MkdirTemp("", "krkl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := Listen(filepath.Join(dir, "s.sock"), -1)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	e.s.newKRLTicker = func() (<-chan time.Time, func()) {
		close(started)
		return tick, func() {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- e.s.Serve(ctx, l) }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("krlLoop did not start")
	}
	return func() {
		t.Helper()
		cancel()
		if err := <-served; err != nil {
			t.Fatalf("Serve: %v", err)
		}
	}
}

// publishes returns the krl_publish leaves of e's log.
func publishes(e *logEnv) []tlog.Leaf {
	var out []tlog.Leaf
	for _, l := range e.leavesOf() {
		if l.Kind == tlog.KindKRLPublish {
			out = append(out, l)
		}
	}
	return out
}

// TestKRLStartupAndRepublish (D-10, Q1): a fresh installation whose bundle
// has an installation ID publishes its first, empty KRL when Serve starts,
// as the first leaf the started signer writes, with krl_version = the
// publish time in seconds; a check less than an hour after it publishes
// nothing; a check an hour later publishes the next version, strictly
// greater, with a fresh issued_at and the same set; a restarted signer
// whose KRL is under an hour old publishes nothing at start; and audit
// verify accepts the log.
func TestKRLStartupAndRepublish(t *testing.T) {
	fx := NewFixture(t, 1, 1)
	fx.InstallationID = testInstallationID
	clock := &tickingClock{now: time.Unix(time.Now().Unix(), 0)}
	e := newLogEnvClock(t, fx, clock.Now)
	if got := e.s.GetKRL(); len(got.KRL) != 0 {
		t.Fatal("a KRL is published before the signer served")
	}
	tick := make(chan time.Time)
	stop := serveKRL(t, e, tick)
	first := publishes(e)
	if len(first) != 1 || first[0].Index != e.base {
		t.Fatalf("krl_publish leaves after the start: %+v; want one, at index %d (the first leaf the started signer writes)", first, e.base)
	}
	b0, err := tlog.DecodeKRLPublishBody(first[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(clock.Now().Unix()); b0.KRLVersion != want || b0.IssuedAtSeconds != want { //nolint:gosec // G115: after 1970
		t.Fatalf("first KRL version %d, issued_at %d; want both the publish time %d", b0.KRLVersion, b0.IssuedAtSeconds, want)
	}
	empty, err := krl.Encode(krl.Set{}, b0.KRLVersion, time.Unix(int64(b0.IssuedAtSeconds), 0)) //nolint:gosec // G115: a test time
	if err != nil {
		t.Fatal(err)
	}
	if got := e.s.GetKRL(); string(got.KRL) != string(empty) {
		t.Fatal("the first KRL is not the empty KRL")
	}

	// A check 59 minutes later publishes nothing (the tick is received
	// before the next one can be sent, so the second send waits for the
	// first check to finish).
	clock.set(clock.Now().Add(59*time.Minute), false)
	tick <- time.Now()
	tick <- time.Now()
	if n := len(publishes(e)); n != 1 {
		t.Fatalf("%d krl_publish leaves after a check under an hour after the first, want 1", n)
	}
	// An hour after the first publish, the next version.
	clock.set(time.Unix(int64(b0.IssuedAtSeconds), 0).Add(time.Hour), false) //nolint:gosec // G115: a test time
	tick <- time.Now()
	tick <- time.Now()
	stop()
	all := publishes(e)
	if len(all) != 2 {
		t.Fatalf("%d krl_publish leaves after the hourly check, want 2", len(all))
	}
	b1, err := tlog.DecodeKRLPublishBody(all[1].Body)
	if err != nil {
		t.Fatal(err)
	}
	if b1.KRLVersion <= b0.KRLVersion || b1.IssuedAtSeconds != b0.IssuedAtSeconds+3600 {
		t.Fatalf("re-published version %d, issued_at %d; want above %d and issued an hour after %d", b1.KRLVersion, b1.IssuedAtSeconds, b0.KRLVersion, b0.IssuedAtSeconds)
	}
	rep := e.verifyExport()
	if rep.KRLPublishes != 2 || rep.KRLVersion != b1.KRLVersion {
		t.Fatalf("audit report: %d KRL publishes, last version %d; want 2 and %d", rep.KRLPublishes, rep.KRLVersion, b1.KRLVersion)
	}

	// Restarted with a KRL published under an hour ago: nothing at start.
	e.close()
	if err := e.open(); err != nil {
		t.Fatal(err)
	}
	clock.set(clock.Now().Add(10*time.Minute), false)
	stop = serveKRL(t, e, make(chan time.Time))
	stop()
	if n := len(publishes(e)); n != 2 {
		t.Fatalf("%d krl_publish leaves after a restart with a fresh KRL, want 2", n)
	}
}
