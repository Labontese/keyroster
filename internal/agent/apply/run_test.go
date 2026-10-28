//go:build linux

package apply

import (
	"context"
	"slices"
	"testing"
	"time"
)

// TestRunCatchUp (PR #71 review F9): with more directory versions queued
// in the spool than one capture reads (spool.MaxVersionsPerKind), keyroster
// -agent run applies again until the spool is drained, so the last
// version, which removes a principal, takes effect without waiting for
// another version to arrive.
func TestRunCatchUp(t *testing.T) {
	h := newTestHost(t, newFixture(t))
	h.installed("role:ops", "role:old")
	for range 68 {
		h.publishDir(h.spec("role:ops", "role:old"))
	}
	h.publishDir(h.spec("role:ops"))
	h.write()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, RunConfig{Config: h.cfg, Interval: 20 * time.Millisecond, Retry: time.Hour}, h.l)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !slices.Equal(h.principals("deploy"), []string{"role:ops"}) {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("70 queued directory versions: principals %v after 10 s, want the last version's [role:ops]", h.principals("deploy"))
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}
