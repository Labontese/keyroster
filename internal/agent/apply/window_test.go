//go:build linux

package apply

import (
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/state"
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
}
