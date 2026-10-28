//go:build linux

package apply

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
)

// TestInstalledKRLVersion (T-03-277, the restore cross-check): the KRL
// version a host enforces is the larger of accepted/'s and current's,
// read without a lock or any write.
func TestInstalledKRLVersion(t *testing.T) {
	h := newTestHost(t, newFixture(t))
	if v, err := InstalledKRLVersion(h.l); err != nil || v != 0 {
		t.Fatalf("before the first install: %d, %v", v, err)
	}
	h.publishKRL(3)
	h.installed("role:ops")
	v0, err := InstalledKRLVersion(h.l)
	if err != nil || v0 == 0 {
		t.Fatalf("after the first install: %d, %v", v0, err)
	}
	// A revocation whose self-test fails keeps the new KRL in current;
	// accepted/ keeps the older one (the KRL never rolls back).
	h.cfg.SelfTestTimeout = 300 * time.Millisecond
	h.sshd.stop()
	h.publishKRL(7)
	if _, err := h.apply(); !errors.Is(err, ErrSelfTest) {
		t.Fatalf("the failing apply: %v", err)
	}
	cur, err := readGeneration(h.l.Gen(h.current()))
	if err != nil {
		t.Fatal(err)
	}
	v1, err := InstalledKRLVersion(h.l)
	if err != nil || v1 <= v0 || v1 != krlVersion(cur) {
		t.Fatalf("after a rollback that kept the KRL: %d (before %d, current's %d), %v", v1, v0, krlVersion(cur), err)
	}
	// It reads only: no lock file appears, and an unsafe state directory
	// is refused.
	if err := os.Remove(h.l.State(lockFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := InstalledKRLVersion(h.l); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(h.l.State(lockFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("krl-version took the apply lock")
	}
	chmod(t, h.l.StateDir, 0o770)
	if _, err := InstalledKRLVersion(h.l); !errors.Is(err, ErrStateDirUnsafe) {
		t.Fatalf("a group-writable state directory: %v", err)
	}
}

// TestWriteAccepted (PR #71 review F3/F7): every apply leaves the
// accepted versions in the outbox's accepted.json, where the fetcher
// starts its state requests; the KRL is the one the host enforces.
func TestWriteAccepted(t *testing.T) {
	h := newTestHost(t, newFixture(t))
	if err := os.Mkdir(h.l.Outbox(), 0o750); err != nil { //nolint:gosec // the outbox's mode
		t.Fatal(err)
	}
	read := func() enroll.Accepted { return readAccepted(t, h) }
	h.publishKRL(3)
	h.installed("role:ops")
	if a := read(); a.Bundle != 1 || a.Directory != 1 || a.KRL != h.f.krlVersion {
		t.Fatalf("after the first install: %+v, want bundle 1, directory 1, KRL %d", a, h.f.krlVersion)
	}
	h.publishDir(h.spec("role:ops", "role:web"))
	h.publishKRL(3, 4)
	h.mustApply()
	if a := read(); a.Directory != 2 || a.KRL != h.f.krlVersion {
		t.Fatalf("after a second apply: %+v, want directory 2, KRL %d", a, h.f.krlVersion)
	}
	if st, err := os.Stat(filepath.Join(h.l.Outbox(), enroll.AcceptedFile)); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("accepted.json mode %v (%v), want 0640", st.Mode(), err)
	}
	// 03-08: the applier never reads the outbox back. A file planted there
	// with the very bytes it would write does not make it skip the write:
	// the file is replaced (its mode is the applier's 0640 again).
	p := filepath.Join(h.l.Outbox(), enroll.AcceptedFile)
	b, err := os.ReadFile(p) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil { //nolint:gosec // G703: the test's own outbox
		t.Fatal(err)
	}
	if err := WriteAccepted(h.l); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o640 {
		t.Fatalf("a planted accepted.json with the same bytes was kept (mode %v, %v): the applier read the outbox", st.Mode(), err)
	}
}
