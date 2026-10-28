//go:build linux

package apply

import (
	"errors"
	"os"
	"testing"
	"time"
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
