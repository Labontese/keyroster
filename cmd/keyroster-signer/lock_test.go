//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStateDirLock (A-CR-01, C-CR-01): serve, ca-init and install-bundle
// share one exclusive lock on the state directory, so install-bundle and
// ca-init refuse while the service runs, and a second serve refuses too.
func TestStateDirLock(t *testing.T) {
	st := newDoctorState(t)
	unlock, err := lockStateDir(st.dir)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := lockStateDir(st.dir); !errors.Is(err, errStateLocked) {
		if again != nil {
			again()
		}
		t.Fatalf("second lock = %v, want errStateLocked", err)
	}

	// install-bundle reads its documents first; the lock refusal comes
	// before any of them is parsed and before the backend is opened.
	docs := t.TempDir()
	for _, name := range []string{"bundle.json", "bundle.json.sigs", "policy.json", "policy.json.sigs"} {
		if err := os.WriteFile(filepath.Join(docs, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, args := range map[string][]string{
		"install-bundle": {"install-bundle", "--state-dir", st.dir,
			"--bundle", filepath.Join(docs, "bundle.json"), "--policy", filepath.Join(docs, "policy.json")},
		"ca-init": {"ca-init", "--state-dir", st.dir, "--backend", "agent", "--out", filepath.Join(docs, "ca-pubkeys.json")},
		"serve":   {"serve", "--state-dir", st.dir, "--socket", filepath.Join(docs, "s.sock"), "--allow-uid", "1"},
	} {
		code, out := runSigner(t, args...)
		if code != 1 || !strings.Contains(out, errStateLocked.Error()) || !strings.Contains(out, "stop the service first") {
			t.Fatalf("%s with the state directory locked exited %d, want 1 and the lock refusal:\n%s", name, code, out)
		}
	}
	if _, err := os.Stat(filepath.Join(docs, "ca-pubkeys.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ca-init wrote its output although the state directory was locked: %v", err)
	}

	unlock()
	relock, err := lockStateDir(st.dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	relock()
}
