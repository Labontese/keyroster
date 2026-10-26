//go:build linux

package spool

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func openDir(t *testing.T, path string) int {
	t.Helper()
	fd, err := OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// TestSpool covers the F2 open contract (REVIEWS L1362@e7b3b32): every
// file the fetcher can write is opened relative to a directory
// descriptor, without following a symlink and without blocking, must be
// a regular file within its cap, and is read once.
func TestSpool(t *testing.T) {
	t.Run("oversize_refused", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "exact"), bytes.Repeat([]byte{'a'}, 100))
		writeTestFile(t, filepath.Join(dir, "over"), bytes.Repeat([]byte{'a'}, 101))
		fd := openDir(t, dir)
		if b, err := ReadFileAt(fd, "exact", 100); err != nil || len(b) != 100 {
			t.Fatalf("max bytes: %d, %v", len(b), err)
		}
		if _, err := ReadFileAt(fd, "over", 100); !errors.Is(err, ErrOversize) {
			t.Fatalf("max+1 bytes: %v, want spool_oversize", err)
		}
	})
	t.Run("symlink_refused", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "target"), []byte("x"))
		if err := os.Symlink("target", filepath.Join(dir, "bundle-1.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadFileAt(openDir(t, dir), "bundle-1.json", 100); !errors.Is(err, ErrSymlink) {
			t.Fatalf("symlink: %v, want spool_symlink", err)
		}
	})
	t.Run("fifo_refused_without_blocking", func(t *testing.T) {
		dir := t.TempDir()
		if err := unix.Mkfifo(filepath.Join(dir, "bundle-1.json"), 0o600); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, "bundle-1.json.sigs"), []byte("x"))
		done := make(chan error, 1)
		go func() {
			_, _, err := Read(dir)
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrNotRegular) || !strings.Contains(err.Error(), "bundle-1.json") {
				t.Fatalf("FIFO: %v, want spool_not_regular naming it", err)
			}
		case <-time.After(time.Second):
			t.Fatal("Read blocked on a FIFO")
		}
	})
	t.Run("spool_dir_symlink_refused", func(t *testing.T) {
		base := t.TempDir()
		realDir := filepath.Join(base, "real")
		if err := os.Mkdir(realDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realDir, filepath.Join(base, "spool")); err != nil {
			t.Fatal(err)
		}
		if _, _, err := Read(filepath.Join(base, "spool")); !errors.Is(err, ErrSymlink) {
			t.Fatalf("symlinked spool: %v, want spool_symlink", err)
		}
		writeTestFile(t, filepath.Join(base, "file"), nil)
		if _, _, err := Read(filepath.Join(base, "file")); !errors.Is(err, ErrNotDir) {
			t.Fatalf("a file as spool: %v, want spool_not_directory", err)
		}
	})
	t.Run("symlink_to_pins_refused", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "spool")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(base, "pins.json"), []byte(`{"secret":true}`))
		if err := os.Symlink("../pins.json", filepath.Join(dir, "bundle-5.json")); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(dir, "bundle-5.json.sigs"), []byte("x"))
		st, _, err := Read(dir)
		if !errors.Is(err, ErrSymlink) || len(st.Bundles) != 0 {
			t.Fatalf("bundle-5.json -> ../pins.json: %v, %d bundles; want spool_symlink and nothing read", err, len(st.Bundles))
		}
	})
	t.Run("name_outside_patterns_ignored", func(t *testing.T) {
		dir := t.TempDir()
		for _, n := range []string{"bundle-05.json", "bundle-05.json.sigs", "bundle-1.json~", "notes.txt", "krl-01.krl"} {
			writeTestFile(t, filepath.Join(dir, n), []byte("x"))
		}
		writeTestFile(t, filepath.Join(dir, "bundle-1.json"), []byte("b"))
		writeTestFile(t, filepath.Join(dir, "bundle-1.json.sigs"), []byte("s"))
		st, ignored, err := Read(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(st.Bundles) != 1 || string(st.Bundles[1].Body) != "b" {
			t.Fatalf("bundles %v", st.Bundles)
		}
		for _, n := range []string{"bundle-05.json", "bundle-1.json~", "notes.txt", "krl-01.krl"} {
			if !slices.Contains(ignored, n) {
				t.Fatalf("ignored %v, want %s in it", ignored, n)
			}
		}
	})
	t.Run("torn_temp_never_read", func(t *testing.T) {
		dir := t.TempDir()
		// A writer killed between create and rename leaves its temporary
		// file: never read, only reported.
		writeTestFile(t, filepath.Join(dir, ".bundle-2.json.tmp-0011223344556677"), []byte("torn"))
		writeTestFile(t, filepath.Join(dir, "bundle-1.json"), []byte("b"))
		writeTestFile(t, filepath.Join(dir, "bundle-1.json.sigs"), []byte("s"))
		st, ignored, err := Read(dir)
		if err != nil || len(st.Bundles) != 1 || !slices.Contains(ignored, ".bundle-2.json.tmp-0011223344556677") {
			t.Fatalf("Read = %v, %v, %v", st.Bundles, ignored, err)
		}
	})
	t.Run("write_does_not_follow_planted_symlink", func(t *testing.T) {
		base := t.TempDir()
		dir := filepath.Join(base, "state")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(base, "victim")
		writeTestFile(t, victim, []byte("untouched"))
		if err := os.Symlink(victim, filepath.Join(dir, "status.json")); err != nil {
			t.Fatal(err)
		}
		fd := openDir(t, dir)
		if err := WriteFileAt(fd, "status.json", []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "untouched" { //nolint:gosec // test fixture
			t.Fatalf("the symlink's target was written: %q", b)
		}
		fi, err := os.Lstat(filepath.Join(dir, "status.json"))
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
			t.Fatalf("status.json after the write: %v, %v", fi, err)
		}
		// A symlink planted at a temporary name is never followed either:
		// creation is O_EXCL|O_NOFOLLOW.
		if err := os.Symlink(victim, filepath.Join(dir, ".pending.json.tmp-planted")); err != nil {
			t.Fatal(err)
		}
		if err := WriteFileAt(fd, "pending.json", []byte("p"), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "untouched" { //nolint:gosec // test fixture
			t.Fatalf("the planted temporary symlink's target was written: %q", b)
		}
	})
	t.Run("read_write_round_trip", func(t *testing.T) {
		dir := t.TempDir()
		in := State{
			Bundles:     map[uint64]Doc{1: {Body: []byte("b1"), Sigs: []byte("s1")}, 2: {Body: []byte("b2"), Sigs: []byte("s2")}},
			Policies:    map[uint64]Doc{1: {Body: []byte("p1"), Sigs: []byte("ps1")}},
			Directories: map[uint64]Doc{3: {Body: []byte("d3"), Sigs: []byte("ds3")}},
			KRLs:        map[uint64]KRLFiles{1793000001: {KRL: []byte("k1"), Manifest: []byte("m1"), Sig: []byte("g1")}, 1793000002: {KRL: []byte("k2"), Manifest: []byte("m2"), Sig: []byte("g2")}},
		}
		if err := Write(dir, in); err != nil {
			t.Fatal(err)
		}
		st, ignored, err := Read(dir)
		if err != nil || len(st.Bundles) != 2 || len(st.Directories) != 1 || len(st.KRLs) != 1 || string(st.KRLs[1793000002].KRL) != "k2" {
			t.Fatalf("Read = %+v, %v, %v", st, ignored, err)
		}
	})
	t.Run("bad_names_refused", func(t *testing.T) {
		fd := openDir(t, t.TempDir())
		for _, n := range []string{"", ".", "..", "a/b"} {
			if _, err := ReadFileAt(fd, n, 10); !errors.Is(err, ErrBadName) {
				t.Fatalf("ReadFileAt(%q): %v", n, err)
			}
			if err := WriteFileAt(fd, n, nil, 0o600); !errors.Is(err, ErrBadName) {
				t.Fatalf("WriteFileAt(%q): %v", n, err)
			}
		}
	})
}
