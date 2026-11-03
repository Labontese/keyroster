//go:build linux

package spool

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/wire"
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
			_, _, err := Read(dir, Floor{})
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
		if _, _, err := Read(filepath.Join(base, "spool"), Floor{}); !errors.Is(err, ErrSymlink) {
			t.Fatalf("symlinked spool: %v, want spool_symlink", err)
		}
		writeTestFile(t, filepath.Join(base, "file"), nil)
		if _, _, err := Read(filepath.Join(base, "file"), Floor{}); !errors.Is(err, ErrNotDir) {
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
		st, _, err := Read(dir, Floor{})
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
		st, ignored, err := Read(dir, Floor{})
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
		st, ignored, err := Read(dir, Floor{})
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
		st, ignored, err := Read(dir, Floor{})
		if err != nil || len(st.Bundles) != 2 || len(st.Directories) != 1 || len(st.KRLs) != 1 || string(st.KRLs[1793000002].KRL) != "k2" {
			t.Fatalf("Read = %+v, %v, %v", st, ignored, err)
		}
	})
	t.Run("floor_selects_versions", func(t *testing.T) {
		dir := t.TempDir()
		in := State{Directories: map[uint64]Doc{}}
		for v := uint64(1); v <= 100; v++ {
			in.Directories[v] = Doc{Body: []byte("d"), Sigs: []byte("s")}
		}
		if err := Write(dir, in); err != nil {
			t.Fatal(err)
		}
		// With a floor: the lowest MaxVersionsPerKind above it, and the
		// newest at or below it.
		st, _, err := Read(dir, Floor{Directory: 10})
		if err != nil {
			t.Fatal(err)
		}
		if len(st.Directories) != MaxVersionsPerKind+1 {
			t.Fatalf("%d directories read, want %d", len(st.Directories), MaxVersionsPerKind+1)
		}
		for _, v := range []uint64{10, 11, 10 + MaxVersionsPerKind} {
			if _, ok := st.Directories[v]; !ok {
				t.Fatalf("version %d not read", v)
			}
		}
		if _, ok := st.Directories[11+MaxVersionsPerKind]; ok {
			t.Fatal("a version beyond the window was read")
		}
		// Without one: the newest MaxVersionsPerKind.
		st, _, _ = Read(dir, Floor{})
		if _, ok := st.Directories[100]; !ok || len(st.Directories) != MaxVersionsPerKind {
			t.Fatalf("without a floor: %d read, newest read %t", len(st.Directories), ok)
		}
	})
	t.Run("cap_is_what_read_enforces", func(t *testing.T) {
		// F01 (03-08e): Cap is the cap Read applies to each recognised name,
		// so the fetcher can refuse what the applier would. Each file is
		// written in a complete set, at Cap bytes and at Cap+1. The policy
		// signatures delivered with a bundle are read with it (F02
		// (03-08f)).
		sets := map[string][]string{
			"bundle":    {"bundle-1.json", "bundle-1.json.sigs", "bundle-1.policy.sigs"},
			"policy":    {"policy-1.json", "policy-1.json.sigs"},
			"directory": {"directory-1.json", "directory-1.json.sigs"},
			"krl":       {"krl-1.krl", "krl-1.manifest.json", "krl-1.manifest.sig"},
		}
		want := map[string]int64{
			"bundle-1.json": MaxBundle, "bundle-1.json.sigs": MaxBundle, "bundle-1.policy.sigs": MaxBundle,
			"policy-1.json": MaxBundle, "policy-1.json.sigs": MaxBundle,
			"directory-1.json": wire.MaxDirectory, "directory-1.json.sigs": wire.MaxDirectorySigs,
			"krl-1.krl": krl.MaxKRL, "krl-1.manifest.json": krl.MaxManifest, "krl-1.manifest.sig": krl.MaxManifestSig,
		}
		for _, set := range sets {
			for _, name := range set {
				limit, ok := Cap(name)
				if !ok || limit != want[name] {
					t.Fatalf("Cap(%q) = %d, %t, want %d, true", name, limit, ok, want[name])
				}
				for _, n := range []int64{limit, limit + 1} {
					dir := t.TempDir()
					for _, other := range set {
						writeTestFile(t, filepath.Join(dir, other), []byte("x"))
					}
					writeTestFile(t, filepath.Join(dir, name), bytes.Repeat([]byte{'a'}, int(n)))
					_, _, err := Read(dir, Floor{})
					if n == limit && err != nil {
						t.Fatalf("%s of Cap = %d bytes: %v", name, n, err)
					}
					if n > limit && (!errors.Is(err, ErrOversize) || !strings.Contains(err.Error(), name)) {
						t.Fatalf("%s of Cap+1 = %d bytes: %v, want spool_oversize naming it", name, n, err)
					}
				}
			}
		}
		for _, name := range []string{"identity.pub", "enroll-request.json", "policy-0.json", "krl-1.json", "bundle-1.json.tmp",
			"bundle-99999999999999999999.json", "krl-99999999999999999999.krl"} {
			if limit, ok := Cap(name); ok {
				t.Fatalf("Cap(%q) = %d, true for a name Read never reads", name, limit)
			}
		}
	})
	t.Run("bundle_policy_sigs_read_when_present", func(t *testing.T) {
		// F02 (03-08f): the policy signatures delivered with a bundle are
		// read with every bundle version the capture takes, and the file
		// is not listed as ignored.
		dir := t.TempDir()
		for _, n := range []string{"bundle-1.json", "bundle-1.json.sigs", "bundle-2.json", "bundle-2.json.sigs", "bundle-3.json", "bundle-3.json.sigs"} {
			writeTestFile(t, filepath.Join(dir, n), []byte(n))
		}
		writeTestFile(t, filepath.Join(dir, "bundle-1.policy.sigs"), []byte("p1"))
		writeTestFile(t, filepath.Join(dir, "bundle-3.policy.sigs"), []byte("p3"))
		st, ignored, err := Read(dir, Floor{Bundle: 2})
		if err != nil {
			t.Fatal(err)
		}
		if len(st.Bundles) != 2 || string(st.BundlePolicySigs[3]) != "p3" || len(st.BundlePolicySigs) != 1 {
			t.Fatalf("bundles %d, per-bundle policy signatures %v; want bundles 2 and 3, bundle 3's file alone", len(st.Bundles), st.BundlePolicySigs)
		}
		for _, n := range ignored {
			if strings.Contains(n, "policy.sigs") {
				t.Fatalf("ignored %q lists a per-bundle policy signature file", ignored)
			}
		}
		// Write puts it in the spool before the bundle it belongs to.
		out := t.TempDir()
		if err := Write(out, State{Bundles: map[uint64]Doc{4: {Body: []byte("b"), Sigs: []byte("s")}}, BundlePolicySigs: map[uint64][]byte{4: []byte("p4")}}); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(filepath.Join(out, "bundle-4.policy.sigs")); err != nil || string(b) != "p4" { //nolint:gosec // test fixture
			t.Fatalf("bundle-4.policy.sigs after Write: %q, %v", b, err)
		}
	})
	t.Run("bundle_policy_sigs_absent_is_allowed", func(t *testing.T) {
		// F02 (03-08f): a spool written before 03-08f holds no per-bundle
		// file; its bundles are read as before.
		dir := t.TempDir()
		for _, n := range []string{"bundle-1.json", "bundle-1.json.sigs", "bundle-2.json", "bundle-2.json.sigs"} {
			writeTestFile(t, filepath.Join(dir, n), []byte(n))
		}
		st, _, err := Read(dir, Floor{})
		if err != nil || len(st.Bundles) != 2 || len(st.BundlePolicySigs) != 0 {
			t.Fatalf("bundles %d, per-bundle policy signatures %d (%v); want 2, 0", len(st.Bundles), len(st.BundlePolicySigs), err)
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

// TestReadRecapture (F01 (03-08e), 03-08j): a name Read's listing returned
// that is gone at its open, as when the fetcher's prune removes it in
// between, makes Read capture once more from a fresh listing; a second
// such race fails the capture as before. The seam stands in for the prune.
func TestReadRecapture(t *testing.T) {
	doc := Doc{Body: []byte("d"), Sigs: []byte("s")}
	floor := Floor{Bundle: 3, Policy: 2}
	setup := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		// Bundle 3 names policy 2; policy 9 is an orphan no bundle names,
		// inside the policy window of floor.
		in := State{Bundles: map[uint64]Doc{3: doc}, Policies: map[uint64]Doc{2: doc, 9: doc}}
		if err := Write(dir, in); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	remove := func(t *testing.T, dir string, v uint64) {
		t.Helper()
		for _, n := range []string{"policy-" + strconv.FormatUint(v, 10) + ".json", "policy-" + strconv.FormatUint(v, 10) + ".json.sigs"} {
			if err := os.Remove(filepath.Join(dir, n)); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("listed_name_gone_is_recaptured_once", func(t *testing.T) {
		dir := setup(t)
		n := 0
		st, _, err := readSpool(dir, floor, func() {
			if n++; n == 1 {
				remove(t, dir, 9)
			}
		})
		if err != nil {
			t.Fatalf("a capture racing the prune: %v, want a recapture", err)
		}
		if _, ok := st.Policies[9]; ok || n != 2 {
			t.Fatalf("policy 9 read %t, %d listings; want not read and 2", ok, n)
		}
		if _, ok := st.Policies[2]; !ok {
			t.Fatalf("policy 2 was not read")
		}
	})
	t.Run("gone_again_fails_the_capture", func(t *testing.T) {
		dir := setup(t)
		n, next := 0, uint64(9)
		_, _, err := readSpool(dir, floor, func() {
			n++
			remove(t, dir, next)
			next++
			if err := Write(dir, State{Policies: map[uint64]Doc{next: doc}}); err != nil {
				t.Fatal(err)
			}
		})
		if !errors.Is(err, unix.ENOENT) || n != 2 {
			t.Fatalf("two races in a row: %v after %d listings, want ENOENT after 2", err, n)
		}
	})
}
