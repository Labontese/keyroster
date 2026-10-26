//go:build linux

package state

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
)

const testID = "0123456789abcdef0123456789abcdef"

var testPins = &Pins{TrustPins: []string{"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"}, Threshold: 1, InstallationID: testID}

func stateDir(t *testing.T) (paths.Layout, int) {
	t.Helper()
	base := t.TempDir()
	l := paths.Layout{Root: filepath.Join(base, "root"), StateDir: filepath.Join(base, "state")}
	if err := os.Mkdir(l.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := spool.OpenDir(l.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return l, fd
}

// TestPins covers pins.json: written canonical and 0600, read back only
// as a regular 0600 file of the applier's own uid.
func TestPins(t *testing.T) {
	t.Run("round_trip", func(t *testing.T) {
		l, fd := stateDir(t)
		if err := WritePins(l, fd, testPins); err != nil {
			t.Fatal(err)
		}
		p, err := LoadPins(fd)
		if err != nil || p.InstallationID != testID || p.Threshold != 1 {
			t.Fatalf("LoadPins = %+v, %v", p, err)
		}
	})
	t.Run("mode_refused", func(t *testing.T) {
		l, fd := stateDir(t)
		if err := WritePins(l, fd, testPins); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(l.State(PinsFile), 0o644); err != nil { //nolint:gosec // the refusal under test
			t.Fatal(err)
		}
		if _, err := LoadPins(fd); !errors.Is(err, ErrPins) {
			t.Fatalf("pins.json mode 0644: %v, want pins_invalid", err)
		}
	})
	t.Run("symlink_refused", func(t *testing.T) {
		l, fd := stateDir(t)
		other := filepath.Join(t.TempDir(), "pins.json")
		if err := os.WriteFile(other, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(other, l.State(PinsFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPins(fd); !errors.Is(err, spool.ErrSymlink) {
			t.Fatalf("pins.json as a symlink: %v, want spool_symlink", err)
		}
	})
	t.Run("invalid_refused", func(t *testing.T) {
		for _, p := range []*Pins{
			{TrustPins: nil, Threshold: 1, InstallationID: testID},
			{TrustPins: testPins.TrustPins, Threshold: 0, InstallationID: testID},
			{TrustPins: testPins.TrustPins, Threshold: 2, InstallationID: testID},
			{TrustPins: testPins.TrustPins, Threshold: 1, InstallationID: ""},
			{TrustPins: testPins.TrustPins, Threshold: 1, InstallationID: "ABCDEF0123456789abcdef0123456789"},
		} {
			if err := p.Validate(); !errors.Is(err, ErrPins) {
				t.Fatalf("%+v: %v, want pins_invalid", p, err)
			}
		}
	})
}

// TestStored covers accepted/: nothing stored reads as nil, a state
// without its bundle and policy is never activated, and the snapshot
// pointer guards the set (PR #67 review).
func TestStored(t *testing.T) {
	accepted := func(t *testing.T) (paths.Layout, int) {
		t.Helper()
		l, _ := stateDir(t)
		if err := os.Mkdir(l.State(AcceptedDir), 0o700); err != nil {
			t.Fatal(err)
		}
		fd, err := spool.OpenDir(l.State(AcceptedDir))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return l, fd
	}
	t.Run("empty_is_nil", func(t *testing.T) {
		_, fd := accepted(t)
		s, err := LoadStored(fd)
		if err != nil || s != nil {
			t.Fatalf("LoadStored of an empty directory = %v, %v", s, err)
		}
	})
	t.Run("partial_refused", func(t *testing.T) {
		l, fd := accepted(t)
		s := &Stored{Directory: []byte(`{"version":1}`), DirectorySigs: []byte("x")}
		if err := s.Save(l, fd, nil); !errors.Is(err, ErrSnapshot) {
			t.Fatalf("saving a directory without a bundle: %v, want accepted_snapshot_invalid", err)
		}
		if s, err := LoadStored(fd); err != nil || s != nil {
			t.Fatalf("after the refused save: %v, %v, want nothing accepted", s, err)
		}
	})
	t.Run("files_without_pointer_refused", func(t *testing.T) {
		_, fd := accepted(t)
		if err := spool.WriteFileAt(fd, bundleFile, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadStored(fd); !errors.Is(err, ErrStored) {
			t.Fatalf("accepted/ files without current.json: %v, want stored_state_invalid", err)
		}
	})
	t.Run("staged_snapshot_not_in_force", func(t *testing.T) {
		l, fd := accepted(t)
		s := &Stored{Directory: []byte(`{"version":1}`), DirectorySigs: []byte("x")}
		if _, err := s.Stage(l, fd, nil); err != nil {
			t.Fatal(err)
		}
		if s, err := LoadStored(fd); err != nil || s != nil {
			t.Fatalf("a staged snapshot without Activate: %v, %v, want nothing accepted", s, err)
		}
	})
	t.Run("tampered_file_refused", func(t *testing.T) {
		_, fd := accepted(t)
		if err := unix.Mkdirat(fd, "1", 0o700); err != nil {
			t.Fatal(err)
		}
		dfd, err := openSnapshot(fd, 1)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = unix.Close(dfd) }()
		if err := spool.WriteFileAt(dfd, bundleFile, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		ptr := []byte(`{"files":{"bundle.json":"` + strings.Repeat("0", 64) + `"},"snapshot":1}`)
		if err := spool.WriteFileAt(fd, pointerFile, ptr, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadStored(fd); !errors.Is(err, ErrStored) {
			t.Fatalf("a file that does not match its SHA-256: %v, want stored_state_invalid", err)
		}
	})
}
