//go:build linux

package apply

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
)

// Layout is the agent's on-disk layout (internal/agent/paths): the
// keyroster tree with gen/<N>, current and last-good, the drop-in and the
// state directory.
type Layout = paths.Layout

// State directory entries.
const (
	pendingFile    = "pending.json"
	lockFile       = "apply.lock"
	dropinPrevFile = "dropin.prev"
	lastSwapFile   = "last_swap.json"
	loginGraceFile = "login_grace.json"
	statusFile     = "status.json"
	generationsDir = "generations"
	checkDir       = "check"
)

// ErrStateDirUnsafe is a state directory, or one of its subdirectories,
// that another user could change: not a directory owned by the applier's
// effective uid, writable by group or others, or a symlink.
var ErrStateDirUnsafe = errors.New("state_dir_unsafe")

// checkOwnDir refuses path unless it is a directory (not a symlink)
// owned by the effective uid with no group or world write bit.
func checkOwnDir(path string) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrStateDirUnsafe, path, err)
	}
	switch {
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		return fmt.Errorf("%w: %s is a symlink", ErrStateDirUnsafe, path)
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return fmt.Errorf("%w: %s is not a directory", ErrStateDirUnsafe, path)
	case int(st.Uid) != os.Geteuid():
		return fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrStateDirUnsafe, path, st.Uid, os.Geteuid())
	case st.Mode&0o022 != 0:
		return fmt.Errorf("%w: %s is writable by group or others (mode %04o)", ErrStateDirUnsafe, path, st.Mode&0o7777)
	}
	return nil
}

// mkdir creates path with mode when it is missing, after paths.Allowed.
// An existing directory is left as it is.
func (e *engine) mkdir(path string, mode os.FileMode) error {
	if err := paths.Allowed(e.l, path); err != nil {
		return err
	}
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// mkdirMode is mkdir followed by a chmod to mode, for a directory that
// must have exactly mode whatever the umask, and whether it was created
// now or before (PR #67 review: sshd opens AuthorizedPrincipalsFile as the
// target user, so the keyroster tree must be traversable by everyone).
func (e *engine) mkdirMode(path string, mode os.FileMode) error {
	if err := paths.Allowed(e.l, path); err != nil {
		return err
	}
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return os.Chmod(path, mode) //nolint:gosec // G302: the keyroster tree is world-traversable by design; only root writes it
}

// writeFile writes data to dir/name atomically (spool.WriteFileAt), after
// paths.Allowed: dir is opened with O_DIRECTORY|O_NOFOLLOW and the file
// created relative to it.
func (e *engine) writeFile(dir, name string, data []byte, mode uint32) error {
	if err := paths.Allowed(e.l, filepath.Join(dir, name)); err != nil {
		return err
	}
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return spool.WriteFileAt(fd, name, data, mode)
}

// writeState writes a state-directory file, mode 0600.
func (e *engine) writeState(name string, data []byte) error {
	return e.writeFile(e.l.StateDir, name, data, 0o600)
}

// remove deletes path (a file or an empty directory or a link) after
// paths.Allowed; a missing path is not an error.
func (e *engine) remove(path string) error {
	if err := paths.Allowed(e.l, path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// removeAll deletes path and everything below it after paths.Allowed.
func (e *engine) removeAll(path string) error {
	if err := paths.Allowed(e.l, path); err != nil {
		return err
	}
	return os.RemoveAll(path)
}

// renameDir renames a directory the agent created, after paths.Allowed
// for both names. It is used only for a generation directory; links are
// replaced only by replaceLink (swap.go).
func (e *engine) renameDir(from, to string) error {
	if err := paths.Allowed(e.l, from); err != nil {
		return err
	}
	if err := paths.Allowed(e.l, to); err != nil {
		return err
	}
	return os.Rename(from, to)
}

// fsyncDir fsyncs a directory.
func fsyncDir(path string) error {
	fd, err := spool.OpenDir(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.Fsync(fd)
}

// readState reads a state-directory file of at most max bytes through
// spool.ReadFileAt; a missing file is (nil, nil).
func (e *engine) readState(name string, limit int64) ([]byte, error) {
	b, err := spool.ReadFileAt(e.stateFd, name, limit)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	return b, err
}
