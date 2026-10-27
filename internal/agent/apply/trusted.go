//go:build linux

package apply

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrUnsafeFile is a configuration file the agent reads to decide what
// sshd does (sshd_config, a file it includes, the service's
// EnvironmentFile or OpenRC settings) that it cannot read safely: one
// another user could change (PR #68 review, D-R3 and D-R4).
var ErrUnsafeFile = errors.New("unsafe_file")

// maxSymlinkHops bounds the symlinks resolveTrusted follows, as the
// kernel's own limit does.
const maxSymlinkHops = 40

// insideRoot reports whether the clean absolute path p is root or below
// it.
func insideRoot(p, root string) bool {
	return root == "/" || p == root || strings.HasPrefix(p, root+"/")
}

// trustedNode refuses an entry another user could change: owned by
// another uid than the applier's (root), or, unless it is a symlink,
// writable by group or others.
func trustedNode(p string, st *unix.Stat_t) error {
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrUnsafeFile, p, st.Uid, os.Geteuid())
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK && st.Mode&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others (mode %04o)", ErrUnsafeFile, p, st.Mode&0o7777)
	}
	return nil
}

// resolveTrusted resolves the absolute path p inside root (the layout's
// root: "/" in production), following only symlinks the applier's uid
// owns: root and every directory, symlink and the final entry on the way
// must pass trustedNode, and every path a symlink leads to must stay
// inside root. It returns the resolved path and its Lstat. A missing
// entry is its error (errors.Is unix.ENOENT); everything else refused is
// ErrUnsafeFile.
func resolveTrusted(root, p string) (string, *unix.Stat_t, error) {
	root = filepath.Clean(root)
	if !filepath.IsAbs(root) || !filepath.IsAbs(p) {
		return "", nil, fmt.Errorf("%w: %q is not an absolute path", ErrUnsafeFile, p)
	}
	p = filepath.Clean(p)
	for hops := 0; ; {
		if !insideRoot(p, root) {
			return "", nil, fmt.Errorf("%w: %s is outside %s", ErrUnsafeFile, p, root)
		}
		var st unix.Stat_t
		if err := unix.Lstat(root, &st); err != nil {
			return "", nil, fmt.Errorf("%s: %w", root, err)
		}
		if err := trustedNode(root, &st); err != nil {
			return "", nil, err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return "", nil, fmt.Errorf("%w: %s: %w", ErrUnsafeFile, p, err)
		}
		var parts []string
		if rel != "." {
			parts = strings.Split(rel, "/")
		}
		cur, next := root, ""
		for i, c := range parts {
			n := filepath.Join(cur, c)
			if err := unix.Lstat(n, &st); err != nil {
				return "", nil, fmt.Errorf("%s: %w", n, err)
			}
			if err := trustedNode(n, &st); err != nil {
				return "", nil, err
			}
			switch st.Mode & unix.S_IFMT {
			case unix.S_IFLNK:
				if hops++; hops > maxSymlinkHops {
					return "", nil, fmt.Errorf("%w: %s: more than %d symlinks", ErrUnsafeFile, p, maxSymlinkHops)
				}
				target, err := os.Readlink(n)
				if err != nil {
					return "", nil, fmt.Errorf("%s: %w", n, err)
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(cur, target)
				}
				next = filepath.Join(append([]string{target}, parts[i+1:]...)...)
			case unix.S_IFDIR:
				cur = n
				continue
			default:
				if i != len(parts)-1 {
					return "", nil, fmt.Errorf("%w: %s is not a directory", ErrUnsafeFile, n)
				}
				cur = n
			}
			if next != "" {
				break
			}
		}
		if next == "" {
			return cur, &st, nil
		}
		p = next
	}
}

// readTrusted reads the regular file at p (inside root) when
// resolveTrusted accepts it: the file is opened by its resolved path with
// O_NOFOLLOW and must still be the entry that was checked. A file larger
// than limit bytes is ErrUnsafeFile, never read in part.
func readTrusted(root, p string, limit int64) ([]byte, error) {
	resolved, st, err := resolveTrusted(root, p)
	if err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafeFile, resolved)
	}
	fd, err := unix.Open(resolved, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", resolved, err)
	}
	f := os.NewFile(uintptr(fd), resolved) //nolint:gosec // G115: a file descriptor from unix.Open
	defer func() { _ = f.Close() }()
	var fst unix.Stat_t
	if err := unix.Fstat(fd, &fst); err != nil {
		return nil, fmt.Errorf("%s: %w", resolved, err)
	}
	if fst.Dev != st.Dev || fst.Ino != st.Ino {
		return nil, fmt.Errorf("%w: %s changed while it was read", ErrUnsafeFile, resolved)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", resolved, err)
	}
	if int64(len(b)) > limit {
		// sshd and systemd read the whole file: a setting past the limit
		// would be in force but unseen (PR #68 review fix round 2, P5).
		return nil, fmt.Errorf("%w: %s is larger than %d bytes, more than the agent reads", ErrUnsafeFile, resolved, limit)
	}
	return b, nil
}
