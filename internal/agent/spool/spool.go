//go:build linux

// Package spool is the hand-over between the unprivileged fetcher (03-07)
// and the root applier: a directory of signed documents, one file each,
// written atomically by the fetcher and read by the applier. The spool
// holds data only, never commands, and the applier treats every byte as
// untrusted until state.Verify has checked it against its own pins.
//
// Every file the fetcher can write is read through ReadFileAt (F2): opened
// relative to a directory descriptor with O_NOFOLLOW and O_NONBLOCK,
// checked to be a regular file within its kind's cap, and read once, at
// most cap+1 bytes. A symlink, FIFO, device, directory or oversize file is
// refused without blocking. WriteFileAt is the matching atomic writer.
package spool

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/wire"
)

// Refusals of the open contract. Each error's text starts with its code.
var (
	ErrNotRegular = errors.New("spool_not_regular")
	ErrOversize   = errors.New("spool_oversize")
	ErrSymlink    = errors.New("spool_symlink")
	ErrBadName    = errors.New("spool_bad_name")
	ErrNotDir     = errors.New("spool_not_directory")
)

// Size caps per kind (Task 2 of 03-05).
const (
	// MaxBundle bounds a trust bundle, a policy and the signature file of
	// each.
	MaxBundle = 1 << 20
	// MaxVersionsPerKind bounds how many versions of the bundle, policy
	// and directory the applier reads from one spool capture (see Floor).
	// A host further behind than that catches up over several applies,
	// MaxVersionsPerKind versions at a time.
	MaxVersionsPerKind = 64
)

// Floor is what the applier has accepted already, by kind (0: nothing).
// Read takes, for a kind with a floor, the lowest MaxVersionsPerKind
// versions above it, so that the chain from the floor is never cut, plus
// the newest version at or below it, so that an equal version reads as a
// no-op and an older one is refused; for a kind without a floor, the
// newest MaxVersionsPerKind versions.
type Floor struct {
	Bundle, Policy, Directory uint64
}

// Doc is one signed document and its detached signatures.
type Doc struct {
	Body, Sigs []byte
}

// KRLFiles is one published KRL version: the KRL, its manifest and the
// ops key's signature over the manifest.
type KRLFiles struct {
	KRL, Manifest, Sig []byte
}

// State is what one spool capture holds, by version. Only complete sets
// are listed (a document with its signatures, a KRL with its manifest and
// signature), and of the KRLs only the newest complete one: the applier
// never uses an older KRL.
type State struct {
	Bundles     map[uint64]Doc
	Policies    map[uint64]Doc
	Directories map[uint64]Doc
	KRLs        map[uint64]KRLFiles
}

var (
	docRE = regexp.MustCompile(`^(bundle|policy|directory)-([1-9][0-9]{0,19})\.json(\.sigs)?$`)
	krlRE = regexp.MustCompile(`^krl-([1-9][0-9]{0,19})\.(krl|manifest\.json|manifest\.sig)$`)
)

// checkName refuses a name that is not one path component.
func checkName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') || strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: %q", ErrBadName, name)
	}
	return nil
}

// OpenDir opens path as a directory with O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC:
// a symlink in its place is ErrSymlink, anything but a directory
// ErrNotDir. The caller closes the descriptor with unix.Close.
func OpenDir(path string) (int, error) {
	for {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		switch {
		case err == nil:
			return fd, nil
		case errors.Is(err, unix.EINTR):
			continue
		case errors.Is(err, unix.ELOOP):
			return -1, fmt.Errorf("%w: %s is a symlink", ErrSymlink, path)
		case errors.Is(err, unix.ENOTDIR):
			// O_DIRECTORY|O_NOFOLLOW on a symlink fails ENOTDIR on Linux.
			var st unix.Stat_t
			if unix.Lstat(path, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
				return -1, fmt.Errorf("%w: %s is a symlink", ErrSymlink, path)
			}
			return -1, fmt.Errorf("%w: %s is not a directory", ErrNotDir, path)
		}
		return -1, fmt.Errorf("open directory %s: %w", path, err)
	}
}

// Info is what fstat said about a file ReadFileAtInfo read.
type Info struct {
	Mode uint32 // permission bits
	UID  uint32
}

// ReadFileAt reads name, one path component, relative to the directory
// descriptor dirfd: opened with O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC
// (a symlink is ErrSymlink, a FIFO opens without blocking), then fstat
// must show a regular file (ErrNotRegular) of at most limit bytes
// (ErrOversize), and at most limit+1 bytes are read, refusing limit+1.
func ReadFileAt(dirfd int, name string, limit int64) ([]byte, error) {
	b, _, err := ReadFileAtInfo(dirfd, name, limit)
	return b, err
}

// ReadFileAtInfo is ReadFileAt that also returns the file's mode and
// owner from the same fstat.
func ReadFileAtInfo(dirfd int, name string, limit int64) ([]byte, Info, error) {
	if err := checkName(name); err != nil {
		return nil, Info{}, err
	}
	var fd int
	for {
		var err error
		fd, err = unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ELOOP) {
			return nil, Info{}, fmt.Errorf("%w: %s is a symlink", ErrSymlink, name)
		}
		if err != nil {
			return nil, Info{}, fmt.Errorf("open %s: %w", name, err)
		}
		break
	}
	f := os.NewFile(uintptr(fd), name) //nolint:gosec // G115: a file descriptor is non-negative
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, Info{}, fmt.Errorf("fstat %s: %w", name, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, Info{}, fmt.Errorf("%w: %s is not a regular file", ErrNotRegular, name)
	}
	if st.Size > limit {
		return nil, Info{}, fmt.Errorf("%w: %s is %d bytes, above %d", ErrOversize, name, st.Size, limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, Info{}, fmt.Errorf("read %s: %w", name, err)
	}
	if int64(len(b)) > limit {
		return nil, Info{}, fmt.Errorf("%w: %s grew above %d bytes while it was read", ErrOversize, name, limit)
	}
	return b, Info{Mode: st.Mode & 0o7777, UID: st.Uid}, nil
}

// WriteFileAt writes data to name, one path component, in the directory
// dirfd, atomically: a fresh temporary name in the same directory created
// with O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC (so a symlink planted
// at it is never followed), the data, fchmod to mode, fsync, renameat over
// name (which replaces a symlink at name instead of following it) and an
// fsync of the directory. The fetcher's spool writes, the applier's state
// writes and its outbox writes (03-07, 03-08) all use it.
func WriteFileAt(dirfd int, name string, data []byte, mode uint32) error {
	if err := checkName(name); err != nil {
		return err
	}
	var (
		fd  int
		tmp string
	)
	for attempt := 0; ; attempt++ {
		var rnd [8]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			return err
		}
		tmp = "." + name + ".tmp-" + hex.EncodeToString(rnd[:])
		var err error
		fd, err = unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode&0o7777)
		if err == nil {
			break
		}
		if (errors.Is(err, unix.EEXIST) || errors.Is(err, unix.EINTR)) && attempt < 8 {
			continue
		}
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	f := os.NewFile(uintptr(fd), tmp) //nolint:gosec // G115: a file descriptor is non-negative
	fail := func(err error) error {
		_ = f.Close()
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("write %s: %w", tmp, err))
	}
	if err := unix.Fchmod(fd, mode&0o7777); err != nil {
		return fail(fmt.Errorf("chmod %s: %w", tmp, err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("fsync %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := unix.Renameat(dirfd, tmp, dirfd, name); err != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return fmt.Errorf("rename %s: %w", name, err)
	}
	return unix.Fsync(dirfd)
}

// ListDir returns the names in the directory dirfd, sorted.
func ListDir(dirfd int) ([]string, error) {
	dup, err := unix.Dup(dirfd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(dup)
	f := os.NewFile(uintptr(dup), "dir") //nolint:gosec // G115: a file descriptor is non-negative
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}
	slices.Sort(names)
	return names, nil
}

// Read captures the spool at dir: it opens dir with OpenDir (a symlink or
// non-directory in its place refuses the whole spool), lists it, and
// reads every recognised name through ReadFileAt with its kind's cap:
// bundle and policy and their signatures MaxBundle, directory
// wire.MaxDirectory with wire.MaxDirectorySigs for its signatures, the
// KRL krl.MaxKRL, its manifest krl.MaxManifest and the manifest's
// signature krl.MaxManifestSig. Names outside the fixed patterns, sets
// that are not complete, versions Floor leaves out and every KRL but the
// newest complete one are not read; they are returned as ignored, for the
// report. A recognised file that fails the open contract refuses the
// whole capture.
func Read(dir string, floor Floor) (State, []string, error) {
	st := State{Bundles: map[uint64]Doc{}, Policies: map[uint64]Doc{}, Directories: map[uint64]Doc{}, KRLs: map[uint64]KRLFiles{}}
	fd, err := OpenDir(dir)
	if err != nil {
		return st, nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := ListDir(fd)
	if err != nil {
		return st, nil, fmt.Errorf("list spool %s: %w", dir, err)
	}
	present := map[string]bool{}
	var ignored []string
	docs := map[string][]uint64{}
	var krls []uint64
	for _, n := range names {
		present[n] = true
		if m := docRE.FindStringSubmatch(n); m != nil {
			v, err := strconv.ParseUint(m[2], 10, 64)
			if err != nil {
				ignored = append(ignored, n)
				continue
			}
			if m[3] == "" {
				docs[m[1]] = append(docs[m[1]], v)
			}
			continue
		}
		if m := krlRE.FindStringSubmatch(n); m != nil {
			v, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil {
				ignored = append(ignored, n)
				continue
			}
			if m[2] == "krl" {
				krls = append(krls, v)
			}
			continue
		}
		ignored = append(ignored, n)
	}
	caps := map[string][2]int64{
		"bundle":    {MaxBundle, MaxBundle},
		"policy":    {MaxBundle, MaxBundle},
		"directory": {wire.MaxDirectory, wire.MaxDirectorySigs},
	}
	targets := map[string]map[uint64]Doc{"bundle": st.Bundles, "policy": st.Policies, "directory": st.Directories}
	floors := map[string]uint64{"bundle": floor.Bundle, "policy": floor.Policy, "directory": floor.Directory}
	for _, kind := range []string{"bundle", "policy", "directory"} {
		var complete []uint64
		for _, v := range docs[kind] {
			base := kind + "-" + strconv.FormatUint(v, 10) + ".json"
			if present[base+".sigs"] {
				complete = append(complete, v)
			} else {
				ignored = append(ignored, base+" (no "+base+".sigs)")
			}
		}
		take := pick(complete, floors[kind])
		for _, v := range complete {
			base := kind + "-" + strconv.FormatUint(v, 10) + ".json"
			if !take[v] {
				ignored = append(ignored, base+" (outside the versions read this time)")
				continue
			}
			body, err := ReadFileAt(fd, base, caps[kind][0])
			if err != nil {
				return st, ignored, err
			}
			sigs, err := ReadFileAt(fd, base+".sigs", caps[kind][1])
			if err != nil {
				return st, ignored, err
			}
			targets[kind][v] = Doc{Body: body, Sigs: sigs}
		}
	}
	slices.Sort(krls)
	slices.Reverse(krls)
	read := false
	for _, v := range krls {
		base := "krl-" + strconv.FormatUint(v, 10)
		if read || !present[base+".manifest.json"] || !present[base+".manifest.sig"] {
			ignored = append(ignored, base+".krl (not the newest complete KRL)")
			continue
		}
		var files KRLFiles
		for _, f := range []struct {
			name string
			max  int64
			dst  *[]byte
		}{{base + ".krl", krl.MaxKRL, &files.KRL}, {base + ".manifest.json", krl.MaxManifest, &files.Manifest}, {base + ".manifest.sig", krl.MaxManifestSig, &files.Sig}} {
			b, err := ReadFileAt(fd, f.name, f.max)
			if err != nil {
				return st, ignored, err
			}
			*f.dst = b
		}
		st.KRLs[v] = files
		read = true
	}
	return st, ignored, nil
}

// pick is Floor's rule over the complete versions vs of one kind.
func pick(vs []uint64, floor uint64) map[uint64]bool {
	slices.Sort(vs)
	take := map[uint64]bool{}
	if floor == 0 {
		for i := len(vs) - 1; i >= 0 && len(take) < MaxVersionsPerKind; i-- {
			take[vs[i]] = true
		}
		return take
	}
	var below uint64
	n := 0
	for _, v := range vs {
		switch {
		case v <= floor:
			below = v
		case n < MaxVersionsPerKind:
			take[v] = true
			n++
		}
	}
	if below != 0 {
		take[below] = true
	}
	return take
}

// Write stores s in the spool at dir through WriteFileAt (mode 0644),
// signatures and manifests before the file that completes a set, so a
// reader never sees a set without the bytes that complete it. It is the
// fetcher's writer (03-07); the applier never calls it.
func Write(dir string, s State) error {
	fd, err := OpenDir(dir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	for _, k := range []struct {
		kind string
		docs map[uint64]Doc
	}{{"bundle", s.Bundles}, {"policy", s.Policies}, {"directory", s.Directories}} {
		for v, d := range k.docs {
			base := k.kind + "-" + strconv.FormatUint(v, 10) + ".json"
			if err := WriteFileAt(fd, base+".sigs", d.Sigs, 0o644); err != nil {
				return err
			}
			if err := WriteFileAt(fd, base, d.Body, 0o644); err != nil {
				return err
			}
		}
	}
	for v, f := range s.KRLs {
		base := "krl-" + strconv.FormatUint(v, 10)
		for _, w := range []struct {
			name string
			data []byte
		}{{base + ".manifest.sig", f.Sig}, {base + ".manifest.json", f.Manifest}, {base + ".krl", f.KRL}} {
			if err := WriteFileAt(fd, w.name, w.data, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}
