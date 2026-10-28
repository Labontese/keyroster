//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/apply"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "install",
		Summary: "enroll this host: read a join file and lay out the applier's and the fetcher's files (run as root)",
		Run:     runInstall,
	})
}

const installUsage = `usage: keyroster-agent install --join-file FILE [--root DIR] [--state-dir DIR]
       [--fetch-user NAME]

Reads the join string an admin made with keyroster host join-token (a 0600
file, never an argument) and lays out the agent's files, each with its
owner and mode, created relative to its parent opened without following
links (F2):

  <state>                                 root:root 0755
  <state>/accepted                        root:root 0700
  <state>/pins.json                       root 0600 (trust pins, threshold,
                                          installation ID)
  <state>/spool                           keyroster-agent:root 0750
  <state>/outbox                          root:keyroster-agent 2750
  <root>/etc/keyroster-agent              root:root 0755
  <root>/etc/keyroster-agent/fetch.json   root:keyroster-agent 0640 (agent
                                          server URL, TLS roots and pins)
  <root>/var/lib/keyroster-agent-fetch    keyroster-agent 0700
  .../keyroster-agent-fetch/join-token    keyroster-agent 0600 (the token)

The fetcher (keyroster-agent-fetch, user keyroster-agent) can write only
its own directory and the spool. A path that exists already as a symlink,
as the wrong type, with another owner or a wider mode is refused
(install_path_unsafe) before anything is written, and so is a pins.json
that pins something else (install_pins_differ). The system user
(--fetch-user, default keyroster-agent) must exist.
`

// Install refusals.
var (
	errInstallPathUnsafe = errors.New("install_path_unsafe")
	errInstallPinsDiffer = errors.New("install_pins_differ")
)

// defaultFetchUser is the fetcher's system user.
const defaultFetchUser = "keyroster-agent"

// maxJoinFile bounds the join file read.
const maxJoinFile = join.MaxString + 2

// installPath is one path install lays out.
type installPath struct {
	path     string
	dir      bool
	uid, gid int
	mode     uint32
}

// installFile is a file install writes, with its contents.
type installFile struct {
	installPath
	data []byte
}

func runInstall(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("install", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, installUsage) }
	joinFile := fset.String("join-file", "", "the file holding the join string (required)")
	root := fset.String("root", "/", "the root of the file system the agent's files are under")
	stateDir := fset.String("state-dir", defaultStateDir, "the applier's state directory")
	fetchUser := fset.String("fetch-user", defaultFetchUser, "the fetcher's system user (tests set another)")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 || *joinFile == "" {
		return errUsage
	}
	for name, v := range map[string]string{"--root": *root, "--state-dir": *stateDir} {
		if !filepath.IsAbs(v) {
			_, _ = fmt.Fprintf(stderr, "install: %s must be an absolute path\n", name)
			return errUsage
		}
	}
	j, err := readJoinFile(*joinFile)
	if err != nil {
		return err
	}
	u, err := user.Lookup(*fetchUser)
	if err != nil {
		return fmt.Errorf("the fetcher's system user %s does not exist: create it first (docs/runbooks/host-setup.md \"Enrolling a host\"): %w", *fetchUser, err)
	}
	fuid, err1 := strconv.Atoi(u.Uid)
	fgid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return fmt.Errorf("the system user %s has no numeric uid and gid", *fetchUser)
	}
	l := apply.Layout{Root: filepath.Clean(*root), StateDir: filepath.Clean(*stateDir)}
	ruid, rgid := os.Geteuid(), os.Getegid()
	layout := []installPath{
		{path: l.StateDir, dir: true, uid: ruid, gid: rgid, mode: 0o755},
		{path: l.State(state.AcceptedDir), dir: true, uid: ruid, gid: rgid, mode: 0o700},
		{path: l.Spool(), dir: true, uid: fuid, gid: rgid, mode: 0o750},
		{path: l.Outbox(), dir: true, uid: ruid, gid: fgid, mode: 0o2750},
		{path: l.FetchConfigDir(), dir: true, uid: ruid, gid: rgid, mode: 0o755},
		{path: l.FetchDir(), dir: true, uid: fuid, gid: fgid, mode: 0o700},
	}
	fc, err := trust.CanonicalJSON(join.FetchConfigOf(j))
	if err != nil {
		return err
	}
	tok, err := trust.CanonicalJSON(join.FetcherTokenOf(j))
	if err != nil {
		return err
	}
	files := []installFile{
		{installPath{path: l.FetchConfig(), uid: ruid, gid: fgid, mode: 0o640}, fc},
		{installPath{path: l.JoinTokenFile(), uid: fuid, gid: fgid, mode: 0o600}, tok},
	}
	pins := &state.Pins{TrustPins: j.TrustPins, Threshold: j.Threshold, InstallationID: j.InstallationID}
	wantPins, err := trust.CanonicalJSON(pins)
	if err != nil {
		return err
	}
	// Check everything first: a refusal writes nothing.
	for _, p := range layout {
		if err := checkInstallPath(p); err != nil {
			return err
		}
	}
	for _, f := range files {
		if err := checkInstallPath(f.installPath); err != nil {
			return err
		}
	}
	if err := checkInstallPath(installPath{path: l.State(state.PinsFile), uid: ruid, gid: rgid, mode: 0o600}); err != nil {
		return err
	}
	if old, err := os.ReadFile(l.State(state.PinsFile)); err == nil && !bytes.Equal(old, wantPins) { //nolint:gosec // G304: the agent's own pins.json, checked above
		return fmt.Errorf("%w: %s pins another trust root set or installation; this host is enrolled already. "+
			"To enroll it into another deployment, remove the agent's state first (docs/runbooks/host-setup.md)", errInstallPinsDiffer, l.State(state.PinsFile))
	}
	for _, p := range layout {
		if err := mkdirInstall(l, p); err != nil {
			return err
		}
	}
	stateFd, err := spool.OpenDir(l.StateDir)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(stateFd) }()
	if err := state.WritePins(l, stateFd, pins); err != nil {
		return err
	}
	for _, f := range files {
		if err := writeInstallFile(l, f.installPath, f.data); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "Installed the agent for host %s of installation %s (agent server %s, join token expires %s).\n"+
		"Next: start keyroster-agent-fetch as %s and keyroster-agent run as root (docs/runbooks/host-setup.md \"Enrolling a host\"),\n"+
		"then ask an admin to run keyroster host pending and compare with keyroster-agent identity here.\n",
		j.ExpectedName, j.InstallationID, j.Server, j.ExpiresAt, *fetchUser)
	return err
}

// readJoinFile reads and parses the join file. Its text never reaches an
// error message: join's errors name the rule, not the token.
func readJoinFile(path string) (*join.JoinToken, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the join file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxJoinFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxJoinFile {
		return nil, fmt.Errorf("%w: %s is larger than a join string", join.ErrInvalid, path)
	}
	return join.Parse(string(b))
}

// checkInstallPath refuses a path that exists as a symlink, as another
// type than p expects, with another owner or group, or with a mode wider
// than p's (install_path_unsafe). A missing path, and a missing parent of
// a path install creates, pass; the parent is checked when it is opened.
func checkInstallPath(p installPath) error {
	var st unix.Stat_t
	err := unix.Lstat(p.path, &st)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w", errInstallPathUnsafe, p.path, err)
	}
	mode := uint32(st.Mode) & 0o7777
	switch {
	case st.Mode&unix.S_IFMT == unix.S_IFLNK:
		return fmt.Errorf("%w: %s is a symlink", errInstallPathUnsafe, p.path)
	case p.dir && st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return fmt.Errorf("%w: %s exists and is not a directory", errInstallPathUnsafe, p.path)
	case !p.dir && st.Mode&unix.S_IFMT != unix.S_IFREG:
		return fmt.Errorf("%w: %s exists and is not a regular file", errInstallPathUnsafe, p.path)
	case int(st.Uid) != p.uid || int(st.Gid) != p.gid:
		return fmt.Errorf("%w: %s is owned by %d:%d, not %d:%d", errInstallPathUnsafe, p.path, st.Uid, st.Gid, p.uid, p.gid)
	case mode&^p.mode != 0:
		return fmt.Errorf("%w: %s has mode %04o, wider than %04o", errInstallPathUnsafe, p.path, mode, p.mode)
	}
	return nil
}

// mkdirInstall creates the directory p (or keeps it, checked by
// checkInstallPath) relative to its parent opened with O_NOFOLLOW, and
// sets its owner and exact mode through a descriptor opened with
// O_NOFOLLOW, so no link planted at p is ever followed.
func mkdirInstall(l apply.Layout, p installPath) error {
	if err := paths.Allowed(l, p.path); err != nil {
		return err
	}
	pfd, err := spool.OpenDir(filepath.Dir(p.path))
	if err != nil {
		return fmt.Errorf("%w: %w", errInstallPathUnsafe, err)
	}
	defer func() { _ = unix.Close(pfd) }()
	name := filepath.Base(p.path)
	if err := unix.Mkdirat(pfd, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create %s: %w", p.path, err)
	}
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", errInstallPathUnsafe, p.path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fchown(fd, p.uid, p.gid); err != nil {
		return fmt.Errorf("chown %s: %w", p.path, err)
	}
	if err := unix.Fchmod(fd, p.mode); err != nil {
		return fmt.Errorf("chmod %s: %w", p.path, err)
	}
	return unix.Fsync(pfd)
}

// writeInstallFile writes data to p atomically, with p's owner and mode
// set on the new file's descriptor before it is renamed into place: a
// fresh temporary name created with O_EXCL|O_NOFOLLOW, the data, fchown,
// fchmod and fsync, renameat over p and a directory fsync. Nothing is
// ever chowned by name, so a link the fetcher plants in its own directory
// cannot redirect an ownership change.
func writeInstallFile(l apply.Layout, p installPath, data []byte) error {
	if err := paths.Allowed(l, p.path); err != nil {
		return err
	}
	dfd, err := spool.OpenDir(filepath.Dir(p.path))
	if err != nil {
		return fmt.Errorf("%w: %w", errInstallPathUnsafe, err)
	}
	defer func() { _ = unix.Close(dfd) }()
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	name := filepath.Base(p.path)
	tmp := "." + name + ".tmp-" + hex.EncodeToString(rnd[:])
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	f := os.NewFile(uintptr(fd), tmp) //nolint:gosec // G115: a file descriptor is non-negative
	fail := func(err error) error {
		_ = f.Close()
		_ = unix.Unlinkat(dfd, tmp, 0)
		return err
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := unix.Fchown(fd, p.uid, p.gid); err != nil {
		return fail(fmt.Errorf("chown %s: %w", p.path, err))
	}
	if err := unix.Fchmod(fd, p.mode); err != nil {
		return fail(fmt.Errorf("chmod %s: %w", p.path, err))
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return err
	}
	if err := unix.Renameat(dfd, tmp, dfd, name); err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("rename %s: %w", p.path, err)
	}
	return unix.Fsync(dfd)
}
