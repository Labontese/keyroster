//go:build linux

package apply

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
)

// ErrResetPending refuses keyroster-agent reset-directory while an apply
// is unfinished (a pending marker): the operator finishes it first.
var ErrResetPending = errors.New("reset_apply_unfinished")

// ResetReport is what ResetDirectory dropped.
type ResetReport struct {
	// Version and SHA256 are the accepted directory it dropped (0 and ""
	// when none was accepted).
	Version uint64
	SHA256  string
	// SpoolRemoved are the directory files it removed from the spool.
	SpoolRemoved []string
}

var spoolDirectoryRE = regexp.MustCompile(`^directory-[1-9][0-9]{0,19}\.json(\.sigs)?$`)

// ResetDirectory is keyroster-agent reset-directory (owner decision D-R2,
// PR #71 review F5), run by root on a host whose accepted directory is a
// version a signer restore lost, so the re-made chain never verifies
// against it. Under the apply lock, with no apply unfinished, it:
//
//  1. drops the accepted directory from accepted/ (a new snapshot without
//     it; the bundle, policy and KRL stay), so the next apply takes the
//     directory as a first install does: the newest one the spool offers,
//     verified against the admin quorum of the accepted policy and the
//     pinned installation, standalone;
//  2. removes every directory file from the spool at spoolDir, which must
//     be inside the agent's paths (paths.Allowed: the state directory's
//     spool by default), by its fixed-pattern name relative to a
//     descriptor opened without following links, so a lost version the
//     fetcher spooled earlier is not taken again;
//  3. rewrites the outbox's accepted versions (WriteAccepted), so the
//     fetcher asks for the server's current directory.
//
// It accepts nothing itself, signed or unsigned. Until the fetcher spools
// the server's current directory an apply has no directory to render: one
// with nothing new is a no-op, one with a newer KRL fails and changes
// nothing, and the current generation stays in force either way.
func ResetDirectory(l Layout, spoolDir string) (*ResetReport, error) {
	if err := CheckStateDirs(l); err != nil {
		return nil, err
	}
	// Before anything changes: the spool must be one the applier may
	// remove files from.
	if err := paths.Allowed(l, spoolDir); err != nil {
		return nil, err
	}
	fd, err := spool.OpenDir(l.StateDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	e := &engine{l: l, stateFd: fd}
	defer func() { _ = unix.Close(fd) }()
	if _, err := state.LoadPins(fd); err != nil {
		return nil, err
	}
	unlock, err := e.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	m, err := e.loadMarker()
	if err != nil {
		return nil, err
	}
	if m != nil {
		return nil, fmt.Errorf("%w: an apply stopped mid-move (%s); run keyroster-agent apply --once first", ErrResetPending, l.State(pendingFile))
	}
	r := &ResetReport{}
	afd, err := e.acceptedFd()
	switch {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return nil, err
	default:
		stored, err := state.LoadStored(afd)
		if err == nil && stored != nil && stored.Directory != nil {
			r.Version, r.SHA256 = stored.DirectoryVersion, trust.SHA256Hex(stored.Directory)
			stored.Directory, stored.DirectorySigs, stored.DirectoryVersion = nil, nil, 0
			err = stored.Save(l, afd, nil)
		}
		_ = unix.Close(afd)
		if err != nil {
			return nil, err
		}
	}
	sfd, err := spool.OpenDir(spoolDir)
	if err != nil {
		return r, err
	}
	defer func() { _ = unix.Close(sfd) }()
	names, err := spool.ListDir(sfd)
	if err != nil {
		return r, err
	}
	for _, n := range names {
		if !spoolDirectoryRE.MatchString(n) {
			continue
		}
		if err := paths.Allowed(l, filepath.Join(spoolDir, n)); err != nil {
			return r, err
		}
		if err := unix.Unlinkat(sfd, n, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return r, fmt.Errorf("remove %s from the spool: %w", n, err)
		}
		r.SpoolRemoved = append(r.SpoolRemoved, n)
	}
	if err := unix.Fsync(sfd); err != nil {
		return r, err
	}
	return r, WriteAccepted(l)
}
