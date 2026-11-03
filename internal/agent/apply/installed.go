//go:build linux

package apply

import (
	"errors"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
)

// InstalledKRLVersion is the KRL version this host enforces: the larger of
// the version accepted/ holds and the header version of the KRL in the
// agent's generation current names (a rollback or a crash recovery can
// keep a newer KRL in current than accepted/ holds, and an accepted
// version can be newer than current's until its swap). 0 means none. It
// only reads, through descriptors opened without following links, and
// takes no lock (keyroster-agent krl-version, the restore cross-check of
// signer-install.md, T-03-277). The state directory must pass the
// state_dir_unsafe check.
func InstalledKRLVersion(l Layout) (uint64, error) {
	if err := CheckStateDirs(l); err != nil {
		return 0, err
	}
	a, err := AcceptedVersions(l)
	return a.KRL, err
}

// AcceptedVersions is what the applier has accepted, for the fetcher
// (enroll.Accepted): the bundle and directory versions of accepted/ and
// the KRL version this host enforces (InstalledKRLVersion's rule). It only
// reads.
func AcceptedVersions(l Layout) (enroll.Accepted, error) {
	var a enroll.Accepted
	fd, err := spool.OpenDir(l.State(state.AcceptedDir))
	switch {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return a, err
	default:
		s, err := state.LoadStored(fd)
		_ = unix.Close(fd)
		if err != nil {
			return a, err
		}
		if s != nil {
			a = enroll.Accepted{Bundle: s.BundleVersion, Directory: s.DirectoryVersion, KRL: s.KRLVersion}
		}
	}
	e := &engine{l: l, stateFd: -1}
	cur, link, err := e.readCurrent()
	if err != nil {
		return a, err
	}
	if cur != nil && link.kind == linkAgent {
		a.KRL = max(a.KRL, krlVersion(cur))
	}
	return a, nil
}

// loadAcceptedState is accepted/ as LoadStored reads it (nil: nothing
// accepted yet).
func loadAcceptedState(l Layout) (*state.Stored, error) {
	fd, err := spool.OpenDir(l.State(state.AcceptedDir))
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	return state.LoadStored(fd)
}

// WriteAccepted writes the applier's accepted versions to the outbox's
// enroll.AcceptedFile (spool.WriteFileAt, mode 0640, so the fetcher can
// read it through the outbox's group), after every apply. It never reads
// the outbox (03-08, F2): nothing the fetcher could plant there decides
// whether it writes. The fetcher bases its state requests on it (PR #71
// review F3/F7).
//
// For the bundle and the directory it writes the higher of accepted/'s
// version and the unapplied record's (loadUnapplied; PR #76 review F8
// (03-08j)); on any loader error, accepted/'s, as before. The raise is
// needed: the fetcher's cursor is min(accepted.json, the spool's newest),
// and one poll reaches 1024 versions above it, so a host whose accepted/
// stays put while it reads past a record would otherwise stop spooling
// about 1024 versions above accepted/. And the fetcher's pruneSpool keeps
// the versions from accepted.json's, so the raise also keeps the record's
// version and what a capture from it reads, which a prune counted from
// accepted/ alone would remove once the record is more than keepAbove
// above it. It is safe: the server uses the request's versions only to
// choose what to serve (handleAgentState) and stores none of them, and the
// KRL cursor stays the KRL in force. AcceptedVersions is unchanged.
//
// F03 (03-08f), owner decision O-2 (c): it writes directory 0 while the
// directory the next capture chains from is unauthorized under its chain
// base's policy (state.Stored.DirectoryUnderPolicy): the chain base is the
// record's base when loadUnapplied returns one, else accepted/ (also on a
// loader error). The bundle and the KRL are never changed by this rule.
//   - The fetcher then asks from 0, and the server's answer for 0 is its
//     current directory (internal/server's directoryItems), which the
//     agent's recovery at the same version needs.
//   - While the base's directory is authorized, the cursor keeps following
//     the chain base. A host whose recorded directory is the new admins'
//     then keeps fetching the versions after the record; with directory 0
//     it would receive only the server's current directory, which does not
//     chain to the record once the server is two or more versions ahead.
//   - A crash between forward's record write (recordUnapplied) and this
//     write, or between a commit and this write, leaves the previous
//     accepted.json for one run. The next locked run rewrites it from disk,
//     and the record holds its own copies, so this costs at most one poll
//     of extra or fewer directory items, and nothing stalls. DryRun and
//     unlocked runs skip WriteAccepted, as before.
//
// ResetDirectory calls it after dropping the accepted directory and the
// record's directory part, so its base holds none and the rule changes
// nothing there.
func WriteAccepted(l Layout) error {
	a, err := AcceptedVersions(l)
	if err != nil {
		return err
	}
	if stored, err := loadAcceptedState(l); err == nil && stored != nil {
		chain := stored
		if base, _, err := loadUnapplied(l, stored); err == nil && base != nil {
			a.Bundle, a.Directory = max(a.Bundle, base.BundleVersion), max(a.Directory, base.DirectoryVersion)
			chain = base
		}
		if chain.DirectoryUnderPolicy() != nil {
			a.Directory = 0
		}
	}
	b, err := trust.CanonicalJSON(a)
	if err != nil {
		return err
	}
	return writeOutbox(l, enroll.AcceptedFile, b)
}
