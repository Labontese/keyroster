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

// WriteAccepted writes the applier's accepted versions to the outbox's
// enroll.AcceptedFile (spool.WriteFileAt, mode 0640, so the fetcher can
// read it through the outbox's group), after every apply. It never reads
// the outbox (03-08, F2): nothing the fetcher could plant there decides
// whether it writes. The fetcher bases its state requests on it (PR #71
// review F3/F7).
func WriteAccepted(l Layout) error {
	a, err := AcceptedVersions(l)
	if err != nil {
		return err
	}
	b, err := trust.CanonicalJSON(a)
	if err != nil {
		return err
	}
	return writeOutbox(l, enroll.AcceptedFile, b)
}
