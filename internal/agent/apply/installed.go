//go:build linux

package apply

import (
	"errors"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
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
	var v uint64
	fd, err := spool.OpenDir(l.State(state.AcceptedDir))
	switch {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return 0, err
	default:
		s, err := state.LoadStored(fd)
		_ = unix.Close(fd)
		if err != nil {
			return 0, err
		}
		if s != nil {
			v = s.KRLVersion
		}
	}
	e := &engine{l: l, stateFd: -1}
	cur, link, err := e.readCurrent()
	if err != nil {
		return 0, err
	}
	if cur != nil && link.kind == linkAgent {
		v = max(v, krlVersion(cur))
	}
	return v, nil
}
