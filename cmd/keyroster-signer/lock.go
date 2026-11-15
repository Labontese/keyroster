//go:build linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// lockFileName is the lock file in the state directory. serve holds it for
// its whole lifetime; ca-init and install-bundle hold it while they run.
const lockFileName = "signer.lock"

// errStateLocked means another keyroster-signer process holds the state
// directory's lock.
var errStateLocked = errors.New("the state directory is in use by another keyroster-signer process (serve, ca-init or install-bundle)")

// lockStateDir takes an exclusive, non-blocking flock on
// {stateDir}/signer.lock, so that at most one of serve, ca-init and
// install-bundle writes the state at a time. In particular install-bundle
// refuses while the service runs: a successor bundle is installed with the
// service stopped, and serve loads it when it starts again. The lock is
// released by calling the returned function, or by the kernel when the
// process exits.
//
// It is also the restore gate (03-12): after the flock is taken it refuses
// restore_recovery_pending, and releases the flock, while a directory entry
// named restore-recovery-pending exists in the state directory (of any
// type, read with lstat; a stat error other than not-exist refuses too).
// The runbook's file-restore block writes that marker before signer.db is
// replaced, so serve, ca-init, install-bundle and ca-rotate prepare cannot
// write a restored state before its revocations are recovered or the
// recovery is ruled out. recover-revocations (its recovery,
// --no-recovery-needed and --migrate-only) is the one caller of the exempt
// variant, lockStateDirForRecovery: it is how the marker is cleared, and
// under the marker it is the only command that opens signer.db for
// writing.
func lockStateDir(stateDir string) (func(), error) {
	return lockState(stateDir, true)
}

// lockStateDirForRecovery is lockStateDir without the restore gate, for
// recover-revocations only (03-12).
func lockStateDirForRecovery(stateDir string) (func(), error) {
	return lockState(stateDir, false)
}

// restoreMarkerName is the restore marker in the state directory (03-12):
// the runbook's file-restore block writes it before signer.db is replaced.
const restoreMarkerName = "restore-recovery-pending"

// errRestorePending is the restore_recovery_pending refusal of the state
// lock (03-12).
var errRestorePending = errors.New("restore_recovery_pending")

func lockState(stateDir string, gate bool) (func(), error) {
	path := filepath.Join(stateDir, lockFileName)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: the path is the operator's state directory
	if err != nil {
		return nil, fmt.Errorf("state dir lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a file descriptor fits int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s; stop the service first (systemctl stop keyroster-signer.service)", errStateLocked, stateDir)
		}
		return nil, fmt.Errorf("state dir lock %s: %w", path, err)
	}
	if gate {
		marker := filepath.Join(stateDir, restoreMarkerName)
		switch _, err := os.Lstat(marker); {
		case err == nil:
			_ = f.Close()
			return nil, fmt.Errorf("%w: %s exists: this state directory was restored and no recovery has been applied or ruled out; run keyroster-signer recover-revocations (docs/runbooks/signer-install.md, restore step 2b)", errRestorePending, marker)
		case !errors.Is(err, fs.ErrNotExist):
			_ = f.Close()
			return nil, fmt.Errorf("%w: cannot read %s: %w", errRestorePending, marker, err)
		}
	}
	return func() { _ = f.Close() }, nil
}
