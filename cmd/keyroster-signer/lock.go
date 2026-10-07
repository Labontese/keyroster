//go:build linux

package main

import (
	"errors"
	"fmt"
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
func lockStateDir(stateDir string) (func(), error) {
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
	return func() { _ = f.Close() }, nil
}
