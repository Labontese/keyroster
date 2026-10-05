//go:build windows

package rootceremony

import "syscall"

// readFD reads from the inherited handle fd without wrapping it in an
// *os.File, whose finalizer would close a handle this package does not own.
// syscall.Read reports a closed pipe as end of file.
func readFD(fd int, b []byte) (int, error) {
	return syscall.Read(syscall.Handle(fd), b) //nolint:gosec // G115: a handle value passed by the operator
}
