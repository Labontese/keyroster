//go:build unix

package rootceremony

import (
	"errors"
	"syscall"
)

// readFD reads from the inherited descriptor fd without wrapping it in an
// *os.File, whose finalizer would close a descriptor this package does not
// own.
func readFD(fd int, b []byte) (int, error) {
	for {
		n, err := syscall.Read(fd, b)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return n, err
	}
}
