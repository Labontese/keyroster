//go:build linux

package signer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// maxPeerGroups bounds the SO_PEERGROUPS buffer (NGROUPS_MAX is 65536).
const maxPeerGroups = 65536

// peerCredentials reads the peer's uid, gid and pid (SO_PEERCRED) and its
// supplementary groups (SO_PEERGROUPS) from the kernel.
func peerCredentials(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var (
		p    Peer
		cErr error
	)
	err = raw.Control(func(fd uintptr) {
		ucred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) //nolint:gosec // G115: a file descriptor fits int
		if err != nil {
			cErr = fmt.Errorf("signer: SO_PEERCRED: %w", err)
			return
		}
		groups, err := peerGroups(int(fd)) //nolint:gosec // G115: a file descriptor fits int
		if err != nil {
			cErr = fmt.Errorf("signer: SO_PEERGROUPS: %w", err)
			return
		}
		p = Peer{UID: ucred.Uid, GID: ucred.Gid, PID: ucred.Pid, Groups: groups}
	})
	if err != nil {
		return Peer{}, err
	}
	return p, cErr
}

// peerGroups returns SO_PEERGROUPS as native-endian uint32 gids. x/sys has
// no binary-safe getter for it (GetsockoptString stops at the first NUL
// byte), so this calls getsockopt directly, growing the buffer on ERANGE.
func peerGroups(fd int) ([]uint32, error) {
	size := 64 * 4
	for {
		buf := make([]byte, size)
		n := uint32(len(buf)) //nolint:gosec // G115: size <= maxPeerGroups*4
		// The unsafe.Pointer to uintptr conversions must stay inside the
		// call expression (unsafe.Pointer rule 4).
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0) //nolint:gosec // G103, G115: getsockopt needs the buffer address; fd >= 0
		switch {
		case errno == 0:
			if n%4 != 0 || int(n) > len(buf) {
				return nil, errors.New("signer: unexpected SO_PEERGROUPS length")
			}
			gids := make([]uint32, 0, n/4)
			for i := 0; i+4 <= int(n); i += 4 {
				gids = append(gids, binary.NativeEndian.Uint32(buf[i:i+4]))
			}
			return gids, nil
		case errors.Is(errno, unix.ERANGE) && int(n) > size && int(n) <= maxPeerGroups*4:
			size = int(n)
		default:
			return nil, errno
		}
	}
}
