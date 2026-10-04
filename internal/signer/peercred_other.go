//go:build !linux

package signer

import (
	"errors"
	"net"
)

// peerCredentials is only implemented on Linux (SO_PEERCRED and
// SO_PEERGROUPS); keyroster-signer runs on Linux only, so every connection
// elsewhere is refused.
func peerCredentials(*net.UnixConn) (Peer, error) {
	return Peer{}, errors.New("signer: peer credentials are only available on Linux")
}
