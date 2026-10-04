//go:build !linux

// Command keyroster-signer is keyroster's signing process. It needs Linux
// peer credentials (SO_PEERCRED, SO_PEERGROUPS), so on every other OS it
// only reports that.
package main

import (
	"fmt"
	"os"
)

func main() {
	_, _ = fmt.Fprintln(os.Stderr, "keyroster-signer runs on Linux only")
	os.Exit(1)
}
