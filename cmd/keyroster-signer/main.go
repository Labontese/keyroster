//go:build linux

// Command keyroster-signer is keyroster's signing process. It holds the CA
// keys (through a keystore backend), listens only on a Unix socket, serves
// only allowlisted local peers, and is the only process that signs
// certificates.
package main

import (
	"context"
	"os"
	"syscall"
)

func main() {
	// Every file the signer creates (state database, socket before its
	// chmod) starts private.
	syscall.Umask(0o077)
	os.Exit(dispatch(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
