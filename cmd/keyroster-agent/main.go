//go:build linux

// Command keyroster-agent keeps an enrolled Linux host's sshd trust files
// in sync with keyroster's signed state. In this version it is the root
// applier only (03-05): apply --once reads signed documents from a spool
// directory, verifies them against the pins it alone stores and installs
// them atomically, with a self-test and rollback. It has no HTTP, TLS or
// RPC code; its only network traffic is the self-test to sshd over
// loopback (the owner's D-05 answer, loopback-only). The fetcher that
// fills the spool is 03-07.
package main

import (
	"context"
	"os"
)

func main() {
	os.Exit(dispatch(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
