//go:build !windows

package main

import (
	"context"
	"errors"
	"net"
	"os"
)

// connectLoginAgent connects keyroster login to the ssh-agent at
// SSH_AUTH_SOCK (D-15). It is the one test seam of the login's agent
// connection, like dialAgent: tests replace it and restore it with
// t.Cleanup; no environment variable, flag or build tag overrides it.
//
// A3 (moved from 02-02) passed in 02-14 on Ubuntu 26.04: GNOME's
// gcr-ssh-agent honoured the lifetime constraint for a key and its
// certificate, and a real login used it, so login needs no gcr check.
// Other gcr versions are UNVERIFIED.
var connectLoginAgent = func(_ context.Context) (net.Conn, error) {
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		return nil, errors.New("SSH_AUTH_SOCK is not set: start ssh-agent (eval $(ssh-agent)) and retry; keyroster never writes the key to a file")
	}
	return dialAgent()
}

// loginAgentHint is what keyroster login prints after the add: nothing on
// Unix, where ssh finds the agent through SSH_AUTH_SOCK.
func loginAgentHint() string { return "" }
