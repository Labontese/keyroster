//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	winio "github.com/Microsoft/go-winio"
)

// inboxAgentPipe is the Windows OpenSSH agent's named pipe, used for admin
// SSHSIG signing when SSH_AUTH_SOCK is not set. Login keys never go there:
// that agent refuses lifetime constraints and stores keys in the registry
// (owner decision D-15 option A; login uses internal/winagent instead).
const inboxAgentPipe = `\\.\pipe\openssh-ssh-agent`

// dialAgent connects to the ssh-agent named pipe: SSH_AUTH_SOCK when set,
// else the inbox OpenSSH agent. It is a variable so tests can route the CLI
// to an in-memory keyring.
var dialAgent = func() (net.Conn, error) {
	pipe := os.Getenv("SSH_AUTH_SOCK")
	if pipe == "" {
		pipe = inboxAgentPipe
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := winio.DialPipeContext(ctx, pipe)
	if err != nil {
		return nil, fmt.Errorf("connect to ssh-agent pipe %s: %w", pipe, err)
	}
	return conn, nil
}
