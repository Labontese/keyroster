//go:build !windows

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// dialAgent connects to the ssh-agent at SSH_AUTH_SOCK, a Unix socket. It is
// a variable so tests can route the CLI to an in-memory keyring.
var dialAgent = func() (net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, errors.New("ssh-agent: SSH_AUTH_SOCK is not set; start ssh-agent and load the root key")
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("connect to ssh-agent: %w", err)
	}
	return conn, nil
}
