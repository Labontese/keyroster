//go:build windows

package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/Labontese/keyroster/internal/winagent"
)

// connectLoginAgent connects keyroster login to keyroster's own agent
// (D-15 option A), never the inbox OpenSSH agent: winagent.Ensure starts
// keyroster agent when it is not running and returns a connection only
// after the pipe owner check, to an agent that already counts it as
// active. Its errors, notably winagent.ErrOwnerUnverifiable, reach the
// user with their own help text. keyroster login calls it once, before it
// begins the login (03-02), so these errors stop the login before the
// signer issues anything. It is the one test seam of the login's
// agent connection: tests replace it and restore it with t.Cleanup;
// winagent itself exports no hook.
var connectLoginAgent = func(ctx context.Context) (net.Conn, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot locate the keyroster executable to start keyroster agent: %w", err)
	}
	return winagent.Ensure(ctx, exe)
}

// loginAgentHint is the host-scoped ssh config block that points the inbox
// ssh.exe at keyroster's agent (owner decision 2026-10-17: a host-scoped
// IdentityAgent block only, never SSH_AUTH_SOCK).
func loginAgentHint() string {
	pipe, err := winagent.PipePath()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("\nTo use it, add this block to ~/.ssh/config, with your keyroster hosts in place of <your keyroster hosts>:\n"+
		"  Host <your keyroster hosts>\n      IdentityAgent %s\n"+
		"Keep it host-scoped: the inbox ssh.exe does not check who serves this pipe.\n", winagent.OpenSSHSpelling(pipe))
}
