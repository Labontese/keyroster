//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/Labontese/keyroster/internal/winagent"
)

// keyroster agent exists only on Windows. On Linux and macOS the login key
// goes into the user's own ssh-agent, which honours lifetime constraints.
func init() {
	register(command{
		Name:    "agent",
		Summary: "in-memory ssh-agent for login certificates (Windows)",
		Run:     runAgent,
	})
}

const agentHelp = `usage: keyroster agent

Serves an in-memory ssh-agent on this account's own named pipe,
\\.\pipe\keyroster-agent-<your SID>. Keys added to it are held in memory
only, leave it when their lifetime ends, and the agent exits once its last
key has expired (or 5 minutes after start when no key was added).
keyroster login starts it on its own; run it by hand only to inspect it.

Point the Windows OpenSSH client at it in one of two ways:
  ~/.ssh/config:  IdentityAgent //./pipe/keyroster-agent-<your SID>
  PowerShell:     $env:SSH_AUTH_SOCK = '//./pipe/keyroster-agent-<your SID>'
(Use forward slashes: OpenSSH reads backslashes in IdentityAgent as escapes.)

Each Windows account, including one reached through runas, gets its own agent
on its own per-SID pipe. An agent started from an elevated ("Run as
administrator") shell cannot be used from a normal shell: keyroster refuses
it and says so. Stop that agent or let it exit, then run keyroster again from
a normal shell.
`

func runAgent(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("agent", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = fmt.Fprint(stderr, agentHelp) }
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	if fset.NArg() != 0 {
		_, _ = fmt.Fprint(stderr, agentHelp)
		return errUsage
	}
	path, err := winagent.PipePath()
	if err != nil {
		return err
	}
	ssh := winagent.OpenSSHSpelling(path)
	// When keyroster login starts the agent detached, stdout is discarded.
	_, _ = fmt.Fprintf(stdout, "keyroster agent: serving %s\n\nTo use it, add this line to ~/.ssh/config:\n  IdentityAgent %s\nor set it in PowerShell:\n  $env:SSH_AUTH_SOCK = '%s'\n", path, ssh, ssh)
	return winagent.Serve(ctx, path, winagent.Options{})
}
