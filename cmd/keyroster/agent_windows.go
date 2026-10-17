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

Point the Windows OpenSSH client at it for your keyroster hosts only, with
this block in ~/.ssh/config (put your keyroster hosts in place of
<your keyroster hosts>):
  Host <your keyroster hosts>
      IdentityAgent //./pipe/keyroster-agent-<your SID>
(Use forward slashes: OpenSSH reads backslashes in IdentityAgent as escapes.)
Keep it host-scoped: the inbox ssh.exe and ssh-add.exe do not check who
serves the pipe, so only your keyroster hosts should rely on it.

Only keyroster login adds keys to this agent. Do not add keys to the pipe
with ssh-add or AddKeysToAgent: the Windows OpenSSH tools do not check who
serves it, and while no keyroster agent runs (between logins) the pipe name
can be taken by a process of another local account or by a sandboxed process
of your own (Low integrity, or a restricted or deny-only token). keyroster
itself refuses such a pipe; the host-scoped block above limits the inbox
clients' exposure to such a pipe to your keyroster hosts.

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
	_, _ = fmt.Fprintf(stdout, "keyroster agent: serving %s\n\nTo use it, add this block to ~/.ssh/config, with your keyroster hosts in place of <your keyroster hosts>:\n  Host <your keyroster hosts>\n      IdentityAgent %s\nKeep it host-scoped: the inbox ssh.exe and ssh-add.exe do not check who serves this pipe.\n\nOnly keyroster login adds keys here: do not use ssh-add or AddKeysToAgent with this pipe (see keyroster agent -h).\n", path, ssh)
	return winagent.Serve(ctx, path, winagent.Options{})
}
