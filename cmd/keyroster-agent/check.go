//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

func init() {
	register(command{
		Name:    "check",
		Summary: "report drift of sshd's effective trust settings and of the installed generation; fixes nothing (exit 0 clean, 3 drift)",
		Run:     runCheck,
	})
}

const checkUsage = `usage: keyroster-agent check [--root DIR] [--state-dir DIR]
       [--sshd PATH] [--sshd-config PATH]

Compares sshd -T, and sshd -T -C for every managed account, with the
agent's drop-in, and re-hashes the generation current names against its
record (AGENT-05). It prints the report as JSON and fixes nothing.

Exit status: 0 when nothing drifted, 3 on drift, 2 for a usage or tool
error (no generation installed, sshd -T failing). Accounts that AllowUsers,
AllowGroups, DenyUsers or DenyGroups exclude are listed, report only.
`

// runCheck is keyroster-agent check.
func runCheck(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("check", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, checkUsage) }
	svc := addServiceFlags(fset, false)
	stateDir := fset.String("state-dir", defaultStateDir, "the applier's state directory")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 || !filepath.IsAbs(*stateDir) {
		return errUsage
	}
	sshd, config, keygen, _, err := svc.resolve(ctx, stderr)
	if errors.Is(err, errUsage) {
		return err
	}
	if err != nil {
		return &exitError{code: 2, err: err}
	}
	cfg := apply.Config{SSHD: sshd, SSHDConfig: config, SSHKeygen: keygen, Log: stderr}
	report, err := apply.Check(ctx, cfg, apply.Layout{Root: filepath.Clean(*svc.root), StateDir: filepath.Clean(*stateDir)})
	if err != nil {
		return &exitError{code: 2, err: err}
	}
	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return &exitError{code: 2, err: err}
	}
	if _, err := fmt.Fprintf(stdout, "%s\n", out); err != nil {
		return &exitError{code: 2, err: err}
	}
	if report.Drift() {
		return &exitError{code: 3}
	}
	return nil
}
