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
		Name:    "apply",
		Summary: "verify the signed state in the spool and install it into sshd's trust files (apply --once)",
		Run:     runApply,
	})
}

const applyUsage = `usage: keyroster-agent apply --once --spool DIR --state-dir DIR [--root DIR]
       [--sshd PATH] [--sshd-config PATH] [--ssh-keygen PATH] [--reload STRATEGY]
       [--dry-run] [--recover-to-last-good]

Verifies the signed documents in the spool against the pins in the state
directory and installs the newest state under ROOT/etc/ssh/keyroster: a new
generation, swapped in through an intermediate generation when a change
both adds and removes, the sshd drop-in on first install, a self-test over
loopback, and a rollback to last-good when it fails. The report is printed
as JSON. The first apply, and every drop-in change, runs the preflight's
checks first and refuses on any refusal (keyroster-agent preflight).

STRATEGY is how sshd is reloaded when the drop-in changes: signal (SIGHUP
to the PidFile sshd -T names), systemd:<unit>.service, openrc, or none (a
socket-activated sshd whose service is not running). Without --sshd,
--sshd-config and --reload the service that runs sshd is detected (systemd
or OpenRC); a flag that is given overrides the detected value.

A host set up by hand with the Phase 2 runbook's exact layout is taken over
by this command (and only by it): the agent installs its own files, proves
they win, reloads and self-tests, and only then removes the three Phase 2
paths. Run it from a root shell after approving the host and re-rendering
its principals files (host-setup.md "Moving a Phase 2 host to the agent").

--dry-run verifies and renders and prints the difference against current
without installing anything. --recover-to-last-good is the operator's way
out of "stuck: pending_state_unknown" (a layout the agent did not make),
run by hand after inspection.
`

// runApply is keyroster-agent apply --once.
func runApply(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("apply", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, applyUsage) }
	once := fset.Bool("once", false, "apply once and exit (the only mode in this version)")
	spoolDir := fset.String("spool", "", "the spool directory")
	stateDir := fset.String("state-dir", "", "the applier's state directory (pins.json, accepted/)")
	svc := addServiceFlags(fset, true)
	dryRun := fset.Bool("dry-run", false, "verify and render, print the difference, install nothing")
	recoverFlag := fset.Bool("recover-to-last-good", false, "leave a layout the agent did not make, back to last-good")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		return errUsage
	}
	if !*once {
		_, _ = fmt.Fprintln(stderr, "apply: --once is required (the agent has no daemon mode in this version)")
		return errUsage
	}
	for name, v := range map[string]string{"--spool": *spoolDir, "--state-dir": *stateDir} {
		if v == "" || !filepath.IsAbs(v) {
			_, _ = fmt.Fprintf(stderr, "apply: %s must be an absolute path\n", name)
			return errUsage
		}
	}
	sshd, config, keygen, reload, err := svc.resolve(ctx, stderr)
	if errors.Is(err, errUsage) {
		return err
	}
	if err != nil {
		return err
	}
	if err := apply.CheckReload(reload); err != nil {
		_, _ = fmt.Fprintf(stderr, "apply: %v\n", err)
		return errUsage
	}
	cfg := apply.Config{
		Spool: filepath.Clean(*spoolDir), SSHD: sshd, SSHDConfig: config, SSHKeygen: keygen,
		Reload: reload, DryRun: *dryRun, RecoverToLastGood: *recoverFlag, Log: stderr,
		// D-08: only this hand run takes a Phase 2 host over; the applier
		// unit's run loop (03-07) never sets it.
		AllowAdoption: true,
	}
	report, err := apply.Apply(ctx, cfg, apply.Layout{Root: filepath.Clean(*svc.root), StateDir: filepath.Clean(*stateDir)})
	out, merr := json.MarshalIndent(report, "", "  ")
	if merr != nil {
		return merr
	}
	if _, werr := fmt.Fprintf(stdout, "%s\n", out); werr != nil && err == nil {
		err = werr
	}
	return err
}
