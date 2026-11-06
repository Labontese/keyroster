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

const applyUsage = `usage: keyroster-agent apply --once [--spool DIR] [--state-dir DIR] [--root DIR]
       [--sshd PATH] [--sshd-config PATH] [--ssh-keygen PATH] [--reload STRATEGY]
       [--dry-run] [--recover-to-last-good]

Verifies the signed documents in the spool against the pins in the state
directory and installs the newest state under ROOT/etc/ssh/keyroster: a new
generation, swapped in through an intermediate generation when a change
both adds and removes, the sshd drop-in on first install, a self-test over
loopback, and a rollback to last-good when it fails. The report is printed
as JSON. The first apply, and every drop-in change, runs the preflight's
checks first and refuses on any refusal (keyroster-agent preflight).

--spool defaults to <state-dir>/spool, --state-dir to /var/lib/keyroster-agent.

STRATEGY is how sshd is reloaded when the drop-in changes: signal (SIGHUP
to the PidFile sshd -T names), systemd:<unit>.service (systemctl reload),
systemd-socket:<unit>.service (systemctl try-reload-or-restart, for a
socket-activated sshd: a running one re-reads, a stopped one reads the
files when it next starts), or openrc. Without --sshd,
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

// applyArgs are keyroster-agent apply's parsed flags.
type applyArgs struct {
	once, dryRun, recover bool
	spool, stateDir       string
	svc                   serviceFlags
}

// parseApply parses apply's flags and checks its paths. It detects no
// service and touches no file; runApply does both.
func parseApply(args []string, stderr io.Writer) (applyArgs, error) {
	fset := flag.NewFlagSet("apply", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, applyUsage) }
	once := fset.Bool("once", false, "apply once and exit (the only mode in this version)")
	spoolDir := fset.String("spool", "", "the spool directory (default <state-dir>/spool)")
	stateDir := fset.String("state-dir", defaultStateDir, "the applier's state directory (pins.json, accepted/)")
	svc := addServiceFlags(fset, true)
	dryRun := fset.Bool("dry-run", false, "verify and render, print the difference, install nothing")
	recoverFlag := fset.Bool("recover-to-last-good", false, "leave a layout the agent did not make, back to last-good")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		return applyArgs{}, errUsage
	}
	if !*once {
		_, _ = fmt.Fprintln(stderr, "apply: --once is required (the agent has no daemon mode in this version)")
		return applyArgs{}, errUsage
	}
	// The paths follow run's and identity's rule: --state-dir defaults to
	// defaultStateDir, --spool to <state-dir>/spool, and each must be
	// absolute when given.
	if !filepath.IsAbs(*stateDir) || (*spoolDir != "" && !filepath.IsAbs(*spoolDir)) {
		_, _ = fmt.Fprintln(stderr, "apply: --state-dir and --spool must be absolute paths")
		return applyArgs{}, errUsage
	}
	l := apply.Layout{StateDir: filepath.Clean(*stateDir)}
	spool := l.Spool()
	if *spoolDir != "" {
		spool = filepath.Clean(*spoolDir)
	}
	return applyArgs{once: *once, dryRun: *dryRun, recover: *recoverFlag, spool: spool, stateDir: l.StateDir, svc: svc}, nil
}

// runApply is keyroster-agent apply --once.
func runApply(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	a, err := parseApply(args, stderr)
	if err != nil {
		return err
	}
	sshd, config, keygen, reload, err := a.svc.resolve(ctx, stderr)
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
		Spool: a.spool, SSHD: sshd, SSHDConfig: config, SSHKeygen: keygen,
		Reload: reload, DryRun: a.dryRun, RecoverToLastGood: a.recover, Log: stderr,
		// D-08: only this hand run takes a Phase 2 host over; the applier
		// unit's run loop (03-07) never sets it.
		AllowAdoption: true,
	}
	l := apply.Layout{Root: filepath.Clean(*a.svc.root), StateDir: a.stateDir}
	report, err := apply.Apply(ctx, cfg, l)
	// The host-certificate step after the apply (03-09), not on --dry-run;
	// the exit status stays the apply's.
	var hc *apply.HostCertReport
	if !a.dryRun {
		var herr error
		if hc, herr = apply.HostCerts(ctx, cfg, l); herr != nil {
			_, _ = fmt.Fprintf(stderr, "keyroster-agent: ERROR host certificates: %v\n", herr)
		}
	}
	out, merr := json.MarshalIndent(struct {
		*apply.Report
		HostCerts *apply.HostCertReport `json:"host_certs,omitempty"`
	}{report, hc}, "", "  ")
	if merr != nil {
		return merr
	}
	if _, werr := fmt.Fprintf(stdout, "%s\n", out); werr != nil && err == nil {
		err = werr
	}
	return err
}
