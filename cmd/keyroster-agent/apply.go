//go:build linux

package main

import (
	"context"
	"encoding/json"
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

const applyUsage = `usage: keyroster-agent apply --once --spool DIR --state-dir DIR --root DIR
       --sshd PATH --sshd-config PATH --ssh-keygen PATH --reload STRATEGY
       [--dry-run] [--recover-to-last-good]

Verifies the signed documents in the spool against the pins in the state
directory and installs the newest state under ROOT/etc/ssh/keyroster: a new
generation, swapped in through an intermediate generation when a change
both adds and removes, the sshd drop-in on first install, a self-test over
loopback, and a rollback to last-good when it fails. The report is printed
as JSON.

STRATEGY is how sshd is reloaded when the drop-in changes: signal (SIGHUP
to the PidFile sshd -T names), systemd:<unit>.service or openrc.

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
	root := fset.String("root", "/", "the root of the file system the trust files are written under")
	sshd := fset.String("sshd", "", "absolute path of the service's sshd binary")
	sshdConfig := fset.String("sshd-config", "", "absolute path of the service's sshd_config")
	keygen := fset.String("ssh-keygen", "", "absolute path of ssh-keygen")
	reload := fset.String("reload", "", "reload strategy: signal, systemd:<unit>.service or openrc")
	dryRun := fset.Bool("dry-run", false, "verify and render, print the difference, install nothing")
	recoverFlag := fset.Bool("recover-to-last-good", false, "leave a layout the agent did not make, back to last-good")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		return errUsage
	}
	if !*once {
		_, _ = fmt.Fprintln(stderr, "apply: --once is required (the agent has no daemon mode in this version)")
		return errUsage
	}
	for name, v := range map[string]string{"--spool": *spoolDir, "--state-dir": *stateDir, "--root": *root, "--sshd": *sshd, "--sshd-config": *sshdConfig, "--ssh-keygen": *keygen} {
		if v == "" || !filepath.IsAbs(v) {
			_, _ = fmt.Fprintf(stderr, "apply: %s must be an absolute path\n", name)
			return errUsage
		}
	}
	if err := apply.CheckReload(*reload); err != nil {
		_, _ = fmt.Fprintf(stderr, "apply: %v\n", err)
		return errUsage
	}
	cfg := apply.Config{
		Spool: filepath.Clean(*spoolDir), SSHD: *sshd, SSHDConfig: *sshdConfig, SSHKeygen: *keygen,
		Reload: *reload, DryRun: *dryRun, RecoverToLastGood: *recoverFlag, Log: stderr,
	}
	report, err := apply.Apply(ctx, cfg, apply.Layout{Root: filepath.Clean(*root), StateDir: filepath.Clean(*stateDir)})
	out, merr := json.MarshalIndent(report, "", "  ")
	if merr != nil {
		return merr
	}
	if _, werr := fmt.Fprintf(stdout, "%s\n", out); werr != nil && err == nil {
		err = werr
	}
	return err
}
