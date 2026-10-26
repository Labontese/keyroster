//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

func init() {
	register(command{
		Name:    "preflight",
		Summary: "check whether this host's sshd can be managed safely; changes nothing (exit 0 clean, 3 refused, 2 error)",
		Run:     runPreflight,
	})
}

const preflightUsage = `usage: keyroster-agent preflight [--root DIR] [--state-dir DIR] [--spool DIR]
       [--sshd PATH] [--sshd-config PATH] [--ssh-keygen PATH]

Checks whether the agent can manage this host's sshd without editing
sshd_config (D-07), and prints the findings as JSON. It changes nothing but
a trial copy of the agent's drop-in, written only while none exists and
removed before it exits, with no reload.

Exit status: 0 when no finding refuses the host (account_excluded and
phase2_adoptable are report only), 3 when one does, 2 for a usage or tool
error (an sshd that cannot run, an apply holding the lock).

Without --sshd and --sshd-config the service that runs sshd is detected
(systemd or OpenRC). Without --state-dir the policy and account checks do
not run, as before enrollment.
`

// defaultStateDir is the applier's state directory in production.
const defaultStateDir = "/var/lib/keyroster-agent"

// keygenPaths are where ssh-keygen is looked for without --ssh-keygen.
var keygenPaths = []string{"/usr/bin/ssh-keygen", "/bin/ssh-keygen"}

// serviceFlags are the flags that name sshd and its service.
type serviceFlags struct {
	root, sshd, sshdConfig, keygen, reload *string
}

func addServiceFlags(fset *flag.FlagSet, withReload bool) serviceFlags {
	s := serviceFlags{
		root:       fset.String("root", "/", "the root of the file system sshd's configuration and the agent's files are under"),
		sshd:       fset.String("sshd", "", "absolute path of the service's sshd binary (default: detected)"),
		sshdConfig: fset.String("sshd-config", "", "absolute path of the service's sshd_config (default: detected)"),
		keygen:     fset.String("ssh-keygen", "", "absolute path of ssh-keygen (default: "+keygenPaths[0]+" or "+keygenPaths[1]+")"),
	}
	if withReload {
		s.reload = fset.String("reload", "", "reload strategy: signal, systemd:<unit>.service, openrc or none (default: detected)")
	}
	return s
}

// resolve fills what the flags leave out: the sshd service from Detect
// (an explicit --sshd, --sshd-config or --reload overrides it, for tests
// and odd hosts) and ssh-keygen from keygenPaths. A flag that is set must
// be an absolute path.
func (s serviceFlags) resolve(ctx context.Context, stderr io.Writer) (sshd, config, keygen, reload string, err error) {
	sshd, config, keygen = *s.sshd, *s.sshdConfig, *s.keygen
	if s.reload != nil {
		reload = *s.reload
	}
	for name, v := range map[string]string{"--root": *s.root, "--sshd": sshd, "--sshd-config": config, "--ssh-keygen": keygen} {
		if v != "" && !filepath.IsAbs(v) {
			_, _ = fmt.Fprintf(stderr, "%s must be an absolute path\n", name)
			return "", "", "", "", errUsage
		}
	}
	if sshd == "" || config == "" || (s.reload != nil && reload == "") {
		svc, err := apply.Detect(ctx, nil, filepath.Clean(*s.root))
		if err != nil {
			return "", "", "", "", err
		}
		sshd, config = or(sshd, svc.SSHD), or(config, svc.Config)
		if s.reload != nil {
			reload = or(reload, svc.Reload)
		}
	}
	if keygen == "" {
		keygen = keygenPaths[0]
		for _, p := range keygenPaths {
			if _, err := os.Stat(p); err == nil {
				keygen = p
				break
			}
		}
	}
	return sshd, config, keygen, reload, nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// runPreflight is keyroster-agent preflight.
func runPreflight(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("preflight", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, preflightUsage) }
	svc := addServiceFlags(fset, false)
	stateDir := fset.String("state-dir", "", "the applier's state directory (optional before enrollment)")
	spoolDir := fset.String("spool", "", "the spool directory (optional)")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		return errUsage
	}
	for name, v := range map[string]string{"--state-dir": *stateDir, "--spool": *spoolDir} {
		if v != "" && !filepath.IsAbs(v) {
			_, _ = fmt.Fprintf(stderr, "preflight: %s must be an absolute path\n", name)
			return errUsage
		}
	}
	sshd, config, keygen, _, err := svc.resolve(ctx, stderr)
	if errors.Is(err, errUsage) {
		return err
	}
	if err != nil {
		return &exitError{code: 2, err: err}
	}
	l := apply.Layout{Root: filepath.Clean(*svc.root)}
	if *stateDir != "" {
		l.StateDir = filepath.Clean(*stateDir)
	}
	cfg := apply.Config{SSHD: sshd, SSHDConfig: config, SSHKeygen: keygen, Log: stderr}
	if *spoolDir != "" {
		cfg.Spool = filepath.Clean(*spoolDir)
	}
	report, err := apply.Preflight(ctx, cfg, l)
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
	if report.Refused() {
		return &exitError{code: 3}
	}
	return nil
}
