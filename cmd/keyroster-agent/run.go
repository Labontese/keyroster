//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

func init() {
	register(command{
		Name:    "run",
		Summary: "the applier's loop: answer the fetcher's enrollment request and apply new signed state from the spool (run as root)",
		Run:     runRun,
	})
}

const runUsage = `usage: keyroster-agent run [--spool DIR] [--state-dir DIR] [--root DIR]
       [--sshd PATH] [--sshd-config PATH] [--ssh-keygen PATH] [--reload STRATEGY]
       [--interval D]

The root applier's loop (03-07), every --interval (default 5s, at least
1s): the state directory, accepted/ and the outbox must be the applier's
own (state_dir_unsafe); an enrollment request the fetcher left in the spool
is answered with the host keys' proof of possession in the outbox; and when
the spool holds new signed documents, they are applied as apply --once
would, except that a Phase 2 host is never taken over here (D-08). Each
apply that changed something prints its report as one JSON line. It never
ends on an error; it logs it and retries.

--spool defaults to <state-dir>/spool. The service flags are apply's.
`

// minInterval is the shortest --interval.
const minInterval = time.Second

func runRun(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("run", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, runUsage) }
	spoolDir := fset.String("spool", "", "the spool directory (default <state-dir>/spool)")
	stateDir := fset.String("state-dir", defaultStateDir, "the applier's state directory (pins.json, accepted/, outbox/)")
	svc := addServiceFlags(fset, true)
	interval := fset.Duration("interval", apply.DefaultInterval, "how often the spool is looked at (at least 1s)")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		return errUsage
	}
	if *interval < minInterval {
		_, _ = fmt.Fprintf(stderr, "run: --interval must be at least %s\n", minInterval)
		return errUsage
	}
	if !filepath.IsAbs(*stateDir) || (*spoolDir != "" && !filepath.IsAbs(*spoolDir)) {
		_, _ = fmt.Fprintln(stderr, "run: --state-dir and --spool must be absolute paths")
		return errUsage
	}
	l := apply.Layout{Root: filepath.Clean(*svc.root), StateDir: filepath.Clean(*stateDir)}
	spool := l.Spool()
	if *spoolDir != "" {
		spool = filepath.Clean(*spoolDir)
	}
	sshd, config, keygen, reload, err := svc.resolve(ctx, stderr)
	if errors.Is(err, errUsage) {
		return err
	}
	if err != nil {
		return err
	}
	if err := apply.CheckReload(reload); err != nil {
		_, _ = fmt.Fprintf(stderr, "run: %v\n", err)
		return errUsage
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var mu sync.Mutex
	rc := apply.RunConfig{
		Config:   apply.Config{Spool: spool, SSHD: sshd, SSHDConfig: config, SSHKeygen: keygen, Reload: reload, Log: stderr},
		Interval: *interval,
		Out: func(r *apply.Report, _ error) {
			b, err := json.Marshal(r)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			_, _ = fmt.Fprintf(stdout, "%s\n", b)
		},
	}
	err = apply.Run(ctx, rc, l)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}
