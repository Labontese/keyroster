//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

func init() {
	register(command{
		Name:    "reset-directory",
		Summary: "drop the accepted directory so the next apply takes the server's current one from the start, as a first install does (run as root; signer-install.md)",
		Run:     runResetDirectory,
	})
}

const resetDirectoryUsage = `usage: keyroster-agent reset-directory [--state-dir DIR] [--spool DIR] [--root DIR]

For a host that accepted a directory version a signer restore lost, so it
refuses the re-made chain (directory_not_verified, "does not chain"):
under the apply lock, with no apply unfinished, it drops the accepted
directory from accepted/ (the bundle, policy and KRL stay), removes every
directory file from the spool, and rewrites the outbox's accepted.json.
The next apply then takes the newest directory the fetcher spools from
the server, verified against the admin quorum of the accepted policy and
the pinned installation, standalone, exactly like a first install. It
accepts nothing itself, and prints what it dropped. Run it only as
docs/runbooks/signer-install.md says.

--spool defaults to <state-dir>/spool.
`

func runResetDirectory(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("reset-directory", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, resetDirectoryUsage) }
	root := fset.String("root", "/", "the root of the file system the agent's files are under")
	stateDir := fset.String("state-dir", defaultStateDir, "the applier's state directory")
	spoolDir := fset.String("spool", "", "the spool directory (default <state-dir>/spool)")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 || !filepath.IsAbs(*root) || !filepath.IsAbs(*stateDir) || (*spoolDir != "" && !filepath.IsAbs(*spoolDir)) {
		return errUsage
	}
	l := apply.Layout{Root: filepath.Clean(*root), StateDir: filepath.Clean(*stateDir)}
	sp := l.Spool()
	if *spoolDir != "" {
		sp = filepath.Clean(*spoolDir)
	}
	r, err := apply.ResetDirectory(l, sp)
	if r != nil {
		var b strings.Builder
		if r.Version == 0 {
			b.WriteString("no accepted directory: nothing was dropped from accepted/\n")
		} else {
			fmt.Fprintf(&b, "dropped the accepted directory version %d (SHA-256 %s)\n", r.Version, r.SHA256)
		}
		for _, n := range r.SpoolRemoved {
			fmt.Fprintf(&b, "removed from the spool: %s\n", n)
		}
		if err == nil {
			b.WriteString("the next apply takes the server's current directory from the start, verified like a first install; check its version in status.json\n")
		}
		if _, werr := io.WriteString(stdout, b.String()); werr != nil && err == nil {
			err = werr
		}
	}
	return err
}
