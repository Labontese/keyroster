//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

func init() {
	register(command{
		Name:    "krl-version",
		Summary: "print the KRL version this host enforces, for the restore cross-check (read only)",
		Run:     runKRLVersion,
	})
}

const krlVersionUsage = `usage: keyroster-agent krl-version [--root DIR] [--state-dir DIR]

Prints one line, "installed KRL version: N": the KRL version this host
enforces, the larger of the version in accepted/ and the KRL in the
generation current names (0: none yet). It only reads; it takes no lock
and changes nothing. signer-install.md's restore cross-check compares it
with the KRL copy keyroster-server kept (T-03-277).
`

// krlVersionLine is the pinned output of krl-version, before the number.
const krlVersionLine = "installed KRL version: "

func runKRLVersion(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("krl-version", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, krlVersionUsage) }
	root := fset.String("root", "/", "the root of the file system the agent's files are under")
	stateDir := fset.String("state-dir", defaultStateDir, "the applier's state directory")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 || !filepath.IsAbs(*root) || !filepath.IsAbs(*stateDir) {
		return errUsage
	}
	v, err := apply.InstalledKRLVersion(apply.Layout{Root: filepath.Clean(*root), StateDir: filepath.Clean(*stateDir)})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "%s%d\n", krlVersionLine, v)
	return err
}
