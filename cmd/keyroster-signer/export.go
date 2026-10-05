//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/signerdb"
)

func init() {
	register(command{
		Name:    "export-log",
		Summary: "export the audit log as JSONL for keyroster audit verify",
		Run:     runExportLog,
	})
}

func runExportLog(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("export-log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "state directory holding signer.db (required)")
	out := fs.String("out", "", "output file (default: standard output)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *stateDir == "" {
		_, _ = fmt.Fprintln(stderr, "export-log: --state-dir is required; no positional arguments")
		return errUsage
	}
	db, err := signerdb.OpenReadOnly(filepath.Join(*stateDir, "signer.db"))
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	if *out == "" {
		n, err := audit.Export(ctx, stdout, db)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stderr, "exported %d entries\n", n)
		return nil
	}
	// Write to a temporary file next to the target and rename it into
	// place, so a failed export never leaves a truncated file behind.
	tmp, err := os.CreateTemp(filepath.Dir(*out), ".export-log-*")
	if err != nil {
		return err
	}
	n, err := audit.Export(ctx, tmp, db)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), *out)
	}
	if err != nil {
		return errors.Join(err, os.Remove(tmp.Name()))
	}
	_, _ = fmt.Fprintf(stderr, "exported %d entries to %s\n", n, *out)
	return nil
}
