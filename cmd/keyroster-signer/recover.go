//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/wire"
)

func init() {
	register(command{
		Name:    "recover-revocations",
		Summary: "apply a signed revocation recovery read from stdin (after a restore, under the hold)",
		Run:     runRecoverRevocations,
	})
}

// runRecoverRevocations is keyroster-signer recover-revocations --state-dir
// DIR [--backend-opt K=V ...] (03-06b): it reads the file form of an
// admin-signed recovery request (keyroster revoke recover --out) from
// standard input, takes the state lock, opens the signer with every
// start-up check (signer.New) and applies the request in one transaction
// (Signer.RecoverRevocations). It never serves, so no start-up publish
// runs; the only KRL it publishes is the recovery's. A refusal exits 1 with
// its name and reason, and nothing is written.
func runRecoverRevocations(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("recover-revocations", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "state directory of the restored signer (required); the signer must not be running")
	var backendOpts listFlag
	fs.Var(&backendOpts, "backend-opt", "override a backend option stored by ca-init, key=value (repeatable)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *stateDir == "" {
		_, _ = fmt.Fprintln(stderr, "recover-revocations: --state-dir is required; the request is read from standard input")
		return errUsage
	}
	return recoverRevocations(ctx, os.Stdin, *stateDir, backendOpts, stdout, stderr)
}

// recoverRevocations is runRecoverRevocations with its input.
func recoverRevocations(ctx context.Context, in io.Reader, stateDir string, backendOpts []string, stdout, stderr io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(in, wire.MaxRecoveryFile+1))
	if err != nil {
		return err
	}
	if len(data) > wire.MaxRecoveryFile {
		return fmt.Errorf("refused: recovery_malformed: the request on standard input is larger than %d bytes", wire.MaxRecoveryFile)
	}
	overrides, err := parseBackendOpts(backendOpts)
	if err != nil {
		return err
	}
	db, unlock, err := openState(stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	defer func() { _ = db.Close() }()
	_, be, err := openStoredBackend(ctx, db, overrides, stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()
	s, err := signer.New(signer.Config{
		Backend: be,
		DB:      db,
		// New refuses an empty peer allowlist. This command never serves
		// (no Serve, no socket), so no peer ever connects; the invoking
		// user stands in.
		AllowUIDs: []uint32{uint32(os.Getuid())}, //nolint:gosec // G115: a uid fits uint32
		Logger:    slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
	})
	if err != nil {
		return err
	}
	res, err := s.RecoverRevocations(ctx, data)
	if err != nil {
		// A refusal's error names it ("refused: recovery_log_mismatch");
		// its cause is the reason.
		if cause := errors.Unwrap(err); cause != nil {
			return fmt.Errorf("%w: %w", err, cause)
		}
		return err
	}
	_, err = fmt.Fprintf(stdout, "recovered: %d entries from %d imported KRLs, %d lost certificates revoked, %d kept; KRL v%d (log entries %d, %d)\n",
		res.Entries, res.Imports, res.Revoked, res.Kept, res.KRLVersion, res.RecoveryLeaf, res.PublishLeaf)
	return err
}
