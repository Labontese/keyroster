//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/wire"
)

func init() {
	register(command{
		Name:    "recover-revocations",
		Summary: "apply a signed revocation recovery read from stdin (after a restore, under the hold); --no-recovery-needed or --migrate-only",
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
//
// It is the one command the restore marker does not refuse (03-12): a
// successful recovery removes the marker. --no-recovery-needed removes it
// without a recovery (when step 2b found nothing to recover), and
// --migrate-only opens signer.db under it to apply a pending migration and
// keeps it; neither reads standard input.
func runRecoverRevocations(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("recover-revocations", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", "", "state directory of the restored signer (required); the signer must not be running")
	noRecovery := flags.Bool("no-recovery-needed", false, "remove the restore-recovery-pending marker without a recovery; reads no standard input and opens no database")
	migrateOnly := flags.Bool("migrate-only", false, "open signer.db under the restore-recovery-pending marker to apply a pending migration, write nothing else and keep the marker")
	var backendOpts listFlag
	flags.Var(&backendOpts, "backend-opt", "override a backend option stored by ca-init, key=value (repeatable)")
	if err := flags.Parse(args); err != nil {
		return errUsage
	}
	if flags.NArg() != 0 || *stateDir == "" {
		_, _ = fmt.Fprintln(stderr, "recover-revocations: --state-dir is required; the request is read from standard input")
		return errUsage
	}
	switch {
	case *noRecovery && *migrateOnly:
		_, _ = fmt.Fprintln(stderr, "recover-revocations: --migrate-only and --no-recovery-needed exclude each other")
		return errUsage
	case *noRecovery:
		return releaseWithoutRecovery(*stateDir, stdout, stderr)
	case *migrateOnly:
		return migrateOnlyRun(*stateDir, stdout)
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
	db, unlock, err := openStateForRecovery(stateDir)
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
		// The recovery configuration (03-12e): no CA private key opens, so
		// a database restored from before a switch recovers after
		// retire-key removed the old key.
		Recovery: true,
	})
	if err != nil {
		return err
	}
	res, err := applyRecovery(ctx, s, data)
	if err != nil {
		// A refusal's error names it ("refused: recovery_log_mismatch");
		// its cause is the reason.
		if cause := errors.Unwrap(err); cause != nil {
			return fmt.Errorf("%w: %w", err, cause)
		}
		return err
	}
	if _, err := fmt.Fprintf(stdout, "recovered: %d entries from %d imported KRLs, %d lost certificates revoked, %d kept; KRL v%d (log entries %d, %d)\n",
		res.Entries, res.Imports, res.Revoked, res.Kept, res.KRLVersion, res.RecoveryLeaf, res.PublishLeaf); err != nil {
		return err
	}
	for _, b := range res.BeyondDrain {
		if _, err := fmt.Fprintln(stdout, b.String()); err != nil {
			return err
		}
	}
	// The recovery is committed: the restore hold can be released.
	if err := releaseRestoreMarker(stateDir, stderr); err != nil {
		return fmt.Errorf("the recovery was applied, but %w", err)
	}
	return nil
}

// applyRecovery applies a recovery request through the signer; tests
// replace it (03-12).
var applyRecovery = func(ctx context.Context, s *signer.Signer, data []byte) (*signer.RecoveryResult, error) {
	return s.RecoverRevocations(ctx, data)
}

// openStateForRecovery is openState with the state lock that the restore
// marker does not refuse (lockStateDirForRecovery), for recover-revocations
// only (03-12). It is the one place in this file that opens signer.db.
func openStateForRecovery(stateDir string) (db *signerdb.DB, unlock func(), err error) {
	if err := checkStateDir(stateDir); err != nil {
		return nil, nil, err
	}
	unlock, err = lockStateDirForRecovery(stateDir)
	if err != nil {
		return nil, nil, err
	}
	db, err = signerdb.Open(filepath.Join(stateDir, "signer.db"))
	if err != nil {
		unlock()
		return nil, nil, err
	}
	return db, unlock, nil
}

// releaseRestoreMarker removes the restore marker of stateDir, fsyncs the
// directory and records the release on stderr and in the journal (03-12).
// No marker is a silent no-op. A removed marker is recorded even when the
// fsync after it fails, and that error names the fsync. A marker
// os.Remove cannot remove (a non-empty directory) must be removed by
// hand; any other failure to remove it leaves it to --no-recovery-needed.
func releaseRestoreMarker(stateDir string, stderr io.Writer) error {
	marker := filepath.Join(stateDir, restoreMarkerName)
	removed, err := removeMarker(stateDir, marker)
	if removed {
		noteRelease(marker, stderr)
	}
	if err != nil {
		if removed || errors.Is(err, errMarkerByHand) {
			return err
		}
		return fmt.Errorf("the restore marker %s could not be removed (%w): remove it with keyroster-signer recover-revocations --state-dir %s --no-recovery-needed", marker, err, stateDir)
	}
	return nil
}

// errMarkerByHand is a marker that os.Remove cannot remove.
var errMarkerByHand = errors.New("the restore marker cannot be removed by this command")

// removeMarker removes marker and fsyncs stateDir. It reports whether it
// removed a marker, also when the fsync then fails.
func removeMarker(stateDir, marker string) (bool, error) {
	if _, err := os.Lstat(marker); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := os.Remove(marker); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if fi, serr := os.Lstat(marker); serr == nil && fi.IsDir() {
			return false, fmt.Errorf("%w: %s is a directory that is not empty: remove %s by hand", errMarkerByHand, marker, marker)
		}
		return false, err
	}
	if err := syncStateDir(stateDir); err != nil {
		return true, fmt.Errorf("the marker %s was removed, and syncing %s failed afterwards (%w), so the removal may not survive a crash", marker, stateDir, err)
	}
	return true, nil
}

// syncStateDir fsyncs the state directory dir; tests replace it.
var syncStateDir = func(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: the operator's state directory
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

// noteRelease records a removed marker on stderr and in the journal.
func noteRelease(marker string, stderr io.Writer) {
	text := "restore-recovery-pending removed: " + marker
	_, _ = fmt.Fprintln(stderr, text)
	journalNotice(text)
}

// releaseWithoutRecovery is --no-recovery-needed (03-12): it removes the
// restore marker without a recovery, after step 2b found nothing to
// recover. It reads no standard input and opens no database. Nothing
// authenticates it: it guards against operator error, not a local actor.
func releaseWithoutRecovery(stateDir string, stdout, stderr io.Writer) error {
	if err := checkStateDir(stateDir); err != nil {
		return err
	}
	unlock, err := lockStateDirForRecovery(stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	marker := filepath.Join(stateDir, restoreMarkerName)
	removed, err := removeMarker(stateDir, marker)
	if removed {
		noteRelease(marker, stderr)
	}
	if err != nil {
		return err
	}
	if !removed {
		_, err := fmt.Fprintf(stdout, "no restore-recovery-pending marker in %s\n", stateDir)
		return err
	}
	return nil
}

// migrateOnlyRun is --migrate-only (03-12): under the exempt lock it opens
// signer.db, which applies a pending migration (a backup older than this
// build is at schema 5), writes nothing else and keeps the marker. It
// reads no standard input, writes no journal entry, and refuses a
// signer.db that is missing or not a regular file, because signerdb.Open
// creates a missing file and follows a dangling symlink.
func migrateOnlyRun(stateDir string, stdout io.Writer) error {
	dbPath := filepath.Join(stateDir, "signer.db")
	fi, err := os.Lstat(dbPath)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", dbPath)
	}
	db, unlock, err := openStateForRecovery(stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	if err := db.Close(); err != nil {
		return err
	}
	marker := filepath.Join(stateDir, restoreMarkerName)
	const done = "migrate-only: signer.db is at the schema this binary reads; "
	if _, err := os.Lstat(marker); err == nil {
		_, err = fmt.Fprintf(stdout, "%srestore-recovery-pending kept: %s\n", done, marker)
		return err
	}
	_, err = fmt.Fprintf(stdout, "%sno restore-recovery-pending marker in %s\n", done, stateDir)
	return err
}

// journalSocketPath is the native journal socket (03-12); a test points it
// at its own listener.
var journalSocketPath = "/run/systemd/journal/socket"

// journalNotice sends text to the journal as one native-protocol datagram
// (PRIORITY=4, SYSLOG_IDENTIFIER=keyroster-signer, MESSAGE=text), best
// effort (03-12): the release commands run in a terminal, where the
// signer's own log reaches no journal. Every error is ignored, and no
// socket is no error. Any local user can write such an entry, so it is a
// record, not proof (the runbook filters on journald's own _UID).
func journalNotice(text string) {
	conn, err := net.DialTimeout("unixgram", journalSocketPath, time.Second)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	msg := "PRIORITY=4\nSYSLOG_IDENTIFIER=keyroster-signer\nMESSAGE=" + strings.ReplaceAll(text, "\n", " ") + "\n"
	_, _ = conn.Write([]byte(msg))
}
