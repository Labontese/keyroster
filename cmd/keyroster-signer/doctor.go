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
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/doctor"
	"github.com/Labontese/keyroster/internal/keystore/tpm"
	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/signerdb"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "doctor",
		Summary: "check the state directory, database, audit log, clock and key custody",
		Run:     runDoctor,
	})
}

// runDoctor prints one line per check, "LEVEL code: message", and fails
// (exit status 1) when any check is FAIL. It only reads: the database is
// opened read-only and never created, and it opens no network socket and
// runs no program. With the TPM backend it reads the TPM's manufacturer ID.
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "state directory of the signer (required)")
	var backendOpts listFlag
	fs.Var(&backendOpts, "backend-opt", "override a backend option stored by ca-init, key=value (repeatable), as given to serve; used to reach the TPM")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *stateDir == "" {
		_, _ = fmt.Fprintln(stderr, "doctor: --state-dir is required; no positional arguments")
		return errUsage
	}
	overrides, err := parseBackendOpts(backendOpts)
	if err != nil {
		return err
	}
	rs := doctor.Run(gatherFacts(ctx, *stateDir, overrides))
	var b strings.Builder
	fails := 0
	for _, r := range rs {
		b.WriteString(r.Line())
		b.WriteByte('\n')
		if r.Level == doctor.FAIL {
			fails++
		}
	}
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		return err
	}
	if doctor.ExitCode(rs) != 0 {
		return fmt.Errorf("%d check(s) failed", fails)
	}
	return nil
}

// gatherFacts collects the facts doctor checks. Every failure to read
// something becomes a fact (StateDirError, DBError, TPMError), never a
// silent OK.
func gatherFacts(ctx context.Context, stateDir string, overrides map[string]string) doctor.Facts {
	f := doctor.Facts{
		UID:           os.Getuid(),
		SignerUID:     os.Getuid(),
		StateDirOwner: -1,
		NowMicros:     uint64(time.Now().UnixMicro()), //nolint:gosec // G115: the clock is after 1970
	}
	if fi, err := os.Lstat(stateDir); err != nil {
		f.StateDirError = err.Error()
	} else if !fi.IsDir() {
		f.StateDirError = stateDir + " is not a directory"
	} else if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		f.StateDirMode, f.StateDirOwner = fi.Mode(), int(st.Uid)
	} else {
		f.StateDirError = "cannot read the owner of " + stateDir
	}

	dbPath := filepath.Join(stateDir, "signer.db")
	fi, err := os.Lstat(dbPath)
	switch {
	case err != nil:
		f.DBError = err.Error()
		return f
	case !fi.Mode().IsRegular():
		f.DBError = dbPath + " is not a regular file"
		return f
	}
	f.DBMode = fi.Mode()
	db, err := signerdb.OpenReadOnly(dbPath)
	if err != nil {
		f.DBError = err.Error()
		return f
	}
	defer func() { _ = db.Close() }()
	if err := readDBFacts(ctx, db, &f, overrides); err != nil {
		f.DBError = err.Error()
	}
	return f
}

// readDBFacts fills the facts that come from the state database (and, for
// the TPM backend, from the TPM the database names).
func readDBFacts(ctx context.Context, db *signerdb.DB, f *doctor.Facts, overrides map[string]string) error {
	out, err := db.IntegrityCheck(ctx)
	if err != nil {
		return err
	}
	f.IntegrityOK, f.IntegrityDetail = out == "ok", out

	keys, err := db.CAKeys(ctx)
	if err != nil {
		return err
	}
	var logKey ssh.PublicKey
	for _, k := range keys {
		f.CAKeys = append(f.CAKeys, doctor.CAKeyFact{Role: k.Role, Alg: k.Alg, Custody: k.Custody})
		if k.Role == "log" {
			if logKey, err = ssh.ParsePublicKey(k.PublicKey); err != nil {
				return fmt.Errorf("recorded log key: %w", err)
			}
		}
	}
	if logKey == nil {
		return errors.New("no log key recorded")
	}
	if err := signer.CheckLog(ctx, db, logKey); err != nil {
		f.LogDetail = err.Error()
	} else {
		f.LogMatches = true
	}

	if f.HighWaterMicros, err = db.LastSerial(ctx); err != nil {
		return err
	}

	stored, err := db.LatestBundle(ctx)
	switch {
	case errors.Is(err, signerdb.ErrNoBundle):
	case err != nil:
		return err
	default:
		if f.Bundle, err = trust.ParseBundle(stored.Bundle); err != nil {
			return fmt.Errorf("installed trust bundle: %w", err)
		}
	}

	name, opts, err := db.BackendConfig(ctx)
	if err != nil {
		return err
	}
	if name == "tpm" {
		for k, v := range overrides {
			opts[k] = v
		}
		id, custody, err := tpm.Inspect(opts)
		if err != nil {
			f.TPMError = err.Error()
		} else {
			f.TPMManufacturer, f.TPMCustody = id, string(custody)
		}
	}
	return nil
}
