//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/doctor"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/keystore/software"
	"github.com/Labontese/keyroster/internal/keystore/tpm"
	"github.com/Labontese/keyroster/internal/krl"
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
// runs no program. With the TPM backend it reads the TPM's manufacturer ID;
// with the agent backend, after a CA switch, it asks the stored agent
// socket whether the agent still lists a draining key (03-12e).
func runDoctor(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "state directory of the signer (required)")
	var backendOpts listFlag
	fs.Var(&backendOpts, "backend-opt", "override a backend option stored by ca-init, key=value (repeatable), as given to serve; used to reach the TPM or the agent")
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

	// The restore marker is read without the lock, as every fact here;
	// any entry of that name counts, as in lockStateDir (03-12).
	marker := filepath.Join(stateDir, restoreMarkerName)
	if _, err := os.Lstat(marker); err == nil || !errors.Is(err, fs.ErrNotExist) {
		f.RestoreMarker = marker
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
	drain, err := readDBFacts(ctx, db, &f, overrides)
	if err != nil {
		f.DBError = err.Error()
	}
	if gens, err := db.CAGenerations(ctx); err == nil {
		f.Generations = generationFacts(gens, f.Bundle)
		f.UnrecordedGenerationFiles = unrecordedGenerationFiles(stateDir, gens)
		if f.DBError == "" {
			f.SwitchFloors = switchFloors(gens, f.Bundle, drain)
			f.DrainingHeld = drainingHeld(ctx, db, stateDir, overrides, gens, f.Bundle)
		}
	}
	return f
}

// storedGeneration is the stored generation row of role whose key is the
// bundle key key, or nil.
func storedGeneration(gens []signerdb.CAGeneration, role, key string) *signerdb.CAGeneration {
	for i, g := range gens {
		if g.Role != role {
			continue
		}
		if pub, err := ssh.ParsePublicKey(g.PublicKey); err == nil && trust.FormatKey(pub) == key {
			return &gens[i]
		}
	}
	return nil
}

// switchFloors are, per active CA entry of b, the certificate of its key
// with the largest ValidBefore in drain, the verified log's accumulator
// (03-12e). With no bundle, or no accumulator (the log did not verify,
// which doctor reports as a FAIL), there are none.
func switchFloors(gens []signerdb.CAGeneration, b *trust.Bundle, drain *krl.DrainMax) []doctor.SwitchFloor {
	if b == nil || drain == nil {
		return nil
	}
	var out []doctor.SwitchFloor
	for _, ca := range b.CAs {
		if ca.State != "active" {
			continue
		}
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			continue
		}
		sf := doctor.SwitchFloor{Role: ca.Role, Generation: ca.Generation}
		if g := storedGeneration(gens, ca.Role, ca.Key); g != nil {
			sf.Generation = g.Generation
		}
		if e, ok := drain.For(pub.Marshal()); ok {
			_, fits := krl.EarliestTrustedUntil(e.ValidBefore)
			sf.HasCertificate, sf.Serial, sf.KeyID, sf.ValidBefore, sf.Saturated = true, e.Serial, e.KeyID, e.ValidBefore, !fits
		}
		out = append(out, sf)
	}
	return out
}

// drainingHeld asks, for every draining CA entry of b, whether the stored
// backend still holds its generation (03-12e), as serve does at start:
// the software backend by its file (software.GenerationHeld, which needs
// no passphrase), the agent backend through the stored socket
// (keystore.Holds). A generation doctor cannot check, because no stored
// row names its key, the agent cannot be reached or answers with an
// error, or the backend is neither, is reported Unchecked, never as gone.
func drainingHeld(ctx context.Context, db *signerdb.DB, stateDir string, overrides map[string]string, gens []signerdb.CAGeneration, b *trust.Bundle) []doctor.HeldFact {
	if b == nil {
		return nil
	}
	type target struct {
		fact doctor.HeldFact
		gen  *signerdb.CAGeneration
	}
	var targets []target
	for _, ca := range b.CAs {
		if ca.State != "draining" {
			continue
		}
		t := target{fact: doctor.HeldFact{Role: ca.Role, Generation: ca.Generation, Fingerprint: ca.Key}}
		if pub, err := trust.ParseKey(ca.Key); err == nil {
			t.fact.Fingerprint = ssh.FingerprintSHA256(pub)
		}
		if t.gen = storedGeneration(gens, ca.Role, ca.Key); t.gen == nil {
			t.fact.Unchecked = "no stored generation row names this key"
		} else {
			t.fact.Generation = t.gen.Generation
		}
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return nil
	}
	var (
		be      keystore.Backend
		openErr error
	)
	switch name, _, err := db.BackendConfig(ctx); {
	case err != nil:
		openErr = err
	case name == "agent":
		if _, be, openErr = openStoredBackend(ctx, db, overrides, stateDir); openErr == nil {
			defer func() { _ = be.Close() }()
		}
	case name != "software":
		openErr = fmt.Errorf("doctor does not ask the %s backend", name)
	}
	var out []doctor.HeldFact
	for _, t := range targets {
		f := t.fact
		if f.Unchecked == "" {
			var (
				held bool
				err  error
			)
			switch {
			case openErr != nil:
				err = openErr
			case be == nil:
				held, err = software.GenerationHeld(stateDir, keystore.Role(f.Role), f.Generation)
			default:
				held, err = keystore.Holds(be, keystore.Role(f.Role), f.Generation, f.Fingerprint, t.gen.Location)
			}
			switch {
			case err != nil:
				f.Unchecked = err.Error()
			case !held:
				continue
			}
		}
		out = append(out, f)
	}
	return out
}

// generationFacts are the stored CA key generations with the state of the
// installed bundle's entry for the same key (03-12): active for the ops or
// log key the bundle names, prepared when the bundle names no such entry.
func generationFacts(gens []signerdb.CAGeneration, b *trust.Bundle) []doctor.GenerationFact {
	out := make([]doctor.GenerationFact, 0, len(gens))
	for _, g := range gens {
		gf := doctor.GenerationFact{Role: g.Role, Generation: g.Generation, Alg: g.Alg, Custody: g.Custody, State: "prepared"}
		pub, err := ssh.ParsePublicKey(g.PublicKey)
		if err != nil {
			gf.Fingerprint = "an unparsable key"
			out = append(out, gf)
			continue
		}
		gf.Fingerprint = ssh.FingerprintSHA256(pub)
		if b != nil {
			key := trust.FormatKey(pub)
			for _, ca := range b.CAs {
				if ca.Key == key {
					gf.State = ca.State
					if ca.State == "draining" {
						gf.TrustedUntil = ca.TrustedUntil // 03-12c
					}
				}
			}
			if b.OpsKey.Key == key || b.Log.Key == key {
				gf.State = "active"
			}
		}
		out = append(out, gf)
	}
	return out
}

// generationFile is the name of a software key file of a later CA key
// generation: <role>-g<N>.age.
var generationFile = regexp.MustCompile(`^(user|host|machine|ops|log)-g([0-9]{1,10})\.age$`)

// unrecordedGenerationFiles lists, by name only (no file is opened), the
// <role>-g<N>.age files in {stateDir}/software with N of at least 2 that no
// generation row names (03-12). A missing or unreadable directory gives
// none: the agent, tpm and piv backends have no such directory.
func unrecordedGenerationFiles(stateDir string, gens []signerdb.CAGeneration) []string {
	dir := filepath.Join(stateDir, "software")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		m := generationFile.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		n, err := strconv.ParseUint(m[2], 10, 32)
		if err != nil || n < 2 {
			continue
		}
		recorded := false
		for _, g := range gens {
			if g.Role == m[1] && uint64(g.Generation) == n {
				recorded = true
			}
		}
		if !recorded {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// readDBFacts fills the facts that come from the state database (and, for
// the TPM backend, from the TPM the database names). It returns the
// verified log's drain accumulator (03-12e), nil when the log does not
// verify.
func readDBFacts(ctx context.Context, db *signerdb.DB, f *doctor.Facts, overrides map[string]string) (*krl.DrainMax, error) {
	out, err := db.IntegrityCheck(ctx)
	if err != nil {
		return nil, err
	}
	f.IntegrityOK, f.IntegrityDetail = out == "ok", out

	keys, err := db.CAKeys(ctx)
	if err != nil {
		return nil, err
	}
	var logKey ssh.PublicKey
	for _, k := range keys {
		f.CAKeys = append(f.CAKeys, doctor.CAKeyFact{Role: k.Role, Alg: k.Alg, Custody: k.Custody})
		if k.Role == "log" {
			if logKey, err = ssh.ParsePublicKey(k.PublicKey); err != nil {
				return nil, fmt.Errorf("recorded log key: %w", err)
			}
		}
	}
	if logKey == nil {
		return nil, errors.New("no log key recorded")
	}
	// One walk: CheckLog's verified rebuild with the drain scan (03-12e).
	drain, err := signer.LogDrain(ctx, db, logKey)
	if err != nil {
		f.LogDetail = err.Error()
	} else {
		f.LogMatches = true
	}

	if f.HighWaterMicros, err = db.LastSerial(ctx); err != nil {
		return nil, err
	}

	stored, err := db.LatestBundle(ctx)
	switch {
	case errors.Is(err, signerdb.ErrNoBundle):
	case err != nil:
		return nil, err
	default:
		if f.Bundle, err = trust.ParseBundle(stored.Bundle); err != nil {
			return nil, fmt.Errorf("installed trust bundle: %w", err)
		}
	}
	// The checks serve runs on the bundle at start, except opening the
	// keys in the backend: the recorded log key above is checked against
	// the bundle's here.
	if err := signer.CheckTrust(ctx, db); err != nil {
		f.TrustError = err.Error()
	}

	name, opts, err := db.BackendConfig(ctx)
	if err != nil {
		return nil, err
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
	return drain, nil
}
