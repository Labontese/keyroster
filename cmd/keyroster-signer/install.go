//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "install-bundle",
		Summary: "verify a root-signed trust bundle and policy and install them",
		Run:     runInstallBundle,
	})
}

func runInstallBundle(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("install-bundle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "state directory initialised by ca-init (required)")
	threshold := fs.Int("threshold", 0, "root signatures a genesis bundle needs (genesis only; must equal the bundle's threshold)")
	bundlePath := fs.String("bundle", "", "bundle.json (required); its signatures are read from FILE.sigs")
	policyPath := fs.String("policy", "", "policy.json (required); its signatures are read from FILE.sigs")
	var pins, backendOpts listFlag
	fs.Var(&pins, "pin", "SHA256 fingerprint of a root key, obtained out of band (repeatable; genesis only: the bundle's root set must be exactly the pinned set)")
	fs.Var(&backendOpts, "backend-opt", "override a backend option stored by ca-init, key=value (repeatable)")
	previousPath := fs.String("previous", "", "an export-log file of this log kept off the box; its last line, the signed checkpoint, must be extended by the log (required for a CA switch)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *stateDir == "" || *bundlePath == "" || *policyPath == "" {
		_, _ = fmt.Fprintln(stderr, "install-bundle: --state-dir, --bundle and --policy are required; no positional arguments")
		return errUsage
	}
	if len(pins) != 0 && *threshold == 0 {
		*threshold = len(pins)
	}
	docs := make([][]byte, 4)
	for i, p := range []string{*bundlePath, *bundlePath + ".sigs", *policyPath, *policyPath + ".sigs"} {
		data, err := os.ReadFile(p) //nolint:gosec // G304: the operator names the files
		if err != nil {
			return err
		}
		docs[i] = data
	}
	var previous []byte
	if *previousPath != "" {
		cp, err := readPreviousCheckpoint(*previousPath)
		if err != nil {
			return err
		}
		previous = cp
	}
	overrides, err := parseBackendOpts(backendOpts)
	if err != nil {
		return err
	}
	db, unlock, err := openState(*stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	defer func() { _ = db.Close() }()
	_, be, err := openStoredBackend(ctx, db, overrides, *stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()

	b, notes, err := signer.InstallBundleWithPrevious(ctx, db, be, pins, *threshold, docs[0], docs[1], docs[2], docs[3], nil, previous)
	if err != nil {
		return err
	}
	var s strings.Builder
	fmt.Fprintf(&s, "installed bundle version %d (issued %s, sha256 %s)\n", b.Version, b.IssuedAt, trust.SHA256Hex(docs[0]))
	fmt.Fprintf(&s, "roots: %d, threshold %d\n", len(b.Root.Keys), b.Root.Threshold)
	for _, ca := range b.CAs {
		fmt.Fprintf(&s, "ca %-8s %s %s %s\n", ca.Role, keyFP(ca.Key), ca.Alg, ca.Custody)
	}
	// One line per newly draining entry (03-12e).
	for _, n := range notes {
		fmt.Fprintln(&s, n.String())
	}
	fmt.Fprintf(&s, "ops         %s %s %s\n", keyFP(b.OpsKey.Key), b.OpsKey.Alg, b.OpsKey.Custody)
	fmt.Fprintf(&s, "log         %s %s %s origin %s\n", keyFP(b.Log.Key), b.Log.Alg, b.Log.Custody, b.Log.Origin)
	fmt.Fprintf(&s, "policy sha256 %s\n", b.PolicySHA256)
	_, err = io.WriteString(stdout, s.String())
	return err
}

// maxPreviousTail is the most of an export-log file that --previous reads:
// its last 1 MiB, which holds its last line, the checkpoint (03-12e).
const maxPreviousTail = 1 << 20

// readPreviousCheckpoint returns the signed checkpoint note of the
// export-log file at path: the last non-empty line of its last 1 MiB,
// which must be {"checkpoint":"<note>"} and nothing else (03-12e). A file
// whose last line is longer than that, or is no checkpoint line, is
// refused install_previous_invalid; whether the note verifies and the log
// extends it is the install's check.
func readPreviousCheckpoint(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	off := max(fi.Size()-maxPreviousTail, 0)
	tail := make([]byte, fi.Size()-off)
	if _, err := f.ReadAt(tail, off); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	tail = bytes.TrimRight(tail, "\n")
	i := bytes.LastIndexByte(tail, '\n')
	if i < 0 && off > 0 {
		return nil, fmt.Errorf("%w: the last line of %s is longer than 1 MiB", signer.ErrInstallPreviousInvalid, path)
	}
	line := tail[i+1:]
	if len(line) == 0 {
		return nil, fmt.Errorf("%w: %s holds no line", signer.ErrInstallPreviousInvalid, path)
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var cp struct {
		Checkpoint string `json:"checkpoint"`
	}
	if err := dec.Decode(&cp); err != nil || dec.More() || cp.Checkpoint == "" {
		return nil, fmt.Errorf("%w: the last line of %s is not the checkpoint line of an export-log file", signer.ErrInstallPreviousInvalid, path)
	}
	return []byte(cp.Checkpoint), nil
}

func keyFP(key string) string {
	pub, err := trust.ParseKey(key)
	if err != nil {
		return "?"
	}
	return fingerprint(pub)
}

func fingerprint(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }
