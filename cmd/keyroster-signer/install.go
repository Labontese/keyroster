//go:build linux

package main

import (
	"context"
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
	overrides, err := parseBackendOpts(backendOpts)
	if err != nil {
		return err
	}
	db, err := openState(*stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	_, be, err := openStoredBackend(ctx, db, overrides, *stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()

	b, err := signer.InstallBundle(ctx, db, be, pins, *threshold, docs[0], docs[1], docs[2], docs[3], nil)
	if err != nil {
		return err
	}
	var s strings.Builder
	fmt.Fprintf(&s, "installed bundle version %d (issued %s, sha256 %s)\n", b.Version, b.IssuedAt, trust.SHA256Hex(docs[0]))
	fmt.Fprintf(&s, "roots: %d, threshold %d\n", len(b.Root.Keys), b.Root.Threshold)
	for _, ca := range b.CAs {
		fmt.Fprintf(&s, "ca %-8s %s %s %s\n", ca.Role, keyFP(ca.Key), ca.Alg, ca.Custody)
	}
	fmt.Fprintf(&s, "ops         %s %s %s\n", keyFP(b.OpsKey.Key), b.OpsKey.Alg, b.OpsKey.Custody)
	fmt.Fprintf(&s, "log         %s %s %s origin %s\n", keyFP(b.Log.Key), b.Log.Alg, b.Log.Custody, b.Log.Origin)
	fmt.Fprintf(&s, "policy sha256 %s\n", b.PolicySHA256)
	_, err = io.WriteString(stdout, s.String())
	return err
}

func keyFP(key string) string {
	pub, err := trust.ParseKey(key)
	if err != nil {
		return "?"
	}
	return fingerprint(pub)
}

func fingerprint(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }
