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

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "ca-init",
		Summary: "select or create the user, host and machine CA, ops and log keys; write ca-pubkeys.json",
		Run:     runCAInit,
	})
}

func runCAInit(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("ca-init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", "", "state directory (required; owned by this user, mode 0700); holds signer.db")
	backend := fs.String("backend", "", "keystore backend holding the keys (required), e.g. agent")
	out := fs.String("out", "", "ca-pubkeys.json for the root ceremony; must not exist (default {state-dir}/ca-pubkeys.json)")
	var backendOpts, keyFlags listFlag
	fs.Var(&backendOpts, "backend-opt", "backend option key=value (repeatable), e.g. socket=PATH")
	fs.Var(&keyFlags, "key", "ROLE=SHA256:... selects the key for a role: user, host, machine, ops, log (repeatable; all five, or none for a backend that creates keys)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 || *stateDir == "" || *backend == "" {
		_, _ = fmt.Fprintln(stderr, "ca-init: --state-dir and --backend are required; no positional arguments")
		return errUsage
	}
	selection, err := parseKeySelection(keyFlags)
	if err != nil {
		return err
	}
	opts, err := parseBackendOpts(backendOpts)
	if err != nil {
		return err
	}
	dest := *out
	if dest == "" {
		dest = filepath.Join(*stateDir, "ca-pubkeys.json")
	}

	db, err := openState(*stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	// The state directory reaches the backend as the reserved state-dir
	// option; InitCA stores only the operator's options.
	be, err := openBackend(*backend, opts, *stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()

	// Claim the output file before anything is committed, so a ca-init
	// that cannot write its result commits nothing.
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302,G304: public keys; the operator names the path
	if err != nil {
		return err
	}
	cas, err := signer.InitCA(ctx, db, be, *backend, opts, selection, nil)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(dest)
		return err
	}
	data, err := cas.Canonical()
	if err == nil {
		_, err = f.Write(data)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("the CA keys are initialised, but writing %s failed: %w", dest, err)
	}
	var b strings.Builder
	if d, ok := be.(keystore.Describer); ok {
		fmt.Fprintln(&b, d.Describe())
	}
	for _, k := range cas.Keys {
		pub, err := trust.ParseKey(k.Key)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%-8s %s %s %s\n", k.Role, fingerprint(pub), k.Alg, k.Custody)
	}
	fmt.Fprintf(&b, "ca-pubkeys: %s\n", dest)
	_, err = io.WriteString(stdout, b.String())
	return err
}

// parseKeySelection parses --key ROLE=SHA256:... flags.
func parseKeySelection(vals []string) (map[keystore.Role]string, error) {
	sel := map[keystore.Role]string{}
	for _, v := range vals {
		role, fp, ok := strings.Cut(v, "=")
		if !ok || !strings.HasPrefix(fp, "SHA256:") {
			return nil, fmt.Errorf("--key %q: want ROLE=SHA256:<fingerprint>", v)
		}
		switch r := keystore.Role(role); r {
		case keystore.RoleUser, keystore.RoleHost, keystore.RoleMachine, keystore.RoleOps, keystore.RoleLog:
			if _, dup := sel[r]; dup {
				return nil, fmt.Errorf("--key %s given twice", role)
			}
			sel[r] = fp
		default:
			return nil, errors.New("--key: role must be user, host, machine, ops or log")
		}
	}
	return sel, nil
}
