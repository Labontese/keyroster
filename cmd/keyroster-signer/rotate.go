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
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/signer"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "ca-rotate",
		Summary: "CA key rotation: prepare records the next CA key generation of a role; retire-key removes its draining keys after a switch (signer stopped)",
		Run:     runCARotate,
	})
}

// runCARotate dispatches the ca-rotate subcommands: prepare (03-12) and
// retire-key (03-12e).
func runCARotate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "prepare":
			return runCARotatePrepare(ctx, args[1:], stdout, stderr)
		case "retire-key":
			return runCARotateRetireKey(ctx, args[1:], stdout, stderr)
		}
	}
	_, _ = fmt.Fprintln(stderr, "ca-rotate: want a subcommand: prepare or retire-key")
	return errUsage
}

// runCARotateRetireKey removes the draining CA keys of a role after a
// switch install, with signer.RetireKeys, and prints one line per draining
// generation (03-12e). It takes the state lock, so it is refused under the
// restore marker, and refuses a backend by its stored name before the
// backend opens. It exits 0 only when no draining key of the role is
// held.
func runCARotateRetireKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ca-rotate retire-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", "", "state directory initialised by ca-init (required)")
	role := flags.String("role", "", "the CA role whose draining keys to remove: user, host or machine (required)")
	var backendOpts listFlag
	flags.Var(&backendOpts, "backend-opt", "override a backend option stored by ca-init, key=value (repeatable)")
	if err := flags.Parse(args); err != nil {
		return errUsage
	}
	if flags.NArg() != 0 || *stateDir == "" || *role == "" {
		_, _ = fmt.Fprintln(stderr, "ca-rotate retire-key: --state-dir and --role are required; no positional arguments")
		return errUsage
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
	name, _, err := db.BackendConfig(ctx)
	if err != nil {
		return err
	}
	if err := signer.CheckRotationBackend(name); err != nil {
		return err
	}
	_, be, err := openStoredBackend(ctx, db, overrides, *stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()
	res, err := signer.RetireKeys(ctx, db, be, keystore.Role(*role))
	if res != nil {
		if werr := writeRetireResult(stdout, res); werr != nil {
			return werr
		}
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "retire-key: no draining key of role %s is held\n", res.Role)
	return err
}

// writeRetireResult prints one line per draining generation of res
// (03-12e): "role <r> generation <g> <fingerprint>: removed", ": not
// held", ": not removed: <reason>", or, for a key the agent still holds,
// the ssh-add command through the stored agent socket with the key's
// public line and one more command and line per certificate identity of
// that key, then "run retire-key again".
func writeRetireResult(w io.Writer, res *signer.RetireResult) error {
	var b strings.Builder
	for _, g := range res.Generations {
		head := fmt.Sprintf("role %s generation %d %s: ", res.Role, g.Generation, g.Fingerprint)
		switch g.Outcome {
		case signer.RetireRemoved, signer.RetireNotHeld:
			fmt.Fprintf(&b, "%s%s\n", head, g.Outcome)
		case signer.RetireNotRemoved:
			fmt.Fprintf(&b, "%snot removed: %s\n", head, g.Detail)
		default:
			if g.Detail != "" {
				fmt.Fprintf(&b, "%sstill held: %s\n", head, g.Detail)
			}
			if res.Socket == "" {
				fmt.Fprintf(&b, "%sstill held by the backend; remove it there, then run retire-key again\n", head)
				continue
			}
			file := fmt.Sprintf("retire-%s-g%d", res.Role, g.Generation)
			fmt.Fprintf(&b, "%sstill held by the agent; write this public key line into %s and run: SSH_AUTH_SOCK=%s ssh-add -d %s\n%s\n",
				head, file, res.Socket, file, g.KeyLine)
			for _, c := range g.CertLines {
				fmt.Fprintf(&b, "%swrite this certificate line into %s-cert.pub and run: SSH_AUTH_SOCK=%s ssh-add -d %s-cert.pub\n%s\n",
					head, file, res.Socket, file, c)
			}
			b.WriteString("run retire-key again\n")
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// runCARotatePrepare records the next CA key generation of a role with
// signer.PrepareGeneration and writes the prepare file a later root
// ceremony reads (03-12).
func runCARotatePrepare(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("ca-rotate prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	stateDir := flags.String("state-dir", "", "state directory initialised by ca-init (required)")
	role := flags.String("role", "", "the CA role to prepare a generation for: user, host or machine (required)")
	keyFP := flags.String("key", "", "SHA256:... selects the new key in the backend (agent); without it the backend creates one (software)")
	out := flags.String("out", "", "the prepare file for the root ceremony; must not exist (required)")
	var backendOpts listFlag
	flags.Var(&backendOpts, "backend-opt", "override a backend option stored by ca-init, key=value (repeatable)")
	if err := flags.Parse(args); err != nil {
		return errUsage
	}
	if flags.NArg() != 0 || *stateDir == "" || *role == "" || *out == "" {
		_, _ = fmt.Fprintln(stderr, "ca-rotate prepare: --state-dir, --role and --out are required; no positional arguments")
		return errUsage
	}
	overrides, err := parseBackendOpts(backendOpts)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(*out); err == nil {
		return fmt.Errorf("%s exists; name a new prepare file", *out)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	db, unlock, err := openState(*stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	defer func() { _ = db.Close() }()
	// Refuse a backend by its stored name before it is opened, so that a
	// refusal needs no device.
	name, _, err := db.BackendConfig(ctx)
	if err != nil {
		return err
	}
	if err := signer.CheckRotationBackend(name); err != nil {
		return err
	}
	_, be, err := openStoredBackend(ctx, db, overrides, *stateDir)
	if err != nil {
		return err
	}
	defer func() { _ = be.Close() }()

	// Claim the output file before anything is committed, as ca-init
	// does; every error path after the claim removes it again.
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G302,G304: a public key; the operator names the path
	if err != nil {
		return err
	}
	g, err := signer.PrepareGeneration(ctx, db, be, keystore.Role(*role), *keyFP, nil)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(*out)
		return err
	}
	pub, err := ssh.ParsePublicKey(g.PublicKey)
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("generation %d of %s is recorded, but its key does not parse, so %s was not written: %w", g.Generation, g.Role, *out, err)
	}
	data, err := prepareFileBytes(g.Role, g.Generation, pub, g.Custody)
	if err == nil {
		_, err = f.Write(data)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("generation %d of %s is recorded, but writing %s failed: %w", g.Generation, g.Role, *out, err)
	}
	_, err = fmt.Fprintf(stdout, "role %s generation %d %s %s %s\nprepare file: %s\n",
		g.Role, g.Generation, ssh.FingerprintSHA256(pub), g.Alg, g.Custody, *out)
	return err
}

// prepareFile is the prepare file: untagged strict JSON, its fields in
// this order (03-12). A later root ceremony reads it.
type prepareFile struct {
	Role       string `json:"role"`
	Generation uint32 `json:"generation"`
	Key        string `json:"key"`
	Alg        string `json:"alg"`
	Custody    string `json:"custody"`
}

// prepareFileBytes returns the prepare file's canonical JSON
// (trust.CanonicalJSON, which ends in one newline).
func prepareFileBytes(role string, generation uint32, pub ssh.PublicKey, custody string) ([]byte, error) {
	return trust.CanonicalJSON(prepareFile{Role: role, Generation: generation, Key: trust.FormatKey(pub), Alg: pub.Type(), Custody: custody})
}
