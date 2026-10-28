//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Labontese/keyroster/internal/agent/apply"
)

func init() {
	register(command{
		Name:    "identity",
		Summary: "print this host's agent identity and host key fingerprints, to compare with keyroster host approve",
		Run:     runIdentity,
	})
}

const identityUsage = `usage: keyroster-agent identity [--state-dir DIR] [--spool DIR] [--root DIR]
       [--sshd PATH] [--sshd-config PATH]

Prints the fetcher's TLS identity (from identity.pub in the spool) and the
SHA256 fingerprint of every host key an enrollment signs with (the
Ed25519 and ECDSA host keys sshd -T names), in exactly the lines keyroster
host pending and keyroster host approve print for this host. Compare them
out of band before an admin approves the host. It changes nothing.
`

func runIdentity(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("identity", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, identityUsage) }
	stateDir := fset.String("state-dir", defaultStateDir, "the applier's state directory")
	spoolDir := fset.String("spool", "", "the spool directory (default <state-dir>/spool)")
	svc := addServiceFlags(fset, false)
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		return errUsage
	}
	if !filepath.IsAbs(*stateDir) || (*spoolDir != "" && !filepath.IsAbs(*spoolDir)) {
		_, _ = fmt.Fprintln(stderr, "identity: --state-dir and --spool must be absolute paths")
		return errUsage
	}
	l := apply.Layout{Root: filepath.Clean(*svc.root), StateDir: filepath.Clean(*stateDir)}
	spool := l.Spool()
	if *spoolDir != "" {
		spool = filepath.Clean(*spoolDir)
	}
	sshd, config, keygen, _, err := svc.resolve(ctx, stderr)
	if errors.Is(err, errUsage) {
		return err
	}
	if err != nil {
		return err
	}
	id, err := apply.ReadIdentity(ctx, apply.Config{Spool: spool, SSHD: sshd, SSHDConfig: config, SSHKeygen: keygen, Log: stderr}, l)
	if err != nil {
		return err
	}
	var b strings.Builder
	if id.Agent == "" {
		b.WriteString("agent identity: none yet (start keyroster-agent-fetch, which writes it)\n")
	} else {
		fmt.Fprintf(&b, "agent identity: %s\n", id.Agent)
	}
	for i, k := range id.HostKeys {
		fmt.Fprintf(&b, "host key: %s %s\n", id.Fingerprints[i], strings.Fields(k)[0])
	}
	_, err = io.WriteString(stdout, b.String())
	return err
}
