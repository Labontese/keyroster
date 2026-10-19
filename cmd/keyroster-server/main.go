//go:build linux

// Command keyroster-server is keyroster's web front: the untrusted server
// that proposes but never decides. It serves HTTPS from an operator's
// certificate files and takes its identity (the WebAuthn relying party)
// and every custody fact from keyroster-signer's Status.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// errUsage reports a command-line usage error (exit status 2).
var errUsage = errors.New("usage error")

const usage = "usage: keyroster-server serve --tls-cert FILE --tls-key FILE [--listen ADDR] [--signer-socket PATH]\n"

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

// run dispatches the subcommand and returns the exit status: 0 on
// success, 2 on a usage error and 1 on any other error.
func run(ctx context.Context, args []string, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "serve" {
		_, _ = io.WriteString(stderr, usage)
		return 2
	}
	if err := runServe(ctx, args[1:], stderr); err != nil {
		if errors.Is(err, errUsage) {
			_, _ = io.WriteString(stderr, usage)
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "keyroster-server serve: %v\n", err)
		return 1
	}
	return 0
}
