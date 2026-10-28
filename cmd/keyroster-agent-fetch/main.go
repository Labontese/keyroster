//go:build linux

// Command keyroster-agent-fetch is the keyroster agent's unprivileged
// fetcher (03-07, D-05), run as the system user keyroster-agent: it
// enrolls the host with the join token keyroster-agent install left, then
// polls the agent server over pinned mTLS and writes the signed state it
// receives into the spool, where the root applier (keyroster-agent run)
// verifies it. It runs no program and opens no listening socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Labontese/keyroster/internal/agent/fetch"
)

const usage = `usage: keyroster-agent-fetch [--config FILE] [--dir DIR] [--spool DIR] [--outbox DIR] [--poll D]
       keyroster-agent-fetch --rotate-identity [--config FILE] [--dir DIR] [--spool DIR] [--outbox DIR]

Runs as keyroster-agent. --config is fetch.json (default
/etc/keyroster-agent/fetch.json), --dir the fetcher's own directory
(default /var/lib/keyroster-agent-fetch), --spool and --outbox the
applier's (default /var/lib/keyroster-agent/spool and .../outbox). --poll
is the poll interval (default 60s, at least 1s), with a uniform jitter of a
sixth of it either way. Every poll ends with a heartbeat: the applier's
status (outbox/status.json) with this host's clock offset.

--rotate-identity replaces the agent's TLS identity once and exits (run it
as keyroster-agent, while the service runs or not): a new key is written to
identity.next, the server is asked to switch, signed by the current key,
and on its answer identity.next becomes identity.key. When the answer is
lost, the next poll finishes the rotation.
`

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stderr))
}

func run(ctx context.Context, args []string, stderr io.Writer) int {
	fset := flag.NewFlagSet("keyroster-agent-fetch", flag.ContinueOnError)
	fset.SetOutput(stderr)
	fset.Usage = func() { _, _ = io.WriteString(stderr, usage) }
	config := fset.String("config", "/etc/keyroster-agent/fetch.json", "fetch.json")
	dir := fset.String("dir", "/var/lib/keyroster-agent-fetch", "the fetcher's own directory")
	spoolDir := fset.String("spool", "/var/lib/keyroster-agent/spool", "the spool directory")
	outbox := fset.String("outbox", "/var/lib/keyroster-agent/outbox", "the applier's outbox")
	poll := fset.Duration("poll", fetch.DefaultPoll, "the poll interval (at least 1s)")
	rotate := fset.Bool("rotate-identity", false, "rotate the agent's TLS identity once and exit")
	if err := fset.Parse(args); err != nil || fset.NArg() != 0 {
		return 2
	}
	for _, p := range []string{*config, *dir, *spoolDir, *outbox} {
		if !filepath.IsAbs(p) {
			_, _ = fmt.Fprintf(stderr, "keyroster-agent-fetch: %s is not an absolute path\n", p)
			return 2
		}
	}
	if *poll < time.Second {
		_, _ = fmt.Fprintln(stderr, "keyroster-agent-fetch: --poll must be at least 1s")
		return 2
	}
	f, err := fetch.New(fetch.Config{ConfigFile: filepath.Clean(*config), Dir: filepath.Clean(*dir), Spool: filepath.Clean(*spoolDir),
		Outbox: filepath.Clean(*outbox), Poll: *poll, Log: stderr})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "keyroster-agent-fetch: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *rotate {
		if err := f.RotateIdentity(ctx); err != nil {
			_, _ = fmt.Fprintf(stderr, "keyroster-agent-fetch: %v\n", err)
			return 1
		}
		return 0
	}
	if err := f.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		_, _ = fmt.Fprintf(stderr, "keyroster-agent-fetch: %v\n", err)
		return 1
	}
	return 0
}
