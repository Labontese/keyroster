package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/tlog"
)

func init() {
	register(command{
		Name:    "audit",
		Summary: "audit log operations (verify)",
		Run:     runAudit,
	})
}

func runAudit(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: keyroster audit verify --log-key FILE.pub [--json] EXPORT.jsonl")
		return errUsage
	}
	switch args[0] {
	case "verify":
		return runAuditVerify(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "keyroster audit: unknown subcommand %q\n", args[0])
		return errUsage
	}
}

// verifyResult is the --json output of audit verify.
type verifyResult struct {
	OK       bool              `json:"ok"`
	Entries  uint64            `json:"entries"`
	Root     string            `json:"root"`
	Issued   int               `json:"issued"`
	Refusals uint64            `json:"refusals"`
	Kinds    map[string]uint64 `json:"kinds"`
}

func runAuditVerify(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	logKeyPath := fs.String("log-key", "", "pinned log public key, OpenSSH .pub file (required; never taken from the export)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 || *logKeyPath == "" {
		_, _ = fmt.Fprintln(stderr, "audit verify: --log-key and exactly one export file are required")
		return errUsage
	}
	logKey, err := readPublicKey(*logKeyPath)
	if err != nil {
		return err
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	rep, err := audit.Verify(f, audit.Options{LogKey: logKey})
	if err != nil {
		return err
	}
	res := verifyResult{
		OK:       true,
		Entries:  rep.Size,
		Root:     base64.StdEncoding.EncodeToString(rep.Root),
		Issued:   rep.Serials,
		Refusals: rep.Counts[tlog.KindRefusal],
		Kinds:    map[string]uint64{},
	}
	for k, n := range rep.Counts {
		res.Kinds[k.String()] = n
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		return enc.Encode(res)
	}
	_, err = fmt.Fprintf(stdout, "OK: %d entries, root %s, issued %d, refusals %d\n", res.Entries, res.Root, res.Issued, res.Refusals)
	return err
}
