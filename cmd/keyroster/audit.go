package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh"

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
		_, _ = fmt.Fprintln(stderr, "usage: keyroster audit verify --pin SHA256:... [--pin ...] --threshold N [--previous FILE] [--json] EXPORT.jsonl")
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
	Refusals uint64            `json:"refusals"` // logged individually + summarized
	Logged   uint64            `json:"refusals_logged"`
	Summed   uint64            `json:"refusals_summarized"`
	Kinds    map[string]uint64 `json:"kinds"`
	ByCA     map[string]int    `json:"issued_by_ca"`
	Bundle   uint64            `json:"bundle_version"`
	Policy   uint64            `json:"policy_version"`
	LogKey   string            `json:"log_key"` // fingerprint, from the root-signed bundle
}

func runAuditVerify(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var pins stringList
	fs.Var(&pins, "pin", "SHA256 fingerprint of an offline root key, obtained out of band (repeatable, required; the only trust anchor: the log key and CA keys come from root-signed bundles in the log)")
	threshold := fs.Int("threshold", 0, "root signatures the genesis bundle needs (required; must equal the bundle's threshold)")
	previousPath := fs.String("previous", "", "an earlier signed checkpoint, or an earlier export, that this log must extend")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 || len(pins) == 0 || *threshold < 1 {
		_, _ = fmt.Fprintln(stderr, "audit verify: at least one --pin, --threshold N (N >= 1) and exactly one export file are required")
		return errUsage
	}
	opts := audit.Options{Pins: pins, Threshold: *threshold}
	if *previousPath != "" {
		var err error
		if opts.Previous, err = readPrevious(*previousPath); err != nil {
			return err
		}
	}
	f, err := os.Open(fs.Arg(0))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	rep, err := audit.Verify(f, opts)
	if err != nil {
		return err
	}
	res := verifyResult{
		OK:       true,
		Entries:  rep.Size,
		Root:     base64.StdEncoding.EncodeToString(rep.Root),
		Issued:   rep.Serials,
		Refusals: rep.Counts[tlog.KindRefusal] + rep.SummarizedRefusals,
		Logged:   rep.Counts[tlog.KindRefusal],
		Summed:   rep.SummarizedRefusals,
		Kinds:    map[string]uint64{},
		ByCA:     rep.IssuedByCA,
		Bundle:   rep.BundleVersion,
		Policy:   rep.PolicyVersion,
		LogKey:   ssh.FingerprintSHA256(rep.LogKey),
	}
	for k, n := range rep.Counts {
		res.Kinds[k.String()] = n
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		return enc.Encode(res)
	}
	_, err = fmt.Fprintf(stdout, "OK: %d entries, root %s, issued %d (user %d, host %d, machine %d), refusals %d, trust bundle v%d, policy v%d, log key %s\n",
		res.Entries, res.Root, res.Issued, res.ByCA["user"], res.ByCA["host"], res.ByCA["machine"], res.Refusals, res.Bundle, res.Policy, res.LogKey)
	return err
}

// readPrevious returns the signed checkpoint in path: either a checkpoint
// note as written by keyroster, or an earlier export, whose final
// checkpoint line is used. The note is verified later, against the log key
// of the root-signed bundle.
func readPrevious(path string) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return nil, err
	}
	trimmed := bytes.TrimSpace(data)
	if !bytes.HasPrefix(trimmed, []byte("{")) {
		return data, nil
	}
	last := trimmed[bytes.LastIndexByte(trimmed, '\n')+1:]
	var line audit.ExportLine
	if err := json.Unmarshal(last, &line); err != nil || line.Checkpoint == "" {
		return nil, fmt.Errorf("--previous %s: the last line of the export is not a checkpoint line", path)
	}
	return []byte(line.Checkpoint), nil
}
