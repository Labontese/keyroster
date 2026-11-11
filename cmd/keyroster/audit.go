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
	"github.com/Labontese/keyroster/internal/trust"
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
		_, _ = fmt.Fprintln(stderr, "usage: keyroster audit verify --pin SHA256:... [--pin ...] --threshold N [--installation-id ID | --any-installation] [--previous FILE] [--json] EXPORT.jsonl")
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
	LogKey   string            `json:"log_key"`               // fingerprint, from the root-signed bundle
	Anchor   uint64            `json:"anchor_bundle_version"` // the trust bundle whose root set the pins name
	// PendingNegativeProbes counts the negative probe certificates that no
	// published KRL lists yet (03-10c, owner answer P2); omitted when zero.
	PendingNegativeProbes int `json:"pending_negative_probes,omitempty"`
	// InstallationID is the installation ID of the trust bundle in force
	// at the end of the log, "" when it names none (03-14c, F05).
	InstallationID string `json:"installation_id"`
}

func runAuditVerify(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var pins stringList
	fs.Var(&pins, "pin", "SHA256 fingerprint of an offline root key, obtained out of band (repeatable, required; the only trust anchor). The pins name the root set of one trust bundle in the log (the anchor), for example the current roots after a rotation; the log key and CA keys come from the root-signed bundles chained to it")
	threshold := fs.Int("threshold", 0, "root signatures the anchor bundle needs (required; must equal that bundle's threshold)")
	previousPath := fs.String("previous", "", "an earlier signed checkpoint, or an earlier export, that this log must extend")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	installationID := fs.String("installation-id", "", "the installation ID this export must be the log of: 32 lowercase hex digits, from the ceremony transcript's Installation ID line (03-14c, F05)")
	var anyInstallation bool
	fs.BoolVar(&anyInstallation, "any-installation", false, "verify without binding the result to one installation; the output still names the installation (03-14c, Q-C7)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 || len(pins) == 0 || *threshold < 1 {
		_, _ = fmt.Fprintln(stderr, "audit verify: at least one --pin, --threshold N (N >= 1) and exactly one export file are required")
		return errUsage
	}
	if *installationID != "" && !trust.IsInstallationID(*installationID) {
		_, _ = fmt.Fprintln(stderr, "audit verify: --installation-id wants 32 lowercase hex digits")
		return errUsage
	}
	if *installationID != "" && anyInstallation {
		_, _ = fmt.Fprintln(stderr, "audit verify: --installation-id and --any-installation exclude each other")
		return errUsage
	}
	opts := audit.Options{Pins: pins, Threshold: *threshold, InstallationID: *installationID}
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
	// Q-C7 (03-14c, F05): an installation-bound log is never verified
	// unbound by default. This runs before either output, so --json
	// prints nothing either.
	if rep.Bundle != nil && rep.Bundle.InstallationID != "" && *installationID == "" && !anyInstallation {
		return fmt.Errorf("audit verify: the trust bundle in force (v%d) names installation %s: pass --installation-id with the installation ID you have on record (the ceremony transcript's Installation ID line), or --any-installation to verify without binding the result to one installation",
			rep.Bundle.Version, rep.Bundle.InstallationID)
	}
	res := verifyResultOf(rep)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		return enc.Encode(res)
	}
	if err := printVerifyOK(stdout, res, rep); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "anchored: the pinned roots are the root set of trust bundle v%d\n", res.Anchor); err != nil {
		return err
	}
	var installation string
	switch {
	case res.InstallationID == "":
		installation = "installation id: none (the trust bundle in force names none)\n"
	case *installationID != "":
		installation = "installation id: " + res.InstallationID + " (checked against --installation-id)\n"
	default:
		installation = "installation id: " + res.InstallationID + " (not checked: --any-installation)\n"
	}
	if _, err := io.WriteString(stdout, installation); err != nil {
		return err
	}
	_, err = io.WriteString(stdout,
		"not checked: that each issuance was authorized by the policy's admins (the log keeps their evidence, not the signed request it covers)\n")
	return err
}

// printVerifyOK prints the OK line and, when the log holds host
// certificates (03-09), the line "host certificates: N" after it, then,
// when it holds machine certificates (03-11b, b-C12), "machine
// certificates: N", then,
// when it holds probe certificates (03-10c, owner answer P2), the line
// "probe certificates: N, negative probes no published KRL lists yet: M".
// issued counts admin issuances (issue entries) only; login certificates,
// directory installs, host and probe certificates are the counts of their
// own kinds. The two certificate counts need no JSON field, since Kinds
// carries them; the pending negatives do (pending_negative_probes),
// because no count of Kinds says which negatives a published KRL lists.
func printVerifyOK(w io.Writer, res verifyResult, rep *audit.Report) error {
	if _, err := fmt.Fprintf(w, "OK: %d entries, root %s, issued %d (user %d, host %d, machine %d), login certificates %d, directory installs %d, refusals %d, trust bundle v%d, policy v%d, log key %s\n",
		res.Entries, res.Root, res.Issued, res.ByCA["user"], res.ByCA["host"], res.ByCA["machine"],
		rep.Counts[tlog.KindLoginIssue], rep.Counts[tlog.KindDirectoryInstall],
		res.Refusals, res.Bundle, res.Policy, res.LogKey); err != nil {
		return err
	}
	if n := rep.Counts[tlog.KindHostIssue]; n > 0 {
		if _, err := fmt.Fprintf(w, "host certificates: %d\n", n); err != nil {
			return err
		}
	}
	if n := rep.Counts[tlog.KindMachineIssue]; n > 0 {
		if _, err := fmt.Fprintf(w, "machine certificates: %d\n", n); err != nil {
			return err
		}
	}
	if n := rep.Counts[tlog.KindProbeIssue]; n > 0 {
		if _, err := fmt.Fprintf(w, "probe certificates: %d, negative probes no published KRL lists yet: %d\n", n, res.PendingNegativeProbes); err != nil {
			return err
		}
	}
	return nil
}

// verifyResultOf is the summary of rep that the text and JSON outputs
// share (the log key is "" when rep has none).
func verifyResultOf(rep *audit.Report) verifyResult {
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
		Anchor:   rep.AnchorVersion,

		PendingNegativeProbes: rep.PendingNegativeProbes,
	}
	if rep.LogKey != nil {
		res.LogKey = ssh.FingerprintSHA256(rep.LogKey)
	}
	if rep.Bundle != nil {
		res.InstallationID = rep.Bundle.InstallationID
	}
	for k, n := range rep.Counts {
		res.Kinds[k.String()] = n
	}
	return res
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
