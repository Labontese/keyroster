package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/rootceremony"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "trust",
		Summary: "trust bundle operations (verify)",
		Run:     runTrust,
	})
}

func runTrust(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: keyroster trust verify [flags]")
		return errUsage
	}
	switch args[0] {
	case "verify":
		return runTrustVerify(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "keyroster trust: unknown subcommand %q\n", args[0])
		return errUsage
	}
}

func runTrustVerify(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("trust verify", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var pins stringList
	fset.Var(&pins, "pin", "SHA256 fingerprint of a root key, obtained out of band (repeatable, at least one)")
	threshold := fset.Int("threshold", 0, "number of distinct pinned roots that must have signed (required)")
	bundlePath := fset.String("bundle", "", "bundle.json; signatures are read from bundle.json.sigs (required)")
	policyPath := fset.String("policy", "", "policy.json; signatures are read from policy.json.sigs (required)")
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	if fset.NArg() != 0 || len(pins) == 0 || *threshold == 0 || *bundlePath == "" || *policyPath == "" {
		_, _ = fmt.Fprintln(stderr, "trust verify: --pin, --threshold, --bundle and --policy are required")
		return errUsage
	}
	var files [4][]byte
	for i, path := range []string{*bundlePath, *bundlePath + sigsSuffix, *policyPath, *policyPath + sigsSuffix} {
		data, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
		if err != nil {
			return err
		}
		files[i] = data
	}
	bundle, bundleSigs, policy, policySigs := files[0], files[1], files[2], files[3]
	b, p, err := trust.VerifyGenesisBundle(bundle, bundleSigs, policy, policySigs, pins, *threshold)
	if err != nil {
		return err
	}

	pinned := map[string]ssh.PublicKey{}
	for _, r := range b.Root.Keys {
		pub, err := trust.ParseKey(r.Key)
		if err != nil {
			return err
		}
		pinned[ssh.FingerprintSHA256(pub)] = pub
	}
	bundleSigners, err := trust.CountPinnedSigners(bundle, bundleSigs, trust.NamespaceBundle, pinned)
	if err != nil {
		return err
	}
	policySigners, err := trust.CountPinnedSigners(policy, policySigs, trust.NamespacePolicy, pinned)
	if err != nil {
		return err
	}
	_, _ = io.WriteString(stdout, rootceremony.Summary(b, p))
	// Each document met the threshold on its own, and the roots behind the
	// two counts may differ: report who signed what, not one merged count.
	both := 0
	for _, fp := range bundleSigners {
		if slices.Contains(policySigners, fp) {
			both++
			_, _ = fmt.Fprintf(stdout, "signed by root %s\n", fp)
		} else {
			_, _ = fmt.Fprintf(stdout, "root %s signed the bundle only\n", fp)
		}
	}
	for _, fp := range policySigners {
		if !slices.Contains(bundleSigners, fp) {
			_, _ = fmt.Fprintf(stdout, "root %s signed the policy only\n", fp)
		}
	}
	reportUnpinned(stdout, bundleSigs, pinned, "bundle")
	reportUnpinned(stdout, policySigs, pinned, "policy")
	_, _ = fmt.Fprintf(stdout, "OK: %d of %d pinned roots signed both documents (bundle %d, policy %d, threshold %d)\n",
		both, len(pinned), len(bundleSigners), len(policySigners), *threshold)
	return nil
}

// reportUnpinned lists signatures by keys that are not pinned roots; they
// were ignored by the verification.
func reportUnpinned(w io.Writer, sigs []byte, pinned map[string]ssh.PublicKey, what string) {
	parsed, err := sshsig.ParseAll(sigs)
	if err != nil {
		return
	}
	for _, s := range parsed {
		fp := ssh.FingerprintSHA256(s.PublicKey())
		if _, ok := pinned[fp]; !ok {
			_, _ = fmt.Fprintf(w, "ignored: %s signature by non-pinned key %s\n", what, fp)
		}
	}
}
