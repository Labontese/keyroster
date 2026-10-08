package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
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
	prevDir := fset.String("prev", "", "directory holding the bundle.json and policy.json in force; verifies --bundle as its successor, and --pin/--threshold name the successor's NEW root set")
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
	if *prevDir != "" {
		return verifySuccessorBundle(stdout, *prevDir, bundle, bundleSigs, policy, policySigs, pins, *threshold)
	}
	b, p, err := trust.VerifyGenesisBundle(bundle, bundleSigs, policy, policySigs, pins, *threshold)
	if err != nil {
		return err
	}

	pinned, err := rootKeyMap(b)
	if err != nil {
		return err
	}
	_, _ = io.WriteString(stdout, rootceremony.Summary(b, p))
	both, nBundle, nPolicy, err := reportSigners(stdout, "root", bundle, bundleSigs, policy, policySigs, pinned)
	if err != nil {
		return err
	}
	reportUnpinned(stdout, bundleSigs, pinned, "bundle")
	reportUnpinned(stdout, policySigs, pinned, "policy")
	_, _ = fmt.Fprintf(stdout, "OK: %d of %d pinned roots signed both documents (bundle %d, policy %d, threshold %d)\n",
		both, len(pinned), nBundle, nPolicy, *threshold)
	return nil
}

// verifySuccessorBundle is trust verify --prev: it verifies the successor
// bundle and policy against the bundle and policy in force in prevDir
// (trust.VerifySuccessor: version, prev hash, policy chain, and the
// threshold of the previous roots AND of the new roots on both documents),
// then requires the successor's root set to be exactly the pins at exactly
// threshold (trust.MatchPins), so the new roots are checked against their
// out-of-band fingerprints before the successor is installed.
func verifySuccessorBundle(stdout io.Writer, prevDir string, bundle, bundleSigs, policy, policySigs []byte, pins []string, threshold int) error {
	prevBundle, err := os.ReadFile(filepath.Join(prevDir, "bundle.json")) //nolint:gosec // G304: the operator names the directory
	if err != nil {
		return err
	}
	prevPolicy, err := os.ReadFile(filepath.Join(prevDir, "policy.json")) //nolint:gosec // G304: the operator names the directory
	if err != nil {
		return err
	}
	prev, err := trust.ParseBundle(prevBundle)
	if err != nil {
		return fmt.Errorf("--prev %s: %w", filepath.Join(prevDir, "bundle.json"), err)
	}
	next, p, err := trust.VerifySuccessor(prev, prevBundle, prevPolicy, bundle, bundleSigs, policy, policySigs)
	if err != nil {
		return fmt.Errorf("not a valid successor of trust bundle v%d in %s: %w", prev.Version, prevDir, err)
	}
	if err := trust.MatchPins(next, pins, threshold); err != nil {
		return fmt.Errorf("the successor's new roots are not the pinned roots: %w", err)
	}

	prevRoots, err := rootKeyMap(prev)
	if err != nil {
		return err
	}
	newRoots, err := rootKeyMap(next)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "Successor of trust bundle v%d, sha256 %s\n", prev.Version, trust.SHA256Hex(prevBundle))
	_, _ = io.WriteString(stdout, rootceremony.Summary(next, p))
	prevBoth, _, _, err := reportSigners(stdout, "previous root", bundle, bundleSigs, policy, policySigs, prevRoots)
	if err != nil {
		return err
	}
	newBoth, _, _, err := reportSigners(stdout, "new root", bundle, bundleSigs, policy, policySigs, newRoots)
	if err != nil {
		return err
	}
	// A signature counts if it is by a key of either set; only keys in
	// neither set were ignored.
	either := maps.Clone(prevRoots)
	maps.Copy(either, newRoots)
	reportUnpinned(stdout, bundleSigs, either, "bundle")
	reportUnpinned(stdout, policySigs, either, "policy")
	_, _ = fmt.Fprintf(stdout, "OK: successor of trust bundle v%d: previous roots %d of %d signed both documents (threshold %d); new roots %d of %d signed both documents (threshold %d, pinned)\n",
		prev.Version, prevBoth, len(prevRoots), prev.Root.Threshold, newBoth, len(newRoots), next.Root.Threshold)
	return nil
}

// rootKeyMap returns b's root keys by SHA256 fingerprint.
func rootKeyMap(b *trust.Bundle) (map[string]ssh.PublicKey, error) {
	m := map[string]ssh.PublicKey{}
	for _, r := range b.Root.Keys {
		pub, err := trust.ParseKey(r.Key)
		if err != nil {
			return nil, err
		}
		m[ssh.FingerprintSHA256(pub)] = pub
	}
	return m, nil
}

// reportSigners prints, for the roots in keys, which signed both documents
// and which signed only one, each labelled with label ("root", "previous
// root", "new root"). Each document met its threshold on its own, and the
// roots behind the two counts may differ: it reports who signed what, not
// one merged count. It returns the number that signed both documents and
// the per-document counts.
func reportSigners(w io.Writer, label string, bundle, bundleSigs, policy, policySigs []byte, keys map[string]ssh.PublicKey) (both, nBundle, nPolicy int, err error) {
	bundleSigners, err := trust.CountPinnedSigners(bundle, bundleSigs, trust.NamespaceBundle, keys)
	if err != nil {
		return 0, 0, 0, err
	}
	policySigners, err := trust.CountPinnedSigners(policy, policySigs, trust.NamespacePolicy, keys)
	if err != nil {
		return 0, 0, 0, err
	}
	for _, fp := range bundleSigners {
		if slices.Contains(policySigners, fp) {
			both++
			_, _ = fmt.Fprintf(w, "signed by %s %s\n", label, fp)
		} else {
			_, _ = fmt.Fprintf(w, "%s %s signed the bundle only\n", label, fp)
		}
	}
	for _, fp := range policySigners {
		if !slices.Contains(bundleSigners, fp) {
			_, _ = fmt.Fprintf(w, "%s %s signed the policy only\n", label, fp)
		}
	}
	return both, len(bundleSigners), len(policySigners), nil
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
