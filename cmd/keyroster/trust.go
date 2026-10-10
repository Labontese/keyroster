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
	prevDir := fset.String("prev", "", "directory holding the bundle.json and policy.json in force and their .sigs files; verifies --bundle as its successor, and --pin/--threshold name the successor's NEW root set")
	prevSHA := fset.String("prev-sha256", "", prevSHA256Usage)
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	if fset.NArg() != 0 || len(pins) == 0 || *threshold == 0 || *bundlePath == "" || *policyPath == "" {
		_, _ = fmt.Fprintln(stderr, "trust verify: --pin, --threshold, --bundle and --policy are required")
		return errUsage
	}
	if err := checkPrevFlags(stderr, "trust verify", *prevDir, *prevSHA); err != nil {
		return err
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
		return verifySuccessorBundle(stdout, *prevDir, *prevSHA, bundle, bundleSigs, policy, policySigs, pins, *threshold)
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

// prevSHA256Usage is the --prev-sha256 flag help of root sign and trust
// verify.
const prevSHA256Usage = "with --prev (and required by it): the SHA-256 of the bundle.json in force, as recorded in the transcript when it was installed, 64 lowercase hex digits; never take it from the copy in --prev"

// checkPrevFlags checks that --prev and --prev-sha256 come together and
// that the SHA-256 is 64 lowercase hex digits; cmd names the command.
func checkPrevFlags(stderr io.Writer, cmd, prevDir, prevSHA string) error {
	if (prevDir == "") != (prevSHA == "") || (prevSHA != "" && !isSHA256Hex(prevSHA)) {
		_, _ = fmt.Fprintf(stderr, "%s: --prev needs --prev-sha256 with the SHA-256 of the bundle in force as recorded at its install (64 lowercase hex digits), and --prev-sha256 needs --prev\n", cmd)
		return errUsage
	}
	return nil
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// loadPrev reads the bundle and policy in force from dir, for root sign
// --prev and trust verify --prev, and authenticates them before anything
// is built, written or reported against them (G-CR-01). bundle.json must
// have exactly wantSHA, the SHA-256 recorded when it was installed: the new
// roots sign a successor over its prev hash, and audit verify pinned to the
// new roots authenticates every earlier bundle only through that hash, so a
// successor must never chain to a forged --prev. As defence in depth, the
// bundle's own root threshold must have signed bundle.json and policy.json
// (the .sigs files beside them; trust.VerifySelfSigned). That check cannot
// tell a forged root set from the real one; only the hash pin can.
func loadPrev(dir, wantSHA string) (prev *trust.Bundle, prevBundle, prevPolicy []byte, err error) {
	bundlePath := filepath.Join(dir, bundleFile)
	prevBundle, err = os.ReadFile(bundlePath) //nolint:gosec // G304: the operator names the directory
	if err != nil {
		return nil, nil, nil, err
	}
	if got := trust.SHA256Hex(prevBundle); got != wantSHA {
		return nil, nil, nil, fmt.Errorf("--prev %s has sha256 %s, not the recorded --prev-sha256 %s: it is not the bundle in force", bundlePath, got, wantSHA)
	}
	var files [3][]byte
	for i, name := range []string{bundleFile + sigsSuffix, policyFile, policyFile + sigsSuffix} {
		if files[i], err = os.ReadFile(filepath.Join(dir, name)); err != nil { //nolint:gosec // G304: the operator names the directory
			return nil, nil, nil, fmt.Errorf("--prev %s: %w", dir, err)
		}
	}
	prevPolicy = files[1]
	prev, err = trust.VerifySelfSigned(prevBundle, files[0], prevPolicy, files[2])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("--prev %s: %w", dir, err)
	}
	return prev, prevBundle, prevPolicy, nil
}

// verifySuccessorBundle is trust verify --prev: it authenticates the bundle
// and policy in force in prevDir (loadPrev: the recorded SHA-256 prevSHA and
// its own roots' signatures), verifies the successor bundle and policy
// against them (trust.VerifySuccessor: version, prev hash, policy chain,
// and the threshold of the previous roots AND of the new roots on both
// documents), then requires the successor's root set to be exactly the
// pins at exactly threshold (trust.MatchPins), so the new roots are checked
// against their out-of-band fingerprints before the successor is installed.
func verifySuccessorBundle(stdout io.Writer, prevDir, prevSHA string, bundle, bundleSigs, policy, policySigs []byte, pins []string, threshold int) error {
	prev, prevBundle, prevPolicy, err := loadPrev(prevDir, prevSHA)
	if err != nil {
		return err
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
