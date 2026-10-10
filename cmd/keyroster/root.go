package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/rootceremony"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "root",
		Summary: "offline root ceremony (init, genesis-policy, sign)",
		Run:     runRoot,
	})
}

// Hooks replaced by tests: the ssh-agent connection, the operator's
// confirmation input and the clock.
var (
	dialAgent = func() (net.Conn, error) {
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, errors.New("ssh-agent: SSH_AUTH_SOCK is not set; start ssh-agent and load the root key")
		}
		conn, err := net.Dial("unix", sock)
		if err != nil {
			return nil, fmt.Errorf("connect to ssh-agent: %w", err)
		}
		return conn, nil
	}
	ceremonyInput io.Reader = os.Stdin
	ceremonyNow             = time.Now
)

const (
	bundleFile = "bundle.json"
	policyFile = "policy.json"
	sigsSuffix = ".sigs"
)

func runRoot(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: keyroster root init|genesis-policy|sign [flags]")
		return errUsage
	}
	switch args[0] {
	case "init":
		return runRootInit(ctx, args[1:], stdout, stderr)
	case "genesis-policy":
		return runRootGenesisPolicy(ctx, args[1:], stdout, stderr)
	case "sign":
		return runRootSign(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "keyroster root: unknown subcommand %q\n", args[0])
		return errUsage
	}
}

// softwareRootBanner is printed whenever a software-held root is created or
// signs (D-10, D-11): it must never pass for hardware custody.
const softwareRootBanner = `SOFTWARE ROOT: this root key is held in software, in an age-encrypted
file protected only by its passphrase. It is weaker than a FIDO2 or PIV
hardware root: anyone who copies the file and learns the passphrase can sign
trust bundles. Keep the file on offline media, never on a networked machine,
and run the ceremony as described in docs/runbooks/root-ceremony.md.
`

// runRootInit creates an age-encrypted software root (D-10): FILE.age
// (mode 0600, created exclusively) and FILE.age.pub with custody=software.
func runRootInit(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("root init", flag.ContinueOnError)
	fset.SetOutput(stderr)
	out := fset.String("out", "", "encrypted root key file FILE.age; FILE.age and FILE.age.pub must not exist (required)")
	passFD := fset.Int("passphrase-fd", -1, "read the passphrase from this inherited file descriptor instead of the terminal")
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	if fset.NArg() != 0 || *out == "" {
		_, _ = fmt.Fprintln(stderr, "root init: --out is required")
		return errUsage
	}
	pubPath := *out + ".pub"
	for _, p := range []string{*out, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return fmt.Errorf("%s already exists; refusing to overwrite a root key", p)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	pass, err := rootceremony.ReadPassphrase(*passFD, "Passphrase for the new root key: ", true)
	if err != nil {
		return err
	}
	defer clear(pass)
	if err := rootceremony.ValidatePassphrase(pass); err != nil {
		return err
	}
	encrypted, pub, err := rootceremony.GenerateRoot(rand.Reader, pass)
	if err != nil {
		return err
	}
	if err := writeExclusive(*out, encrypted, 0o600); err != nil {
		return err
	}
	if err := writeExclusive(pubPath, []byte(trust.FormatKey(pub)+" custody=software\n"), 0o644); err != nil {
		// Nobody has seen this key yet; do not leave it without its label.
		_ = os.Remove(*out)
		return err
	}
	_, _ = io.WriteString(stderr, softwareRootBanner)
	_, _ = fmt.Fprintf(stderr, "root key: %s\npublic key: %s\n", *out, pubPath)
	_, _ = fmt.Fprintln(stdout, ssh.FingerprintSHA256(pub))
	return nil
}

func runRootGenesisPolicy(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("root genesis-policy", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var admins stringList
	fset.Var(&admins, "admin", "NAME=FILE.pub: an admin whose SSHSIG may authorize issuance (repeatable, at least one)")
	quorum := fset.Uint("admin-quorum", 1, "number of admin signatures an authorization needs")
	userTTL := fset.Duration("user-max-ttl", 12*time.Hour, "maximum user certificate validity")
	hostTTL := fset.Duration("host-max-ttl", 720*time.Hour, "maximum host certificate validity")
	machineTTL := fset.Duration("machine-max-ttl", 24*time.Hour, "maximum machine certificate validity")
	out := fset.String("out", "", "policy output file; must not exist (required)")
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	if fset.NArg() != 0 || len(admins) == 0 || *out == "" {
		_, _ = fmt.Fprintln(stderr, "root genesis-policy: --out and at least one --admin NAME=FILE.pub are required")
		return errUsage
	}
	if *quorum > math.MaxUint32 {
		return errors.New("--admin-quorum is too large")
	}
	p := &trust.Policy{
		Version:     1,
		Prev:        trust.GenesisPrev,
		AdminQuorum: uint32(*quorum), //nolint:gosec // G115: bounded above
		Admins:      make([]trust.AdminKey, 0, len(admins)),
	}
	for _, a := range admins {
		name, file, ok := strings.Cut(a, "=")
		if !ok || name == "" || file == "" {
			return fmt.Errorf("--admin %q: want NAME=FILE.pub", a)
		}
		pub, err := readPublicKey(file)
		if err != nil {
			return err
		}
		p.Admins = append(p.Admins, trust.AdminKey{Name: name, Key: trust.FormatKey(pub)})
	}
	ttls := map[string]*time.Duration{trust.RoleUser: userTTL, trust.RoleHost: hostTTL, trust.RoleMachine: machineTTL}
	for _, role := range []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine} {
		d := *ttls[role]
		if d <= 0 || d%time.Second != 0 {
			return fmt.Errorf("--%s-max-ttl must be a positive whole number of seconds", role)
		}
		prof := trust.CAProfile{
			Role:                   role,
			MaxTTLSeconds:          uint64(d / time.Second),
			DefaultExtensions:      []string{},
			AllowedExtensions:      []string{},
			AllowedCriticalOptions: []string{},
		}
		if role != trust.RoleHost {
			prof.DefaultExtensions = []string{"permit-pty"}
		}
		p.CAProfiles = append(p.CAProfiles, prof)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	data, err := p.Canonical()
	if err != nil {
		return err
	}
	if err := writeNew(*out, data); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "policy: %s\nsha256: %s\n", *out, trust.SHA256Hex(data))
	return nil
}

func runRootSign(_ context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("root sign", flag.ContinueOnError)
	fset.SetOutput(stderr)
	caPath := fset.String("ca-pubkeys", "", "ca-pubkeys.json from the CA host (required for a genesis bundle; refused with --prev)")
	prevDir := fset.String("prev", "", "directory holding the bundle.json and policy.json in force and their .sigs files; builds their successor (version+1) instead of a genesis bundle, which needs signatures by the previous roots' threshold AND the new roots' threshold")
	prevSHA := fset.String("prev-sha256", "", prevSHA256Usage)
	policyPath := fset.String("policy", "", "canonical policy file (required)")
	rootsPath := fset.String("roots", "", "roots.pub: one root key per line with comment custody=<value> (required)")
	threshold := fset.Int("threshold", 0, "number of root signatures a verifier requires (required)")
	outDir := fset.String("out-dir", "", "directory for bundle.json, policy.json and their .sigs files (required)")
	agentKey := fset.String("agent-key", "", "SHA256 fingerprint of the root key in ssh-agent that signs (this or --key)")
	keyPath := fset.String("key", "", "age-encrypted software root FILE.age that signs (this or --agent-key)")
	passFD := fset.Int("passphrase-fd", -1, "with --key: read the passphrase from this inherited file descriptor instead of the terminal")
	confirm := fset.String("confirm", "", "first 8 hex digits of the bundle hash (default: prompt on stdin)")
	if err := fset.Parse(args); err != nil {
		return errUsage
	}
	successor := *prevDir != ""
	if successor && *caPath != "" {
		_, _ = fmt.Fprintln(stderr, "root sign: --ca-pubkeys is refused with --prev: a successor carries the CA, ops and log keys of the previous bundle unchanged (CA rotation is Phase 3)")
		return errUsage
	}
	if fset.NArg() != 0 || (!successor && *caPath == "") || *policyPath == "" || *rootsPath == "" || *threshold == 0 || *outDir == "" {
		if successor {
			_, _ = fmt.Fprintln(stderr, "root sign: with --prev, --prev-sha256, --policy, --roots, --threshold, --out-dir and one of --agent-key or --key are required")
		} else {
			_, _ = fmt.Fprintln(stderr, "root sign: --ca-pubkeys, --policy, --roots, --threshold, --out-dir and one of --agent-key or --key are required")
		}
		return errUsage
	}
	if err := checkPrevFlags(stderr, "root sign", *prevDir, *prevSHA); err != nil {
		return err
	}
	if (*agentKey == "") == (*keyPath == "") {
		_, _ = fmt.Fprintln(stderr, "root sign: give exactly one of --agent-key and --key")
		return errUsage
	}
	if *passFD >= 0 && *keyPath == "" {
		_, _ = fmt.Fprintln(stderr, "root sign: --passphrase-fd needs --key")
		return errUsage
	}

	policy, err := os.ReadFile(*policyPath) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return err
	}
	pol, err := trust.ParsePolicy(policy)
	if err != nil {
		return fmt.Errorf("%s: %w", *policyPath, err)
	}
	rootsData, err := os.ReadFile(*rootsPath) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return err
	}
	roots, err := trust.ParseRootsFile(rootsData)
	if err != nil {
		return fmt.Errorf("%s: %w", *rootsPath, err)
	}
	if *threshold < 1 || *threshold > len(roots) {
		return fmt.Errorf("--threshold %d with %d roots", *threshold, len(roots))
	}
	thr := uint32(*threshold) //nolint:gosec // G115: <= len(roots)

	// Genesis mode builds from --ca-pubkeys. Successor mode builds from the
	// bundle and policy in force in --prev and never takes a CA key.
	var (
		prev       *trust.Bundle
		prevBundle []byte
		build      func(issuedAt string) (*trust.Bundle, error)
		inputs     = "--ca-pubkeys, --roots, --threshold and --policy"
		rootSets   = [][]trust.RootKey{roots}
	)
	if successor {
		prev, prevBundle, build, err = successorBuilder(*prevDir, *prevSHA, *outDir, roots, thr, policy)
		if err != nil {
			return err
		}
		inputs = "--prev, --roots, --threshold and --policy"
		rootSets = append(rootSets, prev.Root.Keys)
	} else {
		cas, err := readParsed(*caPath, trust.ParseCAPubKeys)
		if err != nil {
			return err
		}
		build = func(issuedAt string) (*trust.Bundle, error) {
			return buildBundle(cas, roots, thr, policy, issuedAt)
		}
	}
	// A root never authorizes issuance (KEY-07), and a root that a
	// successor retires may still exist. Checked before prepareBundle, so a
	// refused pair leaves nothing in --out-dir.
	if err := trust.CheckAdminsNotRoots(pol, rootSets...); err != nil {
		return fmt.Errorf("%s: %w; nothing was written or signed", *policyPath, err)
	}

	bundle, b, err := prepareBundle(*outDir, build, inputs, policy)
	if err != nil {
		return err
	}

	// Resolve the signing root. A software root is decrypted first: its
	// fingerprint is known only after decryption.
	var softRoot *rootceremony.Root
	fp := *agentKey
	if *keyPath != "" {
		softRoot, err = openSoftwareRoot(*keyPath, *passFD)
		if err != nil {
			return err
		}
		defer softRoot.Close()
		fp = ssh.FingerprintSHA256(softRoot.PublicKey())
	}
	rootPub, custody, fromPrev, err := rootByFingerprint(b, prev, fp)
	if err != nil {
		return err
	}
	if softRoot != nil && custody != "software" {
		source := *rootsPath
		if fromPrev {
			source = filepath.Join(*prevDir, bundleFile)
		}
		return fmt.Errorf("--key holds root %s in software, but %s declares custody=%s; refusing to sign under a false custody label", fp, source, custody)
	}
	// A rerun after a partial failure (the bundle signature written, the
	// policy signature not) signs only the document this root has not
	// signed yet; it is refused only when both already carry its signature.
	type sigDoc struct {
		path, ns string
		doc      []byte
	}
	all := []sigDoc{
		{filepath.Join(*outDir, bundleFile+sigsSuffix), trust.NamespaceBundle, bundle},
		{filepath.Join(*outDir, policyFile+sigsSuffix), trust.NamespacePolicy, policy},
	}
	var todo []sigDoc
	for _, d := range all {
		signed, err := hasSignature(d.path, d.ns, d.doc, rootPub)
		if err != nil {
			return err
		}
		if signed {
			_, _ = fmt.Fprintf(stdout, "%s already holds a signature by %s; not signing it again\n", d.path, fp)
			continue
		}
		todo = append(todo, d)
	}
	if len(todo) == 0 {
		return fmt.Errorf("%s already holds a signature by %s, and so does %s; nothing to sign", all[0].path, fp, all[1].path)
	}

	hash := rootceremony.BundleHash(bundle)
	if prev != nil {
		_, _ = io.WriteString(stdout, successorHeader(prev, prevBundle, b))
	}
	_, _ = io.WriteString(stdout, rootceremony.Summary(b, pol))
	answer := *confirm
	if answer == "" {
		_, _ = fmt.Fprintf(stderr, "Type the first 8 hex digits of the bundle SHA-256 to sign with %s: ", fp)
		line, err := bufio.NewReader(ceremonyInput).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("no confirmation read: %w", err)
		}
		answer = strings.TrimSpace(line)
	}
	if !strings.EqualFold(answer, hash[:8]) {
		return fmt.Errorf("confirmation %q does not match the bundle hash prefix %s; nothing was signed", answer, hash[:8])
	}

	var signer documentSigner = softRoot
	if softRoot == nil {
		s, closeAgent, err := agentSigner(rootPub)
		if err != nil {
			return err
		}
		defer closeAgent()
		signer = agentRoot{s}
	}
	if custody == "software" {
		_, _ = io.WriteString(stderr, softwareRootBanner)
	}
	// Sign everything first, so a failed signature (a FIDO touch timing
	// out) writes nothing.
	sigs := make([][]byte, len(todo))
	for i, d := range todo {
		sign := signer.SignBundle
		if d.ns == trust.NamespacePolicy {
			sign = signer.SignPolicy
		}
		if sigs[i], err = sign(rand.Reader, d.doc); err != nil {
			return err
		}
	}
	for i, d := range todo {
		if err := appendSignature(d.path, sigs[i]); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "signed %s with %s\n", strings.TrimSuffix(d.path, sigsSuffix), fp)
	}
	return nil
}

// documentSigner is a root that signs exactly the two root-signed document
// types: a *rootceremony.Root or an ssh-agent root.
type documentSigner interface {
	SignBundle(rnd io.Reader, bundleJSON []byte) ([]byte, error)
	SignPolicy(rnd io.Reader, policyJSON []byte) ([]byte, error)
}

// agentRoot signs through rootceremony with a root key held in ssh-agent.
type agentRoot struct{ s ssh.Signer }

func (a agentRoot) SignBundle(rnd io.Reader, bundleJSON []byte) ([]byte, error) {
	return rootceremony.SignBundle(rnd, a.s, bundleJSON)
}

func (a agentRoot) SignPolicy(rnd io.Reader, policyJSON []byte) ([]byte, error) {
	return rootceremony.SignPolicy(rnd, a.s, policyJSON)
}

// openSoftwareRoot reads the passphrase (terminal or inherited descriptor)
// and decrypts the root key file in memory.
func openSoftwareRoot(path string, passFD int) (*rootceremony.Root, error) {
	encrypted, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the key file
	if err != nil {
		return nil, err
	}
	pass, err := rootceremony.ReadPassphrase(passFD, "Passphrase for "+path+": ", false)
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	root, err := rootceremony.OpenRoot(encrypted, pass)
	if err != nil {
		return nil, fmt.Errorf("%s: %w; nothing was signed", path, err)
	}
	return root, nil
}

// prepareBundle builds the bundle for the inputs with build and writes it
// and a copy of the policy into dir, or, when dir already holds a bundle (a
// further root signing), rebuilds it with the stored issued_at and requires
// that bundle and policy to match exactly. inputs names the flags the
// bundle is built from, for the mismatch error.
func prepareBundle(dir string, build func(issuedAt string) (*trust.Bundle, error), inputs string, policy []byte) ([]byte, *trust.Bundle, error) {
	bundlePath := filepath.Join(dir, bundleFile)
	policyPath := filepath.Join(dir, policyFile)
	existing, err := os.ReadFile(bundlePath) //nolint:gosec // G304: inside the operator's out-dir
	switch {
	case err == nil:
		b, err := trust.ParseBundle(existing)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", bundlePath, err)
		}
		want, err := build(b.IssuedAt)
		if err != nil {
			return nil, nil, err
		}
		wantData, err := want.Canonical()
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(wantData, existing) {
			return nil, nil, fmt.Errorf("%s does not match %s; refusing to sign a different bundle", bundlePath, inputs)
		}
		pol, err := os.ReadFile(policyPath) //nolint:gosec // G304: inside the operator's out-dir
		if err != nil || !bytes.Equal(pol, policy) {
			return nil, nil, fmt.Errorf("%s is missing or differs from --policy", policyPath)
		}
		return existing, b, nil
	case errors.Is(err, fs.ErrNotExist):
		issued := ceremonyNow().UTC().Truncate(time.Second).Format(trust.TimeFormat)
		b, err := build(issued)
		if err != nil {
			return nil, nil, err
		}
		data, err := b.Canonical()
		if err != nil {
			return nil, nil, err
		}
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: signed documents are public
			return nil, nil, err
		}
		if pol, err := os.ReadFile(policyPath); err == nil { //nolint:gosec // G304: inside the operator's out-dir
			if !bytes.Equal(pol, policy) {
				return nil, nil, fmt.Errorf("%s exists and differs from --policy", policyPath)
			}
		} else if err := writeNew(policyPath, policy); err != nil {
			return nil, nil, err
		}
		if err := writeNew(bundlePath, data); err != nil {
			return nil, nil, err
		}
		return data, b, nil
	default:
		return nil, nil, err
	}
}

// buildBundle assembles a genesis bundle: version 1, all-zero prev, the
// roots and threshold, the three CAs active at generation 1, the ops and
// log keys and the policy hash. It validates the result.
func buildBundle(cas *trust.CAPubKeys, roots []trust.RootKey, threshold uint32, policy []byte, issuedAt string) (*trust.Bundle, error) {
	b := &trust.Bundle{
		Version:      1,
		Prev:         trust.GenesisPrev,
		IssuedAt:     issuedAt,
		Root:         trust.RootSet{Keys: roots, Threshold: threshold},
		CAs:          []trust.CAEntry{},
		PolicySHA256: trust.SHA256Hex(policy),
	}
	for _, role := range []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine} {
		k, _ := cas.Key(role)
		b.CAs = append(b.CAs, trust.CAEntry{Role: role, Key: k.Key, Alg: k.Alg, Custody: k.Custody, State: "active", Generation: 1})
	}
	ops, _ := cas.Key("ops")
	b.OpsKey = trust.KeyEntry{Key: ops.Key, Alg: ops.Alg, Custody: ops.Custody}
	lg, _ := cas.Key("log")
	logPub, err := trust.ParseKey(lg.Key)
	if err != nil {
		return nil, fmt.Errorf("log key: %w", err)
	}
	b.Log = trust.LogEntry{Key: lg.Key, Alg: lg.Alg, Custody: lg.Custody, Origin: trust.LogOrigin(logPub)}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// successorBuilder reads and authenticates the bundle and policy in force
// from prevDir (loadPrev: the recorded SHA-256 prevSHA and its own roots'
// signatures) and returns the previous bundle, its bytes and the builder of
// its successor (trust.BuildSuccessor). outDir must not be prevDir: the
// successor never overwrites the documents it chains to. Every refusal
// comes before anything is written.
func successorBuilder(prevDir, prevSHA, outDir string, roots []trust.RootKey, threshold uint32, policy []byte) (*trust.Bundle, []byte, func(string) (*trust.Bundle, error), error) {
	absPrev, err := filepath.Abs(prevDir)
	if err != nil {
		return nil, nil, nil, err
	}
	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return nil, nil, nil, err
	}
	if absPrev == absOut {
		return nil, nil, nil, fmt.Errorf("--out-dir %s is the --prev directory; write the successor to a new directory; nothing was written or signed", outDir)
	}
	prev, prevBundle, prevPolicy, err := loadPrev(prevDir, prevSHA)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w; nothing was written or signed", err)
	}
	build := func(issuedAt string) (*trust.Bundle, error) {
		return trust.BuildSuccessor(prev, prevBundle, prevPolicy, roots, threshold, policy, issuedAt)
	}
	return prev, prevBundle, build, nil
}

// successorHeader describes the bundle a successor chains to, before the
// successor's own summary: the previous version and SHA-256, the previous
// roots, and the signatures the successor needs.
func successorHeader(prev *trust.Bundle, prevBundle []byte, next *trust.Bundle) string {
	var w strings.Builder
	fmt.Fprintf(&w, "Successor of trust bundle v%d, sha256 %s\n", prev.Version, trust.SHA256Hex(prevBundle))
	fmt.Fprintf(&w, "Previous root keys (threshold %d of %d):\n", prev.Root.Threshold, len(prev.Root.Keys))
	for _, r := range prev.Root.Keys {
		// ParseBundle validated every root key.
		pub, _ := trust.ParseKey(r.Key)
		fmt.Fprintf(&w, "  %s  %-34s custody=%s\n", ssh.FingerprintSHA256(pub), pub.Type(), r.Custody)
	}
	fmt.Fprintf(&w, "signatures needed: %d of the %d previous roots AND %d of the %d new roots, on both documents\n",
		prev.Root.Threshold, len(prev.Root.Keys), next.Root.Threshold, len(next.Root.Keys))
	return w.String()
}

// rootByFingerprint returns the root key with fingerprint fp and its
// declared custody, from the bundle's root set or, for a successor, from
// the previous bundle's (prev; nil for a genesis bundle). fromPrev reports
// that the key and its custody label come from prev.
func rootByFingerprint(b, prev *trust.Bundle, fp string) (pub ssh.PublicKey, custody string, fromPrev bool, err error) {
	sets := []*trust.Bundle{b}
	if prev != nil {
		sets = append(sets, prev)
	}
	for i, set := range sets {
		for _, r := range set.Root.Keys {
			k, perr := trust.ParseKey(r.Key)
			if perr == nil && ssh.FingerprintSHA256(k) == fp {
				return k, r.Custody, i == 1, nil
			}
		}
	}
	if prev != nil {
		return nil, "", false, fmt.Errorf("signing root %s is not one of the new root keys nor one of the previous bundle's (v%d) root keys", fp, prev.Version)
	}
	return nil, "", false, fmt.Errorf("signing root %s is not one of the bundle's root keys", fp)
}

// hasSignature reports whether the sigs file holds a valid signature by pub
// over doc under namespace. A missing file holds none; a file that does not
// parse is an error.
func hasSignature(path, namespace string, doc []byte, pub ssh.PublicKey) (bool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: inside the operator's out-dir
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	sigs, err := sshsig.ParseAll(data)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	for _, s := range sigs {
		if bytes.Equal(s.PublicKey().Marshal(), pub.Marshal()) && s.Verify(namespace, doc) == nil {
			return true, nil
		}
	}
	return false, nil
}

// agentSigner returns the ssh-agent signer for pub.
func agentSigner(pub ssh.PublicKey) (ssh.Signer, func(), error) {
	conn, err := dialAgent()
	if err != nil {
		return nil, nil, err
	}
	signers, err := agent.NewClient(conn).Signers()
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("list ssh-agent keys: %w", err)
	}
	for _, s := range signers {
		if bytes.Equal(s.PublicKey().Marshal(), pub.Marshal()) {
			return s, func() { _ = conn.Close() }, nil
		}
	}
	_ = conn.Close()
	return nil, nil, fmt.Errorf("ssh-agent does not hold the root key %s", ssh.FingerprintSHA256(pub))
}

// readParsed reads path and parses it with parse.
func readParsed[T any](path string, parse func([]byte) (T, error)) (T, error) {
	var zero T
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return zero, err
	}
	v, err := parse(data)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", path, err)
	}
	return v, nil
}

// writeNew creates path with data and fails if it already exists, so a
// ceremony never overwrites a document that may already carry signatures.
func writeNew(path string, data []byte) error {
	return writeExclusive(path, data, 0o644)
}

// writeExclusive creates path with mode perm (O_EXCL: never an existing
// file) and writes data to it.
func writeExclusive(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // G304: the operator names the path
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	// The root key goes to removable media and is the only copy: flush it
	// before success is reported and its public key is distributed.
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// appendSignature appends the SSHSIG block sig to the signature file path,
// creating it if needed. sshsig.ParseAll accepts a last block without its
// newline (a hand-assembled file, an editor that strips it), so a missing
// newline is added first: a block written straight after "-----END SSH
// SIGNATURE-----" would make the whole file, and every signature already
// in it, unparseable. The result must still parse, or the file is left
// unchanged; it is written with replaceFile, so a failed write cannot
// truncate the signatures already in it.
func appendSignature(path string, sig []byte) error {
	data, err := os.ReadFile(path) //nolint:gosec // G304: inside the operator's out-dir
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, sig...)
	if _, err := sshsig.ParseAll(data); err != nil {
		return fmt.Errorf("%s would not parse with the new signature appended, so it was left unchanged: %w", path, err)
	}
	return replaceFile(path, data, 0o644)
}

// replaceFile writes data to path atomically: to a temporary file in the
// same directory, synced to disk, then renamed over path. A failure part way
// leaves path as it was, never a truncated signature block.
//
// UNVERIFIED: the failure paths (disk full, media pulled mid-write) and
// durability across power loss are not exercised by tests; the parent
// directory is not fsynced, so the rename itself may still be lost if the
// media is pulled without unmounting.
func replaceFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	err = f.Chmod(perm)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
