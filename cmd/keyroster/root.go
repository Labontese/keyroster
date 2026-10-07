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
	caPath := fset.String("ca-pubkeys", "", "ca-pubkeys.json from the CA host (required)")
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
	if fset.NArg() != 0 || *caPath == "" || *policyPath == "" || *rootsPath == "" || *threshold == 0 || *outDir == "" {
		_, _ = fmt.Fprintln(stderr, "root sign: --ca-pubkeys, --policy, --roots, --threshold, --out-dir and one of --agent-key or --key are required")
		return errUsage
	}
	if (*agentKey == "") == (*keyPath == "") {
		_, _ = fmt.Fprintln(stderr, "root sign: give exactly one of --agent-key and --key")
		return errUsage
	}
	if *passFD >= 0 && *keyPath == "" {
		_, _ = fmt.Fprintln(stderr, "root sign: --passphrase-fd needs --key")
		return errUsage
	}

	cas, err := readParsed(*caPath, trust.ParseCAPubKeys)
	if err != nil {
		return err
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
	// A root never authorizes issuance (KEY-07). Checked before
	// prepareBundle, so a refused pair leaves nothing in --out-dir.
	if err := trust.CheckAdminsNotRoots(pol, roots); err != nil {
		return fmt.Errorf("%s: %w; nothing was written or signed", *policyPath, err)
	}

	bundle, b, err := prepareBundle(*outDir, cas, roots, uint32(*threshold), policy) //nolint:gosec // G115: <= len(roots)
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
	rootPub, custody, err := rootByFingerprint(b, fp)
	if err != nil {
		return err
	}
	if softRoot != nil && custody != "software" {
		return fmt.Errorf("--key holds root %s in software, but %s declares custody=%s; refusing to sign under a false custody label", fp, *rootsPath, custody)
	}
	bundleSigsPath := filepath.Join(*outDir, bundleFile+sigsSuffix)
	policySigsPath := filepath.Join(*outDir, policyFile+sigsSuffix)
	for _, f := range []struct {
		path, ns string
		doc      []byte
	}{{bundleSigsPath, trust.NamespaceBundle, bundle}, {policySigsPath, trust.NamespacePolicy, policy}} {
		if err := refuseIfSigned(f.path, f.ns, f.doc, rootPub); err != nil {
			return err
		}
	}

	hash := rootceremony.BundleHash(bundle)
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
	bundleSig, err := signer.SignBundle(rand.Reader, bundle)
	if err != nil {
		return err
	}
	policySig, err := signer.SignPolicy(rand.Reader, policy)
	if err != nil {
		return err
	}
	if err := appendFile(bundleSigsPath, bundleSig); err != nil {
		return err
	}
	if err := appendFile(policySigsPath, policySig); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "signed %s and %s with %s\n", filepath.Join(*outDir, bundleFile), filepath.Join(*outDir, policyFile), fp)
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

// prepareBundle builds the genesis bundle for the inputs and writes it and a
// copy of the policy into dir, or, when dir already holds a bundle (a
// further root signing), requires that bundle and policy to match the
// inputs exactly.
func prepareBundle(dir string, cas *trust.CAPubKeys, roots []trust.RootKey, threshold uint32, policy []byte) ([]byte, *trust.Bundle, error) {
	bundlePath := filepath.Join(dir, bundleFile)
	policyPath := filepath.Join(dir, policyFile)
	existing, err := os.ReadFile(bundlePath) //nolint:gosec // G304: inside the operator's out-dir
	switch {
	case err == nil:
		b, err := trust.ParseBundle(existing)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", bundlePath, err)
		}
		want, err := buildBundle(cas, roots, threshold, policy, b.IssuedAt)
		if err != nil {
			return nil, nil, err
		}
		wantData, err := want.Canonical()
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(wantData, existing) {
			return nil, nil, fmt.Errorf("%s does not match --ca-pubkeys, --roots, --threshold and --policy; refusing to sign a different bundle", bundlePath)
		}
		pol, err := os.ReadFile(policyPath) //nolint:gosec // G304: inside the operator's out-dir
		if err != nil || !bytes.Equal(pol, policy) {
			return nil, nil, fmt.Errorf("%s is missing or differs from --policy", policyPath)
		}
		return existing, b, nil
	case errors.Is(err, fs.ErrNotExist):
		issued := ceremonyNow().UTC().Truncate(time.Second).Format(trust.TimeFormat)
		b, err := buildBundle(cas, roots, threshold, policy, issued)
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

// rootByFingerprint returns the bundle root key with fingerprint fp and its
// declared custody.
func rootByFingerprint(b *trust.Bundle, fp string) (ssh.PublicKey, string, error) {
	for _, r := range b.Root.Keys {
		pub, err := trust.ParseKey(r.Key)
		if err == nil && ssh.FingerprintSHA256(pub) == fp {
			return pub, r.Custody, nil
		}
	}
	return nil, "", fmt.Errorf("signing root %s is not one of the bundle's root keys", fp)
}

// refuseIfSigned fails when the sigs file already holds a valid signature by
// pub over doc.
func refuseIfSigned(path, namespace string, doc []byte, pub ssh.PublicKey) error {
	data, err := os.ReadFile(path) //nolint:gosec // G304: inside the operator's out-dir
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	sigs, err := sshsig.ParseAll(data)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	for _, s := range sigs {
		if bytes.Equal(s.PublicKey().Marshal(), pub.Marshal()) && s.Verify(namespace, doc) == nil {
			return fmt.Errorf("%s already holds a signature by %s", path, ssh.FingerprintSHA256(pub))
		}
	}
	return nil
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
	return f.Close()
}

// appendFile appends data to path, creating it if needed.
func appendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644) //nolint:gosec // G302,G304: signatures are public; inside the operator's out-dir
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
