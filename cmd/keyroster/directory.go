package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

func init() {
	register(command{
		Name:    "directory",
		Summary: "the admin-signed directory (show: the version the server serves, its signatures verified; sign: co-sign a proposal; install: install a fully signed proposal)",
		Run:     runDirectory,
	})
}

func runDirectory(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "directory: want a subcommand: show, sign or install")
		return errUsage
	}
	switch args[0] {
	case "show":
		return runDirectoryShow(ctx, args[1:], stdout, stderr)
	case "sign":
		return runDirectorySign(ctx, args[1:], stdout, stderr)
	case "install":
		return runDirectoryInstall(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "directory: unknown subcommand %q; want show, sign or install\n", args[0])
		return errUsage
	}
}

// runDirectoryShow is keyroster directory show [--admin-key FP]: the
// directory the server serves, after the CLI verified its signatures
// against the admins of the root-verified policy, with its version,
// SHA-256 and signers, and every user, credential fingerprint, group, role
// and host group. That the signer has installed it is the server's word;
// the output says so, and only the signer's audit log proves it.
func runDirectoryShow(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("directory show", flag.ContinueOnError)
	fset.SetOutput(stderr)
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	if pos, err := parseInterspersed(fset, args); err != nil || len(pos) != 0 {
		return errUsage
	}
	s, err := openAdminSession(*adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	vd, err := fetchVerifiedDirectory(ctx, s)
	if err != nil {
		return err
	}
	if vd.Version == 0 {
		_, err := io.WriteString(stdout, "The server serves no directory.\n")
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "The admin-signed directory the server serves: version %d, signatures verified against the root-signed policy version %d\n", vd.Version, vd.Policy.Version)
	b.WriteString(serverServesNote)
	fmt.Fprintf(&b, "SHA-256  %s\n", vd.SHA256)
	fmt.Fprintf(&b, "Signed by %d of the policy's admins (quorum %d):\n", len(vd.Signers), vd.Policy.AdminQuorum)
	for _, fp := range vd.Signers {
		fmt.Fprintf(&b, "  %s %s\n", adminNameOf(vd.Policy, fp), fp)
	}
	b.WriteString("Contents:\n")
	for _, line := range directory.Diff(nil, vd.Dir) {
		b.WriteString("  " + strings.TrimPrefix(line, "+ ") + "\n")
	}
	_, err = io.WriteString(stdout, b.String())
	return err
}

// serverServesNote is what directory show and user list say about the
// directory they print: the admins signed it, but that the signer holds it
// is the server's word (residual until the CLI verifies a signer-signed
// install receipt, Phase 4).
const serverServesNote = "That the signer has installed this version is the server's word; " +
	"the signer's audit log is the proof (keyroster audit verify on an export from the signer host).\n"

// adminNameOf is the policy's name for the admin key with fingerprint fp.
func adminNameOf(pol *trust.Policy, fp string) string {
	for _, a := range pol.Admins {
		if pub, err := trust.ParseKey(a.Key); err == nil && ssh.FingerprintSHA256(pub) == fp {
			return a.Name
		}
	}
	return "(unknown)"
}

// proposal is a proposal directory as directory sign and install read it.
type proposal struct {
	dir       string
	doc, sigs []byte
	d         *directory.Directory
}

// loadProposal reads dir's directory.json and directory.json.sigs, within
// the signer's size caps, and parses the document. base.sha256 is never
// read: the prev check uses the document's own prev field.
func loadProposal(dir string) (*proposal, error) {
	read := func(name string, limit int) ([]byte, error) {
		p := filepath.Join(dir, name)
		f, err := os.Open(p) //nolint:gosec // G304: the admin names the proposal directory
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
		if err != nil {
			return nil, err
		}
		if len(data) > limit {
			return nil, fmt.Errorf("%s is larger than %d bytes", p, limit)
		}
		return data, nil
	}
	doc, err := read(proposalDoc, wire.MaxDirectory)
	if err != nil {
		return nil, err
	}
	sigs, err := read(proposalSigs, wire.MaxDirectorySigs)
	if err != nil {
		return nil, err
	}
	d, err := directory.Parse(doc)
	if err != nil {
		return nil, fmt.Errorf("proposal %s: %s is not a valid directory document: %w", dir, proposalDoc, err)
	}
	return &proposal{dir: dir, doc: doc, sigs: sigs, d: d}, nil
}

// errProposalServed is checkProposalBase's answer for a proposal that is
// itself the verified version the server serves (same version, same
// SHA-256), as after an install whose answer was lost: not stale, and
// nothing to sign or install.
var errProposalServed = errors.New("the proposal is the version the server serves")

// checkProposalBase requires the proposal to follow the verified directory
// the server serves: the version after it with prev = the SHA-256 of its
// bytes, or the genesis version when it serves none. A proposal that is
// that version itself gets errProposalServed. A stale proposal is refused
// with advice to rebuild it, never to repeat this command, which would
// fail again (02-09-F10).
func checkProposalBase(p *proposal, vd *verifiedDirectory) error {
	want := trust.GenesisPrev
	if vd.Version > 0 {
		want = vd.SHA256
	}
	if p.d.Version == vd.Version+1 && p.d.Prev == want {
		return nil
	}
	if vd.Version > 0 && p.d.Version == vd.Version && trust.SHA256Hex(p.doc) == vd.SHA256 {
		return errProposalServed
	}
	return staleProposal(p, vd.Version)
}

// staleProposal is the refusal of a proposal built on a version that is no
// longer the one the server serves (served).
func staleProposal(p *proposal, served uint64) error {
	return fmt.Errorf("the directory changed since it was read: proposal %s is based on version %d, but the server serves version %d. "+
		"Discard %s and re-run the command that produced it (for example keyroster user approve NAME --fingerprint FP)",
		p.dir, p.d.Version-1, served, p.dir)
}

// reportServed is directory install's answer for a proposal the server
// already serves: nothing to do. That the signer holds it is the server's
// word, as everywhere (serverServesNote).
func reportServed(stdout io.Writer, p *proposal) error {
	_, err := fmt.Fprintf(stdout, "The server already serves proposal %s as directory version %d (SHA-256 %s); nothing to do.\n%s",
		p.dir, p.d.Version, trust.SHA256Hex(p.doc), serverServesNote)
	return err
}

// afterChainRefusal is directory install's answer to 409
// directory_version_chain after its pre-check passed: another version
// landed meanwhile. It reads the served directory again, so it names the
// version served now (or says the proposal is that version), never the
// one the pre-check read.
func afterChainRefusal(ctx context.Context, s *adminSession, p *proposal, stdout io.Writer) error {
	now, err := fetchVerifiedDirectory(ctx, s)
	if err == nil {
		err = checkProposalBase(p, now)
	}
	switch {
	case errors.Is(err, errProposalServed):
		return reportServed(stdout, p)
	case err != nil && now != nil:
		return err // staleProposal with the version served now
	}
	// The served directory could not be read, or the server's mirror has
	// not caught up yet: no version can be named.
	return fmt.Errorf("the directory changed since it was read: the signer installed another version after the check, so proposal %s no longer follows it. "+
		"Discard %s and re-run the command that produced it (for example keyroster user approve NAME --fingerprint FP)", p.dir, p.dir)
}

// checkProposalSigs verifies every signature of a proposal: each must
// parse, verify over doc under directory.Namespace, and be by an admin of
// the root-verified policy pol. Any signature that fails any of these
// refuses the whole proposal (VerifySignatures only skips a non-admin
// signer, so this check is separate; 02-09-F14). It returns the distinct
// admins' fingerprints, sorted.
func checkProposalSigs(doc, sigs []byte, pol *trust.Policy) ([]string, error) {
	parsed, err := sshsig.ParseAll(sigs)
	if err != nil {
		return nil, fmt.Errorf("%s does not parse as SSHSIG signatures: %w", proposalSigs, err)
	}
	admins := map[string]ssh.PublicKey{}
	for _, a := range pol.Admins {
		pub, err := trust.ParseKey(a.Key)
		if err != nil {
			return nil, fmt.Errorf("policy admin %s: %w", a.Name, err)
		}
		admins[ssh.FingerprintSHA256(pub)] = pub
	}
	seen := map[string]bool{}
	for i, s := range parsed {
		fp := ssh.FingerprintSHA256(s.PublicKey())
		pub, ok := admins[fp]
		if !ok || !bytes.Equal(pub.Marshal(), s.PublicKey().Marshal()) {
			return nil, fmt.Errorf("signature %d in %s is by %s, which is not an admin of the root-signed policy; refusing the proposal", i+1, proposalSigs, fp)
		}
		if err := s.Verify(directory.Namespace, doc); err != nil {
			return nil, fmt.Errorf("signature %d in %s, by %s, does not verify over %s; refusing the proposal", i+1, proposalSigs, fp, proposalDoc)
		}
		seen[fp] = true
	}
	out := make([]string, 0, len(seen))
	for fp := range seen {
		out = append(out, fp)
	}
	slices.Sort(out)
	return out, nil
}

// runDirectorySign is keyroster directory sign DIR [--yes] [--admin-key FP]:
// a co-signer adds their signature to a proposal. Before the agent is
// asked, the proposal must parse, fit the policy, follow the installed
// verified directory, and carry only valid signatures by policy admins
// (checkProposalSigs); then the diff against the installed base is shown
// and confirmSign asks (02-09-R2-F10). An admin who already signed is
// refused: a second signature by one admin counts once.
func runDirectorySign(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("directory sign", flag.ContinueOnError)
	fset.SetOutput(stderr)
	yes := fset.Bool("yes", false, "sign without asking (needed when stdin is not a terminal); check the printed diff first")
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	pos, err := parseInterspersed(fset, args)
	if err != nil || len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, "directory sign: want exactly one proposal directory")
		return errUsage
	}
	p, err := loadProposal(pos[0])
	if err != nil {
		return err
	}
	s, err := openAdminSession(*adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	vd, err := fetchVerifiedDirectory(ctx, s)
	if err != nil {
		return err
	}
	if err := checkProposalBase(p, vd); errors.Is(err, errProposalServed) {
		return fmt.Errorf("proposal %s is already the version the server serves (directory version %d, SHA-256 %s); there is nothing to sign",
			p.dir, p.d.Version, vd.SHA256)
	} else if err != nil {
		return err
	}
	if err := directory.CheckPolicy(p.d, vd.Policy); err != nil {
		return fmt.Errorf("proposal %s exceeds the root-signed policy: %w", p.dir, err)
	}
	signed, err := checkProposalSigs(p.doc, p.sigs, vd.Policy)
	if err != nil {
		return fmt.Errorf("proposal %s: %w", p.dir, err)
	}
	if slices.Contains(signed, s.adminFP) {
		return fmt.Errorf("%s already holds a signature by %s; a second one would count once. Ask another admin to co-sign", filepath.Join(p.dir, proposalSigs), s.adminFP)
	}
	printChanges(stdout, vd, p.d.Version, p.doc, directory.Diff(vd.Dir, p.d))
	_, _ = fmt.Fprintf(stdout, "Signatures so far: %d of %d.\n", len(signed), vd.Policy.AdminQuorum)
	if err := confirmSign(*yes, p.d.Version, stdout); err != nil {
		return err
	}
	sig, err := sshsig.Sign(rand.Reader, s.signer, directory.Namespace, p.doc)
	if err != nil {
		return fmt.Errorf("sign directory version %d with %s: %w", p.d.Version, s.adminFP, err)
	}
	if err := appendSignature(filepath.Join(p.dir, proposalSigs), sig); err != nil {
		return err
	}
	have := len(signed) + 1
	next := "Next: keyroster directory install " + p.dir
	if have < int(vd.Policy.AdminQuorum) {
		next = "Next: another admin runs keyroster directory sign " + p.dir
	}
	_, err = fmt.Fprintf(stdout, "Signed proposal %s with %s: %d of %d admin signatures.\n%s\n", p.dir, s.adminFP, have, vd.Policy.AdminQuorum, next)
	return err
}

// runDirectoryInstall is keyroster directory install DIR [--admin-key FP]:
// it checks that the proposal follows the installed verified directory and
// posts it; the signer decides whether its signatures meet the quorum. It
// signs nothing and so asks nothing (02-09-R2-F10).
func runDirectoryInstall(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("directory install", flag.ContinueOnError)
	fset.SetOutput(stderr)
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	pos, err := parseInterspersed(fset, args)
	if err != nil || len(pos) != 1 {
		_, _ = fmt.Fprintln(stderr, "directory install: want exactly one proposal directory")
		return errUsage
	}
	p, err := loadProposal(pos[0])
	if err != nil {
		return err
	}
	s, err := openAdminSession(*adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	vd, err := fetchVerifiedDirectory(ctx, s)
	if err != nil {
		return err
	}
	if err := checkProposalBase(p, vd); errors.Is(err, errProposalServed) {
		return reportServed(stdout, p)
	} else if err != nil {
		return err
	}
	var ans serverclient.InstallDirectoryAnswer
	err = s.client.AdminJSON(ctx, http.MethodPost, serverclient.AdminDirectoryPath, serverclient.InstallDirectoryRequest{Directory: p.doc, Sigs: p.sigs}, &ans, s.signer)
	if err != nil {
		var he *serverclient.HTTPError
		switch {
		case errors.As(err, &he) && he.Code == http.StatusConflict && he.APIErrorIs(serverclient.AdminErrVersionChain):
			return afterChainRefusal(ctx, s, p, stdout)
		case errors.As(err, &he) && he.Code == http.StatusConflict && he.APIErrorIs(serverclient.AdminErrNotPendingCredential):
			// 409 credential_not_pending: the server's check, the one place
			// that stops every install through the server of a proposal
			// written before a reinvite.
			return fmt.Errorf("proposal %s binds a passkey that is no longer pending for its user: the user was re-invited after %s was written. "+
				"Discard %s, list the user's current passkey with keyroster user pending NAME, and run keyroster user approve NAME --fingerprint FP again",
				p.dir, p.dir, p.dir)
		case errors.As(err, &he) && he.APIErrorIs(serverclient.AdminErrQuorum):
			return fmt.Errorf("the signer refused proposal %s: it does not carry signatures by %d distinct policy admins. Another admin runs keyroster directory sign %s first",
				p.dir, vd.Policy.AdminQuorum, p.dir)
		}
		if refusal := installRefusal(err); refusal != nil {
			return refusal
		}
		return adminError(err, s, vd.Policy)
	}
	return reportInstalled(stdout, ans, p.d.Version, p.doc)
}
