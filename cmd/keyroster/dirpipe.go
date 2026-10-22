package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// stdinIsTerminal reports whether standard input is a terminal, the
// condition under which confirmSign asks; tests replace it, as they
// replace ceremonyInput.
var stdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) } //nolint:gosec // G115: a file descriptor fits an int

// The files of a proposal directory. directory sign and directory install
// read only proposalDoc and proposalSigs; proposalBase is a note for the
// admins (the SHA-256 the proposal was built on) and is never read.
const (
	proposalDoc  = "directory.json"
	proposalSigs = "directory.json" + sigsSuffix
	proposalBase = "base.sha256"
)

// adminSession is what every admin command shares: the saved config, one
// serverclient.Client (so the custody banner prints at most once per
// command) and the admin key in ssh-agent that signs both the admin API
// requests and, where the command signs one, the directory version.
type adminSession struct {
	cfg     *Config
	client  *serverclient.Client
	signer  ssh.Signer
	adminFP string
	close   func()
}

// openAdminSession loads and checks the saved config, finds the admin key
// (adminKey, else the config's admin_key) in ssh-agent, and builds the
// pinned TLS client. close releases the agent connection.
func openAdminSession(adminKey string, stderr io.Writer) (*adminSession, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if err := checkInviteConfig(cfg); err != nil {
		return nil, err
	}
	fp := adminKey
	if fp == "" {
		fp = cfg.AdminKey
	}
	if fp == "" {
		return nil, errNoAdminKey
	}
	if err := trust.CheckPins([]string{fp}, 1); err != nil {
		return nil, fmt.Errorf("--admin-key: %w", err)
	}
	signer, closeAgent, err := adminSigner(fp)
	if err != nil {
		return nil, err
	}
	client, err := serverclient.New(serverclient.Config{Server: cfg.Server, RootsPEM: cfg.TLSRootsPEM, Pins: cfg.TLSPins, Stderr: stderr})
	if err != nil {
		closeAgent()
		return nil, err
	}
	return &adminSession{cfg: cfg, client: client, signer: signer, adminFP: fp, close: closeAgent}, nil
}

// verifiedDirectory is the installed directory after the CLI verified it.
// With a nil error from fetchVerifiedDirectory the result is never nil and
// Policy is always the root-verified policy, also when nothing is
// installed. Nothing installed is exactly Version 0, which always comes
// with a nil Dir, nil Doc and Sigs, no Signers and an empty SHA256; it is
// not an error. Above 0, Version equals Dir.Version, Dir is non-nil,
// Signers are the policy admins whose signatures over Doc verified (at
// least the quorum), and SHA256 is the lowercase hex SHA-256 of Doc.
type verifiedDirectory struct {
	Version   uint64
	Doc, Sigs []byte
	Dir       *directory.Directory
	Policy    *trust.Policy
	Signers   []string
	SHA256    string
}

// errUnsignedBase refuses a served directory that the policy admins did
// not sign. It never repeats the server's text.
var errUnsignedBase = errors.New("the server's directory is not signed by the policy admins; refusing to build on it")

// errBadDirectoryAnswer refuses a directory answer whose parts disagree.
var errBadDirectoryAnswer = errors.New("the server's directory answer does not check out (its version does not match its document); refusing to use it")

// fetchVerifiedDirectory is the one fetch-and-verify step of every
// directory command (02-11-F7). It verifies the served trust bundle and
// policy against the saved root pins (Trust), GETs the installed directory
// through the admin API, and, for a version above 0, verifies the
// signatures over the exact bytes against the admins of that root-verified
// policy before it parses them (directory.VerifySignatures, at least the
// policy's quorum). Each caller decides what version 0 means for it.
func fetchVerifiedDirectory(ctx context.Context, s *adminSession) (*verifiedDirectory, error) {
	_, pol, err := s.client.Trust(ctx, s.cfg.TrustPins, s.cfg.TrustThreshold)
	if err != nil {
		return nil, err
	}
	var ans serverclient.DirectoryAnswer
	if err := s.client.AdminJSON(ctx, http.MethodGet, serverclient.AdminDirectoryPath, nil, &ans, s.signer); err != nil {
		return nil, adminError(err, s, pol)
	}
	out := &verifiedDirectory{Policy: pol}
	if ans.Version == 0 {
		if len(ans.Directory) != 0 || len(ans.Sigs) != 0 {
			return nil, errBadDirectoryAnswer
		}
		return out, nil
	}
	signers, err := directory.VerifySignatures(ans.Directory, ans.Sigs, pol)
	if err != nil {
		return nil, errUnsignedBase
	}
	d, err := directory.Parse(ans.Directory)
	if err != nil {
		// Admin-signed, but not a document this CLI accepts.
		return nil, fmt.Errorf("the installed directory is signed by the policy admins but does not validate here: %w", serverclient.PeerError(err))
	}
	if d.Version != ans.Version {
		return nil, errBadDirectoryAnswer
	}
	out.Version, out.Doc, out.Sigs, out.Dir, out.Signers, out.SHA256 = d.Version, ans.Directory, ans.Sigs, d, signers, trust.SHA256Hex(ans.Directory)
	return out, nil
}

// adminError adds adminOriginDiagnosis to an admin API failure when the
// root-verified policy pol names WebAuthn origins (nil pol: none known).
func adminError(err error, s *adminSession, pol *trust.Policy) error {
	if pol != nil && pol.WebAuthn != nil {
		return adminOriginDiagnosis(err, s.client.Server(), pol.WebAuthn.Origins)
	}
	return err
}

// editOpts are the options every directory edit shares.
type editOpts struct {
	// Yes signs without asking (confirmSign).
	Yes bool
	// Out writes a proposal directory instead of installing.
	Out string
	// User names the user the edit is about, for the refusal messages
	// ("" when there is none).
	User string
}

// editDirectory is the one pipeline of every directory edit (user approve,
// disable, enable; 02-11's role, group and host-group commands):
//
//  1. fetchVerifiedDirectory: the trust bundle against the root pins, then
//     the installed directory against that policy's admins;
//  2. next is a copy of that base (or a new genesis, version 1 with the
//     all-zero prev) with version + 1 and prev = SHA-256 of the base bytes;
//     mutate changes it; then Sort, Validate and CheckPolicy;
//  3. the diff and next's SHA-256 are printed, and confirmSign asks (or
//     --yes); a refusal reaches no agent;
//  4. next's canonical bytes are signed with SSHSIG under
//     directory.Namespace by the admin key in ssh-agent;
//  5. with a policy quorum above 1, or --out, a proposal directory is
//     written for co-signing; otherwise the version is installed through
//     the server, which forwards it to the signer.
//
// The CLI never signs a version built on a base it did not verify, and
// never signs one it did not show (T-02-42, T-02-43).
func editDirectory(ctx context.Context, s *adminSession, opts editOpts, stdout io.Writer, mutate func(d *directory.Directory, pol *trust.Policy) error) error {
	base, err := fetchVerifiedDirectory(ctx, s)
	if err != nil {
		return err
	}
	next := &directory.Directory{Version: 1, Prev: trust.GenesisPrev}
	if base.Version > 0 {
		next = &directory.Directory{}
		// A deep copy: the base's verified canonical bytes decoded again.
		if err := json.Unmarshal(base.Doc, next); err != nil {
			return fmt.Errorf("copy the installed directory: %w", err)
		}
		next.Version, next.Prev = base.Version+1, base.SHA256
	}
	if err := mutate(next, base.Policy); err != nil {
		return err
	}
	next.Sort()
	if err := next.Validate(); err != nil {
		return fmt.Errorf("the new directory version would not be valid, so nothing was signed: %w", err)
	}
	if err := directory.CheckPolicy(next, base.Policy); err != nil {
		return fmt.Errorf("the new directory version exceeds the root-signed policy, so nothing was signed: %w", err)
	}
	doc, err := next.Canonical()
	if err != nil {
		return err
	}
	changes := directory.Diff(base.Dir, next)
	if len(changes) == 0 {
		return errors.New("the change leaves the directory as it is; nothing was signed")
	}
	proposal := ""
	if base.Policy.AdminQuorum > 1 || opts.Out != "" {
		if proposal, err = proposalTarget(opts.Out, next.Version); err != nil {
			return err
		}
	}
	printChanges(stdout, base, next.Version, doc, changes)
	if err := confirmSign(opts.Yes, next.Version, stdout); err != nil {
		return err
	}
	sig, err := sshsig.Sign(rand.Reader, s.signer, directory.Namespace, doc)
	if err != nil {
		return fmt.Errorf("sign directory version %d with %s: %w", next.Version, s.adminFP, err)
	}
	if proposal != "" {
		return writeProposal(stdout, proposal, base, next.Version, doc, sig)
	}
	return installVersion(ctx, s, base, opts, stdout, next.Version, doc, sig)
}

// printChanges prints what an admin is asked to sign: the base, the diff
// and the SHA-256 of the new version's bytes.
func printChanges(stdout io.Writer, base *verifiedDirectory, version uint64, doc []byte, changes []string) {
	var b strings.Builder
	if base.Version == 0 {
		fmt.Fprintf(&b, "Directory version %d (the first; the server serves none). Changes:\n", version)
	} else {
		fmt.Fprintf(&b, "Directory version %d, based on version %d (SHA-256 %s), the admin-signed version the server serves. Changes:\n", version, base.Version, base.SHA256)
	}
	for _, c := range changes {
		b.WriteString("  " + c + "\n")
	}
	fmt.Fprintf(&b, "SHA-256 of directory version %d: %s\n", version, trust.SHA256Hex(doc))
	_, _ = io.WriteString(stdout, b.String())
}

// proposalTarget returns the proposal directory an edit writes, checked
// before anything is signed: out when given (it may exist, but must not
// hold a proposal already), else keyroster-directory-v<version> in the
// working directory, which must not exist.
func proposalTarget(out string, version uint64) (string, error) {
	if out == "" {
		dir := fmt.Sprintf("keyroster-directory-v%d", version)
		if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%s already exists; pass --out to name another proposal directory. Nothing was signed", dir)
		}
		return dir, nil
	}
	if _, err := os.Lstat(filepath.Join(out, proposalDoc)); !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%s already holds a proposal; pass another --out. Nothing was signed", out)
	}
	return out, nil
}

// writeProposal writes the proposal directory dir: the version's canonical
// bytes, its first signature and a note of the base it was built on.
func writeProposal(stdout io.Writer, dir string, base *verifiedDirectory, version uint64, doc, sig []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // G301: a proposal holds public data for other admins
		return err
	}
	if err := writeNew(filepath.Join(dir, proposalDoc), doc); err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, proposalSigs), sig); err != nil {
		return err
	}
	note := "none (genesis)\n"
	if base.Version > 0 {
		note = fmt.Sprintf("%s (version %d)\n", base.SHA256, base.Version)
	}
	if err := writeNew(filepath.Join(dir, proposalBase), []byte(note)); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "Wrote proposal %s for directory version %d: 1 of %d admin signatures.\n"+
		"Next: other admins run keyroster directory sign %s, then one of you runs keyroster directory install %s.\n",
		dir, version, base.Policy.AdminQuorum, dir, dir)
	return err
}

// installVersion posts a fully signed version through the server, the
// direct path of editDirectory.
func installVersion(ctx context.Context, s *adminSession, base *verifiedDirectory, opts editOpts, stdout io.Writer, version uint64, doc, sig []byte) error {
	var ans serverclient.InstallDirectoryAnswer
	err := s.client.AdminJSON(ctx, http.MethodPost, serverclient.AdminDirectoryPath, serverclient.InstallDirectoryRequest{Directory: doc, Sigs: sig}, &ans, s.signer)
	if err != nil {
		var he *serverclient.HTTPError
		switch {
		case errors.As(err, &he) && he.Code == http.StatusConflict && he.APIErrorIs(serverclient.AdminErrVersionChain):
			return errors.New("the directory changed since it was read (another admin installed a version); re-run this command")
		case errors.As(err, &he) && he.Code == http.StatusConflict && he.APIErrorIs(serverclient.AdminErrNotPendingCredential):
			// 409 credential_not_pending: a reinvite completed between this
			// command's pending lookup and the server's check.
			name := opts.User
			if name == "" {
				name = "NAME"
			}
			return fmt.Errorf("the passkey this change binds is no longer pending for its user (the user was re-invited, or the invite was replaced). "+
				"List the current one with keyroster user pending %s and approve it with keyroster user approve %s --fingerprint FP", name, name)
		}
		if refusal := installRefusal(err); refusal != nil {
			return refusal
		}
		return adminError(err, s, base.Policy)
	}
	return reportInstalled(stdout, ans, version, doc)
}

// installRefusal states the signer's refusals of an install that are not
// about the base, in the CLI's own words; nil for any other error.
func installRefusal(err error) error {
	var he *serverclient.HTTPError
	if !errors.As(err, &he) {
		return nil
	}
	switch {
	case he.APIErrorIs(serverclient.AdminErrQuorum):
		return errors.New("the signer refused the directory version: it does not carry signatures by enough distinct policy admins")
	case he.APIErrorIs(serverclient.AdminErrExceedsPolicy):
		return errors.New("the signer refused the directory version: it exceeds the root-signed policy in force")
	case he.APIErrorIs(serverclient.AdminErrInvalid):
		return errors.New("the signer refused the directory version as not valid")
	}
	return nil
}

// errBadInstallAnswer refuses an install answer that does not describe the
// version the CLI sent.
var errBadInstallAnswer = errors.New("the server's install answer does not match the version sent; " +
	"only the signer's audit log shows what is installed (on the signer host: keyroster-signer export-log, then keyroster audit verify)")

// reportInstalled prints an accepted install as what it is: the server's
// report. The version and SHA-256 printed are the ones the CLI computed
// for what it sent, and the server's answer must agree with them, but a
// server can compute both from the request without forwarding it, and
// nothing the signer signed comes back (residual until the CLI verifies
// a signer-signed install receipt, Phase 4). The log leaf is printed so
// it can be compared with the signer's exported log.
func reportInstalled(stdout io.Writer, ans serverclient.InstallDirectoryAnswer, version uint64, doc []byte) error {
	sum := trust.SHA256Hex(doc)
	if ans.Version != version || ans.SHA256 != sum {
		return errBadInstallAnswer
	}
	_, err := fmt.Fprintf(stdout, "The server reports directory version %d installed (SHA-256 %s, log leaf %d).\n"+
		"That is the server's word: the signer's audit log is the proof (keyroster audit verify on a log exported on the signer host must print \"directory installs %d\").\n",
		version, sum, ans.LeafIndex, version)
	return err
}

// confirmSign is the one confirmation rule for every command that signs a
// directory version (editDirectory and directory sign; 02-09-R2-F10). It is
// called after the diff is printed and before the agent is asked, so a
// refusal means no sign request reached the agent:
//   - with yes it returns nil and reads nothing;
//   - on a terminal it asks "Sign directory version N? [y/N]" and reads one
//     line from ceremonyInput; only y or yes, in any letter case, is
//     consent, anything else (an empty line, the end of input) refuses;
//   - with no terminal and no yes it refuses.
func confirmSign(yes bool, version uint64, stdout io.Writer) error {
	if yes {
		return nil
	}
	if !stdinIsTerminal() {
		return errors.New("refusing to sign without confirmation: stdin is not a terminal; check the diff and re-run with --yes")
	}
	if _, err := fmt.Fprintf(stdout, "Sign directory version %d? [y/N] ", version); err != nil {
		return err
	}
	line, _ := bufio.NewReader(ceremonyInput).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return errors.New("not confirmed; nothing was signed")
}
