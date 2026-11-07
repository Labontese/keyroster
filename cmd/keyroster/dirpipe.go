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
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
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
// least the quorum), SHA256 is the lowercase hex SHA-256 of Doc, and
// Dir's installation ID is Bundle's or empty (CheckStoredInstallation).
type verifiedDirectory struct {
	Version   uint64
	Doc, Sigs []byte
	Dir       *directory.Directory
	// Bundle is the root-verified trust bundle Policy belongs to; its
	// installation ID is the one every new directory version names (D-04).
	Bundle  *trust.Bundle
	Policy  *trust.Policy
	Signers []string
	SHA256  string
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
// policy's quorum). Then it applies the signer's installation rule for an
// installed directory (directory.CheckStoredInstallation, D-04): a
// directory bound to another installation than the root-verified bundle,
// or to one while the bundle names none, is refused, so no command reads,
// renders or builds on it; a directory without an installation ID is
// accepted, as the signer accepts it until keyroster directory rebind
// binds it. Each caller decides what version 0 means for it.
func fetchVerifiedDirectory(ctx context.Context, s *adminSession) (*verifiedDirectory, error) {
	bundle, pol, err := s.client.Trust(ctx, s.cfg.TrustPins, s.cfg.TrustThreshold)
	if err != nil {
		return nil, err
	}
	var ans serverclient.DirectoryAnswer
	if err := s.client.AdminJSON(ctx, http.MethodGet, serverclient.AdminDirectoryPath, nil, &ans, s.signer); err != nil {
		return nil, adminError(err, s, pol)
	}
	out := &verifiedDirectory{Bundle: bundle, Policy: pol}
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
	if err := directory.CheckStoredInstallation(d, bundle.InstallationID); err != nil {
		return nil, &cliError{text: fmt.Sprintf("the server's directory version %d is bound to installation %s, but the root-verified trust bundle names %s; "+
			"the signer never installs a directory for another installation, so this server serves another deployment's directory. Refusing to use it",
			d.Version, d.InstallationID, installationText(bundle.InstallationID)), err: err}
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
	// CheckBase, when set, checks the verified base before anything is
	// built on it (directory rebind's refusals); an error is returned
	// unchanged and nothing is signed.
	CheckBase func(base *verifiedDirectory) error
}

// editDirectory is the one pipeline of every directory edit (user approve,
// disable, enable; 02-11's role, group and host-group commands):
//
//  1. fetchVerifiedDirectory: the trust bundle against the root pins, then
//     the installed directory against that policy's admins and the
//     bundle's installation (a base bound to another installation is
//     refused: the signer installs no version built on it);
//  2. next is a copy of that base (or a new genesis, version 1 with the
//     all-zero prev) with version + 1 and prev = SHA-256 of the base bytes;
//     mutate changes it; its installation ID is set to the root-verified
//     bundle's (D-04: admins never type it, and the diff shows it when it
//     changes); then Sort, Validate and CheckPolicy;
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
	_, err := editDirectoryOutcome(ctx, s, opts, stdout, mutate)
	return err
}

// editOutcome is what a successful editDirectoryOutcome did with the
// signed version.
type editOutcome int

const (
	// editInstalled: the server reports the version installed.
	editInstalled editOutcome = iota + 1
	// editProposed: a proposal directory was written for co-signing.
	editProposed
)

// editDirectoryOutcome is editDirectory, also returning whether the
// version was installed or written as a proposal (keyroster revoke user
// sends its second revocation only after an install). An error from
// mutate is returned unchanged, before anything is signed.
func editDirectoryOutcome(ctx context.Context, s *adminSession, opts editOpts, stdout io.Writer, mutate func(d *directory.Directory, pol *trust.Policy) error) (editOutcome, error) {
	base, err := fetchVerifiedDirectory(ctx, s)
	if err != nil {
		return 0, err
	}
	next := &directory.Directory{Version: 1, Prev: trust.GenesisPrev}
	if base.Version > 0 {
		next = &directory.Directory{}
		// A deep copy: the base's verified canonical bytes decoded again.
		if err := json.Unmarshal(base.Doc, next); err != nil {
			return 0, fmt.Errorf("copy the installed directory: %w", err)
		}
		next.Version, next.Prev = base.Version+1, base.SHA256
	}
	if opts.CheckBase != nil {
		if err := opts.CheckBase(base); err != nil {
			return 0, err
		}
	}
	if err := mutate(next, base.Policy); err != nil {
		return 0, err
	}
	next.InstallationID = base.Bundle.InstallationID
	next.Sort()
	if err := next.Validate(); err != nil {
		return 0, fmt.Errorf("the new directory version would not be valid, so nothing was signed: %w", err)
	}
	if err := directory.CheckPolicy(next, base.Policy); err != nil {
		return 0, fmt.Errorf("the new directory version exceeds the root-signed policy, so nothing was signed: %w", err)
	}
	doc, err := next.Canonical()
	if err != nil {
		return 0, err
	}
	changes := directory.Diff(base.Dir, next)
	if len(changes) == 0 {
		return 0, errors.New("the change leaves the directory as it is; nothing was signed")
	}
	proposal := ""
	if base.Policy.AdminQuorum > 1 || opts.Out != "" {
		if proposal, err = proposalTarget(opts.Out, next.Version); err != nil {
			return 0, err
		}
	}
	// A version that removes a host entry, or a principal or key of one,
	// first revokes the entry's live host certificates (03-09b, T-03-345):
	// the losses are part of what is signed, so the consent below covers
	// both.
	losses := hostLosses(base.Dir, next)
	printChanges(stdout, base, next.Version, doc, changes)
	printLosses(stdout, next.Version, losses, proposal != "")
	if err := confirmSign(opts.Yes, next.Version, stdout); err != nil {
		return 0, err
	}
	sig, err := sshsig.Sign(rand.Reader, s.signer, directory.Namespace, doc)
	if err != nil {
		return 0, fmt.Errorf("sign directory version %d with %s: %w", next.Version, s.adminFP, err)
	}
	if proposal != "" {
		// Nothing is revoked at propose time: directory install revokes
		// right before it installs.
		return editProposed, writeProposal(stdout, proposal, base, next.Version, doc, sig)
	}
	if len(losses) == 0 {
		return editInstalled, installVersion(ctx, s, base, opts, stdout, next.Version, doc, sig)
	}
	lr := newLossRevoker(s, base.Bundle, next.Version, stdout)
	defer lr.notice()
	if err := lr.before(ctx, losses); err != nil {
		return 0, err
	}
	if err := installVersion(ctx, s, base, opts, stdout, next.Version, doc, sig); err != nil {
		return 0, lr.failed(losses, err)
	}
	lr.after(ctx, losses)
	return editInstalled, nil
}

// installationText names an installation ID in a message, an empty one as
// "none".
func installationText(id string) string {
	if id == "" {
		return "none"
	}
	return id
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
	case he.APIErrorIs(serverclient.AdminErrInstallationMissing):
		return errors.New("the signer refused the directory version: it names no installation, but the trust bundle in force does; " +
			"build it with this version of keyroster, which copies the installation ID from the root-verified bundle (keyroster directory rebind binds the installed directory)")
	case he.APIErrorIs(serverclient.AdminErrInstallationMismatch):
		return errors.New("the signer refused the directory version: it names another installation than the trust bundle in force, so it was signed for another deployment")
	case he.APIErrorIs(serverclient.AdminErrInstallationUnknown):
		return errors.New("the signer refused the directory version: it names an installation, but the trust bundle in force has none")
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

// hostLoss is what a directory version takes from one host entry of the
// verified base it replaces (03-09b, threat-03, T-03-345): the entry
// itself (Removed, with every principal and key), or principals or keys it
// no longer holds.
type hostLoss struct {
	Name           string
	Removed        bool
	LostPrincipals []string
	LostKeys       []string
}

// hostLosses returns the losses of next against the verified base: for
// each entry h of base (any status), with n the entry of next with h's
// name, h's principals and keys that n does not hold, all of them when
// there is no n. Entries with nothing lost are left out; the result is
// sorted by name and each set is sorted. A nil base, a disable, an
// enable, an addition and an installation ID change are no loss. A
// renamed entry is the removal of its old name. Only verified data is
// read (the base the CLI verified, the version it is about to sign or
// install).
func hostLosses(base, next *directory.Directory) []hostLoss {
	if base == nil {
		return nil
	}
	var out []hostLoss
	for _, h := range base.Hosts {
		l := hostLoss{Name: h.Name, Removed: true, LostPrincipals: slices.Sorted(slices.Values(h.Principals)), LostKeys: slices.Sorted(slices.Values(h.Keys))}
		if next != nil {
			if n, ok := next.HostByName(h.Name); ok {
				l = hostLoss{Name: h.Name, LostPrincipals: missingFrom(h.Principals, n.Principals), LostKeys: missingFrom(h.Keys, n.Keys)}
			}
		}
		if len(l.LostPrincipals) > 0 || len(l.LostKeys) > 0 {
			out = append(out, l)
		}
	}
	slices.SortFunc(out, func(a, b hostLoss) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// missingFrom returns the sorted members of a that b does not hold.
func missingFrom(a, b []string) []string {
	var out []string
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	slices.Sort(out)
	return out
}

// lossText describes l: "web1 (removed; principals web1, web1.lab; keys
// SHA256:...)".
func lossText(l hostLoss) string {
	var parts []string
	if l.Removed {
		parts = append(parts, "removed")
	}
	if len(l.LostPrincipals) > 0 {
		parts = append(parts, "principals "+strings.Join(l.LostPrincipals, ", "))
	}
	if len(l.LostKeys) > 0 {
		fps := make([]string, len(l.LostKeys))
		for i, k := range l.LostKeys {
			fps[i] = hostKeyFingerprint(k)
		}
		parts = append(parts, "keys "+strings.Join(fps, ", "))
	}
	return l.Name + " (" + strings.Join(parts, "; ") + ")"
}

// lossNames is the names of losses, comma-separated.
func lossNames(losses []hostLoss) string {
	names := make([]string, len(losses))
	for i, l := range losses {
		names[i] = l.Name
	}
	return strings.Join(names, ", ")
}

// printLosses prints, as part of what is signed or installed, that
// installing version first revokes every live host certificate of each
// losing entry. For a proposal (and keyroster directory sign) nothing is
// revoked now: keyroster directory install revokes them first.
func printLosses(stdout io.Writer, version uint64, losses []hostLoss, proposal bool) {
	var b strings.Builder
	for _, l := range losses {
		fmt.Fprintf(&b, "Installing version %d first revokes every live host certificate of: %s.\n", version, lossText(l))
	}
	if proposal && len(losses) > 0 {
		b.WriteString("Nothing is revoked now: keyroster directory install will revoke them first, right before it installs this version.\n")
	}
	_, _ = io.WriteString(stdout, b.String())
}

// lossRevoker revokes the losses of one install (03-09b): right before the
// install POST, every live host certificate of each losing entry, by
// subject (the signer resolves its kr1 and kr3 certificates), each checked
// in the verified KRL under a host CA key; after a successful install,
// each removed entry once more. Revoking before the install records the
// cert_revoked hold at the version the signer holds, so the same install
// releases it for an entry that stays.
type lossRevoker struct {
	r       *revocation
	version uint64
	stdout  io.Writer
	skip    bool // the bundle has no installation ID: the signer revokes nothing
	sent    bool // a revoke request was sent
}

func newLossRevoker(s *adminSession, b *trust.Bundle, version uint64, stdout io.Writer) *lossRevoker {
	return &lossRevoker{r: &revocation{s: s, bundle: b}, version: version, stdout: stdout, skip: b.InstallationID == ""}
}

// sweep sends one host subject revocation of name, headed by label.
func (lr *lossRevoker) sweep(ctx context.Context, name, label string) error {
	req := &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectHost, Subject: name}
	if err := checkRevokeRequest(req, fmt.Sprintf("directory version %d drops host %s", lr.version, name)); err != nil {
		return err
	}
	lr.sent = true
	_, err := lr.r.sweepSubject(ctx, req, wire.CARoleHost, name, label, lr.stdout, lr.stdout)
	return err
}

// before revokes the losses right before the install. A failed revoke
// installs nothing (installing would leave the old certificates valid for
// names another host may later be given); the error lists what was
// revoked and names the re-run.
func (lr *lossRevoker) before(ctx context.Context, losses []hostLoss) error {
	if lr.skip {
		_, _ = fmt.Fprintf(lr.stdout, "Warning: trust bundle v%d in force has no installation ID, so the signer revokes nothing (krl_no_installation_id): "+
			"the kr1 host certificates of %s are not revoked. Installing anyway.\n", lr.r.bundle.Version, lossNames(losses))
		return nil
	}
	var done []string
	for _, l := range losses {
		if err := lr.sweep(ctx, l.Name, fmt.Sprintf("Revocation before installing version %d", lr.version)); err != nil {
			revoked := "none"
			if len(done) > 0 {
				revoked = strings.Join(done, ", ")
			}
			return fmt.Errorf("the live host certificates of %s could not be revoked: %w. Nothing was installed: installing would leave them valid "+
				"for names another host may later be given. Revoked so far: %s. Run the command again (revoking again is harmless)", l.Name, err, revoked)
		}
		done = append(done, l.Name)
	}
	return nil
}

// after sweeps each removed entry once more after a successful install: a
// key with no live certificate may have obtained one in between. A
// failure warns and keeps the install.
func (lr *lossRevoker) after(ctx context.Context, losses []hostLoss) {
	if lr.skip {
		return
	}
	for _, l := range losses {
		if !l.Removed {
			continue
		}
		if err := lr.sweep(ctx, l.Name, fmt.Sprintf("Second revocation (after installing version %d)", lr.version)); err != nil {
			_, _ = fmt.Fprintf(lr.stdout, "Warning: the second revocation of %s after the install failed: %v. The install stands; run keyroster revoke host %s "+
				"(it works after a removal) to revoke anything issued in between.\n", l.Name, err, l.Name)
		}
	}
}

// failed is an install failure after the loss revokes: the hold the
// revokes left, and how to release it.
func (lr *lossRevoker) failed(losses []hostLoss, err error) error {
	if !lr.sent {
		return err
	}
	names := lossNames(losses)
	return fmt.Errorf("%w. The live host certificates of %s are revoked. The signer refuses their host keys new certificates (cert_revoked) "+
		"until a directory version newer than the one it holds is installed: install version %d or any newer version. Until then, refreshed clients refuse %s",
		err, names, lr.version, names)
}

// notice prints the recovery notice when a revoke request was sent.
func (lr *lossRevoker) notice() {
	if lr.sent {
		_, _ = fmt.Fprintln(lr.stdout, recoveryKeptNotice)
	}
}
