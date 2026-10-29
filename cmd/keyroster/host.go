package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "host",
		Summary: "hosts in the directory (add, remove, list), agent enrollment and operation (join-token, pending, approve, status, forget) and manual host setup (principals: render an account's AuthorizedPrincipalsFile; ca-key: the TrustedUserCAKeys line)",
		Run:     runHost,
	})
}

const hostSubcommands = "add, remove, list, join-token, pending, approve, status, forget, principals or ca-key"

func runHost(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "host: want a subcommand: "+hostSubcommands)
		return errUsage
	}
	switch args[0] {
	case "add":
		return runHostAdd(ctx, args[1:], stdout, stderr)
	case "remove":
		return runHostRemove(ctx, args[1:], stdout, stderr)
	case "list":
		return runHostList(ctx, args[1:], stdout, stderr)
	case "join-token":
		return runHostJoinToken(ctx, args[1:], stdout, stderr)
	case "pending":
		return runHostPending(ctx, args[1:], stdout, stderr)
	case "approve":
		return runHostApprove(ctx, args[1:], stdout, stderr)
	case "forget":
		return runHostForget(ctx, args[1:], stdout, stderr)
	case "status":
		return runHostStatus(ctx, args[1:], stdout, stderr)
	case "principals":
		return runHostPrincipals(ctx, args[1:], stdout, stderr)
	case "ca-key":
		return runHostCAKey(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "host: unknown subcommand %q; want %s\n", args[0], hostSubcommands)
		return errUsage
	}
}

// errHostName refuses a host or machine name outside the directory's
// grammar (the user name grammar).
func errHostName(what, name string) error {
	return fmt.Errorf("%s name %q: use 1 to 64 characters a-z, 0-9, '.', '_' or '-', starting with a letter or digit", what, name)
}

// readEntryKey reads the public key file path for a host or machine entry
// and returns it in trust.FormatKey form (no comment). A private key file
// and a certificate are refused.
func readEntryKey(path string) (string, error) {
	pub, err := readPublicKey(path)
	if err != nil {
		return "", err
	}
	if _, ok := pub.(*ssh.Certificate); ok {
		return "", fmt.Errorf("%s is a certificate; pass the public key file", path)
	}
	return trust.FormatKey(pub), nil
}

// runHostAdd is keyroster host add NAME --group G --key FILE...
// --principal P...: registers host NAME in host group G (D-11) with its
// host public keys and the names its host certificate will carry (D-16).
// The principals are typed by the admin, each in its canonical spelling
// (directory.CheckHostPrincipal); nothing about the host comes from the
// host itself.
func runHostAdd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host add", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	group := fset.String("group", "", "the host group the host belongs to (required; exactly one)")
	var keyFiles, principals stringList
	fset.Var(&keyFiles, "key", "a host public key file, such as /etc/ssh/ssh_host_ed25519_key.pub (repeatable, 1 to 8; Ed25519 or ECDSA)")
	fset.Var(&principals, "principal", "a name clients use for the host, in its host certificate (repeatable, 1 to 8): short name, FQDN or address, lowercase, no trailing dot")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "host add", pos)
	if err != nil {
		return err
	}
	if !directory.ValidUserName(name) {
		return errHostName("host", name)
	}
	if *group == "" {
		_, _ = fmt.Fprintln(stderr, "host add: --group is required")
		return errUsage
	}
	if !directory.ValidGroupName(*group) {
		return errGroupName(*group)
	}
	if len(keyFiles) == 0 || len(principals) == 0 {
		_, _ = fmt.Fprintln(stderr, "host add: give at least one --key and one --principal")
		return errUsage
	}
	for _, p := range principals {
		if err := directory.CheckHostPrincipal(p); err != nil {
			return fmt.Errorf("%w; nothing was signed", err)
		}
	}
	keys := make([]string, 0, len(keyFiles))
	for _, f := range keyFiles {
		k, err := readEntryKey(f)
		if err != nil {
			return err
		}
		keys = append(keys, k)
	}
	return ef.edit(ctx, stdout, stderr, addHostEntry(name, *group, keys, principals))
}

// addHostEntry is the one mutation of host add and host approve: a new
// active entry NAME in host group GROUP with keys and the principals the
// admin typed.
func addHostEntry(name, group string, keys, principals []string) func(d *directory.Directory) error {
	return func(d *directory.Directory) error {
		if _, ok := d.HostByName(name); ok {
			return fmt.Errorf("host %s is already in the directory; remove it first to change it. Nothing was signed", name)
		}
		if _, err := findHostGroup(d, group); err != nil {
			return err
		}
		d.Hosts = append(d.Hosts, directory.Host{
			Name: name, HostGroup: group, Keys: slices.Clone(keys), Principals: slices.Clone(principals), Status: directory.StatusActive,
		})
		return nil
	}
}

// runHostRemove is keyroster host remove NAME: removes the host entry, so
// the signer no longer issues it a host certificate (03-09).
func runHostRemove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host remove", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "host remove", pos)
	if err != nil {
		return err
	}
	if !directory.ValidUserName(name) {
		return errHostName("host", name)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i := slices.IndexFunc(d.Hosts, func(h directory.Host) bool { return h.Name == name })
		if i < 0 {
			return fmt.Errorf("there is no host %s in the directory; nothing was signed", name)
		}
		d.Hosts = slices.Delete(d.Hosts, i, i+1)
		return nil
	})
}

// runHostList is keyroster host list [--admin-key FP]: the hosts of the
// admin-signed directory the server serves, its signatures verified
// against the root-verified policy.
func runHostList(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host list", flag.ContinueOnError)
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
	var b strings.Builder
	if vd.Version == 0 || len(vd.Dir.Hosts) == 0 {
		fmt.Fprintf(&b, "Directory version %d names no host.\n", vd.Version)
	} else {
		fmt.Fprintf(&b, "Hosts of directory version %d (SHA-256 %s, admin signatures verified), installation %s:\n",
			vd.Version, vd.SHA256, installationText(vd.Dir.InstallationID))
		for _, line := range directory.Diff(&directory.Directory{}, &directory.Directory{Hosts: vd.Dir.Hosts}) {
			b.WriteString("  " + strings.TrimPrefix(line, "+ host ") + "\n")
		}
	}
	b.WriteString(serverServesNote)
	_, err = io.WriteString(stdout, b.String())
	return err
}

// cliError is an error with the CLI's own text that still matches err
// with errors.Is.
type cliError struct {
	text string
	err  error
}

func (e *cliError) Error() string { return e.text }
func (e *cliError) Unwrap() error { return e.err }

// errNothingToRender refuses host principals while no directory is
// installed: there is no host group to render for, and a header-only file
// would claim that an installed version grants the account nothing.
var errNothingToRender = &cliError{text: "no directory is installed on the server; nothing to render", err: directory.ErrNoDirectory}

// runHostPrincipals is keyroster host principals GROUP ACCOUNT, or
// --host NAME ACCOUNT, [--admin-key FP]: the AuthorizedPrincipalsFile of
// ACCOUNT in host group GROUP, or in the one host group of host NAME
// (directory.HostPrincipals, exactly the file that host's agent writes,
// AUTHZ-02), rendered with directory.RenderPrincipalsFile (the renderer the
// Phase 3 agent will use, D-07) from the admin-signed directory the server
// serves, its signatures verified against the root-verified policy
// (fetchVerifiedDirectory, 02-11-F7). stdout carries exactly the file. An
// account the host group does not map gets the header-only file, which
// grants nothing; an unknown host group is an error.
func runHostPrincipals(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host principals", flag.ContinueOnError)
	fset.SetOutput(stderr)
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	hostName := fset.String("host", "", "render for this host of the directory (its one host group) instead of naming a GROUP")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	var group, account string
	switch {
	case *hostName != "" && len(pos) == 1:
		account = pos[0]
		if !directory.ValidUserName(*hostName) {
			return errHostName("host", *hostName)
		}
	case *hostName == "" && len(pos) == 2:
		group, account = pos[0], pos[1]
		if !directory.ValidGroupName(group) {
			return errGroupName(group)
		}
	default:
		_, _ = fmt.Fprintln(stderr, "host principals: want GROUP ACCOUNT, or --host NAME ACCOUNT")
		return errUsage
	}
	if !directory.ValidAccountName(account) {
		return errAccountName(account)
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
		return errNothingToRender
	}
	var file []byte
	if *hostName != "" {
		file, err = directory.HostPrincipals(vd.Dir, *hostName, account)
	} else {
		file, err = directory.RenderPrincipalsFile(vd.Dir, group, account)
	}
	if err != nil {
		switch {
		case errors.Is(err, directory.ErrUnknownHost):
			return &cliError{text: fmt.Sprintf("directory version %d has no active host %s", vd.Version, *hostName), err: err}
		case errors.Is(err, directory.ErrUnknownHostGroup):
			return fmt.Errorf("directory version %d has no host group %s: %w", vd.Version, group, err)
		}
		return err
	}
	_, err = stdout.Write(file)
	return err
}

// runHostCAKey is keyroster host ca-key: the active user CA key of the
// trust bundle the server serves, verified against the saved root pins
// (Trust), as an authorized_keys line for TrustedUserCAKeys. It needs the
// saved config but no admin key.
func runHostCAKey(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host ca-key", flag.ContinueOnError)
	fset.SetOutput(stderr)
	if pos, err := parseInterspersed(fset, args); err != nil || len(pos) != 0 {
		return errUsage
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := checkInviteConfig(cfg); err != nil {
		return err
	}
	client, err := serverclient.New(serverclient.Config{Server: cfg.Server, RootsPEM: cfg.TLSRootsPEM, Pins: cfg.TLSPins, Stderr: stderr})
	if err != nil {
		return err
	}
	b, _, err := client.Trust(ctx, cfg.TrustPins, cfg.TrustThreshold)
	if err != nil {
		return err
	}
	for _, ca := range b.CAs {
		if ca.Role != trust.RoleUser || ca.State != "active" {
			continue
		}
		pub, err := trust.ParseKey(ca.Key) // the bundle validated it
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "%s keyroster user CA (bundle v%d)\n", trust.FormatKey(pub), b.Version)
		return err
	}
	// Bundle validation requires exactly one active key per role.
	return errors.New("the verified trust bundle has no active user CA key")
}

// errHostPoPNotEnabled refuses host enrollment while the root-signed
// policy lacks pop.hosts (owner decision 2026-10-24): checked here on the
// policy the CLI verified against its own pins, before any request that
// changes state; the server refuses the same independently.
var errHostPoPNotEnabled = errors.New("host_pop_not_enabled: the root-signed policy in force does not set pop.hosts, which host agents need " +
	"(their revocation self-test relies on host proof of possession); run a root ceremony with keyroster root successor-policy --pop-hosts " +
	"(docs/runbooks/root-ceremony.md), which can never be turned off again, then enroll the host")

// requireHostPoP verifies the served trust bundle and policy against the
// saved pins (Trust) and refuses errHostPoPNotEnabled when the verified
// policy does not set pop.hosts.
func requireHostPoP(ctx context.Context, s *adminSession) (*trust.Bundle, *trust.Policy, error) {
	b, pol, err := s.client.Trust(ctx, s.cfg.TrustPins, s.cfg.TrustThreshold)
	if err != nil {
		return nil, nil, err
	}
	if pol.PoP == nil || !pol.PoP.Hosts {
		return nil, nil, errHostPoPNotEnabled
	}
	return b, pol, nil
}

// hostAdminRefusal states the server's refusals of the host enrollment
// routes in the CLI's own words; nil for any other error.
func hostAdminRefusal(err error) error {
	var he *serverclient.HTTPError
	if !errors.As(err, &he) {
		return nil
	}
	switch {
	case he.APIErrorIs(serverclient.AgentErrHostPoPNotEnable):
		return errHostPoPNotEnabled
	case he.APIErrorIs(serverclient.AdminErrNoAgentListener):
		return errors.New("the server has no agent listener: start keyroster-server with --agent-listen (docs/runbooks/server-install.md); no join token was minted")
	case he.APIErrorIs(serverclient.AdminErrTTL):
		return errors.New("the server refused the join token's lifetime: at most 1h")
	case he.APIErrorIs(serverclient.AdminErrHostInDirectory):
		return errors.New("the directory still has a host entry with this agent's host keys; remove the host first (keyroster host remove), " +
			"wait until the host has applied that version, then forget it (docs/runbooks/host-setup.md \"Removing a host\"). Nothing was forgotten")
	case he.APIErrorIs(serverclient.AdminErrHostNotEnrolled):
		return errors.New("no agent with this identity is enrolled (it was forgotten, or its identity rotated); check keyroster host pending. Nothing was forgotten")
	case he.APIErrorIs(serverclient.AdminErrRemovalNotApplied):
		return errRemovalNotApplied("")
	case he.APIErrorIs(serverclient.AdminErrForgetStateChanged):
		return errors.New("forget_state_changed: the agent changed since keyroster host pending was read (its approval, removal version or " +
			"recorded removal confirmation), so the server forgot nothing; run the command again")
	}
	return nil
}

// errRemovalNotApplied is host forget's refusal of an agent approved once
// whose host has no recorded removal confirmation, for the agent with
// identity fingerprint id ("" when unknown).
func errRemovalNotApplied(id string) error {
	if id == "" {
		id = "SHA256:..."
	}
	return fmt.Errorf("host_removal_not_applied: the host has not yet confirmed, in its heartbeat, that it applied a directory version that removed it "+
		"(keyroster host pending shows the confirmation once the server recorded it); forgetting it now would stop the signed state, revocations included, "+
		"before the removal reached it. Wait for its next heartbeat; for a host that is gone for good, run keyroster host forget --identity %s --host-gone. Nothing was forgotten", id)
}

// runHostJoinToken is keyroster host join-token NAME [--ttl D] --out FILE
// [--admin-key FP] (AGENT-01): mints a one-time join token for host NAME
// through the admin API and writes the join string (internal/agent/join)
// to FILE, mode 0600, never to stdout or a log. The string carries the
// agent listener's URL (this config's server host with the port the
// server names), the saved TLS roots and pins, the saved trust pins and
// threshold and the installation ID of the verified trust bundle. FILE
// must not exist.
func runHostJoinToken(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host join-token", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ttl := fset.Duration("ttl", 30*time.Minute, "how long the token stays valid (whole seconds, at most 1h)")
	out := fset.String("out", "", "the file to write the join string to, mode 0600 (required; must not exist)")
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "host join-token", pos)
	if err != nil {
		return err
	}
	if !directory.ValidUserName(name) {
		return errHostName("host", name)
	}
	if *out == "" {
		_, _ = fmt.Fprintln(stderr, "host join-token: --out FILE is required; the join string is a secret and is never printed")
		return errUsage
	}
	secs := int64(ttl.Round(time.Second) / time.Second)
	if secs < 1 || secs > serverclient.MaxJoinTokenTTLSeconds {
		return fmt.Errorf("--ttl %s: want 1s to 1h; no join token was minted", *ttl)
	}
	if _, err := os.Lstat(*out); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s exists; name a new file. No join token was minted", *out)
	}
	s, err := openAdminSession(*adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	bundle, pol, err := requireHostPoP(ctx, s)
	if err != nil {
		return err
	}
	if bundle.InstallationID == "" {
		return errors.New("the verified trust bundle names no installation ID, which every enrolled agent pins (D-04); bind the installation first (docs/runbooks/root-ceremony.md). No join token was minted")
	}
	var ans serverclient.JoinTokenAnswer
	if err := s.client.AdminJSON(ctx, http.MethodPost, serverclient.AdminJoinTokensPath, serverclient.JoinTokenRequest{ExpectedName: name, TTLSeconds: secs}, &ans, s.signer); err != nil {
		if refusal := hostAdminRefusal(err); refusal != nil {
			return refusal
		}
		return adminError(err, s, pol)
	}
	if ans.ExpectedName != name || ans.AgentPort < 1 || ans.AgentPort > 65535 {
		return errors.New("the server's join token answer does not match the request; nothing was written")
	}
	base, err := serverclient.ParseServerURL(s.cfg.Server)
	if err != nil {
		return err
	}
	agentURL, err := serverclient.ParseServerURL("https://" + net.JoinHostPort(base.Hostname(), strconv.Itoa(ans.AgentPort)))
	if err != nil {
		return err
	}
	str, err := join.Format(join.JoinToken{
		Version: join.Version, Server: agentURL.String(), TLSRoots: s.cfg.TLSRootsPEM, TLSPins: s.cfg.TLSPins,
		TrustPins: s.cfg.TrustPins, Threshold: s.cfg.TrustThreshold, InstallationID: bundle.InstallationID,
		Token: ans.Token, ExpectedName: name, ExpiresAt: ans.ExpiresAt,
	})
	if err != nil {
		// join's errors never repeat the token.
		return fmt.Errorf("the join string would not be valid, so nothing was written: %w", err)
	}
	if err := writeExclusive(*out, []byte(str+"\n"), 0o600); err != nil {
		return err
	}
	protection, warning := joinFileProtection(runtime.GOOS)
	if warning != "" {
		_, _ = fmt.Fprintln(stderr, warning)
	}
	_, err = fmt.Fprintf(stdout, "Wrote the join string for host %s to %s (%s). It expires at %s and enrolls one agent.\n"+
		"It is a secret: copy it to the host with mode 0600 and run, as root there, keyroster-agent install --join-file <file> "+
		"(docs/runbooks/host-setup.md \"Enrolling a host\"). The agent server is %s.\n", name, *out, protection, ans.ExpiresAt, agentURL)
	return err
}

// joinFileProtection is how host join-token describes the join file's
// protection on goos, and a warning to print first (PR #71 review F14):
// mode 0600 where the OS has file modes; on Windows the mode only sets
// the read-only attribute, and the file inherits its directory's ACL.
func joinFileProtection(goos string) (protection, warning string) {
	if goos == "windows" {
		return "with the ACL it inherits from its directory",
			"WARNING: on Windows the join file is not mode 0600: it inherits the ACL of the directory it is in, so any account that can read that directory can read the token. Write it to a directory only you can read (for example under your user profile), and delete it once it is on the host."
	}
	return "mode 0600", ""
}

// fetchPendingHosts GETs the pending hosts through the admin API, after
// requireHostPoP, whose verified policy it returns: the hosts waiting for
// approval, and the hosts approved once that the directory no longer
// approves (served until forget, 03-08 carry-over a), each checked
// (checkServedHost).
func fetchPendingHosts(ctx context.Context, s *adminSession) ([]serverclient.PendingHost, []servedHostView, *trust.Policy, error) {
	_, pol, err := requireHostPoP(ctx, s)
	if err != nil {
		return nil, nil, nil, err
	}
	var ans serverclient.PendingHostsAnswer
	if err := s.client.AdminJSON(ctx, http.MethodGet, serverclient.AdminPendingHostsPath, nil, &ans, s.signer); err != nil {
		if refusal := hostAdminRefusal(err); refusal != nil {
			return nil, nil, nil, refusal
		}
		return nil, nil, nil, adminError(err, s, pol)
	}
	var served []servedHostView
	for _, h := range ans.Served {
		v, err := checkServedHost(h)
		if err != nil {
			return nil, nil, nil, err
		}
		served = append(served, *v)
	}
	return ans.Hosts, served, pol, nil
}

// servedHostView is a served host as the CLI shows it: its state, its
// removal version (0: none recorded) and its recorded removal
// confirmation (nil: none; 03-08b).
type servedHostView struct {
	pendingHostView
	State          string
	RemovalVersion uint64
	Confirmed      *serverclient.RemovalConfirmation
}

// checkServedHost is checkPendingHost for a served host, whose state must
// be one of removed, disabled or keys_changed, and whose confirmation, if
// any, has a removal version, a version at or above it and a 64-hex
// SHA-256.
func checkServedHost(h serverclient.ServedHost) (*servedHostView, error) {
	v, err := checkPendingHost(h.PendingHost)
	if err != nil {
		return nil, err
	}
	switch h.State {
	case serverclient.HostStateRemoved, serverclient.HostStateDisabled, serverclient.HostStateKeysChanged:
	default:
		return nil, errBadPendingHosts
	}
	if c := h.RemovalConfirmed; c != nil && (h.RemovalVersion == 0 || c.Version < h.RemovalVersion || !enroll.IsSHA256Hex(c.SHA256)) {
		return nil, errBadPendingHosts
	}
	return &servedHostView{pendingHostView: *v, State: h.State, RemovalVersion: h.RemovalVersion, Confirmed: h.RemovalConfirmed}, nil
}

// servedLine is the line host pending and host status print for a served
// host's state: removed, disabled or re-keyed, and served until forget.
func servedLine(state string) string {
	switch state {
	case serverclient.HostStateDisabled:
		return "disabled, served until forget"
	case serverclient.HostStateKeysChanged:
		return "host_keys_changed, served until forget"
	}
	return "removed, served until forget"
}

// confirmationLine is how host pending and host forget show a served
// host's removal confirmation (03-08b).
func confirmationLine(v *servedHostView) string {
	switch {
	case v.Confirmed != nil:
		return fmt.Sprintf("removal confirmed at directory v%d", v.Confirmed.Version)
	case v.RemovalVersion != 0:
		return fmt.Sprintf("removal at directory v%d not confirmed", v.RemovalVersion)
	}
	return "no removal recorded, not confirmed"
}

// forgetCommand is the host forget command that names the agent with
// identity fingerprint id.
func forgetCommand(id string) string { return "keyroster host forget --identity " + id }

// pendingHostView is a pending host as the CLI shows it: every value
// re-derived and checked from the server's answer.
type pendingHostView struct {
	Name        string
	Identity    string // enroll.IdentityFingerprint
	Keys        []string
	Fingerprint []string // ssh.FingerprintSHA256 of each key, in Keys order
	Facts       enroll.Facts
	EnrolledAt  string
}

// errBadPendingHosts refuses a pending host list that does not check
// out; it never repeats the server's text.
var errBadPendingHosts = errors.New("the server's pending host list does not check out; refusing to use it")

// checkPendingHost re-derives what host approve and host pending print:
// the name in the host name grammar, the identity hash as 64 lowercase hex
// digits, 1 to directory.MaxHostKeys sorted distinct host keys of a host
// key type, printable facts and an RFC 3339 time.
func checkPendingHost(p serverclient.PendingHost) (*pendingHostView, error) {
	if !directory.ValidUserName(p.ExpectedName) || !enroll.IsSHA256Hex(p.IdentitySPKISHA256) || enroll.CheckFacts(p.Facts) != nil {
		return nil, errBadPendingHosts
	}
	if _, err := time.Parse(time.RFC3339, p.EnrolledAt); err != nil {
		return nil, errBadPendingHosts
	}
	if len(p.HostKeys) == 0 || len(p.HostKeys) > directory.MaxHostKeys {
		return nil, errBadPendingHosts
	}
	v := &pendingHostView{Name: p.ExpectedName, Facts: p.Facts, EnrolledAt: p.EnrolledAt}
	spki, err := hex.DecodeString(p.IdentitySPKISHA256)
	if err != nil {
		return nil, errBadPendingHosts
	}
	v.Identity = enroll.IdentityFingerprint(spki)
	for i, k := range p.HostKeys {
		pub, err := trust.ParseKey(k)
		if err != nil || trust.FormatKey(pub) != k || !directory.IsHostKeyType(pub.Type()) || (i > 0 && p.HostKeys[i-1] >= k) {
			return nil, errBadPendingHosts
		}
		v.Keys = append(v.Keys, k)
		v.Fingerprint = append(v.Fingerprint, ssh.FingerprintSHA256(pub))
	}
	return v, nil
}

// describePendingHost writes the block host pending and host approve print
// for one pending host: the lines keyroster-agent identity prints on the
// host, for the comparison.
func describePendingHost(b *strings.Builder, v *pendingHostView) {
	fact := func(s string) string {
		if s == "" {
			return "unknown"
		}
		return s
	}
	fmt.Fprintf(b, "Pending host %s (enrolled %s)\n", v.Name, v.EnrolledAt)
	fmt.Fprintf(b, "  agent identity: %s\n", v.Identity)
	for i, k := range v.Keys {
		fmt.Fprintf(b, "  host key: %s %s\n", v.Fingerprint[i], strings.Fields(k)[0])
	}
	fmt.Fprintf(b, "  facts (the host's word): hostname %s, os %s %s, sshd %s\n",
		fact(v.Facts.Hostname), fact(v.Facts.OSID), fact(v.Facts.OSVersionID), fact(v.Facts.SSHDVersion))
}

// runHostPending is keyroster host pending [--admin-key FP]: the enrolled
// agents waiting for approval, with the fingerprints to compare.
func runHostPending(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host pending", flag.ContinueOnError)
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
	hosts, served, _, err := fetchPendingHosts(ctx, s)
	if err != nil {
		return err
	}
	var b strings.Builder
	if len(hosts) == 0 {
		b.WriteString("No host is waiting for approval.\n")
	}
	for _, h := range hosts {
		v, err := checkPendingHost(h)
		if err != nil {
			return err
		}
		describePendingHost(&b, v)
	}
	if len(hosts) > 0 {
		b.WriteString("Compare each fingerprint with `keyroster-agent identity` on the host, then run keyroster host approve NAME --group G --principal P.\n")
	}
	if len(served) > 0 {
		b.WriteString("Approved once and no longer in the directory as active; not waiting for approval (keyroster host forget ends the service):\n")
		for _, v := range served {
			fmt.Fprintf(&b, "Host %s: %s (agent identity %s)\n", v.Name, servedLine(v.State), v.Identity)
			fmt.Fprintf(&b, "  %s; enrolled %s\n", confirmationLine(&v), v.EnrolledAt)
			fmt.Fprintf(&b, "  forget it with: %s\n", forgetCommand(v.Identity))
		}
	}
	_, err = io.WriteString(stdout, b.String())
	return err
}

// runHostApprove is keyroster host approve NAME --group G --principal P...
// [--yes] [--out DIR] [--admin-key FP] (AGENT-01): shows the pending
// host's key and identity fingerprints and facts for the out-of-band
// comparison with keyroster-agent identity on the host, then signs a
// directory version with a new host entry NAME, the enrolled host keys,
// the host group and the principals the admin typed (the host add path).
// The server then treats the agent as approved while that entry is active
// with exactly those keys. Nothing about the entry comes from the host but
// its keys, which the agent proved it holds.
func runHostApprove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host approve", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	group := fset.String("group", "", "the host group the host belongs to (required; exactly one)")
	var principals, hostKeys stringList
	fset.Var(&principals, "principal", "a name clients use for the host, in its host certificate (repeatable, 1 to 8): short name, FQDN or address, lowercase, no trailing dot")
	fset.Var(&hostKeys, "host-key", "the SHA256 fingerprint of a host key, as keyroster-agent identity prints it on the host (repeatable: every host key; required with --yes)")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "host approve", pos)
	if err != nil {
		return err
	}
	if !directory.ValidUserName(name) {
		return errHostName("host", name)
	}
	if *group == "" || len(principals) == 0 {
		_, _ = fmt.Fprintln(stderr, "host approve: --group and at least one --principal are required")
		return errUsage
	}
	if !directory.ValidGroupName(*group) {
		return errGroupName(*group)
	}
	for _, p := range principals {
		if err := directory.CheckHostPrincipal(p); err != nil {
			return fmt.Errorf("%w; nothing was signed", err)
		}
	}
	// PR #71 review D-R4: with --yes nobody compares the fingerprints this
	// run prints, so the admin names the ones they compared on the host.
	if *ef.yes && len(hostKeys) == 0 {
		_, _ = fmt.Fprintln(stderr, "host approve: --yes needs --host-key SHA256:... for every host key the host has (keyroster-agent identity on the host prints them); nothing was signed")
		return errUsage
	}
	if len(hostKeys) > 0 {
		if err := trust.CheckPins(hostKeys, 1); err != nil {
			return fmt.Errorf("--host-key: %w; nothing was signed", err)
		}
	}
	s, err := openAdminSession(*ef.adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	hosts, served, _, err := fetchPendingHosts(ctx, s)
	if err != nil {
		return err
	}
	var match []*pendingHostView
	for _, h := range hosts {
		v, err := checkPendingHost(h)
		if err != nil {
			return err
		}
		if v.Name == name {
			match = append(match, v)
		}
	}
	switch len(match) {
	case 0:
		for _, v := range served {
			if v.Name == name {
				return fmt.Errorf("host %s was approved before and is now %s; it never waits for approval again, so it is not approved by name. "+
					"To give it access again, add its entry back with keyroster host add; to start over, forget that agent by its identity (%s) "+
					"and enroll it with a new join token (docs/runbooks/host-setup.md \"Removing a host\"). Nothing was signed",
					name, servedLine(v.State), forgetCommand(v.Identity))
			}
		}
		return fmt.Errorf("no enrolled host named %s is waiting for approval (keyroster host pending lists them); nothing was signed", name)
	case 1:
	default:
		return fmt.Errorf("%d enrolled agents wait under the name %s (two join tokens for one name were used); approving by this name is refused: "+
			"compare them with keyroster host pending and keyroster-agent identity on each host. Nothing was signed", len(match), name)
	}
	var b strings.Builder
	describePendingHost(&b, match[0])
	b.WriteString("Compare the agent identity and every host key fingerprint with `keyroster-agent identity` on the host, out of band, before you sign.\n")
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		return err
	}
	if len(hostKeys) > 0 && !sameFingerprints(hostKeys, match[0].Fingerprint) {
		return fmt.Errorf("the pending host %s has the host keys %s, not exactly the --host-key fingerprints you gave (%s); "+
			"compare again with keyroster-agent identity on the host. Nothing was signed",
			name, strings.Join(match[0].Fingerprint, ", "), strings.Join(hostKeys, ", "))
	}
	return editDirectory(ctx, s, editOpts{Yes: *ef.yes, Out: *ef.out}, stdout, func(d *directory.Directory, _ *trust.Policy) error {
		return addHostEntry(name, *group, match[0].Keys, principals)(d)
	})
}

// sameFingerprints reports whether a and b, each without repeats
// (trust.CheckPins and checkPendingHost refuse them), hold the same
// fingerprints: nothing missing and nothing extra.
func sameFingerprints(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

// forgetCandidate is an agent host forget can name (03-08b): from
// keyroster host pending, a pending agent (never approved) or a served one
// with its state, removal version and recorded confirmation (Listed);
// from keyroster host status, an agent the directory approves now, which
// only makes a name ambiguous and cannot be forgotten before its entry is
// removed.
type forgetCandidate struct {
	servedHostView
	SPKIHex      string // the identity's SPKI SHA-256, lowercase hex, as the request carries it
	ApprovedOnce bool
	Listed       bool   // in host pending's answer, with the facts a forget sends
	NotYetPolled bool   // host status: approved by the directory, not polled since (D-R2)
	EntryName    string // host status: the directory entry holding its keys (Name is the name it enrolled as)
}

// stateLine is how host forget shows a candidate's state.
func (c *forgetCandidate) stateLine() string {
	switch {
	case !c.Listed && c.NotYetPolled:
		return notYetPolled + " (" + c.entryClause() + ")"
	case !c.ApprovedOnce:
		return "pending, never approved"
	case !c.Listed:
		return c.State + " in the directory (" + c.entryClause() + ")"
	}
	return servedLine(c.State) + "; " + confirmationLine(&c.servedHostView)
}

// entryClause names the name a host status candidate enrolled as and the
// directory entry that holds its keys, which can differ (PR #74 review
// finding 4): `keyroster host remove` takes the entry's name.
func (c *forgetCandidate) entryClause() string {
	return "enrolled as " + c.Name + ", directory entry " + c.EntryName
}

// forgetCandidates are the agents host forget can name: the pending and
// served agents of host pending's answer, then each agent of host status
// that answer does not list (one the directory approves now).
func forgetCandidates(hosts []serverclient.PendingHost, served []servedHostView, status *serverclient.HostsStatusAnswer) ([]forgetCandidate, error) {
	var out []forgetCandidate
	seen := map[string]bool{}
	for _, h := range hosts {
		v, err := checkPendingHost(h)
		if err != nil {
			return nil, err
		}
		out = append(out, forgetCandidate{servedHostView: servedHostView{pendingHostView: *v}, SPKIHex: h.IdentitySPKISHA256, Listed: true})
		seen[h.IdentitySPKISHA256] = true
	}
	for _, v := range served {
		c := forgetCandidate{servedHostView: v, SPKIHex: identityHex(v.Identity), ApprovedOnce: true, Listed: true}
		out = append(out, c)
		seen[c.SPKIHex] = true
	}
	for _, r := range status.Hosts {
		if seen[r.IdentitySPKISHA256] {
			continue
		}
		spki, _ := hex.DecodeString(r.IdentitySPKISHA256) // checkHostsStatus checked it
		v := pendingHostView{Name: r.ExpectedName, Identity: enroll.IdentityFingerprint(spki)}
		out = append(out, forgetCandidate{servedHostView: servedHostView{pendingHostView: v, State: r.State}, SPKIHex: r.IdentitySPKISHA256, ApprovedOnce: true,
			NotYetPolled: r.NotYetPolled, EntryName: r.Name})
		seen[r.IdentitySPKISHA256] = true
	}
	return out, nil
}

// identityHex is the lowercase hex of the SPKI SHA-256 an identity
// fingerprint (enroll.IdentityFingerprint) names, "" when it names none.
func identityHex(fp string) string {
	b, err := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(fp, "SHA256:"))
	if err != nil || len(b) != 32 || !strings.HasPrefix(fp, "SHA256:") {
		return ""
	}
	return hex.EncodeToString(b)
}

// runHostForget is keyroster host forget [NAME] [--identity SHA256:...]
// [--host-gone] [--admin-key FP] (PR #71 review D-R1, 03-08b): the server
// deletes one agent, so its identity gets 403 unknown_agent from then on
// and its host keys can enroll again with a new join token. An agent
// approved once keeps getting signed state after its host entry is
// removed, so the removal and later revocations reach the host; forget
// ends that. In order:
//  1. it reads keyroster host pending (fetchPendingHosts), the pending and
//     served agents with the facts it sends, and keyroster host status,
//     for the agents the directory approves now; each answer checked;
//  2. it picks the agent by --identity, or by NAME when exactly one of
//     those agents has it: a name more than one agent has is refused
//     forget_name_ambiguous, listing each agent with its state and the
//     --identity command that names it, and nothing is sent. An agent the
//     directory approves now is refused: remove its entry first;
//  3. an agent approved once without a recorded removal confirmation (its
//     host's heartbeat never showed a directory that removed it) is
//     refused here, host_removal_not_applied, unless --host-gone is given
//     for a host that will never report again; --host-gone for an agent
//     confirmed or never approved is dropped, with a note;
//  4. it prints the agent, its state and the confirmation or the
//     override, and sends its identity with the facts it read (approved
//     once, the removal version, the confirmation, host_gone);
//  5. it checks that the server's answer names exactly that identity.
//
// The server refuses while a directory host entry still holds the
// agent's host keys (host_in_directory), and when the agent changed
// since step 1 (forget_state_changed).
func runHostForget(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host forget", flag.ContinueOnError)
	fset.SetOutput(stderr)
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	identity := fset.String("identity", "", "the agent identity to forget, SHA256:... as keyroster host pending prints it (needed when more than one agent has the name)")
	hostGone := fset.Bool("host-gone", false, "forget an agent approved once although its host never confirmed applying its removal (a host that is gone for good); printed and logged")
	pos, err := parseInterspersed(fset, args)
	if err != nil || len(pos) > 1 || (len(pos) == 0 && *identity == "") {
		_, _ = fmt.Fprintln(stderr, "host forget: want NAME, --identity SHA256:..., or both")
		return errUsage
	}
	name := ""
	if len(pos) == 1 {
		if name = pos[0]; !directory.ValidUserName(name) {
			return errHostName("host", name)
		}
	}
	if *identity != "" && (trust.CheckPins([]string{*identity}, 1) != nil || identityHex(*identity) == "") {
		return fmt.Errorf("--identity %q: want an agent identity fingerprint, SHA256:<base64> as keyroster host pending prints it; nothing was forgotten", *identity)
	}
	s, err := openAdminSession(*adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	hosts, served, pol, err := fetchPendingHosts(ctx, s)
	if err != nil {
		return err
	}
	status, err := fetchHostsStatus(ctx, s, pol)
	if err != nil {
		return err
	}
	cands, err := forgetCandidates(hosts, served, status)
	if err != nil {
		return err
	}
	c, err := pickForgetTarget(cands, name, *identity)
	if err != nil {
		return err
	}
	gone := *hostGone
	switch {
	case gone && (!c.ApprovedOnce || c.Confirmed != nil):
		why := "it was never approved, so it has no removal to wait for"
		if c.ApprovedOnce {
			why = "its host confirmed its removal"
		}
		_, _ = fmt.Fprintf(stderr, "host forget: --host-gone dropped for %s (%s): %s.\n", c.Name, c.Identity, why)
		gone = false
	case c.ApprovedOnce && c.Confirmed == nil && !gone:
		return errRemovalNotApplied(c.Identity)
	case gone:
		_, _ = fmt.Fprintf(stderr, "host forget --host-gone: forgetting %s without its confirmation that it applied its removal. "+
			"If the host is still running, it gets no more signed state from now on, revocations included, and keeps enforcing what it applied last. The server logs this override.\n", c.Name)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Forgetting agent %s, enrolled as %s: %s\n", c.Identity, c.Name, c.stateLine())
	if gone {
		b.WriteString("  override: --host-gone\n")
	}
	if _, err := io.WriteString(stdout, b.String()); err != nil {
		return err
	}
	req := serverclient.ForgetHostRequest{IdentitySPKISHA256: c.SPKIHex, ApprovedOnce: c.ApprovedOnce, RemovalVersion: c.RemovalVersion,
		RemovalConfirmed: c.Confirmed, HostGone: gone}
	var ans serverclient.ForgetHostAnswer
	if err := s.client.AdminJSON(ctx, http.MethodPost, serverclient.AdminForgetHostPath, req, &ans, s.signer); err != nil {
		if refusal := hostAdminRefusal(err); refusal != nil {
			return refusal
		}
		return adminError(err, s, pol)
	}
	if len(ans.Forgotten) != 1 {
		return errors.New("the server's forget answer does not name exactly the requested agent; the server may have forgotten other agents: check keyroster host pending")
	}
	v, err := checkPendingHost(ans.Forgotten[0])
	if err != nil || ans.Forgotten[0].IdentitySPKISHA256 != c.SPKIHex || v.Name != c.Name {
		return errors.New("the server's forget answer does not check out: it names another agent than the requested one; check keyroster host pending")
	}
	b.Reset()
	fmt.Fprintf(&b, "Forgot the agent enrolled as %s (enrolled %s)\n", v.Name, v.EnrolledAt)
	fmt.Fprintf(&b, "  agent identity: %s\n", v.Identity)
	for i, k := range v.Keys {
		fmt.Fprintf(&b, "  host key: %s %s\n", v.Fingerprint[i], strings.Fields(k)[0])
	}
	b.WriteString("Its identity gets unknown_agent from now on and receives no more signed state; its host keys can enroll again with a new join token.\n")
	if gone {
		b.WriteString("Forgotten with --host-gone: the host never confirmed that it applied its removal.\n")
	}
	_, err = io.WriteString(stdout, b.String())
	return err
}

// pickForgetTarget is the agent host forget names: the one with the
// identity fingerprint id when given (and then NAME, when given too, must
// be its name), otherwise the one agent named name.
func pickForgetTarget(cands []forgetCandidate, name, id string) (*forgetCandidate, error) {
	var match []*forgetCandidate
	for i := range cands {
		c := &cands[i]
		if (id == "" || c.Identity == id) && (name == "" || c.Name == name) {
			match = append(match, c)
		}
	}
	switch {
	case len(match) == 1 && match[0].Listed:
		return match[0], nil
	case len(match) == 1 && match[0].State == serverclient.HostStateActive:
		return nil, fmt.Errorf("the directory approves agent %s now (%s): remove that entry first (keyroster host remove %s), wait until the host "+
			"confirmed that version, then forget it (docs/runbooks/host-setup.md \"Removing a host\"). Nothing was forgotten",
			match[0].Identity, match[0].entryClause(), match[0].EntryName)
	case len(match) == 1:
		return nil, fmt.Errorf("agent %s changed while host pending and host status were read; run the command again. Nothing was forgotten", match[0].Identity)
	case len(match) > 1:
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %d agents are enrolled under the name %s, so the name does not say which one to forget; name it by its identity. Nothing was forgotten:", errForgetNameAmbiguous, len(match), name)
		for _, c := range match {
			fmt.Fprintf(&b, "\n  agent %s: %s", c.Identity, c.stateLine())
			if c.EnrolledAt != "" {
				fmt.Fprintf(&b, "; enrolled %s", c.EnrolledAt)
			}
			fmt.Fprintf(&b, "\n    %s", forgetCommand(c.Identity))
		}
		return nil, errors.New(b.String())
	case id != "":
		return nil, fmt.Errorf("no pending or served agent has the identity %s%s (keyroster host pending lists them; an agent the directory approves now is "+
			"forgotten only after keyroster host remove). Nothing was forgotten", id, nameClause(name))
	}
	return nil, fmt.Errorf("no pending or served agent is enrolled under the name %s (keyroster host pending lists them; a host the directory approves now is "+
		"forgotten only after keyroster host remove). Nothing was forgotten", name)
}

// errForgetNameAmbiguous is host forget's refusal of a name more than one
// agent has (03-08b); the CLI refuses it before it sends anything.
const errForgetNameAmbiguous = "forget_name_ambiguous"

// nameClause is " named NAME" for a given name.
func nameClause(name string) string {
	if name == "" {
		return ""
	}
	return " named " + name
}
