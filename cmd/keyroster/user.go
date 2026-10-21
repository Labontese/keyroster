package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
)

func init() {
	register(command{
		Name:    "user",
		Summary: "manage keyroster users on the server (add: create a pending account and its invite; pending: show the passkey it registered)",
		Run:     runUser,
	})
}

// tlsRootFileName is the file name the printed keyroster init line reads
// the pinned TLS roots from; user add prints those roots to save under it.
const tlsRootFileName = "keyroster-tls-root.pem"

// errNoAdminKey refuses an admin command without an admin key.
var errNoAdminKey = errors.New("no admin key: pass --admin-key SHA256:<fingerprint> of an admin key from the root-signed policy " +
	"that is loaded in ssh-agent, or re-run keyroster init with --admin-key to save it")

func runUser(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "user: want a subcommand: add or pending")
		return errUsage
	}
	switch args[0] {
	case "add":
		return runUserAdd(ctx, args[1:], stdout, stderr)
	case "pending":
		return runUserPending(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "user: unknown subcommand %q; want add or pending\n", args[0])
		return errUsage
	}
}

// runUserAdd is keyroster user add NAME [--reinvite] [--admin-key FP]. It
// verifies the server's trust document against the saved root pins, asks
// the server, through the SSHSIG-authenticated admin API, for a pending
// account and an invite, and prints what the user needs: the invite URL,
// only when it is at a webauthn origin of the verified policy, the
// keyroster init line built from the admin's own verified config, and the
// pinned TLS root PEM that line reads. The pending account
// is not authority: it grants nothing until an admin-signed directory
// binds a passkey (D-03).
func runUserAdd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("user add", flag.ContinueOnError)
	fset.SetOutput(stderr)
	reinvite := fset.Bool("reinvite", false, "replace the invite of a pending account (the old link stops working), or invite a directory user to register one more passkey")
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	names, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(names) != 1 {
		_, _ = fmt.Fprintln(stderr, "user add: want exactly one user name")
		return errUsage
	}
	name := names[0]
	if !directory.ValidUserName(name) {
		return fmt.Errorf("user name %q: use 1 to 64 characters a-z, 0-9, '.', '_' or '-', starting with a letter or digit", name)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := checkInviteConfig(cfg); err != nil {
		return err
	}
	fp := *adminKey
	if fp == "" {
		fp = cfg.AdminKey
	}
	if fp == "" {
		return errNoAdminKey
	}
	if err := trust.CheckPins([]string{fp}, 1); err != nil {
		return fmt.Errorf("--admin-key: %w", err)
	}
	signer, closeAgent, err := adminSigner(fp)
	if err != nil {
		return err
	}
	defer closeAgent()

	client, err := serverclient.New(serverclient.Config{Server: cfg.Server, RootsPEM: cfg.TLSRootsPEM, Pins: cfg.TLSPins, Stderr: stderr})
	if err != nil {
		return err
	}
	// The invite's origin is checked against the policy the saved root
	// pins verify, read before the account is created: the server chooses
	// the invite URL, and a compromised one must not send the new user to
	// an origin of its own under the admin's name.
	_, policy, err := client.Trust(ctx, cfg.TrustPins, cfg.TrustThreshold)
	if err != nil {
		return err
	}
	if policy.WebAuthn == nil {
		return errors.New("the root-signed policy names no WebAuthn relying party, so the server cannot serve invites")
	}
	var resp serverclient.AddUserResponse
	err = client.AdminJSON(ctx, http.MethodPost, serverclient.AdminUsersPath, serverclient.AddUserRequest{Name: name, Reinvite: *reinvite}, &resp, signer)
	if err != nil {
		return adminOriginDiagnosis(userAddError(name, err), client.Server(), policy.WebAuthn.Origins)
	}
	origin, inviteURL, err := parseInviteURL(resp.InviteURL)
	if err != nil {
		return err
	}
	if !slices.Contains(policy.WebAuthn.Origins, origin) {
		return errNotPolicyOrigin
	}
	expires, err := time.Parse(time.RFC3339, resp.ExpiresAt)
	if err != nil {
		return errors.New("the server's answer has no valid invite expiry")
	}
	text := inviteText(cfg, name, inviteURL, expires.UTC())
	if *reinvite {
		text += reinviteText(name)
	}
	_, err = io.WriteString(stdout, text)
	return err
}

// reinviteText is what user add --reinvite adds: the old invite is gone,
// and so is any passkey registered with it that no directory binds yet. A
// proposal directory already written for the user still names that
// passkey; the server refuses to install it (02-09), and the admin
// discards it.
func reinviteText(name string) string {
	return fmt.Sprintf("\nThe previous invite for %s no longer works, and neither does any passkey %s registered with it that you have not approved yet. "+
		"If you already wrote a proposal directory for %s (keyroster user approve --out), discard it.\n", name, name, name)
}

// userAddError states the server's refusal of user add in the CLI's own
// words. The server's text is only compared with the known refusals; any
// other text reaches the user only as a PeerError excerpt.
func userAddError(name string, err error) error {
	var he *serverclient.HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusConflict {
		return err
	}
	switch {
	case he.APIErrorIs(serverclient.AdminErrPending):
		return fmt.Errorf("%s is already pending; nothing was changed. Use --reinvite to replace the invite (the old link stops working)", name)
	case he.APIErrorIs(serverclient.AdminErrInDirectory):
		return fmt.Errorf("%s is already in directory; nothing was changed. Use --reinvite to let %s register one more passkey", name, name)
	}
	return err
}

// errAdminOriginAdvice is the CLI's own advice that ends the diagnosis of
// adminOriginDiagnosis.
var errAdminOriginAdvice = errors.New("run keyroster init again with --server set to one of them")

// adminOriginDiagnosis names the cause of an admin authentication failure
// when server, the Client's canonical server URL, is not one of origins,
// the webauthn origins of the root-verified policy: the server accepts an
// admin request only at one of those, and answers any other with the same
// 401 as a bad signature. The origins printed are root-verified values in
// their validated canonical form, never text from the server's answer,
// and the CLI's own advice comes last (T-02-93). The diagnosis follows
// err's own text, so AdminJSON's clock hint stays as it wrote it. Any
// other error, and the failure at a server URL that is a policy origin,
// are returned unchanged.
func adminOriginDiagnosis(err error, server string, origins []string) error {
	if !errors.Is(err, serverclient.ErrAdminAuth) || slices.Contains(origins, server) {
		return err
	}
	return fmt.Errorf("%w. The saved server URL %s is not a webauthn origin of the root-signed policy (%s), and the server accepts admin requests only there; %w",
		err, server, strings.Join(origins, ", "), errAdminOriginAdvice)
}

// adminSigner finds the admin key with fingerprint fp in ssh-agent and
// returns agentSigner for it: the private key never leaves the agent.
func adminSigner(fp string) (ssh.Signer, func(), error) {
	conn, err := dialAgent()
	if err != nil {
		return nil, nil, err
	}
	keys, err := agent.NewClient(conn).List()
	_ = conn.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("list ssh-agent keys: %w", err)
	}
	for _, k := range keys {
		pub, err := ssh.ParsePublicKey(k.Blob)
		if err != nil || strings.HasSuffix(pub.Type(), "-cert-v01@openssh.com") {
			continue
		}
		if ssh.FingerprintSHA256(pub) == fp {
			return agentSigner(pub)
		}
	}
	return nil, nil, fmt.Errorf("ssh-agent does not hold the admin key %s; load it with ssh-add", fp)
}

// checkInviteConfig checks every config value the init line repeats, so
// the line holds only validated values from alphabets without shell
// metacharacters: the server URL, sha256/ TLS pins, the pinned roots and
// SHA256: root pins with a threshold.
func checkInviteConfig(cfg *Config) error {
	u, err := serverclient.ParseServerURL(cfg.Server)
	if err != nil || u.String() != cfg.Server {
		return errors.New("the saved config has no valid server URL; run keyroster init again")
	}
	if len(cfg.TLSPins) == 0 || len(cfg.TLSRootsPEM) == 0 {
		return errors.New("the saved config has no pinned TLS roots; run keyroster init again")
	}
	for _, p := range cfg.TLSPins {
		if err := serverclient.CheckPin(p); err != nil {
			return fmt.Errorf("the saved config: %w", err)
		}
	}
	for _, r := range cfg.TLSRootsPEM {
		if _, err := serverclient.ParseRoots([]byte(r)); err != nil {
			return fmt.Errorf("the saved config: %w", err)
		}
	}
	if err := trust.CheckPins(cfg.TrustPins, cfg.TrustThreshold); err != nil {
		return fmt.Errorf("the saved config's root pins: %w", err)
	}
	return nil
}

// errNotPolicyOrigin refuses an invite URL whose origin the verified
// policy does not name. It never repeats the URL.
var errNotPolicyOrigin = errors.New("the server's invite URL is not at a webauthn origin of the root-signed policy, so it was not printed. " +
	"Check the server before you re-run with --reinvite (the account may now be pending)")

// parseInviteURL reads the server's invite URL as structured data, never
// as text: an origin that ParseServerURL accepts, the path /enroll/ and a
// 43-character base64url token, nothing else. It returns the canonical
// origin and the URL rebuilt from those parts; the caller checks the
// origin against the verified policy.
func parseInviteURL(s string) (origin, inviteURL string, err error) {
	bad := errors.New("the server's answer has no valid invite URL")
	u, err := url.Parse(s)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || u.RawPath != "" {
		return "", "", bad
	}
	token, ok := strings.CutPrefix(u.Path, "/enroll/")
	if !ok || !validToken(token) {
		return "", "", bad
	}
	o, err := serverclient.ParseServerURL(u.Scheme + "://" + u.Host)
	if err != nil {
		return "", "", bad
	}
	return o.String(), o.String() + "/enroll/" + token, nil
}

// validToken reports whether t is 32 bytes as unpadded base64url.
func validToken(t string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(t)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == t
}

// inviteText is what user add prints: the invite, the init line for the
// user and the pinned TLS roots that line reads. Exactly one line starts
// with "keyroster init ".
func inviteText(cfg *Config, name, inviteURL string, expires time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Invite for %s: %s\n", name, inviteURL)
	fmt.Fprintf(&b, "The invite expires at %s.\n\n", expires.Format(time.RFC3339))
	fmt.Fprintf(&b, "%s runs this command after saving the TLS root below as %s:\n\n", name, tlsRootFileName)
	line := []string{"keyroster", "init", "--server", cfg.Server, "--tls-root-file", tlsRootFileName}
	for _, p := range cfg.TLSPins {
		line = append(line, "--tls-pin", p)
	}
	for _, p := range cfg.TrustPins {
		line = append(line, "--root-pin", p)
	}
	line = append(line, "--threshold", strconv.Itoa(cfg.TrustThreshold), "--user", name)
	b.WriteString(strings.Join(line, " "))
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "Save the following as %s:\n", tlsRootFileName)
	for _, r := range cfg.TLSRootsPEM {
		b.WriteString(strings.TrimRight(r, "\n"))
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "\nSend the invite URL, the command and %s to %s out of band, over a channel you trust. "+
		"The account grants nothing until you approve the passkey %s registers.\n", tlsRootFileName, name, name)
	return b.String()
}

// parseInterspersed parses fset's flags anywhere among args and returns
// the positional arguments in order.
func parseInterspersed(fset *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fset.Parse(args); err != nil {
			return nil, err
		}
		args = fset.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// runUserPending is keyroster user pending NAME [--admin-key FP]: it asks
// the server, through the SSHSIG-authenticated admin API, for the passkey
// the pending account NAME registered through its invite, and prints its
// fingerprint, algorithm, backup flags and registration time, so the admin
// can compare the fingerprint with the one the user read off the
// registration page. With no passkey yet it says whether the invite is
// open (until when), expired or used, and advises a reinvite for the last
// two. Every value printed is re-derived from validated data: the
// fingerprint is computed from the SPKI after webauthn.ParsePublicKey
// accepted it for its algorithm, never taken from the server's text, and
// the invite state is one of three known words with an RFC 3339 time
// (T-02-93). A pending passkey grants nothing until an admin-signed
// directory binds it (02-09).
func runUserPending(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("user pending", flag.ContinueOnError)
	fset.SetOutput(stderr)
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	names, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(names) != 1 {
		_, _ = fmt.Fprintln(stderr, "user pending: want exactly one user name")
		return errUsage
	}
	name := names[0]
	if !directory.ValidUserName(name) {
		return fmt.Errorf("user name %q: use 1 to 64 characters a-z, 0-9, '.', '_' or '-', starting with a letter or digit", name)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := checkInviteConfig(cfg); err != nil {
		return err
	}
	fp := *adminKey
	if fp == "" {
		fp = cfg.AdminKey
	}
	if fp == "" {
		return errNoAdminKey
	}
	if err := trust.CheckPins([]string{fp}, 1); err != nil {
		return fmt.Errorf("--admin-key: %w", err)
	}
	signer, closeAgent, err := adminSigner(fp)
	if err != nil {
		return err
	}
	defer closeAgent()
	client, err := serverclient.New(serverclient.Config{Server: cfg.Server, RootsPEM: cfg.TLSRootsPEM, Pins: cfg.TLSPins, Stderr: stderr})
	if err != nil {
		return err
	}
	var resp serverclient.PendingAnswer
	err = client.AdminJSON(ctx, http.MethodGet, serverclient.AdminPendingPath(name), nil, &resp, signer)
	if err != nil {
		if errors.Is(err, serverclient.ErrAdminAuth) {
			// Name the cause when the saved server URL is not a policy
			// origin, from the root-verified policy only.
			if _, policy, terr := client.Trust(ctx, cfg.TrustPins, cfg.TrustThreshold); terr == nil && policy.WebAuthn != nil {
				return adminOriginDiagnosis(err, client.Server(), policy.WebAuthn.Origins)
			}
		}
		var he *serverclient.HTTPError
		if errors.As(err, &he) && he.Code == http.StatusNotFound && he.APIErrorIs(serverclient.AdminErrNotPending) {
			return fmt.Errorf("%s is not pending: no invite is open for that name. Use keyroster user add %s to invite them", name, name)
		}
		return err
	}
	inv, err := checkPendingInvite(resp.Invite)
	if err != nil {
		return err
	}
	creds := make([]pendingCredential, 0, len(resp.Credentials))
	for _, c := range resp.Credentials {
		pc, err := checkPendingCredential(c)
		if err != nil {
			return err
		}
		creds = append(creds, pc)
	}
	_, err = io.WriteString(stdout, pendingText(name, inv, creds))
	return err
}

// pendingCredential is one pending passkey as user pending prints it,
// every field re-derived or re-formatted by the CLI.
type pendingCredential struct {
	fingerprint    string
	alg            string
	backupEligible bool
	backedUp       bool
	registered     time.Time
}

// errBadPendingAnswer refuses a pending list the CLI cannot check. It
// never repeats the server's text.
var errBadPendingAnswer = errors.New("the server's pending passkey list does not check out, so nothing was printed")

// checkPendingCredential validates one entry of the server's pending
// list: the ID is canonical unpadded base64url of 1 to 1023 bytes, the
// SPKI canonical standard base64 that webauthn.ParsePublicKey accepts for
// the algorithm (EdDSA, ES256 or RS256), the server's fingerprint equals
// the one computed from that SPKI, and the time is RFC 3339. The
// fingerprint returned is the computed one.
func checkPendingCredential(c serverclient.PendingCredential) (pendingCredential, error) {
	id, err := base64.RawURLEncoding.Strict().DecodeString(c.ID)
	if err != nil || len(id) == 0 || len(id) > 1023 || base64.RawURLEncoding.EncodeToString(id) != c.ID {
		return pendingCredential{}, errBadPendingAnswer
	}
	var alg string
	switch c.Alg {
	case webauthn.AlgEdDSA:
		alg = "EdDSA"
	case webauthn.AlgES256:
		alg = "ES256"
	case webauthn.AlgRS256:
		alg = "RS256"
	default:
		return pendingCredential{}, errBadPendingAnswer
	}
	spki, err := base64.StdEncoding.Strict().DecodeString(c.SPKI)
	if err != nil || len(spki) == 0 || base64.StdEncoding.EncodeToString(spki) != c.SPKI {
		return pendingCredential{}, errBadPendingAnswer
	}
	if _, err := webauthn.ParsePublicKey(c.Alg, spki); err != nil {
		return pendingCredential{}, errBadPendingAnswer
	}
	fp := webauthn.Fingerprint(spki)
	if c.Fingerprint != fp {
		return pendingCredential{}, errBadPendingAnswer
	}
	if c.BackedUp && !c.BackupEligible {
		return pendingCredential{}, errBadPendingAnswer
	}
	reg, err := time.Parse(time.RFC3339, c.RegisteredAt)
	if err != nil {
		return pendingCredential{}, errBadPendingAnswer
	}
	return pendingCredential{fingerprint: fp, alg: alg, backupEligible: c.BackupEligible, backedUp: c.BackedUp, registered: reg.UTC()}, nil
}

// pendingInvite is the invite state user pending prints, validated by
// checkPendingInvite.
type pendingInvite struct {
	state   string // serverclient.InviteOpen, InviteExpired or InviteUsed
	expires time.Time
}

// checkPendingInvite validates the invite state of the server's pending
// answer: one of the three states and an RFC 3339 time. It never repeats
// the server's text.
func checkPendingInvite(i serverclient.PendingInvite) (pendingInvite, error) {
	switch i.State {
	case serverclient.InviteOpen, serverclient.InviteExpired, serverclient.InviteUsed:
	default:
		return pendingInvite{}, errBadPendingAnswer
	}
	exp, err := time.Parse(time.RFC3339, i.ExpiresAt)
	if err != nil {
		return pendingInvite{}, errBadPendingAnswer
	}
	return pendingInvite{state: i.State, expires: exp.UTC()}, nil
}

// pendingText is what user pending prints: with no passkey yet, the
// invite's state in the CLI's own words, and the advice last.
func pendingText(name string, inv pendingInvite, creds []pendingCredential) string {
	if len(creds) == 0 {
		at := inv.expires.Format(time.RFC3339)
		switch inv.state {
		case serverclient.InviteExpired:
			return fmt.Sprintf("The invite for %s expired at %s, and no passkey was registered with it. "+
				"Run keyroster user add %s --reinvite to send a new invite.\n", name, at, name)
		case serverclient.InviteUsed:
			return fmt.Sprintf("The invite for %s was used, and no passkey is pending approval. "+
				"To let %s register a passkey again, run keyroster user add %s --reinvite.\n", name, name, name)
		}
		return fmt.Sprintf("%s has an open invite, valid until %s, but has not registered a passkey yet.\n", name, at)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Pending passkey for %s, not approved yet:\n", name)
	for _, c := range creds {
		fmt.Fprintf(&b, "\n  fingerprint  %s\n", c.fingerprint)
		fmt.Fprintf(&b, "  algorithm    %s\n", c.alg)
		fmt.Fprintf(&b, "  synced       %s (backup eligible: %s)\n", yesNo(c.backedUp), yesNo(c.backupEligible))
		fmt.Fprintf(&b, "  registered   %s\n", c.registered.Format(time.RFC3339))
	}
	fmt.Fprintf(&b, "\nCompare the fingerprint with the one %s read off the registration page, over a channel you trust, before you approve it.\n", name)
	return b.String()
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
