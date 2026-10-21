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
)

func init() {
	register(command{
		Name:    "user",
		Summary: "manage keyroster users on the server (add: create a pending account and its invite)",
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
		_, _ = fmt.Fprintln(stderr, "user: want a subcommand: add")
		return errUsage
	}
	switch args[0] {
	case "add":
		return runUserAdd(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "user: unknown subcommand %q; want add\n", args[0])
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
	_, err = io.WriteString(stdout, inviteText(cfg, name, inviteURL, expires.UTC()))
	return err
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
