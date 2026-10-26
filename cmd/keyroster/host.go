package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "host",
		Summary: "hosts in the directory (add, remove, list) and manual host setup (principals: render an account's AuthorizedPrincipalsFile; ca-key: the TrustedUserCAKeys line)",
		Run:     runHost,
	})
}

const hostSubcommands = "add, remove, list, principals or ca-key"

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
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		if _, ok := d.HostByName(name); ok {
			return fmt.Errorf("host %s is already in the directory; remove it first to change it. Nothing was signed", name)
		}
		if _, err := findHostGroup(d, *group); err != nil {
			return err
		}
		d.Hosts = append(d.Hosts, directory.Host{
			Name: name, HostGroup: *group, Keys: keys, Principals: slices.Clone([]string(principals)), Status: directory.StatusActive,
		})
		return nil
	})
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
