package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "host",
		Summary: "manual host setup (principals: render an account's AuthorizedPrincipalsFile; ca-key: the TrustedUserCAKeys line)",
		Run:     runHost,
	})
}

func runHost(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "host: want a subcommand: principals or ca-key")
		return errUsage
	}
	switch args[0] {
	case "principals":
		return runHostPrincipals(ctx, args[1:], stdout, stderr)
	case "ca-key":
		return runHostCAKey(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "host: unknown subcommand %q; want principals or ca-key\n", args[0])
		return errUsage
	}
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

// runHostPrincipals is keyroster host principals GROUP ACCOUNT
// [--admin-key FP]: the AuthorizedPrincipalsFile of ACCOUNT in host group
// GROUP, rendered with directory.RenderPrincipalsFile (the renderer the
// Phase 3 agent will use, D-07) from the admin-signed directory the server
// serves, its signatures verified against the root-verified policy
// (fetchVerifiedDirectory, 02-11-F7). stdout carries exactly the file. An
// account the host group does not map gets the header-only file, which
// grants nothing; an unknown host group is an error.
func runHostPrincipals(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host principals", flag.ContinueOnError)
	fset.SetOutput(stderr)
	adminKey := fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		_, _ = fmt.Fprintln(stderr, "host principals: want GROUP ACCOUNT")
		return errUsage
	}
	group, account := pos[0], pos[1]
	if !directory.ValidGroupName(group) {
		return errGroupName(group)
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
	file, err := directory.RenderPrincipalsFile(vd.Dir, group, account)
	if err != nil {
		if errors.Is(err, directory.ErrUnknownHostGroup) {
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
