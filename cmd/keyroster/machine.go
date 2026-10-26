package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "machine",
		Summary: "machine identities in the directory: an automation's key, roles and max TTL (add, remove, list)",
		Run:     runMachine,
	})
}

func runMachine(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "machine: want a subcommand: add, remove or list")
		return errUsage
	}
	switch args[0] {
	case "add":
		return runMachineAdd(ctx, args[1:], stdout, stderr)
	case "remove":
		return runMachineRemove(ctx, args[1:], stdout, stderr)
	case "list":
		return runMachineList(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "machine: unknown subcommand %q; want add, remove or list\n", args[0])
		return errUsage
	}
}

// machineCap returns the max TTL of the root-signed policy's machine CA
// profile.
func machineCap(pol *trust.Policy) (uint64, error) {
	i := slices.IndexFunc(pol.CAProfiles, func(p trust.CAProfile) bool { return p.Role == trust.RoleMachine })
	if i < 0 {
		return 0, fmt.Errorf("the root-signed policy has no machine CA profile; nothing was signed")
	}
	return pol.CAProfiles[i].MaxTTLSeconds, nil
}

// runMachineAdd is keyroster machine add NAME --key FILE --role R...
// [--max-ttl D]: registers an automation identity (D-15) with its public
// key, the roles whose principals its certificates carry, and its max TTL
// (default: the machine CA cap of the root-signed policy). A role that no
// user or group grants is then checked against the machine CA profile
// instead of the user CA profile (directory.CheckPolicy).
func runMachineAdd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("machine add", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	keyFile := fset.String("key", "", "the machine's public key file (required; Ed25519, ECDSA or a security key)")
	var roles stringList
	fset.Var(&roles, "role", "a role the machine's certificates carry (repeatable, 1 to 16)")
	maxTTL := fset.Duration("max-ttl", 0, "the machine's max certificate TTL, at most the machine CA cap (default: that cap)")
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "machine add", pos)
	if err != nil {
		return err
	}
	if !directory.ValidUserName(name) {
		return errHostName("machine", name)
	}
	if *keyFile == "" || len(roles) == 0 {
		_, _ = fmt.Fprintln(stderr, "machine add: --key and at least one --role are required")
		return errUsage
	}
	for _, r := range roles {
		if !directory.ValidRoleName(r) {
			return errRoleName(r)
		}
	}
	if flagGiven(fset, "max-ttl") && (*maxTTL < directory.MinMachineTTLSeconds*time.Second || *maxTTL%time.Second != 0) {
		return fmt.Errorf("--max-ttl %s: use whole seconds, at least %ds; nothing was signed", *maxTTL, directory.MinMachineTTLSeconds)
	}
	key, err := readEntryKey(*keyFile)
	if err != nil {
		return err
	}
	s, err := openAdminSession(*ef.adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	return editDirectory(ctx, s, editOpts{Yes: *ef.yes, Out: *ef.out}, stdout, func(d *directory.Directory, pol *trust.Policy) error {
		if _, ok := d.MachineByName(name); ok {
			return fmt.Errorf("machine %s is already in the directory; remove it first to change it. Nothing was signed", name)
		}
		for _, r := range roles {
			if !slices.ContainsFunc(d.Roles, func(x directory.Role) bool { return x.Name == r }) {
				return fmt.Errorf("there is no role %q in the directory; nothing was signed", r)
			}
		}
		limit, err := machineCap(pol)
		if err != nil {
			return err
		}
		ttl := limit
		if flagGiven(fset, "max-ttl") {
			ttl = uint64(*maxTTL / time.Second) //nolint:gosec // G115: checked >= 60 s above
		}
		if ttl > limit {
			return fmt.Errorf("--max-ttl %s is above the machine CA cap %s of the root-signed policy; nothing was signed", *maxTTL, time.Duration(limit)*time.Second) //nolint:gosec // G115: a policy cap fits int64 nanoseconds
		}
		d.Machines = append(d.Machines, directory.Machine{
			Name: name, Key: key, Roles: slices.Clone([]string(roles)), MaxTTLSeconds: ttl, Status: directory.StatusActive,
		})
		return nil
	})
}

// runMachineRemove is keyroster machine remove NAME: removes the machine
// entry, so the signer no longer renews its certificates (03-11). A role
// that only this machine names and nobody grants falls back to the user
// CA profile (directory.CheckPolicy); when it exceeds that, the refusal
// names the role and the two ways out: add the replacement machine first
// (key rotation), or bring the role within the user CA profile first.
func runMachineRemove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("machine remove", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "machine remove", pos)
	if err != nil {
		return err
	}
	if !directory.ValidUserName(name) {
		return errHostName("machine", name)
	}
	var orphans []string // roles that no user, group or other machine uses after the removal
	err = ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i := slices.IndexFunc(d.Machines, func(m directory.Machine) bool { return m.Name == name })
		if i < 0 {
			return fmt.Errorf("there is no machine %s in the directory; nothing was signed", name)
		}
		roles := d.Machines[i].Roles
		d.Machines = slices.Delete(d.Machines, i, i+1)
		for _, r := range roles {
			named := slices.ContainsFunc(d.Machines, func(m directory.Machine) bool { return slices.Contains(m.Roles, r) })
			j := slices.IndexFunc(d.Roles, func(x directory.Role) bool { return x.Name == r })
			if !named && j >= 0 && len(d.Roles[j].Users) == 0 && len(d.Roles[j].Groups) == 0 {
				orphans = append(orphans, r)
			}
		}
		return nil
	})
	if !errors.Is(err, directory.ErrPolicy) {
		return err
	}
	// CheckPolicy stops at the first role it refuses and names it.
	for _, r := range orphans {
		if strings.Contains(err.Error(), "role "+r+": ") {
			return fmt.Errorf("%w. Removing machine %s leaves role %s granted to no user, group or machine, so the user CA profile applies to it. "+
				"To rotate the machine's key, add the new machine with that role first (keyroster machine add NEW --key FILE --role %s), then remove %s. "+
				"To remove the machine for good, first bring the role within the user CA profile (keyroster role update %s --max-ttl D), then remove %s",
				err, name, r, r, name, r, name)
		}
	}
	return err
}

// runMachineList is keyroster machine list [--admin-key FP]: the machines
// of the admin-signed directory the server serves, its signatures
// verified against the root-verified policy.
func runMachineList(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("machine list", flag.ContinueOnError)
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
	if vd.Version == 0 || len(vd.Dir.Machines) == 0 {
		fmt.Fprintf(&b, "Directory version %d names no machine.\n", vd.Version)
	} else {
		fmt.Fprintf(&b, "Machines of directory version %d (SHA-256 %s, admin signatures verified), installation %s:\n",
			vd.Version, vd.SHA256, installationText(vd.Dir.InstallationID))
		for _, line := range directory.Diff(&directory.Directory{}, &directory.Directory{Machines: vd.Dir.Machines}) {
			b.WriteString("  " + strings.TrimPrefix(line, "+ machine ") + "\n")
		}
	}
	b.WriteString(serverServesNote)
	_, err = io.WriteString(stdout, b.String())
	return err
}
