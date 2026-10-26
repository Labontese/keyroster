package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Labontese/keyroster/internal/directory"
)

func init() {
	register(command{
		Name:    "host-group",
		Summary: "manage host groups: which roles each local account accepts in its principals file (add, remove, map, unmap)",
		Run:     runHostGroup,
	})
}

// hostGroupUsage is what keyroster host-group prints for a missing or an
// unknown subcommand. Its second line states the scope of host groups
// (D-07, 02-11-R2-F1).
const hostGroupUsage = "usage: keyroster host-group add|remove|map|unmap [arguments]\n" +
	"Host groups only decide what keyroster host principals renders (the AuthorizedPrincipalsFile content); they do not restrict certificate issuance, and certificates are not host-scoped.\n"

func runHostGroup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = io.WriteString(stderr, hostGroupUsage)
		return errUsage
	}
	switch args[0] {
	case "add":
		return runHostGroupAdd(ctx, args[1:], stdout, stderr)
	case "remove":
		return runHostGroupRemove(ctx, args[1:], stdout, stderr)
	case "map":
		return runHostGroupMap(ctx, args[1:], stdout, stderr)
	case "unmap":
		return runHostGroupUnmap(ctx, args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "keyroster host-group: unknown subcommand %q\n", args[0])
		_, _ = io.WriteString(stderr, hostGroupUsage)
		return errUsage
	}
}

// findHostGroup returns the index of host group name in d, or an error
// naming it.
func findHostGroup(d *directory.Directory, name string) (int, error) {
	i := slices.IndexFunc(d.HostGroups, func(h directory.HostGroup) bool { return h.Name == name })
	if i < 0 {
		return -1, fmt.Errorf("there is no host group %s in the directory; nothing was signed", name)
	}
	return i, nil
}

// errAccountName refuses an account name outside the directory's grammar.
func errAccountName(account string) error {
	return fmt.Errorf("account name %q: use 1 to 32 characters a-z, 0-9, '_', '.' or '-', starting with a letter or '_'; "+
		"account names are lowercase, also for Windows hosts", account)
}

// runHostGroupAdd is keyroster host-group add NAME: an empty host group.
func runHostGroupAdd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host-group add", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "host-group add", pos)
	if err != nil {
		return err
	}
	if !directory.ValidGroupName(name) {
		return errGroupName(name)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		if _, err := findHostGroup(d, name); err == nil {
			return fmt.Errorf("host group %s already exists; nothing was signed", name)
		}
		d.HostGroups = append(d.HostGroups, directory.HostGroup{Name: name, Accounts: []directory.AccountMap{}})
		return nil
	})
}

// runHostGroupRemove is keyroster host-group remove NAME. It refuses while
// a host names the host group (D-11; Validate refuses that directory too,
// this is the friendlier message), and while the host group maps an
// account: once the host group is gone, keyroster
// host principals can no longer render the header-only file that replaces
// an account's old grant (T-02-100). Unmap the accounts and install their
// re-rendered files first.
func runHostGroupRemove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host-group remove", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "host-group remove", pos)
	if err != nil {
		return err
	}
	if !directory.ValidGroupName(name) {
		return errGroupName(name)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i, err := findHostGroup(d, name)
		if err != nil {
			return err
		}
		// D-11: every host names exactly one existing host group.
		var hosts []string
		for _, h := range d.Hosts {
			if h.HostGroup == name {
				hosts = append(hosts, h.Name)
			}
		}
		if len(hosts) > 0 {
			return fmt.Errorf("host group %s is the host group of host(s) %s; remove each (keyroster host remove HOST) or register it again in another host group first. Nothing was signed",
				name, strings.Join(hosts, ", "))
		}
		if accounts := d.HostGroups[i].Accounts; len(accounts) > 0 {
			names := make([]string, len(accounts))
			for j, a := range accounts {
				names[j] = a.Account
			}
			return fmt.Errorf("host group %s still maps account(s) %s; unmap each (keyroster host-group unmap %s ACCOUNT), "+
				"re-render and install their principals files, then remove the host group. Nothing was signed",
				name, strings.Join(names, ", "), name)
		}
		d.HostGroups = slices.Delete(d.HostGroups, i, i+1)
		return nil
	})
}

// runHostGroupMap is keyroster host-group map NAME ACCOUNT ROLE...: sets
// the roles ACCOUNT accepts in host group NAME (at least one).
func runHostGroupMap(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host-group map", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) < 2 {
		_, _ = fmt.Fprintln(stderr, "host-group map: want NAME ACCOUNT ROLE...")
		return errUsage
	}
	name, account, roles := pos[0], pos[1], pos[2:]
	if !directory.ValidGroupName(name) {
		return errGroupName(name)
	}
	if !directory.ValidAccountName(account) {
		return errAccountName(account)
	}
	if len(roles) == 0 {
		return errors.New("give at least one role; to revoke the account's access use host-group unmap. Nothing was signed")
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i, err := findHostGroup(d, name)
		if err != nil {
			return err
		}
		for _, r := range roles {
			if !slices.ContainsFunc(d.Roles, func(x directory.Role) bool { return x.Name == r }) {
				return fmt.Errorf("there is no role %q in the directory; nothing was signed", r)
			}
		}
		h := &d.HostGroups[i]
		entry := directory.AccountMap{Account: account, Roles: slices.Clone(roles)}
		if j := slices.IndexFunc(h.Accounts, func(a directory.AccountMap) bool { return a.Account == account }); j >= 0 {
			h.Accounts[j] = entry
		} else {
			h.Accounts = append(h.Accounts, entry)
		}
		return nil
	})
}

// runHostGroupUnmap is keyroster host-group unmap NAME ACCOUNT: removes
// ACCOUNT's entry, so its re-rendered principals file grants nothing.
func runHostGroupUnmap(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("host-group unmap", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) != 2 {
		_, _ = fmt.Fprintln(stderr, "host-group unmap: want NAME ACCOUNT")
		return errUsage
	}
	name, account := pos[0], pos[1]
	if !directory.ValidGroupName(name) {
		return errGroupName(name)
	}
	if !directory.ValidAccountName(account) {
		return errAccountName(account)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i, err := findHostGroup(d, name)
		if err != nil {
			return err
		}
		h := &d.HostGroups[i]
		j := slices.IndexFunc(h.Accounts, func(a directory.AccountMap) bool { return a.Account == account })
		if j < 0 {
			return fmt.Errorf("host group %s maps no account %s; nothing was signed", name, account)
		}
		h.Accounts = slices.Delete(h.Accounts, j, j+1)
		return nil
	})
}
