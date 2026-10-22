package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/Labontese/keyroster/internal/directory"
)

func init() {
	register(command{
		Name:    "group",
		Summary: "manage groups: named sets of users that roles are granted to (add, remove, add-member, remove-member)",
		Run:     runGroup,
	})
}

func runGroup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "group: want a subcommand: add, remove, add-member or remove-member")
		return errUsage
	}
	switch args[0] {
	case "add":
		return runGroupAdd(ctx, args[1:], stdout, stderr)
	case "remove":
		return runGroupRemove(ctx, args[1:], stdout, stderr)
	case "add-member":
		return runGroupMembers(ctx, "add-member", args[1:], stdout, stderr)
	case "remove-member":
		return runGroupMembers(ctx, "remove-member", args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "group: unknown subcommand %q; want add, remove, add-member or remove-member\n", args[0])
		return errUsage
	}
}

// errGroupName refuses a group or host group name outside the directory's
// grammar.
func errGroupName(name string) error {
	return fmt.Errorf("name %q: use 1 to 64 characters a-z, 0-9, '.', '_' or '-', starting with a letter or digit", name)
}

// findGroup returns the index of group name in d, or an error naming it.
func findGroup(d *directory.Directory, name string) (int, error) {
	i := slices.IndexFunc(d.Groups, func(g directory.Group) bool { return g.Name == name })
	if i < 0 {
		return -1, fmt.Errorf("there is no group %s in the directory; nothing was signed", name)
	}
	return i, nil
}

// runGroupAdd is keyroster group add NAME [--member U]...
func runGroupAdd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("group add", flag.ContinueOnError)
	fset.SetOutput(stderr)
	var members stringList
	fset.Var(&members, "member", "a user in the group (repeatable)")
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "group add", pos)
	if err != nil {
		return err
	}
	if !directory.ValidGroupName(name) {
		return errGroupName(name)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		if _, err := findGroup(d, name); err == nil {
			return fmt.Errorf("group %s already exists; nothing was signed", name)
		}
		if err := requireUsers(d, members); err != nil {
			return err
		}
		d.Groups = append(d.Groups, directory.Group{Name: name, Members: append([]string{}, members...)})
		return nil
	})
}

// runGroupRemove is keyroster group remove NAME. It refuses while a role
// is granted to the group, naming every granting role (02-11-F6).
func runGroupRemove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("group remove", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "group remove", pos)
	if err != nil {
		return err
	}
	if !directory.ValidGroupName(name) {
		return errGroupName(name)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i, err := findGroup(d, name)
		if err != nil {
			return err
		}
		var granting []string
		for _, r := range d.Roles {
			if slices.Contains(r.Groups, name) {
				granting = append(granting, r.Name)
			}
		}
		if len(granting) > 0 {
			return fmt.Errorf("group %s is granted role(s) %s; revoke them first (keyroster role revoke ROLE --group %s). Nothing was signed",
				name, strings.Join(granting, ", "), name)
		}
		d.Groups = slices.Delete(d.Groups, i, i+1)
		return nil
	})
}

// runGroupMembers is keyroster group add-member|remove-member NAME U...
func runGroupMembers(ctx context.Context, verb string, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("group "+verb, flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	if len(pos) < 2 {
		_, _ = fmt.Fprintf(stderr, "group %s: want a group name and at least one user\n", verb)
		return errUsage
	}
	name, users := pos[0], pos[1:]
	if !directory.ValidGroupName(name) {
		return errGroupName(name)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i, err := findGroup(d, name)
		if err != nil {
			return err
		}
		g := &d.Groups[i]
		if verb == "add-member" {
			if err := requireUsers(d, users); err != nil {
				return err
			}
			for _, u := range users {
				if slices.Contains(g.Members, u) {
					return fmt.Errorf("%s is already a member of group %s; nothing was signed", u, name)
				}
				g.Members = append(g.Members, u)
			}
			return nil
		}
		for _, u := range users {
			j := slices.Index(g.Members, u)
			if j < 0 {
				return fmt.Errorf("%q is not a member of group %s; nothing was signed", u, name)
			}
			g.Members = slices.Delete(g.Members, j, j+1)
		}
		return nil
	})
}
