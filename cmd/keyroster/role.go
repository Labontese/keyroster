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

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

func init() {
	register(command{
		Name:    "role",
		Summary: "manage roles: the principals, max TTL and extensions granted to users and groups (add, update, remove, grant, revoke)",
		Run:     runRole,
	})
}

// rolePrincipalPrefix is the D-06 convention, confirmed by the owner on
// 2026-10-22 (02-11 Task 1): a role grants role:<name> unless --principal
// says otherwise; a personal account is u:<username>.
const rolePrincipalPrefix = "role:"

func runRole(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "role: want a subcommand: add, update, remove, grant or revoke")
		return errUsage
	}
	switch args[0] {
	case "add":
		return runRoleAdd(ctx, args[1:], stdout, stderr)
	case "update":
		return runRoleUpdate(ctx, args[1:], stdout, stderr)
	case "remove":
		return runRoleRemove(ctx, args[1:], stdout, stderr)
	case "grant":
		return runRoleGrant(ctx, "grant", args[1:], stdout, stderr)
	case "revoke":
		return runRoleGrant(ctx, "revoke", args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "role: unknown subcommand %q; want add, update, remove, grant or revoke\n", args[0])
		return errUsage
	}
}

// editFlags are the flags of every command that edits the directory.
type editFlags struct {
	yes      *bool
	out      *string
	adminKey *string
}

func addEditFlags(fset *flag.FlagSet) editFlags {
	return editFlags{
		yes:      fset.Bool("yes", false, "sign without asking (needed when stdin is not a terminal); check the printed diff first"),
		out:      fset.String("out", "", "write a proposal directory for co-signing (keyroster directory sign, install) instead of installing"),
		adminKey: fset.String("admin-key", "", "SHA256 fingerprint of your admin key in ssh-agent (default: admin_key from keyroster init)"),
	}
}

// edit runs mutate through the directory pipeline (editDirectory): the
// verified base, Sort, Validate, CheckPolicy, the diff, confirmation and
// SSHSIG, then install or a proposal.
func (f editFlags) edit(ctx context.Context, stdout, stderr io.Writer, mutate func(d *directory.Directory) error) error {
	s, err := openAdminSession(*f.adminKey, stderr)
	if err != nil {
		return err
	}
	defer s.close()
	return editDirectory(ctx, s, editOpts{Yes: *f.yes, Out: *f.out}, stdout, func(d *directory.Directory, _ *trust.Policy) error {
		return mutate(d)
	})
}

// flagGiven reports whether the flag name was set on the command line.
func flagGiven(fset *flag.FlagSet, name string) bool {
	given := false
	fset.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}

// roleTTL converts --max-ttl to whole seconds: rounded to the second, at
// least directory.MinRoleTTLSeconds. The user CA cap is checked by
// CheckPolicy in the pipeline.
func roleTTL(role string, d time.Duration) (uint64, error) {
	d = d.Round(time.Second)
	if d < directory.MinRoleTTLSeconds*time.Second {
		return 0, fmt.Errorf("role %s: --max-ttl %s is below the minimum of 1m; nothing was signed", role, d)
	}
	return uint64(d / time.Second), nil //nolint:gosec // G115: d is at least one minute here
}

// checkRolePrincipals refuses, before anything is signed, the principals
// the signer would refuse (cert.ValidatePrincipals: 1 to 32, no empty
// value, wildcard, comma, whitespace or control character, no duplicate),
// naming the role and the offending principal.
func checkRolePrincipals(role string, ps []string) error {
	for _, p := range ps {
		if err := cert.ValidatePrincipals([]string{p}); err != nil {
			return fmt.Errorf("role %s: principal %q is not allowed (use a-z, 0-9 and . _ @ : + -, starting with a letter or digit, at most 128 characters; no wildcards, commas or whitespace); nothing was signed", role, p)
		}
	}
	if err := cert.ValidatePrincipals(ps); err != nil {
		return fmt.Errorf("role %s: %w; nothing was signed", role, err)
	}
	return nil
}

// findRole returns the index of role name in d, or an error naming it.
func findRole(d *directory.Directory, name string) (int, error) {
	i := slices.IndexFunc(d.Roles, func(r directory.Role) bool { return r.Name == name })
	if i < 0 {
		return -1, fmt.Errorf("there is no role %s in the directory; nothing was signed", name)
	}
	return i, nil
}

// requireUsers refuses user names the directory does not hold.
func requireUsers(d *directory.Directory, users []string) error {
	for _, u := range users {
		if !slices.ContainsFunc(d.Users, func(x directory.User) bool { return x.Name == u }) {
			return fmt.Errorf("there is no user %q in the directory; nothing was signed", u)
		}
	}
	return nil
}

// requireGroups refuses group names the directory does not hold.
func requireGroups(d *directory.Directory, groups []string) error {
	for _, g := range groups {
		if !slices.ContainsFunc(d.Groups, func(x directory.Group) bool { return x.Name == g }) {
			return fmt.Errorf("there is no group %q in the directory; nothing was signed", g)
		}
	}
	return nil
}

// oneName returns the single positional argument of verb, or errUsage.
func oneName(stderr io.Writer, verb string, pos []string) (string, error) {
	if len(pos) != 1 {
		_, _ = fmt.Fprintf(stderr, "%s: want exactly one name\n", verb)
		return "", errUsage
	}
	return pos[0], nil
}

// errRoleName refuses a role name outside the directory's grammar.
func errRoleName(name string) error {
	return fmt.Errorf("role name %q: use 1 to 32 characters a-z, 0-9, '.', '_' or '-', starting with a letter or digit", name)
}

// runRoleAdd is keyroster role add NAME --max-ttl D [--principal P]...
// [--extension E]... [--user U]... [--group G]...: a new role through the
// directory pipeline. Without --principal it grants role:NAME (D-06).
func runRoleAdd(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("role add", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ttl := fset.Duration("max-ttl", 0, "the longest certificate the role allows, as a Go duration (1h, 30m), at least 1m and at most the user CA cap (required)")
	var principals, extensions, users, groups stringList
	fset.Var(&principals, "principal", "a principal the role grants (repeatable; default role:NAME)")
	fset.Var(&extensions, "extension", "a certificate extension the role allows, from the user CA profile (repeatable)")
	fset.Var(&users, "user", "a user the role is granted to (repeatable)")
	fset.Var(&groups, "group", "a group the role is granted to (repeatable)")
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "role add", pos)
	if err != nil {
		return err
	}
	if !directory.ValidRoleName(name) {
		return errRoleName(name)
	}
	if !flagGiven(fset, "max-ttl") {
		_, _ = fmt.Fprintln(stderr, "role add: --max-ttl is required")
		return errUsage
	}
	secs, err := roleTTL(name, *ttl)
	if err != nil {
		return err
	}
	ps := []string(principals)
	if len(ps) == 0 {
		ps = []string{rolePrincipalPrefix + name}
	}
	if err := checkRolePrincipals(name, ps); err != nil {
		return err
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		if _, err := findRole(d, name); err == nil {
			return fmt.Errorf("role %s already exists; use keyroster role update. Nothing was signed", name)
		}
		if err := requireUsers(d, users); err != nil {
			return err
		}
		if err := requireGroups(d, groups); err != nil {
			return err
		}
		d.Roles = append(d.Roles, directory.Role{
			Name: name, Principals: slices.Clone(ps), MaxTTLSeconds: secs,
			Extensions: append([]string{}, extensions...), Users: append([]string{}, users...), Groups: append([]string{}, groups...),
		})
		return nil
	})
}

// runRoleUpdate is keyroster role update NAME [--max-ttl D]
// [--principal P]... [--extension E]... [--no-extensions]: a list flag
// that is given replaces the role's list, an omitted one keeps it;
// --no-extensions empties the extensions. Principals cannot be cleared (a
// role needs 1 to 32). Grants are left as they are (role grant, revoke).
func runRoleUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("role update", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ttl := fset.Duration("max-ttl", 0, "the new max TTL, as a Go duration, at least 1m and at most the user CA cap")
	var principals, extensions stringList
	fset.Var(&principals, "principal", "a principal the role grants (repeatable; replaces the role's principals)")
	fset.Var(&extensions, "extension", "an extension the role allows (repeatable; replaces the role's extensions)")
	noExt := fset.Bool("no-extensions", false, "remove every extension from the role")
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "role update", pos)
	if err != nil {
		return err
	}
	if !directory.ValidRoleName(name) {
		return errRoleName(name)
	}
	setTTL, setPrincipals, setExt := flagGiven(fset, "max-ttl"), len(principals) > 0, len(extensions) > 0
	if *noExt && setExt {
		return errors.New("--no-extensions and --extension contradict each other; give one of them. Nothing was signed")
	}
	if !setTTL && !setPrincipals && !setExt && !*noExt {
		_, _ = fmt.Fprintln(stderr, "role update: give --max-ttl, --principal, --extension or --no-extensions")
		return errUsage
	}
	var secs uint64
	if setTTL {
		if secs, err = roleTTL(name, *ttl); err != nil {
			return err
		}
	}
	if setPrincipals {
		if err := checkRolePrincipals(name, principals); err != nil {
			return err
		}
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i, err := findRole(d, name)
		if err != nil {
			return err
		}
		r := &d.Roles[i]
		if setTTL {
			r.MaxTTLSeconds = secs
		}
		if setPrincipals {
			r.Principals = slices.Clone([]string(principals))
		}
		switch {
		case setExt:
			r.Extensions = slices.Clone([]string(extensions))
		case *noExt:
			r.Extensions = []string{}
		}
		return nil
	})
}

// runRoleRemove is keyroster role remove NAME. It refuses while a host
// group maps the role, naming the host groups: unmap it first, so every
// account's principals file can be re-rendered.
func runRoleRemove(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("role remove", flag.ContinueOnError)
	fset.SetOutput(stderr)
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "role remove", pos)
	if err != nil {
		return err
	}
	if !directory.ValidRoleName(name) {
		return errRoleName(name)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i, err := findRole(d, name)
		if err != nil {
			return err
		}
		var mapped []string
		for _, h := range d.HostGroups {
			if slices.ContainsFunc(h.Accounts, func(a directory.AccountMap) bool { return slices.Contains(a.Roles, name) }) {
				mapped = append(mapped, h.Name)
			}
		}
		if len(mapped) > 0 {
			return fmt.Errorf("role %s is mapped by host group(s) %s; change those mappings with keyroster host-group map or unmap first. Nothing was signed",
				name, strings.Join(mapped, ", "))
		}
		d.Roles = slices.Delete(d.Roles, i, i+1)
		return nil
	})
}

// runRoleGrant is keyroster role grant|revoke NAME [--user U]...
// [--group G]...: adds the users and groups to the role's grants, or
// removes them. Granting what is granted already, or revoking what is
// not, is refused.
func runRoleGrant(ctx context.Context, verb string, args []string, stdout, stderr io.Writer) error {
	fset := flag.NewFlagSet("role "+verb, flag.ContinueOnError)
	fset.SetOutput(stderr)
	var users, groups stringList
	fset.Var(&users, "user", "a user (repeatable)")
	fset.Var(&groups, "group", "a group (repeatable)")
	ef := addEditFlags(fset)
	pos, err := parseInterspersed(fset, args)
	if err != nil {
		return errUsage
	}
	name, err := oneName(stderr, "role "+verb, pos)
	if err != nil {
		return err
	}
	if len(users) == 0 && len(groups) == 0 {
		_, _ = fmt.Fprintf(stderr, "role %s: give at least one --user or --group\n", verb)
		return errUsage
	}
	if !directory.ValidRoleName(name) {
		return errRoleName(name)
	}
	return ef.edit(ctx, stdout, stderr, func(d *directory.Directory) error {
		i, err := findRole(d, name)
		if err != nil {
			return err
		}
		r := &d.Roles[i]
		if verb == "grant" {
			if err := requireUsers(d, users); err != nil {
				return err
			}
			if err := requireGroups(d, groups); err != nil {
				return err
			}
			for _, u := range users {
				if slices.Contains(r.Users, u) {
					return fmt.Errorf("role %s is already granted to user %s; nothing was signed", name, u)
				}
				r.Users = append(r.Users, u)
			}
			for _, g := range groups {
				if slices.Contains(r.Groups, g) {
					return fmt.Errorf("role %s is already granted to group %s; nothing was signed", name, g)
				}
				r.Groups = append(r.Groups, g)
			}
			return nil
		}
		for _, u := range users {
			j := slices.Index(r.Users, u)
			if j < 0 {
				return fmt.Errorf("role %s is not granted to user %q directly; nothing was signed", name, u)
			}
			r.Users = slices.Delete(r.Users, j, j+1)
		}
		for _, g := range groups {
			j := slices.Index(r.Groups, g)
			if j < 0 {
				return fmt.Errorf("role %s is not granted to group %q; nothing was signed", name, g)
			}
			r.Groups = slices.Delete(r.Groups, j, j+1)
		}
		return nil
	})
}
