package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// roleBase returns a mutation that builds the base directory of the role
// tests: users alice and bob, group devs with alice, role ops (role:ops,
// 1 h) granted to alice and to devs, role dev2 (role:dev2) granted to devs,
// and host group web mapping root to ops; then extra.
func roleBase(t *testing.T, extra func(d *directory.Directory)) func(d *directory.Directory) {
	t.Helper()
	alice, _ := pendingEntry(t, webauthn.AlgES256)
	bob, _ := pendingEntry(t, webauthn.AlgEdDSA)
	return func(d *directory.Directory) {
		addUser("alice", credOf(alice))(d)
		addUser("bob", credOf(bob))(d)
		d.Groups = []directory.Group{{Name: "devs", Members: []string{"alice"}}}
		d.Roles = []directory.Role{
			{Name: "dev2", Principals: []string{"role:dev2"}, MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{}, Groups: []string{"devs"}},
			{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{"alice"}, Groups: []string{"devs"}},
		}
		d.HostGroups = []directory.HostGroup{{Name: "web", Accounts: []directory.AccountMap{{Account: "root", Roles: []string{"ops"}}}}}
		if extra != nil {
			extra(d)
		}
	}
}

// roleEnv is a fake server with the role base installed as version 1.
func roleEnv(t *testing.T, extra func(d *directory.Directory)) *dirEnv {
	t.Helper()
	e := newDirEnv(t, 1, 1)
	e.installDirect(t, buildDir(t, nil, roleBase(t, extra)))
	return e
}

// installedDir parses the fake server's installed directory.
func installedDir(t *testing.T, e *dirEnv) *directory.Directory {
	t.Helper()
	doc, _ := e.installed()
	d, err := directory.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// requireVersion fails unless the installed directory is version v.
func requireVersion(t *testing.T, e *dirEnv, v uint64) {
	t.Helper()
	if d := installedDir(t, e); d.Version != v {
		t.Fatalf("installed version %d, want %d", d.Version, v)
	}
}

func roleOf(t *testing.T, d *directory.Directory, name string) directory.Role {
	t.Helper()
	i := slices.IndexFunc(d.Roles, func(r directory.Role) bool { return r.Name == name })
	if i < 0 {
		t.Fatalf("no role %s in %+v", name, d.Roles)
	}
	return d.Roles[i]
}

// TestRoleRefusals: every refusal comes before signing: the agent is never
// asked for a directory signature and nothing is posted.
func TestRoleRefusals(t *testing.T) {
	cases := []struct {
		name  string
		extra func(d *directory.Directory)
		args  []string
		want  []string // substrings of stderr
	}{
		{name: "wildcard_principal_refused", args: []string{"role", "add", "x", "--max-ttl", "1h", "--principal", "*"}, want: []string{"role x", `principal "*" is not allowed`}},
		{name: "comma_principal_refused", args: []string{"role", "add", "x", "--max-ttl", "1h", "--principal", "a,b"}, want: []string{"role x", `principal "a,b" is not allowed`}},
		{name: "space_principal_refused", args: []string{"role", "add", "x", "--max-ttl", "1h", "--principal", "a b"}, want: []string{"role x", `principal "a b" is not allowed`}},
		{name: "empty_principal_refused", args: []string{"role", "add", "x", "--max-ttl", "1h", "--principal", ""}, want: []string{"role x", `principal "" is not allowed`}},
		{name: "tab_principal_refused", args: []string{"role", "update", "ops", "--principal", "a\tb"}, want: []string{"role ops", `principal "a\tb" is not allowed`}},
		{name: "duplicate_principal_refused", args: []string{"role", "add", "x", "--max-ttl", "1h", "--principal", "p", "--principal", "p"}, want: []string{"role x", "duplicate"}},
		{name: "ttl_above_cap_refused", args: []string{"role", "add", "x", "--max-ttl", "13h"}, want: []string{"role x", "above the user CA cap"}},
		{name: "ttl_below_minimum_refused", args: []string{"role", "add", "x", "--max-ttl", "30s"}, want: []string{"role x", "below the minimum of 1m"}},
		{name: "extension_not_allowed_refused", args: []string{"role", "update", "ops", "--extension", "permit-port-forwarding"}, want: []string{"role ops", `"permit-port-forwarding" is not allowed by the user CA profile`}},
		{name: "grant_unknown_user_refused", args: []string{"role", "grant", "ops", "--user", "carol"}, want: []string{`no user "carol"`}},
		{name: "grant_unknown_group_refused", args: []string{"role", "grant", "ops", "--group", "admins"}, want: []string{`no group "admins"`}},
		{name: "role_add_unknown_user_refused", args: []string{"role", "add", "x", "--max-ttl", "1h", "--user", "carol"}, want: []string{`no user "carol"`}},
		{name: "unknown_role_mapping_refused", args: []string{"host-group", "map", "web", "root", "nosuch"}, want: []string{`no role "nosuch"`}},
		{name: "uppercase_account_refused", args: []string{"host-group", "map", "web", "Root", "ops"}, want: []string{`account name "Root"`, "lowercase"}},
		{name: "remove_mapped_role_refused", args: []string{"role", "remove", "ops"}, want: []string{"role ops is mapped by host group(s) web"}},
		{name: "remove_granted_group_refused", args: []string{"group", "remove", "devs"}, want: []string{"group devs is granted role(s) dev2, ops"}},
		{name: "map_zero_roles_refused", args: []string{"host-group", "map", "web", "root"}, want: []string{"give at least one role; to revoke the account's access use host-group unmap"}},
		{name: "no_extensions_with_extension_refused", args: []string{"role", "update", "ops", "--no-extensions", "--extension", "permit-pty"}, want: []string{"--no-extensions and --extension"}},
		{name: "unmap_unmapped_account_refused", args: []string{"host-group", "unmap", "web", "deploy"}, want: []string{"host group web maps no account deploy"}},
		{name: "remove_host_group_with_accounts_refused", args: []string{"host-group", "remove", "web"}, want: []string{"host group web still maps account(s) root"}},
		{name: "duplicate_role_refused", args: []string{"role", "add", "ops", "--max-ttl", "1h"}, want: []string{"role ops already exists"}},
		{name: "grant_twice_refused", args: []string{"role", "grant", "ops", "--user", "alice"}, want: []string{"already granted to user alice"}},
		{name: "revoke_not_granted_refused", args: []string{"role", "revoke", "ops", "--user", "bob"}, want: []string{`not granted to user "bob"`}},
		{name: "add_member_unknown_user_refused", args: []string{"group", "add-member", "devs", "carol"}, want: []string{`no user "carol"`}},
		{
			name: "too_many_roles_refused",
			extra: func(d *directory.Directory) {
				for i := range directory.MaxRolesPerUser - 2 { // ops and dev2 make 16
					d.Roles = append(d.Roles, directory.Role{Name: fmt.Sprintf("r%02d", i), Principals: []string{fmt.Sprintf("role:r%02d", i)}, MaxTTLSeconds: 3600, Users: []string{"alice"}})
				}
			},
			args: []string{"role", "add", "r99", "--max-ttl", "1h", "--user", "alice"},
			want: []string{"user alice has more than 16 roles"},
		},
		{
			name: "too_many_principals_refused",
			extra: func(d *directory.Directory) {
				var ps []string
				for i := range 30 { // with role:ops and role:dev2, 32
					ps = append(ps, fmt.Sprintf("p%02d", i))
				}
				d.Roles = append(d.Roles, directory.Role{Name: "big", Principals: ps, MaxTTLSeconds: 3600, Users: []string{"alice"}})
			},
			args: []string{"role", "add", "x", "--max-ttl", "1h", "--user", "alice"},
			want: []string{"user alice would get 33 principals"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := roleEnv(t, c.extra)
			code, stdout, stderr := run(t, append(c.args, "--yes")...)
			if code == 0 {
				t.Fatalf("keyroster %q: exit 0, want a refusal; stdout:\n%s", c.args, stdout)
			}
			for _, w := range c.want {
				if !strings.Contains(stderr, w) {
					t.Fatalf("keyroster %q: exit %d, stderr %q does not contain %q", c.args, code, stderr, w)
				}
			}
			requireNotSigned(t, e, 0)
		})
	}
}

// TestRoleEdits: the role, group and host-group edits that sign, through
// the pipeline, the version their diff shows.
func TestRoleEdits(t *testing.T) {
	t.Run("role_add_default_principal", func(t *testing.T) {
		e := roleEnv(t, nil)
		code, stdout, stderr := run(t, "role", "add", "deploy", "--max-ttl", "90m", "--group", "devs", "--yes")
		if code != 0 || !strings.Contains(stdout, "+ role deploy principals=[role:deploy] max_ttl_seconds=5400 extensions=[] users=[] groups=[devs]") {
			t.Fatalf("role add deploy: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		r := roleOf(t, installedDir(t, e), "deploy")
		if !slices.Equal(r.Principals, []string{"role:deploy"}) || r.MaxTTLSeconds != 5400 {
			t.Fatalf("installed role deploy = %+v, want principals [role:deploy] and 5400 s", r)
		}
	})

	t.Run("role_add_with_principals_on_genesis", func(t *testing.T) {
		// A role can be the first version: no user is needed.
		e := newDirEnv(t, 1, 1)
		code, stdout, stderr := run(t, "role", "add", "alice-personal", "--max-ttl", "1h", "--principal", "u:alice", "--yes")
		if code != 0 || !strings.Contains(stdout, "Directory version 1 (the first") {
			t.Fatalf("role add on genesis: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if r := roleOf(t, installedDir(t, e), "alice-personal"); !slices.Equal(r.Principals, []string{"u:alice"}) {
			t.Fatalf("installed principals %q, want [u:alice]", r.Principals)
		}
	})

	t.Run("role_update_replaces_principals_keeps_grants", func(t *testing.T) {
		e := roleEnv(t, nil)
		code, stdout, stderr := run(t, "role", "update", "ops", "--principal", "role:ops", "--principal", "u:alice", "--yes")
		if code != 0 ||
			!strings.Contains(stdout, "- role ops principals=[role:ops] max_ttl_seconds=3600 extensions=[] users=[alice] groups=[devs]") ||
			!strings.Contains(stdout, "+ role ops principals=[role:ops u:alice] max_ttl_seconds=3600 extensions=[] users=[alice] groups=[devs]") {
			t.Fatalf("role update ops: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if r := roleOf(t, installedDir(t, e), "ops"); !slices.Equal(r.Principals, []string{"role:ops", "u:alice"}) ||
			!slices.Equal(r.Users, []string{"alice"}) || !slices.Equal(r.Groups, []string{"devs"}) {
			t.Fatalf("installed role ops = %+v, want the new principals and the grants unchanged", r)
		}
	})

	t.Run("role_update_clears_extensions", func(t *testing.T) {
		e := newDirEnvPolicy(t, 1, 1, func(p *trust.Policy) {
			for i := range p.CAProfiles {
				if p.CAProfiles[i].Role == trust.RoleUser {
					p.CAProfiles[i].AllowedExtensions = []string{"permit-agent-forwarding"}
				}
			}
		})
		e.installDirect(t, buildDir(t, nil, roleBase(t, func(d *directory.Directory) {
			d.Roles[1].Extensions = []string{"permit-agent-forwarding"}
		})))
		// No list flag: the extensions stay.
		code, stdout, stderr := run(t, "role", "update", "ops", "--max-ttl", "2h", "--yes")
		if code != 0 || !strings.Contains(stdout, "+ role ops principals=[role:ops] max_ttl_seconds=7200 extensions=[permit-agent-forwarding] users=[alice] groups=[devs]") {
			t.Fatalf("role update ops --max-ttl 2h: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		code, stdout, stderr = run(t, "role", "update", "ops", "--no-extensions", "--yes")
		if code != 0 ||
			!strings.Contains(stdout, "- role ops principals=[role:ops] max_ttl_seconds=7200 extensions=[permit-agent-forwarding] users=[alice] groups=[devs]") ||
			!strings.Contains(stdout, "+ role ops principals=[role:ops] max_ttl_seconds=7200 extensions=[] users=[alice] groups=[devs]") {
			t.Fatalf("role update ops --no-extensions: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if r := roleOf(t, installedDir(t, e), "ops"); len(r.Extensions) != 0 {
			t.Fatalf("installed extensions %q, want none", r.Extensions)
		}
	})

	t.Run("grant_and_revoke", func(t *testing.T) {
		e := roleEnv(t, nil)
		if code, stdout, stderr := run(t, "role", "grant", "dev2", "--user", "bob", "--yes"); code != 0 || !strings.Contains(stdout, "+ role dev2 principals=[role:dev2] max_ttl_seconds=3600 extensions=[] users=[bob] groups=[devs]") {
			t.Fatalf("role grant: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, stdout, stderr := run(t, "role", "revoke", "dev2", "--group", "devs", "--yes"); code != 0 || !strings.Contains(stdout, "+ role dev2 principals=[role:dev2] max_ttl_seconds=3600 extensions=[] users=[bob] groups=[]") {
			t.Fatalf("role revoke: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if g, err := installedDir(t, e).Authorize("bob", nil); err != nil || !slices.Equal(g.Principals, []string{"role:dev2"}) {
			t.Fatalf("bob's grant after the grant = %+v, %v", g, err)
		}
	})

	t.Run("group_members_and_remove", func(t *testing.T) {
		e := roleEnv(t, nil)
		if code, stdout, stderr := run(t, "group", "add-member", "devs", "bob", "--yes"); code != 0 || !strings.Contains(stdout, "+ group devs members=[alice bob]") {
			t.Fatalf("group add-member: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, stdout, stderr := run(t, "group", "remove-member", "devs", "alice", "--yes"); code != 0 || !strings.Contains(stdout, "+ group devs members=[bob]") {
			t.Fatalf("group remove-member: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, stdout, stderr := run(t, "group", "add", "ops-team", "--member", "alice", "--yes"); code != 0 || !strings.Contains(stdout, "+ group ops-team members=[alice]") {
			t.Fatalf("group add: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, stdout, stderr := run(t, "group", "remove", "ops-team", "--yes"); code != 0 || !strings.Contains(stdout, "- group ops-team members=[alice]") {
			t.Fatalf("group remove: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if d := installedDir(t, e); d.Version != 5 {
			t.Fatalf("installed version %d, want 5", d.Version)
		}
	})

	t.Run("map_sets_role_list", func(t *testing.T) {
		e := roleEnv(t, nil)
		defer requireVersion(t, e, 3)
		if code, stdout, stderr := run(t, "host-group", "map", "web", "deploy", "dev2", "ops", "--yes"); code != 0 || !strings.Contains(stdout, "+ host_group web accounts=[deploy:dev2,ops root:ops]") {
			t.Fatalf("host-group map: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		if code, stdout, stderr := run(t, "host-group", "map", "web", "root", "dev2", "--yes"); code != 0 || !strings.Contains(stdout, "+ host_group web accounts=[deploy:dev2,ops root:dev2]") {
			t.Fatalf("host-group map (replace): exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})

	t.Run("unmap_removes_account", func(t *testing.T) {
		e := roleEnv(t, nil)
		code, stdout, stderr := run(t, "host-group", "unmap", "web", "root", "--yes")
		if code != 0 || !strings.Contains(stdout, "- host_group web accounts=[root:ops]") || !strings.Contains(stdout, "+ host_group web accounts=[]") {
			t.Fatalf("host-group unmap: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
		d := installedDir(t, e)
		if d.Version != 2 || len(d.HostGroups) != 1 || len(d.HostGroups[0].Accounts) != 0 {
			t.Fatalf("installed version %d host groups %+v, want version 2 with web holding no account", d.Version, d.HostGroups)
		}
		// The host group is now empty, so it can be removed.
		if code, stdout, stderr := run(t, "host-group", "remove", "web", "--yes"); code != 0 || !strings.Contains(stdout, "- host_group web accounts=[]") {
			t.Fatalf("host-group remove: exit %d, stderr %q, stdout:\n%s", code, stderr, stdout)
		}
	})

	t.Run("host_group_usage_states_scope", func(t *testing.T) {
		const sentence = "Host groups only decide what keyroster host principals renders (the AuthorizedPrincipalsFile content); they do not restrict certificate issuance, and certificates are not host-scoped."
		for _, args := range [][]string{{"host-group"}, {"host-group", "bogus"}} {
			var stdout, stderr bytes.Buffer
			code := dispatch(context.Background(), args, &stdout, &stderr)
			if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), sentence) {
				t.Fatalf("keyroster %q: exit %d, stdout %q, stderr:\n%s", args, code, stdout.String(), stderr.String())
			}
			if len(args) == 2 && !strings.Contains(stderr.String(), `keyroster host-group: unknown subcommand "bogus"`) {
				t.Fatalf("keyroster host-group bogus: stderr does not name the subcommand:\n%s", stderr.String())
			}
		}
	})
}

// TestHostPrincipals: keyroster host principals against the fake server.
func TestHostPrincipals(t *testing.T) {
	t.Run("no_directory_refused", func(t *testing.T) {
		newDirEnv(t, 1, 1) // nothing installed: version 0, nil Dir
		var stdout, stderr bytes.Buffer
		err := runHostPrincipals(context.Background(), []string{"web", "root"}, &stdout, &stderr)
		if !errors.Is(err, directory.ErrNoDirectory) || stdout.Len() != 0 {
			t.Fatalf("host principals with no directory: err %v, stdout %q; want ErrNoDirectory and no output", err, stdout.String())
		}
		code, out, errOut := run(t, "host", "principals", "web", "root")
		if code == 0 || out != "" || !strings.Contains(errOut, "no directory is installed on the server; nothing to render") {
			t.Fatalf("host principals with no directory: exit %d, stdout %q, stderr %q", code, out, errOut)
		}
		t.Run("control_installed", func(t *testing.T) {
			e := roleEnv(t, nil)
			code, out, errOut := run(t, "host", "principals", "web", "root")
			want, err := directory.RenderPrincipalsFile(installedDir(t, e), "web", "root")
			if err != nil {
				t.Fatal(err)
			}
			if code != 0 || out != string(want) || !strings.HasSuffix(out, "\nrole:ops\n") {
				t.Fatalf("host principals web root: exit %d, stderr %q, stdout %q; want %q", code, errOut, out, want)
			}
		})
	})

	t.Run("unmapped_account_header_only", func(t *testing.T) {
		e := roleEnv(t, nil)
		code, out, errOut := run(t, "host", "principals", "web", "deploy")
		doc, _ := e.installed()
		want := "# keyroster: generated AuthorizedPrincipalsFile; do not edit\n# host group web, account deploy, directory version 1 sha256 " + trust.SHA256Hex(doc) + "\n"
		if code != 0 || out != want {
			t.Fatalf("host principals web deploy: exit %d, stderr %q, stdout %q; want %q", code, errOut, out, want)
		}
	})

	t.Run("unknown_host_group_refused", func(t *testing.T) {
		roleEnv(t, nil)
		code, out, errOut := run(t, "host", "principals", "db", "root")
		if code == 0 || out != "" || !strings.Contains(errOut, "directory version 1 has no host group db") {
			t.Fatalf("host principals db root: exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})

	t.Run("invalid_account_refused", func(t *testing.T) {
		roleEnv(t, nil)
		code, out, errOut := run(t, "host", "principals", "web", "x\nrole:ops")
		if code == 0 || out != "" || !strings.Contains(errOut, "account name") {
			t.Fatalf("host principals with a newline in the account: exit %d, stdout %q, stderr %q", code, out, errOut)
		}
	})
}

// TestHostCAKey: keyroster host ca-key prints the active user CA key of
// the root-verified bundle, and needs no admin key.
func TestHostCAKey(t *testing.T) {
	e := newDirEnv(t, 1, 1)
	e.cfg.AdminKey = ""
	if _, err := saveConfig(e.cfg, true); err != nil {
		t.Fatal(err)
	}
	useCountingKeyring(t) // an agent without the admin key
	var tr serverclient.TrustResponse
	if err := json.Unmarshal(e.trustDoc, &tr); err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(tr.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	want := ""
	for _, ca := range b.CAs {
		if ca.Role == trust.RoleUser && ca.State == "active" {
			want = ca.Key + " keyroster user CA (bundle v1)\n"
		}
	}
	code, out, errOut := run(t, "host", "ca-key")
	if code != 0 || want == "" || out != want {
		t.Fatalf("host ca-key: exit %d, stderr %q, stdout %q; want %q", code, errOut, out, want)
	}
}
