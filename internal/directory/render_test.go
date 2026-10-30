package directory

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/trust"
)

// renderDir is a directory, built with the 02-01 types, with roles a and b
// sharing the principal shared, and host group web mapping root to both,
// empty to an empty role list and ops to a only.
func renderDir(t *testing.T, mutate func(d *Directory)) *Directory {
	t.Helper()
	d := &Directory{
		Version: 3,
		Prev:    strings.Repeat("ab", 32),
		Roles: []Role{
			{Name: "a", Principals: []string{"role:a", "shared"}, MaxTTLSeconds: 3600},
			{Name: "b", Principals: []string{"role:b", "shared"}, MaxTTLSeconds: 3600},
		},
		HostGroups: []HostGroup{{Name: "web", Accounts: []AccountMap{
			{Account: "empty", Roles: []string{}},
			{Account: "ops", Roles: []string{"a"}},
			{Account: "root", Roles: []string{"b", "a"}},
		}}},
	}
	if mutate != nil {
		mutate(d)
	}
	d.Sort()
	if err := d.Validate(); err != nil {
		t.Fatalf("the test directory does not validate: %v", err)
	}
	return d
}

// wantHeader is the two header lines for account in web of d.
func wantHeader(t *testing.T, d *Directory, account string) string {
	t.Helper()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return "# keyroster: generated AuthorizedPrincipalsFile; do not edit\n" +
		"# host group web, account " + account + ", directory version 3 sha256 " + trust.SHA256Hex(doc) + "\n"
}

func TestRenderPrincipalsFile(t *testing.T) {
	t.Run("union_sorted_deduplicated", func(t *testing.T) {
		d := renderDir(t, nil)
		got, err := AccountPrincipals(d, "web", "root")
		if err != nil || !slices.Equal(got, []string{"role:a", "role:b", "shared"}) {
			t.Fatalf("AccountPrincipals(web, root) = %q, %v; want [role:a role:b shared]", got, err)
		}
		file, err := RenderPrincipalsFile(d, "web", "root")
		if err != nil {
			t.Fatal(err)
		}
		if want := wantHeader(t, d, "root") + "role:a\nrole:b\nshared\n"; string(file) != want {
			t.Fatalf("RenderPrincipalsFile(web, root) =\n%q\nwant\n%q", file, want)
		}
	})

	t.Run("output_is_header_plus_account_principals", func(t *testing.T) {
		d := renderDir(t, nil)
		for _, account := range []string{"root", "ops", "empty", "nobody"} {
			ps, err := AccountPrincipals(d, "web", account)
			if err != nil {
				t.Fatal(err)
			}
			want := wantHeader(t, d, account)
			for _, p := range ps {
				want += p + "\n"
			}
			file, err := RenderPrincipalsFile(d, "web", account)
			if err != nil || string(file) != want {
				t.Fatalf("RenderPrincipalsFile(web, %s) = %q, %v; want %q", account, file, err, want)
			}
		}
	})

	t.Run("unknown_host_group_errors", func(t *testing.T) {
		d := renderDir(t, nil)
		if ps, err := AccountPrincipals(d, "db", "root"); !errors.Is(err, ErrUnknownHostGroup) || ps != nil {
			t.Fatalf("AccountPrincipals(db, root) = %q, %v; want ErrUnknownHostGroup", ps, err)
		}
		if file, err := RenderPrincipalsFile(d, "db", "root"); !errors.Is(err, ErrUnknownHostGroup) || file != nil {
			t.Fatalf("RenderPrincipalsFile(db, root) = %q, %v; want ErrUnknownHostGroup and no bytes", file, err)
		}
	})

	t.Run("nil_directory_errors", func(t *testing.T) {
		if ps, err := AccountPrincipals(nil, "web", "root"); !errors.Is(err, ErrNoDirectory) || ps != nil {
			t.Fatalf("AccountPrincipals(nil) = %q, %v; want ErrNoDirectory", ps, err)
		}
		if file, err := RenderPrincipalsFile(nil, "web", "root"); !errors.Is(err, ErrNoDirectory) || file != nil {
			t.Fatalf("RenderPrincipalsFile(nil) = %q, %v; want ErrNoDirectory and no bytes", file, err)
		}
	})

	t.Run("unmapped_account_renders_header_only", func(t *testing.T) {
		d := renderDir(t, nil)
		ps, err := AccountPrincipals(d, "web", "nobody")
		if err != nil || ps == nil || len(ps) != 0 {
			t.Fatalf("AccountPrincipals(web, nobody) = %#v, %v; want an empty, non-nil list and no error", ps, err)
		}
		file, err := RenderPrincipalsFile(d, "web", "nobody")
		if err != nil || string(file) != wantHeader(t, d, "nobody") {
			t.Fatalf("RenderPrincipalsFile(web, nobody) = %q, %v; want exactly the two header lines", file, err)
		}
	})

	t.Run("empty_role_list_renders_header_only", func(t *testing.T) {
		// The same account, once with roles [] (Validate accepts it) and
		// once with no entry: both are the header-only file, and they
		// differ only in the directory hash of the second header line.
		withEmpty := renderDir(t, func(d *Directory) {
			d.HostGroups[0].Accounts = []AccountMap{{Account: "deploy", Roles: []string{}}}
		})
		without := renderDir(t, func(d *Directory) { d.HostGroups[0].Accounts = []AccountMap{} })
		ps, err := AccountPrincipals(withEmpty, "web", "deploy")
		if err != nil || ps == nil || len(ps) != 0 {
			t.Fatalf("AccountPrincipals with roles [] = %#v, %v; want an empty, non-nil list", ps, err)
		}
		a, err := RenderPrincipalsFile(withEmpty, "web", "deploy")
		if err != nil {
			t.Fatal(err)
		}
		b, err := RenderPrincipalsFile(without, "web", "deploy")
		if err != nil {
			t.Fatal(err)
		}
		if string(a) != wantHeader(t, withEmpty, "deploy") || string(b) != wantHeader(t, without, "deploy") {
			t.Fatalf("renders %q and %q, want the header-only files", a, b)
		}
		mask := func(file []byte, d *Directory) []byte {
			doc, err := d.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			return bytes.ReplaceAll(file, []byte(trust.SHA256Hex(doc)), []byte("HASH"))
		}
		if !bytes.Equal(mask(a, withEmpty), mask(b, without)) {
			t.Fatalf("roles [] renders %q, no entry renders %q; want the same bytes but for the hash", a, b)
		}
	})

	t.Run("header_sha256_matches_installed_bytes", func(t *testing.T) {
		doc, err := renderDir(t, nil).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		installed, err := Parse(doc) // as the signer and the CLI hold it
		if err != nil {
			t.Fatal(err)
		}
		file, err := RenderPrincipalsFile(installed, "web", "ops")
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(file), "\n")
		if want := "# host group web, account ops, directory version 3 sha256 " + trust.SHA256Hex(doc); lines[1] != want {
			t.Fatalf("header line %q, want %q (the SHA-256 of the installed bytes)", lines[1], want)
		}
	})

	t.Run("names_outside_the_grammars_refused", func(t *testing.T) {
		// A name goes into the header line; one with a newline would forge
		// a principal line there.
		d := renderDir(t, nil)
		for _, c := range []struct{ group, account string }{
			{"web", "x\nrole:a"}, {"web", "Root"}, {"web", ""}, {"web\nrole:a", "root"}, {"", "root"},
		} {
			if file, err := RenderPrincipalsFile(d, c.group, c.account); !errors.Is(err, ErrInvalid) || file != nil {
				t.Errorf("RenderPrincipalsFile(%q, %q) = %q, %v; want ErrInvalid and no bytes", c.group, c.account, file, err)
			}
		}
	})
}

// TestRenderMatchesAuthorize: for a user granted exactly the roles an
// account accepts, the rendered principals are the principals Authorize
// puts in the user's certificate (T-02-53: one package computes both).
func TestRenderMatchesAuthorize(t *testing.T) {
	d := renderDir(t, func(d *Directory) {
		d.Users = []User{{Name: "alice", Status: StatusDisabled, Credentials: []Credential{}}}
		d.Roles[0].Users = []string{"alice"}
		d.Roles[1].Users = []string{"alice"}
	})
	d.Users[0].Status = StatusActive // Authorize only reads the status
	g, err := d.Authorize("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := AccountPrincipals(d, "web", "root")
	if err != nil || !slices.Equal(ps, g.Principals) {
		t.Fatalf("rendered %q, Authorize grants %q", ps, g.Principals)
	}
}

// referenceRenderPrincipalsFile is RenderPrincipalsFile as it was before
// PrincipalsRenderer (PR #76 review, owner decision D-1): AccountPrincipals,
// then the canonical encoding and its SHA-256 for every file.
func referenceRenderPrincipalsFile(d *Directory, hostGroup, account string) ([]byte, error) {
	principals, err := AccountPrincipals(d, hostGroup, account)
	if err != nil {
		return nil, err
	}
	canonical, err := d.Canonical()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString("# keyroster: generated AuthorizedPrincipalsFile; do not edit\n")
	fmt.Fprintf(&b, "# host group %s, account %s, directory version %d sha256 %s\n", hostGroup, account, d.Version, trust.SHA256Hex(canonical))
	for _, p := range principals {
		b.WriteString(p + "\n")
	}
	return []byte(b.String()), nil
}

// TestPrincipalsRendererMatchesReference (PR #76 review, owner decision
// D-1): one PrincipalsRenderer, used for every file of a directory and
// across errors, renders byte for byte what the per-file renderer did,
// with the same errors.
func TestPrincipalsRendererMatchesReference(t *testing.T) {
	dirs := map[string]*Directory{
		"one_group": renderDir(t, nil),
		"two_groups": renderDir(t, func(d *Directory) {
			d.Version = 9
			d.HostGroups = append(d.HostGroups, HostGroup{Name: "db", Accounts: []AccountMap{
				{Account: "postgres", Roles: []string{"b"}},
				{Account: "root", Roles: []string{"a"}},
			}})
		}),
		"nil": nil,
	}
	groups := []string{"web", "db", "nope", "Bad Group"}
	accounts := []string{"empty", "ops", "root", "postgres", "nobody", "Bad", "a\nb"}
	for name, d := range dirs {
		t.Run(name, func(t *testing.T) {
			r := NewPrincipalsRenderer(d)
			for range 2 { // the second round reads the cached sum
				for _, g := range groups {
					for _, a := range accounts {
						want, wantErr := referenceRenderPrincipalsFile(d, g, a)
						got, err := r.File(g, a)
						if !bytes.Equal(got, want) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
							t.Fatalf("File(%q, %q) = %q, %v; the reference renders %q, %v", g, a, got, err, want, wantErr)
						}
						for _, sentinel := range []error{ErrNoDirectory, ErrUnknownHostGroup, ErrInvalid} {
							if errors.Is(err, sentinel) != errors.Is(wantErr, sentinel) {
								t.Fatalf("File(%q, %q): %v, the reference %v (%v)", g, a, err, wantErr, sentinel)
							}
						}
						if wrapped, err := RenderPrincipalsFile(d, g, a); !bytes.Equal(wrapped, want) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
							t.Fatalf("RenderPrincipalsFile(%q, %q) = %q, %v; want %q, %v", g, a, wrapped, err, want, wantErr)
						}
					}
				}
			}
		})
	}
}
