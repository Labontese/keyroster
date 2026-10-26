package directory

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// testInstallationID is the installation ID of the hosts vector: the bytes
// 00 01 ... 0f in hex.
const testInstallationID = "000102030405060708090a0b0c0d0e0f"

// entryKey is the trust.FormatKey form of the Ed25519 key with seed first.
func entryKey(t testing.TB, first byte) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(seedKey(first).Public())
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(pub)
}

// hostsFixture is the directory of test/vectors/directory_hosts_v1.json:
// fixture, bound to testInstallationID, with host web1 in host group lab
// (the Ed25519 key with seed 0x40, principals web1 and web1.lab.example)
// and machine ci (the Ed25519 key with seed 0x60, role ops, 3600 s).
func hostsFixture(t testing.TB) *Directory {
	t.Helper()
	d := fixture(t)
	d.InstallationID = testInstallationID
	d.Hosts = []Host{{Name: "web1", HostGroup: "lab", Keys: []string{entryKey(t, 0x40)}, Principals: []string{"web1", "web1.lab.example"}, Status: StatusActive}}
	d.Machines = []Machine{{Name: "ci", Key: entryKey(t, 0x60), Roles: []string{"ops"}, MaxTTLSeconds: 3600, Status: StatusActive}}
	return d
}

// TestDirectoryHostsGoldenVector pins the Phase 3 fields byte for byte:
// the hosts fixture's canonical bytes equal
// test/vectors/directory_hosts_v1.json, and the file parses and re-encodes
// to itself. installation_id, hosts and machines are the last three
// fields, in that order.
func TestDirectoryHostsGoldenVector(t *testing.T) {
	built := mustCanonical(t, hostsFixture(t))
	path := filepath.Join(vectorDir, "directory_hosts_v1.json")
	if *updateVectors {
		if err := os.WriteFile(path, built, 0o644); err != nil { //nolint:gosec // G306: public test vector
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatalf("%v (create it with -update only for a deliberate format change)", err)
	}
	if !bytes.Equal(got, built) {
		t.Fatalf("%s differs from the fixture's canonical encoding\ngot:  %s\nwant: %s", path, got, built)
	}
	d, err := Parse(got)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if re := mustCanonical(t, d); !bytes.Equal(re, got) {
		t.Fatalf("%s does not re-encode to itself", path)
	}
	i, h, m := bytes.Index(got, []byte(`,"installation_id":`)), bytes.Index(got, []byte(`,"hosts":`)), bytes.Index(got, []byte(`,"machines":`))
	if i < 0 || h < i || m < h || !bytes.HasSuffix(got, []byte("]}\n")) || bytes.Contains(got[m:], []byte(`"host_groups"`)) {
		t.Fatalf("installation_id, hosts and machines are not the last three fields:\n%s", got)
	}
	// The Phase 2 vector is unchanged by the new fields.
	v1, err := os.ReadFile(filepath.Join(vectorDir, "directory_v1.json")) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(v1, mustCanonical(t, fixture(t))) {
		t.Fatal("directory_v1.json no longer equals the Phase 2 fixture's encoding")
	}
	t.Logf("directory_hosts_v1.json sha256 %s", trust.SHA256Hex(got))
}

// policyCaps is a policy with a 12 h user CA cap (permit-pty default) and
// a 24 h machine CA cap (permit-pty default, permit-port-forwarding
// allowed).
func policyCaps() *trust.Policy {
	return &trust.Policy{CAProfiles: []trust.CAProfile{
		{Role: trust.RoleUser, MaxTTLSeconds: 12 * 3600, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}},
		{Role: trust.RoleHost, MaxTTLSeconds: 720 * 3600, DefaultExtensions: []string{}, AllowedExtensions: []string{}},
		{Role: trust.RoleMachine, MaxTTLSeconds: 24 * 3600, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{"permit-port-forwarding"}},
	}}
}

// withNoncanonicalField returns the canonical bytes of d with field (a
// `"name":value` JSON member) inserted before the final "}".
func withNoncanonicalField(t *testing.T, d *Directory, field string) []byte {
	t.Helper()
	doc := mustCanonical(t, d)
	return append(bytes.TrimSuffix(doc, []byte("}\n")), []byte(","+field+"}\n")...)
}

// TestHostsValidate covers every host, machine and installation rule of
// Validate and CheckPolicy, each refusal against the hosts fixture as
// control.
func TestHostsValidate(t *testing.T) {
	if _, err := Parse(mustCanonical(t, hostsFixture(t))); err != nil {
		t.Fatalf("control: the hosts fixture is refused: %v", err)
	}
	if err := CheckPolicy(hostsFixture(t), policyCaps()); err != nil {
		t.Fatalf("control: the hosts fixture exceeds the policy: %v", err)
	}
	refused := func(t *testing.T, d *Directory, want string) {
		t.Helper()
		err := d.Validate()
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate = %v, want ErrInvalid naming %q", err, want)
		}
	}
	t.Run("empty_hosts_list_noncanonical", func(t *testing.T) {
		if _, err := Parse(withNoncanonicalField(t, fixture(t), `"hosts":[]`)); !errors.Is(err, ErrInvalid) || !errors.Is(err, trust.ErrNotCanonical) {
			t.Fatalf("Parse with \"hosts\":[] = %v, want ErrInvalid (non-canonical)", err)
		}
		d := fixture(t)
		d.Hosts = []Host{}
		refused(t, d, "hosts must be omitted")
	})
	t.Run("empty_machines_list_noncanonical", func(t *testing.T) {
		if _, err := Parse(withNoncanonicalField(t, fixture(t), `"machines":[]`)); !errors.Is(err, trust.ErrNotCanonical) {
			t.Fatalf("Parse with \"machines\":[] = %v, want non-canonical", err)
		}
	})
	t.Run("empty_installation_id_noncanonical", func(t *testing.T) {
		if _, err := Parse(withNoncanonicalField(t, fixture(t), `"installation_id":""`)); !errors.Is(err, ErrInvalid) || !errors.Is(err, trust.ErrNotCanonical) {
			t.Fatalf("Parse with \"installation_id\":\"\" = %v, want ErrInvalid (non-canonical)", err)
		}
	})
	t.Run("installation_id_malformed", func(t *testing.T) {
		d := hostsFixture(t)
		d.InstallationID = strings.ToUpper(testInstallationID)
		refused(t, d, "is not an installation ID")
	})
	t.Run("host_unknown_group", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].HostGroup = "web"
		refused(t, d, `unknown host group "web"`)
	})
	t.Run("host_group_remove_refused_while_used", func(t *testing.T) {
		// A version that drops lab while web1 names it does not validate.
		d := hostsFixture(t)
		d.HostGroups = []HostGroup{}
		refused(t, d, `host web1: unknown host group "lab"`)
	})
	t.Run("host_rsa_key_refused", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		d := hostsFixture(t)
		d.Hosts[0].Keys = []string{trust.FormatKey(pub)}
		refused(t, d, "key type ssh-rsa")
	})
	t.Run("host_key_with_comment_refused", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Keys = []string{d.Hosts[0].Keys[0] + " root@web1"}
		refused(t, d, "without options or comment")
	})
	t.Run("host_without_key_refused", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Keys = []string{}
		refused(t, d, "needs 1 to 8 host keys")
	})
	t.Run("host_key_on_two_hosts", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts = append(d.Hosts, Host{Name: "web2", HostGroup: "lab", Keys: d.Hosts[0].Keys, Principals: []string{"web2"}, Status: StatusActive})
		refused(t, d, "is on hosts web1 and web2")
	})
	t.Run("host_principal_on_two_hosts", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts = append(d.Hosts, Host{Name: "web2", HostGroup: "lab", Keys: []string{entryKey(t, 0x41)}, Principals: []string{"web1.lab.example"}, Status: StatusActive})
		refused(t, d, "host principal web1.lab.example is on hosts web1 and web2")
	})
	t.Run("host_principal_wildcard", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Principals = []string{"*.lab.example"}
		refused(t, d, "no wildcard")
	})
	t.Run("host_principal_star", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Principals = []string{"*"}
		refused(t, d, "no wildcard")
	})
	t.Run("host_principal_question_mark", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Principals = []string{"web?"}
		refused(t, d, "no wildcard")
	})
	t.Run("host_principal_comma", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Principals = []string{"web1,web2"}
		refused(t, d, "comma")
	})
	t.Run("host_principal_whitespace", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Principals = []string{"web1 web2"}
		refused(t, d, "whitespace")
	})
	t.Run("host_principals_unsorted", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Principals = []string{"web1.lab.example", "web1"}
		refused(t, d, "must be sorted")
	})
	t.Run("host_too_many_principals", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Principals = []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9"}
		refused(t, d, "needs 1 to 8 principals")
	})
	t.Run("host_bad_status", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Status = "enabled"
		refused(t, d, `status "enabled"`)
	})
	t.Run("host_bad_name", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts[0].Name = "Web1"
		refused(t, d, "invalid name")
	})
	t.Run("hosts_unsorted", func(t *testing.T) {
		d := hostsFixture(t)
		d.Hosts = append(d.Hosts, Host{Name: "app1", HostGroup: "lab", Keys: []string{entryKey(t, 0x41)}, Principals: []string{"app1"}, Status: StatusActive})
		refused(t, d, "hosts must be sorted")
	})
	t.Run("machine_key_equals_host_key", func(t *testing.T) {
		d := hostsFixture(t)
		d.Machines[0].Key = d.Hosts[0].Keys[0]
		refused(t, d, "is the host key of host web1")
	})
	t.Run("machine_key_on_two_machines", func(t *testing.T) {
		d := hostsFixture(t)
		d.Machines = append(d.Machines, Machine{Name: "deploy", Key: d.Machines[0].Key, Roles: []string{"ops"}, MaxTTLSeconds: 3600, Status: StatusActive})
		refused(t, d, "is on machines ci and deploy")
	})
	t.Run("machine_unknown_role", func(t *testing.T) {
		d := hostsFixture(t)
		d.Machines[0].Roles = []string{"deploy"}
		refused(t, d, `unknown or invalid entry "deploy"`)
	})
	t.Run("machine_without_role", func(t *testing.T) {
		d := hostsFixture(t)
		d.Machines[0].Roles = []string{}
		refused(t, d, "needs 1 to 16 roles")
	})
	t.Run("machine_ttl_below_minimum", func(t *testing.T) {
		d := hostsFixture(t)
		d.Machines[0].MaxTTLSeconds = 59
		refused(t, d, "max_ttl_seconds must be >= 60")
	})
	t.Run("machine_ttl_above_machine_cap", func(t *testing.T) {
		d := hostsFixture(t)
		d.Machines[0].MaxTTLSeconds = 24*3600 + 1
		if err := CheckPolicy(d, policyCaps()); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "machine ci: max_ttl_seconds 86401 is above the machine CA cap 86400") {
			t.Fatalf("CheckPolicy = %v, want the machine cap refusal", err)
		}
	})
	t.Run("machine_only_role_above_user_cap_accepted", func(t *testing.T) {
		// Role ops granted to no user or group and named by machine ci:
		// 24 h, above the 12 h user cap, within the machine cap.
		d := hostsFixture(t)
		d.Roles[0].Users = []string{}
		d.Roles[0].MaxTTLSeconds = 24 * 3600
		d.Machines[0].MaxTTLSeconds = 24 * 3600
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := CheckPolicy(d, policyCaps()); err != nil {
			t.Fatalf("CheckPolicy = %v, want a machine-only role checked against the machine cap only", err)
		}
	})
	t.Run("user_role_above_user_cap_refused", func(t *testing.T) {
		d := fixture(t)
		d.Roles[0].MaxTTLSeconds = 12*3600 + 1
		if err := CheckPolicy(d, policyCaps()); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "above the user CA cap") {
			t.Fatalf("CheckPolicy = %v, want the user cap refusal", err)
		}
	})
	t.Run("ungranted_unnamed_role_keeps_user_cap", func(t *testing.T) {
		d := fixture(t)
		d.Roles[0].Users = []string{}
		d.Roles[0].MaxTTLSeconds = 12*3600 + 1
		if err := CheckPolicy(d, policyCaps()); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "above the user CA cap") {
			t.Fatalf("CheckPolicy = %v, want the user cap for a role nobody grants or names", err)
		}
	})
}

// TestHostPrincipalSpelling (T-03-21): a host principal is accepted only
// in its one canonical spelling, and a refusal names the canonical form
// when one exists. Nothing is rewritten.
func TestHostPrincipalSpelling(t *testing.T) {
	for _, tc := range []struct {
		name, principal, canonical string
	}{
		{"host_principal_ipv6_uppercase_refused", "2001:DB8::1", "2001:db8::1"},
		{"host_principal_ipv6_uncompressed_refused", "2001:db8:0:0::1", "2001:db8::1"},
		{"host_principal_ipv6_leading_zero_refused", "2001:db8::0001", "2001:db8::1"},
		{"host_principal_ipv4_leading_zero_refused", "192.0.2.01", "192.0.2.1"},
		{"host_principal_ipv4_mapped_refused", "::ffff:192.0.2.1", "192.0.2.1"},
		{"host_principal_zone_refused", "fe80::1%eth0", "fe80::1"},
		{"host_principal_trailing_dot_refused", "web1.lab.example.", "web1.lab.example"},
		{"host_principal_uppercase_dns_refused", "Web1", "web1"},
		{"host_principal_numeric_last_label_refused", "192.0.2.256", ""},
		{"host_principal_label_hyphen_refused", "-web1", ""},
		{"host_principal_long_label_refused", strings.Repeat("a", 64) + ".example", ""},
		// inet_aton spellings of an IPv4 address (pre-merge review, 03-04).
		{"host_principal_hex_address_refused", "0x7f000001", ""},
		{"host_principal_hex_address_uppercase_refused", "0X7F000001", ""},
		{"host_principal_hex_last_part_refused", "127.0.0.0x1", ""},
		{"host_principal_hex_parts_refused", "0xc0.0x0.0x2.0x1", ""},
		{"host_principal_hex_two_parts_refused", "0x7f.0x1", ""},
		{"host_principal_empty_hex_refused", "0x", ""},
		{"host_principal_two_part_decimal_refused", "127.1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckHostPrincipal(tc.principal)
			if err == nil {
				t.Fatalf("CheckHostPrincipal(%q) accepted it", tc.principal)
			}
			if tc.canonical != "" && !strings.HasSuffix(err.Error(), " "+tc.canonical) {
				t.Fatalf("CheckHostPrincipal(%q) = %v, want the message to name %s", tc.principal, err, tc.canonical)
			}
			if tc.canonical == "" && inetNumeral(strings.ToLower(tc.principal)) && !strings.Contains(err.Error(), "a resolver reads it as an IPv4 address") {
				t.Fatalf("CheckHostPrincipal(%q) = %v, want the inet_aton refusal", tc.principal, err)
			}
			d := hostsFixture(t)
			d.Hosts[0].Principals = []string{tc.principal}
			if err := d.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate with principal %q = %v, want ErrInvalid", tc.principal, err)
			}
			if d.Hosts[0].Principals[0] != tc.principal {
				t.Fatal("Validate rewrote the principal")
			}
		})
	}
	for _, tc := range []struct{ name, principal string }{
		{"host_principal_ipv6_canonical_accepted", "2001:db8::1"},
		{"host_principal_ipv4_accepted", "192.0.2.1"},
		{"host_principal_short_name_accepted", "web1"},
		{"host_principal_fqdn_accepted", "web1.lab.example"},
		{"host_principal_digit_label_accepted", "1web.example"},
		{"host_principal_hex_like_label_accepted", "0xdead.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckHostPrincipal(tc.principal); err != nil {
				t.Fatalf("CheckHostPrincipal(%q) = %v, want accepted", tc.principal, err)
			}
			d := hostsFixture(t)
			d.Hosts[0].Principals = []string{tc.principal}
			if err := d.Validate(); err != nil {
				t.Fatalf("Validate with principal %q = %v", tc.principal, err)
			}
		})
	}
}

// TestMachineRoleClasses (D-15, T-03-22): a role's class comes from its
// own users and groups lists, never from group membership, and a role used
// under both CAs passes both caps and both profiles.
func TestMachineRoleClasses(t *testing.T) {
	pol := policyCaps()
	t.Run("mixed_role_keeps_user_cap", func(t *testing.T) {
		// ops granted to group ops-team and named by machine ci, 24 h.
		d := hostsFixture(t)
		d.Roles[0].Users, d.Roles[0].Groups = []string{}, []string{"ops-team"}
		d.Roles[0].MaxTTLSeconds = 24 * 3600
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := CheckPolicy(d, pol); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "above the user CA cap") {
			t.Fatalf("CheckPolicy = %v, want the user cap for a mixed role", err)
		}
	})
	t.Run("role_granted_to_empty_group_is_user_facing", func(t *testing.T) {
		// ops granted only to a group with no members, named by ci, 24 h.
		d := hostsFixture(t)
		d.Groups = []Group{{Name: "nobody", Members: []string{}}, d.Groups[0]}
		d.Roles[0].Users, d.Roles[0].Groups = []string{}, []string{"nobody"}
		d.Roles[0].MaxTTLSeconds = 24 * 3600
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}
		if err := CheckPolicy(d, pol); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "above the user CA cap") {
			t.Fatalf("CheckPolicy = %v, want the user cap for a role granted to an empty group", err)
		}
	})
	t.Run("mixed_role_extension_needs_both_profiles", func(t *testing.T) {
		// permit-port-forwarding: allowed by the machine profile only.
		mixed := hostsFixture(t)
		mixed.Roles[0].Extensions = []string{"permit-port-forwarding"}
		if err := CheckPolicy(mixed, pol); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "not allowed by the user CA profile") {
			t.Fatalf("mixed role: CheckPolicy = %v, want the user profile refusal", err)
		}
		machineOnly := hostsFixture(t)
		machineOnly.Roles[0].Users = []string{}
		machineOnly.Roles[0].Extensions = []string{"permit-port-forwarding"}
		if err := CheckPolicy(machineOnly, pol); err != nil {
			t.Fatalf("machine-only role: CheckPolicy = %v, want accepted", err)
		}
		// And the other way: an extension the user profile allows but the
		// machine profile does not is refused for the mixed role.
		userPol := policyCaps()
		userPol.CAProfiles[0].AllowedExtensions = []string{"permit-agent-forwarding"}
		agent := hostsFixture(t)
		agent.Roles[0].Extensions = []string{"permit-agent-forwarding"}
		if err := CheckPolicy(agent, userPol); !errors.Is(err, ErrPolicy) || !strings.Contains(err.Error(), "not allowed by the machine CA profile") {
			t.Fatalf("mixed role: CheckPolicy = %v, want the machine profile refusal", err)
		}
	})
	t.Run("mixed_role_within_both_caps_accepted", func(t *testing.T) {
		if err := CheckPolicy(hostsFixture(t), pol); err != nil {
			t.Fatal(err)
		}
	})
}

// TestHostLookups covers HostByName, HostForKey, MachineByName and
// HostPrincipals.
func TestHostLookups(t *testing.T) {
	d := hostsFixture(t)
	if h, ok := d.HostByName("web1"); !ok || h.HostGroup != "lab" {
		t.Fatalf("HostByName(web1) = %+v, %v", h, ok)
	}
	if _, ok := d.HostByName("web2"); ok {
		t.Fatal("HostByName(web2) found a host")
	}
	pub, err := trust.ParseKey(entryKey(t, 0x40))
	if err != nil {
		t.Fatal(err)
	}
	if h, ok := d.HostForKey(pub); !ok || h.Name != "web1" {
		t.Fatalf("HostForKey(web1's key) = %+v, %v", h, ok)
	}
	other, err := trust.ParseKey(entryKey(t, 0x60))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := d.HostForKey(other); ok {
		t.Fatal("HostForKey(a machine key) found a host")
	}
	if m, ok := d.MachineByName("ci"); !ok || m.Roles[0] != "ops" {
		t.Fatalf("MachineByName(ci) = %+v, %v", m, ok)
	}

	got, err := HostPrincipals(d, "web1", "zima")
	if err != nil {
		t.Fatal(err)
	}
	want, err := RenderPrincipalsFile(d, "lab", "zima")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) || !bytes.HasSuffix(got, []byte("\nrole:ops\n")) {
		t.Fatalf("HostPrincipals(web1, zima) = %q, want %q", got, want)
	}
	if _, err := HostPrincipals(d, "web2", "zima"); !errors.Is(err, ErrUnknownHost) || !strings.Contains(err.Error(), "web2") {
		t.Fatalf("HostPrincipals(web2) = %v, want ErrUnknownHost naming web2", err)
	}
	d.Hosts[0].Status = StatusDisabled
	if _, err := HostPrincipals(d, "web1", "zima"); !errors.Is(err, ErrUnknownHost) {
		t.Fatalf("HostPrincipals(disabled web1) = %v, want ErrUnknownHost", err)
	}
	if _, err := HostPrincipals(d, "web1\n", "zima"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("HostPrincipals(bad name) = %v, want ErrInvalid", err)
	}
	if _, err := HostPrincipals(nil, "web1", "zima"); !errors.Is(err, ErrNoDirectory) {
		t.Fatalf("HostPrincipals(nil) = %v, want ErrNoDirectory", err)
	}
}

// TestCheckInstallation covers the install rule and the stored-directory
// rule (the owner's lenient D-04 answer, 03-01).
func TestCheckInstallation(t *testing.T) {
	const other = "ffffffffffffffffffffffffffffffff"
	for _, tc := range []struct {
		name, dirID, bundleID string
		install, stored       error
	}{
		{"both_set_equal", testInstallationID, testInstallationID, nil, nil},
		{"both_empty", "", "", nil, nil},
		{"directory_installation_missing", "", testInstallationID, ErrInstallationMissing, nil},
		{"directory_installation_mismatch", other, testInstallationID, ErrInstallationMismatch, ErrInstallationMismatch},
		{"directory_installation_unknown", testInstallationID, "", ErrInstallationUnknown, ErrInstallationUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &Directory{InstallationID: tc.dirID}
			if err := CheckInstallation(d, tc.bundleID); !errors.Is(err, tc.install) || (tc.install == nil) != (err == nil) {
				t.Fatalf("CheckInstallation = %v, want %v", err, tc.install)
			}
			if err := CheckStoredInstallation(d, tc.bundleID); !errors.Is(err, tc.stored) || (tc.stored == nil) != (err == nil) {
				t.Fatalf("CheckStoredInstallation = %v, want %v", err, tc.stored)
			}
		})
	}
}

// TestDiffHostsAndMachines: the installation ID, hosts and machines show
// in the diff an admin signs, keys by fingerprint.
func TestDiffHostsAndMachines(t *testing.T) {
	old, next := fixture(t), hostsFixture(t)
	hostPub, err := trust.ParseKey(next.Hosts[0].Keys[0])
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(Diff(old, next), "\n")
	for _, want := range []string{
		"+ installation_id " + testInstallationID,
		"+ host web1 host_group=lab status=active principals=[web1 web1.lab.example] keys=[ssh-ed25519 " + ssh.FingerprintSHA256(hostPub) + "]",
		"+ machine ci status=active key=ssh-ed25519 SHA256:",
		"roles=[ops] max_ttl_seconds=3600",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("Diff lacks %q:\n%s", want, got)
		}
	}
	if !strings.HasPrefix(got, "+ installation_id") {
		t.Fatalf("the installation ID is not the first line:\n%s", got)
	}
	rebound := hostsFixture(t)
	rebound.InstallationID = "ffffffffffffffffffffffffffffffff"
	if got := Diff(next, rebound); len(got) != 1 || got[0] != "~ installation_id "+testInstallationID+" -> ffffffffffffffffffffffffffffffff" {
		t.Fatalf("Diff of an installation change = %q", got)
	}
	if got := Diff(next, hostsFixture(t)); len(got) != 0 {
		t.Fatalf("Diff of equal directories = %q", got)
	}
}
