package directory

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
)

var updateVectors = flag.Bool("update", false, "rewrite the golden vectors in test/vectors")

const vectorDir = "../../test/vectors"

// seedKey returns the Ed25519 private key whose 32-byte seed is
// first, first+1, ..., first+31: fixed, so fixtures are reproducible.
func seedKey(first byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = first + byte(i)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// credential returns a directory credential for an Ed25519 key with seed
// first and the 16-byte ID idFirst, idFirst+1, ...
func credential(t testing.TB, first, idFirst byte) Credential {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(seedKey(first).Public())
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	for i := range id {
		id[i] = idFirst + byte(i)
	}
	return Credential{ID: base64.RawURLEncoding.EncodeToString(id), Alg: webauthn.AlgEdDSA, SPKI: base64.StdEncoding.EncodeToString(spki)}
}

// fixture is the directory of test/vectors/directory_v1.json: alice (one
// credential), group ops-team = [alice], role ops (role:ops, 3600 s, users
// [alice]) and host group lab mapping account zima to [ops].
func fixture(t testing.TB) *Directory {
	t.Helper()
	return &Directory{
		Version:    1,
		Prev:       trust.GenesisPrev,
		Users:      []User{{Name: "alice", Status: StatusActive, Credentials: []Credential{credential(t, 0x00, 0x01)}}},
		Groups:     []Group{{Name: "ops-team", Members: []string{"alice"}}},
		Roles:      []Role{{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{"alice"}, Groups: []string{}}},
		HostGroups: []HostGroup{{Name: "lab", Accounts: []AccountMap{{Account: "zima", Roles: []string{"ops"}}}}},
	}
}

func mustCanonical(t testing.TB, d *Directory) []byte {
	t.Helper()
	b, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDirectoryGoldenVector pins the directory encoding byte for byte: the
// fixture's canonical bytes equal test/vectors/directory_v1.json, and the
// file parses and re-encodes to itself. Rewrite it only for a deliberate
// format change (go test -run TestDirectoryGoldenVector -update).
func TestDirectoryGoldenVector(t *testing.T) {
	built := mustCanonical(t, fixture(t))
	path := filepath.Join(vectorDir, "directory_v1.json")
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
	t.Logf("directory_v1.json sha256 %s", trust.SHA256Hex(got))
}

// TestValidate covers the structural rules, each refusal against the valid
// fixture as control.
func TestValidate(t *testing.T) {
	if _, err := Parse(mustCanonical(t, fixture(t))); err != nil {
		t.Fatalf("control: the fixture is refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Directory)
	}{
		{"unsorted_list", func(d *Directory) {
			d.Users = append(d.Users, User{Name: "aaron", Status: StatusDisabled, Credentials: []Credential{}})
		}},
		{"duplicate_credential_across_users", func(d *Directory) {
			d.Users = append(d.Users, User{Name: "bob", Status: StatusActive, Credentials: []Credential{d.Users[0].Credentials[0]}})
		}},
		// The decoders skip CR and LF even in strict mode, so these are
		// second text forms of the same bytes (T-02-77).
		{"credential_id_with_newline", func(d *Directory) {
			id := d.Users[0].Credentials[0].ID
			d.Users[0].Credentials[0].ID = id[:4] + "\n" + id[4:]
		}},
		{"duplicate_credential_across_users_newline_variant", func(d *Directory) {
			c := d.Users[0].Credentials[0]
			c.ID = c.ID[:4] + "\r\n" + c.ID[4:]
			d.Users = append(d.Users, User{Name: "bob", Status: StatusActive, Credentials: []Credential{c}})
		}},
		{"credential_spki_with_newline", func(d *Directory) {
			spki := d.Users[0].Credentials[0].SPKI
			d.Users[0].Credentials[0].SPKI = spki[:8] + "\n" + spki[8:]
		}},
		{"active_user_without_credentials", func(d *Directory) { d.Users[0].Credentials = []Credential{} }},
		{"unknown_role_referenced", func(d *Directory) { d.HostGroups[0].Accounts[0].Roles = []string{"nope"} }},
		{"unknown_group_referenced", func(d *Directory) { d.Roles[0].Groups = []string{"nope"} }},
		{"unknown_user_referenced", func(d *Directory) { d.Groups[0].Members = []string{"nope"} }},
		{"wildcard_principal", func(d *Directory) { d.Roles[0].Principals = []string{"*"} }},
		{"comma_principal", func(d *Directory) { d.Roles[0].Principals = []string{"role:a,role:b"} }},
		{"rsa_1024_credential", func(d *Directory) {
			k, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // G403: the point is a too-short key
			if err != nil {
				t.Fatal(err)
			}
			spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			d.Users[0].Credentials[0].Alg, d.Users[0].Credentials[0].SPKI = webauthn.AlgRS256, base64.StdEncoding.EncodeToString(spki)
		}},
		{"unsupported_algorithm", func(d *Directory) { d.Users[0].Credentials[0].Alg = -35 }},
		{"version_zero", func(d *Directory) { d.Version = 0 }},
		{"v1_with_prev", func(d *Directory) { d.Prev = trust.SHA256Hex([]byte("x")) }},
		{"bad_status", func(d *Directory) { d.Users[0].Status = "enabled" }},
		{"role_ttl_below_minimum", func(d *Directory) { d.Roles[0].MaxTTLSeconds = 59 }},
		{"bad_account", func(d *Directory) { d.HostGroups[0].Accounts[0].Account = "Zima" }},
		{"null_list", func(d *Directory) { d.Groups = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := fixture(t)
			tc.edit(d)
			err := d.Validate()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate = %v, want ErrInvalid", err)
			}
			t.Logf("refused: %v", err)
		})
	}
}

// TestCanonicalOrder (AUTH-01 edge: ordering): the same content built in
// two insertion orders gives identical canonical bytes after Sort.
func TestCanonicalOrder(t *testing.T) {
	t.Run("insertion_order_canonical", func(t *testing.T) {
		a, b := fixture(t), fixture(t)
		bob := User{Name: "bob", Status: StatusActive, Credentials: []Credential{credential(t, 0x40, 0x41), credential(t, 0x20, 0x21)}}
		dev := Role{Name: "dev", Principals: []string{"u:bob", "role:dev"}, MaxTTLSeconds: 600, Extensions: []string{}, Users: []string{"bob", "alice"}, Groups: []string{}}
		a.Users = append(a.Users, bob)
		a.Roles = append(a.Roles, dev)
		a.Groups[0].Members = []string{"alice", "bob"}
		// b: the same entries added in the reverse order.
		bob2 := bob
		bob2.Credentials = []Credential{bob.Credentials[1], bob.Credentials[0]}
		dev2 := dev
		dev2.Principals, dev2.Users = []string{"role:dev", "u:bob"}, []string{"alice", "bob"}
		b.Users = []User{bob2, b.Users[0]}
		b.Roles = []Role{dev2, b.Roles[0]}
		b.Groups[0].Members = []string{"bob", "alice"}
		a.Sort()
		b.Sort()
		ca, cb := mustCanonical(t, a), mustCanonical(t, b)
		if !bytes.Equal(ca, cb) {
			t.Fatalf("two insertion orders give different bytes:\n%s\n%s", ca, cb)
		}
		if _, err := Parse(ca); err != nil {
			t.Fatalf("the sorted directory is refused: %v", err)
		}
	})
	t.Run("credential_id_noncanonical_refused", func(t *testing.T) {
		d := fixture(t)
		canonical := d.Users[0].Credentials[0].ID
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		last := bytes.IndexByte([]byte(alphabet), canonical[len(canonical)-1])
		// 16 bytes are 22 characters; the last one carries 2 data bits and 4
		// bits that must be zero. Setting one of those gives a second text
		// form of the same bytes, which only the strict decoding refuses.
		other := canonical[:len(canonical)-1] + string(alphabet[last|1])
		lax, err := base64.RawURLEncoding.DecodeString(other)
		strict, _ := base64.RawURLEncoding.DecodeString(canonical)
		if err != nil || !bytes.Equal(lax, strict) {
			t.Fatalf("%q is not a second encoding of the same bytes (%v)", other, err)
		}
		if err := d.Validate(); err != nil {
			t.Fatalf("control: the canonical id is refused: %v", err)
		}
		d.Users[0].Credentials[0].ID = other
		if err := d.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("Validate with a non-canonical credential id = %v, want ErrInvalid", err)
		}
	})
}

// admin returns an admin signer with seed first.
func admin(t testing.TB, first byte) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(seedKey(first))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func policyWith(quorum uint32, admins ...ssh.Signer) *trust.Policy {
	p := &trust.Policy{Version: 1, AdminQuorum: quorum}
	for i, a := range admins {
		p.Admins = append(p.Admins, trust.AdminKey{Name: string(rune('a' + i)), Key: trust.FormatKey(a.PublicKey())})
	}
	return p
}

func sign(t testing.TB, s ssh.Signer, doc []byte) []byte {
	t.Helper()
	sig, err := sshsig.Sign(rand.Reader, s, Namespace, doc)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// TestVerifySignatures: the admin quorum counts distinct policy admins.
func TestVerifySignatures(t *testing.T) {
	doc := mustCanonical(t, fixture(t))
	a, b, stranger := admin(t, 0x60), admin(t, 0x70), admin(t, 0x80)
	for _, tc := range []struct {
		name string
		pol  *trust.Policy
		sigs []byte
		want error
	}{
		{"quorum_one_admin", policyWith(1, a, b), sign(t, a, doc), nil},
		{"quorum_two_admins", policyWith(2, a, b), append(sign(t, a, doc), sign(t, b, doc)...), nil},
		{"non_admin_not_counted", policyWith(1, a, b), sign(t, stranger, doc), ErrQuorum},
		{"quorum_same_admin_twice", policyWith(2, a, b), append(sign(t, a, doc), sign(t, a, doc)...), ErrQuorum},
		{"other_document", policyWith(1, a), sign(t, a, []byte("another document")), ErrQuorum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifySignatures(doc, tc.sigs, tc.pol)
			if tc.want == nil && err != nil {
				t.Fatalf("VerifySignatures = %v, want success", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("VerifySignatures = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestCheckSuccessor: version 1 with the all-zero prev, then version + 1
// with prev = SHA-256 of the installed bytes.
func TestCheckSuccessor(t *testing.T) {
	v1 := fixture(t)
	raw1 := mustCanonical(t, v1)
	// An installed v1 that no longer parses (here: a role TTL below the
	// minimum, as if a later release tightened Validate) still has a
	// version and a SHA-256, which is all the chain rule needs.
	stale := fixture(t)
	stale.Roles[0].MaxTTLSeconds = MinRoleTTLSeconds - 1
	rawStale := mustCanonical(t, stale)
	if _, err := Parse(rawStale); !errors.Is(err, ErrInvalid) {
		t.Fatalf("the stale directory parses (%v); the case would test nothing", err)
	}
	next := func(version uint64, prev string) *Directory {
		d := fixture(t)
		d.Version, d.Prev = version, prev
		return d
	}
	for _, tc := range []struct {
		name      string
		installed []byte
		next      *Directory
		want      error
	}{
		{"first_v1", nil, v1, nil},
		{"first_not_v1", nil, next(2, trust.SHA256Hex(raw1)), ErrChain},
		{"v2_right_prev", raw1, next(2, trust.SHA256Hex(raw1)), nil},
		{"wrong_prev", raw1, next(2, trust.SHA256Hex([]byte("other"))), ErrChain},
		{"v3_after_v1", raw1, next(3, trust.SHA256Hex(raw1)), ErrChain},
		{"v1_again", raw1, v1, ErrChain},
		{"v2_after_unparsable_installed", rawStale, next(2, trust.SHA256Hex(rawStale)), nil},
		{"v3_after_unparsable_installed", rawStale, next(3, trust.SHA256Hex(rawStale)), ErrChain},
		{"wrong_prev_after_unparsable_installed", rawStale, next(2, trust.SHA256Hex(raw1)), ErrChain},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckSuccessor(tc.installed, tc.next)
			if tc.want == nil && err != nil {
				t.Fatalf("CheckSuccessor = %v, want success", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("CheckSuccessor = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestCheckPolicy: role TTLs within the user CA cap, role extensions among
// the user profile's default and allowed extensions.
func TestCheckPolicy(t *testing.T) {
	pol := &trust.Policy{CAProfiles: []trust.CAProfile{
		{Role: trust.RoleUser, MaxTTLSeconds: 3600, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{"permit-agent-forwarding"}},
		{Role: trust.RoleHost, MaxTTLSeconds: 86400},
	}}
	ok := fixture(t)
	ok.Roles[0].Extensions = []string{"permit-agent-forwarding", "permit-pty"}
	if err := CheckPolicy(ok, pol); err != nil {
		t.Fatalf("control: %v", err)
	}
	over := fixture(t)
	over.Roles[0].MaxTTLSeconds = 3601
	if err := CheckPolicy(over, pol); !errors.Is(err, ErrPolicy) {
		t.Fatalf("role TTL above the user cap: %v, want ErrPolicy", err)
	}
	ext := fixture(t)
	ext.Roles[0].Extensions = []string{"permit-X11-forwarding"}
	if err := CheckPolicy(ext, pol); !errors.Is(err, ErrPolicy) {
		t.Fatalf("extension the user profile does not allow: %v, want ErrPolicy", err)
	}
}

// TestAuthorize covers the grant computation (D-08).
func TestAuthorize(t *testing.T) {
	d := fixture(t)
	d.Users = append(d.Users,
		User{Name: "bob", Status: StatusActive, Credentials: []Credential{credential(t, 0x40, 0x41)}},
		User{Name: "carol", Status: StatusDisabled, Credentials: []Credential{}},
	)
	d.Roles = append(d.Roles,
		Role{Name: "dev", Principals: []string{"role:dev", "u:alice"}, MaxTTLSeconds: 600, Extensions: []string{"permit-agent-forwarding"}, Users: []string{"alice", "carol"}, Groups: []string{}},
		Role{Name: "net", Principals: []string{"role:net"}, MaxTTLSeconds: 1800, Extensions: []string{}, Users: []string{}, Groups: []string{"ops-team"}},
	)
	d.Groups[0].Members = []string{"alice", "bob"}
	d.Sort()
	if err := d.Validate(); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for _, tc := range []struct {
		name  string
		user  string
		roles []string
		want  Grant
		err   error
	}{
		{"all_roles", "alice", nil, Grant{Roles: []string{"dev", "net", "ops"}, Principals: []string{"role:dev", "role:net", "role:ops", "u:alice"}, MaxTTLSeconds: 600, Extensions: []string{"permit-agent-forwarding"}}, nil},
		{"subset", "alice", []string{"ops", "net"}, Grant{Roles: []string{"net", "ops"}, Principals: []string{"role:net", "role:ops"}, MaxTTLSeconds: 1800, Extensions: []string{}}, nil},
		{"role_via_group", "bob", nil, Grant{Roles: []string{"net"}, Principals: []string{"role:net"}, MaxTTLSeconds: 1800, Extensions: []string{}}, nil},
		{"role_not_granted", "bob", []string{"ops"}, Grant{}, ErrRoleNotGranted},
		{"user_disabled", "carol", nil, Grant{}, ErrUserDisabled},
		{"unknown_user", "mallory", nil, Grant{}, ErrUnknownUser},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := d.Authorize(tc.user, tc.roles)
			if tc.err != nil {
				if !errors.Is(err, tc.err) {
					t.Fatalf("Authorize = %v, want %v", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(g.Roles, tc.want.Roles) || !slices.Equal(g.Principals, tc.want.Principals) ||
				g.MaxTTLSeconds != tc.want.MaxTTLSeconds || !slices.Equal(g.Extensions, tc.want.Extensions) {
				t.Fatalf("Authorize = %+v, want %+v", g, tc.want)
			}
		})
	}
	id, _ := base64.RawURLEncoding.DecodeString(d.Users[0].Credentials[0].ID)
	if c, ok := d.Credential("alice", id); !ok || c.Alg != webauthn.AlgEdDSA {
		t.Fatalf("Credential(alice, her id) = %+v, %v", c, ok)
	}
	if _, ok := d.Credential("bob", id); ok {
		t.Fatal("Credential(bob, alice's id) found a credential")
	}
}
