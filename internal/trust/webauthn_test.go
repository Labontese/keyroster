package trust

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyWebAuthn pins the Phase 2 policy field (D-09, RESEARCH Q4): an
// omitempty pointer that leaves every Phase 1 policy byte-identical, a
// null that is refused as non-canonical, and the owner-locked rp_id and
// origin rules.
func TestPolicyWebAuthn(t *testing.T) {
	t.Run("genesis_v1_vector_unchanged", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(vectorDir, "policy_genesis_v1.json")) //nolint:gosec // G304: fixed test vector path
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePolicy(data)
		if err != nil {
			t.Fatalf("the Phase 1 genesis policy no longer parses: %v", err)
		}
		if p.WebAuthn != nil {
			t.Fatal("a policy without the webauthn field decoded with one")
		}
		re, err := p.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("the Phase 1 genesis policy re-encodes differently:\n%s\nwant:\n%s", re, data)
		}
	})
	t.Run("null_refused", func(t *testing.T) {
		data := mustCanonical(t, goldenPolicy(t))
		withNull := append(bytes.TrimSuffix(data, []byte("}\n")), []byte(`,"webauthn":null}`+"\n")...)
		if _, err := ParsePolicy(withNull); !errors.Is(err, ErrNotCanonical) {
			t.Fatalf("ParsePolicy with \"webauthn\":null = %v, want ErrNotCanonical", err)
		}
	})
	t.Run("round_trip", func(t *testing.T) {
		p := goldenPolicy(t)
		p.WebAuthn = &WebAuthnRP{RPID: "keyroster.example.org", Origins: []string{"https://keyroster.example.org", "https://keyroster.example.org:8443"}}
		data := mustCanonical(t, p)
		if !bytes.Contains(data, []byte(`,"webauthn":{"rp_id":"keyroster.example.org","origins":["https://keyroster.example.org","https://keyroster.example.org:8443"]}}`)) {
			t.Fatalf("webauthn is not the last field of the canonical policy:\n%s", data)
		}
		got, err := ParsePolicy(data)
		if err != nil {
			t.Fatal(err)
		}
		if got.WebAuthn == nil || got.WebAuthn.RPID != "keyroster.example.org" || len(got.WebAuthn.Origins) != 2 {
			t.Fatalf("round trip lost the RP: %+v", got.WebAuthn)
		}
	})
}

// TestPolicyWebAuthnRPID covers the rp_id rule: a lowercase DNS hostname
// of at least two labels, never an IP literal, port, trailing dot,
// all-digit last label or bare tailnet domain.
func TestPolicyWebAuthnRPID(t *testing.T) {
	for _, tc := range []struct {
		name string
		rp   string
		ok   bool
	}{
		{"dns_name_accepted", "keyroster.example.org", true},
		{"tailnet_machine_accepted", "machine.tailnet.ts.net", true},
		{"c_tailnet_machine_accepted", "machine.tailnet.c.ts.net", true},
		{"localhost_subdomain_accepted", "keyroster.localhost", true},
		{"ip_literal_refused", "127.0.0.1", false},
		{"ipv6_literal_refused", "[::1]", false},
		{"port_refused", "example.org:8443", false},
		{"uppercase_refused", "Example.org", false},
		{"single_label_refused", "localhost", false},
		{"tailnet_domain_refused", "tailnet.ts.net", false},
		{"ts_net_refused", "ts.net", false},
		{"c_tailnet_domain_refused", "tailnet.c.ts.net", false},
		{"digit_tld_refused", "host.123", false},
		{"trailing_dot_refused", "example.org.", false},
		{"empty_refused", "", false},
		{"label_hyphen_edge_refused", "-a.example.org", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := goldenPolicy(t)
			p.WebAuthn = &WebAuthnRP{RPID: tc.rp, Origins: []string{"https://" + tc.rp}}
			err := p.Validate()
			if tc.ok && err != nil {
				t.Fatalf("rp_id %q refused: %v", tc.rp, err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("rp_id %q: Validate = %v, want ErrInvalid", tc.rp, err)
			}
		})
	}
}

// TestPolicyWebAuthnOrigins covers the origin rule: exactly https://<rp_id>
// with an optional port other than 443, in a sorted duplicate-free list.
func TestPolicyWebAuthnOrigins(t *testing.T) {
	const rp = "keyroster.example.org"
	for _, tc := range []struct {
		name    string
		origins []string
		ok      bool
	}{
		{"plain", []string{"https://" + rp}, true},
		{"with_port", []string{"https://" + rp, "https://" + rp + ":8443"}, true},
		{"empty_refused", []string{}, false},
		{"unsorted_refused", []string{"https://" + rp + ":8443", "https://" + rp}, false},
		{"duplicate_refused", []string{"https://" + rp, "https://" + rp}, false},
		{"path_refused", []string{"https://" + rp + "/login"}, false},
		{"trailing_slash_refused", []string{"https://" + rp + "/"}, false},
		{"http_refused", []string{"http://" + rp}, false},
		{"default_port_refused", []string{"https://" + rp + ":443"}, false},
		{"leading_zero_port_refused", []string{"https://" + rp + ":08443"}, false},
		{"port_out_of_range_refused", []string{"https://" + rp + ":65536"}, false},
		{"uppercase_refused", []string{"https://" + strings.ToUpper(rp)}, false},
		{"other_host_refused", []string{"https://other.example.org"}, false},
		{"subdomain_refused", []string{"https://a." + rp}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := goldenPolicy(t)
			p.WebAuthn = &WebAuthnRP{RPID: rp, Origins: tc.origins}
			err := p.Validate()
			if tc.ok && err != nil {
				t.Fatalf("origins %q refused: %v", tc.origins, err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalid) {
				t.Fatalf("origins %q: Validate = %v, want ErrInvalid", tc.origins, err)
			}
		})
	}
}
