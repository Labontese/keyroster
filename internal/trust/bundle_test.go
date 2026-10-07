package trust

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// goldenDocs returns the canonical golden policy and bundle bytes.
func goldenDocs(t *testing.T) (policy, bundle []byte) {
	t.Helper()
	policy = mustCanonical(t, goldenPolicy(t))
	return policy, mustCanonical(t, goldenBundle(t, policy))
}

// nonCanonicalVariants returns semantically equal or near-equal encodings
// of a canonical document that a lenient parser would accept.
func nonCanonicalVariants(t *testing.T, doc []byte) map[string][]byte {
	t.Helper()
	body := bytes.TrimSuffix(doc, []byte("\n"))
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		t.Fatal(err)
	}
	pretty.WriteByte('\n')
	// Swap the first two members: {"version":1,"prev":"..."} -> {"prev":"...","version":1}.
	first := bytes.IndexByte(body, ',')
	second := first + 1 + bytes.IndexByte(body[first+1:], ',')
	reordered := append(append(append([]byte("{"), body[first+1:second]...), ','), body[1:first]...)
	reordered = append(append(reordered, body[second:]...), '\n')

	replace := func(old, repl string) []byte {
		if !bytes.Contains(doc, []byte(old)) {
			t.Fatalf("fixture lacks %q", old)
		}
		return bytes.Replace(doc, []byte(old), []byte(repl), 1)
	}
	return map[string][]byte{
		"duplicate_key":          append([]byte(`{"version":1,`), doc[1:]...),
		"unknown_field":          append(append(bytes.Clone(body[:len(body)-1]), []byte(`,"extra":1}`)...), '\n'),
		"reordered_keys":         reordered,
		"pretty_printed":         pretty.Bytes(),
		"space_after_colon":      replace(`"version":1`, `"version": 1`),
		"trailing_bytes":         append(bytes.Clone(doc), 'x'),
		"trailing_newline_twice": append(bytes.Clone(doc), '\n'),
		"trailing_second_value":  append(bytes.Clone(doc), []byte("{}\n")...),
		"missing_newline":        body,
		"float":                  replace(`"version":1`, `"version":1.0`),
		"exponent":               replace(`"version":1`, `"version":1e0`),
		"utf8_bom":               append([]byte("\xef\xbb\xbf"), doc...),
		"capitalized_key":        replace(`"version"`, `"Version"`),
		"escaped_string":         replace(`"prev":"0`, `"prev":"`+"\\"+`u0030`),
		"crlf":                   append(bytes.Clone(body), '\r', '\n'),
	}
}

// TestCanonicalStrictness checks that every non-canonical encoding of a
// valid bundle or policy is refused with ErrNotCanonical, by the parsers
// and by VerifyGenesisBundle before any signature is checked (the
// signature inputs are empty here, so a signature check would fail with a
// different error).
func TestCanonicalStrictness(t *testing.T) {
	policy, bundle := goldenDocs(t)
	if _, err := ParseBundle(bundle); err != nil {
		t.Fatalf("golden bundle: %v", err)
	}
	if _, err := ParsePolicy(policy); err != nil {
		t.Fatalf("golden policy: %v", err)
	}
	pins := goldenPins(t)
	for name, v := range nonCanonicalVariants(t, bundle) {
		t.Run("bundle_"+name, func(t *testing.T) {
			if _, err := ParseBundle(v); !errors.Is(err, ErrNotCanonical) {
				t.Fatalf("ParseBundle: err = %v, want ErrNotCanonical", err)
			}
			if _, _, err := VerifyGenesisBundle(v, nil, policy, nil, pins, 1); !errors.Is(err, ErrNotCanonical) {
				t.Fatalf("VerifyGenesisBundle: err = %v, want ErrNotCanonical", err)
			}
		})
	}
	for name, v := range nonCanonicalVariants(t, policy) {
		t.Run("policy_"+name, func(t *testing.T) {
			if _, err := ParsePolicy(v); !errors.Is(err, ErrNotCanonical) {
				t.Fatalf("ParsePolicy: err = %v, want ErrNotCanonical", err)
			}
			if _, _, err := VerifyGenesisBundle(bundle, nil, v, nil, pins, 1); !errors.Is(err, ErrNotCanonical) {
				t.Fatalf("VerifyGenesisBundle: err = %v, want ErrNotCanonical", err)
			}
		})
	}
}

// TestBundleValidation checks that each structural violation is refused
// with its own error.
func TestBundleValidation(t *testing.T) {
	policy, _ := goldenDocs(t)
	rootA := keyOf(edKey(t, seedRootA))
	tests := []struct {
		name   string
		mutate func(b *Bundle)
		want   error
	}{
		{"ca_key_equals_root_key", func(b *Bundle) { b.CAs[0].Key, b.CAs[0].Alg = rootA, ssh.KeyAlgoED25519 }, ErrKeyIsRoot},
		{"ops_key_equals_root_key", func(b *Bundle) { b.OpsKey.Key, b.OpsKey.Alg = rootA, ssh.KeyAlgoED25519 }, ErrKeyIsRoot},
		{"log_key_equals_ca_key", func(b *Bundle) { b.Log.Key = b.CAs[1].Key; b.Log.Origin = originOf(t, b.Log.Key) }, ErrDuplicateKey},
		{"ops_key_equals_log_key", func(b *Bundle) { b.OpsKey.Key = b.Log.Key }, ErrDuplicateKey},
		{"duplicate_root_key", func(b *Bundle) { b.Root.Keys[1] = RootKey{Key: rootA, Custody: "software"} }, ErrDuplicateKey},
		{"alg_differs_from_key_type", func(b *Bundle) { b.CAs[0].Alg = ssh.KeyAlgoED25519 }, ErrAlgorithm},
		{"alg_rsa", func(b *Bundle) { b.OpsKey.Alg = "ssh-rsa" }, ErrAlgorithm},
		{"root_key_wrong_type_for_custody", func(b *Bundle) { b.Root.Keys[0].Custody = "fido" }, ErrCustody},
		{"unknown_ca_custody", func(b *Bundle) { b.CAs[2].Custody = "cloud-kms" }, ErrCustody},
		{"unknown_root_custody", func(b *Bundle) { b.Root.Keys[1].Custody = "paper" }, ErrCustody},
		{"missing_role", func(b *Bundle) { b.CAs = b.CAs[:2] }, ErrCARole},
		{"roles_out_of_order", func(b *Bundle) { b.CAs[0], b.CAs[1] = b.CAs[1], b.CAs[0] }, ErrCARole},
		{"unknown_role", func(b *Bundle) { b.CAs[2].Role = "admin" }, ErrCARole},
		{"two_active_cas_for_one_role", func(b *Bundle) {
			extra := b.CAs[0]
			extra.Key, extra.Generation = keyOf(p256Key(t, 30)), 2
			b.CAs = append([]CAEntry{b.CAs[0], extra}, b.CAs[1:]...)
		}, ErrActiveCA},
		{"log_origin_mismatch", func(b *Bundle) { b.Log.Origin = LogOriginPrefix + "0000000000000000" }, ErrLogOrigin},
		{"threshold_zero", func(b *Bundle) { b.Root.Threshold = 0 }, ErrInvalid},
		{"threshold_above_roots", func(b *Bundle) { b.Root.Threshold = 3 }, ErrInvalid},
		{"genesis_prev_not_zero", func(b *Bundle) { b.Prev = strings.Repeat("a", 64) }, ErrInvalid},
		{"issued_at_not_utc", func(b *Bundle) { b.IssuedAt = "2026-10-05T02:00:00+02:00" }, ErrInvalid},
		{"issued_at_fractional", func(b *Bundle) { b.IssuedAt = "2026-10-05T00:00:00.5Z" }, ErrInvalid},
		{"key_with_comment", func(b *Bundle) { b.CAs[0].Key += " user-ca" }, ErrInvalid},
		{"cas_null", func(b *Bundle) { b.CAs = nil }, ErrCARole},
	}
	sentinels := []error{ErrKeyIsRoot, ErrDuplicateKey, ErrAlgorithm, ErrCustody, ErrCARole, ErrActiveCA, ErrLogOrigin, ErrInvalid}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := goldenBundle(t, policy)
			tc.mutate(b)
			_, err := ParseBundle(mustCanonical(t, b))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			for _, other := range sentinels {
				if !errors.Is(other, tc.want) && errors.Is(err, other) {
					t.Fatalf("err = %v also matches %v; each refusal needs its own error", err, other)
				}
			}
		})
	}
}

// TestPolicyValidation checks the structural rules of a policy.
func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(p *Policy)
		want   error
	}{
		{"quorum_zero", func(p *Policy) { p.AdminQuorum = 0 }, ErrInvalid},
		{"quorum_above_admins", func(p *Policy) { p.AdminQuorum = 2 }, ErrInvalid},
		{"duplicate_admin_key", func(p *Policy) {
			p.Admins = append(p.Admins, AdminKey{Name: "bob", Key: p.Admins[0].Key})
		}, ErrDuplicateKey},
		{"duplicate_admin_name", func(p *Policy) {
			p.Admins = append(p.Admins, AdminKey{Name: "alice", Key: keyOf(edKey(t, 21))})
		}, ErrInvalid},
		{"missing_profile", func(p *Policy) { p.CAProfiles = p.CAProfiles[:2] }, ErrCARole},
		{"profiles_out_of_order", func(p *Policy) { p.CAProfiles[0], p.CAProfiles[1] = p.CAProfiles[1], p.CAProfiles[0] }, ErrCARole},
		{"zero_ttl", func(p *Policy) { p.CAProfiles[0].MaxTTLSeconds = 0 }, ErrInvalid},
		{"unknown_extension", func(p *Policy) { p.CAProfiles[0].AllowedExtensions = []string{"permit-everything"} }, ErrInvalid},
		{"unknown_critical_option", func(p *Policy) { p.CAProfiles[0].AllowedCriticalOptions = []string{"no-such-option"} }, ErrInvalid},
		{"host_profile_with_extension", func(p *Policy) { p.CAProfiles[1].DefaultExtensions = []string{"permit-pty"} }, ErrInvalid},
		{"default_also_allowed", func(p *Policy) { p.CAProfiles[0].AllowedExtensions = []string{"permit-pty"} }, ErrInvalid},
		{"unsorted_extensions", func(p *Policy) {
			p.CAProfiles[0].AllowedExtensions = []string{"permit-user-rc", "permit-port-forwarding"}
		}, ErrInvalid},
		{"null_extension_list", func(p *Policy) { p.CAProfiles[2].AllowedExtensions = nil }, ErrInvalid},
		{"version_zero", func(p *Policy) { p.Version = 0 }, ErrInvalid},
		{"genesis_prev_not_zero", func(p *Policy) { p.Prev = strings.Repeat("b", 64) }, ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := goldenPolicy(t)
			tc.mutate(p)
			if _, err := ParsePolicy(mustCanonical(t, p)); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	t.Run("admin_rsa_key_refused", func(t *testing.T) {
		p := goldenPolicy(t)
		p.Admins[0].Key = rsaTestKey(t)
		if _, err := ParsePolicy(mustCanonical(t, p)); !errors.Is(err, ErrAlgorithm) {
			t.Fatalf("err = %v, want ErrAlgorithm", err)
		}
	})
	// A-WR-03: an issue request carries at most MaxAdminQuorum evidence
	// items, so a larger quorum would make issuance impossible.
	withAdmins := func(n int, quorum uint32) *Policy {
		p := goldenPolicy(t)
		for i := 1; i < n; i++ {
			p.Admins = append(p.Admins, AdminKey{Name: "admin" + string(rune('a'+i)), Key: keyOf(edKey(t, byte(70+i)))})
		}
		p.AdminQuorum = quorum
		return p
	}
	t.Run("quorum_above_max_refused", func(t *testing.T) {
		_, err := ParsePolicy(mustCanonical(t, withAdmins(MaxAdminQuorum+1, MaxAdminQuorum+1)))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "most admin signatures") {
			t.Fatalf("err = %v, want ErrInvalid naming the evidence limit", err)
		}
	})
	t.Run("quorum_at_max_accepted", func(t *testing.T) {
		if _, err := ParsePolicy(mustCanonical(t, withAdmins(MaxAdminQuorum+1, MaxAdminQuorum))); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("timelock_zero_accepted", func(t *testing.T) {
		if _, err := ParsePolicy(mustCanonical(t, goldenPolicy(t))); err != nil {
			t.Fatal(err)
		}
	})
}

// TestCAPubKeysAndRootsFile checks the two unsigned ceremony inputs.
func TestCAPubKeysAndRootsFile(t *testing.T) {
	good := &CAPubKeys{}
	for i, role := range CAPubKeyRoles {
		good.Keys = append(good.Keys, CAPubKey{Role: role, Key: keyOf(p256Key(t, byte(40+i))), Alg: ssh.KeyAlgoECDSA256, Custody: "tpm"})
	}
	if _, err := ParseCAPubKeys(mustCanonical(t, good)); err != nil {
		t.Fatalf("valid ca-pubkeys: %v", err)
	}
	dup := *good
	dup.Keys = append([]CAPubKey{}, good.Keys...)
	dup.Keys[4].Key = dup.Keys[3].Key
	if _, err := ParseCAPubKeys(mustCanonical(t, &dup)); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("duplicate ops/log key: err = %v", err)
	}
	short := &CAPubKeys{Keys: good.Keys[:4]}
	if _, err := ParseCAPubKeys(mustCanonical(t, short)); !errors.Is(err, ErrCARole) {
		t.Fatalf("missing log key: err = %v", err)
	}

	rootA, rootB := keyOf(edKey(t, seedRootA)), keyOf(p256Key(t, seedRootB))
	roots, err := ParseRootsFile([]byte("# roots\n" + rootA + " custody=software\n\n" + rootB + " custody=piv\n"))
	if err != nil || len(roots) != 2 || roots[1].Custody != "piv" {
		t.Fatalf("valid roots file: %v %v", roots, err)
	}
	for name, data := range map[string]string{
		"no_custody":      rootA + "\n",
		"bad_custody":     rootA + " custody=usb\n",
		"duplicate":       rootA + " custody=software\n" + rootA + " custody=piv\n",
		"options":         `from="10.0.0.1" ` + rootA + " custody=software\n",
		"rsa_root":        rsaTestKey(t) + " custody=software\n",
		"empty":           "# nothing\n",
		"fido_for_non_sk": rootA + " custody=fido\n",
	} {
		if _, err := ParseRootsFile([]byte(data)); err == nil {
			t.Errorf("%s: roots file accepted", name)
		}
	}
}

func originOf(t *testing.T, key string) string {
	t.Helper()
	pub, err := ParseKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return LogOrigin(pub)
}

// rsaTestKey returns a fresh RSA public key; keyroster refuses RSA keys
// everywhere (D-09).
func rsaTestKey(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return FormatKey(pub)
}
