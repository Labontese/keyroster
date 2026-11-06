package cert

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

const validKeyIDString = "kr1/ca=user/sub=u:alice/req=" + testRequestHex + "/pol=0/ser=42"

func TestKeyIDRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		k    KeyID
	}{
		{"user_policy_zero", KeyID{CA: "user", Subject: "u:alice", Request: testRequestHex, Policy: 0, Serial: 42}},
		{"host_policy_set", KeyID{CA: "host", Subject: "h:web-01.example", Request: testRequestHex, Policy: 7, Serial: 1}},
		{"machine_max_serial", KeyID{CA: "machine", Subject: "m:ci+deploy@x", Request: testRequestHex, Policy: 1 << 40, Serial: 1<<64 - 1}},
		{"subject_64_bytes", KeyID{CA: "user", Subject: strings.Repeat("a", 64), Request: testRequestHex, Policy: 0, Serial: 9}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.k.String()
			got, err := ParseKeyID(s)
			if err != nil {
				t.Fatalf("ParseKeyID(%q): %v", s, err)
			}
			if !got.Equal(tc.k) {
				t.Fatalf("ParseKeyID(%q) = %+v, want %+v", s, got, tc.k)
			}
		})
	}
	if s := (KeyID{CA: "user", Subject: "u:alice", Request: testRequestHex, Serial: 42}).String(); s != validKeyIDString {
		t.Fatalf("String() = %q, want the fixed field order %q", s, validKeyIDString)
	}
}

func TestParseKeyIDRefusals(t *testing.T) {
	r := testRequestHex
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"kr2_prefix", "kr2/ca=user/sub=u:alice/req=" + r + "/pol=0/ser=42"},
		{"no_prefix", "ca=user/sub=u:alice/req=" + r + "/pol=0/ser=42"},
		{"uppercase_prefix", "KR1/ca=user/sub=u:alice/req=" + r + "/pol=0/ser=42"},
		{"slash_in_subject", "kr1/ca=user/sub=u:a/b/req=" + r + "/pol=0/ser=42"},
		{"equals_in_subject", "kr1/ca=user/sub=u=alice/req=" + r + "/pol=0/ser=42"},
		{"equals_in_ca", "kr1/ca=us=er/sub=u:alice/req=" + r + "/pol=0/ser=42"},
		{"empty_ca", "kr1/ca=/sub=u:alice/req=" + r + "/pol=0/ser=42"},
		{"empty_subject", "kr1/ca=user/sub=/req=" + r + "/pol=0/ser=42"},
		{"empty_request", "kr1/ca=user/sub=u:alice/req=/pol=0/ser=42"},
		{"empty_policy", "kr1/ca=user/sub=u:alice/req=" + r + "/pol=/ser=42"},
		{"empty_serial", "kr1/ca=user/sub=u:alice/req=" + r + "/pol=0/ser="},
		{"uppercase_hex", "kr1/ca=user/sub=u:alice/req=" + strings.ToUpper(r) + "/pol=0/ser=42"},
		{"short_request", "kr1/ca=user/sub=u:alice/req=" + r[:31] + "/pol=0/ser=42"},
		{"long_request", "kr1/ca=user/sub=u:alice/req=" + r + "0/pol=0/ser=42"},
		{"leading_zero_policy", "kr1/ca=user/sub=u:alice/req=" + r + "/pol=01/ser=42"},
		{"leading_zero_serial", "kr1/ca=user/sub=u:alice/req=" + r + "/pol=0/ser=042"},
		{"signed_serial", "kr1/ca=user/sub=u:alice/req=" + r + "/pol=0/ser=+42"},
		{"serial_overflow", "kr1/ca=user/sub=u:alice/req=" + r + "/pol=0/ser=18446744073709551616"},
		{"reordered_fields", "kr1/sub=u:alice/ca=user/req=" + r + "/pol=0/ser=42"},
		{"reordered_tail", "kr1/ca=user/sub=u:alice/req=" + r + "/ser=42/pol=0"},
		{"missing_field", "kr1/ca=user/sub=u:alice/req=" + r + "/ser=42"},
		{"extra_field", "kr1/ca=user/sub=u:alice/req=" + r + "/pol=0/ser=42/x=1"},
		{"trailing_slash", "kr1/ca=user/sub=u:alice/req=" + r + "/pol=0/ser=42/"},
		{"unknown_ca", "kr1/ca=root/sub=u:alice/req=" + r + "/pol=0/ser=42"},
		{"uppercase_subject", "kr1/ca=user/sub=U:alice/req=" + r + "/pol=0/ser=42"},
		{"subject_65_bytes", "kr1/ca=user/sub=" + strings.Repeat("a", 65) + "/req=" + r + "/pol=0/ser=42"},
		{"field_name_case", "kr1/CA=user/sub=u:alice/req=" + r + "/pol=0/ser=42"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeyID(tc.in); !errors.Is(err, ErrKeyID) {
				t.Fatalf("ParseKeyID(%q) error = %v, want ErrKeyID", tc.in, err)
			}
		})
	}
}

// TestKeyIDKr2Golden pins the kr2 format (D-08) with a literal: the field
// order, "+" between sorted roles and the decimals.
func TestKeyIDKr2Golden(t *testing.T) {
	const want = "kr2/ca=user/sub=alice/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=1/roles=admin+ops/ser=1700000000000003"
	k := KeyID{CA: "user", Subject: "alice", Request: "000102030405060708090a0b0c0d0e0f", Policy: 2, Directory: 1,
		Roles: []string{"admin", "ops"}, Serial: 1700000000000003}
	if got := k.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	got, err := ParseKeyID(want)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(k) {
		t.Fatalf("ParseKeyID(%q) = %+v, want %+v", want, got, k)
	}
}

// TestKeyIDKr2 covers kr2 round trips, the unchanged kr1 of the Phase 1
// issue-leaf vector, and kr2 refusals.
func TestKeyIDKr2(t *testing.T) {
	r := testRequestHex
	for _, k := range []KeyID{
		{CA: "user", Subject: "alice", Request: r, Policy: 1, Directory: 7, Roles: []string{"ops"}, Serial: 9},
		{CA: "user", Subject: "bob.smith", Request: r, Policy: 3, Directory: 1 << 40, Roles: []string{"a", "b.c", "d-e", "f_g"}, Serial: 1<<64 - 1},
		{CA: "user", Subject: "alice", Request: r, Policy: 1, Directory: 1, Roles: sixteenRoles(), Serial: 1},
	} {
		got, err := ParseKeyID(k.String())
		if err != nil {
			t.Fatalf("ParseKeyID(%q): %v", k.String(), err)
		}
		if !got.Equal(k) || got.String() != k.String() {
			t.Fatalf("round trip of %q gave %+v", k.String(), got)
		}
	}

	// The kr1 key ID of test/vectors/leaf_issue_v1.hex (Phase 1) still
	// parses and formats back identically, as kr1.
	const kr1 = "kr1/ca=user/sub=u:alice/req=000102030405060708090a0b0c0d0e0f/pol=0/ser=1700000000000001"
	vec, err := os.ReadFile("../../test/vectors/leaf_issue_v1.hex")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(vec)))
	if err != nil || !bytes.Contains(raw, []byte(kr1)) {
		t.Fatalf("leaf_issue_v1.hex does not hold the key ID %q (%v)", kr1, err)
	}
	k1, err := ParseKeyID(kr1)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Roles != nil || k1.Directory != 0 || k1.String() != kr1 {
		t.Fatalf("Phase 1 key ID parsed as %+v, formats as %q", k1, k1.String())
	}

	pre := "kr2/ca=user/sub=alice/req=" + r + "/pol=1/dir=1/roles="
	for _, tc := range []struct{ name, in string }{
		{"unsorted_roles", pre + "ops+admin/ser=1"},
		{"duplicate_roles", pre + "ops+ops/ser=1"},
		{"seventeen_roles", pre + strings.Join(append(sixteenRoles(), "zz"), "+") + "/ser=1"},
		{"role_name_too_long", pre + strings.Repeat("a", 33) + "/ser=1"},
		{"empty_roles", pre + "/ser=1"},
		{"trailing_plus", pre + "ops+/ser=1"},
		{"uppercase_role", pre + "Ops/ser=1"},
		{"missing_dir", "kr2/ca=user/sub=alice/req=" + r + "/pol=1/roles=ops/ser=1"},
		{"leading_zero_dir", "kr2/ca=user/sub=alice/req=" + r + "/pol=1/dir=01/roles=ops/ser=1"},
		{"kr1_with_dir", "kr1/ca=user/sub=alice/req=" + r + "/pol=1/dir=1/ser=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKeyID(tc.in); !errors.Is(err, ErrKeyID) {
				t.Fatalf("ParseKeyID(%q) = %v, want ErrKeyID", tc.in, err)
			}
		})
	}

	// The length cap is checked before anything else. No key ID that is
	// otherwise valid reaches 1024 bytes (the longest kr2 is about 730), so
	// the cap is pinned by its error text: 1025 bytes hit it, 1024 do not.
	long := func(n int) string {
		s := pre + "ops/ser=1"
		return s + strings.Repeat("x", n-len(s))
	}
	if _, err := ParseKeyID(long(MaxKeyIDLen + 1)); !errors.Is(err, ErrKeyID) || !strings.Contains(err.Error(), "longer than 1024 bytes") {
		t.Fatalf("ParseKeyID of %d bytes = %v, want the length limit", MaxKeyIDLen+1, err)
	}
	if _, err := ParseKeyID(long(MaxKeyIDLen)); !errors.Is(err, ErrKeyID) || strings.Contains(err.Error(), "longer than") {
		t.Fatalf("ParseKeyID of %d bytes = %v, want a refusal other than the length limit", MaxKeyIDLen, err)
	}
}

// sixteenRoles returns 16 sorted role names.
func sixteenRoles() []string {
	var out []string
	for i := range 16 {
		out = append(out, "r"+string(rune('a'+i)))
	}
	return out
}

// TestKeyIDKr3: the kr3 key ID of certificates obtained by proof of
// possession (03-09), with its subject bounds (Q-09-8).
func TestKeyIDKr3(t *testing.T) {
	const host = "kr3/ca=host/sub=web1/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=3/ser=1700000000000005"
	t.Run("round_trip", func(t *testing.T) {
		k, err := ParseKeyID(host)
		if err != nil || !k.V3 || k.CA != "host" || k.Subject != "web1" || k.Policy != 2 || k.Directory != 3 || k.Serial != 1700000000000005 || k.Roles != nil {
			t.Fatalf("ParseKeyID(%q) = %+v, %v", host, k, err)
		}
		if k.String() != host {
			t.Fatalf("String() = %q", k.String())
		}
		if !k.Equal(k) || k.Equal(KeyID{CA: k.CA, Subject: k.Subject, Request: k.Request, Policy: k.Policy, Directory: k.Directory, Serial: k.Serial}) {
			t.Fatal("Equal does not compare V3")
		}
	})
	probe := "probe." + strings.Repeat("a", 64)
	t.Run("probe_subject_70", func(t *testing.T) {
		id := "kr3/ca=machine/sub=" + probe + "/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=3/ser=1"
		if k, err := ParseKeyID(id); err != nil || k.Subject != probe || k.String() != id {
			t.Fatalf("a 70-byte probe. subject: %+v, %v", k, err)
		}
		if _, err := ParseKeyID("kr3/ca=machine/sub=" + probe + "a/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=3/ser=1"); err == nil {
			t.Fatal("a 71-byte probe. subject was accepted")
		}
	})
	t.Run("host_subject_65_refused", func(t *testing.T) {
		long := strings.Repeat("a", 65)
		for _, ca := range []string{"host", "machine"} {
			if _, err := ParseKeyID("kr3/ca=" + ca + "/sub=" + long + "/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=3/ser=1"); err == nil {
				t.Errorf("a 65-byte ca=%s subject was accepted", ca)
			}
		}
		if _, err := ParseKeyID("kr3/ca=host/sub=" + probe + "/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=3/ser=1"); err == nil {
			t.Error("a 70-byte probe. subject was accepted for ca=host")
		}
	})
	t.Run("kr1_kr2_keep_64", func(t *testing.T) {
		long := strings.Repeat("a", 65)
		for _, id := range []string{
			"kr1/ca=host/sub=" + long + "/req=000102030405060708090a0b0c0d0e0f/pol=2/ser=1",
			"kr2/ca=user/sub=" + long + "/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=3/roles=ops/ser=1",
			"kr1/ca=machine/sub=" + probe + "/req=000102030405060708090a0b0c0d0e0f/pol=2/ser=1",
		} {
			if _, err := ParseKeyID(id); err == nil {
				t.Errorf("%q was accepted", id)
			}
		}
	})
	t.Run("user_and_roles_refused", func(t *testing.T) {
		for _, id := range []string{
			"kr3/ca=user/sub=alice/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=3/ser=1",
			"kr3/ca=host/sub=web1/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=3/roles=ops/ser=1",
		} {
			if _, err := ParseKeyID(id); err == nil {
				t.Errorf("%q was accepted", id)
			}
		}
	})
}
