package cert

import (
	"errors"
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
			if got != tc.k {
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

func FuzzParseKeyID(f *testing.F) {
	for _, s := range []string{
		validKeyIDString,
		"kr1/ca=host/sub=h:web/req=" + testRequestHex + "/pol=7/ser=18446744073709551615",
		"kr1/ca=machine/sub=m:x/req=" + testRequestHex + "/pol=0/ser=1",
		"kr2/ca=user/sub=u:alice/req=" + testRequestHex + "/pol=0/ser=42",
		"kr1/ca=user/sub=u:a/b/req=" + testRequestHex + "/pol=0/ser=42",
		"kr1/ca=user/sub=/req=/pol=/ser=",
		"kr1/ca=user/sub=u:alice/req=" + testRequestHex + "/pol=01/ser=42",
		"",
		"kr1/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParseKeyID(s)
		if err != nil {
			if !errors.Is(err, ErrKeyID) {
				t.Fatalf("ParseKeyID(%q) = %v, want ErrKeyID", s, err)
			}
			return
		}
		if got := k.String(); got != s {
			t.Fatalf("accepted key ID %q formats back as %q", s, got)
		}
	})
}
