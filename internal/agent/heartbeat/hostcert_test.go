package heartbeat

import (
	"errors"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/trust"
)

// withHostCerts is full() with 03-09's host-certificate fields.
func withHostCerts() Status {
	s := full()
	h := strings.Repeat("0f", 32)
	s.HostCerts = []HostCert{{KeySHA256: h, Type: "ssh-ed25519-cert-v01@openssh.com", Serial: 1793000000000001, ValidBefore: 1795592000, CASHA256: h, Served: true},
		{KeySHA256: h, Type: "ecdsa-sha2-nistp256-cert-v01@openssh.com", Serial: 1793000000000002, ValidBefore: 1795592000, CASHA256: h}}
	s.HostKeysSkipped = []SkippedKey{{Type: "ssh-rsa", Reason: "rsa_host_key_skipped"}}
	s.HostCertDetail = "refused:cert_revoked"
	return s
}

// TestValidateHostCerts pins the rules of the host-certificate fields
// (03-09).
func TestValidateHostCerts(t *testing.T) {
	ok := withHostCerts()
	if err := Validate(&ok); err != nil {
		t.Fatalf("a status with host certificates: %v", err)
	}
	for _, c := range []struct {
		field string
		mut   func(s *Status)
	}{
		{"host_certs", func(s *Status) { s.HostCerts = append(s.HostCerts, make([]HostCert, MaxHostCerts-1)...) }},
		{"host_certs[0]", func(s *Status) { s.HostCerts[0].KeySHA256 = strings.Repeat("0f", 31) }},
		{"host_certs[0]", func(s *Status) { s.HostCerts[0].KeySHA256 = strings.ToUpper(s.HostCerts[0].KeySHA256) }},
		{"host_certs[1]", func(s *Status) { s.HostCerts[1].CASHA256 = "" }},
		{"host_certs[0]", func(s *Status) { s.HostCerts[0].Type = "ssh-ed25519\x00" }},
		{"host_certs[0]", func(s *Status) { s.HostCerts[0].Type = strings.Repeat("a", 65) }},
		{"host_certs[1]", func(s *Status) { s.HostCerts[1].Serial = 0 }},
		{"host_keys_skipped", func(s *Status) {
			s.HostKeysSkipped = append(s.HostKeysSkipped, make([]SkippedKey, MaxHostKeysSkipped)...)
		}},
		{"host_keys_skipped[0]", func(s *Status) { s.HostKeysSkipped[0].Type = "SSH-RSA" }},
		{"host_keys_skipped[0]", func(s *Status) { s.HostKeysSkipped[0].Reason = "rsa host key\n" }},
		{"host_cert_detail", func(s *Status) { s.HostCertDetail = "a:b:c" }},
		{"host_cert_detail", func(s *Status) { s.HostCertDetail = "Refused" }},
		{"host_cert_detail", func(s *Status) { s.HostCertDetail = strings.Repeat("a", MaxDetail+1) }},
		{"host_cert_detail", func(s *Status) { s.HostCertDetail = "refused:\x1b" }},
	} {
		s := withHostCerts()
		s.HostCerts = append([]HostCert(nil), s.HostCerts...)
		s.HostKeysSkipped = append([]SkippedKey(nil), s.HostKeysSkipped...)
		c.mut(&s)
		err := Validate(&s)
		if !errors.Is(err, ErrFieldInvalid) || Field(err) != c.field {
			t.Errorf("%s: %v, want heartbeat_field_invalid naming %s", c.field, err, c.field)
		}
	}
	// At the bounds: 8 certificates, 16 skipped key types, a 64-byte detail.
	bound := withHostCerts()
	for len(bound.HostCerts) < MaxHostCerts {
		bound.HostCerts = append(bound.HostCerts, bound.HostCerts[0])
	}
	for len(bound.HostKeysSkipped) < MaxHostKeysSkipped {
		bound.HostKeysSkipped = append(bound.HostKeysSkipped, bound.HostKeysSkipped[0])
	}
	bound.HostCertDetail = strings.Repeat("a", MaxDetail)
	if err := Validate(&bound); err != nil {
		t.Fatalf("a status at the bounds: %v", err)
	}

	// ParseHeartbeat accepts the fields, served false included, and a
	// heartbeat without them parses as before.
	b, err := trust.CanonicalJSON(Heartbeat{Status: withHostCerts(), ClockOffsetS: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"served":false`) {
		t.Fatalf("served false is not encoded: %s", b)
	}
	h, err := ParseHeartbeat(b)
	if err != nil || len(h.Status.HostCerts) != 2 || h.Status.HostCerts[1].Served || !h.Status.HostCerts[0].Served ||
		h.Status.HostKeysSkipped[0].Reason != "rsa_host_key_skipped" || h.Status.HostCertDetail != "refused:cert_revoked" {
		t.Fatalf("round trip: %v %+v", err, h)
	}
	b, err = trust.CanonicalJSON(Heartbeat{Status: full(), ClockOffsetS: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"host_certs", "host_keys_skipped", "host_cert_detail"} {
		if strings.Contains(string(b), `"`+f+`"`) {
			t.Fatalf("a status without host certificates encodes %s: %s", f, b)
		}
	}
	if h, err := ParseHeartbeat(b); err != nil || h.Status.HostCerts != nil {
		t.Fatalf("a heartbeat without the fields: %v %+v", err, h)
	}
}
