package heartbeat

import (
	"errors"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/trust"
)

func full() Status {
	h := strings.Repeat("0f", 32)
	return Status{
		AgentVersion: "keyroster-agent v0.3.0",
		Bundle:       Doc{Version: 2, SHA256: h}, Policy: Doc{Version: 2, SHA256: h}, Directory: Doc{Version: 9, SHA256: h},
		KRL:          KRL{Version: 1793196839, SHA256: h, IssuedAt: "2026-10-28T12:00:00Z"},
		Generation:   4,
		Files:        []File{{Path: "principals/deploy", SHA256: h}, {Path: "revoked.krl", SHA256: h}, {Path: "user_ca_keys", SHA256: h}},
		DropInSHA256: h, SSHDVersion: "OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13 30 Jan 2024",
		Effective: Effective{TrustedUserCAKeys: "/etc/ssh/keyroster/current/user_ca_keys", RevokedKeys: "/etc/ssh/keyroster/current/revoked.krl",
			AuthorizedPrincipalsFile: "/etc/ssh/keyroster/current/principals/%u", HostCertificate: ""},
		LastApply: &LastApply{At: "2026-10-28T12:00:00Z", Result: ResultOK, Detail: "probe:negative_refused", HostStatus: "host_removed"},
		LastCheck: &LastCheck{At: "2026-10-28T12:15:00Z", Drift: true},
		Pending:   &Pending{Step: StepCommit, From: 3, To: 4},
		Stuck:     StuckPendingStateUnknown, KRLStale: true, Seq: 1793196839000000,
	}
}

// TestValidate pins Validate's rules field by field (03-08, T-03-227).
func TestValidate(t *testing.T) {
	ok := full()
	if err := Validate(&ok); err != nil {
		t.Fatalf("a full status: %v", err)
	}
	for _, c := range []struct {
		field string
		mut   func(s *Status)
	}{
		{"agent_version", func(s *Status) { s.AgentVersion = "v\x00" }},
		{"bundle.sha256", func(s *Status) { s.Bundle.SHA256 = "" }},
		{"policy.sha256", func(s *Status) { s.Policy = Doc{Version: 0, SHA256: strings.Repeat("0f", 32)} }},
		{"directory.sha256", func(s *Status) { s.Directory.SHA256 = strings.Repeat("0f", 31) }},
		{"krl.sha256", func(s *Status) { s.KRL.SHA256 = strings.ToUpper(s.KRL.SHA256) }},
		{"krl.issued_at", func(s *Status) { s.KRL.IssuedAt = "2026-10-28T12:00:00.5Z" }},
		{"files", func(s *Status) { s.Files = nil }},
		{"files[0].path", func(s *Status) { s.Files[0].Path = "/etc/passwd" }},
		{"files[0].path", func(s *Status) { s.Files[0].Path = "principals/" + strings.Repeat("a", 120) }},
		{"files[2].path", func(s *Status) { s.Files[2].Path = "Principals" }},
		{"files[1].sha256", func(s *Status) { s.Files[1].SHA256 = "x" }},
		{"files", func(s *Status) { s.Generation = 0 }},
		{"dropin_sha256", func(s *Status) { s.DropInSHA256 = "nope" }},
		{"sshd_version", func(s *Status) { s.SSHDVersion = strings.Repeat("x", MaxText+1) }},
		{"effective.revokedkeys", func(s *Status) { s.Effective.RevokedKeys = "a\tb" }},
		{"last_apply.at", func(s *Status) { s.LastApply.At = "yesterday" }},
		{"last_apply.result", func(s *Status) { s.LastApply.Result = "OK" }},
		{"last_apply.error", func(s *Status) { s.LastApply.Error = "\x7f" }},
		{"last_apply.detail", func(s *Status) { s.LastApply.Detail = "a:b:c" }},
		{"last_apply.host_status", func(s *Status) { s.LastApply.HostStatus = "host_gone" }},
		{"last_check.at", func(s *Status) { s.LastCheck.At = "" }},
		{"last_check.error", func(s *Status) { s.LastCheck.Error = "sshd_T_failed: \x1b[2J" }},
		{"last_check.error", func(s *Status) { s.LastCheck.Error, s.LastCheck.Drift = "sshd_T_failed: x", true }},
		{"pending.step", func(s *Status) { s.Pending.Step = "" }},
		{"stuck", func(s *Status) { s.Stuck = "stuck" }},
		{"unapplied", func(s *Status) { s.Unapplied = &Unapplied{} }},
		{"unapplied.bundle_sha256", func(s *Status) {
			s.Unapplied = &Unapplied{Directory: 65, BundleSHA256: strings.Repeat("0f", 32)}
		}},
		{"unapplied.directory_sha256", func(s *Status) {
			s.Unapplied = &Unapplied{Directory: 65, DirectorySHA256: strings.Repeat("0F", 32)}
		}},
		{"seq", func(s *Status) { s.Seq = 0 }},
		{"seq", func(s *Status) { s.Seq = 1 << 63 }},
	} {
		s := full()
		s.Files = append([]File(nil), s.Files...)
		la, lc, p := *s.LastApply, *s.LastCheck, *s.Pending
		s.LastApply, s.LastCheck, s.Pending = &la, &lc, &p
		c.mut(&s)
		err := Validate(&s)
		if !errors.Is(err, ErrFieldInvalid) || Field(err) != c.field {
			t.Errorf("%s: %v, want heartbeat_field_invalid naming %s", c.field, err, c.field)
		}
	}
	h := Heartbeat{Status: full(), ClockOffsetS: MaxClockOffset + 1}
	if err := ValidateHeartbeat(&h); Field(err) != "clock_offset_s" {
		t.Errorf("an offset above the bound: %v", err)
	}
	// PR #76 review F8 (03-08j): a status naming an unapplied directory
	// passes and survives the strict round trip.
	un := full()
	un.Unapplied = &Unapplied{Directory: 65, DirectorySHA256: strings.Repeat("0f", 32)}
	if err := Validate(&un); err != nil {
		t.Errorf("a status with unapplied {directory: 65}: %v", err)
	}
	// An agent from before the SHA-256 fields sends versions only.
	old := full()
	old.Unapplied = &Unapplied{Bundle: 2, Directory: 65}
	if err := Validate(&old); err != nil {
		t.Errorf("a status with unapplied versions only: %v", err)
	}
	if b, err := trust.CanonicalJSON(&un); err != nil {
		t.Error(err)
	} else if back, err := ParseStatus(b); err != nil || back.Unapplied == nil || *back.Unapplied != *un.Unapplied {
		t.Errorf("unapplied after ParseStatus: %+v, %v", back, err)
	}
}

// TestParseHeartbeat: the canonical encoding round-trips; anything else,
// an unknown field and a body above MaxBody are refused.
func TestParseHeartbeat(t *testing.T) {
	b, err := trust.CanonicalJSON(Heartbeat{Status: full(), ClockOffsetS: -3})
	if err != nil {
		t.Fatal(err)
	}
	h, err := ParseHeartbeat(b)
	if err != nil || h.ClockOffsetS != -3 || h.Status.Seq != full().Seq {
		t.Fatalf("round trip: %v %+v", err, h)
	}
	for name, body := range map[string]string{
		"unknown_field": strings.Replace(string(b), `"clock_offset_s"`, `"extra":1,"clock_offset_s"`, 1),
		"not_canonical": " " + string(b),
		"too_large":     string(b[:len(b)-2]) + strings.Repeat(" ", MaxBody) + "}\n",
	} {
		if _, err := ParseHeartbeat([]byte(body)); !errors.Is(err, ErrFieldInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestClockSkew(t *testing.T) {
	for off, want := range map[int64]bool{0: false, 300: false, -300: false, 301: true, -301: true} {
		if ClockSkew(off) != want {
			t.Errorf("ClockSkew(%d) = %v", off, !want)
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("a\x1b[2Jb\n", 5); got != "a?[2J" {
		t.Fatalf("Sanitize = %q", got)
	}
}

// FuzzParseHeartbeat: the parser never panics, and what it accepts
// re-encodes to exactly the input and passes Validate.
func FuzzParseHeartbeat(f *testing.F) {
	b, _ := trust.CanonicalJSON(Heartbeat{Status: full(), ClockOffsetS: 7})
	f.Add(b)
	e, _ := trust.CanonicalJSON(Heartbeat{Status: Status{Files: []File{}, Seq: 1}})
	f.Add(e)
	f.Add([]byte(`{"status":{},"clock_offset_s":0}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ParseHeartbeat(data)
		if err != nil {
			if !errors.Is(err, ErrFieldInvalid) {
				t.Fatalf("an error outside heartbeat_field_invalid: %v", err)
			}
			return
		}
		if err := ValidateHeartbeat(h); err != nil {
			t.Fatalf("accepted an invalid heartbeat: %v", err)
		}
		c, err := trust.CanonicalJSON(h)
		if err != nil || string(c) != string(data) {
			t.Fatalf("accepted a non-canonical body")
		}
	})
}

// FuzzParseStatus is FuzzParseHeartbeat for status.json.
func FuzzParseStatus(f *testing.F) {
	s := full()
	b, _ := trust.CanonicalJSON(s)
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		st, err := ParseStatus(data)
		if err != nil {
			return
		}
		if err := Validate(st); err != nil {
			t.Fatalf("accepted an invalid status: %v", err)
		}
	})
}

// TestCommittedAndDiverged (PR #72 review C5): a host is on a version only
// with its SHA-256 too, and one above the current version or on the
// current number with other bytes is diverged. So is one whose unapplied
// record is above the current version (PR #78 review).
func TestCommittedAndDiverged(t *testing.T) {
	ab, cd := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	cur := Doc{Version: 5, SHA256: ab}
	one := Doc{Version: 1, SHA256: ab}
	for _, c := range []struct {
		name                string
		dir                 Doc
		pending             bool
		unapplied           *Unapplied
		committed, diverged bool
	}{
		{"same", cur, false, nil, true, false},
		{"pending", cur, true, nil, false, false},
		{"older", Doc{Version: 4, SHA256: cd}, false, nil, false, false},
		{"same_number_other_sha", Doc{Version: 5, SHA256: cd}, false, nil, false, true},
		{"above_current", Doc{Version: 6, SHA256: cd}, false, nil, false, true},
		{"unapplied_directory_at_current", Doc{Version: 4, SHA256: cd}, false, &Unapplied{Directory: 5}, false, false},
		{"unapplied_directory_above_current", cur, false, &Unapplied{Directory: 6}, false, true},
		{"unapplied_bundle_above_current", cur, false, &Unapplied{Bundle: 2}, false, true},
		// PR #78 review, fix round 2: at the current number, the recorded
		// SHA-256 decides; without one (an older agent) only the number.
		{"unapplied_directory_at_current_same_bytes", Doc{Version: 4, SHA256: cd}, false, &Unapplied{Directory: 5, DirectorySHA256: ab}, false, false},
		{"unapplied_directory_at_current_other_bytes", Doc{Version: 4, SHA256: cd}, false, &Unapplied{Directory: 5, DirectorySHA256: cd}, false, true},
		{"unapplied_bundle_at_current_other_bytes", cur, false, &Unapplied{Bundle: 1, BundleSHA256: cd}, false, true},
		{"unapplied_bundle_at_current_same_bytes", cur, false, &Unapplied{Bundle: 1, BundleSHA256: ab}, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := Status{Bundle: one, Directory: c.dir, KRL: KRL{Version: 1, SHA256: ab}, Unapplied: c.unapplied}
			if c.pending {
				s.Pending = &Pending{Step: StepIntermediate}
			}
			if got := s.Committed(one, cur, one); got != c.committed {
				t.Errorf("Committed = %v, want %v", got, c.committed)
			}
			if got := s.Diverged(one, cur, one); got != c.diverged {
				t.Errorf("Diverged = %v, want %v", got, c.diverged)
			}
		})
	}
}

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
