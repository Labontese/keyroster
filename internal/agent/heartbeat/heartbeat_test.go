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
		{"pending.step", func(s *Status) { s.Pending.Step = "" }},
		{"stuck", func(s *Status) { s.Stuck = "stuck" }},
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
