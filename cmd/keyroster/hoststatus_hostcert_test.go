package main

import (
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/serverclient"
)

// TestHostStatusHostCerts: keyroster host status prints a host's host
// certificates, skipped key types and host_cert_detail (03-09) through the
// existing escaping and checks; a host without them prints none.
func TestHostStatusHostCerts(t *testing.T) {
	ab := strings.Repeat("ab", 32)
	certs := hbStatus(5, 100)
	certs.HostCerts = []heartbeat.HostCert{
		{KeySHA256: strings.Repeat("01", 32), Type: "ssh-ed25519-cert-v01@openssh.com", Serial: 1793000000000001, ValidBefore: 1795592000, CASHA256: strings.Repeat("02", 32), Served: true},
		{KeySHA256: strings.Repeat("03", 32), Type: "ecdsa-sha2-nistp256-cert-v01@openssh.com", Serial: 1793000000000002, ValidBefore: 1795592000, CASHA256: strings.Repeat("02", 32)},
	}
	certs.HostKeysSkipped = []heartbeat.SkippedKey{{Type: "ssh-rsa", Reason: "rsa_host_key_skipped"}}
	certs.HostCertDetail = "refused:cert_revoked"
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 1, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts": []serverclient.HostStatusRow{
			statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: certs}),
			statusRow("web2", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: hbStatus(5, 100)}),
		},
	})
	code, out, stderr := run(t, "host", "status")
	if code != 0 {
		t.Fatalf("host status: exit %d: %s", code, stderr)
	}
	for _, want := range []string{
		"web1: host certificate ssh-ed25519-cert-v01@openssh.com serial 1793000000000001 for key " + strings.Repeat("01", 32) + ", valid before 2026-11-25T07:33:20Z, served true",
		"web1: host certificate ecdsa-sha2-nistp256-cert-v01@openssh.com serial 1793000000000002", "served false",
		"web1: host key ssh-rsa skipped: rsa_host_key_skipped",
		"host_cert: refused:cert_revoked",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "web2: host certificate") || strings.Contains(out, "web2: host key") {
		t.Errorf("web2 has no host certificates but shows some:\n%s", out)
	}

	// A detail outside the grammar never reaches the terminal: the CLI's
	// check refuses the answer.
	bad := hbStatus(5, 100)
	bad.HostCertDetail = "refused:\x1b[2J"
	statusEnv(t, map[string]any{
		"current": map[string]any{"bundle": 1, "directory": 5, "krl": 100, "bundle_sha256": ab, "directory_sha256": ab, "krl_sha256": ab},
		"hosts":   []serverclient.HostStatusRow{statusRow("web1", serverclient.HostStateActive, &heartbeat.Heartbeat{Status: bad})},
	})
	code, out, stderr = run(t, "host", "status")
	if code == 0 || strings.Contains(out+stderr, "\x1b") || !strings.Contains(stderr, "host_cert_detail") {
		t.Fatalf("a bad host_cert_detail: exit %d, out %q, stderr %q; want a refusal naming the field and no escape byte", code, out, stderr)
	}
}
