package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRunbookGoToolchain: the install runbooks build with go.mod's
// toolchain line and check it in the binaries. An older toolchain builds
// fine (the go directive is lower) but links a standard library whose
// fixed vulnerabilities the server and client reach, and nothing else
// would notice.
func TestRunbookGoToolchain(t *testing.T) {
	mod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^toolchain (go1\.[0-9]+\.[0-9]+)\s*$`).FindSubmatch(mod)
	if m == nil {
		t.Fatal("go.mod has no toolchain line")
	}
	toolchain := string(m[1])
	goVersion := regexp.MustCompile(`go1\.[0-9]+\.[0-9]+`)
	for _, name := range []string{"signer-install.md", "server-install.md"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", name)) //nolint:gosec // G304: a constant runbook name under docs/runbooks
		if err != nil {
			t.Fatal(err)
		}
		doc := string(data)
		for _, v := range goVersion.FindAllString(doc, -1) {
			if v != toolchain {
				t.Errorf("%s names %s, but go.mod's toolchain line is %s", name, v, toolchain)
			}
		}
		if !strings.Contains(doc, `export GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)`) {
			t.Errorf("%s does not set GOTOOLCHAIN from go.mod's toolchain line before building", name)
		}
		if !regexp.MustCompile(`(?m)^go version keyroster`).MatchString(doc) {
			t.Errorf("%s does not check the built binaries with go version", name)
		}
	}
}

// TestServerInstallTailscalePrerequisites: the "With Tailscale" path of
// server-install.md step 3 runs `tailscale cert`, which fails on a host
// without tailscaled joined to a tailnet with MagicDNS and HTTPS
// Certificates enabled, and the RP ID is the MagicDNS name. No step of the
// runbook sets these up, so "What you need" must list them.
func TestServerInstallTailscalePrerequisites(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", "server-install.md"))
	if err != nil {
		t.Fatal(err)
	}
	need := ""
	for _, sec := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n## ") {
		if strings.HasPrefix(sec, "What you need") {
			need = strings.Join(strings.Fields(sec), " ")
		}
	}
	if need == "" {
		t.Fatal(`server-install.md has no section "## What you need"`)
	}
	for _, want := range []string{"**With Tailscale**", "`tailscaled`", "joined to the tailnet", "MagicDNS", "HTTPS Certificates"} {
		if !strings.Contains(need, want) {
			t.Errorf("server-install.md \"What you need\" does not contain %q", want)
		}
	}
}

// hostSetupSection returns the text of the host-setup.md section whose
// heading starts with "## "+prefix, up to the next "## " heading.
func hostSetupSection(t *testing.T, prefix string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", "host-setup.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n## ") {
		if strings.HasPrefix(sec, prefix) {
			return sec
		}
	}
	t.Fatalf("host-setup.md has no section %q", "## "+prefix)
	return ""
}

// TestHostSetupSignerCheck: host principals and host ca-key render what
// the server serves, and a compromised server can serve any older
// version the admins or roots once signed. keyroster directory show reads
// the same server, so the runbook must send the admin to the signer's log
// (directory installs, trust bundle) before a rendered file is trusted.
func TestHostSetupSignerCheck(t *testing.T) {
	for _, tc := range []struct{ section, want string }{
		{"1.", "trust bundle v"},
		{"1.", "enroll-user.md#confirm-on-the-signer-host"},
		{"5.", "directory installs"},
		{"5.", "trust bundle v"},
		{"5.", "enroll-user.md#confirm-on-the-signer-host"},
		{"5.", "older"},
		{"5.", "Phase 4"},
	} {
		if !strings.Contains(hostSetupSection(t, tc.section), tc.want) {
			t.Errorf("host-setup.md step %s does not contain %q", tc.section, tc.want)
		}
	}
	for _, prefix := range []string{"3.", "5."} {
		for _, para := range strings.Split(hostSetupSection(t, prefix), "\n\n") {
			if strings.Contains(para, "directory show") && !strings.Contains(para, "server's word") {
				t.Errorf("host-setup.md step %s offers directory show without saying it is the server's word:\n%s", prefix, para)
			}
		}
	}
}

// TestHostSetupEffectiveSshdConfig: sshd keeps the first value it reads
// for TrustedUserCAKeys and AuthorizedPrincipalsFile, drop-ins are often
// included first, and lines after a Match block apply only to it. sshd -t
// checks syntax only, so the runbook must not say "add to sshd_config"
// and must check the effective values with sshd -T.
func TestHostSetupEffectiveSshdConfig(t *testing.T) {
	appendTo := regexp.MustCompile("(?i)add\\s+to\\s+`/etc/ssh/sshd_config`")
	for _, prefix := range []string{"1.", "2."} {
		if appendTo.MatchString(hostSetupSection(t, prefix)) {
			t.Errorf("host-setup.md step %s still says to add the setting to sshd_config", prefix)
		}
	}
	for _, tc := range []struct{ section, want string }{
		{"1.", "Where the sshd settings go"},
		{"2.", "Where the sshd settings go"},
		{"Where the sshd settings go", "sshd_config.d"},
		{"Where the sshd settings go", "Include"},
		{"Where the sshd settings go", "Match"},
		{"Where the sshd settings go", "first value"},
		{"4.", "sudo sshd -T -C user=<account>,host=<host>,addr=<address>"},
		{"4.", "trustedusercakeys /etc/ssh/keyroster_user_ca.pub"},
		{"4.", "authorizedprincipalsfile /etc/ssh/principals/%u"},
		{"5.", "sshd -T"},
	} {
		if !strings.Contains(hostSetupSection(t, tc.section), tc.want) {
			t.Errorf("host-setup.md section %q does not contain %q", tc.section, tc.want)
		}
	}
}
