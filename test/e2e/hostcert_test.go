//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// hostCertPoll is the fetcher's poll in the host-certificate tests (03-09):
// a request the applier writes is posted within one poll.
const hostCertPoll = 5 * time.Second

// hostCertKR is the keyroster CLI as admin of env, retrying while the
// server rate-limits (TestAgentEnrollEndToEnd's kr).
func hostCertKR(t *testing.T, env *serverEnv) func(args ...string) string {
	t.Helper()
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)
	return func(args ...string) string {
		t.Helper()
		code, out, errOut := env.keyroster(t, admin, "", args...)
		for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
			time.Sleep(2 * time.Second)
			code, out, errOut = env.keyroster(t, admin, "", args...)
		}
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}
}

// joinHostCert enrolls a new host as name, as joinApproved does, with
// sshdExtra as more sshd_config lines, and with its fetcher polling every
// hostCertPoll; it approves the host with --principal name and every host
// key keyroster-agent identity prints, and waits for the first apply.
func joinHostCert(t *testing.T, env *serverEnv, kr func(args ...string) string, name string, sshdExtra ...string) *enrolledHost {
	t.Helper()
	login := currentUser(t)
	kr("role", "add", "ops", "--max-ttl", "1h", "--yes")
	kr("host-group", "add", "lab", "--yes")
	kr("host-group", "map", "lab", login, "ops", "--yes")
	joinFile := filepath.Join(t.TempDir(), "join.txt")
	kr("host", "join-token", name, "--out", joinFile)
	h := newEnrolledHostLayout(t, env.Signer, sshdExtra...)
	if code, out := runBin(t, agentBin(t), "", "install", "--root", h.root, "--state-dir", h.state, "--join-file", joinFile, "--fetch-user", login); code != 0 {
		t.Fatalf("keyroster-agent install exited %d:\n%s", code, out)
	}
	eh := &enrolledHost{agentHost: h}
	eh.startRun(t)
	eh.startFetch(t, hostCertPoll)
	for deadline := time.Now().Add(30 * time.Second); !strings.Contains(kr("host", "pending"), "Pending host "+name); time.Sleep(500 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("host pending never listed %s\nfetch log:\n%s", name, eh.fetch.String())
		}
	}
	code, ident := runBin(t, agentBin(t), "", "identity", "--state-dir", h.state, "--root", h.root,
		"--sshd", filepath.Join(opensshPrefix(t), "sbin", "sshd"), "--sshd-config", h.sshd.cfg)
	if code != 0 {
		t.Fatalf("keyroster-agent identity exited %d:\n%s", code, ident)
	}
	args := []string{"host", "approve", name, "--group", "lab", "--principal", name, "--yes"}
	for _, l := range strings.Split(strings.TrimSpace(ident), "\n") {
		if fp, ok := strings.CutPrefix(l, "host key: "); ok {
			args = append(args, "--host-key", strings.Fields(fp)[0])
		}
	}
	kr(args...)
	waitFor(t, "the first apply", eh.runDone, eh.run, func() bool {
		r := h.lastApply(t)
		return r != nil && r.Generation > 0 && r.SelfTest == "pass" && len(r.Errors) == 0
	})
	return eh
}

// installedHostCerts returns the host certificates the agent's drop-in
// names in its HostCertificate lines, in drop-in order, parsed from their
// files.
func installedHostCerts(t *testing.T, h *agentHost) []*ssh.Certificate {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.root, "etc", "ssh", "sshd_config.d", "00-keyroster.conf")) //nolint:gosec // the test host's drop-in
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		t.Fatal(err)
	}
	var out []*ssh.Certificate
	for _, l := range strings.Split(string(b), "\n") {
		p, ok := strings.CutPrefix(l, "HostCertificate ")
		if !ok {
			continue
		}
		raw, err := os.ReadFile(strings.TrimSpace(p)) //nolint:gosec // a path the drop-in names
		if err != nil {
			t.Fatalf("HostCertificate %s: %v", p, err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(raw)
		if err != nil {
			t.Fatalf("HostCertificate %s: %v", p, err)
		}
		c, ok := pub.(*ssh.Certificate)
		if !ok {
			t.Fatalf("HostCertificate %s is not a certificate", p)
		}
		out = append(out, c)
	}
	return out
}

// waitHostCerts waits up to within for the drop-in to name n host
// certificates for which ok holds, and returns them; it fails with msg.
func waitHostCerts(t *testing.T, eh *enrolledHost, n int, within time.Duration, msg string, ok func([]*ssh.Certificate) bool) []*ssh.Certificate {
	t.Helper()
	for deadline := time.Now().Add(within); ; time.Sleep(500 * time.Millisecond) {
		cs := installedHostCerts(t, eh.agentHost)
		if len(cs) == n && (ok == nil || ok(cs)) {
			return cs
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s\nrun log:\n%s\nfetch log:\n%s", msg, eh.run.String(), eh.fetch.String())
		}
	}
}

// hostCertLifetime is a certificate's lifetime V = ValidBefore -
// (ValidAfter + 300).
func hostCertLifetime(c *ssh.Certificate) int64 {
	return int64(c.ValidBefore) - int64(c.ValidAfter) - 300 //nolint:gosec // G115: Unix times
}

// keyscanCert runs ssh-keyscan -c -t typ against the host's sshd (a
// freshly reloaded sshd may not answer at once, so it tries a few times)
// and returns the certificate it printed.
func keyscanCert(t *testing.T, h *agentHost, typ string) *ssh.Certificate {
	t.Helper()
	var last string
	for try := 0; try < 10; try++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		out, err := exec.CommandContext(ctx, filepath.Join(opensshPrefix(t), "bin", "ssh-keyscan"), "-c", "-t", typ,
			"-p", strconv.Itoa(h.sshd.port), "127.0.0.1").Output()
		cancel()
		last = fmt.Sprintf("%v: %s", err, out)
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) < 3 || strings.HasPrefix(l, "#") {
				continue
			}
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(f[1:], " ")))
			if err != nil {
				continue
			}
			if c, ok := pub.(*ssh.Certificate); ok {
				return c
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("ssh-keyscan -c -t %s printed no certificate: %s", typ, last)
	return nil
}

// strictHostLogin logs in to the host's sshd with c as user, with no ssh
// configuration file, knownHosts as the only known_hosts file, strict
// host key checking and -v, from the loopback source src; extra are more
// ssh options.
func strictHostLogin(t *testing.T, h *agentHost, c agentCert, user, knownHosts, src string, extra ...string) (int, string) {
	t.Helper()
	args := []string{"-v", "-F", "/dev/null", "-i", c.key, "-o", "CertificateFile=" + c.cert, "-o", "IdentitiesOnly=yes",
		"-o", "UserKnownHostsFile=" + knownHosts, "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "BindAddress=" + src,
		"-p", strconv.Itoa(h.sshd.port)}
	args = append(args, extra...)
	args = append(args, user+"@127.0.0.1", "true")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(opensshPrefix(t), "bin", "ssh"), args...)
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("ssh: %v\n%s", err, out)
	}
	return 0, string(out)
}

// hostStatusRaw is keyroster host status --json, decoded generically, so
// fields the CLI may not know yet are read too.
func hostStatusRaw(t *testing.T, kr func(args ...string) string) map[string]any {
	t.Helper()
	var a map[string]any
	if err := json.Unmarshal([]byte(kr("host", "status", "--json")), &a); err != nil {
		t.Fatalf("host status --json: %v", err)
	}
	return a
}

// hostCertsInStatus returns the host_certs of host name's heartbeat in a
// host status --json answer (nil when there are none).
func hostCertsInStatus(a map[string]any, name string) []map[string]any {
	hosts, _ := a["hosts"].([]any)
	for _, x := range hosts {
		row, _ := x.(map[string]any)
		if row["name"] != name {
			continue
		}
		hb, _ := row["heartbeat"].(map[string]any)
		st, _ := hb["status"].(map[string]any)
		list, _ := st["host_certs"].([]any)
		var out []map[string]any
		for _, c := range list {
			if m, ok := c.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// writeHostKnownHosts writes a known_hosts file with content.
func writeHostKnownHosts(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestHostCertIssueAndServe is 03-09's tracer: an enrolled host with an
// Ed25519 and an ECDSA P-256 host key obtains a kr3 host certificate for
// each by proof of possession (applier, fetcher, keyroster-server,
// keyroster-signer), installs them through the one drop-in, and real sshd
// serves one per algorithm. A client whose only known_hosts line is
// @cert-authority web1 <host CA> connects with no prompt under
// HostKeyAlias web1, and is refused under another name; a client that
// still holds the plain key keeps working. The next apply keeps the lines,
// and keyroster-agent check reports no drift.
func TestHostCertIssueAndServe(t *testing.T) {
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true})
	kr := hostCertKR(t, env)
	login := currentUser(t)
	ecdsaKey := filepath.Join(t.TempDir(), "ssh_host_ecdsa_key")
	sshKeygen(t, "-q", "-t", "ecdsa", "-b", "256", "-N", "", "-f", ecdsaKey)
	eh := joinHostCert(t, env, kr, "web1", "HostKey "+ecdsaKey)
	h := eh.agentHost

	certs := waitHostCerts(t, eh, 2, 120*time.Second, "no HostCertificate line within 120 s", nil)
	for _, c := range certs {
		if !strings.HasPrefix(c.KeyId, "kr3/ca=host/sub=web1/") || strings.Join(c.ValidPrincipals, ",") != "web1" || c.CertType != ssh.HostCert {
			t.Fatalf("installed host certificate key ID %q, principals %v, type %d; want kr3/ca=host/sub=web1/..., [web1], host", c.KeyId, c.ValidPrincipals, c.CertType)
		}
	}
	t.Logf("installed host certificates: %s and %s", certs[0].KeyId, certs[1].KeyId)
	byType := map[string]*ssh.Certificate{}
	for _, c := range certs {
		byType[c.Key.Type()] = c
	}

	t.Run("heartbeat_shows_host_certs", func(t *testing.T) {
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(time.Second) {
			hc := hostCertsInStatus(hostStatusRaw(t, kr), "web1")
			served := 0
			for _, c := range hc {
				if c["served"] == true {
					served++
				}
			}
			if len(hc) == 2 && served == 2 {
				t.Logf("host status host_certs: %v", hc)
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("keyroster host status lists host_certs %v, want both certificates served", hc)
			}
		}
	})

	t.Run("served_both_algorithms", func(t *testing.T) {
		for typ, keyType := range map[string]string{"ed25519": ssh.KeyAlgoED25519, "ecdsa": ssh.KeyAlgoECDSA256} {
			want := byType[keyType]
			if want == nil {
				t.Fatalf("no installed certificate for %s", keyType)
			}
			got := keyscanCert(t, h, typ)
			if !bytes.Equal(got.Marshal(), want.Marshal()) {
				t.Fatalf("ssh-keyscan -c -t %s serves %q (serial %d), want the installed %q (serial %d)", typ, got.KeyId, got.Serial, want.KeyId, want.Serial)
			}
		}
	})

	c := issueAgentCert(t, env.Signer, "hc1", "role:ops")
	caLine := "@cert-authority web1 " + readPub(t, env.Signer.HostCAPub) + "\n"

	t.Run("no_prompt_with_ca_line", func(t *testing.T) {
		kh := writeHostKnownHosts(t, caLine)
		code, out := strictHostLogin(t, h, c, login, kh, "127.0.0.1", "-o", "HostKeyAlias=web1", "-o", "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com")
		if code != 0 || !strings.Contains(out, "Server host certificate") {
			t.Fatalf("ssh with @cert-authority web1 and HostKeyAlias web1 exited %d, want 0 with Server host certificate:\n%s", code, out)
		}
		for _, tofu := range []string{"authenticity of host", "Permanently added"} {
			if strings.Contains(out, tofu) {
				t.Fatalf("ssh output contains the TOFU message %q:\n%s", tofu, out)
			}
		}
		if after, err := os.ReadFile(kh); err != nil || string(after) != caLine { //nolint:gosec // test file
			t.Fatalf("known_hosts changed during login: %q, %v", after, err)
		}
	})

	t.Run("other_name_refused", func(t *testing.T) {
		kh := writeHostKnownHosts(t, caLine)
		code, out := strictHostLogin(t, h, c, login, kh, net.IPv4(127, 0, 0, 2).String(), "-o", "HostKeyAlias=web2", "-o", "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com")
		if code == 0 || !strings.Contains(out, "Host key verification failed") {
			t.Fatalf("ssh under HostKeyAlias web2 exited %d, want a refusal with Host key verification failed:\n%s", code, out)
		}
	})

	t.Run("existing_known_hosts_still_accepted", func(t *testing.T) {
		kh := writeHostKnownHosts(t, "web1 "+readPub(t, h.sshd.hostKey)+"\n")
		code, out := strictHostLogin(t, h, c, login, kh, "127.0.0.1", "-o", "HostKeyAlias=web1", "-o", "HostKeyAlgorithms=ssh-ed25519-cert-v01@openssh.com")
		if code != 0 || !strings.Contains(out, "Server host certificate") {
			t.Fatalf("ssh with the plain key and a forced certificate algorithm exited %d, want 0 with Server host certificate:\n%s", code, out)
		}
		code, out = strictHostLogin(t, h, c, login, kh, "127.0.0.1", "-o", "HostKeyAlias=web1")
		if code != 0 {
			t.Fatalf("ssh with the plain key and default algorithms exited %d, want 0:\n%s", code, out)
		}
	})

	t.Run("next_apply_keeps_line", func(t *testing.T) {
		before := hostsStatusJSON(t, kr).Current.Directory
		kr("role", "add", "dev", "--max-ttl", "1h", "--yes")
		want := hostsStatusJSON(t, kr).Current.Directory
		if want <= before {
			t.Fatalf("role add left the directory at version %d", want)
		}
		for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(500 * time.Millisecond) {
			applied := uint64(0)
			for _, row := range hostsStatusJSON(t, kr).Hosts {
				if row.Name == "web1" && row.Heartbeat != nil {
					applied = row.Heartbeat.Status.Directory.Version
				}
			}
			if applied >= want {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("second apply did not commit within 60 s (heartbeat directory v%d, want v%d)\nrun log:\n%s", applied, want, eh.run.String())
			}
		}
		after := installedHostCerts(t, h)
		if len(after) != 2 {
			t.Fatalf("after the second apply the drop-in names %d host certificates, want 2", len(after))
		}
		code, out := runBin(t, agentBin(t), "", "check", "--state-dir", h.state, "--root", h.root,
			"--sshd", filepath.Join(opensshPrefix(t), "sbin", "sshd"), "--sshd-config", h.sshd.cfg)
		if code != 0 {
			t.Fatalf("keyroster-agent check exited %d, want 0 (no drift):\n%s", code, out)
		}
	})
}

// TestHostCertRenewAndRestart: under a host cap of 90 s the signer issues
// every host certificate for exactly 90 s (it chooses the lifetime,
// Q-09-6), and the agent renews at two thirds of that lifetime, minus its
// jitter, before the certificate counts as missing; a signer restart
// rebuilds its host index from the log and the next renewal is issued.
// audit verify of the exported log counts every host certificate.
func TestHostCertRenewAndRestart(t *testing.T) {
	withGenesisHostMaxTTL(t, 90*time.Second)
	env := startServerEnv(t, serverOpts{PoPHosts: true, AgentListen: true, StoppableSigner: true})
	kr := hostCertKR(t, env)
	eh := joinHostCert(t, env, kr, "web1")

	c1 := waitHostCerts(t, eh, 1, 120*time.Second, "no first host certificate within 120 s", nil)[0]
	c2 := waitHostCerts(t, eh, 1, 120*time.Second, "no renewed host certificate within 120 s", func(cs []*ssh.Certificate) bool {
		return cs[0].Serial > c1.Serial
	})[0]
	installedAt := uint64(time.Now().Unix())                                 //nolint:gosec // G115: after 1970
	if d := int64(c2.ValidAfter) - int64(c1.ValidAfter); d < 51 || d >= 75 { //nolint:gosec // G115: Unix times
		t.Fatalf("the renewal came %d s after the first issuance, want in [51, 75): renew at issued + 60 - j, j < 9", d)
	}
	if installedAt >= c1.ValidBefore-15 {
		t.Fatalf("the renewal was installed at %d, not before the first certificate's ValidBefore - 15 (%d)", installedAt, c1.ValidBefore-15)
	}
	t.Logf("renewed: serial %d -> %d, %d s apart", c1.Serial, c2.Serial, c2.ValidAfter-c1.ValidAfter)

	env.StopSigner()
	serveStoppable(t, env.Signer)
	c3 := waitHostCerts(t, eh, 1, 120*time.Second, "no host certificate after the signer restart within 120 s", func(cs []*ssh.Certificate) bool {
		return cs[0].Serial > c2.Serial
	})[0]
	t.Logf("after the signer restart: serial %d", c3.Serial)

	for i, c := range []*ssh.Certificate{c1, c2, c3} {
		if v := hostCertLifetime(c); v != 90 {
			t.Fatalf("certificate %d (serial %d) lives %d s, want the 90 s cap the signer chose", i+1, c.Serial, v)
		}
	}

	export := env.Signer.exportLog(t)
	code, out := auditVerify(t, env.Signer, export)
	if code != 0 {
		t.Fatalf("keyroster audit verify exited %d:\n%s", code, out)
	}
	m := regexp.MustCompile(`(?m)^host certificates: (\d+)$`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("keyroster audit verify printed no host certificates line:\n%s", out)
	}
	if n, _ := strconv.Atoi(m[1]); n < 3 {
		t.Fatalf("keyroster audit verify counts %d host certificates, want at least 3:\n%s", n, out)
	}
	t.Logf("keyroster audit verify: %s", strings.TrimSpace(out))
}
