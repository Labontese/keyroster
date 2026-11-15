//go:build e2e && e2erotation

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// caRotFailedLogin is the start of the sshd log line (LogLevel VERBOSE)
// for a refused publickey login of user from src, which a certificate
// signed by a CA key that TrustedUserCAKeys does not list gets (03-12b).
// sshd names that CA reason only at a debug level, so the generic line,
// from a source address of its own, is what can be matched; the 9.5p1 and
// 10.5p1 builds both print it.
func caRotFailedLogin(user, src string) string {
	return "Failed publickey for " + user + " from " + src + " port"
}

// caRotKeyLine is the trust.FormatKey line of the OpenSSH .pub file path.
func caRotKeyLine(t *testing.T, path string) string {
	t.Helper()
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(readPub(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(pub)
}

// caRotUserCALines are the user CA lines of the live user_ca_keys of h, in
// file order: the file also lists the machine CA keys, which are dropped.
func caRotUserCALines(t *testing.T, h *agentHost, userCAs ...string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.root, "etc", "ssh", "keyroster", "current", "user_ca_keys")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		for _, u := range userCAs {
			if l == u {
				out = append(out, l)
			}
		}
	}
	return out
}

// caRotCeremony runs root sign --prev prevDir (its recorded SHA-256
// prevSHA) with the root in rootAgent and the CA flags ca, into out: first
// with a wrong confirmation, which signs nothing, then with the real hash
// prefix. It returns the display. Then trust verify --prev checks the
// signed successor against the pin.
func caRotCeremony(t *testing.T, rootAgent, rootFP, rootsPub, prevDir, prevSHA, out string, ca ...string) string {
	t.Helper()
	sign := append([]string{"root", "sign", "--prev", prevDir, "--prev-sha256", prevSHA, "--roots", rootsPub, "--threshold", "1",
		"--policy", filepath.Join(prevDir, "policy.json"), "--out-dir", out, "--agent-key", rootFP}, ca...)
	code, display := keyrosterWithAgent(t, rootAgent, append(sign, "--confirm", "00000000")...)
	if code != 1 || !strings.Contains(display, "nothing was signed") {
		t.Fatalf("root sign --prev %v with a wrong confirmation exited %d:\n%s", ca, code, display)
	}
	succ, err := os.ReadFile(filepath.Join(out, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	if code, msg := keyrosterWithAgent(t, rootAgent, append(sign, "--confirm", trust.SHA256Hex(succ)[:8])...); code != 0 {
		t.Fatalf("root sign --prev %v exited %d:\n%s", ca, code, msg)
	}
	code, verified := runKeyroster(t, "trust", "verify", "--prev", prevDir, "--prev-sha256", prevSHA, "--pin", rootFP, "--threshold", "1",
		"--bundle", filepath.Join(out, "bundle.json"), "--policy", filepath.Join(out, "policy.json"))
	if code != 0 || !strings.Contains(verified, "OK: successor of trust bundle") {
		t.Fatalf("trust verify --prev of %s exited %d:\n%s", out, code, verified)
	}
	return display + verified
}

// caRotInstall installs the successor in dir on env's stopped signer and
// starts serve again; it returns the new stop function.
func caRotInstall(t *testing.T, env *signerEnv, dir string, version string) func() {
	t.Helper()
	if code, out := env.signerCmd(t, "install-bundle", "--state-dir", env.StateDir,
		"--bundle", filepath.Join(dir, "bundle.json"), "--policy", filepath.Join(dir, "policy.json")); code != 0 ||
		!strings.Contains(out, "installed bundle version "+version) {
		t.Fatalf("install-bundle of %s exited %d:\n%s", dir, code, out)
	}
	return serveStoppable(t, env)
}

// TestCANextAndAbort (03-12b, D-14, KEY-08) runs ceremony 1 and its abort
// with the real binaries against an sshd that keyroster-agent drives: a
// prepared user CA key becomes next through a root ceremony, the host
// trusts it beside the active key after the widening wait, and an abort
// withdraws it at once, so a certificate it signed is refused. The
// exported log verifies across both (the e2e-rotation lane, 9.5p1 and
// 10.5p1).
func TestCANextAndAbort(t *testing.T) {
	login := currentUser(t)
	keys := t.TempDir()

	// 1. A root R in its own agent, the signer, a host, and c1.
	rAgent := startAgent(t)
	rKey := filepath.Join(keys, "r")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "r", "-f", rKey)
	sshAdd(t, rAgent, rKey)
	rFP := fingerprint(t, rKey+".pub")
	rootsPub := filepath.Join(keys, "roots.pub")
	if err := os.WriteFile(rootsPub, []byte(caRotKeyLine(t, rKey+".pub")+" custody=software\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := prepareSigner(t, bootstrapOpts{RootAgentSocket: rAgent, RootFingerprint: rFP, RootCustody: "software", PoPHosts: true})
	stop := serveStoppable(t, env)
	h := newAgentHost(t, env)
	installAgentDirectory(t, env, agentDirectory(t, env, nil, login, h.sshd.hostKey, "role:ops"))
	c1 := issueAgentCert(t, env, "c1", "role:ops")
	h.refreshSpool(t)
	if code, r, stderr := h.apply(t); code != 0 || !r.Reloaded || r.SelfTest != "pass" {
		t.Fatalf("first install: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	h.wantAccepted(t, "c1 after the first install", c1, login)
	gen1 := caRotKeyLine(t, env.UserCAPub)

	// 2. Prepare generation 2 of the user CA, with the signer stopped.
	stop()
	k2 := filepath.Join(keys, "user_g2")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user-g2", "-f", k2)
	sshAdd(t, env.RoleAgent, k2)
	fp2, line2 := fingerprint(t, k2+".pub"), caRotKeyLine(t, k2+".pub")
	prepared := filepath.Join(keys, "user-g2.json")
	if code, out := env.signerCmd(t, "ca-rotate", "prepare", "--state-dir", env.StateDir, "--role", "user", "--key", fp2, "--out", prepared); code != 0 ||
		!strings.Contains(out, "role user generation 2 "+fp2) {
		t.Fatalf("ca-rotate prepare exited %d:\n%s", code, out)
	}

	// 3. Ceremony 1. A wrong fingerprint is refused before anything is
	// written; the right one builds, signs and verifies.
	v1, err := os.ReadFile(filepath.Join(env.BundleDir, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(keys, "succ-wrong-fp")
	if code, out := keyrosterWithAgent(t, rAgent, "root", "sign", "--prev", env.BundleDir, "--prev-sha256", trust.SHA256Hex(v1),
		"--roots", rootsPub, "--threshold", "1", "--policy", filepath.Join(env.BundleDir, "policy.json"), "--out-dir", wrong,
		"--agent-key", rFP, "--ca-next", "user="+prepared, "--ca-next-fingerprint", "user="+rFP, "--confirm", "00000000"); code != 1 ||
		!strings.Contains(out, "ca_next_fingerprint_mismatch") {
		t.Fatalf("root sign with a wrong --ca-next-fingerprint exited %d:\n%s", code, out)
	}
	if _, err := os.Stat(wrong); !os.IsNotExist(err) {
		t.Fatalf("%s exists after the refused root sign (stat error %v)", wrong, err)
	}
	succ := filepath.Join(keys, "succ")
	out := caRotCeremony(t, rAgent, rFP, rootsPub, env.BundleDir, trust.SHA256Hex(v1), succ,
		"--ca-next", "user="+prepared, "--ca-next-fingerprint", "user="+fp2)
	for _, want := range []string{"CA user gen 2 " + fp2 + ": none -> next\n", "Root set: unchanged\n"} {
		if n := strings.Count(out, want); n != 2 {
			t.Fatalf("root sign and trust verify print %q %d times, want once each:\n%s", want, n, out)
		}
	}

	// 4. Install; 5. the host trusts both user CA keys after the widening
	// wait, with no reload. A CA line added alone is a pure widening: the
	// agent waits and swaps once, with no intermediate generation (that is
	// for a change that also narrows).
	stop = caRotInstall(t, env, succ, "2")
	h.refreshSpool(t)
	code, r, stderr := h.apply(t)
	if code != 0 || r.WaitedMS < int64(agentLoginGrace+30)*1000 || r.SelfTest != "pass" || r.Reloaded {
		t.Fatalf("the next CA: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	if got := caRotUserCALines(t, h, gen1, line2); len(got) != 2 || got[0] != gen1 || got[1] != line2 {
		t.Fatalf("live user CA lines %q, want generation 1 then generation 2", got)
	}
	h.wantAccepted(t, "c1 with the next CA trusted", c1, login)
	// A certificate signed directly with the next key (test-only: the
	// signer never signs with a next key).
	nk := filepath.Join(t.TempDir(), "id_next")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "next", "-f", nk)
	sshKeygen(t, "-q", "-s", k2, "-I", "e2e-next", "-n", "role:ops", "-V", "-5m:+10m", "-z", "4242", nk+".pub")
	byNext := agentCert{key: nk, cert: nk + "-cert.pub", serial: "4242"}
	h.wantAccepted(t, "a certificate by the next CA key", byNext, login)

	// 6. The abort, on the version-2 directory as --prev.
	stop()
	v2, err := os.ReadFile(filepath.Join(succ, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	abort := filepath.Join(keys, "abort")
	out = caRotCeremony(t, rAgent, rFP, rootsPub, succ, trust.SHA256Hex(v2), abort, "--ca-retire", "user:2")
	if n := strings.Count(out, "CA user gen 2 "+fp2+": next -> retired\n"); n != 2 {
		t.Fatalf("root sign and trust verify print the abort line %d times, want once each:\n%s", n, out)
	}
	_ = caRotInstall(t, env, abort, "3") // serve stops at the test's cleanup
	h.refreshSpool(t)
	code, r, stderr = h.apply(t)
	if code != 0 || r.Intermediate != 0 || r.Reloaded || r.SelfTest != "pass" || r.WaitedMS >= int64(agentLoginGrace)*1000 {
		t.Fatalf("the abort: exit %d, report %+v\nstderr:\n%s", code, r, stderr)
	}
	if got := caRotUserCALines(t, h, gen1, line2); len(got) != 1 || got[0] != gen1 {
		t.Fatalf("live user CA lines %q after the abort, want generation 1 only", got)
	}
	h.wantAccepted(t, "c1 after the abort", c1, login)
	h.wantRefused(t, "the certificate by the aborted key", byNext, login, "127.0.0.2", caRotFailedLogin(login, "127.0.0.2"))

	// 7. The exported log verifies, and the bundle in force lists the
	// aborted entry as retired.
	if code, out := auditVerifyPins(t, env.RootFingerprints, env.exportLog(t), "--installation-id", env.InstallationID); code != 0 ||
		!strings.Contains(out, "trust bundle v3") {
		t.Fatalf("audit verify after the abort exited %d:\n%s", code, out)
	}
	st, err := signerclient.Status(context.Background(), env.Socket)
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.ParseBundle(st.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.CAs) != 4 || b.CAs[1].Generation != 2 || b.CAs[1].State != "retired" || b.CAs[1].Key != line2 {
		t.Fatalf("the bundle in force lists %+v, want user generation 2 retired", b.CAs)
	}
}
