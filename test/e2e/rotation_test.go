//go:build e2e

package e2e

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/trust"
)

// rotationPassphrase protects the new age software roots in the rotation
// test (root init requires at least 20 characters).
const rotationPassphrase = "rotation test passphrase, not a secret"

// TestRootRotationLiveSigner (KEY-07, owner decision 1) rotates a live
// signer's root set with the real binaries: the signer runs under a genesis
// bundle signed by root R1 and issues; keyroster root sign --prev builds
// successor v2 naming new software roots C and D; install-bundle refuses v2
// while serve holds the state lock, and after serve is stopped refuses it
// again while only the new root C has signed; once the previous root R1 has
// also signed, trust verify --prev checks v2 against the bundle in force and
// pins it to C and D (and refuses R1 as its pins), v2 installs without
// --pin, serve restarts, issues a certificate that real sshd accepts, and
// the exported log verifies across the rotation anchored on v2 under the
// pins C and D and on v1 under R1, and is refused under C alone.
func TestRootRotationLiveSigner(t *testing.T) {
	login := currentUser(t)
	keys := t.TempDir()

	// Genesis: root R1 (custody software) in its own agent.
	r1Agent := startAgent(t)
	r1Key := filepath.Join(keys, "r1")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "r1", "-f", r1Key)
	sshAdd(t, r1Agent, r1Key)
	r1FP := fingerprint(t, r1Key+".pub")
	env := prepareSigner(t, bootstrapOpts{RootAgentSocket: r1Agent, RootFingerprint: r1FP, RootCustody: "software"})
	stop := serveStoppable(t, env)
	first := newUserKey(t, "id_before")
	env.issue(t, "--pubkey", first+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")

	// New roots C and D: age software roots made by keyroster root init.
	var newRoots strings.Builder
	rootFiles := map[string]string{}
	for _, name := range []string{"c", "d"} {
		path := filepath.Join(keys, name+".age")
		if code, out := keyrosterWithPassphrase(t, "", "root", "init", "--out", path, "--passphrase-fd", "3"); code != 0 {
			t.Fatalf("root init %s exited %d:\n%s", name, code, out)
		}
		pub, err := os.ReadFile(path + ".pub") //nolint:gosec // test file
		if err != nil {
			t.Fatal(err)
		}
		newRoots.Write(pub)
		rootFiles[name] = path
	}
	rootsPub := filepath.Join(keys, "new-roots.pub")
	if err := os.WriteFile(rootsPub, []byte(newRoots.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	// The new root C signs first: a wrong confirmation writes bundle.json
	// and signs nothing, then the real hash prefix signs.
	succ := filepath.Join(keys, "succ")
	sign := []string{"root", "sign", "--prev", env.BundleDir, "--roots", rootsPub, "--threshold", "1",
		"--policy", filepath.Join(env.BundleDir, "policy.json"), "--out-dir", succ}
	signC := append(append([]string{}, sign...), "--key", rootFiles["c"], "--passphrase-fd", "3")
	if code, out := keyrosterWithPassphrase(t, "", append(signC, "--confirm", "00000000")...); code != 1 || !strings.Contains(out, "nothing was signed") {
		t.Fatalf("root sign --prev with a wrong confirmation exited %d:\n%s", code, out)
	}
	succBundle, err := os.ReadFile(filepath.Join(succ, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	prefix := trust.SHA256Hex(succBundle)[:8]
	code, out := keyrosterWithPassphrase(t, "", append(signC, "--confirm", prefix)...)
	if code != 0 {
		t.Fatalf("root sign --prev with the new root C exited %d:\n%s", code, out)
	}
	for _, want := range []string{"Successor of trust bundle v1", "signatures needed: 1 of the 1 previous roots AND 1 of the 2 new roots"} {
		if !strings.Contains(out, want) {
			t.Fatalf("root sign --prev output lacks %q:\n%s", want, out)
		}
	}

	install := []string{"install-bundle", "--state-dir", env.StateDir,
		"--bundle", filepath.Join(succ, "bundle.json"), "--policy", filepath.Join(succ, "policy.json")}
	if code, out := env.signerCmd(t, install...); code == 0 || !strings.Contains(out, "in use by another keyroster-signer process") {
		t.Fatalf("install-bundle while serve runs exited %d, want the state-lock refusal:\n%s", code, out)
	}
	stop()
	if code, out := env.signerCmd(t, install...); code == 0 || !strings.Contains(out, "threshold not met") || !strings.Contains(out, "previous roots") {
		t.Fatalf("install-bundle signed by a new root only exited %d, want the previous roots' threshold refusal:\n%s", code, out)
	}

	// The previous root R1 co-signs from its agent; v2 now installs without
	// --pin.
	if code, out := keyrosterWithAgent(t, r1Agent, append(sign, "--agent-key", r1FP, "--confirm", prefix)...); code != 0 {
		t.Fatalf("root sign --prev with the previous root R1 exited %d:\n%s", code, out)
	}

	// Before the install, the successor is checked against the bundle in
	// force and pinned to the new roots' out-of-band fingerprints.
	cFP, dFP := fingerprint(t, rootFiles["c"]+".pub"), fingerprint(t, rootFiles["d"]+".pub")
	verifyPrev := func(pins ...string) (int, string) {
		args := []string{"trust", "verify", "--prev", env.BundleDir, "--threshold", "1",
			"--bundle", filepath.Join(succ, "bundle.json"), "--policy", filepath.Join(succ, "policy.json")}
		for _, p := range pins {
			args = append(args, "--pin", p)
		}
		return runKeyroster(t, args...)
	}
	if code, out := verifyPrev(cFP, dFP); code != 0 || !strings.Contains(out, "OK: successor of trust bundle v1") ||
		!strings.Contains(out, "signed by previous root "+r1FP) || !strings.Contains(out, "signed by new root "+cFP) {
		t.Fatalf("trust verify --prev pinned to the new roots C and D exited %d:\n%s", code, out)
	}
	if code, out := verifyPrev(r1FP); code == 0 || !strings.Contains(out, "not the pinned roots") {
		t.Fatalf("trust verify --prev pinned to the previous root R1 exited %d, want the pin refusal:\n%s", code, out)
	}

	if code, out := env.signerCmd(t, install...); code != 0 || !strings.Contains(out, "installed bundle version 2") {
		t.Fatalf("install-bundle of the co-signed successor exited %d:\n%s", code, out)
	}

	// After the rotation: serve restarts, issues under the unchanged user
	// CA, and sshd accepts the certificate.
	if isSocket(env.Socket) {
		t.Fatalf("%s is still a socket after serve stopped", env.Socket)
	}
	serveStoppable(t, env)
	second := newUserKey(t, "id_after")
	env.issue(t, "--pubkey", second+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	info := parseCertInfo(t, sshKeygen(t, "-L", "-f", second+"-cert.pub"))
	if !strings.Contains(info.keyID, "/pol=1/") {
		t.Fatalf("key ID %q, want the unchanged policy version pol=1", info.keyID)
	}
	if info.signingCAFP != fingerprint(t, env.UserCAPub) {
		t.Fatalf("certificate signed by %s, want the bundle's user CA %s", info.signingCAFP, fingerprint(t, env.UserCAPub))
	}
	port := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {login}}})
	if code, out := sshLogin(t, loginOptions{Port: port, Key: second, Cert: second + "-cert.pub", User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with the certificate issued after the rotation exited %d:\n%s", code, out)
	}

	export := env.exportLog(t)
	if code, out := auditVerifyPins(t, env.RootFingerprints, export); code != 0 || !strings.Contains(out, "trust bundle v2") || !strings.Contains(out, "issued 2") {
		t.Fatalf("audit verify pinned to the genesis root exited %d, want OK with trust bundle v2 and 2 issued:\n%s", code, out)
	}

	// The anchor follows the pins: the new roots anchor on v2 (the earlier
	// bundle is authenticated by v2's prev hash), the genesis root on v1,
	// and a set that is the root set of no bundle anchors nothing.
	if code, out := auditVerifyPins(t, []string{cFP, dFP}, export); code != 0 ||
		!strings.Contains(out, "anchored: the pinned roots are the root set of trust bundle v2\n") || !strings.Contains(out, "issued 2") {
		t.Fatalf("audit verify pinned to the new roots C and D exited %d, want OK anchored on trust bundle v2:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, []string{cFP, dFP}, export, "--json"); code != 0 || !strings.Contains(out, `"anchor_bundle_version":2`) {
		t.Fatalf("audit verify --json pinned to C and D exited %d, want anchor_bundle_version 2:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, []string{r1FP}, export); code != 0 ||
		!strings.Contains(out, "anchored: the pinned roots are the root set of trust bundle v1\n") {
		t.Fatalf("audit verify pinned to the genesis root R1 exited %d, want OK anchored on trust bundle v1:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, []string{cFP}, export); code == 0 || !strings.Contains(out, "not anchored in the pinned roots") {
		t.Fatalf("audit verify pinned to C alone exited %d, want the not-anchored refusal:\n%s", code, out)
	}
}

// serveStoppable starts keyroster-signer serve on env's state like
// env.serve and returns a function that stops it with SIGTERM and waits for
// it to exit.
func serveStoppable(t *testing.T, env *signerEnv) (stop func()) {
	t.Helper()
	cmd, log, done := startDaemon(t, "keyroster-signer", envWithout("SSH_AUTH_SOCK"), signerBin,
		"serve", "--state-dir", env.StateDir, "--socket", env.Socket, "--allow-uid", strconv.Itoa(os.Getuid()))
	waitFor(t, "signer socket", done, log, func() bool { return isSocket(env.Socket) })
	return func() {
		t.Helper()
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("stop serve: %v", err)
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("serve did not exit after SIGTERM:\n%s", log.String())
		}
	}
}

// keyrosterWithPassphrase runs the keyroster CLI with rotationPassphrase on
// the inherited descriptor 3 and SSH_AUTH_SOCK set to agentSock ("" for
// none), and returns its exit code and combined output.
func keyrosterWithPassphrase(t *testing.T, agentSock string, args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := w.WriteString(rotationPassphrase + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, keyrosterBin, args...) //nolint:gosec // G204: the binary under test
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	if agentSock != "" {
		cmd.Env = append(cmd.Env, "SSH_AUTH_SOCK="+agentSock)
	}
	cmd.ExtraFiles = []*os.File{r} // descriptor 3 in the child
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("keyroster %v: %v\n%s", args, err, out)
	}
	return 0, string(out)
}
