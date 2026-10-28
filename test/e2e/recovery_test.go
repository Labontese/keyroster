//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
)

// startStoppableServer starts keyroster-server in front of env's signer
// with --state-dir state (so the test can read krl-served.json), waits
// until /healthz answers 200, sets env's process fields and returns a
// function that stops it with SIGTERM and waits for it to exit.
func startStoppableServer(t *testing.T, env *serverEnv, state string) (stop func()) {
	t.Helper()
	cmd, log, done := startDaemon(t, "keyroster-server", envWithout("SSH_AUTH_SOCK"), serverBin, "serve",
		"--listen", "127.0.0.1:"+strconv.Itoa(env.Port), "--tls-cert", env.CA.CertPath, "--tls-key", env.CA.KeyPath,
		"--signer-socket", env.Signer.Socket, "--state-dir", state)
	env.Cmd, env.Stderr, env.Done = cmd, log, done
	waitFor(t, "keyroster-server /healthz", done, log, func() bool {
		r, err := env.get("/healthz")
		return err == nil && r.code == http.StatusOK
	})
	return func() {
		t.Helper()
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("stop keyroster-server: %v", err)
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Fatalf("keyroster-server did not exit after SIGTERM:\n%s", log.String())
		}
	}
}

// servedCopyVersion reads keyroster-server's krl-served.json in state
// strictly and returns its manifest's KRL version.
func servedCopyVersion(t *testing.T, state string) uint64 {
	t.Helper()
	doc, err := serverclient.DecodeKRLDocument(readFile(t, filepath.Join(state, "krl-served.json")))
	if err != nil {
		t.Fatalf("krl-served.json: %v", err)
	}
	m, err := krl.ParseManifest(doc.Manifest)
	if err != nil {
		t.Fatalf("krl-served.json manifest: %v", err)
	}
	return m.KRLVersion
}

// keygenVerdict reads the exit code and output of ssh-keygen -Q -f KRL
// CERT for one certificate (PR #69 review, F5): revoked for exit 1 with a
// line ending in ": REVOKED" and none ending in ": ok", not revoked for
// exit 0 with a line ending in ": ok" and none ending in ": REVOKED", and
// an error for anything else, such as exit 255 for a KRL OpenSSH cannot
// parse ("Couldn't parse KRL"), which is never a refusal.
func keygenVerdict(code int, out string) (revoked bool, err error) {
	var ok, rev bool
	for line := range strings.Lines(out) {
		line = strings.TrimRight(line, "\r\n")
		ok = ok || strings.HasSuffix(line, ": ok")
		rev = rev || strings.HasSuffix(line, ": REVOKED")
	}
	switch {
	case code == 1 && rev && !ok:
		return true, nil
	case code == 0 && ok && !rev:
		return false, nil
	}
	return false, fmt.Errorf("ssh-keygen -Q exited %d without exactly one verdict line", code)
}

// requireKeygen runs ssh-keygen -Q -f krlFile cert and fails unless its
// verdict (keygenVerdict) is wantRevoked.
func requireKeygen(t *testing.T, what, krlFile, cert string, wantRevoked bool) {
	t.Helper()
	code, out := keygenQuery(t, krlFile, cert)
	revoked, err := keygenVerdict(code, out)
	if err != nil || revoked != wantRevoked {
		t.Fatalf("%s: ssh-keygen -Q gave revoked=%v (%v), want revoked=%v:\n%s", what, revoked, err, wantRevoked, out)
	}
	t.Logf("%s: ssh-keygen -Q exit %d: %s", what, code, strings.TrimSpace(out))
}

// TestKeygenVerdict pins keygenVerdict on the outputs ssh-keygen -Q
// gives: a refusal and an acceptance count, a parse failure or an exit
// code without its verdict line does not.
func TestKeygenVerdict(t *testing.T) {
	for _, c := range []struct {
		code    int
		out     string
		revoked bool
		ok      bool
	}{
		{1, "/tmp/a-cert.pub (a): REVOKED\n", true, true},
		{0, "/tmp/b-cert.pub (b): ok\n", false, true},
		{255, "Couldn't parse KRL /tmp/r.krl: invalid format\n", false, false},
		{1, "something else\n", false, false},
		{0, "", false, false},
		{1, "/tmp/a-cert.pub (a): ok\n", false, false},
		{0, "/tmp/a-cert.pub (a): REVOKED\n", false, false},
	} {
		revoked, err := keygenVerdict(c.code, c.out)
		if (err == nil) != c.ok || revoked != c.revoked {
			t.Errorf("keygenVerdict(%d, %q) = %v, %v; want revoked=%v, ok=%v", c.code, c.out, revoked, err, c.revoked, c.ok)
		}
	}
}

// TestRestoreRecoveryTracer (03-06b Task 2) runs the recovery through the
// real binaries:
//
//  1. keyroster-server serves the KRL after a keyroster revoke serial made
//     after the saved export, and krl-served.json then holds that version;
//  2. with the server stopped, the signer is restored to a copy of
//     signer.db taken before the revocation, and the restored log is
//     exported while the signer is stopped;
//  3. keyroster revoke recover --yes, offline, with the server's copy as
//     --krl, writes the admin-signed request;
//  4. keyroster-signer recover-revocations applies it under the state
//     lock, before the restored signer ever starts;
//  5. with both started again, the KRL the server serves makes ssh-keygen
//     -Q refuse the certificate (exit 1, ": REVOKED") and accept a control
//     certificate B that was never revoked (exit 0, ": ok"), and
//     krl-served.json holds the new, higher version;
//  6. keyroster audit verify passes on the final export, with --previous
//     set to the restored export.
func TestRestoreRecoveryTracer(t *testing.T) {
	port := freePort(t)
	sg := prepareSigner(t, bootstrapOpts{WebAuthnRPID: serverRPID, WebAuthnOrigins: []string{"https://" + serverRPID + ":" + strconv.Itoa(port)}})
	stopSigner := serveStoppable(t, sg)
	env := &serverEnv{Signer: sg, CA: newTestCA(t, serverRPID), Port: port, URL: "https://" + serverRPID + ":" + strconv.Itoa(port)}
	state := filepath.Join(t.TempDir(), "server-state")
	stopServer := startStoppableServer(t, env, state)

	// Certificate A through the admin path.
	key := filepath.Join(t.TempDir(), "id_a")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "a", "-f", key)
	sg.issue(t, "--pubkey", key+".pub", "--principal", "role:t", "--subject", "u:a", "--ttl", "10m")
	cert := key + "-cert.pub"
	serial := parseCertInfo(t, sshKeygen(t, "-L", "-f", cert)).serial
	// The control certificate B, issued before the backup too, never
	// revoked: every KRL here must accept it.
	keyB := filepath.Join(t.TempDir(), "id_b")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "b", "-f", keyB)
	sg.issue(t, "--pubkey", keyB+".pub", "--principal", "role:t", "--subject", "u:b", "--ttl", "10m")
	certB := keyB + "-cert.pub"

	// The backup and the saved export, taken from the stopped signer, both
	// before the revocation.
	stopSigner()
	backup := t.TempDir()
	copyDB(t, sg.StateDir, backup)
	saved := sg.exportLog(t)
	stopSigner = serveStoppable(t, sg)

	// 1. The revocation after the saved export, through keyroster-server.
	admin := newCLIEnv(t)
	if code, out, errOut := runCLIIn(t, admin, "", "", keyrosterBin, append(env.initArgs(), "--admin-key", sg.AdminFingerprint)...); code != 0 {
		t.Fatalf("keyroster init exited %d:\n%s%s", code, out, errOut)
	}
	code, out, errOut := runCLIIn(t, admin, sg.AdminAgent, "", keyrosterBin, "revoke", "serial", serial, "--reason", "e2e recovery tracer")
	if code != 0 {
		t.Fatalf("keyroster revoke serial exited %d:\n%s%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	match := regexp.MustCompile(`The server reports serial ` + serial + ` \(user\) revoked: KRL v([0-9]+) published`).FindStringSubmatch(out)
	if match == nil {
		t.Fatalf("keyroster revoke serial output:\n%s", out)
	}
	revoked, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if v := servedCopyVersion(t, state); v != revoked {
		t.Fatalf("krl-served.json holds KRL v%d after the revocation, want v%d", v, revoked)
	}
	revKRL := writeKRL(t, mustServedKRL(t, env, revoked-1))
	requireKeygen(t, "the KRL of the revocation on A", revKRL, cert, true)
	requireKeygen(t, "the KRL of the revocation on B", revKRL, certB, false)

	// 2. The restore, with the server stopped: the copy replaces signer.db.
	stopServer()
	stopSigner()
	restoreDB(t, backup, sg.StateDir)
	restored := sg.exportLog(t)
	work := t.TempDir()
	serverCopy := filepath.Join(work, "krl-served.json")
	copyFile(t, filepath.Join(state, "krl-served.json"), serverCopy, 0o600)

	// 3. keyroster revoke recover, offline.
	reqFile := filepath.Join(work, "recovery.req")
	code, out, errOut = runCLIIn(t, admin, sg.AdminAgent, "", keyrosterBin, "revoke", "recover",
		"--restored", restored, "--saved", saved, "--krl", serverCopy, "--out", reqFile, "--yes")
	if code != 0 || !strings.Contains(out, "installation: "+sg.InstallationID+"\n") ||
		!strings.Contains(out, "import: "+serverCopy+": KRL v"+match[1]+",") ||
		!strings.Contains(out, "lost certificates: none\n") ||
		!strings.Contains(out, "wrote the signed recovery request to "+reqFile) {
		t.Fatalf("keyroster revoke recover exited %d:\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	t.Logf("keyroster revoke recover:\n%s", out)

	// 4. keyroster-signer recover-revocations, the signer stopped. Its
	// publish must be above every imported version, and versions are
	// time-derived in whole seconds (max(prev + 1, issued_at)): this test
	// runs within a second or two of the revocation, so it waits for the
	// clock to pass the imported version, as the refusal
	// recovery_version_not_above_import would ask.
	for time.Now().Unix() <= int64(revoked) { //nolint:gosec // G115: a time-derived version fits int64
		time.Sleep(100 * time.Millisecond)
	}
	in, err := os.Open(reqFile) //nolint:gosec // G304: the test's file
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, signerBin, "recover-revocations", "--state-dir", sg.StateDir) //nolint:gosec // G204: the binary under test
	cmd.Env, cmd.Stdin = envWithout("SSH_AUTH_SOCK"), in
	recOut, err := cmd.CombinedOutput()
	_ = in.Close()
	rm := regexp.MustCompile(`(?m)^recovered: [0-9]+ entries from 2 imported KRLs, 0 lost certificates revoked, 0 kept; KRL v([0-9]+) \(log entries [0-9]+, [0-9]+\)$`).FindSubmatch(recOut)
	if err != nil || rm == nil {
		t.Fatalf("keyroster-signer recover-revocations: %v\n%s", err, recOut)
	}
	t.Logf("keyroster-signer recover-revocations: %s", strings.TrimSpace(string(recOut)))
	recovered, err := strconv.ParseUint(string(rm[1]), 10, 64)
	if err != nil || recovered <= revoked {
		t.Fatalf("the recovery published KRL v%s, want above v%d", rm[1], revoked)
	}

	// 5. Both started again: the server serves the recovered KRL and keeps
	// it.
	serveStoppable(t, sg)
	startStoppableServer(t, env, state)
	recKRL := writeKRL(t, mustServedKRL(t, env, revoked))
	requireKeygen(t, "the recovered KRL on A", recKRL, cert, true)
	requireKeygen(t, "the recovered KRL on B", recKRL, certB, false)
	if v := servedCopyVersion(t, state); v != recovered {
		t.Fatalf("krl-served.json holds KRL v%d after the recovery, want v%d", v, recovered)
	}

	// 6. The final log verifies and extends the restored one.
	final := sg.exportLog(t)
	if code, out := auditVerifyPins(t, sg.RootFingerprints, final, "--previous", restored); code != 0 {
		t.Fatalf("keyroster audit verify --previous <restored export> <final export>: exit %d:\n%s", code, out)
	}
}

// mustServedKRL reads the KRL env's server serves through the pinned
// client, verifies it against the root-pinned bundle with a version above
// above, and returns its bytes.
func mustServedKRL(t *testing.T, env *serverEnv, above uint64) []byte {
	t.Helper()
	client, bundle := revokeClient(t, env)
	doc, err := client.GetKRL(context.Background())
	if err != nil || doc == nil {
		t.Fatalf("GetKRL = %v, %v\nserver log:\n%s", doc, err, env.Stderr.String())
	}
	if _, err := krl.VerifyManifest(doc.Manifest, doc.Sig, doc.KRL, bundle, env.Signer.InstallationID, above); err != nil {
		t.Fatalf("VerifyManifest of the served KRL (above v%d): %v", above, err)
	}
	return doc.KRL
}

// drillCert is one certificate of the restore drill.
type drillCert struct {
	name, key, cert, serial string
}

// drillIssue issues a certificate through the admin path with subject and
// args (the principals and, for a host certificate, --ca host) and
// returns it.
func drillIssue(t *testing.T, sg *signerEnv, name, subject string, args ...string) drillCert {
	t.Helper()
	key := filepath.Join(t.TempDir(), "id_"+name)
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key)
	sg.issue(t, append([]string{"--pubkey", key + ".pub", "--subject", subject, "--ttl", "10m"}, args...)...)
	c := drillCert{name: name, key: key, cert: key + "-cert.pub"}
	c.serial = parseCertInfo(t, sshKeygen(t, "-L", "-f", c.cert)).serial
	return c
}

// runRecoverRevocations runs keyroster-signer recover-revocations on sg's
// state directory with reqFile on standard input, as the runbook's
// recovery line does, and returns its exit code and combined output.
func runRecoverRevocations(t *testing.T, sg *signerEnv, reqFile string) (int, string) {
	t.Helper()
	in, err := os.Open(reqFile) //nolint:gosec // G304: the test's file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, signerBin, "recover-revocations", "--state-dir", sg.StateDir) //nolint:gosec // G204: the binary under test
	cmd.Env, cmd.Stdin = envWithout("SSH_AUTH_SOCK"), in
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("keyroster-signer recover-revocations: %v\n%s", err, out)
		}
		return ee.ExitCode(), string(out)
	}
	return 0, string(out)
}

// TestRestoreRecoversLostRevocations is the restore drill of
// docs/runbooks/signer-install.md step 2b (03-06c), through the runbook's
// commands (as the test's own user; test/systemd/smoke.sh runs the
// runbook's runuser blocks):
//
//  1. B (user) and the control E (user, never revoked) are issued, the
//     backup is taken from the stopped signer, and the saved export is
//     taken;
//  2. B is revoked through keyroster-server after the saved export, so
//     only the server's krl-served.json holds the revocation;
//  3. the server and the signer are stopped (the hold), the server's copy
//     is kept as the capture block keeps it, the backup is restored, and
//     the restored export is taken before the signer ever starts;
//  4. keyroster revoke recover with the restored and saved exports and
//     --krl set to the kept copy, whose summary lists the copy among the
//     imports; keyroster-signer recover-revocations reads its file under
//     the hold;
//  5. both started again, the served KRL makes ssh-keygen -Q refuse B and
//     accept E, and sshd refuses B's login and accepts E's.
func TestRestoreRecoversLostRevocations(t *testing.T) {
	port := freePort(t)
	sg := prepareSigner(t, bootstrapOpts{WebAuthnRPID: serverRPID, WebAuthnOrigins: []string{"https://" + serverRPID + ":" + strconv.Itoa(port)}})
	stopSigner := serveStoppable(t, sg)
	env := &serverEnv{Signer: sg, CA: newTestCA(t, serverRPID), Port: port, URL: "https://" + serverRPID + ":" + strconv.Itoa(port)}
	state := filepath.Join(t.TempDir(), "server-state")
	stopServer := startStoppableServer(t, env, state)
	admin := newCLIEnv(t)
	if code, out, errOut := runCLIIn(t, admin, "", "", keyrosterBin, append(env.initArgs(), "--admin-key", sg.AdminFingerprint)...); code != 0 {
		t.Fatalf("keyroster init exited %d:\n%s%s", code, out, errOut)
	}
	kr := func(args ...string) string {
		t.Helper()
		code, out, errOut := revokeCLIRetry(t, env, admin, args...)
		if code != 0 {
			t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, env.Stderr.String())
		}
		return out
	}

	// 1. Before the backup: B and the control E.
	b := drillIssue(t, sg, "b", "bert", "--principal", "role:t")
	e := drillIssue(t, sg, "e", "erik", "--principal", "role:t")
	stopSigner()
	backup := t.TempDir()
	copyDB(t, sg.StateDir, backup)
	saved := sg.exportLog(t)
	stopSigner = serveStoppable(t, sg)

	// 2. B revoked after the saved export, through keyroster-server.
	out := kr("revoke", "serial", b.serial, "--reason", "e2e restore drill")
	match := regexp.MustCompile(`The server reports serial ` + b.serial + ` \(user\) revoked: KRL v([0-9]+) published`).FindStringSubmatch(out)
	if match == nil {
		t.Fatalf("keyroster revoke serial output:\n%s", out)
	}
	lastServed, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if v := servedCopyVersion(t, state); v != lastServed {
		t.Fatalf("krl-served.json holds KRL v%d after the revocation of B, want v%d", v, lastServed)
	}

	// 3. The hold: the server and the signer stopped. The capture block
	// keeps the server's copy before the file restore; the restored export
	// is taken before the restored signer ever starts.
	stopServer()
	stopSigner()
	recovery := t.TempDir()
	serverCopy := filepath.Join(recovery, "server-krl.json")
	copyFile(t, filepath.Join(state, "krl-served.json"), serverCopy, 0o600)
	restoreDB(t, backup, sg.StateDir)
	restored := sg.exportLog(t)
	if code, out := auditVerifyPins(t, sg.RootFingerprints, restored); code != 0 {
		t.Fatalf("audit verify of the restored export: exit %d:\n%s", code, out)
	}

	// 4. Step 2b: the admin's keyroster revoke recover with --krl, then
	// the recovery line under the hold, past the newest imported version
	// (versions are time-derived in whole seconds; the runbook's refusal
	// recovery_version_not_above_import says to wait).
	reqFile := filepath.Join(recovery, "recovery.bin")
	out = kr("revoke", "recover", "--restored", restored, "--saved", saved, "--krl", serverCopy, "--out", reqFile, "--yes")
	if !strings.Contains(out, "import: "+serverCopy+": KRL v"+match[1]+",") || !strings.Contains(out, "lost certificates: none\n") {
		t.Fatalf("keyroster revoke recover summary:\n%s", out)
	}
	t.Logf("keyroster revoke recover:\n%s", out)
	for time.Now().Unix() <= int64(lastServed) { //nolint:gosec // G115: a time-derived version fits int64
		time.Sleep(100 * time.Millisecond)
	}
	code, recOut := runRecoverRevocations(t, sg, reqFile)
	rm := regexp.MustCompile(`(?m)^recovered: [0-9]+ entries from 2 imported KRLs, 0 lost certificates revoked, 0 kept; KRL v([0-9]+) \(log entries [0-9]+, [0-9]+\)$`).FindStringSubmatch(recOut)
	if code != 0 || rm == nil {
		t.Fatalf("keyroster-signer recover-revocations exited %d:\n%s", code, recOut)
	}
	t.Logf("keyroster-signer recover-revocations: %s", strings.TrimSpace(recOut))
	recovered, err := strconv.ParseUint(rm[1], 10, 64)
	if err != nil || recovered <= lastServed {
		t.Fatalf("the recovery published KRL v%s, want above v%d", rm[1], lastServed)
	}
	final := sg.exportLog(t)
	if code, out := auditVerifyPins(t, sg.RootFingerprints, final); code != 0 {
		t.Fatalf("audit verify of the recovered export: exit %d:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, sg.RootFingerprints, final, "--previous", restored); code != 0 {
		t.Fatalf("audit verify --previous <restored export> <recovered export>: exit %d:\n%s", code, out)
	}

	// 5. The release: both started again. The served KRL refuses B and
	// accepts E, with ssh-keygen and with sshd.
	serveStoppable(t, sg)
	startStoppableServer(t, env, state)
	served := mustServedKRL(t, env, lastServed)
	recKRL := writeKRL(t, served)
	requireKeygen(t, "the recovered KRL on B", recKRL, b.cert, true)
	requireKeygen(t, "the recovered KRL on the control E", recKRL, e.cert, false)

	login := currentUser(t)
	d := krlLayout(t)
	sshd := startSSHDWithLog(t, sshdOptions{
		UserCAPub:  sg.UserCAPub,
		Principals: map[string][]string{login: {"role:t"}},
		Extra:      []string{"RevokedKeys " + filepath.Join(d, "current", "revoked.krl")},
	})
	from := func(c drillCert, src string) (int, string) {
		return sshLogin(t, loginOptions{Port: sshd.port, Key: c.key, Cert: c.cert, User: login, Command: "true", Extra: []string{"-o", "BindAddress=" + src}})
	}
	for _, c := range []drillCert{e, b} {
		if code, out := from(c, "127.0.0.1"); code != 0 {
			t.Fatalf("login with %s before the swap exited %d:\n%s", c.name, code, out)
		}
	}
	swapKRL(t, d, served)
	if code, out := from(e, "127.0.0.1"); code != 0 {
		t.Fatalf("login with the control E under the recovered KRL exited %d:\n%s", code, out)
	}
	before := sshd.log.String()
	if code, out := from(b, "127.0.0.2"); code == 0 {
		t.Fatalf("login with B under the recovered KRL succeeded:\n%s", out)
	}
	waitForLog(t, sshd, before, "revoked")
	t.Logf("sshd refused B: %s", strings.TrimSpace(strings.TrimPrefix(sshd.log.String(), before)))
}
