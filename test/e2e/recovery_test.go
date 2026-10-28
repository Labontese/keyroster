//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/wire"
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

// exportKinds returns the decoded kind of every leaf line of a
// keyroster-signer export, in order (the closing checkpoint line carries
// no index and is skipped). Unlike exportLines it reads nothing else, so
// it also reads revocation_recovery lines, whose "entries" is a count.
func exportKinds(t *testing.T, export string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(readFile(t, export))), "\n") {
		var e struct {
			Index   *uint64 `json:"index"`
			Decoded struct {
				Kind string `json:"kind"`
			} `json:"decoded"`
		}
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("export line %q: %v", l, err)
		}
		if e.Index != nil {
			out = append(out, e.Decoded.Kind)
		}
	}
	return out
}

// TestRestoreRecoversLostRevocations is the restore drill of
// docs/runbooks/signer-install.md step 2b (03-06c), through the runbook's
// commands (as the test's own user; test/systemd/smoke.sh runs the
// runbook's runuser blocks). Setup, in order:
//
//  1. A and B (user) and the control E (user, never revoked) are issued;
//  2. the backup: signer.db copied with the signer stopped;
//  3. C and D (user, other subjects) and H (host) are issued, and A is
//     revoked by key ID, C with keyroster revoke user (subject carol) and
//     the plain key K by key;
//  4. the saved export is taken;
//  5. B is revoked by serial through keyroster-server, which serves and
//     keeps it, so only krl-served.json holds that revocation;
//  6. the hold: the server and the signer are stopped, the server's copy
//     is kept as the capture block keeps it, and the backup is restored.
//
// Then step 2 (the restored export on its own, the saved export on its
// own and with --previous set to the restored one) and step 2b:
// keyroster revoke recover with --krl, whose summary lists the server
// copy, revokes the lost user certificates C and D and keeps the lost
// host certificate H with its public key; and keyroster-signer
// recover-revocations, which is refused while another process holds
// signer.lock and with the evidence of a key that is no admin, each
// writing nothing, then applies the genuine file once, and refuses a
// second run recovery_log_mismatch. The recovered log adds exactly one
// revocation_recovery entry and one krl_publish to the restored one, so
// no KRL was published between the restore and the recovery, and it
// verifies with --previous set to the restored export. Both started
// again, the served KRL makes ssh-keygen -Q refuse A, B, C, D and K and
// accept E and H, and sshd refuses A, B, C and D and accepts E. H is then
// revoked with keyroster revoke key and the public key the summary
// printed. A restarted signer serves the same KRL version, which still
// refuses all of them, and the final export verifies.
//
// Extension point: 03-10's negative-probe revocation (its cross-plan
// note) is added to this drill as a lost revocation of its own.
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

	// 1. Before the backup: A, B and the control E.
	a := drillIssue(t, sg, "a", "anna", "--principal", "role:t")
	b := drillIssue(t, sg, "b", "bert", "--principal", "role:t")
	e := drillIssue(t, sg, "e", "erik", "--principal", "role:t")

	// 2. The backup, from the stopped signer.
	stopSigner()
	backup := t.TempDir()
	copyDB(t, sg.StateDir, backup)
	stopSigner = serveStoppable(t, sg)

	// 3. After the backup: C, D and H issued; A revoked by key ID, C by
	// subject and K by key.
	c := drillIssue(t, sg, "c", "carol", "--principal", "role:t")
	d := drillIssue(t, sg, "d", "dave", "--principal", "role:t")
	h := drillIssue(t, sg, "h", "h:web1", "--ca", "host", "--principal", "web1")
	k := drillCert{name: "k", key: filepath.Join(t.TempDir(), "id_k")}
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "k", "-f", k.key)
	aKeyID := parseCertInfo(t, sshKeygen(t, "-L", "-f", a.cert)).keyID
	if out := kr("revoke", "key-id", aKeyID, "--ca", "user", "--reason", "e2e restore drill: A"); !strings.Contains(out, fmt.Sprintf("lists key ID %q under a user CA key of your trust bundle", aKeyID)) {
		t.Fatalf("keyroster revoke key-id output:\n%s", out)
	}
	if out := kr("revoke", "user", "carol", "--yes", "--reason", "e2e restore drill: C"); !strings.Contains(out, "First revocation of carol: the server reports 1 certificate(s) revoked") ||
		!strings.Contains(out, "Serials: "+c.serial+"\n") {
		t.Fatalf("keyroster revoke user carol does not report C's serial %s:\n%s", c.serial, out)
	}
	kPub := pubKey(t, readPub(t, k.key+".pub"))
	if out := kr("revoke", "key", k.key+".pub", "--reason", "e2e restore drill: K"); !strings.Contains(out, "The server reports key "+ssh.FingerprintSHA256(kPub)+" revoked") {
		t.Fatalf("keyroster revoke key output:\n%s", out)
	}

	// 4. The saved export.
	saved := sg.exportLog(t)

	// 5. B revoked by serial after the saved export.
	out := kr("revoke", "serial", b.serial, "--reason", "e2e restore drill: B")
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

	// 6. The hold: the server and the signer stopped. The capture block
	// keeps the server's copy before the file restore; the restored export
	// is taken before the restored signer ever starts (step 1).
	stopServer()
	stopSigner()
	recovery := t.TempDir()
	serverCopy := filepath.Join(recovery, "server-krl.json")
	copyFile(t, filepath.Join(state, "krl-served.json"), serverCopy, 0o600)
	restoreDB(t, backup, sg.StateDir)
	restored := sg.exportLog(t)

	// Step 2: the restored export on its own, the saved export on its own,
	// and the restored log a prefix of the saved one.
	if code, out := auditVerifyPins(t, sg.RootFingerprints, restored); code != 0 {
		t.Fatalf("audit verify of the restored export: exit %d:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, sg.RootFingerprints, saved); code != 0 {
		t.Fatalf("audit verify of the saved export: exit %d:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, sg.RootFingerprints, saved, "--previous", restored); code != 0 {
		t.Fatalf("audit verify --previous <restored export> <saved export>: exit %d:\n%s", code, out)
	}

	// Step 2b, part 3: the admin's keyroster revoke recover with --krl.
	// The summary lists the server copy among the imports, revokes the
	// lost user certificates C and D, and keeps the lost host certificate
	// H with its public key.
	reqFile := filepath.Join(recovery, "recovery.bin")
	out = kr("revoke", "recover", "--restored", restored, "--saved", saved, "--krl", serverCopy, "--out", reqFile, "--yes")
	t.Logf("keyroster revoke recover:\n%s", out)
	for _, want := range []string{
		"installation: " + sg.InstallationID + "\n",
		"import: saved export, log entry ",
		"import: " + serverCopy + ": KRL v" + match[1] + ",",
		"wrote the signed recovery request to " + reqFile,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("keyroster revoke recover summary lacks %q:\n%s", want, out)
		}
	}
	for _, lc := range []drillCert{c, d} {
		if !regexp.MustCompile(`(?m)^lost certificate: serial ` + lc.serial + `, user, subject ` + map[string]string{"c": "carol", "d": "dave"}[lc.name] + `, key SHA256:\S+, valid before [0-9]+ \(live\): revoke$`).MatchString(out) {
			t.Fatalf("keyroster revoke recover does not revoke the lost user certificate %s (serial %s):\n%s", lc.name, lc.serial, out)
		}
	}
	keep := regexp.MustCompile(`(?m)^lost certificate: serial ` + h.serial + `, host, subject h:web1, key SHA256:\S+, valid before [0-9]+ \(live\): keep; public key (ssh-ed25519 \S+); revoke later with: keyroster revoke key <file with this public key>$`).FindStringSubmatch(out)
	if keep == nil {
		t.Fatalf("keyroster revoke recover does not keep the lost host certificate H (serial %s) with its public key:\n%s", h.serial, out)
	}
	if n := strings.Count(out, "lost certificate: "); n != 3 || strings.Contains(out, "lost certificates expired") {
		t.Fatalf("keyroster revoke recover lists %d lost certificates, want C, D and H and none expired:\n%s", n, out)
	}
	// Versions are time-derived in whole seconds; the recovery's must be
	// above every imported one (recovery_version_not_above_import says to
	// wait).
	for time.Now().Unix() <= int64(lastServed) { //nolint:gosec // G115: a time-derived version fits int64
		time.Sleep(100 * time.Millisecond)
	}

	// Step 2b, part 5, the pending cases. Each refused run writes nothing:
	// the export is byte for byte the restored one.
	unchanged := func(what string) {
		t.Helper()
		if !bytes.Equal(readFile(t, sg.exportLog(t)), readFile(t, restored)) {
			t.Fatalf("%s changed the signer's log", what)
		}
	}
	lock, err := os.OpenFile(filepath.Join(sg.StateDir, "signer.lock"), os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // G304: the test's state directory
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a file descriptor fits int
		t.Fatal(err)
	}
	code, recOut := runRecoverRevocations(t, sg, reqFile)
	_ = lock.Close()
	if code == 0 || !strings.Contains(recOut, "is in use by another keyroster-signer process") {
		t.Fatalf("recover-revocations while another process holds signer.lock exited %d, want the lock refusal:\n%s", code, recOut)
	}
	unchanged("recover-revocations refused for the lock")
	req, err := wire.ParseRecoveryRequest(readFile(t, reqFile))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := req.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	_, notAdmin, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAdminSigner, err := ssh.NewSignerFromKey(notAdmin)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := sshsig.Sign(rand.Reader, notAdminSigner, wire.RecoverySSHSIGNamespace, msg)
	if err != nil {
		t.Fatal(err)
	}
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: blob}}
	tampered, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tamperedFile := filepath.Join(recovery, "recovery-not-admin.bin")
	if err := os.WriteFile(tamperedFile, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := runRecoverRevocations(t, sg, tamperedFile); code == 0 || !strings.Contains(out, "recovery_evidence_invalid") {
		t.Fatalf("recover-revocations with the evidence of a key that is no admin exited %d, want recovery_evidence_invalid:\n%s", code, out)
	}
	unchanged("recover-revocations refused for the evidence")
	code, recOut = runRecoverRevocations(t, sg, reqFile)
	rm := regexp.MustCompile(`(?m)^recovered: [0-9]+ entries from 2 imported KRLs, 2 lost certificates revoked, 1 kept; KRL v([0-9]+) \(log entries [0-9]+, [0-9]+\)$`).FindStringSubmatch(recOut)
	if code != 0 || rm == nil {
		t.Fatalf("keyroster-signer recover-revocations exited %d:\n%s", code, recOut)
	}
	t.Logf("keyroster-signer recover-revocations: %s", strings.TrimSpace(recOut))
	recovered, err := strconv.ParseUint(rm[1], 10, 64)
	if err != nil || recovered <= lastServed {
		t.Fatalf("the recovery published KRL v%s, want above v%d", rm[1], lastServed)
	}
	if code, out := runRecoverRevocations(t, sg, reqFile); code == 0 || !strings.Contains(out, "recovery_log_mismatch") {
		t.Fatalf("a second recover-revocations of the same file exited %d, want recovery_log_mismatch:\n%s", code, out)
	}

	// The recovered export: exactly one revocation_recovery entry and one
	// krl_publish after the restored log, so no KRL was published between
	// the restored log's end and the recovery; it verifies on its own and
	// extends the restored log.
	recoveredExport := sg.exportLog(t)
	restoredKinds, recoveredKinds := exportKinds(t, restored), exportKinds(t, recoveredExport)
	if len(recoveredKinds) != len(restoredKinds)+2 || !slices.Equal(recoveredKinds[:len(restoredKinds)], restoredKinds) ||
		recoveredKinds[len(restoredKinds)] != "revocation_recovery" || recoveredKinds[len(restoredKinds)+1] != "krl_publish" {
		t.Fatalf("the recovered log adds %v to the restored log, want exactly [revocation_recovery krl_publish]", recoveredKinds[min(len(restoredKinds), len(recoveredKinds)):])
	}
	if code, out := auditVerifyPins(t, sg.RootFingerprints, recoveredExport); code != 0 {
		t.Fatalf("audit verify of the recovered export: exit %d:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, sg.RootFingerprints, recoveredExport, "--previous", restored); code != 0 {
		t.Fatalf("audit verify --previous <restored export> <recovered export>: exit %d:\n%s", code, out)
	}

	// The release: both started again. The served KRL refuses A, B, C, D
	// and K and accepts the control E and the kept host certificate H.
	stopSigner = serveStoppable(t, sg)
	startStoppableServer(t, env, state)
	served := mustServedKRL(t, env, lastServed)
	if v := servedCopyVersion(t, state); v != recovered {
		t.Fatalf("krl-served.json holds KRL v%d after the recovery, want v%d", v, recovered)
	}
	recKRL := writeKRL(t, served)
	for _, rc := range []drillCert{a, b, c, d} {
		requireKeygen(t, "the recovered KRL on "+rc.name, recKRL, rc.cert, true)
	}
	requireKeygen(t, "the recovered KRL on the plain key K", recKRL, k.key+".pub", true)
	requireKeygen(t, "the recovered KRL on the control E", recKRL, e.cert, false)
	requireKeygen(t, "the recovered KRL on the kept host certificate H", recKRL, h.cert, false)

	// sshd with the recovered KRL: E logs in, A, B, C and D are refused as
	// revoked, each from its own loopback source (OpenSSH 10.x's
	// PerSourcePenalties never touch 127.0.0.1, which E uses).
	login := currentUser(t)
	layout := krlLayout(t)
	sshd := startSSHDWithLog(t, sshdOptions{
		UserCAPub:  sg.UserCAPub,
		Principals: map[string][]string{login: {"role:t"}},
		Extra:      []string{"RevokedKeys " + filepath.Join(layout, "current", "revoked.krl")},
	})
	from := func(lc drillCert, src string) (int, string) {
		return sshLogin(t, loginOptions{Port: sshd.port, Key: lc.key, Cert: lc.cert, User: login, Command: "true", Extra: []string{"-o", "BindAddress=" + src}})
	}
	for _, lc := range []drillCert{e, a, b, c, d} {
		if code, out := from(lc, "127.0.0.1"); code != 0 {
			t.Fatalf("login with %s before the swap exited %d:\n%s", lc.name, code, out)
		}
	}
	swapKRL(t, layout, served)
	if code, out := from(e, "127.0.0.1"); code != 0 {
		t.Fatalf("login with the control E under the recovered KRL exited %d:\n%s", code, out)
	}
	for i, lc := range []drillCert{a, b, c, d} {
		before := sshd.log.String()
		if code, out := from(lc, "127.0.0."+strconv.Itoa(i+2)); code == 0 {
			t.Fatalf("login with %s under the recovered KRL succeeded:\n%s", lc.name, out)
		}
		waitForLog(t, sshd, before, "revoked")
		t.Logf("sshd refused %s: %s", lc.name, strings.TrimSpace(strings.TrimPrefix(sshd.log.String(), before)))
	}

	// The kept host certificate H, revoked by key with the public key the
	// recovery's summary printed (revoke.md, section 7).
	hPubFile := filepath.Join(t.TempDir(), "h.pub")
	if err := os.WriteFile(hPubFile, []byte(keep[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubKey(t, keep[1]).Marshal(), pubKey(t, readPub(t, h.key+".pub")).Marshal()) {
		t.Fatal("the public key the summary printed for H is not H's key")
	}
	out = kr("revoke", "key", hPubFile, "--reason", "e2e restore drill: H, kept by the recovery")
	hm := regexp.MustCompile(`The server reports key SHA256:\S+ revoked: KRL v([0-9]+) published`).FindStringSubmatch(out)
	if hm == nil {
		t.Fatalf("keyroster revoke key of H's public key:\n%s", out)
	}
	afterH, err := strconv.ParseUint(hm[1], 10, 64)
	if err != nil || afterH <= recovered {
		t.Fatalf("the revocation of H published KRL v%s, want above v%d", hm[1], recovered)
	}
	hKRL := writeKRL(t, mustServedKRL(t, env, recovered))
	requireKeygen(t, "the KRL after revoke key on H", hKRL, h.cert, true)

	// The signer restarts: it serves the same KRL version, which still
	// refuses all of them. keyroster-server serves its copy for up to
	// serverclient.KRLMaxStale; wait it out so the read reaches the
	// restarted signer.
	stopSigner()
	serveStoppable(t, sg)
	time.Sleep(serverclient.KRLMaxStale + time.Second)
	client, _ := revokeClient(t, env)
	doc, err := client.GetKRL(context.Background())
	if err != nil || doc == nil {
		t.Fatalf("GetKRL after the signer restart = %v, %v\nserver log:\n%s", doc, err, env.Stderr.String())
	}
	if m, err := krl.ParseManifest(doc.Manifest); err != nil || m.KRLVersion != afterH {
		t.Fatalf("the restarted signer serves %+v, %v; want KRL v%d again", m, err, afterH)
	}
	restartKRL := writeKRL(t, mustServedKRL(t, env, recovered))
	for _, rc := range []drillCert{a, b, c, d, h} {
		requireKeygen(t, "the KRL after the restart on "+rc.name, restartKRL, rc.cert, true)
	}
	requireKeygen(t, "the KRL after the restart on the plain key K", restartKRL, k.key+".pub", true)
	requireKeygen(t, "the KRL after the restart on the control E", restartKRL, e.cert, false)

	// The final export verifies on its own and extends the restored log.
	final := sg.exportLog(t)
	if code, out := auditVerifyPins(t, sg.RootFingerprints, final, "--previous", restored); code != 0 {
		t.Fatalf("keyroster audit verify --previous <restored export> <final export>: exit %d:\n%s", code, out)
	}
}
