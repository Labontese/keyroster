//go:build e2e

package e2e

import (
	"context"
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
//     -Q refuse the certificate, and krl-served.json holds the new, higher
//     version;
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
	if code, out := keygenQuery(t, writeKRL(t, mustServedKRL(t, env, revoked-1)), cert); code == 0 {
		t.Fatalf("the KRL of the revocation does not refuse A:\n%s", out)
	}

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
	krlData := mustServedKRL(t, env, revoked)
	if code, out := keygenQuery(t, writeKRL(t, krlData), cert); code == 0 {
		t.Fatalf("after the recovery, ssh-keygen -Q accepts A, want a refusal:\n%s", out)
	} else {
		t.Logf("ssh-keygen -Q on A after the recovery (exit %d): %s", code, strings.TrimSpace(out))
	}
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
