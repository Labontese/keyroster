//go:build e2e_tpm

// TPM 2.0 path (KEY-04, D-07, D-08, D-09): keyroster-signer ca-init
// --backend tpm creates the five online keys as ECDSA P-256 keys inside a
// TPM; in CI and locally that TPM is swtpm, which reports manufacturer IBM
// and is therefore recorded as custody vtpm.
//
// Environment, besides KEYROSTER_OPENSSH_PREFIX (sshd, ssh, ssh-keygen):
//
//	KEYROSTER_TPM_OPTS  the tpm backend options, comma-separated key=value,
//	                    as printed by scripts/swtpm-setup.sh, for example
//	                    swtpm-socket=/tmp/x/swtpm.sock
package e2e

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/note"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
)

// tpmOpts parses KEYROSTER_TPM_OPTS. Like the rest of e2e it fails, never
// skips, when unset.
func tpmOpts(t *testing.T) map[string]string {
	t.Helper()
	raw := os.Getenv("KEYROSTER_TPM_OPTS")
	if raw == "" {
		t.Fatal("KEYROSTER_TPM_OPTS is not set; start a TPM with scripts/swtpm-setup.sh and use the option it prints")
	}
	opts := map[string]string{}
	for _, kv := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			t.Fatalf("KEYROSTER_TPM_OPTS: %q is not key=value", kv)
		}
		opts[k] = v
	}
	return opts
}

// tpmSigner is a keyroster-signer serve process that a test can stop and
// start again.
type tpmSigner struct {
	env  *signerEnv
	cmd  interface{ Signal(os.Signal) error }
	done <-chan struct{}
	log  *syncBuffer
}

// tpmServe starts keyroster-signer serve on env's state (the same command
// as signerEnv.serve) and keeps the process handle for a restart.
func tpmServe(t *testing.T, env *signerEnv) *tpmSigner {
	t.Helper()
	cmd, log, done := startDaemon(t, "keyroster-signer", envWithout("SSH_AUTH_SOCK"), signerBin,
		"serve", "--state-dir", env.StateDir, "--socket", env.Socket, "--allow-uid", strconv.Itoa(os.Getuid()))
	waitFor(t, "signer socket", done, log, func() bool { return isSocket(env.Socket) })
	return &tpmSigner{env: env, cmd: cmd.Process, done: done, log: log}
}

// stop sends SIGTERM and waits for the signer to exit.
func (s *tpmSigner) stop(t *testing.T) {
	t.Helper()
	if err := s.cmd.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop the signer: %v", err)
	}
	select {
	case <-s.done:
	case <-time.After(10 * time.Second):
		t.Fatalf("the signer did not stop:\n%s", s.log.String())
	}
}

// tpmVerifiedBundle verifies env's genesis bundle against the pinned root.
func tpmVerifiedBundle(t *testing.T, env *signerEnv) *trust.Bundle {
	t.Helper()
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(env.BundleDir, name)) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	b, _, err := trust.VerifyGenesisBundle(read("bundle.json"), read("bundle.json.sigs"),
		read("policy.json"), read("policy.json.sigs"), env.RootFingerprints, 1)
	if err != nil {
		t.Fatalf("verify genesis bundle: %v", err)
	}
	return b
}

// assertTPMKeys checks that ca-pubkeys.json and the verified bundle record
// five ecdsa-sha2-nistp256 keys with custody vtpm (swtpm reports IBM), and
// returns the ca-pubkeys keys by role.
func assertTPMKeys(t *testing.T, env *signerEnv) map[string]string {
	t.Helper()
	data, err := os.ReadFile(env.CAPubkeys)
	if err != nil {
		t.Fatal(err)
	}
	cas, err := trust.ParseCAPubKeys(data)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	for _, k := range cas.Keys {
		if k.Alg != ssh.KeyAlgoECDSA256 || k.Custody != "vtpm" {
			t.Errorf("ca-pubkeys %s: alg %q custody %q, want %s vtpm", k.Role, k.Alg, k.Custody, ssh.KeyAlgoECDSA256)
		}
		keys[k.Role] = k.Key
	}
	if len(keys) != len(roleNames) {
		t.Fatalf("ca-pubkeys.json lists %d keys, want %d", len(keys), len(roleNames))
	}
	b := tpmVerifiedBundle(t, env)
	if len(b.CAs) != 3 {
		t.Fatalf("bundle lists %d CAs, want user, host and machine", len(b.CAs))
	}
	for _, ca := range b.CAs {
		if ca.Custody != "vtpm" || ca.Alg != ssh.KeyAlgoECDSA256 {
			t.Errorf("bundle CA %s: custody %q alg %q, want vtpm %s", ca.Role, ca.Custody, ca.Alg, ssh.KeyAlgoECDSA256)
		}
	}
	if b.OpsKey.Custody != "vtpm" || b.OpsKey.Alg != ssh.KeyAlgoECDSA256 {
		t.Errorf("bundle ops key: custody %q alg %q, want vtpm %s", b.OpsKey.Custody, b.OpsKey.Alg, ssh.KeyAlgoECDSA256)
	}
	if b.Log.Custody != "vtpm" || b.Log.Alg != ssh.KeyAlgoECDSA256 {
		t.Errorf("bundle log key: custody %q alg %q, want vtpm %s", b.Log.Custody, b.Log.Alg, ssh.KeyAlgoECDSA256)
	}
	return keys
}

var tpmSigningCA = regexp.MustCompile(`(?m)^\s*Signing CA: \S+ (SHA256:\S+)`)

// tpmIssueAndLogin issues a user certificate through env, checks that the
// TPM user CA signed it, and logs in with it on a fresh sshd.
func tpmIssueAndLogin(t *testing.T, env *signerEnv) {
	t.Helper()
	login := currentUser(t)
	userKey := filepath.Join(t.TempDir(), "id_ed25519")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user", "-f", userKey)
	env.issue(t, "--pubkey", userKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	certFile := userKey + "-cert.pub"
	want := fingerprint(t, env.UserCAPub)
	if m := tpmSigningCA.FindStringSubmatch(sshKeygen(t, "-L", "-f", certFile)); m == nil || m[1] != want {
		t.Fatalf("certificate not signed by the TPM user CA %s (ssh-keygen -L match %q)", want, m)
	}
	port := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {login}}})
	if code, out := sshLogin(t, loginOptions{Port: port, Key: userKey, Cert: certFile, User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with the TPM-signed certificate exited %d:\n%s", code, out)
	}
}

// tpmAuditVerify exports env's log, verifies it pinned to the root
// (expecting entries entries and issued issuances), and checks that the
// checkpoint is signed by the TPM log key with the ECDSA note signature
// (C2SP type 0x02: key ID from SHA-256 of the SPKI, DER ECDSA signature).
func tpmAuditVerify(t *testing.T, env *signerEnv, entries, issued int) {
	t.Helper()
	export := env.exportLog(t)
	args := []string{"audit", "verify", "--threshold", "1"}
	for _, fp := range env.RootFingerprints {
		args = append(args, "--pin", fp)
	}
	code, out := keyrosterWithAgent(t, "", append(args, export)...)
	wantPrefix := "OK: " + strconv.Itoa(entries) + " entries,"
	if code != 0 || !strings.HasPrefix(out, wantPrefix) || !strings.Contains(out, "issued "+strconv.Itoa(issued)) {
		t.Fatalf("keyroster audit verify exited %d, want %q and issued %d:\n%s", code, wantPrefix, issued, out)
	}
	t.Logf("keyroster audit verify:\n%s", out)

	f, err := os.Open(export) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var checkpoint string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var line audit.ExportLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		if line.Checkpoint != "" {
			checkpoint = line.Checkpoint
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if checkpoint == "" {
		t.Fatal("the export has no checkpoint")
	}
	logPubData, err := os.ReadFile(env.LogPub)
	if err != nil {
		t.Fatal(err)
	}
	logPub, _, _, _, err := ssh.ParseAuthorizedKey(logPubData)
	if err != nil {
		t.Fatal(err)
	}
	ec, ok := logPub.(ssh.CryptoPublicKey).CryptoPublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("the log key is a %s, want ECDSA P-256", logPub.Type())
	}
	spki, err := x509.MarshalPKIXPublicKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(spki)
	wantID := binary.BigEndian.Uint32(h[:4])

	// The signature line is "— NAME BASE64(keyID || DER signature)".
	_, sigs, ok := strings.Cut(checkpoint, "\n\n")
	if !ok {
		t.Fatalf("checkpoint without signatures:\n%s", checkpoint)
	}
	fields := strings.Fields(strings.SplitN(sigs, "\n", 2)[0])
	if len(fields) != 3 || fields[0] != "—" {
		t.Fatalf("checkpoint signature line %q", sigs)
	}
	raw, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil || len(raw) < 4+8 || raw[4] != 0x30 {
		t.Fatalf("checkpoint signature is not a key ID plus a DER ECDSA signature (%d bytes, err %v)", len(raw), err)
	}
	if got := binary.BigEndian.Uint32(raw[:4]); got != wantID {
		t.Fatalf("checkpoint key ID %08x, want %08x (the ECDSA key ID of the TPM log key)", got, wantID)
	}
	v, err := tlog.NewNoteVerifier(fields[1], logPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open([]byte(checkpoint), note.VerifierList(v)); err != nil {
		t.Fatalf("the checkpoint does not verify with the TPM log key: %v", err)
	}
}

// TestTPMFullFlow is the KEY-04 flow: ca-init --backend tpm creates the
// keys in the TPM; root-signed genesis bundle; install-bundle; serve; an
// admin-signed ca issue signed by the TPM user CA; an sshd 10.5p1 login;
// audit verify --pin with an ECDSA checkpoint from the TPM log key.
func TestTPMFullFlow(t *testing.T) {
	env := prepareSigner(t, bootstrapOpts{Backend: "tpm", BackendOpts: tpmOpts(t)})
	assertTPMKeys(t, env)
	tpmServe(t, env)
	tpmIssueAndLogin(t, env)
	// ca_init, bundle_install and the issuance.
	tpmAuditVerify(t, env, 3, 1)
}

// TestTPMRestartPersistence: after the signer stops and starts again, it
// loads the same five keys from the TPM key files and issuance continues.
func TestTPMRestartPersistence(t *testing.T) {
	env := prepareSigner(t, bootstrapOpts{Backend: "tpm", BackendOpts: tpmOpts(t)})
	before := assertTPMKeys(t, env)
	s := tpmServe(t, env)
	tpmIssueAndLogin(t, env)
	s.stop(t)

	s = tpmServe(t, env)
	waitFor(t, "serving log line", s.done, s.log, func() bool { return strings.Contains(s.log.String(), "msg=serving") })
	logged := s.log.String()
	for role, key := range map[string]string{"user_ca": before["user"], "host_ca": before["host"], "machine_ca": before["machine"], "log_key": before["log"]} {
		pub, err := trust.ParseKey(key)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(logged, role+"="+ssh.FingerprintSHA256(pub)) {
			t.Fatalf("restarted signer does not report %s=%s:\n%s", role, ssh.FingerprintSHA256(pub), logged)
		}
	}
	tpmIssueAndLogin(t, env)
	if after := assertTPMKeys(t, env); len(after) != len(before) {
		t.Fatal("ca-pubkeys.json changed")
	}
	// ca_init, bundle_install and two issuances.
	tpmAuditVerify(t, env, 4, 2)
}

// TestTPMCAInitTwiceRefused: ca-init --backend tpm prints the TPM
// manufacturer and the custody derived from it (swtpm: IBM, vtpm); a second
// ca-init on the same state is refused and leaves the key files,
// ca-pubkeys.json and the audit log unchanged (KEY-04 idempotency).
func TestTPMCAInitTwiceRefused(t *testing.T) {
	base := shortTempDir(t)
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{"ca-init", "--state-dir", state, "--backend", "tpm"}
	opts := tpmOpts(t)
	for _, k := range sortedKeys(opts) {
		args = append(args, "--backend-opt", k+"="+opts[k])
	}
	code, out := runBin(t, signerBin, "", args...)
	if code != 0 {
		t.Fatalf("ca-init exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "TPM manufacturer: IBM → custody vtpm") || strings.Count(out, " ecdsa-sha2-nistp256 vtpm\n") != len(roleNames) {
		t.Fatalf("ca-init output lacks the manufacturer line or five vtpm keys:\n%s", out)
	}

	snapshot := func() map[string][]byte {
		t.Helper()
		files := map[string][]byte{}
		for _, dir := range []string{state, filepath.Join(state, "tpm")} {
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				if e.IsDir() || strings.HasPrefix(e.Name(), "signer.db") {
					continue
				}
				data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // test fixture
				if err != nil {
					t.Fatal(err)
				}
				files[filepath.Join(filepath.Base(dir), e.Name())] = data
			}
		}
		return files
	}
	exportLog := func() []byte {
		t.Helper()
		path := filepath.Join(t.TempDir(), "log.jsonl")
		if code, out := runBin(t, signerBin, "", "export-log", "--state-dir", state, "--out", path); code != 0 {
			t.Fatalf("export-log exited %d:\n%s", code, out)
		}
		data, err := os.ReadFile(path) //nolint:gosec // test fixture
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	before, logBefore := snapshot(), exportLog()
	if len(before) != 1+2*len(roleNames) {
		t.Fatalf("state holds %d files, want ca-pubkeys.json and 10 key and auth files", len(before))
	}

	// The default output, ca-pubkeys.json, already exists.
	if code, out := runBin(t, signerBin, "", args...); code == 0 {
		t.Fatalf("second ca-init exited 0:\n%s", out)
	}
	fresh := filepath.Join(t.TempDir(), "ca-pubkeys.json")
	code, out = runBin(t, signerBin, "", append(args, "--out", fresh)...)
	if code == 0 || !strings.Contains(out, "already initialised") {
		t.Fatalf("second ca-init with --out exited %d, want a refusal naming the initialised state:\n%s", code, out)
	}
	after := snapshot()
	if len(after) != len(before) {
		t.Fatalf("refused ca-init changed the state files: %d -> %d", len(before), len(after))
	}
	for name, data := range before {
		if !bytes.Equal(after[name], data) {
			t.Fatalf("refused ca-init changed %s", name)
		}
	}
	if !bytes.Equal(exportLog(), logBefore) {
		t.Fatal("refused ca-init changed the audit log")
	}
}
