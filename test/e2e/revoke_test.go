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

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// TestRevokeSerialEndToEnd is the Phase 3 tracer (03-01, REVOKE-01..03):
// certificates A and B log in to real sshd whose RevokedKeys points at
// <dir>/current/revoked.krl (a zero-byte file, which revokes nothing);
// keyroster revoke serial A goes through keyroster-server to the signer,
// which publishes the next KRL version (above the empty KRL its first
// start published, 03-03) written by our own encoder with an ops-signed,
// installation-bound manifest; the test fetches it through
// serverclient.Client.GetKRL, verifies it with krl.VerifyManifest against
// the root-pinned bundle, checks the candidate file with ssh-keygen -Q
// (A revoked, B not) and swaps current with rename(2). With no signal sent
// and the same sshd PID, A is refused with sshd's revoked-key log line and
// B still logs in. A restarted signer serves the same KRL, and keyroster
// audit verify accepts the exported log with its revoke and krl_publish
// entries (03-03). Versions are compared, never pinned: krl_version is
// max(previous + 1, issued_at) (owner decision 2026-10-25, Q1).
//
// The direct rename is test harness, not the agent: only the KRL changes
// between gen/1 and gen/2, so 03-05's intermediate generation would equal
// gen/2 and its first step is the whole swap.
func TestRevokeSerialEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{StoppableSigner: true})
	login := currentUser(t)
	keys := t.TempDir()

	// 1. Certificates A and B for principal role:t through the admin path.
	type subject struct{ key, cert, serial string }
	subjects := map[string]*subject{}
	for _, name := range []string{"a", "b"} {
		key := filepath.Join(keys, "id_"+name)
		sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", key)
		env.Signer.issue(t, "--pubkey", key+".pub", "--principal", "role:t", "--subject", "u:"+name, "--ttl", "10m")
		cert := key + "-cert.pub"
		subjects[name] = &subject{key: key, cert: cert, serial: parseCertInfo(t, sshKeygen(t, "-L", "-f", cert)).serial}
	}
	a, b := subjects["a"], subjects["b"]
	if a.serial == b.serial {
		t.Fatalf("A and B share serial %s", a.serial)
	}

	// 2. gen/1 holds a zero-byte KRL; current -> gen/1 (relative).
	d := t.TempDir()
	for _, g := range []string{"gen/1", "gen/2"} {
		if err := os.MkdirAll(filepath.Join(d, g), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(d, "gen/1/revoked.krl"), nil, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.Symlink("gen/1", filepath.Join(d, "current")); err != nil {
		t.Fatal(err)
	}
	sshd := startSSHDWithLog(t, sshdOptions{
		UserCAPub:  env.Signer.UserCAPub,
		Principals: map[string][]string{login: {"role:t"}},
		Extra:      []string{"RevokedKeys " + filepath.Join(d, "current", "revoked.krl")},
	})
	pid := sshd.pid(t)

	// 3. Controls: both log in under the zero-byte KRL.
	for name, s := range subjects {
		if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: s.key, Cert: s.cert, User: login, Command: "true"}); code != 0 {
			t.Fatalf("login with %s before the revocation exited %d:\n%s", name, code, out)
		}
	}

	// The empty KRL serve published at its first start (03-03).
	client, bundle := revokeClient(t, env)
	doc0, err := client.GetKRL(context.Background())
	if err != nil || doc0 == nil {
		t.Fatalf("GetKRL before the revocation = %v, %v", doc0, err)
	}
	m0, err := krl.VerifyManifest(doc0.Manifest, doc0.Sig, doc0.KRL, bundle, env.Signer.InstallationID, 0)
	if err != nil {
		t.Fatalf("VerifyManifest of the start-up KRL: %v", err)
	}
	if code, out := keygenQuery(t, writeKRL(t, doc0.KRL), a.cert); code != 0 {
		t.Fatalf("the start-up KRL revokes A (ssh-keygen -Q exited %d):\n%s", code, out)
	}

	// 4. keyroster revoke serial A through keyroster-server.
	admin := newCLIEnv(t)
	if code, out, errOut := runCLIIn(t, admin, "", "", keyrosterBin, append(env.initArgs(), "--admin-key", env.Signer.AdminFingerprint)...); code != 0 {
		t.Fatalf("keyroster init exited %d:\n%s%s", code, out, errOut)
	}
	code, out, errOut := runCLIIn(t, admin, env.Signer.AdminAgent, "", keyrosterBin, "revoke", "serial", a.serial, "--reason", "e2e tracer")
	if code != 0 {
		t.Fatalf("keyroster revoke serial exited %d:\n%s%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	t.Logf("keyroster revoke serial:\n%s", out)
	match := regexp.MustCompile(`The server reports serial ` + a.serial + ` \(user\) revoked: KRL v([0-9]+) published`).FindStringSubmatch(out)
	if match == nil ||
		!strings.Contains(out, "Checked: the server serves KRL v"+match[1]+", signed by the ops key of your root-pinned trust bundle") ||
		!strings.Contains(out, "Hosts enforce it once their keyroster agent applies this KRL.") {
		t.Fatalf("keyroster revoke serial output:\n%s", out)
	}
	reported, err := strconv.ParseUint(match[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	// 5. GET /api/v1/krl through the pinned client; verify against the
	// root-pinned bundle and the installation ID.
	doc, err := client.GetKRL(context.Background())
	if err != nil || doc == nil {
		t.Fatalf("GetKRL = %v, %v", doc, err)
	}
	m, err := krl.VerifyManifest(doc.Manifest, doc.Sig, doc.KRL, bundle, env.Signer.InstallationID, m0.KRLVersion)
	if err != nil {
		t.Fatalf("VerifyManifest (strictly above the start-up KRL v%d): %v", m0.KRLVersion, err)
	}
	if m.KRLVersion != reported || m.InstallationID != env.Signer.InstallationID || m.BundleVersion != 1 {
		t.Fatalf("manifest = %+v, want the version the CLI reported (%d)", m, reported)
	}
	t.Logf("manifest: %s", doc.Manifest)

	// 6. Candidate file, the oracle on the same bytes, then the swap.
	cand := filepath.Join(d, "gen/2/revoked.krl")
	if err := os.WriteFile(cand, doc.KRL, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if code, out := keygenQuery(t, cand, b.cert); code != 0 {
		t.Fatalf("ssh-keygen -Q on B's certificate exited %d (B is not revoked):\n%s", code, out)
	}
	if code, out := keygenQuery(t, cand, a.cert); code == 0 {
		t.Fatalf("ssh-keygen -Q on A's certificate exited 0, want non-zero (A is revoked):\n%s", out)
	} else {
		t.Logf("ssh-keygen -Q on A (exit %d): %s", code, strings.TrimSpace(out))
	}
	tmp := filepath.Join(d, "current.tmp")
	if err := os.Symlink("gen/2", tmp); err != nil {
		t.Fatal(err)
	}
	fsyncDir(t, filepath.Join(d, "gen/2"))
	fsyncDir(t, d)
	if err := os.Rename(tmp, filepath.Join(d, "current")); err != nil {
		t.Fatal(err)
	}
	fsyncDir(t, d)

	// 7. A is refused with the revoked-key log line; B still logs in; same
	// sshd PID, no signal sent.
	before := sshd.log.String()
	if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: a.key, Cert: a.cert, User: login, Command: "true"}); code == 0 {
		t.Fatalf("login with A after the swap succeeded; want a refusal:\n%s", out)
	}
	waitForLog(t, sshd, before, "revoked")
	t.Logf("sshd after A: %s", strings.TrimSpace(strings.TrimPrefix(sshd.log.String(), before)))
	if code, out := sshLogin(t, loginOptions{Port: sshd.port, Key: b.key, Cert: b.cert, User: login, Command: "true"}); code != 0 {
		t.Fatalf("login with B after the swap exited %d:\n%s", code, out)
	}
	if got := sshd.pid(t); got != pid {
		t.Fatalf("sshd PID changed from %d to %d", pid, got)
	}
	t.Logf("sshd PID %d unchanged; no signal was sent", pid)

	// 8. A restarted signer serves the same KRL.
	env.StopSigner()
	serveStoppable(t, env.Signer)
	// keyroster-server serves its copy of the KRL for up to
	// serverclient.KRLMaxStale; wait it out so this read reaches the
	// restarted signer instead of the cache.
	time.Sleep(serverclient.KRLMaxStale + time.Second)
	doc2, err := client.GetKRL(context.Background())
	if err != nil || doc2 == nil {
		t.Fatalf("GetKRL after the signer restart = %v, %v\nserver log:\n%s", doc2, err, env.Stderr.String())
	}
	if !bytes.Equal(doc2.KRL, doc.KRL) || !bytes.Equal(doc2.Manifest, doc.Manifest) || !bytes.Equal(doc2.Sig, doc.Sig) {
		t.Fatal("the restarted signer serves another KRL")
	}
	if m2, err := krl.ParseManifest(doc2.Manifest); err != nil || m2.KRLVersion != m.KRLVersion {
		t.Fatalf("manifest after the restart = %+v, %v; want version %d again", m2, err, m.KRLVersion)
	}

	// 9. keyroster audit verify checks the revoke entry and both
	// krl_publish entries (the start-up publish and the revocation's) of
	// the exported log; the restart published nothing.
	code, out = auditVerify(t, env.Signer, env.Signer.exportLog(t), "--json")
	if code != 0 {
		t.Fatalf("keyroster audit verify exited %d:\n%s", code, out)
	}
	var res struct {
		Kinds map[string]uint64 `json:"kinds"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("audit verify --json: %v\n%s", err, out)
	}
	if res.Kinds["revoke"] != 1 || res.Kinds["krl_publish"] != 2 {
		t.Fatalf("audit verify kinds = %v, want 1 revoke and 2 krl_publish entries", res.Kinds)
	}
	t.Logf("keyroster audit verify: %s", strings.TrimSpace(out))
}

// writeKRL writes data to a fresh file and returns its path.
func writeKRL(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "revoked.krl")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// revokeClient builds the pinned TLS client for env's server and returns
// it with the trust bundle verified against the root pins.
func revokeClient(t *testing.T, env *serverEnv) (*serverclient.Client, *trust.Bundle) {
	t.Helper()
	root, err := os.ReadFile(env.CA.RootPEM)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	c, err := serverclient.New(serverclient.Config{Server: env.URL, RootsPEM: []string{string(root)}, Pins: []string{env.CA.RootPin}, Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := c.Trust(context.Background(), env.Signer.RootFingerprints, 1)
	if err != nil {
		t.Fatalf("Trust: %v", err)
	}
	return c, b
}

// keygenQuery runs ssh-keygen -Q -f krlFile certFile and returns its exit
// code and output (0: not revoked).
func keygenQuery(t *testing.T, krlFile, certFile string) (int, string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh-keygen"), "-Q", "-f", krlFile, certFile)
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	out, err := cmd.CombinedOutput()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out)
		}
		t.Fatalf("ssh-keygen -Q: %v\n%s", err, out)
	}
	return 0, string(out)
}

func fsyncDir(t *testing.T, dir string) {
	t.Helper()
	f, err := os.Open(dir) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}
}

// sshdRun is an sshd started by startSSHDWithLog.
type sshdRun struct {
	port    int
	pidFile string
	log     *syncBuffer
}

// pid reads sshd's PidFile.
func (s *sshdRun) pid(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(s.pidFile)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("sshd PidFile %q: %v", data, err)
	}
	return n
}

// startSSHDWithLog is startSSHD (harness_test.go) that also returns the
// PidFile path and the daemon's log, which the tracer needs to show that
// the same sshd process refused a revoked key. It builds the same
// configuration from sshdConfigTemplate.
func startSSHDWithLog(t *testing.T, opts sshdOptions) *sshdRun {
	t.Helper()
	prefix := opensshPrefix(t)
	dir := t.TempDir()
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, "ssh_host_ed25519_key"))
	if err := os.Mkdir(filepath.Join(dir, "principals"), 0o755); err != nil {
		t.Fatal(err)
	}
	for u, ps := range opts.Principals {
		if err := os.WriteFile(filepath.Join(dir, "principals", u), []byte(strings.Join(ps, "\n")+"\n"), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	port := freePort(t)
	cfg := fmt.Sprintf(sshdConfigTemplate, port, dir, dir, opts.UserCAPub, dir)
	for _, l := range opts.Extra {
		cfg += l + "\n"
	}
	cfgPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	sshd := filepath.Join(prefix, "sbin", "sshd") // absolute: sshd re-execs itself
	if out, err := exec.Command(sshd, "-t", "-f", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("sshd -t: %v\n%s\n%s", err, out, cfg)
	}
	_, log, done := startDaemon(t, "sshd", envWithout("SSH_AUTH_SOCK"), sshd, "-D", "-e", "-f", cfgPath)
	pidFile := filepath.Join(dir, "sshd.pid")
	waitFor(t, "sshd port", done, log, func() bool {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		_, err = os.Stat(pidFile)
		return err == nil
	})
	return &sshdRun{port: port, pidFile: pidFile, log: log}
}

// waitForLog waits up to 5 s for sshd's log, after the prefix before, to
// contain want.
func waitForLog(t *testing.T, s *sshdRun, before, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if strings.Contains(strings.TrimPrefix(s.log.String(), before), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd log has no %q after the refusal:\n%s", want, strings.TrimPrefix(s.log.String(), before))
		}
		time.Sleep(50 * time.Millisecond)
	}
}
