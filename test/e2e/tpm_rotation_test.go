//go:build e2e_tpm

package e2e

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// tpmRotPrepareFile is the prepare file that ca-rotate prepare writes
// (cmd/keyroster-signer/rotate.go), read strictly (03-12f).
type tpmRotPrepareFile struct {
	Role       string `json:"role"`
	Generation uint32 `json:"generation"`
	Key        string `json:"key"`
	Alg        string `json:"alg"`
	Custody    string `json:"custody"`
}

// tpmRotIssueAndLogin is tpmIssueAndLogin for a given user CA: it issues
// a user certificate through env, checks that the CA key in caPub (with
// fingerprint caFP) signed it, and logs in with it on a fresh sshd that
// trusts caPub only (03-12f).
func tpmRotIssueAndLogin(t *testing.T, env *signerEnv, caPub, caFP string) {
	t.Helper()
	login := currentUser(t)
	userKey := filepath.Join(t.TempDir(), "id_ed25519")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "user", "-f", userKey)
	env.issue(t, "--pubkey", userKey+".pub", "--principal", login, "--subject", "u:"+login, "--ttl", "10m")
	certFile := userKey + "-cert.pub"
	if m := tpmSigningCA.FindStringSubmatch(sshKeygen(t, "-L", "-f", certFile)); m == nil || m[1] != caFP {
		t.Fatalf("certificate not signed by the TPM user CA %s (ssh-keygen -L match %q)", caFP, m)
	}
	port := startSSHD(t, sshdOptions{UserCAPub: caPub, Principals: map[string][]string{login: {login}}})
	if code, out := sshLogin(t, loginOptions{Port: port, Key: userKey, Cert: certFile, User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with the certificate of %s exited %d:\n%s", caFP, code, out)
	}
}

// tpmRotCeremony runs root sign --prev prevDir (its bundle.json's SHA-256
// is the pin) with the genesis root in env's root agent and the CA flags
// ca, into out: first with a wrong confirmation, which signs nothing, then
// with the real hash prefix. Then trust verify --prev checks the signed
// successor against the pin. It returns the display of the first run and
// the output of trust verify, so each display line appears twice (03-12f;
// the model is caRotCeremony, which this build does not compile).
func tpmRotCeremony(t *testing.T, env *signerEnv, prevDir, out string, ca ...string) string {
	t.Helper()
	prev, err := os.ReadFile(filepath.Join(prevDir, "bundle.json")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	prevSHA := trust.SHA256Hex(prev)
	rootFP := env.RootFingerprints[0]
	rootsPub := filepath.Join(filepath.Dir(env.BundleDir), "roots.pub")
	sign := append([]string{"root", "sign", "--prev", prevDir, "--prev-sha256", prevSHA, "--roots", rootsPub, "--threshold", "1",
		"--policy", filepath.Join(prevDir, "policy.json"), "--out-dir", out, "--agent-key", rootFP}, ca...)
	code, display := keyrosterWithAgent(t, env.RootAgent, append(sign, "--confirm", "00000000")...)
	if code != 1 || !strings.Contains(display, "nothing was signed") {
		t.Fatalf("root sign --prev %v with a wrong confirmation exited %d:\n%s", ca, code, display)
	}
	succ, err := os.ReadFile(filepath.Join(out, "bundle.json")) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	if code, msg := keyrosterWithAgent(t, env.RootAgent, append(sign, "--confirm", trust.SHA256Hex(succ)[:8])...); code != 0 {
		t.Fatalf("root sign --prev %v exited %d:\n%s", ca, code, msg)
	}
	code, verified := keyrosterWithAgent(t, "", "trust", "verify", "--prev", prevDir, "--prev-sha256", prevSHA, "--pin", rootFP, "--threshold", "1",
		"--bundle", filepath.Join(out, "bundle.json"), "--policy", filepath.Join(out, "policy.json"))
	if code != 0 || !strings.Contains(verified, "OK: successor of trust bundle") {
		t.Fatalf("trust verify --prev of %s exited %d:\n%s", out, code, verified)
	}
	return display + verified
}

// tpmRotInstall installs the bundle in dir on env's stopped signer, with
// extra install-bundle arguments, and returns the output.
func tpmRotInstall(t *testing.T, env *signerEnv, dir, version string, extra ...string) string {
	t.Helper()
	args := append([]string{"install-bundle", "--state-dir", env.StateDir,
		"--bundle", filepath.Join(dir, "bundle.json"), "--policy", filepath.Join(dir, "policy.json")}, extra...)
	code, out := env.signerCmd(t, args...)
	if code != 0 || !strings.Contains(out, "installed bundle version "+version) {
		t.Fatalf("install-bundle of %s exited %d, want version %s:\n%s", dir, code, version, out)
	}
	return out
}

// tpmRotCount fails the test unless out holds want exactly n times.
func tpmRotCount(t *testing.T, out, want string, n int) {
	t.Helper()
	if got := strings.Count(out, want); got != n {
		t.Fatalf("the output holds %q %d times, want %d:\n%s", want, got, n, out)
	}
}

// tpmRotKeyFiles is the sorted list of names in env's tpm key directory.
func tpmRotKeyFiles(t *testing.T, env *signerEnv) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(env.StateDir, "tpm"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

// TestTPMCARotation (03-12f, D-14, KEY-08) rotates the user CA of a TPM
// signer (swtpm, custody vtpm) end to end with the real binaries, one
// TPM connection at a time: ca-rotate prepare creates generation 2 inside
// the TPM, ceremony 1 makes it next, the switch makes it active, serve
// refuses while generation 1's key and auth files are there, retire-key
// removes both, and the signer then issues with generation 2 only.
func TestTPMCARotation(t *testing.T) {
	env := prepareSigner(t, bootstrapOpts{Backend: "tpm", BackendOpts: tpmOpts(t)})
	fp1 := fingerprint(t, env.UserCAPub)

	// 1. Generation 1 signs, and sshd trusts it.
	s := tpmServe(t, env)
	tpmRotIssueAndLogin(t, env, env.UserCAPub, fp1)
	s.stop(t)

	// 2. Prepare with serve stopped (swtpm serves one connection, and the
	// state lock is free): the TPM creates generation 2's key, stored in
	// two files of mode 0600.
	keys := t.TempDir()
	prepared := filepath.Join(keys, "user-g2.json")
	code, out := env.signerCmd(t, "ca-rotate", "prepare", "--state-dir", env.StateDir, "--role", "user", "--out", prepared)
	if code != 0 {
		t.Fatalf("ca-rotate prepare exited %d:\n%s", code, out)
	}
	data, err := os.ReadFile(prepared) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	var pf tpmRotPrepareFile
	if err := trust.DecodeStrict(data, &pf); err != nil {
		t.Fatalf("prepare file %q: %v", data, err)
	}
	pub2, err := trust.ParseKey(pf.Key)
	if err != nil {
		t.Fatalf("prepare file key %q: %v", pf.Key, err)
	}
	fp2 := ssh.FingerprintSHA256(pub2)
	if pf.Role != "user" || pf.Generation != 2 || pf.Alg != ssh.KeyAlgoECDSA256 || pf.Custody != "vtpm" || fp2 == fp1 {
		t.Fatalf("prepare file %+v (fingerprint %s), want user generation 2 %s vtpm and a key other than %s", pf, fp2, ssh.KeyAlgoECDSA256, fp1)
	}
	if first, _, _ := strings.Cut(out, "\n"); first != "role user generation 2 "+fp2+" ecdsa-sha2-nistp256 vtpm" || strings.Contains(out, "location:") {
		t.Fatalf("ca-rotate prepare printed:\n%s", out)
	}
	for _, name := range []string{"user-g2.tpmkey", "user-g2.auth"} {
		fi, err := os.Lstat(filepath.Join(env.StateDir, "tpm", name))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
			t.Fatalf("tpm/%s: %v, %v; want a regular 0600 file", name, fi, err)
		}
	}
	userG2Pub := filepath.Join(keys, "user-g2.pub")
	if err := os.WriteFile(userG2Pub, []byte(trust.FormatKey(pub2)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := fingerprint(t, userG2Pub); got != fp2 {
		t.Fatalf("%s holds %s, want %s", userG2Pub, got, fp2)
	}

	// 3. Ceremony 1: generation 2 becomes next; install it.
	next := filepath.Join(keys, "next")
	out = tpmRotCeremony(t, env, env.BundleDir, next, "--ca-next", "user="+prepared, "--ca-next-fingerprint", "user="+fp2)
	tpmRotCount(t, out, "CA user gen 2 "+fp2+": none -> next\n", 2)
	tpmRotInstall(t, env, next, "2")

	// 4. Ceremony 2, the switch, installed with the export taken after
	// ceremony 1's install as --previous.
	export := env.exportLog(t)
	sw := filepath.Join(keys, "switch")
	out = tpmRotCeremony(t, env, next, sw, "--ca-switch", "user", "--drain-allowance", "60s")
	tpmRotCount(t, out, "CA user gen 1 "+fp1+": active -> draining, trusted until ", 2)
	tpmRotCount(t, out, "CA user gen 2 "+fp2+": next -> active\n", 2)
	if out := tpmRotInstall(t, env, sw, "3", "--previous", export); !strings.Contains(out, "drain user generation 1 until ") {
		t.Fatalf("install-bundle --previous of the switch does not name the drain:\n%s", out)
	}

	// 5. serve refuses while generation 1's files are there, and opens no
	// socket; doctor fails the check.
	if isSocket(env.Socket) {
		t.Fatalf("%s is a socket before serve starts", env.Socket)
	}
	code, out = env.signerCmd(t, "serve", "--state-dir", env.StateDir, "--socket", env.Socket, "--allow-uid", strconv.Itoa(os.Getuid()))
	if code == 0 || !strings.Contains(out, "draining_key_still_usable") || !strings.Contains(out, "generation 1 of the user CA ("+fp1+")") {
		t.Fatalf("serve with generation 1's files present exited %d, want a refusal naming draining_key_still_usable and %s:\n%s", code, fp1, out)
	}
	if isSocket(env.Socket) {
		t.Fatal("serve created its socket despite the refusal")
	}
	if _, out := env.signerCmd(t, "doctor", "--state-dir", env.StateDir); !strings.Contains(out, "FAIL draining_key_still_usable: user generation 1 "+fp1+" is still held by the backend") {
		t.Fatalf("doctor while generation 1's files are there:\n%s", out)
	}

	// 6. retire-key removes generation 1's two files and nothing else; a
	// second run finds nothing to remove; doctor is silent on draining keys.
	code, out = env.signerCmd(t, "ca-rotate", "retire-key", "--state-dir", env.StateDir, "--role", "user")
	if code != 0 || !strings.Contains(out, "role user generation 1 "+fp1+": removed\n") || !strings.Contains(out, "retire-key: no draining key of role user is held\n") {
		t.Fatalf("retire-key exited %d:\n%s", code, out)
	}
	if got, want := tpmRotKeyFiles(t, env), "host.auth host.tpmkey log.auth log.tpmkey machine.auth machine.tpmkey ops.auth ops.tpmkey user-g2.auth user-g2.tpmkey"; got != want {
		t.Fatalf("the TPM key files after retire-key: %s, want %s", got, want)
	}
	code, out = env.signerCmd(t, "ca-rotate", "retire-key", "--state-dir", env.StateDir, "--role", "user")
	if code != 0 || !strings.Contains(out, "role user generation 1 "+fp1+": not held\n") {
		t.Fatalf("the second retire-key exited %d:\n%s", code, out)
	}
	if _, out := env.signerCmd(t, "doctor", "--state-dir", env.StateDir); strings.Contains(out, "draining_key_") {
		t.Fatalf("doctor after retire-key:\n%s", out)
	}

	// 7. Generation 2 signs, and an sshd that trusts only its key accepts
	// the certificate.
	s = tpmServe(t, env)
	tpmRotIssueAndLogin(t, env, userG2Pub, fp2)
	s.stop(t)

	// 8. ca_init, bundle_install of v1, the first start's krl_publish, the
	// generation-1 issuance, ca_generation, bundle_install of v2 and of v3,
	// and the generation-2 issuance (a later start under an hour publishes
	// no KRL, TestTPMRestartPersistence).
	tpmAuditVerify(t, env, 8, 2)
	t.Log("tpm rotation: generation 2 signs and generation 1's key and auth files are gone")
}
