//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestAuditLoginAcrossPolicyChange (KEY-02, D-09) adds the WebAuthn RP to
// a live signer and proves the resulting login certificate from the log:
// a signer under a genesis policy without an RP refuses a login
// (no_webauthn_policy); keyroster root successor-policy writes policy v2
// with the RP and the one-way warning; root sign --prev builds successor
// bundle v2 with it, signed by the same root at the same threshold, and
// trust verify --prev checks it against the bundle in force; the signer is
// stopped, the bundle installed without pins, and the signer restarted; an
// admin-signed directory v1 is installed and a login certificate issued
// under policy v2, which real sshd accepts for role:ops. The exported log
// then verifies with audit verify (login certificates 1, directory
// installs 1, also in --json), and a later export verifies with --previous
// set to the earlier one, while the reverse is refused as a shrunk log.
func TestAuditLoginAcrossPolicyChange(t *testing.T) {
	ctx := context.Background()
	login := currentUser(t)
	keys := t.TempDir()

	// 1. A signer under a genesis policy without an RP, root R1 in its own
	// agent so it can sign the successor.
	rootAgent := startAgent(t)
	rootKey := filepath.Join(keys, "r1")
	sshKeygen(t, "-q", "-t", "ed25519", "-N", "", "-C", "r1", "-f", rootKey)
	sshAdd(t, rootAgent, rootKey)
	rootFP := fingerprint(t, rootKey+".pub")
	env := prepareSigner(t, bootstrapOpts{RootAgentSocket: rootAgent, RootFingerprint: rootFP, RootCustody: "software"})
	stop := serveStoppable(t, env)

	auth, err := webauthntest.New(webauthn.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}

	// 2. No RP in the policy in force: the login is refused.
	_, err = signerclient.Login(ctx, env.Socket, loginRequest(t, auth, ephemeralKey(t)))
	wantLoginRefused(t, err, "no_webauthn_policy")

	// 3. The successor policy carries the RP and prints the warning.
	policyV1 := filepath.Join(env.BundleDir, "policy.json")
	policyV2 := filepath.Join(keys, "policy-v2.json")
	code, out := runKeyroster(t, "root", "successor-policy", "--prev", policyV1, "--webauthn-rp-id", loginRPID, "--out", policyV2)
	if code != 0 {
		t.Fatalf("root successor-policy exited %d:\n%s", code, out)
	}
	for _, want := range []string{"WARNING: rp_id is a one-way setting", "rp_id:   (none) -> " + loginRPID, "origins: (none) -> " + loginOrigin} {
		if !strings.Contains(out, want) {
			t.Fatalf("root successor-policy output lacks %q:\n%s", want, out)
		}
	}
	v1, err := os.ReadFile(policyV1) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	v2, err := os.ReadFile(policyV2) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	pol, err := trust.ParsePolicy(v2)
	if err != nil {
		t.Fatalf("the successor policy does not parse: %v", err)
	}
	if pol.Version != 2 || pol.Prev != trust.SHA256Hex(v1) || pol.WebAuthn == nil || pol.WebAuthn.RPID != loginRPID {
		t.Fatalf("successor policy version %d, prev %s, RP %+v; want version 2, prev %s, RP %s",
			pol.Version, pol.Prev, pol.WebAuthn, trust.SHA256Hex(v1), loginRPID)
	}

	// 4. root sign --prev with the same root and threshold, then trust
	// verify --prev against the bundle in force and the root's pin.
	genesis, err := os.ReadFile(filepath.Join(env.BundleDir, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	prevSHA := trust.SHA256Hex(genesis)
	succ := filepath.Join(keys, "succ")
	sign := []string{"root", "sign", "--prev", env.BundleDir, "--prev-sha256", prevSHA,
		"--roots", filepath.Join(filepath.Dir(env.BundleDir), "roots.pub"), "--threshold", "1",
		"--policy", policyV2, "--out-dir", succ, "--agent-key", rootFP}
	if code, out := keyrosterWithAgent(t, rootAgent, append(sign, "--confirm", "00000000")...); code != 1 || !strings.Contains(out, "nothing was signed") {
		t.Fatalf("root sign --prev with a wrong confirmation exited %d:\n%s", code, out)
	}
	succBundle, err := os.ReadFile(filepath.Join(succ, "bundle.json")) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	if code, out := keyrosterWithAgent(t, rootAgent, append(sign, "--confirm", trust.SHA256Hex(succBundle)[:8])...); code != 0 {
		t.Fatalf("root sign --prev exited %d:\n%s", code, out)
	}
	if code, out := runKeyroster(t, "trust", "verify", "--prev", env.BundleDir, "--prev-sha256", prevSHA, "--pin", rootFP, "--threshold", "1",
		"--bundle", filepath.Join(succ, "bundle.json"), "--policy", filepath.Join(succ, "policy.json")); code != 0 ||
		!strings.Contains(out, "OK: successor of trust bundle v1") {
		t.Fatalf("trust verify --prev exited %d:\n%s", code, out)
	}

	// 5. Stop, install without pins, restart.
	stop()
	if code, out := env.signerCmd(t, "install-bundle", "--state-dir", env.StateDir,
		"--bundle", filepath.Join(succ, "bundle.json"), "--policy", filepath.Join(succ, "policy.json")); code != 0 ||
		!strings.Contains(out, "installed bundle version 2") {
		t.Fatalf("install-bundle of the successor exited %d:\n%s", code, out)
	}
	serveStoppable(t, env)

	// 6. Directory v1 (admin-signed), then a login certificate that real
	// sshd accepts for role:ops.
	cred := auth.Credential()
	dir := &directory.Directory{
		Version: 1,
		Prev:    trust.GenesisPrev,
		Users: []directory.User{{Name: "alice", Status: directory.StatusActive, Credentials: []directory.Credential{{
			ID:   base64.RawURLEncoding.EncodeToString(cred.ID),
			Alg:  cred.Alg,
			SPKI: base64.StdEncoding.EncodeToString(cred.SPKI),
		}}}},
		Roles: []directory.Role{{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600, Users: []string{"alice"}}},
	}
	dir.Sort()
	doc, err := dir.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signerclient.InstallDirectory(ctx, env.Socket, &wire.InstallDirectoryRequest{Directory: doc, Sigs: adminSign(t, env, directory.Namespace, doc)}); err != nil {
		t.Fatalf("install directory under policy v2: %v", err)
	}
	ephPub, ephPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(ephPub)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := signerclient.Login(ctx, env.Socket, loginRequest(t, auth, sshPub))
	if err != nil {
		t.Fatalf("login under policy v2: %v", err)
	}
	if c := parseCert(t, resp.Cert); !strings.Contains(c.KeyId, "/pol=2/dir=1/roles=ops/") {
		t.Fatalf("key ID %q, want pol=2, dir=1 and roles=ops", c.KeyId)
	}
	keyFile, certFile := writeLoginKey(t, ephPriv, resp.Cert)
	port := startSSHD(t, sshdOptions{UserCAPub: env.UserCAPub, Principals: map[string][]string{login: {"role:ops"}}})
	if code, out := sshLogin(t, loginOptions{Port: port, Key: keyFile, Cert: certFile, User: login, Command: "true"}); code != 0 {
		t.Fatalf("ssh login with the certificate issued under policy v2 exited %d:\n%s", code, out)
	}

	// 7. The exported log proves the login certificate.
	first := env.exportLog(t)
	code, out = auditVerifyPins(t, env.RootFingerprints, first)
	if code != 0 {
		t.Fatalf("audit verify exited %d:\n%s", code, out)
	}
	for _, want := range []string{"OK: ", "login certificates 1, directory installs 1", "trust bundle v2, policy v2"} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit verify output lacks %q:\n%s", want, out)
		}
	}
	code, out = auditVerifyPins(t, env.RootFingerprints, first, "--json")
	if code != 0 || !strings.Contains(out, `"login_issue":1`) || !strings.Contains(out, `"directory_install":1`) {
		t.Fatalf("audit verify --json exited %d, want kinds.login_issue 1 and kinds.directory_install 1:\n%s", code, out)
	}

	// A later export, after a second login, extends the first: it verifies
	// with --previous set to the first, and the first does not verify with
	// --previous set to the later one (a shrunk log, as after a restore).
	if _, err := signerclient.Login(ctx, env.Socket, loginRequest(t, auth, ephemeralKey(t))); err != nil {
		t.Fatalf("second login: %v", err)
	}
	second := filepath.Join(t.TempDir(), "log2.jsonl")
	if code, b := env.signerCmd(t, "export-log", "--state-dir", env.StateDir, "--out", second); code != 0 {
		t.Fatalf("second export-log exited %d:\n%s", code, b)
	}
	if code, out := auditVerifyPins(t, env.RootFingerprints, second, "--previous", first); code != 0 || !strings.Contains(out, "login certificates 2, directory installs 1") {
		t.Fatalf("audit verify --previous <first export> of the later export exited %d:\n%s", code, out)
	}
	if code, out := auditVerifyPins(t, env.RootFingerprints, first, "--previous", second); code == 0 || !strings.Contains(out, "log shrank") {
		t.Fatalf("audit verify --previous <later export> of the earlier export exited %d, want the shrunk-log refusal:\n%s", code, out)
	}
}
