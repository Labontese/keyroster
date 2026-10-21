//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/server/servertest"
	"github.com/Labontese/keyroster/internal/signerclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// adminCLI runs keyroster init for an admin against env with the admin
// key adminFP and returns the admin's CLI environment.
func adminCLI(t *testing.T, env *serverEnv, adminFP string) *cliEnv {
	t.Helper()
	admin := newCLIEnv(t)
	initArgs := []string{"init", "--server", env.URL, "--tls-root-file", env.CA.RootPEM, "--tls-pin", env.CA.RootPin,
		"--root-pin", env.Signer.RootFingerprints[0], "--threshold", "1", "--user", "admin", "--admin-key", adminFP}
	if code, stdout, stderr := runCLIIn(t, admin, env.Signer.AdminAgent, "", keyrosterBin, initArgs...); code != 0 {
		t.Fatalf("admin keyroster init exited %d:\n%s\n%s", code, stdout, stderr)
	}
	return admin
}

// keyroster runs the keyroster CLI as admin with the admin agent and
// working directory dir ("" for the test's).
func (e *serverEnv) keyroster(t *testing.T, admin *cliEnv, dir string, args ...string) (int, string, string) {
	t.Helper()
	return runCLIIn(t, admin, e.Signer.AdminAgent, dir, keyrosterBin, args...)
}

// enroll invites name with keyroster user add and registers a passkey of
// alg through the invite's ceremony (a soft authenticator standing in for
// the browser), and returns the authenticator and the fingerprint the
// registration page got.
func enroll(t *testing.T, env *serverEnv, admin *cliEnv, name string, alg int64) (*webauthntest.Authenticator, string) {
	t.Helper()
	code, stdout, stderr := env.keyroster(t, admin, "", "user", "add", name)
	if code != 0 {
		t.Fatalf("keyroster user add %s exited %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", name, code, stdout, stderr, env.Stderr.String())
	}
	return registerInvite(t, env, inviteToken(t, env, name, stdout), alg)
}

// inviteToken returns the invite token of name in user add's output.
func inviteToken(t *testing.T, env *serverEnv, name, stdout string) string {
	t.Helper()
	for _, l := range strings.Split(stdout, "\n") {
		if u, ok := strings.CutPrefix(l, "Invite for "+name+": "); ok {
			if tok, ok := strings.CutPrefix(u, env.URL+"/enroll/"); ok {
				return tok
			}
		}
	}
	t.Fatalf("no invite URL for %s under %s:\n%s", name, env.URL, stdout)
	return ""
}

// registerInvite runs the registration ceremony of the invite token with a
// new soft authenticator of alg.
func registerInvite(t *testing.T, env *serverEnv, token string, alg int64) (*webauthntest.Authenticator, string) {
	t.Helper()
	post := func(path string, body []byte) *response {
		t.Helper()
		r, err := env.requestBody(http.MethodPost, path, body, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			t.Fatalf("POST %s: %v\nserver log:\n%s", path, err, env.Stderr.String())
		}
		return r
	}
	begin := post("/api/v1/enroll/"+token+"/begin", nil)
	if begin.code != http.StatusOK {
		t.Fatalf("begin = %d %s\nserver log:\n%s", begin.code, begin.body, env.Stderr.String())
	}
	auth, err := webauthntest.New(alg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := servertest.Register(auth, serverRPID, env.URL, []byte(begin.body), 0)
	if err != nil {
		t.Fatal(err)
	}
	finish := post("/api/v1/enroll/"+token+"/finish", body)
	if finish.code != http.StatusOK {
		t.Fatalf("finish = %d %s\nserver log:\n%s", finish.code, finish.body, env.Stderr.String())
	}
	var got struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal([]byte(finish.body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Fingerprint != webauthn.Fingerprint(auth.Credential().SPKI) {
		t.Fatalf("the registration page got fingerprint %q, the authenticator's is %q", got.Fingerprint, webauthn.Fingerprint(auth.Credential().SPKI))
	}
	return auth, got.Fingerprint
}

// signerDirectory reads the signer's installed directory over its socket,
// the authority the server only mirrors.
func signerDirectory(t *testing.T, env *serverEnv) (*wire.GetDirectoryResponse, *directory.Directory) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := signerclient.GetDirectory(ctx, env.Signer.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Version == 0 {
		return resp, nil
	}
	d, err := directory.Parse(resp.Directory)
	if err != nil {
		t.Fatal(err)
	}
	return resp, d
}

// requireBound fails unless d binds exactly auth's credential to name,
// active.
func requireBound(t *testing.T, d *directory.Directory, name string, auth *webauthntest.Authenticator) {
	t.Helper()
	c := auth.Credential()
	for _, u := range d.Users {
		if u.Name != name {
			continue
		}
		if u.Status != directory.StatusActive || len(u.Credentials) != 1 ||
			u.Credentials[0].ID != base64.RawURLEncoding.EncodeToString(c.ID) || u.Credentials[0].SPKI != base64.StdEncoding.EncodeToString(c.SPKI) {
			t.Fatalf("user %s in the signer's directory is %+v, want active with exactly the registered credential", name, u)
		}
		return
	}
	t.Fatalf("user %s is not in the signer's directory %+v", name, d.Users)
}

// TestEnrollApproveEndToEnd: the first admin enrolls exactly like any user
// (D-04): user add, registration, user pending, then user approve with the
// fingerprint the page showed. The CLI verifies the installed base,
// shows the diff, signs version 1 with the admin's SSH key, and the server
// forwards it to the signer, which installs it: the signer's directory is
// version 1 with admin1 holding that credential, and the pending entry is
// gone. A second user (RS256) is approved at once after the first, with no
// wait: version 2 chains to version 1 (the server dropped its status cache
// after the install). The exported audit log then verifies against the
// root pin and counts both admin-signed installs.
func TestEnrollApproveEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{})
	admin := adminCLI(t, env, env.Signer.AdminFingerprint)

	auth1, fp1 := enroll(t, env, admin, "admin1", webauthn.AlgEdDSA)
	if code, out, errOut := env.keyroster(t, admin, "", "user", "pending", "admin1"); code != 0 || !strings.Contains(out, fp1) {
		t.Fatalf("user pending admin1: exit %d, want 0 with %s:\nstdout:\n%s\nstderr:\n%s", code, fp1, out, errOut)
	}

	t.Run("approve_without_fingerprint_lists_and_exits_2", func(t *testing.T) {
		code, out, errOut := env.keyroster(t, admin, "", "user", "approve", "admin1")
		if code != 2 || !strings.Contains(out, fp1) || !strings.Contains(errOut, "re-run with --fingerprint") {
			t.Fatalf("user approve admin1 without --fingerprint: exit %d, want 2 listing %s:\nstdout:\n%s\nstderr:\n%s", code, fp1, out, errOut)
		}
		if resp, _ := signerDirectory(t, env); resp.Version != 0 {
			t.Fatalf("signer directory version %d after an approve that signed nothing, want 0", resp.Version)
		}
	})

	code, out, errOut := env.keyroster(t, admin, "", "user", "approve", "admin1", "--fingerprint", fp1, "--yes")
	if code != 0 || !strings.Contains(out, "+ user admin1 (active)") || !strings.Contains(out, "Installed directory version 1") {
		t.Fatalf("user approve admin1: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	t.Logf("keyroster user approve admin1:\n%s", out)
	resp1, d1 := signerDirectory(t, env)
	if resp1.Version != 1 || !resp1.Authorized {
		t.Fatalf("signer directory version %d (authorized %v) after the first approval, want 1 and authorized", resp1.Version, resp1.Authorized)
	}
	requireBound(t, d1, "admin1", auth1)

	t.Run("pending_gone_and_listed_active", func(t *testing.T) {
		// The approval deleted admin1's pending passkey and, its invite
		// being used, the pending account: user pending takes its
		// not-pending path (exit 1, 02-08's wording).
		code, out, errOut := env.keyroster(t, admin, "", "user", "pending", "admin1")
		if code != 1 || !strings.Contains(errOut, "admin1 has no pending enrollment") {
			t.Fatalf("user pending admin1 after approval: exit %d, want 1 with \"has no pending enrollment\":\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
		}
		code, out, errOut = env.keyroster(t, admin, "", "user", "list")
		if code != 0 || !strings.Contains(out, "admin1") || !strings.Contains(out, "active") || !strings.Contains(out, fp1) {
			t.Fatalf("user list: exit %d, want admin1 active with %s:\nstdout:\n%s\nstderr:\n%s", code, fp1, out, errOut)
		}
	})

	// The second approval follows at once: no sleep, no polling.
	auth2, fp2 := enroll(t, env, admin, "alice", webauthn.AlgRS256)
	code, out, errOut = env.keyroster(t, admin, "", "user", "approve", "alice", "--fingerprint", fp2, "--yes")
	if code != 0 || !strings.Contains(out, "+ user alice (active)") || !strings.Contains(out, "Installed directory version 2") {
		t.Fatalf("user approve alice: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, out, errOut, env.Stderr.String())
	}
	resp2, d2 := signerDirectory(t, env)
	if resp2.Version != 2 || d2.Prev != trust.SHA256Hex(resp1.Directory) {
		t.Fatalf("signer directory version %d with prev %s, want 2 chained to SHA-256(v1) %s", resp2.Version, d2.Prev, trust.SHA256Hex(resp1.Directory))
	}
	requireBound(t, d2, "admin1", auth1)
	requireBound(t, d2, "alice", auth2)

	t.Run("audit_verify_counts_installs", func(t *testing.T) {
		export := env.Signer.exportLog(t)
		code, out := auditVerifyPins(t, env.Signer.RootFingerprints, export)
		if code != 0 || !strings.Contains(out, "OK: ") || !strings.Contains(out, "directory installs 2") {
			t.Fatalf("audit verify: exit %d, want 0 with \"directory installs 2\":\n%s", code, out)
		}
	})
}
