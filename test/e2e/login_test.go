//go:build e2e

package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// loginProc is a running keyroster login: its process, its stdout and
// stderr as they are written, and its exit.
type loginProc struct {
	cmd    *exec.Cmd
	stdout *syncBuffer
	stderr *syncBuffer
	done   chan struct{}
	code   int
}

// startLogin starts keyroster login for c with SSH_AUTH_SOCK agentSock and
// the extra arguments; the process is killed at cleanup if still running.
func startLogin(t *testing.T, c *cliEnv, agentSock string, args ...string) *loginProc {
	t.Helper()
	cmd := exec.Command(keyrosterBin, append([]string{"login", "--no-browser"}, args...)...) //nolint:gosec // G204: the binary under test
	cmd.Env = append(envWithout("SSH_AUTH_SOCK", "XDG_CONFIG_HOME", "HOME"), "XDG_CONFIG_HOME="+c.configHome, "HOME="+c.home, "SSH_AUTH_SOCK="+agentSock)
	p := &loginProc{cmd: cmd, stdout: &syncBuffer{}, stderr: &syncBuffer{}, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = p.stdout, p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		err := cmd.Wait()
		var ee *exec.ExitError
		switch {
		case err == nil:
			p.code = 0
		case errors.As(err, &ee):
			p.code = ee.ExitCode()
		default:
			p.code = -1
		}
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

// line waits up to 30 s for a stderr line starting with prefix and
// returns the rest of it.
func (p *loginProc) line(t *testing.T, prefix string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		for _, l := range strings.Split(p.stderr.String(), "\n") {
			if rest, ok := strings.CutPrefix(l, prefix); ok {
				return rest
			}
		}
		select {
		case <-p.done:
			t.Fatalf("keyroster login exited %d before printing %q:\nstdout:\n%s\nstderr:\n%s", p.code, prefix, p.stdout.String(), p.stderr.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("keyroster login printed no %q within 30 s:\nstderr:\n%s", prefix, p.stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// wait waits up to 60 s for the process to exit and returns its exit code.
func (p *loginProc) wait(t *testing.T) int {
	t.Helper()
	select {
	case <-p.done:
		return p.code
	case <-time.After(60 * time.Second):
		t.Fatalf("keyroster login did not exit within 60 s:\nstderr:\n%s", p.stderr.String())
		return -1
	}
}

// loginStarted is what keyroster login printed before the approval.
type loginStarted struct {
	fingerprint string
	approvalURL string
}

// started reads the fingerprint and approval URL lines of p.
func (p *loginProc) started(t *testing.T) loginStarted {
	t.Helper()
	return loginStarted{
		fingerprint: p.line(t, "Key fingerprint: "),
		approvalURL: p.line(t, "Approve this login in your browser: "),
	}
}

var (
	dataAssertionRE = regexp.MustCompile(`data-assertion="([^"]*)"`)
	dataOptionsRE   = regexp.MustCompile(`data-options="([^"]*)"`)
)

// approvalPage GETs the approval page at approvalURL as a browser would
// and requires it to show fingerprint verbatim. It returns the assertion
// route and the decoded WebAuthn options of the page.
func approvalPage(t *testing.T, env *serverEnv, approvalURL, fingerprint string) (string, approvalOptions) {
	t.Helper()
	path, ok := strings.CutPrefix(approvalURL, env.URL)
	if !ok || !strings.HasPrefix(path, "/login/") {
		t.Fatalf("approval URL %q is not a /login/ page under %s", approvalURL, env.URL)
	}
	page := newWebClient(t, env).do(t, http.MethodGet, path, nil, nil)
	if page.code != http.StatusOK {
		t.Fatalf("GET %s = %d:\n%s\nserver log:\n%s", path, page.code, page.body, env.Stderr.String())
	}
	// html/template escapes "+" in a fingerprint; compare the text.
	if !strings.Contains(html.UnescapeString(page.body), fingerprint) {
		t.Fatalf("the approval page does not show the CLI's fingerprint %s:\n%s", fingerprint, page.body)
	}
	am, om := dataAssertionRE.FindStringSubmatch(page.body), dataOptionsRE.FindStringSubmatch(page.body)
	if am == nil || om == nil {
		t.Fatalf("the approval page has no data-assertion or data-options:\n%s", page.body)
	}
	var opts approvalOptions
	if err := json.Unmarshal([]byte(html.UnescapeString(om[1])), &opts); err != nil {
		t.Fatalf("data-options: %v", err)
	}
	return html.UnescapeString(am[1]), opts
}

// approvalOptions are the WebAuthn request options of an approval page.
type approvalOptions struct {
	Challenge        string `json:"challenge"`
	AllowCredentials []struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"allowCredentials"`
	RPID             string `json:"rpId"`
	UserVerification string `json:"userVerification"`
}

// postAssertion makes auth's assertion over the page's challenge, as the
// policy origin, and posts it to the page's assertion route. It returns
// the answer.
func postAssertion(t *testing.T, env *serverEnv, auth *webauthntest.Authenticator, assertionPath string, opts approvalOptions) *response {
	t.Helper()
	raw, err := base64.RawURLEncoding.Strict().DecodeString(opts.Challenge)
	if err != nil || len(raw) != 32 {
		t.Fatalf("approval challenge %q is not 32 bytes of base64url: %v", opts.Challenge, err)
	}
	a := auth.Assert(serverRPID, env.URL, [32]byte(raw))
	body, err := json.Marshal(map[string]string{
		"credential_id":      base64.RawURLEncoding.EncodeToString(a.CredentialID),
		"authenticator_data": base64.RawURLEncoding.EncodeToString(a.AuthenticatorData),
		"client_data_json":   base64.RawURLEncoding.EncodeToString(a.ClientDataJSON),
		"signature":          base64.RawURLEncoding.EncodeToString(a.Signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return newWebClient(t, env).do(t, http.MethodPost, assertionPath, body, nil)
}

// approve runs the browser's part of a login: the approval page (which
// must show the CLI's fingerprint), the passkey assertion and its answer,
// whose loopback redirect it returns without following it.
func approve(t *testing.T, env *serverEnv, auth *webauthntest.Authenticator, s loginStarted) string {
	t.Helper()
	assertionPath, opts := approvalPage(t, env, s.approvalURL, s.fingerprint)
	r := postAssertion(t, env, auth, assertionPath, opts)
	if r.code != http.StatusOK {
		t.Fatalf("POST %s = %d %s\nserver log:\n%s", assertionPath, r.code, r.body, env.Stderr.String())
	}
	var ans struct {
		Redirect string `json:"redirect"`
	}
	if err := json.Unmarshal([]byte(r.body), &ans); err != nil || !strings.HasPrefix(ans.Redirect, "http://127.0.0.1:") {
		t.Fatalf("assertion answer %q has no loopback redirect: %v", r.body, err)
	}
	return ans.Redirect
}

// followLoopback GETs the loopback redirect as a browser's top-level
// navigation would, and requires keyroster login's answer page.
func followLoopback(t *testing.T, redirect string) {
	t.Helper()
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := c.Get(redirect)
	if err != nil {
		t.Fatalf("GET loopback: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(b), "approved") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("loopback answered %d (Cache-Control %q):\n%s", resp.StatusCode, resp.Header.Get("Cache-Control"), b)
	}
}

// loginOK runs one complete login for alice into agentSock and returns
// what the CLI printed: the fingerprint, and its stdout.
func loginOK(t *testing.T, env *serverEnv, alice *cliEnv, auth *webauthntest.Authenticator, agentSock string, args ...string) (loginStarted, string) {
	t.Helper()
	p := startLogin(t, alice, agentSock, args...)
	s := p.started(t)
	followLoopback(t, approve(t, env, auth, s))
	if code := p.wait(t); code != 0 {
		t.Fatalf("keyroster login exited %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, p.stdout.String(), p.stderr.String(), env.Stderr.String())
	}
	return s, p.stdout.String()
}

// stdoutField returns the value of the "name: " line of a login's stdout.
func stdoutField(t *testing.T, out, name string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, name+": "); ok {
			return v
		}
	}
	t.Fatalf("keyroster login stdout has no %q line:\n%s", name, out)
	return ""
}

// agentList runs ssh-add -l against the agent at sock and returns its
// output ("" for an empty agent).
func agentList(t *testing.T, sock string) string {
	t.Helper()
	cmd := exec.Command(filepath.Join(opensshPrefix(t), "bin", "ssh-add"), "-l")
	cmd.Env = append(envWithout("SSH_AUTH_SOCK"), "SSH_AUTH_SOCK="+sock)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.ExitCode() == 1 {
		return "" // "The agent has no identities."
	}
	if err != nil {
		t.Fatalf("ssh-add -l: %v\n%s", err, out)
	}
	return string(out)
}

// listingLine returns the ssh-add -l line holding both fingerprint and
// keyID, or "".
func listingLine(listing, fingerprint, keyID string) string {
	for _, l := range strings.Split(listing, "\n") {
		if strings.Contains(l, fingerprint) && strings.Contains(l, keyID) {
			return l
		}
	}
	return ""
}

// sshViaAgent logs in to sshd at port as user with only the agent at sock
// (-o IdentityAgent), no key file, and returns the exit code and output.
func sshViaAgent(t *testing.T, sock string, port int, user string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(opensshPrefix(t), "bin", "ssh"),
		"-F", "none", "-o", "IdentityAgent="+sock, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-p", strconv.Itoa(port), user+"@127.0.0.1", "true")
	cmd.Env = envWithout("SSH_AUTH_SOCK")
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("ssh: %v\n%s", err, out)
	}
	return 0, string(out)
}

// loginFixture is the shared setup of TestLoginEndToEnd: a signer and
// server, the admin CLI, alice enrolled and approved with role ops (1 h)
// granted and mapped for the sshd account in host group web, and alice's
// own CLI environment pinned with keyroster init.
type loginFixture struct {
	env      *serverEnv
	admin    *cliEnv
	alice    *cliEnv
	auth     *webauthntest.Authenticator
	account  string
	caFile   string
	sshdPort int
}

// kr runs one admin CLI command and requires exit 0; a command the
// server's per-client admin limiter refused runs again after it refills
// (nothing was done: the limiter refuses before any handler runs).
func (f *loginFixture) kr(t *testing.T, args ...string) string {
	t.Helper()
	code, out, errOut := f.env.keyroster(t, f.admin, "", args...)
	for try := 0; try < 5 && code != 0 && strings.Contains(errOut, "the server is rate-limiting requests from this address"); try++ {
		time.Sleep(2 * time.Second)
		code, out, errOut = f.env.keyroster(t, f.admin, "", args...)
	}
	if code != 0 {
		t.Fatalf("keyroster %s: exit %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", strings.Join(args, " "), code, out, errOut, f.env.Stderr.String())
	}
	return out
}

func newLoginFixture(t *testing.T) *loginFixture {
	t.Helper()
	f := &loginFixture{account: currentUser(t)}
	if !directory.ValidAccountName(f.account) {
		t.Fatalf("the test user %q is not a valid keyroster account name", f.account)
	}
	f.env = startServerEnv(t, serverOpts{})
	f.admin = adminCLI(t, f.env, f.env.Signer.AdminFingerprint)
	var fp string
	f.auth, fp = enroll(t, f.env, f.admin, "alice", webauthn.AlgES256)
	f.kr(t, "user", "approve", "alice", "--fingerprint", fp, "--yes")
	f.kr(t, "role", "add", "ops", "--max-ttl", "1h", "--yes")
	f.kr(t, "role", "grant", "ops", "--user", "alice", "--yes")
	f.kr(t, "host-group", "add", "web", "--yes")
	f.kr(t, "host-group", "map", "web", f.account, "ops", "--yes")

	f.caFile = filepath.Join(t.TempDir(), "keyroster_user_ca.pub")
	if err := os.WriteFile(f.caFile, []byte(f.kr(t, "host", "ca-key")), 0o644); err != nil { //nolint:gosec // test fixture: a public key
		t.Fatal(err)
	}
	lines := principalsLines(t, f.kr(t, "host", "principals", "web", f.account))
	f.sshdPort = startSSHD(t, sshdOptions{UserCAPub: f.caFile, Principals: map[string][]string{f.account: lines}})

	f.alice = newCLIEnv(t)
	if code, out, errOut := f.alice.run(t, f.env.initArgs()...); code != 0 {
		t.Fatalf("alice's keyroster init exited %d:\n%s\n%s", code, out, errOut)
	}
	return f
}

// TestLoginEndToEnd (AUTH-03, AUTH-04, success criteria 2 and 3, D-12 to
// D-15): keyroster login, run as a process, prints its key fingerprint
// and the approval URL; the approval page (fetched as a browser would)
// shows that exact fingerprint; a soft authenticator stands in for the
// passkey and posts the assertion; the test follows the loopback redirect
// as the browser's top-level navigation would; the CLI redeems, verifies
// the certificate and adds it to a real ssh-agent with a lifetime; a real
// sshd fed keyroster's CA line and rendered principals file accepts a
// login through that agent; and the exported log verifies with one login
// certificate. The page's own script (app.js) is not run: no browser runs
// in this test.
func TestLoginEndToEnd(t *testing.T) {
	f := newLoginFixture(t)
	sock := startAgent(t)

	s, out := loginOK(t, f.env, f.alice, f.auth, sock)
	keyID := stdoutField(t, out, "Key ID")
	if !strings.HasPrefix(keyID, "kr2/ca=user/sub=alice/") || !strings.Contains(keyID, "/roles=ops/") {
		t.Fatalf("Key ID %q is not a kr2 user key ID for alice with role ops", keyID)
	}
	if got := stdoutField(t, out, "Logged in as alice"); got != "principals role:ops" {
		t.Fatalf("login stdout names %q, want the principals role:ops:\n%s", got, out)
	}

	listing := agentList(t, sock)
	line := listingLine(listing, s.fingerprint, keyID)
	if line == "" || !strings.Contains(line, "ED25519-CERT") {
		t.Fatalf("ssh-add -l has no certificate line with %s and %s:\n%s", s.fingerprint, keyID, listing)
	}
	t.Logf("ssh-add -l: %s", line)

	if code, sshOut := sshViaAgent(t, sock, f.sshdPort, f.account); code != 0 {
		t.Fatalf("ssh through the agent exited %d, want 0:\n%s", code, sshOut)
	}
	t.Logf("sshd accepted the login through the agent")

	// 8. The export verifies and holds exactly this one login certificate;
	// its decoded line names the serial and key ID the CLI printed and the
	// fingerprint of the key the CLI showed (02-14-F5/F13).
	export := f.env.Signer.exportLog(t)
	if code, vout := auditVerify(t, f.env.Signer, export); code != 0 {
		t.Fatalf("audit verify exited %d:\n%s", code, vout)
	}
	issues := loginIssueLines(t, export)
	if len(issues) != 1 {
		t.Fatalf("the exported log has %d login certificates, want 1", len(issues))
	}
	d := issues[0]
	serial := stdoutField(t, out, "Serial")
	if fmtNumber(d["serial"]) != serial || d["key_id"] != keyID || d["key_fingerprint"] != s.fingerprint {
		t.Fatalf("decoded login_issue %v does not match the CLI's Serial %s, Key ID %s and fingerprint %s", d, serial, keyID, s.fingerprint)
	}
	if !strings.HasSuffix(keyID, "/ser="+serial) {
		t.Fatalf("Key ID %q does not end in the serial %s", keyID, serial)
	}

	t.Run("login_lifetime_expiry", func(t *testing.T) { testLoginLifetimeExpiry(t, f) })
	t.Run("two_concurrent_logins", func(t *testing.T) { testTwoConcurrentLogins(t, f) })
	t.Run("unapproved_login_mints_nothing", func(t *testing.T) { testUnapprovedLogin(t, f) })
	// Last: it revokes role ops from alice.
	t.Run("signer_refusal_after_approval", func(t *testing.T) { testSignerRefusalAfterApproval(t, f) })
}

// fmtNumber formats a JSON number decoded into an any as an integer.
func fmtNumber(v any) string {
	if n, ok := v.(json.Number); ok {
		return n.String()
	}
	return ""
}

// loginIssueLines returns the decoded field of every login_issue line of
// the export file, numbers kept exact.
func loginIssueLines(t *testing.T, export string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(export) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var line struct {
			Decoded json.RawMessage `json:"decoded"`
		}
		if err := json.Unmarshal([]byte(l), &line); err != nil {
			t.Fatal(err)
		}
		if len(line.Decoded) == 0 {
			continue
		}
		dec := json.NewDecoder(strings.NewReader(string(line.Decoded)))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		if m["kind"] == "login_issue" {
			out = append(out, m)
		}
	}
	return out
}

// testLoginLifetimeExpiry (success criterion 2; 02-14-F6): a default-TTL
// login (1 h, the ops cap) and a --ttl 2m login go into one agent; both
// are listed, each with the CLI's fingerprint and key ID on one line;
// after the 2 m certificate's expiry plus 5 s the agent lists neither its
// fingerprint nor its key ID, and still lists the default-TTL entry.
func testLoginLifetimeExpiry(t *testing.T, f *loginFixture) {
	sock := startAgent(t)
	long, longOut := loginOK(t, f.env, f.alice, f.auth, sock)
	short, shortOut := loginOK(t, f.env, f.alice, f.auth, sock, "--ttl", "2m")
	longID, shortID := stdoutField(t, longOut, "Key ID"), stdoutField(t, shortOut, "Key ID")
	listing := agentList(t, sock)
	for _, e := range []struct{ fp, id string }{{long.fingerprint, longID}, {short.fingerprint, shortID}} {
		if listingLine(listing, e.fp, e.id) == "" {
			t.Fatalf("before expiry, ssh-add -l has no line with %s and %s:\n%s", e.fp, e.id, listing)
		}
	}
	var validBefore int64
	for _, d := range loginIssueLines(t, f.env.Signer.exportLog(t)) {
		if d["key_id"] == shortID {
			n, err := d["valid_before"].(json.Number).Int64()
			if err != nil {
				t.Fatal(err)
			}
			validBefore = n
		}
	}
	if validBefore == 0 {
		t.Fatalf("the export has no login_issue with key ID %s", shortID)
	}
	wait := time.Until(time.Unix(validBefore, 0)) + 5*time.Second
	t.Logf("waiting %s for the 2 m certificate to expire", wait.Round(time.Second))
	time.Sleep(wait)
	listing = agentList(t, sock)
	if strings.Contains(listing, short.fingerprint) || strings.Contains(listing, shortID) {
		t.Fatalf("after expiry, ssh-add -l still lists the 2 m login:\n%s", listing)
	}
	if listingLine(listing, long.fingerprint, longID) == "" {
		t.Fatalf("after the 2 m expiry, the default-TTL login is gone too:\n%s", listing)
	}
	t.Logf("the 2 m entry left the agent; the default-TTL entry remains: %s", listingLine(listing, long.fingerprint, longID))
}

// testTwoConcurrentLogins (AUTH-04 concurrency): two keyroster login runs
// for alice get their own fingerprints, URLs and pages. Approving A gives
// A a certificate for key A; A's code on B's redeem endpoint is refused;
// approving B then gives B a certificate for key B.
func testTwoConcurrentLogins(t *testing.T, f *loginFixture) {
	sock := startAgent(t)
	pA, pB := startLogin(t, f.alice, sock), startLogin(t, f.alice, sock)
	sA, sB := pA.started(t), pB.started(t)
	if sA.fingerprint == sB.fingerprint || sA.approvalURL == sB.approvalURL {
		t.Fatalf("the two logins share a fingerprint or URL: %+v %+v", sA, sB)
	}
	approvalPage(t, f.env, sB.approvalURL, sB.fingerprint) // B's page shows B's fingerprint
	redirectA := approve(t, f.env, f.auth, sA)

	// A's code on B's login is refused (B is not approved, and the code
	// belongs to A's login only).
	u, err := url.Parse(redirectA)
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("A", 43)
	body, err := json.Marshal(map[string]string{"code": u.Query().Get("code"), "code_verifier": verifier})
	if err != nil {
		t.Fatal(err)
	}
	idB := strings.TrimPrefix(strings.TrimPrefix(sB.approvalURL, f.env.URL), "/login/")
	if r := newWebClient(t, f.env).do(t, http.MethodPost, "/api/v1/login/"+idB+"/redeem", body, nil); r.code != http.StatusBadRequest {
		t.Fatalf("A's code on B's redeem = %d %s, want 400", r.code, r.body)
	}

	followLoopback(t, redirectA)
	if code := pA.wait(t); code != 0 {
		t.Fatalf("login A exited %d:\n%s", code, pA.stderr.String())
	}
	idA := stdoutField(t, pA.stdout.String(), "Key ID")
	if listingLine(agentList(t, sock), sA.fingerprint, idA) == "" {
		t.Fatalf("the agent has no certificate for key A")
	}
	followLoopback(t, approve(t, f.env, f.auth, sB))
	if code := pB.wait(t); code != 0 {
		t.Fatalf("login B exited %d:\n%s", code, pB.stderr.String())
	}
	idB2 := stdoutField(t, pB.stdout.String(), "Key ID")
	if listingLine(agentList(t, sock), sB.fingerprint, idB2) == "" || idA == idB2 {
		t.Fatalf("the agent has no separate certificate for key B")
	}
}

// testUnapprovedLogin: a login begun and viewed but never approved (the
// CLI killed first) adds no login_issue to the log.
func testUnapprovedLogin(t *testing.T, f *loginFixture) {
	before := len(loginIssueLines(t, f.env.Signer.exportLog(t)))
	p := startLogin(t, f.alice, startAgent(t))
	s := p.started(t)
	approvalPage(t, f.env, s.approvalURL, s.fingerprint)
	_ = p.cmd.Process.Kill()
	p.wait(t)
	if after := len(loginIssueLines(t, f.env.Signer.exportLog(t))); after != before {
		t.Fatalf("an unapproved login changed the login_issue count from %d to %d", before, after)
	}
}

// testSignerRefusalAfterApproval (02-12-F22): alice approves, then an
// admin revokes role ops before the loopback hand-off; the redeem reaches
// the real signer, which refuses, so the CLI exits non-zero with the
// signer's refusal and the rerun advice, the agent gains nothing and the
// log gains no login_issue.
func testSignerRefusalAfterApproval(t *testing.T, f *loginFixture) {
	before := len(loginIssueLines(t, f.env.Signer.exportLog(t)))
	sock := startAgent(t)
	p := startLogin(t, f.alice, sock)
	s := p.started(t)
	redirect := approve(t, f.env, f.auth, s)
	f.kr(t, "role", "revoke", "ops", "--user", "alice", "--yes")
	followLoopback(t, redirect)
	if code := p.wait(t); code == 0 {
		t.Fatalf("login after the revoke exited 0:\n%s", p.stdout.String())
	}
	errOut := p.stderr.String()
	if !strings.Contains(errOut, "refused by the signer:") || !strings.Contains(errOut, "run keyroster login again") {
		t.Fatalf("stderr lacks the signer refusal and the rerun advice:\n%s", errOut)
	}
	t.Logf("CLI: %s", strings.TrimSpace(errOut[strings.LastIndex(strings.TrimSpace(errOut), "\n")+1:]))
	if l := agentList(t, sock); l != "" {
		t.Fatalf("the agent gained an entry:\n%s", l)
	}
	if after := len(loginIssueLines(t, f.env.Signer.exportLog(t))); after != before {
		t.Fatalf("a refused login changed the login_issue count from %d to %d", before, after)
	}
}
