//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/serverclient"
)

// serverRPID is the WebAuthn RP ID of every e2e server. It resolves to
// loopback for the CGO_ENABLED=0 binaries without any test-only flag.
const serverRPID = "keyroster.localhost"

// wantCSP is the exact Content-Security-Policy every response carries.
const wantCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// wantHeaders are the security headers on every server response.
var wantHeaders = map[string]string{
	"Content-Security-Policy":    wantCSP,
	"Strict-Transport-Security":  "max-age=63072000",
	"Cross-Origin-Opener-Policy": "same-origin",
	"X-Content-Type-Options":     "nosniff",
	"Referrer-Policy":            "no-referrer",
	"Cache-Control":              "no-store",
}

// serverOpts configures startServerEnv.
type serverOpts struct {
	// Software runs the signer on the software backend (custody
	// software); the default is the agent backend.
	Software bool
}

// serverEnv is a running signer with a keyroster-server in front of it.
type serverEnv struct {
	Signer *signerEnv
	CA     *testCA
	Port   int
	URL    string // https://keyroster.localhost:<port>
	// Stderr is the server's output (stdout and stderr), safe to read
	// while the process writes; Cmd and Done are the process.
	Stderr *syncBuffer
	Cmd    *exec.Cmd
	Done   <-chan struct{}
}

// startServerEnv bootstraps a signer whose policy names RP serverRPID with
// origin https://keyroster.localhost:<port>, issues a test TLS leaf for
// serverRPID, starts keyroster-server on 127.0.0.1:<port> and waits until
// /healthz answers 200. The port is chosen before the signer, so the
// policy's origin matches what browsers would send.
func startServerEnv(t *testing.T, opts serverOpts) *serverEnv {
	t.Helper()
	port := freePort(t)
	bopts := bootstrapOpts{WebAuthnRPID: serverRPID, WebAuthnOrigins: []string{"https://" + serverRPID + ":" + strconv.Itoa(port)}}
	if opts.Software {
		bopts.Backend = "software"
		bopts.BackendOpts = map[string]string{"passphrase-file": passphraseFile(t)}
	}
	sg := bootstrapSigner(t, bopts)
	ca := newTestCA(t, serverRPID)
	e := &serverEnv{Signer: sg, CA: ca, Port: port, URL: "https://" + serverRPID + ":" + strconv.Itoa(port)}
	e.Cmd, e.Stderr, e.Done = startDaemon(t, "keyroster-server", envWithout("SSH_AUTH_SOCK"), serverBin, "serve",
		"--listen", "127.0.0.1:"+strconv.Itoa(port), "--tls-cert", ca.CertPath, "--tls-key", ca.KeyPath, "--signer-socket", sg.Socket)
	waitFor(t, "keyroster-server /healthz", e.Done, e.Stderr, func() bool {
		r, err := e.get("/healthz")
		return err == nil && r.code == http.StatusOK
	})
	return e
}

// passphraseFile writes a random software-backend passphrase, 0600.
func passphraseFile(t *testing.T) string {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "passphrase")
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(secret)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// response is one HTTP answer.
type response struct {
	code   int
	header http.Header
	body   string
}

// request sends method path to the server. It trusts only the test root,
// verifies serverRPID, and dials 127.0.0.1 directly, so the test process
// itself needs no name resolution.
func (e *serverEnv) request(method, path string, hdr map[string]string) (*response, error) {
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(e.Port))
	tr := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.CA.pool(), ServerName: serverRPID},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	req, err := http.NewRequest(method, e.URL+path, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return &response{code: resp.StatusCode, header: resp.Header, body: string(b)}, nil
}

func (e *serverEnv) get(path string) (*response, error) { return e.request(http.MethodGet, path, nil) }

// mustGet is get that fails the test on a transport error.
func (e *serverEnv) mustGet(t *testing.T, path string) *response {
	t.Helper()
	r, err := e.get(path)
	if err != nil {
		t.Fatalf("GET %s: %v\nserver log:\n%s", path, err, e.Stderr.String())
	}
	return r
}

// requireSecurityHeaders fails unless r carries every security header
// with its exact value.
func requireSecurityHeaders(t *testing.T, what string, r *response) {
	t.Helper()
	for k, want := range wantHeaders {
		if got := r.header.Values(k); len(got) != 1 || got[0] != want {
			t.Errorf("%s: header %s = %q, want exactly %q", what, k, got, want)
		}
	}
}

// cliEnv is a keyroster CLI environment with its own config directory.
type cliEnv struct {
	configHome string // XDG_CONFIG_HOME
	home       string
}

func newCLIEnv(t *testing.T) *cliEnv {
	t.Helper()
	return &cliEnv{configHome: t.TempDir(), home: t.TempDir()}
}

// configFile is where keyroster init saves its config on Linux.
func (c *cliEnv) configFile() string {
	return filepath.Join(c.configHome, "keyroster", "config.json")
}

// run runs the keyroster CLI with XDG_CONFIG_HOME and HOME pointing at
// c's directories and returns its exit code, stdout and stderr.
func (c *cliEnv) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, keyrosterBin, args...) //nolint:gosec // G204: the binary under test
	cmd.Env = append(envWithout("SSH_AUTH_SOCK", "XDG_CONFIG_HOME", "HOME"), "XDG_CONFIG_HOME="+c.configHome, "HOME="+c.home)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("keyroster %v: %v", args, err)
		}
		return ee.ExitCode(), stdout.String(), stderr.String()
	}
	return 0, stdout.String(), stderr.String()
}

// initArgs are the keyroster init arguments that pin e's server.
func (e *serverEnv) initArgs() []string {
	return []string{"init", "--server", e.URL, "--tls-root-file", e.CA.RootPEM, "--tls-pin", e.CA.RootPin,
		"--root-pin", e.Signer.RootFingerprints[0], "--threshold", "1", "--user", "alice"}
}

// TestServerInitEndToEnd: a software-custody signer behind
// keyroster-server; keyroster init pins the test root and the trust root,
// verifies the served bundle, prints the evaluation-only banner and saves
// a 0600 config; every page carries the exact security headers and the
// banner. Control: an agent-custody signer gives a page and init output
// without the banner.
func TestServerInitEndToEnd(t *testing.T) {
	env := startServerEnv(t, serverOpts{Software: true})

	t.Run("logs_start_load_json", func(t *testing.T) {
		// Counted on the exact string with its key: the 1 h test leaf
		// also gets the "tls certificate expires soon" warning at start.
		lines := env.loadedLines()
		if len(lines) != 1 {
			t.Fatalf("%d lines with \"msg\":\"tls certificate loaded\" after start, want 1:\n%s", len(lines), env.Stderr.String())
		}
		requireJSONLine(t, lines[0])
		if !strings.Contains(lines[0], `"trigger":"start"`) {
			t.Fatalf("the start load line lacks \"trigger\":\"start\": %s", lines[0])
		}
	})

	cli := newCLIEnv(t)
	code, stdout, stderr := cli.run(t, env.initArgs()...)
	if code != 0 {
		t.Fatalf("keyroster init exited %d:\nstdout:\n%s\nstderr:\n%s\nserver log:\n%s", code, stdout, stderr, env.Stderr.String())
	}
	t.Logf("keyroster init stdout:\n%s\nstderr:\n%s", stdout, stderr)
	if !strings.Contains(stderr, softwareBannerPhrase) || strings.Count(stderr, softwareBannerPhrase) != 1 {
		t.Fatalf("keyroster init stderr does not carry the banner exactly once:\n%s", stderr)
	}
	if !strings.Contains(stderr, custodytext.SoftwareCABanner(roleNames)) {
		t.Fatalf("keyroster init stderr lacks the banner naming all five keys:\n%s", stderr)
	}
	if !strings.Contains(stdout, "trust bundle version 1") || !strings.Contains(stdout, env.Signer.RootFingerprints[0]) {
		t.Fatalf("keyroster init did not report the verified bundle and root:\n%s", stdout)
	}
	fi, err := os.Stat(cli.configFile())
	if err != nil {
		t.Fatalf("config.json: %v", err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("config.json mode %v, want 0600", fi.Mode().Perm())
	}
	var raw map[string]any
	data := mustRead(t, cli.configFile())
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("config.json: %v", err)
	}
	if raw["server"] != env.URL || !strings.Contains(string(data), env.CA.RootPin) || !strings.Contains(string(data), env.Signer.RootFingerprints[0]) {
		t.Fatalf("config.json does not hold the server, TLS pin and root pin:\n%s", data)
	}

	// The trust document is exactly what the signer runs on.
	tr := env.mustGet(t, serverclient.TrustPath)
	var doc serverclient.TrustResponse
	if tr.code != http.StatusOK || json.Unmarshal([]byte(tr.body), &doc) != nil {
		t.Fatalf("GET %s = %d:\n%s", serverclient.TrustPath, tr.code, tr.body)
	}
	if !bytes.Equal(doc.Bundle, mustRead(t, filepath.Join(env.Signer.BundleDir, "bundle.json"))) ||
		!bytes.Equal(doc.Policy, mustRead(t, filepath.Join(env.Signer.BundleDir, "policy.json"))) ||
		len(doc.BundleSigs) == 0 || len(doc.PolicySigs) == 0 || doc.BundleVersion != 1 || doc.DirectoryVersion != 0 || len(doc.Custody) != len(roleNames) {
		t.Fatalf("GET %s does not carry the installed bundle, policy, signatures, versions and five custody entries:\n%s", serverclient.TrustPath, tr.body)
	}
	requireSecurityHeaders(t, "GET "+serverclient.TrustPath, tr)

	// The page: 200, the exact headers, the custody header and the banner.
	r := env.mustGet(t, "/")
	if r.code != http.StatusOK {
		t.Fatalf("GET / = %d:\n%s", r.code, r.body)
	}
	requireSecurityHeaders(t, "GET /", r)
	if got := r.header.Get(serverclient.CustodyHeader); got != "user=software, host=software, machine=software, ops=software, log=software" {
		t.Errorf("GET / %s = %q", serverclient.CustodyHeader, got)
	}
	if !strings.Contains(r.body, `<div class="kr-banner" role="alert">`+custodytext.SoftwareCABanner(roleNames)+`</div>`) {
		t.Fatalf("GET / lacks the banner:\n%s", r.body)
	}
	if !strings.Contains(r.body, serverRPID) || strings.Contains(r.body, "<script>") || strings.Contains(r.body, " style=") {
		t.Fatalf("GET / page:\n%s", r.body)
	}
	css := env.mustGet(t, "/static/app.css")
	if css.code != http.StatusOK || css.header.Get("Content-Type") != "text/css; charset=utf-8" {
		t.Fatalf("GET /static/app.css = %d %q", css.code, css.header.Get("Content-Type"))
	}
	requireSecurityHeaders(t, "GET /static/app.css", css)

	t.Run("sighup_reload_logs_json", func(t *testing.T) {
		if err := env.Cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		var hit string
		deadline := time.Now().Add(5 * time.Second)
		for hit == "" && time.Now().Before(deadline) {
			for _, l := range env.loadedLines() {
				if strings.Contains(l, `"trigger":"sighup"`) {
					hit = l
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if hit == "" {
			t.Fatalf("no \"tls certificate loaded\" line with \"trigger\":\"sighup\" within 5 s of SIGHUP:\n%s", env.Stderr.String())
		}
		requireJSONLine(t, hit)
		select {
		case <-env.Done:
			t.Fatalf("keyroster-server exited after SIGHUP:\n%s", env.Stderr.String())
		default:
		}
		if r := env.mustGet(t, "/healthz"); r.code != http.StatusOK {
			t.Fatalf("GET /healthz after SIGHUP = %d", r.code)
		}
	})

	// Control: agent custody, no banner on the page or in init.
	ctl := startServerEnv(t, serverOpts{})
	ctlCLI := newCLIEnv(t)
	code, stdout, stderr = ctlCLI.run(t, ctl.initArgs()...)
	if code != 0 {
		t.Fatalf("keyroster init (agent control) exited %d:\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if strings.Contains(stderr, softwareBannerPhrase) || strings.Contains(stdout, softwareBannerPhrase) {
		t.Fatalf("keyroster init (agent control) printed the software banner:\n%s\n%s", stdout, stderr)
	}
	cr := ctl.mustGet(t, "/")
	if cr.code != http.StatusOK || strings.Contains(cr.body, softwareBannerPhrase) || strings.Contains(cr.body, "kr-banner") {
		t.Fatalf("GET / (agent control) = %d, want 200 without the banner:\n%s", cr.code, cr.body)
	}
	if got := cr.header.Get(serverclient.CustodyHeader); got != "user=agent, host=agent, machine=agent, ops=agent, log=agent" {
		t.Errorf("GET / (agent control) %s = %q", serverclient.CustodyHeader, got)
	}
	requireSecurityHeaders(t, "GET / (agent control)", cr)
}

// loadedLines returns the server's stderr lines that carry the exact
// string `"msg":"tls certificate loaded"`.
func (e *serverEnv) loadedLines() []string {
	var out []string
	for _, l := range strings.Split(e.Stderr.String(), "\n") {
		if strings.Contains(l, `"msg":"tls certificate loaded"`) {
			out = append(out, l)
		}
	}
	return out
}

// requireJSONLine fails unless l is one JSON object.
func requireJSONLine(t *testing.T, l string) {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal([]byte(l), &obj); err != nil {
		t.Fatalf("log line is not a JSON object: %q: %v", l, err)
	}
}

// TestServerSIGHUPDuringStartup: a SIGHUP that reaches keyroster-server
// while it still retries the signer's Status (start-up step 1) does not
// end the process. An unregistered SIGHUP ends a Go program, and systemd
// would not restart a service ended by SIGHUP under Restart=on-failure.
func TestServerSIGHUPDuringStartup(t *testing.T) {
	ca := newTestCA(t, serverRPID)
	socket := filepath.Join(shortTempDir(t), "nothing.sock") // nothing listens here
	port := freePort(t)
	cmd, log, done := startDaemon(t, "keyroster-server", envWithout("SSH_AUTH_SOCK"), serverBin, "serve",
		"--listen", "127.0.0.1:"+strconv.Itoa(port), "--tls-cert", ca.CertPath, "--tls-key", ca.KeyPath, "--signer-socket", socket)
	time.Sleep(500 * time.Millisecond)
	select {
	case <-done:
		t.Fatalf("keyroster-server exited before the SIGHUP:\n%s", log.String())
	default:
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	select {
	case <-done:
		t.Fatalf("keyroster-server ended on a SIGHUP during start-up (state %v):\n%s", cmd.ProcessState, log.String())
	default:
	}
	if !strings.Contains(log.String(), "signer status unavailable; retrying") {
		t.Fatalf("keyroster-server is not in start-up step 1:\n%s", log.String())
	}
	_ = cmd.Process.Kill()
	<-done
}

// TestServerRefusesStart: keyroster-server does not start without a
// WebAuthn RP in the signer's policy, nor with a certificate that does
// not cover the RP ID or has expired.
func TestServerRefusesStart(t *testing.T) {
	serve := func(t *testing.T, socket, cert, key string) (int, string) {
		t.Helper()
		return runBin(t, serverBin, "", "serve", "--listen", "127.0.0.1:"+strconv.Itoa(freePort(t)),
			"--tls-cert", cert, "--tls-key", key, "--signer-socket", socket)
	}
	ca := newTestCA(t, serverRPID)

	t.Run("no_rp_in_policy", func(t *testing.T) {
		sg := bootstrapSigner(t, bootstrapOpts{})
		code, out := serve(t, sg.Socket, ca.CertPath, ca.KeyPath)
		if code == 0 || !strings.Contains(out, "the installed policy has no WebAuthn RP") {
			t.Fatalf("serve on a policy without an RP: exit %d:\n%s", code, out)
		}
	})

	rp := bootstrapSigner(t, bootstrapOpts{WebAuthnRPID: serverRPID, WebAuthnOrigins: []string{"https://" + serverRPID + ":8443"}})
	t.Run("leaf_not_covering_rp_id", func(t *testing.T) {
		cert, key := ca.otherNameLeaf(t)
		code, out := serve(t, rp.Socket, cert, key)
		if code == 0 || !strings.Contains(out, "does not cover the RP ID "+serverRPID) {
			t.Fatalf("serve with a leaf for another name: exit %d:\n%s", code, out)
		}
	})
	t.Run("expired_leaf", func(t *testing.T) {
		cert, key := ca.expiredLeaf(t, serverRPID)
		code, out := serve(t, rp.Socket, cert, key)
		if code == 0 || !strings.Contains(out, "the certificate is valid from") {
			t.Fatalf("serve with an expired leaf: exit %d:\n%s", code, out)
		}
	})
	t.Run("control_starts", func(t *testing.T) {
		e := &serverEnv{CA: ca, Port: freePort(t)}
		e.URL = "https://" + serverRPID + ":" + strconv.Itoa(e.Port)
		e.Cmd, e.Stderr, e.Done = startDaemon(t, "keyroster-server", envWithout("SSH_AUTH_SOCK"), serverBin, "serve",
			"--listen", "127.0.0.1:"+strconv.Itoa(e.Port), "--tls-cert", ca.CertPath, "--tls-key", ca.KeyPath, "--signer-socket", rp.Socket)
		waitFor(t, "keyroster-server /healthz", e.Done, e.Stderr, func() bool {
			r, err := e.get("/healthz")
			return err == nil && r.code == http.StatusOK
		})
	})
}
