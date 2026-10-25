package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// fakeLogin is one login begun on the fake server.
type fakeLogin struct {
	id        string
	req       *wire.LoginIssueRequest
	challenge string
	state     string
	port      int
	code      string
}

// loginServer is a fake keyroster-server for keyroster login: a pinned TLS
// server whose /api/v1/trust serves a root-signed bundle whose active user
// CA the test holds, and fake login routes. It is driven like a browser by
// the test (drive). Its clock is the CLI's loginNow plus skew.
type loginServer struct {
	url    string
	ca     ssh.Signer // the bundle's active user CA
	caMax  uint64     // the policy's user CA cap, in seconds
	custom string     // the Keyroster-Custody header

	trustDoc []byte

	mu      sync.Mutex
	skew    time.Duration
	roles   []loginOptionsRole
	logins  map[string]*fakeLogin
	redeems int
	// beginReqs counts every POST to the begin route, answered or not.
	beginReqs int
	serial    uint64
	// certFor, when set, builds the certificate redeem returns instead of
	// the honest one.
	certFor func(t *testing.T, l *fakeLogin) []byte
	// redeemHook, when set, answers the redeem itself.
	redeemHook func(w http.ResponseWriter)
	// override, when it has an entry for the route path, answers that
	// route instead of the fake (options and begin).
	override map[string]func(w http.ResponseWriter)
	begun    chan *fakeLogin
	t        *testing.T
}

const loginTestCustody = "user=agent, host=agent, machine=agent, ops=agent, log=agent"

// newLoginServer signs a genesis bundle whose user CA key the test keeps,
// serves it with the fake login routes over TLS under a test root, and
// saves a config for user alice pinned to both. dialAgent is left as it
// was before the root signing.
func newLoginServer(t *testing.T) *loginServer {
	t.Helper()
	e := &loginServer{custom: loginTestCustody, logins: map[string]*fakeLogin{}, override: map[string]func(http.ResponseWriter){}, begun: make(chan *fakeLogin, 4), t: t,
		roles: []loginOptionsRole{
			{Name: "dev", Principals: []string{"role:dev", "u:alice"}, MaxTTLSeconds: 7200, Extensions: []string{}},
			{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600, Extensions: []string{}},
		}}
	g := newCeremony(t, 1)
	cas := &trust.CAPubKeys{}
	for _, role := range trust.CAPubKeyRoles {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if role == trust.RoleUser {
			e.ca = s
		}
		cas.Keys = append(cas.Keys, trust.CAPubKey{Role: role, Key: trust.FormatKey(s.PublicKey()), Alg: s.PublicKey().Type(), Custody: "tpm"})
	}
	data, err := cas.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, g.caPubkeys, data)
	prevDial := dialAgent
	useKeyring(t, g.rootKeys...)
	typeHashPrefix(t, g.out)
	if code, _, stderr := g.sign(t, "1", 0); code != 0 {
		t.Fatalf("root sign: exit %d: %s", code, stderr)
	}
	dialAgent = prevDial
	read := func(name string) []byte { return readTestFile(t, filepath.Join(g.out, name)) }
	pol, err := trust.ParsePolicy(read("policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pol.CAProfiles {
		if p.Role == trust.RoleUser {
			e.caMax = p.MaxTTLSeconds
		}
	}
	if e.trustDoc, err = json.Marshal(serverclient.TrustResponse{
		Bundle: read("bundle.json"), BundleSigs: read("bundle.json.sigs"),
		Policy: read("policy.json"), PolicySigs: read("policy.json.sigs"), BundleVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}

	root, rootKey := initTestRoot(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	e.url = serveTLS(t, tls.Certificate{Certificate: [][]byte{leaf}, PrivateKey: leafKey}, http.HandlerFunc(e.handle))
	useConfigDir(t)
	if _, err := saveConfig(&Config{
		Server:         e.url,
		TLSRootsPEM:    []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))},
		TLSPins:        []string{serverclient.PinOf(root)},
		TrustPins:      []string{g.fingerprint(t, 0)},
		TrustThreshold: 1,
		User:           "alice",
	}, false); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *loginServer) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return loginNow().Add(e.skew)
}

func (e *loginServer) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (e *loginServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(serverclient.CustodyHeader, e.custom)
	e.mu.Lock()
	over := e.override[r.URL.Path]
	if r.Method == http.MethodPost && r.URL.Path == loginBeginRoute {
		e.beginReqs++
	}
	e.mu.Unlock()
	if over != nil {
		over(w)
		return
	}
	switch {
	case r.URL.Path == serverclient.TrustPath:
		_, _ = w.Write(e.trustDoc)
	case r.Method == http.MethodGet && r.URL.Path == loginOptionsRoute:
		e.mu.Lock()
		roles := e.roles
		e.mu.Unlock()
		e.writeJSON(w, http.StatusOK, loginOptions{ServerTime: e.now().Unix(), User: r.URL.Query().Get("user"), CAMaxTTLSeconds: e.caMax, Roles: roles})
	case r.Method == http.MethodPost && r.URL.Path == loginBeginRoute:
		var b loginBeginBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			e.writeJSON(w, http.StatusBadRequest, serverclient.APIError{Error: "malformed request"})
			return
		}
		req, err := wire.ParseLoginIssueRequest(b.Request)
		if err != nil {
			e.writeJSON(w, http.StatusBadRequest, serverclient.APIError{Error: "malformed request"})
			return
		}
		id := make([]byte, 16)
		_, _ = rand.Read(id)
		l := &fakeLogin{id: hex.EncodeToString(id), req: req, challenge: b.CodeChallenge, state: b.State, port: b.RedirectPort}
		e.mu.Lock()
		e.logins[l.id] = l
		e.mu.Unlock()
		e.writeJSON(w, http.StatusOK, loginBeginAnswer{LoginID: l.id, ApprovalURL: e.url + "/login/" + l.id, ExpiresAt: e.now().Add(240 * time.Second).Unix()})
		e.begun <- l
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/login/"):
		l := e.login(strings.TrimPrefix(r.URL.Path, "/login/"))
		if l == nil {
			http.NotFound(w, r)
			return
		}
		k, err := ssh.ParsePublicKey(l.req.SubjectKey)
		if err != nil {
			http.Error(w, "bad key", http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintf(w, "<p>Key fingerprint: <code>%s</code></p>", ssh.FingerprintSHA256(k))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/assertion"):
		l := e.login(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, loginRoutePrefix), "/assertion"))
		if l == nil {
			http.NotFound(w, r)
			return
		}
		code, err := randomB64(32)
		if err != nil {
			http.Error(w, "rand", http.StatusInternalServerError)
			return
		}
		e.mu.Lock()
		l.code = code
		e.mu.Unlock()
		e.writeJSON(w, http.StatusOK, map[string]string{"redirect": "http://127.0.0.1:" + strconv.Itoa(l.port) + "/callback?code=" + code + "&state=" + l.state})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/redeem"):
		e.mu.Lock()
		e.redeems++
		hook := e.redeemHook
		e.mu.Unlock()
		if hook != nil {
			hook(w)
			return
		}
		l := e.login(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, loginRoutePrefix), "/redeem"))
		var b loginRedeemBody
		if l == nil || json.NewDecoder(r.Body).Decode(&b) != nil {
			e.writeJSON(w, http.StatusBadRequest, serverclient.APIError{Error: "login not redeemable"})
			return
		}
		sum := sha256.Sum256([]byte(b.CodeVerifier))
		e.mu.Lock()
		ok := b.Code == l.code && base64.RawURLEncoding.EncodeToString(sum[:]) == l.challenge
		certFor := e.certFor
		e.mu.Unlock()
		if !ok {
			e.writeJSON(w, http.StatusBadRequest, serverclient.APIError{Error: "login not redeemable"})
			return
		}
		raw := e.honestCert(e.t, l)
		if certFor != nil {
			raw = certFor(e.t, l)
		}
		e.writeJSON(w, http.StatusOK, loginRedeemAnswer{Certificate: raw})
	default:
		http.NotFound(w, r)
	}
}

// begins returns the number of logins begun.
func (e *loginServer) begins() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.logins)
}

// calls returns how many begin and redeem requests reached the server.
func (e *loginServer) calls() (begins, redeems int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.beginReqs, e.redeems
}

// requireCalls fails unless exactly begins begin requests and redeems
// redeem requests reached the server.
func (e *loginServer) requireCalls(t *testing.T, begins, redeems int) {
	t.Helper()
	if b, r := e.calls(); b != begins || r != redeems {
		t.Fatalf("the server got %d begin and %d redeem requests, want %d and %d", b, r, begins, redeems)
	}
}

func (e *loginServer) login(id string) *fakeLogin {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.logins[id]
}

// certParams are the parts of a certificate the fake issues, for the
// refusal cases to change.
type certParams struct {
	ca         ssh.Signer
	key        ssh.PublicKey
	principals []string
	subject    string
	now        time.Time
	validFor   time.Duration
	roles      []string          // the key ID's roles
	extra      map[string]string // extensions beyond the profile's permit-pty
	critical   map[string]string
}

// params are the honest parameters for l, as the signer issues them: the
// requested roles (or all of the user's, sorted) and the requested
// extensions on top of the profile default.
func (e *loginServer) params(t *testing.T, l *fakeLogin) certParams {
	t.Helper()
	k, err := ssh.ParsePublicKey(l.req.SubjectKey)
	if err != nil {
		t.Error(err)
	}
	roles := l.req.Roles
	if len(roles) == 0 {
		e.mu.Lock()
		for _, r := range e.roles {
			roles = append(roles, r.Name)
		}
		e.mu.Unlock()
		slices.Sort(roles)
	}
	extra := map[string]string{}
	for _, x := range l.req.Extensions {
		if x != "permit-pty" {
			extra[x] = ""
		}
	}
	return certParams{ca: e.ca, key: k, principals: l.req.Principals, subject: l.req.Subject, now: e.now(),
		validFor: time.Duration(l.req.ValidForSeconds) * time.Second, roles: roles, extra: extra}
}

// build issues a certificate with p through cert.Build.
func (e *loginServer) build(t *testing.T, l *fakeLogin, p certParams) []byte {
	t.Helper()
	e.mu.Lock()
	e.serial++
	ser := e.serial
	e.mu.Unlock()
	prof := cert.DefaultUserProfile()
	for x := range p.extra {
		prof.AllowedExtensions = append(prof.AllowedExtensions, x)
	}
	for o := range p.critical {
		prof.AllowedCriticalOptions = append(prof.AllowedCriticalOptions, o)
	}
	c, err := cert.Build(cert.Request{
		Profile: prof, Subject: p.key, Principals: p.principals, Now: p.now, ValidFor: p.validFor,
		KeyID:           cert.KeyID{CA: "user", Subject: p.subject, Request: hex.EncodeToString(l.req.RequestID[:]), Policy: 1, Directory: 1, Roles: p.roles, Serial: ser},
		Serial:          ser,
		ExtraExtensions: p.extra,
		CriticalOptions: p.critical,
	}, p.ca, rand.Reader)
	if err != nil {
		t.Error(err)
		return nil
	}
	return c.Marshal()
}

func (e *loginServer) honestCert(t *testing.T, l *fakeLogin) []byte {
	return e.build(t, l, e.params(t, l))
}

// setCert makes redeem return the certificate mutate builds from the
// honest parameters.
func (e *loginServer) setCert(mutate func(t *testing.T, l *fakeLogin, p *certParams) []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.certFor = func(t *testing.T, l *fakeLogin) []byte {
		p := e.params(t, l)
		if out := mutate(t, l, &p); out != nil {
			return out
		}
		return e.build(t, l, p)
	}
}

// loginResult is the outcome of one keyroster login run.
type loginResult struct {
	code           int
	stdout, stderr string
}

// start runs keyroster login --no-browser with args in the background.
func (e *loginServer) start(t *testing.T, args ...string) (stderr *lockedBuffer, wait func() loginResult) {
	t.Helper()
	var stdout lockedBuffer
	stderr = &lockedBuffer{}
	done := make(chan int, 1)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { done <- dispatch(ctx, append([]string{"login", "--no-browser"}, args...), &stdout, stderr) }()
	return stderr, func() loginResult {
		t.Helper()
		select {
		case code := <-done:
			return loginResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
		case <-time.After(60 * time.Second):
			t.Fatalf("keyroster login did not exit within 60 s:\n%s", stderr.String())
			return loginResult{}
		}
	}
}

// drive acts as the browser for the next begun login: it waits for the
// begin, GETs the approval page and requires the fingerprint the CLI
// printed, posts an assertion and follows the loopback redirect. It
// returns the login.
func (e *loginServer) drive(t *testing.T, stderr *lockedBuffer) *fakeLogin {
	t.Helper()
	var l *fakeLogin
	select {
	case l = <-e.begun:
	case <-time.After(30 * time.Second):
		t.Fatalf("no login was begun:\n%s", stderr.String())
	}
	fp := ""
	for _, line := range strings.Split(stderr.String(), "\n") {
		if v, ok := strings.CutPrefix(line, "Key fingerprint: "); ok {
			fp = v
		}
	}
	c := e.client(t)
	page := e.get(t, c, e.url+"/login/"+l.id)
	if fp == "" || !strings.Contains(page, fp) {
		t.Fatalf("the CLI printed fingerprint %q; the page shows %q", fp, page)
	}
	resp, err := c.Post(e.url+loginRoutePrefix+l.id+"/assertion", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	var ans struct {
		Redirect string `json:"redirect"`
	}
	err = json.NewDecoder(resp.Body).Decode(&ans)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	e.get(t, &http.Client{Timeout: 10 * time.Second}, ans.Redirect)
	return l
}

// client is an HTTP client that trusts the fake's TLS leaf.
func (e *loginServer) client(t *testing.T) *http.Client {
	t.Helper()
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // G402: the test's own fake server
}

func (e *loginServer) get(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d %s", u, resp.StatusCode, b)
	}
	return string(b)
}

// recordingAgent is an in-memory agent served over a connection that
// records every add and can refuse a constrained add or leave
// certificates out of its listing.
type recordingAgent struct {
	agent.Agent
	mu                sync.Mutex
	adds              []agent.AddedKey
	refuseConstrained bool
	hideCerts         bool
}

func (a *recordingAgent) Add(k agent.AddedKey) error {
	a.mu.Lock()
	a.adds = append(a.adds, k)
	refuse := a.refuseConstrained && k.LifetimeSecs > 0
	a.mu.Unlock()
	if refuse {
		return errors.New("constraints refused")
	}
	return a.Agent.Add(k)
}

func (a *recordingAgent) List() ([]*agent.Key, error) {
	keys, err := a.Agent.List()
	a.mu.Lock()
	hide := a.hideCerts
	a.mu.Unlock()
	if err != nil || !hide {
		return keys, err
	}
	// Each certificate is listed as its plain key, so the listing is not
	// empty but holds no certificate.
	var out []*agent.Key
	for _, k := range keys {
		pk, err := ssh.ParsePublicKey(k.Blob)
		if c, ok := pk.(*ssh.Certificate); err == nil && ok {
			k = &agent.Key{Format: c.Key.Type(), Blob: c.Key.Marshal(), Comment: k.Comment}
		}
		out = append(out, k)
	}
	return out, nil
}

func (a *recordingAgent) added() []agent.AddedKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]agent.AddedKey(nil), a.adds...)
}

// useRecordingAgent replaces connectLoginAgent with a recordingAgent
// served over net.Pipe by agent.ServeAgent, so the key travels over a
// connection as it does to a real agent.
func useRecordingAgent(t *testing.T) *recordingAgent {
	t.Helper()
	a := &recordingAgent{Agent: agent.NewKeyring()}
	prev := connectLoginAgent
	connectLoginAgent = func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_ = agent.ServeAgent(a, server)
			_ = server.Close()
		}()
		return client, nil
	}
	t.Cleanup(func() { connectLoginAgent = prev })
	return a
}

// useLoginClock fixes loginNow at a whole second, so the remaining
// validity is exact, and restores it at cleanup.
func useLoginClock(t *testing.T) time.Time {
	t.Helper()
	fixed := time.Now().Truncate(time.Second)
	prev := loginNow
	loginNow = func() time.Time { return fixed }
	t.Cleanup(func() { loginNow = prev })
	return fixed
}

// requireTwoMinuteLogin runs a 2-minute --role ops login against e, whose
// signer stamps the certificate 2 s before the CLI checks it, and requires
// it to succeed with one agent add whose lifetime is at least 60 s and at
// most what the certificate has left at serverNow, the server's clock when
// the CLI checks it.
func requireTwoMinuteLogin(t *testing.T, e *loginServer, a *recordingAgent, serverNow time.Time) {
	t.Helper()
	e.setCert(func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
		p.now = p.now.Add(-2 * time.Second)
		return nil
	})
	stderr, wait := e.start(t, "--role", "ops", "--ttl", "2m")
	e.drive(t, stderr)
	if r := wait(); r.code != 0 {
		t.Fatalf("login exit %d:\n%s", r.code, r.stderr)
	}
	adds := a.added()
	if len(adds) != 1 || adds[0].Certificate == nil {
		t.Fatalf("adds = %v, want one certificate add", adds)
	}
	left := time.Unix(int64(adds[0].Certificate.ValidBefore), 0).Sub(serverNow) //nolint:gosec // G115: a test certificate
	if got := time.Duration(adds[0].LifetimeSecs) * time.Second; got < 60*time.Second || got > left {
		t.Fatalf("agent lifetime %v; want at least 60 s and at most %v, what the certificate has left on the server's clock", got, left)
	}
}

// useEmptyHomes points HOME and the temporary directory at fresh empty
// directories and returns them, so a test can require that keyroster
// login wrote no file.
func useEmptyHomes(t *testing.T) []string {
	t.Helper()
	home, tmp := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TMPDIR", tmp)
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)
	return []string{home, tmp}
}

// requireNoFiles fails if any of dirs holds a file.
func requireNoFiles(t *testing.T, dirs []string) {
	t.Helper()
	for _, d := range dirs {
		_ = filepath.WalkDir(d, func(p string, de os.DirEntry, err error) error {
			if err == nil && !de.IsDir() {
				t.Errorf("keyroster login wrote %s", p)
			}
			return nil
		})
	}
}

// requireLoginRefused fails unless r exited non-zero with want in its
// stderr.
func requireLoginRefused(t *testing.T, r loginResult, want string) {
	t.Helper()
	if r.code == 0 || !strings.Contains(r.stderr, want) {
		t.Fatalf("keyroster login exit %d, stderr %q; want a refusal with %q", r.code, r.stderr, want)
	}
}

// TestLoopback: the callback listener accepts only GET /callback with
// Host 127.0.0.1:<port> and the state; a refused request keeps it waiting,
// and it closes after the valid callback.
func TestLoopback(t *testing.T) {
	state, err := randomB64(32)
	if err != nil {
		t.Fatal(err)
	}
	code, err := randomB64(32)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := listenLoopback(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lb.close)
	base := "http://127.0.0.1:" + strconv.Itoa(lb.port)
	send := func(method, target, host string) int {
		t.Helper()
		req, err := http.NewRequest(method, base+target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		_ = resp.Body.Close()
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: Cache-Control %q", method, target, resp.Header.Get("Cache-Control"))
		}
		return resp.StatusCode
	}
	good := "/callback?code=" + code + "&state=" + url.QueryEscape(state)
	t.Run("wrong_state_keeps_waiting", func(t *testing.T) {
		other, _ := randomB64(32)
		if got := send(http.MethodGet, "/callback?code="+code+"&state="+other, ""); got != http.StatusBadRequest {
			t.Fatalf("wrong state = %d, want 400", got)
		}
		select {
		case c := <-lb.codes:
			t.Fatalf("a wrong state delivered %q", c)
		default:
		}
	})
	t.Run("host_header_mismatch", func(t *testing.T) {
		if got := send(http.MethodGet, good, "localhost:"+strconv.Itoa(lb.port)); got != http.StatusBadRequest {
			t.Fatalf("Host localhost = %d, want 400", got)
		}
	})
	t.Run("post_callback_405", func(t *testing.T) {
		if got := send(http.MethodPost, good, ""); got != http.StatusMethodNotAllowed {
			t.Fatalf("POST /callback = %d, want 405", got)
		}
	})
	t.Run("other_path_404", func(t *testing.T) {
		if got := send(http.MethodGet, "/other", ""); got != http.StatusNotFound {
			t.Fatalf("GET /other = %d, want 404", got)
		}
	})
	t.Run("listener_closed_after_callback", func(t *testing.T) {
		if got := send(http.MethodGet, good, ""); got != http.StatusOK {
			t.Fatalf("valid callback = %d, want 200", got)
		}
		got, err := lb.wait(context.Background(), nil)
		if err != nil || got != code {
			t.Fatalf("wait = %q, %v; want the code", got, err)
		}
		lb.close()
		if resp, err := http.Get(base + good); err == nil { //nolint:noctx // test
			_ = resp.Body.Close()
			t.Fatal("the loopback still answers after the callback")
		}
	})
}

// TestCallbackDeadline: the CLI waits until the server's approval deadline
// mapped through the skew, plus 5 s (02-12-F15).
func TestCallbackDeadline(t *testing.T) {
	exp := int64(1_800_000_240)
	if got, want := callbackDeadline(exp, 30*time.Second), time.Unix(exp-30+5, 0); !got.Equal(want) {
		t.Fatalf("deadline = %v, want %v", got, want)
	}
}

// TestLoginRefusals: each refusal of keyroster login leaves the agent
// untouched and writes no file. Fake agents stand in through
// connectLoginAgent on every OS.
func TestLoginRefusals(t *testing.T) {
	t.Run("clock_skew_refused", func(t *testing.T) {
		e := newLoginServer(t)
		a := useRecordingAgent(t)
		dirs := useEmptyHomes(t)
		e.skew = 61 * time.Second
		_, wait := e.start(t)
		requireLoginRefused(t, wait(), "your clock differs from the server by 61s")
		if e.begins() != 0 || len(a.added()) != 0 {
			t.Fatalf("a skewed login began (%d) or added to the agent (%d)", e.begins(), len(a.added()))
		}
		requireNoFiles(t, dirs)
	})
	t.Run("ttl_above_cap_refused", func(t *testing.T) {
		e := newLoginServer(t)
		a := useRecordingAgent(t)
		_, wait := e.start(t, "--ttl", "2h")
		requireLoginRefused(t, wait(), "--ttl 2h0m0s is longer than 1h0m0s")
		if e.begins() != 0 || len(a.added()) != 0 {
			t.Fatal("a refused --ttl began a login or added to the agent")
		}
	})
	t.Run("unknown_role_refused", func(t *testing.T) {
		e := newLoginServer(t)
		useRecordingAgent(t)
		_, wait := e.start(t, "--role", "admin")
		requireLoginRefused(t, wait(), "--role admin: you do not hold that role")
		if e.begins() != 0 {
			t.Fatal("an unknown --role began a login")
		}
	})
	t.Run("options_checked", func(t *testing.T) {
		// Every options answer that fails the user, server time, user CA
		// cap, role-count, role-name, TTL, principal or extension rules is
		// refused before a key is made or a login begun, and its text never
		// reaches stderr.
		const badText = "\x1b[2Jevil"
		for _, c := range []struct {
			name   string
			mutate func(o *loginOptions, caMax uint64)
		}{
			{"other_user", func(o *loginOptions, _ uint64) { o.User = "bob" }},
			{"server_time_zero", func(o *loginOptions, _ uint64) { o.ServerTime = 0 }},
			{"ca_max_not_policy_cap", func(o *loginOptions, caMax uint64) { o.CAMaxTTLSeconds = caMax - 1 }},
			{"too_many_roles", func(o *loginOptions, _ uint64) {
				o.Roles = nil
				for i := range wire.MaxLoginRoles*4 + 1 {
					o.Roles = append(o.Roles, loginOptionsRole{Name: fmt.Sprintf("r%02d", i), Principals: []string{"role:r"}, MaxTTLSeconds: 3600})
				}
			}},
			{"bad_role_name", func(o *loginOptions, _ uint64) { o.Roles[0].Name = "dev" + badText }},
			{"zero_role_ttl", func(o *loginOptions, _ uint64) { o.Roles[0].MaxTTLSeconds = 0 }},
			{"no_principals", func(o *loginOptions, _ uint64) { o.Roles[0].Principals = nil }},
			{"principal_escape", func(o *loginOptions, _ uint64) { o.Roles[0].Principals = []string{"role:dev" + badText} }},
			{"principal_cr", func(o *loginOptions, _ uint64) { o.Roles[0].Principals = []string{"u:alice\revil"} }},
			{"bad_extension", func(o *loginOptions, _ uint64) { o.Roles[0].Extensions = []string{"permit" + badText} }},
			{"duplicate_role", func(o *loginOptions, _ uint64) { o.Roles = append(o.Roles, o.Roles[0]) }},
		} {
			t.Run(c.name, func(t *testing.T) {
				e := newLoginServer(t)
				a := useRecordingAgent(t)
				e.override[loginOptionsRoute] = func(w http.ResponseWriter) {
					e.mu.Lock()
					roles := append([]loginOptionsRole(nil), e.roles...)
					e.mu.Unlock()
					for i := range roles {
						roles[i].Principals = append([]string(nil), roles[i].Principals...)
					}
					o := loginOptions{ServerTime: e.now().Unix(), User: "alice", CAMaxTTLSeconds: e.caMax, Roles: roles}
					c.mutate(&o, e.caMax)
					e.writeJSON(w, http.StatusOK, o)
				}
				_, wait := e.start(t)
				r := wait()
				requireLoginRefused(t, r, errBadLoginOptions.Error())
				requireNoRawControl(t, r.stderr)
				if strings.Contains(r.stderr, "evil") || strings.Contains(r.stderr, "Key fingerprint") {
					t.Fatalf("the refused options reached stderr or a key was made:\n%s", r.stderr)
				}
				if e.begins() != 0 || len(a.added()) != 0 {
					t.Fatalf("refused options began a login (%d) or added to the agent (%d)", e.begins(), len(a.added()))
				}
			})
		}
	})
	t.Run("constrained_add_refused_no_retry", func(t *testing.T) {
		e := newLoginServer(t)
		a := useRecordingAgent(t)
		a.refuseConstrained = true
		dirs := useEmptyHomes(t)
		stderr, wait := e.start(t)
		e.drive(t, stderr)
		requireLoginRefused(t, wait(), "not retrying without it")
		adds := a.added()
		if len(adds) != 1 || adds[0].LifetimeSecs == 0 {
			t.Fatalf("adds = %d (first lifetime %v), want exactly one constrained add and no unconstrained retry", len(adds), adds)
		}
		if keys, _ := a.Agent.List(); len(keys) != 0 {
			t.Fatalf("the agent holds %d keys", len(keys))
		}
		requireNoFiles(t, dirs)
	})
	t.Run("listing_without_cert_refused", func(t *testing.T) {
		e := newLoginServer(t)
		a := useRecordingAgent(t)
		a.hideCerts = true
		stderr, wait := e.start(t)
		e.drive(t, stderr)
		requireLoginRefused(t, wait(), "the agent dropped the certificate")
	})
	for _, c := range []struct {
		name, want string
		mutate     func(t *testing.T, l *fakeLogin, p *certParams) []byte
		args       []string
	}{
		{"cert_extra_role_refused", "key ID does not name the roles requested", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.roles = []string{"admin", "dev", "ops"}
			return nil
		}, nil},
		{"cert_unrequested_role_refused", "key ID does not name the roles requested", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.roles = []string{"dev", "ops"}
			return nil
		}, []string{"--role", "ops"}},
		{"cert_extra_extension_refused", "extensions are not the ones requested", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.extra["permit-agent-forwarding"] = ""
			p.extra["permit-port-forwarding"] = ""
			return nil
		}, nil},
		{"cert_critical_option_refused", "carries critical options", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.critical = map[string]string{"force-command": "/bin/true"}
			return nil
		}, nil},
		{"cert_other_ca_refused", "not signed by the user CA", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			p.ca, _ = ssh.NewSignerFromKey(k)
			return nil
		}, nil},
		{"cert_bad_signature_refused", "CA signature or validity", nil, nil},
		{"cert_other_key_refused", "for another key", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			p.key, _ = ssh.NewPublicKey(pub)
			return nil
		}, nil},
		{"cert_extra_principal_refused", "principals are not the ones requested", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.principals = append(append([]string(nil), p.principals...), "root")
			return nil
		}, nil},
		{"cert_other_user_refused", "key ID does not name this user", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.subject = "bob"
			return nil
		}, nil},
		{"cert_span_ttl_301_refused", "valid for longer than requested", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.validFor += time.Second
			return nil
		}, nil},
		{"cert_59s_remaining_refused", "less than 60 s left", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.now = p.now.Add(-p.validFor + 59*time.Second)
			return nil
		}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			useLoginClock(t)
			e := newLoginServer(t)
			a := useRecordingAgent(t)
			dirs := useEmptyHomes(t)
			if c.mutate != nil {
				e.setCert(c.mutate)
			} else {
				e.certFor = func(t *testing.T, l *fakeLogin) []byte {
					pk, err := ssh.ParsePublicKey(e.honestCert(t, l))
					if err != nil {
						t.Error(err)
						return nil
					}
					crt := pk.(*ssh.Certificate)
					crt.Signature.Blob[len(crt.Signature.Blob)-1] ^= 1
					return crt.Marshal()
				}
			}
			stderr, wait := e.start(t, c.args...)
			e.drive(t, stderr)
			r := wait()
			requireLoginRefused(t, r, c.want)
			requireLoginRefused(t, r, "nothing was added to the agent")
			if len(a.added()) != 0 {
				t.Fatalf("a refused certificate reached the agent")
			}
			requireNoFiles(t, dirs)
		})
	}
	t.Run("lifetime_within_remaining_validity", func(t *testing.T) {
		now := useLoginClock(t)
		e := newLoginServer(t)
		a := useRecordingAgent(t)
		stderr, wait := e.start(t, "--role", "ops", "--ttl", "10m")
		e.drive(t, stderr)
		if r := wait(); r.code != 0 {
			t.Fatalf("login exit %d:\n%s", r.code, r.stderr)
		}
		adds := a.added()
		if len(adds) != 1 || adds[0].Certificate == nil {
			t.Fatalf("adds = %v, want one certificate add", adds)
		}
		left := int64(adds[0].Certificate.ValidBefore) - now.Unix() //nolint:gosec // G115: a test certificate
		if adds[0].LifetimeSecs < 60 || int64(adds[0].LifetimeSecs) > left || adds[0].Comment != adds[0].Certificate.KeyId {
			t.Fatalf("lifetime %d s, comment %q; want 60 <= lifetime <= %d and the key ID", adds[0].LifetimeSecs, adds[0].Comment, left)
		}
	})
	t.Run("role_extensions_accepted", func(t *testing.T) {
		// A role that grants an extension: the honest certificate carries
		// it next to the profile default, and the login succeeds.
		e := newLoginServer(t)
		a := useRecordingAgent(t)
		e.roles[0].Extensions = []string{"permit-agent-forwarding"}
		stderr, wait := e.start(t)
		e.drive(t, stderr)
		if r := wait(); r.code != 0 {
			t.Fatalf("login exit %d:\n%s", r.code, r.stderr)
		}
		adds := a.added()
		if len(adds) != 1 || adds[0].Certificate == nil {
			t.Fatalf("adds = %v, want one certificate add", adds)
		}
		ext := adds[0].Certificate.Extensions
		_, pty := ext["permit-pty"]
		_, fwd := ext["permit-agent-forwarding"]
		if len(ext) != 2 || !pty || !fwd {
			t.Fatalf("extensions %v, want permit-pty and permit-agent-forwarding", ext)
		}
	})
	t.Run("two_minute_login_at_accepted_skew", func(t *testing.T) {
		// The signer stamps the certificate with the server's clock, here
		// 2 s before the CLI checks it. At any accepted skew a 2-minute
		// login succeeds and the agent lifetime never outlasts the
		// certificate on the server's clock (02-12 pre-merge review).
		for _, skew := range []time.Duration{-60 * time.Second, 0, 60 * time.Second} {
			t.Run(fmt.Sprintf("skew_%ds", int(skew/time.Second)), func(t *testing.T) {
				now := useLoginClock(t)
				e := newLoginServer(t)
				a := useRecordingAgent(t)
				e.skew = skew
				requireTwoMinuteLogin(t, e, a, now.Add(skew))
			})
		}
	})
	t.Run("two_minute_login_at_fractional_skew", func(t *testing.T) {
		// The server's clock runs 0.9 s past a whole second of the CLI's,
		// so the skew, measured in whole seconds, is 0.9 s short: the extra
		// second checkLoginCert adds must cover that (02-12 pre-merge review).
		for _, skew := range []time.Duration{-60 * time.Second, 0, 59 * time.Second} {
			skew += 900 * time.Millisecond
			t.Run(fmt.Sprintf("skew_%v", skew), func(t *testing.T) {
				now := useLoginClock(t)
				e := newLoginServer(t)
				a := useRecordingAgent(t)
				e.skew = skew
				requireTwoMinuteLogin(t, e, a, now.Add(skew))
			})
		}
	})
	t.Run("two_minute_login_with_options_latency", func(t *testing.T) {
		// 5 s pass between the server reading its clock for the options
		// answer and the CLI receiving it. The CLI reads its own clock
		// before the request, so the measured skew errs toward the server
		// being ahead: a -60 s skew is still accepted, and the agent
		// lifetime still fits the certificate (02-12 pre-merge review).
		for _, skew := range []time.Duration{-60 * time.Second, 0, 60 * time.Second} {
			t.Run(fmt.Sprintf("skew_%ds", int(skew/time.Second)), func(t *testing.T) {
				start := useLoginClock(t)
				var mu sync.Mutex
				cur := start
				loginNow = func() time.Time {
					mu.Lock()
					defer mu.Unlock()
					return cur
				}
				e := newLoginServer(t)
				a := useRecordingAgent(t)
				e.skew = skew
				e.mu.Lock()
				e.override[loginOptionsRoute] = func(w http.ResponseWriter) {
					e.mu.Lock()
					roles := e.roles
					e.mu.Unlock()
					opts := loginOptions{ServerTime: e.now().Unix(), User: "alice", CAMaxTTLSeconds: e.caMax, Roles: roles}
					mu.Lock()
					cur = cur.Add(5 * time.Second)
					mu.Unlock()
					e.writeJSON(w, http.StatusOK, opts)
				}
				e.mu.Unlock()
				requireTwoMinuteLogin(t, e, a, start.Add(5*time.Second+skew))
			})
		}
	})
	t.Run("redeem_failure_tells_rerun", func(t *testing.T) {
		for _, c := range []struct {
			name, want string
			hook       func(w http.ResponseWriter)
		}{
			{"connection_closed", "run keyroster login again", func(w http.ResponseWriter) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
			}},
			{"signer_refused", "refused by the signer: principals_mismatch; run keyroster login again", func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"error":"principals_mismatch"}`)
			}},
		} {
			t.Run(c.name, func(t *testing.T) {
				e := newLoginServer(t)
				a := useRecordingAgent(t)
				e.redeemHook = c.hook
				stderr, wait := e.start(t)
				e.drive(t, stderr)
				requireLoginRefused(t, wait(), c.want)
				e.mu.Lock()
				n := e.redeems
				e.mu.Unlock()
				if n != 1 || len(a.added()) != 0 {
					t.Fatalf("redeems = %d, agent adds = %d; want exactly one redeem and no add", n, len(a.added()))
				}
			})
		}
	})
	t.Run("callback_deadline_uses_server_expiry", func(t *testing.T) {
		now := useLoginClock(t)
		e := newLoginServer(t)
		useRecordingAgent(t)
		e.skew = 30 * time.Second
		var waited time.Duration
		prev := loginTimer
		loginTimer = func(d time.Duration) <-chan time.Time {
			waited = d
			ch := make(chan time.Time, 1)
			ch <- now.Add(d)
			return ch
		}
		t.Cleanup(func() { loginTimer = prev })
		_, wait := e.start(t)
		requireLoginRefused(t, wait(), "login not approved in time")
		// expires_at = server now + 240 s = now + 30 s + 240 s; mapped
		// through the 30 s skew and 5 s of grace: now + 245 s.
		if waited != 245*time.Second {
			t.Fatalf("the callback wait was %v, want 245s", waited)
		}
	})
	t.Run("begin_answer_checked", func(t *testing.T) {
		e := newLoginServer(t)
		useRecordingAgent(t)
		e.url = "https://evil.example"
		_, wait := e.start(t)
		requireLoginRefused(t, wait(), "the server's login begin answer does not check out")
	})
	t.Run("begin_answer_fields_checked", func(t *testing.T) {
		// A begin answer with an http URL, a query, a fragment, user info
		// or another login's path, or an expiry not within 600 s after the
		// server's time, opens no approval URL; an expiry of exactly 600 s
		// is the control that does.
		id := strings.Repeat("cd", 16)
		for _, c := range []struct {
			name   string
			url    func(base string) string
			expiry int64
			ok     bool
		}{
			{"control_600s", func(b string) string { return b + "/login/" + id }, 600, true},
			{"http_scheme", func(b string) string { return "http://" + strings.TrimPrefix(b, "https://") + "/login/" + id }, 240, false},
			{"query", func(b string) string { return b + "/login/" + id + "?x=1" }, 240, false},
			{"fragment", func(b string) string { return b + "/login/" + id + "#x" }, 240, false},
			{"userinfo", func(b string) string { return "https://u@" + strings.TrimPrefix(b, "https://") + "/login/" + id }, 240, false},
			{"other_login_path", func(b string) string { return b + "/login/" + strings.Repeat("ef", 16) }, 240, false},
			{"expires_at_server_time", func(b string) string { return b + "/login/" + id }, 0, false},
			{"expires_after_601s", func(b string) string { return b + "/login/" + id }, 601, false},
		} {
			t.Run(c.name, func(t *testing.T) {
				now := useLoginClock(t)
				e := newLoginServer(t)
				useRecordingAgent(t)
				prev := loginTimer
				loginTimer = func(time.Duration) <-chan time.Time {
					ch := make(chan time.Time, 1)
					ch <- now
					return ch
				}
				t.Cleanup(func() { loginTimer = prev })
				e.override[loginBeginRoute] = func(w http.ResponseWriter) {
					e.writeJSON(w, http.StatusOK, loginBeginAnswer{LoginID: id, ApprovalURL: c.url(e.url), ExpiresAt: e.now().Unix() + c.expiry})
				}
				_, wait := e.start(t)
				r := wait()
				if c.ok {
					requireLoginRefused(t, r, "Approve this login in your browser: "+e.url+"/login/"+id)
					return
				}
				requireLoginRefused(t, r, "the server's login begin answer does not check out")
				if strings.Contains(r.stderr, "Approve this login in your browser") {
					t.Fatalf("a refused begin answer was offered:\n%s", r.stderr)
				}
			})
		}
	})
}

// TestLoginFlowFakeServer runs keyroster login end to end against the fake
// server. happy_path lands the certificate in the platform agent: a real
// ssh-agent on Linux and macOS, keyroster's own agent (winagent.Serve on a
// test pipe) on Windows. The other cases pin the order of the agent and
// the issuance (03-02): no usable agent means no begin and no certificate
// (E-IN-01), and the agent lifetime is computed at the add (E-IN-02).
func TestLoginFlowFakeServer(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		list := startLoginTestAgent(t)
		e := newLoginServer(t)
		stderr, wait := e.start(t)
		l := e.drive(t, stderr)
		r := wait()
		if r.code != 0 {
			t.Fatalf("keyroster login exit %d:\nstdout:\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
		}
		keys := list(t)
		found := false
		for _, k := range keys {
			pk, err := ssh.ParsePublicKey(k.Blob)
			if err != nil {
				continue
			}
			if c, ok := pk.(*ssh.Certificate); ok && bytes.Equal(c.Key.Marshal(), l.req.SubjectKey) && c.KeyId == k.Comment {
				found = true
			}
		}
		if !found {
			t.Fatalf("the agent lists no certificate for the login key (%d keys)", len(keys))
		}
		for _, want := range []string{"Logged in as alice: principals role:dev, role:ops, u:alice", "Serial: ", "Key ID: kr2/ca=user/sub=alice/"} {
			if !strings.Contains(r.stdout, want) {
				t.Fatalf("stdout lacks %q:\n%s", want, r.stdout)
			}
		}
		e.requireCalls(t, 1, 1)
	})
	t.Run("no_agent_no_begin", func(t *testing.T) {
		// No usable agent (Unix: SSH_AUTH_SOCK unset, the default seam;
		// Windows: Ensure's owner check fails): the login stops with the
		// agent instructions before it begins, so no begin and no redeem
		// reach the server and the signer issues nothing.
		e := newLoginServer(t)
		want := useUnusableLoginAgent(t)
		_, wait := e.start(t)
		r := wait()
		requireLoginRefused(t, r, want)
		e.requireCalls(t, 0, 0)
		if strings.Contains(r.stderr, "Approve this login") || strings.Contains(r.stdout, "Serial:") {
			t.Fatalf("a login without an agent went on:\nstdout:\n%s\nstderr:\n%s", r.stdout, r.stderr)
		}
	})
	// steppedClock fixes loginNow at a whole second T and returns arm:
	// after arm(d), the next reading of loginNow is still T and every
	// later one is T+d. The fake server arms it once it has built the
	// certificate, so checkLoginCert's reading is T and the reading for the
	// agent add is T+d: d stands for whatever time passes between the
	// check and the add.
	steppedClock := func(t *testing.T) (start time.Time, arm func(d time.Duration)) {
		t.Helper()
		start = useLoginClock(t)
		var mu sync.Mutex
		cur, step := start, time.Duration(0)
		armed := false
		loginNow = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			v := cur
			if armed {
				armed = false
				cur = cur.Add(step)
			}
			return v
		}
		return start, func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			armed, step = true, d
		}
	}
	// armAfterCert makes redeem return the honest certificate and arm the
	// clock after building it (the build reads the fake server's clock).
	armAfterCert := func(e *loginServer, arm func(time.Duration), d time.Duration) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.certFor = func(t *testing.T, l *fakeLogin) []byte {
			raw := e.honestCert(t, l)
			arm(d)
			return raw
		}
	}
	t.Run("lifetime_recomputed_at_add", func(t *testing.T) {
		start, arm := steppedClock(t)
		e := newLoginServer(t)
		a := useRecordingAgent(t)
		armAfterCert(e, arm, 4*time.Second)
		stderr, wait := e.start(t, "--role", "ops", "--ttl", "5m")
		e.drive(t, stderr)
		if r := wait(); r.code != 0 {
			t.Fatalf("login exit %d:\n%s", r.code, r.stderr)
		}
		adds := a.added()
		if len(adds) != 1 || adds[0].Certificate == nil {
			t.Fatalf("adds = %v, want one certificate add", adds)
		}
		// At the check the certificate had ValidBefore - (T + 1 s) left on
		// the server's clock (skew 0, plus checkLoginCert's extra second);
		// 4 s later, at the add, 4 s less.
		vb := int64(adds[0].Certificate.ValidBefore) //nolint:gosec // G115: a test certificate
		atCheck := vb - (start.Unix() + 1)
		if got, want := int64(adds[0].LifetimeSecs), atCheck-4; got != want {
			t.Fatalf("agent lifetime %d s, want %d s: the %d s left at the check minus the 4 s before the add", got, want, atCheck)
		}
		e.requireCalls(t, 1, 1)
	})
	t.Run("too_little_left_at_add_refused", func(t *testing.T) {
		// A 2-minute certificate has 119 s left at the check; 60 s later,
		// at the add, 59 s, below minLoginRemaining: nothing is added.
		_, arm := steppedClock(t)
		e := newLoginServer(t)
		a := useRecordingAgent(t)
		armAfterCert(e, arm, 60*time.Second)
		stderr, wait := e.start(t, "--role", "ops", "--ttl", "2m")
		e.drive(t, stderr)
		requireLoginRefused(t, wait(), fmt.Sprintf("the certificate does not check out (it has less than %d s left), so nothing was added to the agent", minLoginRemaining))
		if n := len(a.added()); n != 0 {
			t.Fatalf("agent adds = %d, want none", n)
		}
	})
	t.Run("agent_lost_after_preflight", func(t *testing.T) {
		// The agent answers the preflight List and then goes away. The
		// login was begun and redeemed, so the signer issued and logged a
		// certificate, but the add fails and the login exits non-zero:
		// the residual of E-IN-01, an unusable grant whose key dies with
		// this process.
		e := newLoginServer(t)
		prev := connectLoginAgent
		connectLoginAgent = func(context.Context) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer func() { _ = server.Close() }()
				var n [4]byte
				if _, err := io.ReadFull(server, n[:]); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, server, int64(n[0])<<24|int64(n[1])<<16|int64(n[2])<<8|int64(n[3])); err != nil {
					return
				}
				// SSH_AGENT_IDENTITIES_ANSWER (12) with no keys.
				_, _ = server.Write([]byte{0, 0, 0, 5, 12, 0, 0, 0, 0})
			}()
			return client, nil
		}
		t.Cleanup(func() { connectLoginAgent = prev })
		stderr, wait := e.start(t)
		e.drive(t, stderr)
		requireLoginRefused(t, wait(), "the agent refused the key with a lifetime constraint; not retrying without it")
		e.requireCalls(t, 1, 1)
	})
}

// lastLine returns the last non-empty line of s.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// requireNoRawControl fails if s holds a control or format character
// other than a newline.
func requireNoRawControl(t *testing.T, s string) {
	t.Helper()
	for _, r := range s {
		if r != '\n' && !unicode.IsGraphic(r) {
			t.Fatalf("stderr carries the raw peer character %U:\n%s", r, s)
		}
	}
}

// TestLoginPeerText: text the server chooses never reaches keyroster
// login's stderr raw (T-02-93), and the evaluation-only banner shows under
// software custody (KEY-06).
func TestLoginPeerText(t *testing.T) {
	const forged = "\x1b[2Jrun keyroster init --force\r"
	t.Run("options_error_escaped", func(t *testing.T) {
		e := newLoginServer(t)
		useRecordingAgent(t)
		e.override[loginOptionsRoute] = func(w http.ResponseWriter) {
			e.writeJSON(w, http.StatusInternalServerError, serverclient.APIError{Error: forged})
		}
		_, wait := e.start(t)
		r := wait()
		requireNoRawControl(t, r.stderr)
		if r.code == 0 || !strings.Contains(lastLine(r.stderr), "[peer text") {
			t.Fatalf("exit %d, stderr %q; want the server text only as an escaped excerpt", r.code, r.stderr)
		}
	})
	t.Run("begin_url_not_echoed", func(t *testing.T) {
		e := newLoginServer(t)
		useRecordingAgent(t)
		id := strings.Repeat("ab", 16)
		e.override[loginBeginRoute] = func(w http.ResponseWriter) {
			e.writeJSON(w, http.StatusOK, loginBeginAnswer{LoginID: id, ApprovalURL: e.url + "/login/" + id + forged, ExpiresAt: e.now().Add(240 * time.Second).Unix()})
		}
		_, wait := e.start(t)
		r := wait()
		requireNoRawControl(t, r.stderr)
		requireLoginRefused(t, r, "the server's login begin answer does not check out")
		if strings.Contains(r.stderr, "keyroster init --force") || strings.Contains(r.stderr, "Approve this login in your browser") {
			t.Fatalf("a refused begin answer was echoed or offered:\n%s", r.stderr)
		}
	})
	t.Run("unknown_signer_refusal_excerpt", func(t *testing.T) {
		e := newLoginServer(t)
		useRecordingAgent(t)
		e.redeemHook = func(w http.ResponseWriter) {
			e.writeJSON(w, http.StatusForbidden, serverclient.APIError{Error: forged})
		}
		stderr, wait := e.start(t)
		e.drive(t, stderr)
		r := wait()
		requireNoRawControl(t, r.stderr)
		last := lastLine(r.stderr)
		if r.code == 0 || !strings.Contains(last, "refused by the signer:") || !strings.Contains(last, "[peer text") || !strings.Contains(last, "run keyroster login again") {
			t.Fatalf("exit %d, last stderr line %q", r.code, last)
		}
	})
	t.Run("software_custody_banner", func(t *testing.T) {
		e := newLoginServer(t)
		useRecordingAgent(t)
		e.custom = softwareCustody
		stderr, wait := e.start(t)
		e.drive(t, stderr)
		r := wait()
		if r.code != 0 || !strings.Contains(r.stderr, custodytext.SoftwareCABanner([]string{"user", "host", "machine", "ops", "log"})) {
			t.Fatalf("exit %d; stderr lacks the software custody banner:\n%s", r.code, r.stderr)
		}
	})
}
