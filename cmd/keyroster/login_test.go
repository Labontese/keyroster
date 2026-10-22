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
	serial  uint64
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
}

// params are the honest parameters for l.
func (e *loginServer) params(t *testing.T, l *fakeLogin) certParams {
	t.Helper()
	k, err := ssh.ParsePublicKey(l.req.SubjectKey)
	if err != nil {
		t.Error(err)
	}
	return certParams{ca: e.ca, key: k, principals: l.req.Principals, subject: l.req.Subject, now: e.now(),
		validFor: time.Duration(l.req.ValidForSeconds) * time.Second}
}

// build issues a certificate with p through cert.Build.
func (e *loginServer) build(t *testing.T, l *fakeLogin, p certParams) []byte {
	t.Helper()
	roles := l.req.Roles
	if len(roles) == 0 {
		roles = []string{"dev", "ops"}
	}
	e.mu.Lock()
	e.serial++
	ser := e.serial
	e.mu.Unlock()
	c, err := cert.Build(cert.Request{
		Profile: cert.DefaultUserProfile(), Subject: p.key, Principals: p.principals, Now: p.now, ValidFor: p.validFor,
		KeyID:  cert.KeyID{CA: "user", Subject: p.subject, Request: hex.EncodeToString(l.req.RequestID[:]), Policy: 1, Directory: 1, Roles: roles, Serial: ser},
		Serial: ser,
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
	}{
		{"cert_other_ca_refused", "not signed by the user CA", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			_, k, _ := ed25519.GenerateKey(rand.Reader)
			p.ca, _ = ssh.NewSignerFromKey(k)
			return nil
		}},
		{"cert_bad_signature_refused", "CA signature or validity", nil},
		{"cert_other_key_refused", "for another key", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			pub, _, _ := ed25519.GenerateKey(rand.Reader)
			p.key, _ = ssh.NewPublicKey(pub)
			return nil
		}},
		{"cert_extra_principal_refused", "principals are not the ones requested", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.principals = append(append([]string(nil), p.principals...), "root")
			return nil
		}},
		{"cert_other_user_refused", "key ID does not name this user", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.subject = "bob"
			return nil
		}},
		{"cert_span_ttl_301_refused", "valid for longer than requested", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.validFor += time.Second
			return nil
		}},
		{"cert_59s_remaining_refused", "less than 60 s left", func(_ *testing.T, _ *fakeLogin, p *certParams) []byte {
			p.now = p.now.Add(-p.validFor + 59*time.Second)
			return nil
		}},
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
			stderr, wait := e.start(t)
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
}

// TestLoginFlowFakeServer runs keyroster login end to end against the fake
// server, with the certificate landing in the platform agent: a real
// ssh-agent on Linux and macOS, keyroster's own agent (winagent.Serve on a
// test pipe) on Windows.
func TestLoginFlowFakeServer(t *testing.T) {
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
