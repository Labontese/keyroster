package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// agentEnv is a Server with an agent listener port, a policy with or
// without pop.hosts, a real trust bundle for copyInstallation, a fake
// signer in chain mode and a published KRL.
type agentEnv struct {
	s     *Server
	fake  *fakeSigner
	clock *testClock
	log   *logBuffer
	admin ssh.Signer
	ops   ssh.Signer
	dirs  [][]byte
}

func newAgentEnv(t *testing.T, popHosts bool) *agentEnv {
	t.Helper()
	admin, ops := newSigner(t), newSigner(t)
	st := testStatus(t, "agent", 0)
	pol, err := trust.ParsePolicy(adminPolicy(t, admin))
	if err != nil {
		t.Fatal(err)
	}
	if popHosts {
		pol.PoP = &trust.PoPPolicy{Hosts: true}
	}
	if st.Policy, err = pol.Canonical(); err != nil {
		t.Fatal(err)
	}
	st.Bundle = copyBundle(t, ops, st.Policy)
	fake := newFakeSigner(st)
	fake.setChain(nil, nil)
	fake.krl = krlDoc(t, ops, copyInstallation, 100, "krl version 100")
	clock := &testClock{now: t0}
	logger, buf := newLogger()
	s, err := newServer(Config{RPID: testRPID, Clock: clock.Now, Logger: logger, DB: openTestDB(t), AgentPort: 8443,
		Limits: Limits{AdminPerMinute: 100000, AdminBurst: 100000}}, fake)
	if err != nil {
		t.Fatal(err)
	}
	s.agentLimit = newLimiter(100000, 100000, 0, 0)
	return &agentEnv{s: s, fake: fake, clock: clock, log: buf, admin: admin, ops: ops}
}

// admin sends an admin-signed request to the main handler.
func (e *agentEnv) adminDo(t *testing.T, method, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return serve(e.s.Handler(), signedReq(t, e.admin, method, path, path, body, e.clock.Now()))
}

// mint mints a join token for name with ttl seconds.
func (e *agentEnv) mint(t *testing.T, name string, ttl int64) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(serverclient.JoinTokenRequest{ExpectedName: name, TTLSeconds: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return e.adminDo(t, http.MethodPost, serverclient.AdminJoinTokensPath, body)
}

// mustMint mints a token and returns its answer.
func (e *agentEnv) mustMint(t *testing.T, name string, ttl int64) serverclient.JoinTokenAnswer {
	t.Helper()
	rec := e.mint(t, name, ttl)
	var ans serverclient.JoinTokenAnswer
	if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &ans) != nil {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	return ans
}

// agentID is an agent's TLS identity: its key and self-signed certificate.
type agentID struct {
	key  ed25519.PrivateKey
	cert *x509.Certificate
	spki []byte // SHA-256 of the SPKI
}

func newAgentID(t *testing.T) agentID {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "keyroster-agent"}, NotBefore: t0.Add(-time.Hour), NotAfter: t0.AddDate(100, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return agentID{key: key, cert: c, spki: sum[:]}
}

// tlsCert is id as a client certificate.
func (id agentID) tlsCert() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{id.cert.Raw}, PrivateKey: id.key}
}

// agentDo sends a request to the agent handler as id.
func (e *agentEnv) agentDo(t *testing.T, id agentID, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "https://"+testRPID+":8443"+target, bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{id.cert}}
	return serve(e.s.AgentHandler(), req)
}

// hostSigners are n fresh Ed25519 host keys.
func hostSigners(t *testing.T, n int) []ssh.Signer {
	t.Helper()
	var out []ssh.Signer
	for range n {
		out = append(out, newSigner(t))
	}
	return out
}

// enrollBody is a valid enrollment of id with token, every host key in
// hosts signing the proof of possession.
func enrollBody(t *testing.T, id agentID, token string, hosts []ssh.Signer) []byte {
	t.Helper()
	raw, err := join.DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	facts := enroll.Facts{OSID: "debian", OSVersionID: "13", Hostname: "web1"}
	fsum, err := enroll.FactsSHA256(facts)
	if err != nil {
		t.Fatal(err)
	}
	var pubs []ssh.PublicKey
	for _, h := range hosts {
		pubs = append(pubs, h.PublicKey())
	}
	p := enroll.PoP{Domain: enroll.Domain, InstallationID: copyInstallation, TokenSHA256: join.TokenSHA256(raw),
		IdentitySPKISHA256: hex.EncodeToString(id.spki), HostKeys: enroll.SortHostKeys(pubs), FactsSHA256: fsum}
	ordered := make([]ssh.Signer, 0, len(hosts))
	for _, k := range p.HostKeys {
		for _, h := range hosts {
			if trust.FormatKey(h.PublicKey()) == k {
				ordered = append(ordered, h)
			}
		}
	}
	sigs, err := enroll.Sign(p, ordered)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(serverclient.AgentEnrollRequest{Token: token, HostKeys: p.HostKeys, Sigs: sigs, Facts: facts})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// enroll posts an enrollment.
func (e *agentEnv) enroll(t *testing.T, id agentID, token string, hosts []ssh.Signer) *httptest.ResponseRecorder {
	t.Helper()
	return e.agentDo(t, id, http.MethodPost, serverclient.AgentEnrollPath, enrollBody(t, id, token, hosts))
}

// tokenUsed reports whether the join token's row is used.
func (e *agentEnv) tokenUsed(t *testing.T, token string) bool {
	t.Helper()
	raw, err := join.DecodeToken(token)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	used, err := e.s.db.JoinTokenUsed(t.Context(), h[:])
	if err != nil {
		t.Fatal(err)
	}
	return used
}

// hostEntry is an active host of host group lab with the keys of hosts.
func hostEntry(name string, hosts []ssh.Signer) directory.Host {
	var pubs []ssh.PublicKey
	for _, h := range hosts {
		pubs = append(pubs, h.PublicKey())
	}
	return directory.Host{Name: name, HostGroup: "lab", Keys: enroll.SortHostKeys(pubs), Principals: []string{name}, Status: directory.StatusActive}
}

// installDir installs the next directory version with hosts, as the
// signer would after an admin's approval, and drops the status cache.
func (e *agentEnv) installDir(t *testing.T, hosts ...directory.Host) uint64 {
	t.Helper()
	d := &directory.Directory{Version: uint64(len(e.dirs) + 1), Prev: trust.GenesisPrev, Users: []directory.User{}, Groups: []directory.Group{},
		Roles:          []directory.Role{{Name: "ops", Principals: []string{"role:ops"}, MaxTTLSeconds: 3600, Extensions: []string{}, Users: []string{}, Groups: []string{}}},
		HostGroups:     []directory.HostGroup{{Name: "lab", Accounts: []directory.AccountMap{{Account: "deploy", Roles: []string{"ops"}}}}},
		Hosts:          hosts,
		InstallationID: copyInstallation}
	if len(e.dirs) > 0 {
		d.Prev = trust.SHA256Hex(e.dirs[len(e.dirs)-1])
	}
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Parse(doc); err != nil {
		t.Fatalf("test directory: %v", err)
	}
	e.fake.setChain(doc, []byte("admin sigs over version "+strconv.Itoa(len(e.dirs)+1)))
	e.dirs = append(e.dirs, doc)
	e.s.dropStatus()
	return d.Version
}

// approvedAgent enrolls a new agent with one host key and approves it.
func (e *agentEnv) approvedAgent(t *testing.T) (agentID, []ssh.Signer) {
	t.Helper()
	id, hosts := newAgentID(t), hostSigners(t, 1)
	if rec := e.enroll(t, id, e.mustMint(t, "web1", 0).Token, hosts); rec.Code != http.StatusAccepted {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	e.installDir(t, hostEntry("web1", hosts))
	return id, hosts
}

func apiError(rec *httptest.ResponseRecorder) string {
	var e serverclient.APIError
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	return e.Error
}

// TestHostPoPRequired (owner decision 2026-10-24, REVIEWS L1488): while
// the installed policy lacks pop.hosts, minting a join token, enrolling
// and listing the pending hosts each refuse 409 host_pop_not_enabled,
// before any token row is written or used; with pop.hosts all three work.
func TestHostPoPRequired(t *testing.T) {
	t.Run("join_token_refused", func(t *testing.T) {
		e := newAgentEnv(t, false)
		rec := e.mint(t, "web1", 0)
		if rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrHostPoPNotEnable {
			t.Fatalf("mint without pop.hosts: %d %s", rec.Code, rec.Body.String())
		}
		if n, err := e.s.db.CountJoinTokens(t.Context()); err != nil || n != 0 {
			t.Fatalf("%d join token rows (%v) after the refusal, want 0", n, err)
		}
	})
	t.Run("enroll_refused", func(t *testing.T) {
		e := newAgentEnv(t, false)
		raw := make([]byte, join.TokenBytes)
		raw[0] = 1
		h := sha256.Sum256(raw)
		if err := e.s.db.CreateJoinToken(t.Context(), h[:], "web1", "root-admin", t0.Add(time.Hour).UnixMicro()); err != nil {
			t.Fatal(err)
		}
		token := join.EncodeToken(raw)
		rec := e.enroll(t, newAgentID(t), token, hostSigners(t, 1))
		if rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrHostPoPNotEnable || e.tokenUsed(t, token) {
			t.Fatalf("enroll without pop.hosts: %d %s, token used %t", rec.Code, rec.Body.String(), e.tokenUsed(t, token))
		}
	})
	t.Run("pending_refused", func(t *testing.T) {
		e := newAgentEnv(t, false)
		rec := e.adminDo(t, http.MethodGet, serverclient.AdminPendingHostsPath, nil)
		if rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrHostPoPNotEnable {
			t.Fatalf("pending without pop.hosts: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("all_succeed_with_pop_hosts", func(t *testing.T) {
		e := newAgentEnv(t, true)
		ans := e.mustMint(t, "web1", 0)
		if ans.AgentPort != 8443 || ans.ExpiresAt != join.FormatExpiry(t0.Add(30*time.Minute)) {
			t.Fatalf("mint answer %+v", ans)
		}
		if rec := e.enroll(t, newAgentID(t), ans.Token, hostSigners(t, 2)); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
		}
		rec := e.adminDo(t, http.MethodGet, serverclient.AdminPendingHostsPath, nil)
		var p serverclient.PendingHostsAnswer
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &p) != nil || len(p.Hosts) != 1 || p.Hosts[0].ExpectedName != "web1" || len(p.Hosts[0].HostKeys) != 2 {
			t.Fatalf("pending: %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(e.log.String(), ans.Token) {
			t.Fatal("the server logged the join token")
		}
	})
}

// TestAgentEnroll pins enrollment's edges (AGENT-01): the token's expiry
// to the second on the server's clock, its single use, the lifetime cap,
// host keys and identities in use, and a proof of possession that does
// not verify, each refused with the token left as it was.
func TestAgentEnroll(t *testing.T) {
	t.Run("expiry_boundary", func(t *testing.T) {
		e := newAgentEnv(t, true)
		ans := e.mustMint(t, "web1", 60)
		id, hosts := newAgentID(t), hostSigners(t, 1)
		e.clock.set(t0.Add(60 * time.Second))
		if rec := e.enroll(t, id, ans.Token, hosts); rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrTokenExpired || e.tokenUsed(t, ans.Token) {
			t.Fatalf("at expires_at: %d %s", rec.Code, rec.Body.String())
		}
		e.clock.set(t0.Add(59 * time.Second))
		if rec := e.enroll(t, id, ans.Token, hosts); rec.Code != http.StatusAccepted || !e.tokenUsed(t, ans.Token) {
			t.Fatalf("one second before expires_at: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("second_use_refused", func(t *testing.T) {
		e := newAgentEnv(t, true)
		ans := e.mustMint(t, "web1", 0)
		if rec := e.enroll(t, newAgentID(t), ans.Token, hostSigners(t, 1)); rec.Code != http.StatusAccepted {
			t.Fatalf("first use: %d %s", rec.Code, rec.Body.String())
		}
		if rec := e.enroll(t, newAgentID(t), ans.Token, hostSigners(t, 1)); rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrTokenUsed {
			t.Fatalf("second use: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("unknown_token_refused", func(t *testing.T) {
		e := newAgentEnv(t, true)
		if rec := e.enroll(t, newAgentID(t), join.EncodeToken(make([]byte, join.TokenBytes)), hostSigners(t, 1)); rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrTokenUnknown {
			t.Fatalf("an unminted token: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("ttl_above_hour_refused", func(t *testing.T) {
		e := newAgentEnv(t, true)
		if rec := e.mint(t, "web1", serverclient.MaxJoinTokenTTLSeconds+1); rec.Code != http.StatusBadRequest || apiError(rec) != serverclient.AdminErrTTL {
			t.Fatalf("ttl 3601: %d %s", rec.Code, rec.Body.String())
		}
		if ans := e.mustMint(t, "web1", serverclient.MaxJoinTokenTTLSeconds); ans.ExpiresAt != join.FormatExpiry(t0.Add(time.Hour)) {
			t.Fatalf("ttl 3600: %+v", ans)
		}
		if n, err := e.s.db.CountJoinTokens(t.Context()); err != nil || n != 1 {
			t.Fatalf("%d join tokens, want 1", n)
		}
	})
	t.Run("no_agent_listener_refused", func(t *testing.T) {
		e := newAgentEnv(t, true)
		e.s.agentPort = 0
		if rec := e.mint(t, "web1", 0); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AdminErrNoAgentListener {
			t.Fatalf("mint without an agent listener: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("host_keys_in_use", func(t *testing.T) {
		e := newAgentEnv(t, true)
		inDir := hostSigners(t, 1)
		e.installDir(t, hostEntry("old", inDir))
		ans := e.mustMint(t, "web1", 0)
		if rec := e.enroll(t, newAgentID(t), ans.Token, append(hostSigners(t, 1), inDir...)); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrHostKeysInUse || e.tokenUsed(t, ans.Token) {
			t.Fatalf("a key of a directory host: %d %s", rec.Code, rec.Body.String())
		}
		pendingKeys := hostSigners(t, 1)
		if rec := e.enroll(t, newAgentID(t), ans.Token, pendingKeys); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
		}
		other := e.mustMint(t, "web2", 0)
		if rec := e.enroll(t, newAgentID(t), other.Token, pendingKeys); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrHostKeysInUse || e.tokenUsed(t, other.Token) {
			t.Fatalf("a key of another pending agent: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("identity_in_use", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id := newAgentID(t)
		if rec := e.enroll(t, id, e.mustMint(t, "web1", 0).Token, hostSigners(t, 1)); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
		}
		ans := e.mustMint(t, "web2", 0)
		if rec := e.enroll(t, id, ans.Token, hostSigners(t, 1)); rec.Code != http.StatusConflict || apiError(rec) != serverclient.AgentErrIdentityInUse || e.tokenUsed(t, ans.Token) {
			t.Fatalf("an enrolled identity: %d %s", rec.Code, rec.Body.String())
		}
	})
	t.Run("pop_invalid_refused", func(t *testing.T) {
		e := newAgentEnv(t, true)
		ans := e.mustMint(t, "web1", 0)
		id := newAgentID(t)
		// Signed for another identity: the server builds the statement
		// from the TLS identity, so the signatures do not verify.
		body := enrollBody(t, newAgentID(t), ans.Token, hostSigners(t, 1))
		if rec := e.agentDo(t, id, http.MethodPost, serverclient.AgentEnrollPath, body); rec.Code != http.StatusForbidden || apiError(rec) != serverclient.AgentErrPoPInvalid || e.tokenUsed(t, ans.Token) {
			t.Fatalf("a proof for another identity: %d %s", rec.Code, rec.Body.String())
		}
		for _, bad := range []string{`{}`, `{"token":"x"}`, strings.Repeat(" ", maxAgentEnrollBody+1), `{"token":"` + ans.Token + `","host_keys":[],"sigs":[],"facts":{},"extra":1}`} {
			if rec := e.agentDo(t, id, http.MethodPost, serverclient.AgentEnrollPath, []byte(bad)); rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
				t.Errorf("body %.20q: %d %s", bad, rec.Code, rec.Body.String())
			}
		}
		if e.tokenUsed(t, ans.Token) {
			t.Fatal("a refused enrollment used the token")
		}
	})
	t.Run("pending_lists_only_unapproved", func(t *testing.T) {
		e := newAgentEnv(t, true)
		e.approvedAgent(t)
		if rec := e.enroll(t, newAgentID(t), e.mustMint(t, "web2", 0).Token, hostSigners(t, 1)); rec.Code != http.StatusAccepted {
			t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
		}
		rec := e.adminDo(t, http.MethodGet, serverclient.AdminPendingHostsPath, nil)
		var p serverclient.PendingHostsAnswer
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &p) != nil || len(p.Hosts) != 1 || p.Hosts[0].ExpectedName != "web2" {
			t.Fatalf("pending: %d %s", rec.Code, rec.Body.String())
		}
	})
}

// agentTLSServer serves e's agent handler over real TLS with
// AgentTLSConfig, and returns its URL and the pool that trusts it.
func agentTLSServer(t *testing.T, e *agentEnv) (string, *x509.CertPool) {
	t.Helper()
	ts := httptest.NewUnstartedServer(e.s.AgentHandler())
	ts.TLS = AgentTLSConfig(nil)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return ts.URL, pool
}

// get GETs the state with certs, a fresh connection each time.
func tlsGet(url string, pool *x509.CertPool, certs ...tls.Certificate) (int, string, error) {
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: certs}}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	resp, err := c.Get(url + serverclient.AgentStatePath)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var b bytes.Buffer
	_, _ = b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String(), nil
}

// TestAgentListenerRequiresClientCert (AGENT-02, T-03-46): the agent
// listener refuses a connection without a client certificate, or with
// one that is not a self-signed Ed25519 certificate, at the handshake;
// an unenrolled identity gets 403 unknown_agent, an enrolled one 403
// not_approved until its host entry is installed, then 200.
func TestAgentListenerRequiresClientCert(t *testing.T) {
	e := newAgentEnv(t, true)
	url, pool := agentTLSServer(t, e)
	if _, _, err := tlsGet(url, pool); err == nil {
		t.Fatal("a connection without a client certificate was accepted")
	}
	// An RSA self-signed certificate.
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "keyroster-agent"}, NotBefore: t0, NotAfter: t0.AddDate(1, 0, 0)}
	rder, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tlsGet(url, pool, tls.Certificate{Certificate: [][]byte{rder}, PrivateKey: rk}); err == nil {
		t.Fatal("an RSA client certificate was accepted")
	}
	// An Ed25519 certificate signed by another key (a CA).
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = caPub
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "agent CA"}, NotBefore: t0, NotAfter: t0.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true}
	cder, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, leafPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tlsGet(url, pool, tls.Certificate{Certificate: [][]byte{cder}, PrivateKey: leafKey}); err == nil {
		t.Fatal("a CA-signed client certificate was accepted")
	}
	id := newAgentID(t)
	if code, body, err := tlsGet(url, pool, id.tlsCert()); err != nil || code != http.StatusForbidden || !strings.Contains(body, serverclient.AgentErrUnknown) {
		t.Fatalf("an unenrolled identity: %d %s %v", code, body, err)
	}
	hosts := hostSigners(t, 1)
	if rec := e.enroll(t, id, e.mustMint(t, "web1", 0).Token, hosts); rec.Code != http.StatusAccepted {
		t.Fatalf("enroll: %d %s", rec.Code, rec.Body.String())
	}
	if code, body, err := tlsGet(url, pool, id.tlsCert()); err != nil || code != http.StatusForbidden || !strings.Contains(body, serverclient.AgentErrNotApproved) {
		t.Fatalf("an enrolled, unapproved identity: %d %s %v", code, body, err)
	}
	e.installDir(t, hostEntry("web1", hosts))
	if code, body, err := tlsGet(url, pool, id.tlsCert()); err != nil || code != http.StatusOK {
		t.Fatalf("an approved identity: %d %s %v", code, body, err)
	}
	// A disabled host entry, or one with other keys, approves nothing.
	h := hostEntry("web1", hosts)
	h.Status = directory.StatusDisabled
	e.installDir(t, h)
	if code, _, err := tlsGet(url, pool, id.tlsCert()); err != nil || code != http.StatusForbidden {
		t.Fatalf("a disabled host: %d %v", code, err)
	}
	e.installDir(t, hostEntry("web1", append(hostSigners(t, 1), hosts...)))
	if code, _, err := tlsGet(url, pool, id.tlsCert()); err != nil || code != http.StatusForbidden {
		t.Fatalf("a host entry with one more key: %d %v", code, err)
	}
}

// TestBrowserListenerUnchanged (T-03-47): the main listener asks for no
// client certificate and serves no agent route.
func TestBrowserListenerUnchanged(t *testing.T) {
	if c := BrowserTLSConfig(nil); c.ClientAuth != tls.NoClientCert || c.VerifyConnection != nil || c.VerifyPeerCertificate != nil || c.MinVersion != tls.VersionTLS13 {
		t.Fatalf("browser TLS config %+v", c)
	}
	e := newAgentEnv(t, true)
	id, _ := e.approvedAgent(t)
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		for _, p := range []string{serverclient.AgentStatePath, serverclient.AgentEnrollPath} {
			req := httptest.NewRequest(m, "https://"+testRPID+p, nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{id.cert}}
			if rec := serve(e.s.Handler(), req); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s on the main handler: %d", m, p, rec.Code)
			}
		}
	}
	// And the agent handler serves no browser route.
	for _, p := range []string{"/", "/healthz", serverclient.TrustPath, serverclient.KRLPath, serverclient.AdminJoinTokensPath} {
		if rec := e.agentDo(t, id, http.MethodGet, p, nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s on the agent handler: %d", p, rec.Code)
		}
	}
}

// TestAgentMuxRoutes (AGENT-02): the agent mux registers exactly the
// closed operation set, no pattern of the main mux, and no sign-in
// keyword.
func TestAgentMuxRoutes(t *testing.T) {
	e := newAgentEnv(t, true)
	want := []string{"POST " + serverclient.AgentEnrollPath, "GET " + serverclient.AgentStatePath}
	if !slices.Equal(e.s.agentPatterns, want) {
		t.Fatalf("agent patterns %q, want %q", e.s.agentPatterns, want)
	}
	for _, p := range e.s.agentPatterns {
		if slices.Contains(e.s.patterns, p) || strings.Contains(p, "/api/v1/admin/") {
			t.Errorf("agent pattern %q is also a main route or an admin route", p)
		}
		for _, k := range signInKeywords {
			if strings.Contains(strings.ToLower(p), k) {
				t.Errorf("agent pattern %q contains %q", p, k)
			}
		}
	}
	for _, p := range e.s.patterns {
		if strings.Contains(p, "/api/v1/agent/") {
			t.Errorf("the main mux registers agent route %q", p)
		}
	}
}

// decodeState decodes and checks a state answer.
func decodeState(t *testing.T, rec *httptest.ResponseRecorder) *serverclient.AgentStateResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("state: %d %s", rec.Code, rec.Body.String())
	}
	var r serverclient.AgentStateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("state answer: %v", err)
	}
	if err := r.Check(); err != nil {
		t.Fatalf("state answer: %v", err)
	}
	if rec.Header().Get(serverclient.CustodyHeader) == "" {
		t.Fatal("the state answer has no custody header")
	}
	return &r
}

func versionsOf[T any](items []T, v func(T) uint64) []uint64 {
	var out []uint64
	for _, x := range items {
		out = append(out, v(x))
	}
	return out
}

func bundleVersions(r *serverclient.AgentStateResponse) []uint64 {
	return versionsOf(r.Bundles, func(b serverclient.AgentBundle) uint64 { return b.Version })
}

func dirVersions(r *serverclient.AgentStateResponse) []uint64 {
	return versionsOf(r.Directories, func(d serverclient.AgentDirectory) uint64 { return d.Version })
}

// seq is from..to.
func seq(from, to uint64) []uint64 {
	var out []uint64
	for v := from; v <= to; v++ {
		out = append(out, v)
	}
	return out
}

// TestAgentState pins the state answer (AGENT-02 edges, F12): the
// current state with no versions, every later version in ascending order
// with them (catching up through the signer's chain calls), at most 16 of
// each, a malformed query refused, and the byte budget filled in order
// with more set when an item is left out.
func TestAgentState(t *testing.T) {
	state := func(t *testing.T, e *agentEnv, id agentID, q string) *serverclient.AgentStateResponse {
		t.Helper()
		return decodeState(t, e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath+q, nil))
	}
	t.Run("no_versions_current_only", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, hosts := e.approvedAgent(t)
		e.installDir(t, hostEntry("web1", hosts))
		r := state(t, e, id, "")
		if !slices.Equal(bundleVersions(r), []uint64{1}) || !slices.Equal(dirVersions(r), []uint64{2}) || r.KRL == nil || r.KRL.Version != 100 || r.More {
			t.Fatalf("current only: bundles %v, directories %v, KRL %+v, more %t", bundleVersions(r), dirVersions(r), r.KRL, r.More)
		}
		if !bytes.Equal(r.Directories[0].Directory, e.dirs[1]) || !bytes.Equal(r.Bundles[0].Bundle, e.fake.statusNow().Bundle) {
			t.Fatal("the items are not the current documents")
		}
	})
	t.Run("versions_since", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, hosts := e.approvedAgent(t)
		e.installDir(t, hostEntry("web1", hosts))
		r := state(t, e, id, "?bundle=1&directory=1&krl=99")
		if len(r.Bundles) != 0 || !slices.Equal(dirVersions(r), []uint64{2}) || r.KRL == nil || r.KRL.Version != 100 {
			t.Fatalf("since 1/1/99: %v %v %+v", bundleVersions(r), dirVersions(r), r.KRL)
		}
		r = state(t, e, id, "?bundle=1&directory=2&krl=100")
		if len(r.Bundles)+len(r.Directories) != 0 || r.KRL != nil || r.More {
			t.Fatalf("up to date: %+v", r)
		}
		// An agent ahead of the server (a restored signer) gets nothing.
		if r = state(t, e, id, "?bundle=5&directory=9&krl=200"); len(r.Bundles)+len(r.Directories) != 0 || r.KRL != nil {
			t.Fatalf("ahead of the server: %+v", r)
		}
	})
	t.Run("malformed_version_400", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, _ := e.approvedAgent(t)
		for _, q := range []string{"?bundle=", "?bundle=0", "?bundle=01", "?bundle=x", "?bundle=-1", "?bundle=1&bundle=2", "?other=1",
			"?krl=18446744073709551616", "?directory=1.5", "?bundle"} {
			if rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath+q, nil); rec.Code != http.StatusBadRequest {
				t.Errorf("query %q: %d %s", q, rec.Code, rec.Body.String())
			}
		}
		if r := state(t, e, id, "?krl=18446744073709551615"); r.KRL != nil {
			t.Fatal("the largest version names no newer KRL")
		}
	})
	// catchUp: a host 2 bundle versions and 3 directory versions behind.
	catchUp := func(t *testing.T) (*agentEnv, agentID) {
		t.Helper()
		e := newAgentEnv(t, true)
		id, hosts := e.approvedAgent(t)
		for range 3 {
			e.installDir(t, hostEntry("web1", hosts))
		}
		st := e.fake.statusNow()
		e.fake.bundles = map[uint64]*wire.GetBundleResponse{}
		for v := uint64(1); v <= 2; v++ {
			e.fake.bundles[v] = &wire.GetBundleResponse{Version: v, Bundle: []byte("bundle " + strconv.FormatUint(v, 10)), BundleSigs: []byte("sigs"),
				Policy: st.Policy, PolicySigs: []byte("policy sigs")}
		}
		next := *st
		next.BundleVersion = 3
		e.fake.setStatus(&next, nil)
		e.s.dropStatus()
		return e, id
	}
	t.Run("catch_up_ascending", func(t *testing.T) {
		e, id := catchUp(t)
		r := state(t, e, id, "?bundle=1&directory=1&krl=100")
		if !slices.Equal(bundleVersions(r), []uint64{2, 3}) || !slices.Equal(dirVersions(r), []uint64{2, 3, 4}) || r.More {
			t.Fatalf("catch-up: bundles %v, directories %v, more %t", bundleVersions(r), dirVersions(r), r.More)
		}
		if string(r.Bundles[0].Bundle) != "bundle 2" || !bytes.Equal(r.Directories[1].Directory, e.dirs[2]) || e.fake.count("GetBundle") != 1 || e.fake.count("GetDirectoryVersion") != 2 {
			t.Fatalf("the chain items are not the signer's versions (GetBundle %d, GetDirectoryVersion %d calls)", e.fake.count("GetBundle"), e.fake.count("GetDirectoryVersion"))
		}
	})
	t.Run("ascending_order", func(t *testing.T) {
		e, id := catchUp(t)
		rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath+"?bundle=1&directory=1", nil)
		r := decodeState(t, rec)
		if !slices.IsSorted(bundleVersions(r)) || !slices.IsSorted(dirVersions(r)) {
			t.Fatalf("not ascending: %v %v", bundleVersions(r), dirVersions(r))
		}
		// The kinds come in their fixed order: bundles, directories, KRL.
		body := rec.Body.String()
		if b, d, k := strings.Index(body, `"bundles"`), strings.Index(body, `"directories"`), strings.Index(body, `"krl"`); b < 0 || b > d || d > k {
			t.Fatalf("kinds out of order in %.80s", body)
		}
	})
	t.Run("signer_chain_failure_unavailable", func(t *testing.T) {
		e, id := catchUp(t)
		delete(e.fake.bundles, 2)
		if rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath+"?bundle=1", nil); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("a bundle the signer does not have: %d", rec.Code)
		}
	})
	t.Run("cap_16", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, hosts := e.approvedAgent(t)
		for range 19 {
			e.installDir(t, hostEntry("web1", hosts))
		}
		r := state(t, e, id, "?directory=1")
		if !slices.Equal(dirVersions(r), seq(2, 17)) || !r.More {
			t.Fatalf("19 versions behind: %v, more %t", dirVersions(r), r.More)
		}
	})
	t.Run("more_than_16_continues", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, hosts := e.approvedAgent(t)
		for range 20 {
			e.installDir(t, hostEntry("web1", hosts))
		}
		r := state(t, e, id, "?bundle=1&directory=1&krl=100")
		if !slices.Equal(dirVersions(r), seq(2, 17)) || !r.More {
			t.Fatalf("first answer: %v, more %t", dirVersions(r), r.More)
		}
		r = state(t, e, id, "?bundle=1&directory=17&krl=100")
		if !slices.Equal(dirVersions(r), seq(18, 21)) || r.More {
			t.Fatalf("second answer: %v, more %t", dirVersions(r), r.More)
		}
	})
	// fullSize is the encoded size of the full current answer, with the
	// budget out of the way.
	fullSize := func(t *testing.T, e *agentEnv, id agentID) int {
		t.Helper()
		e.s.agentStateBudget = math.MaxInt
		rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		if r := decodeState(t, rec); r.More || len(r.Bundles) != 1 || len(r.Directories) != 1 || r.KRL == nil {
			t.Fatalf("full answer %+v", r)
		}
		return rec.Body.Len()
	}
	t.Run("budget_exact_fits", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, _ := e.approvedAgent(t)
		n := fullSize(t, e, id)
		e.s.agentStateBudget = n
		rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		if r := decodeState(t, rec); r.More || r.KRL == nil || len(r.Bundles) != 1 || len(r.Directories) != 1 || rec.Body.Len() != n {
			t.Fatalf("budget %d = the full answer: %d bytes, more %t, KRL %v", n, rec.Body.Len(), r.More, r.KRL != nil)
		}
	})
	t.Run("budget_one_byte_short_defers_last", func(t *testing.T) {
		e := newAgentEnv(t, true)
		id, _ := e.approvedAgent(t)
		n := fullSize(t, e, id)
		e.s.agentStateBudget = n - 1
		rec := e.agentDo(t, id, http.MethodGet, serverclient.AgentStatePath, nil)
		r := decodeState(t, rec)
		if !r.More || r.KRL != nil || len(r.Bundles) != 1 || len(r.Directories) != 1 || rec.Body.Len() > n-1 {
			t.Fatalf("budget %d: %d bytes, more %t, KRL %v", n-1, rec.Body.Len(), r.More, r.KRL != nil)
		}
		// A budget below any item still carries the first one.
		e.s.agentStateBudget = 1
		if r := state(t, e, id, ""); len(r.Bundles) != 1 || len(r.Directories) != 0 || r.KRL != nil || !r.More {
			t.Fatalf("budget 1: %+v", r)
		}
	})
	t.Run("largest_items_fit_budget", func(t *testing.T) {
		// The three largest single items, each at its cap: a KRL document
		// of krl.MaxKRL, krl.MaxManifest and krl.MaxManifestSig bytes, a
		// directory of wire.MaxDirectory with wire.MaxDirectorySigs, and a
		// bundle and policy of wire.MaxStatusFrame together.
		big := func(n int) []byte { return bytes.Repeat([]byte{0xff}, n) }
		k := &serverclient.AgentKRL{Version: math.MaxUint64, KRL: big(krl.MaxKRL), Manifest: big(krl.MaxManifest), Sig: big(krl.MaxManifestSig)}
		d := serverclient.AgentDirectory{Version: math.MaxUint64, Directory: big(wire.MaxDirectory), Sigs: big(wire.MaxDirectorySigs)}
		b := serverclient.AgentBundle{Version: math.MaxUint64, PolicyVersion: math.MaxUint64, Bundle: big(wire.MaxStatusFrame - 3), BundleSigs: big(1), Policy: big(1), PolicySigs: big(1)}
		kj, _ := json.Marshal(k)
		dj, _ := json.Marshal(d)
		bj, _ := json.Marshal(b)
		if len(kj) > krl.MaxKRLResponse {
			t.Fatalf("a maximum KRL item is %d bytes, above its share krl.MaxKRLResponse %d", len(kj), krl.MaxKRLResponse)
		}
		sum := agentStateEnvelope + krl.MaxKRLResponse + len(dj) + len(bj)
		if serverclient.MaxAgentStateResponse < sum {
			t.Fatalf("MaxAgentStateResponse %d is below the three largest items together (%d)", serverclient.MaxAgentStateResponse, sum)
		}
		body, err := fillAgentState([]serverclient.AgentBundle{b}, []serverclient.AgentDirectory{d}, k, false, serverclient.MaxAgentStateResponse)
		if err != nil {
			t.Fatal(err)
		}
		var r serverclient.AgentStateResponse
		if json.Unmarshal(body, &r) != nil || r.More || r.KRL == nil || len(r.Bundles) != 1 || len(r.Directories) != 1 || len(body) > serverclient.MaxAgentStateResponse {
			t.Fatalf("the three largest items: %d bytes, more %t", len(body), r.More)
		}
		t.Logf("the three largest items encode to %d bytes (KRL %d, directory %d, bundle %d); MaxAgentStateResponse %d", len(body), len(kj), len(dj), len(bj), serverclient.MaxAgentStateResponse)
	})
}
