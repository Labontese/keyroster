//go:build linux

package fetch

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

const testCustody = "user=agent, host=agent, machine=agent, ops=agent, log=agent"

// testServer is a TLS server for localhost under a test root, with the
// handler h, and a fetcher configured for it.
type testServer struct {
	srv     *httptest.Server
	f       *Fetcher
	dir     string // the fetcher's directory
	spool   string
	outbox  string
	mu      sync.Mutex
	reqs    []string // method and request URI of each request
	enrolls int
}

func (s *testServer) enrollCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enrolls
}

func (s *testServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.reqs)
}

// newTestServer starts h behind a server certificate for localhost signed
// by a fresh root, writes fetch.json for it and builds the fetcher.
func newTestServer(t *testing.T, h http.HandlerFunc) *testServer {
	t.Helper()
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPub, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, leafPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{}
	ts.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.mu.Lock()
		ts.reqs = append(ts.reqs, r.Method+" "+r.RequestURI)
		if r.URL.Path == serverclient.AgentEnrollPath {
			ts.enrolls++
		}
		ts.mu.Unlock()
		if r.TLS == nil || len(r.TLS.PeerCertificates) != 1 {
			http.Error(w, "no client certificate", http.StatusForbidden)
			return
		}
		w.Header().Set(serverclient.CustodyHeader, testCustody)
		h(w, r)
	}))
	ts.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}},
		ClientAuth: tls.RequireAnyClientCert}
	ts.srv.StartTLS()
	t.Cleanup(ts.srv.Close)
	base := t.TempDir()
	ts.dir, ts.spool, ts.outbox = filepath.Join(base, "fetch"), filepath.Join(base, "spool"), filepath.Join(base, "outbox")
	for _, d := range []string{ts.dir, ts.spool, ts.outbox} {
		if err := os.Mkdir(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	port := ts.srv.Listener.Addr().(*net.TCPAddr).Port
	fc := join.FetchConfig{Server: "https://localhost:" + strconv.Itoa(port), TLSRoots: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))},
		TLSPins: []string{serverclient.PinOf(root)}}
	b, err := trust.CanonicalJSON(fc)
	if err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(base, "fetch.json")
	if err := os.WriteFile(cfgFile, b, 0o640); err != nil { //nolint:gosec // G306: fetch.json's mode
		t.Fatal(err)
	}
	if ts.f, err = New(Config{ConfigFile: cfgFile, Dir: ts.dir, Spool: ts.spool, Outbox: ts.outbox, Poll: time.Second}); err != nil {
		t.Fatal(err)
	}
	return ts
}

// spooled lists the spool's names but identity.pub.
func (s *testServer) spooled(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(s.spool)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.Name() != enroll.IdentityFile {
			out = append(out, e.Name())
		}
	}
	return out
}

const emptyState = `{"bundles":[],"directories":[],"krl":null,"more":false}`

// TestFetch pins the fetcher's limits and its side of the enrollment
// hand-over (F2, F12).
func TestFetch(t *testing.T) {
	t.Run("response_at_max_accepted", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(emptyState + strings.Repeat(" ", serverclient.MaxAgentStateResponse-len(emptyState))))
		})
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("a body of exactly MaxAgentStateResponse bytes: %v", err)
		}
	})
	t.Run("response_max_plus_one_refused", func(t *testing.T) {
		// A valid answer with one item, padded to one byte above the limit.
		body := `{"bundles":[{"version":1,"bundle":"YQ==","bundle_sigs":"YQ==","policy_version":1,"policy":"YQ==","policy_sigs":"YQ=="}],"directories":[],"krl":null,"more":false}`
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(body + strings.Repeat(" ", serverclient.MaxAgentStateResponse+1-len(body))))
		})
		err := ts.f.Once(t.Context())
		if !errors.Is(err, serverclient.ErrStateResponseTooLarge) {
			t.Fatalf("a body of MaxAgentStateResponse + 1 bytes: %v, want state_response_too_large", err)
		}
		if got := ts.spooled(t); len(got) != 0 {
			t.Fatalf("spooled %v from a refused answer", got)
		}
	})
	t.Run("more_repolls_immediately", func(t *testing.T) {
		var n atomic.Int32
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if n.Add(1) == 1 {
				_, _ = w.Write([]byte(`{"bundles":[{"version":1,"bundle":"YQ==","bundle_sigs":"YQ==","policy_version":1,"policy":"YQ==","policy_sigs":"YQ=="}],"directories":[],"krl":null,"more":true}`))
				return
			}
			_, _ = w.Write([]byte(`{"bundles":[],"directories":[{"version":1,"directory":"YQ==","sigs":"YQ=="}],"krl":null,"more":false}`))
		})
		start := time.Now()
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		reqs := ts.requests()
		if len(reqs) != 2 || reqs[0] != "GET "+serverclient.AgentStatePath || reqs[1] != "GET "+serverclient.AgentStatePath+"?bundle=1" || time.Since(start) > 900*time.Millisecond {
			t.Fatalf("requests %q in %s, want two at once, the second with the new bundle version", reqs, time.Since(start))
		}
		if got := ts.spooled(t); !slices.Equal(got, []string{"bundle-1.json", "bundle-1.json.sigs", "directory-1.json", "directory-1.json.sigs", "policy-1.json", "policy-1.json.sigs"}) {
			t.Fatalf("spooled %v", got)
		}
	})
	t.Run("more_bounded_per_poll", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"bundles":[],"directories":[],"krl":null,"more":true}`))
		})
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if n := len(ts.requests()); n != MaxRounds {
			t.Fatalf("%d requests in one poll while more stays true, want %d", n, MaxRounds)
		}
	})
	t.Run("version_not_uint64_refused", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"bundles":[{"version":"../pins","bundle":"YQ==","bundle_sigs":"YQ==","policy_version":1,"policy":"YQ==","policy_sigs":"YQ=="}],"directories":[],"krl":null,"more":false}`))
		})
		if err := ts.f.Once(t.Context()); err == nil {
			t.Fatal("a version that is not a uint64 was accepted")
		}
		if got := ts.spooled(t); len(got) != 0 {
			t.Fatalf("spooled %v", got)
		}
	})
	t.Run("chain_out_of_order_refused", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"bundles":[],"directories":[{"version":2,"directory":"YQ==","sigs":"YQ=="},{"version":1,"directory":"YQ==","sigs":"YQ=="}],"krl":null,"more":false}`))
		})
		if err := ts.f.Once(t.Context()); !errors.Is(err, serverclient.ErrChainOutOfOrder) {
			t.Fatalf("directories 2, 1: %v, want chain_out_of_order", err)
		}
		if got := ts.spooled(t); len(got) != 0 {
			t.Fatalf("spooled %v", got)
		}
	})
	t.Run("rate_limited_continues_next_poll", func(t *testing.T) {
		// PR #71 review F4: a 429 with Retry-After inside a poll's more
		// rounds keeps what was spooled and is no error; the next poll goes
		// on from it.
		var n atomic.Int32
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if n.Add(1) == 1 {
				_, _ = w.Write([]byte(`{"bundles":[],"directories":[{"version":1,"directory":"YQ==","sigs":"YQ=="}],"krl":null,"more":true}`))
				return
			}
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate limited"}`))
		})
		var log strings.Builder
		ts.f.cfg.Log = &log
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("a 429 with Retry-After: %v, want no error", err)
		}
		if strings.Contains(log.String(), "ERROR") || !strings.Contains(log.String(), "continuing at the next poll") {
			t.Fatalf("log %q", log.String())
		}
		if got := ts.spooled(t); !slices.Contains(got, "directory-1.json") {
			t.Fatalf("spooled %v, want the first round's directory kept", got)
		}
	})
	t.Run("policy_write_failure_spools_no_bundle", func(t *testing.T) {
		// PR #71 review F10/F12: the policy a bundle names is written before
		// the bundle, so a bundle in the spool implies its policy is there. A
		// policy write that fails (a directory in its place stands in for
		// ENOSPC or a crash) leaves bundle 2 out, and the spool's newest
		// bundle stays 1.
		spoolDir := t.TempDir()
		item := func(v uint64) *serverclient.AgentStateResponse {
			return &serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{{Version: v, Bundle: []byte("b"), BundleSigs: []byte("s"),
				PolicyVersion: v, Policy: []byte("p"), PolicySigs: []byte("s")}}}
		}
		if err := writeState(spoolDir, item(1)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(spoolDir, "policy-2.json"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := writeState(spoolDir, item(2)); err == nil {
			t.Fatal("the policy write did not fail")
		}
		for _, n := range []string{"bundle-2.json", "bundle-2.json.sigs"} {
			if _, err := os.Lstat(filepath.Join(spoolDir, n)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s spooled while its policy is missing: %v", n, err)
			}
		}
		if v, err := spooledVersions(spoolDir); err != nil || v.Bundle != 1 {
			t.Fatalf("the spool's newest bundle %d (%v), want 1", v.Bundle, err)
		}
	})
	t.Run("not_approved_waits", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"not_approved"}`))
		})
		if err := ts.f.Once(t.Context()); err != nil || len(ts.spooled(t)) != 0 {
			t.Fatalf("not_approved: %v", err)
		}
	})
	// enrollFixture writes the join token install leaves.
	enrollFixture := func(t *testing.T, ts *testServer) join.FetcherToken {
		t.Helper()
		tok := join.FetcherToken{Token: join.EncodeToken(make([]byte, join.TokenBytes)), ExpectedName: "web1", InstallationID: "0123456789abcdef0123456789abcdef"}
		b, err := trust.CanonicalJSON(tok)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ts.dir, JoinTokenFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		return tok
	}
	writeAnswer := func(t *testing.T, ts *testServer, p enroll.PoP) {
		t.Helper()
		b, err := trust.CanonicalJSON(enroll.Answer{PoP: p, Sigs: [][]byte{[]byte("sig")}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ts.outbox, enroll.AnswerFile), b, 0o640); err != nil { //nolint:gosec // G306: the answer's mode
			t.Fatal(err)
		}
	}
	t.Run("enroll_pop_mismatch_not_posted", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"expected_name":"web1","status":"pending"}`))
		})
		tok := enrollFixture(t, ts)
		raw, _ := join.DecodeToken(tok.Token)
		// A stale answer for another identity.
		writeAnswer(t, ts, enroll.PoP{Domain: enroll.Domain, InstallationID: tok.InstallationID, TokenSHA256: join.TokenSHA256(raw),
			IdentitySPKISHA256: strings.Repeat("ab", 32), HostKeys: []string{"ssh-ed25519 AAAA"}, FactsSHA256: strings.Repeat("cd", 32)})
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if ts.enrollCount() != 0 {
			t.Fatal("an answer naming another identity was posted")
		}
		// The request names this fetcher's identity and token.
		b, err := os.ReadFile(filepath.Join(ts.spool, enroll.RequestFile))
		if err != nil {
			t.Fatal(err)
		}
		var req enroll.Request
		if err := trust.DecodeStrict(b, &req); err != nil || req.IdentitySPKISHA256 != ts.f.IdentitySPKISHA256() || req.TokenSHA256 != join.TokenSHA256(raw) {
			t.Fatalf("enroll-request.json %s (%v)", b, err)
		}
		// A fresh answer for this identity is posted, and a 202 removes
		// the token and the request.
		writeAnswer(t, ts, enroll.PoP{Domain: enroll.Domain, InstallationID: tok.InstallationID, TokenSHA256: join.TokenSHA256(raw),
			IdentitySPKISHA256: ts.f.IdentitySPKISHA256(), HostKeys: []string{"ssh-ed25519 AAAA"}, FactsSHA256: strings.Repeat("cd", 32)})
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if n := ts.enrollCount(); n != 1 {
			t.Fatalf("%d enrollments posted, want 1", n)
		}
		for _, p := range []string{filepath.Join(ts.dir, JoinTokenFile), filepath.Join(ts.spool, enroll.RequestFile)} {
			if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s after the 202: %v", p, err)
			}
		}
	})
	t.Run("no_answer_waits", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
		enrollFixture(t, ts)
		if err := ts.f.Once(t.Context()); err != nil || ts.enrollCount() != 0 {
			t.Fatalf("no answer yet: %v, %d posts", err, ts.enrollCount())
		}
	})
	t.Run("identity_kept_across_starts", func(t *testing.T) {
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(emptyState)) })
		st, err := os.Stat(filepath.Join(ts.dir, IdentityKeyFile))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("identity key: %v, mode %v", err, st.Mode())
		}
		again, err := New(ts.f.cfg)
		if err != nil || again.IdentitySPKISHA256() != ts.f.IdentitySPKISHA256() {
			t.Fatalf("a restarted fetcher has another identity: %v", err)
		}
	})
}

// TestNextPoll (D-10): 60 s polls fall in [50 s, 70 s].
func TestNextPoll(t *testing.T) {
	var lo, hi time.Duration = time.Hour, 0
	for range 1000 {
		d := NextPoll(DefaultPoll)
		if d < 50*time.Second || d > 70*time.Second {
			t.Fatalf("NextPoll = %s, outside [50s, 70s]", d)
		}
		lo, hi = min(lo, d), max(hi, d)
	}
	if hi-lo < 10*time.Second {
		t.Fatalf("1000 draws span only %s..%s", lo, hi)
	}
}

// TestNoListener (AGENT-02): the fetcher has no code path that opens a
// listening socket: no Listen or ListenPacket call of any package in
// internal/agent/fetch or cmd/keyroster-agent-fetch.
func TestNoListener(t *testing.T) {
	files := 0
	for _, dir := range []string{".", "../../../cmd/keyroster-agent-fetch"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			name := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files++
			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "Listen") {
					t.Errorf("%s: %s", name, sel.Sel.Name)
				}
				return true
			})
		}
	}
	if files < 3 {
		t.Fatalf("read %d source files, want the fetcher's", files)
	}
}
