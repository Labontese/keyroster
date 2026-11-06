//go:build linux

package fetch

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"math"
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

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/hostcert"
	"github.com/Labontese/keyroster/internal/agent/join"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
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

// seed writes files into the spool and, unless acc is nil, accepted.json
// into the outbox.
func (s *testServer) seed(t *testing.T, files map[string]string, acc *enroll.Accepted) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(s.spool, name), []byte(body), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	if acc == nil {
		return
	}
	b, err := trust.CanonicalJSON(*acc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.outbox, enroll.AcceptedFile), b, 0o640); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
}

// snapshot is the bytes of every spool file, by name.
func (s *testServer) snapshot(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	entries, err := os.ReadDir(s.spool)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(s.spool, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = string(b)
	}
	return out
}

// stateBody is r as the server encodes it.
func stateBody(t *testing.T, r serverclient.AgentStateResponse) []byte {
	t.Helper()
	if r.Bundles == nil {
		r.Bundles = []serverclient.AgentBundle{}
	}
	if r.Directories == nil {
		r.Directories = []serverclient.AgentDirectory{}
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// bundleItem is bundle version v naming a policy of size bytes at
// version pv.
func bundleItem(v, pv uint64, size int) serverclient.AgentBundle {
	return serverclient.AgentBundle{Version: v, Bundle: []byte("b"), BundleSigs: []byte("s"), PolicyVersion: pv,
		Policy: bytes.Repeat([]byte{'p'}, size), PolicySigs: []byte("s")}
}

// honestSpool is a spool holding bundle 1 with its policy 1, as the
// applier accepted them: the bundle names the policy by its SHA-256, and
// the policy names its version (F01 (03-08e) fix round 1: the fetcher
// prunes a policy no kept bundle names).
var honestSpool = map[string]string{"bundle-1.json": pruneBundle(1, prunePolicy(1, "p")), "bundle-1.json.sigs": "s",
	"policy-1.json": prunePolicy(1, "p"), "policy-1.json.sigs": "s"}

const emptyState = `{"bundles":[],"directories":[],"krl":null,"more":false}`

// b64 is s in standard base64, as a []byte is in JSON.
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

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
		// F02 (03-08f): the bundle item's policy signatures are spooled per
		// bundle too.
		if got := ts.spooled(t); !slices.Equal(got, []string{"bundle-1.json", "bundle-1.json.sigs", "bundle-1.policy.sigs", "directory-1.json", "directory-1.json.sigs", "policy-1.json", "policy-1.json.sigs"}) {
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
	t.Run("poisoned_answer_then_honest_delivers_newer_krl", func(t *testing.T) {
		// PR #71 review F3/F7: a compromised server's one answer spools a
		// KRL at the largest version and a junk directory 4. Once the
		// server is honest again, the fetcher asks from what the applier
		// accepted (accepted.json: directory 3, KRL 100), not from the
		// spool's newest names, so the honest directory 4 and KRL 101
		// arrive, and the junk KRL above the server's current version goes.
		const maxV = "18446744073709551615"
		var n atomic.Int32
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if n.Add(1) == 1 {
				_, _ = w.Write([]byte(`{"bundles":[],"directories":[{"version":4,"directory":"anVuaw==","sigs":"anVuaw=="}],` +
					`"krl":{"version":` + maxV + `,"krl":"anVuaw==","manifest":"` + b64(`{"krl_version":`+maxV+`}`) + `","sig":"anVuaw=="},"more":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"bundles":[],"directories":[{"version":4,"directory":"aG9uZXN0","sigs":"c2lncw=="}],` +
				`"krl":{"version":101,"krl":"a3JsMTAx","manifest":"` + b64(`{"krl_version":101}`) + `","sig":"c2ln"},"more":false}`))
		})
		for name, body := range map[string]string{
			"bundle-1.json": "b", "bundle-1.json.sigs": "s", "policy-1.json": "p", "policy-1.json.sigs": "s",
			"directory-3.json": "d", "directory-3.json.sigs": "s",
			"krl-100.krl": "k", "krl-100.manifest.json": `{"krl_version":100}`, "krl-100.manifest.sig": "s",
		} {
			if err := os.WriteFile(filepath.Join(ts.spool, name), []byte(body), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}
		acc, err := trust.CanonicalJSON(enroll.Accepted{Bundle: 1, Directory: 3, KRL: 100})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ts.outbox, enroll.AcceptedFile), acc, 0o640); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		for range 2 {
			if err := ts.f.Once(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
		reqs := ts.requests()
		want := "GET " + serverclient.AgentStatePath + "?bundle=1&directory=3&krl=100"
		if len(reqs) != 2 || reqs[0] != want || reqs[1] != want {
			t.Fatalf("requests %q, want both from the accepted versions (%s)", reqs, want)
		}
		got := ts.spooled(t)
		for _, name := range []string{"krl-" + maxV + ".krl", "krl-" + maxV + ".manifest.json", "krl-" + maxV + ".manifest.sig"} {
			if slices.Contains(got, name) {
				t.Errorf("the poisoned %s is still spooled: %v", name, got)
			}
		}
		if b, err := os.ReadFile(filepath.Join(ts.spool, "directory-4.json")); err != nil || string(b) != "honest" {
			t.Fatalf("directory-4.json %q (%v), want the honest version", b, err)
		}
		st, _, err := spool.Read(ts.spool, spool.Floor{Bundle: 1, Directory: 3})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := st.KRLs[101]; !ok || len(st.KRLs) != 1 {
			t.Fatalf("the applier's capture reads KRLs %v, want the honest 101", slices.Collect(maps.Keys(st.KRLs)))
		}
	})
	// F01 (03-08e): a compromised server's answer whose bundle item carries a
	// policy above the cap spool.Read applies to it, at the host's accepted
	// policy version or at the largest one, is refused before anything is
	// written: the spool keeps the honest policy-1.json, the next honest
	// answer is written, and the applier's capture stays readable.
	for _, tc := range []struct {
		name string
		pv   uint64
	}{{"oversize_policy_answer_refused_nothing_written", 1}, {"high_policy_version_oversize_refused", math.MaxUint64}} {
		t.Run(tc.name, func(t *testing.T) {
			var n atomic.Int32
			ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
				if n.Add(1) == 1 {
					_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{bundleItem(2, tc.pv, spool.MaxBundle+1)}}))
					return
				}
				_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{bundleItem(2, 2, 1)}}))
			})
			ts.seed(t, honestSpool, &enroll.Accepted{Bundle: 1})
			before := ts.snapshot(t)
			err := ts.f.Once(t.Context())
			if !errors.Is(err, ErrAnswerOverCap) || !strings.Contains(err.Error(), "policy") || !strings.Contains(err.Error(), strconv.FormatUint(tc.pv, 10)) {
				t.Errorf("an answer with an oversize policy %d: %v, want state_item_over_cap naming the policy and its version", tc.pv, err)
			}
			if after := ts.snapshot(t); !maps.Equal(after, before) {
				t.Errorf("the refused answer changed the spool: %v", slices.Sorted(maps.Keys(after)))
			}
			if err := ts.f.Once(t.Context()); err != nil {
				t.Errorf("the next honest answer: %v", err)
			}
			if _, _, err := spool.Read(ts.spool, spool.Floor{Bundle: 1, Policy: 1}); err != nil {
				t.Fatalf("the applier's capture after the honest answer: %v", err)
			}
		})
	}
	t.Run("item_at_cap_written", func(t *testing.T) {
		// F01 (03-08e): a policy of exactly the cap is an honest size.
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{bundleItem(2, 2, spool.MaxBundle)}}))
		})
		ts.seed(t, honestSpool, &enroll.Accepted{Bundle: 1})
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("a policy of exactly spool.MaxBundle bytes: %v", err)
		}
		if fi, err := os.Stat(filepath.Join(ts.spool, "policy-2.json")); err != nil || fi.Size() != spool.MaxBundle {
			t.Fatalf("policy-2.json: %v, %v", fi, err)
		}
		if st, _, err := spool.Read(ts.spool, spool.Floor{Bundle: 1, Policy: 1}); err != nil || len(st.Policies[2].Body) != spool.MaxBundle {
			t.Fatalf("the applier's capture: %v", err)
		}
	})
	t.Run("honest_answers_fit_the_caps", func(t *testing.T) {
		// F01 (03-08e): what an honest server serves is bounded by the
		// signer at these caps, so the fetcher's refusal never trips on it.
		// bundle_install bounds the bundle, the policy and their signatures
		// at tlog.MaxDocument; directory_install the directory at
		// tlog.MaxDocument and its signatures at tlog.MaxSigs; krl_publish
		// the manifest and its signature at tlog's manifest caps.
		for _, c := range []struct {
			what      string
			got, want int64
		}{
			{"tlog.MaxDocument vs spool.MaxBundle", tlog.MaxDocument, spool.MaxBundle},
			{"tlog.MaxDocument vs wire.MaxDirectory", tlog.MaxDocument, wire.MaxDirectory},
			{"tlog.MaxSigs vs wire.MaxDirectorySigs", tlog.MaxSigs, wire.MaxDirectorySigs},
			{"tlog.MaxManifest vs krl.MaxManifest", tlog.MaxManifest, krl.MaxManifest},
			{"tlog.MaxManifestSig vs krl.MaxManifestSig", tlog.MaxManifestSig, krl.MaxManifestSig},
		} {
			if c.got != c.want {
				t.Errorf("%s: %d, %d", c.what, c.got, c.want)
			}
		}
		for name, want := range map[string]int64{
			"bundle-1.json": tlog.MaxDocument, "bundle-1.json.sigs": tlog.MaxDocument,
			"policy-1.json": tlog.MaxDocument, "policy-1.json.sigs": tlog.MaxDocument,
			"directory-1.json": wire.MaxDirectory, "directory-1.json.sigs": wire.MaxDirectorySigs,
			"krl-1.krl": krl.MaxKRL, "krl-1.manifest.json": tlog.MaxManifest, "krl-1.manifest.sig": tlog.MaxManifestSig,
		} {
			if got, ok := spool.Cap(name); !ok || got != want {
				t.Errorf("spool.Cap(%q) = %d, %t, want %d", name, got, ok, want)
			}
		}
	})
	t.Run("more_than_per_kind_refused", func(t *testing.T) {
		// F01 (03-08e): the server sends at most MaxAgentStatePerKind
		// versions of a kind per answer; 17 contiguous bundles are refused
		// and nothing is written, 16 are spooled.
		bundles := func(n int) []serverclient.AgentBundle {
			var out []serverclient.AgentBundle
			for v := uint64(2); v < uint64(2+n); v++ { //nolint:gosec // G115: n is small
				out = append(out, bundleItem(v, 1, 1))
			}
			return out
		}
		var n atomic.Int32
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			if n.Add(1) == 1 {
				_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: bundles(serverclient.MaxAgentStatePerKind + 1)}))
				return
			}
			_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: bundles(serverclient.MaxAgentStatePerKind)}))
		})
		ts.seed(t, honestSpool, &enroll.Accepted{Bundle: 1})
		before := ts.snapshot(t)
		if err := ts.f.Once(t.Context()); !errors.Is(err, ErrAnswerOverCap) || !strings.Contains(err.Error(), "17 bundle") {
			t.Errorf("17 bundles in one answer: %v, want state_item_over_cap naming the count", err)
		}
		if after := ts.snapshot(t); !maps.Equal(after, before) {
			t.Errorf("the refused answer changed the spool: %v", slices.Sorted(maps.Keys(after)))
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("16 bundles in one answer: %v", err)
		}
		if v, err := spooledVersions(ts.spool); err != nil || v.Bundle != 17 {
			t.Fatalf("the spool's newest bundle %d (%v), want 17", v.Bundle, err)
		}
	})
	t.Run("oversize_directory_and_krl_refused", func(t *testing.T) {
		// F01 (03-08e): every file of a directory and of the KRL is held to
		// the cap spool.Read applies to it.
		manifest := func(pad int) []byte {
			m := `{"krl_version":1}`
			return []byte(m + strings.Repeat(" ", pad-len(m)))
		}
		for _, c := range []struct {
			name string
			r    serverclient.AgentStateResponse
		}{
			{"directory-1.json", serverclient.AgentStateResponse{Directories: []serverclient.AgentDirectory{{Version: 1, Directory: bytes.Repeat([]byte{'d'}, wire.MaxDirectory+1), Sigs: []byte("s")}}}},
			{"directory-1.json.sigs", serverclient.AgentStateResponse{Directories: []serverclient.AgentDirectory{{Version: 1, Directory: []byte("d"), Sigs: bytes.Repeat([]byte{'s'}, wire.MaxDirectorySigs+1)}}}},
			{"krl-1.krl", serverclient.AgentStateResponse{KRL: &serverclient.AgentKRL{Version: 1, KRL: bytes.Repeat([]byte{'k'}, krl.MaxKRL+1), Manifest: manifest(20), Sig: []byte("s")}}},
			{"krl-1.manifest.json", serverclient.AgentStateResponse{KRL: &serverclient.AgentKRL{Version: 1, KRL: []byte("k"), Manifest: manifest(krl.MaxManifest + 1), Sig: []byte("s")}}},
			{"krl-1.manifest.sig", serverclient.AgentStateResponse{KRL: &serverclient.AgentKRL{Version: 1, KRL: []byte("k"), Manifest: manifest(20), Sig: bytes.Repeat([]byte{'s'}, krl.MaxManifestSig+1)}}},
		} {
			ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(stateBody(t, c.r)) })
			before := ts.snapshot(t)
			if err := ts.f.Once(t.Context()); !errors.Is(err, ErrAnswerOverCap) || !strings.Contains(err.Error(), c.name) {
				t.Errorf("%s one byte above its cap: %v, want state_item_over_cap naming it", c.name, err)
			}
			if after := ts.snapshot(t); !maps.Equal(after, before) {
				t.Errorf("%s: the refused answer changed the spool: %v", c.name, slices.Sorted(maps.Keys(after)))
			}
		}
	})
	t.Run("poisoned_spool_file_removed_at_next_poll", func(t *testing.T) {
		// F01 (03-08e): a policy-1.json above the cap, left by an answer from
		// before the fetcher refused such answers, goes at the next poll, and
		// the applier's capture reads again.
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(emptyState)) })
		ts.seed(t, honestSpool, &enroll.Accepted{Bundle: 1})
		ts.seed(t, map[string]string{"policy-1.json": strings.Repeat("p", spool.MaxBundle+1)}, nil)
		if _, _, err := spool.Read(ts.spool, spool.Floor{Bundle: 1, Policy: 1}); !errors.Is(err, spool.ErrOversize) {
			t.Fatalf("the poisoned spool before the poll: %v, want spool_oversize", err)
		}
		var log strings.Builder
		ts.f.cfg.Log = &log
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(filepath.Join(ts.spool, "policy-1.json")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the oversize policy-1.json is still in the spool: %v", err)
		}
		if !strings.Contains(log.String(), "WARNING") || !strings.Contains(log.String(), "policy-1.json") {
			t.Errorf("log %q, want a warning naming policy-1.json", log.String())
		}
		if _, _, err := spool.Read(ts.spool, spool.Floor{Bundle: 1, Policy: 1}); err != nil {
			t.Fatalf("the applier's capture after the poll: %v", err)
		}
	})
	t.Run("per_bundle_policy_sigs_spooled", func(t *testing.T) {
		// F02 (03-08f): each bundle item's policy signatures are spooled as
		// bundle-<N>.policy.sigs, under the bundle's version, so they
		// survive the next item that names the same policy version.
		dir := t.TempDir()
		b2, b3 := bundleItem(2, 1, 1), bundleItem(3, 1, 1)
		b2.PolicySigs, b3.PolicySigs = []byte("p2"), []byte("p3")
		if err := writeState(dir, &serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{b2, b3}}); err != nil {
			t.Fatal(err)
		}
		for n, want := range map[string]string{"bundle-2.policy.sigs": "p2", "bundle-3.policy.sigs": "p3", "policy-1.json.sigs": "p3"} {
			if b, err := os.ReadFile(filepath.Join(dir, n)); err != nil || string(b) != want { //nolint:gosec // test fixture
				t.Errorf("%s: %q, %v; want %q", n, b, err, want)
			}
		}
		// Before bundle-<N>.json: a write of bundle-4.json that fails leaves
		// its policy signatures spooled already.
		dir = t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "bundle-4.json"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := writeState(dir, &serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{bundleItem(4, 1, 1)}}); err == nil {
			t.Fatal("writing over a directory bundle-4.json succeeded")
		}
		if !exists(t, filepath.Join(dir, "bundle-4.policy.sigs")) {
			t.Error("bundle-4.policy.sigs was not written before bundle-4.json")
		}
	})
	t.Run("drop_above_removes_per_bundle_policy_sigs", func(t *testing.T) {
		// F02 (03-08f): dropAbove removes the per-bundle file with its
		// bundle.
		dir := t.TempDir()
		for _, n := range []string{"bundle-2.json", "bundle-2.json.sigs", "bundle-2.policy.sigs", "bundle-3.json", "bundle-3.json.sigs", "bundle-3.policy.sigs"} {
			if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}
		if _, err := dropAbove(dir, serverclient.AgentVersions{Bundle: 2}); err != nil {
			t.Fatal(err)
		}
		for n, want := range map[string]bool{"bundle-2.policy.sigs": true, "bundle-3.json": false, "bundle-3.policy.sigs": false} {
			if got := exists(t, filepath.Join(dir, n)); got != want {
				t.Errorf("%s spooled %t, want %t", n, got, want)
			}
		}
	})
	t.Run("per_bundle_policy_sigs_over_cap_refused", func(t *testing.T) {
		// F02 (03-08f): checkCaps names the per-bundle file as writeState
		// writes it.
		b := bundleItem(2, 1, 1)
		b.PolicySigs = bytes.Repeat([]byte{'s'}, spool.MaxBundle+1)
		err := checkCaps(&serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{b}})
		if !errors.Is(err, ErrAnswerOverCap) || !strings.Contains(err.Error(), "bundle-2.policy.sigs") {
			t.Fatalf("an oversize per-bundle policy signature file: %v, want state_item_over_cap naming bundle-2.policy.sigs", err)
		}
	})
	t.Run("heal_covers_per_bundle_policy_sigs", func(t *testing.T) {
		// F02 (03-08f): a per-bundle file above its cap goes at the next
		// poll, as spool.Read would refuse it.
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "bundle-2.policy.sigs"), bytes.Repeat([]byte{'s'}, spool.MaxBundle+1), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		removed, err := healSpool(dir)
		if err != nil || !slices.Equal(removed, []string{"bundle-2.policy.sigs"}) || exists(t, filepath.Join(dir, "bundle-2.policy.sigs")) {
			t.Fatalf("healSpool: %v, %v; want bundle-2.policy.sigs removed", removed, err)
		}
	})
	t.Run("heal_leaves_symlinks_and_unknown_names", func(t *testing.T) {
		// F01 (03-08e): only recognised regular files are removed. A symlink
		// is never followed (the applier refuses it, T-03-225), and a name
		// the applier never reads is not the heal's.
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(emptyState)) })
		ts.seed(t, honestSpool, &enroll.Accepted{Bundle: 1})
		big := strings.Repeat("x", spool.MaxBundle+1)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte(big), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(ts.spool, "policy-2.json")); err != nil {
			t.Fatal(err)
		}
		ts.seed(t, map[string]string{"notes.txt": big, "policy-0.json": big}, nil)
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"policy-2.json", "notes.txt", "policy-0.json"} {
			if _, err := os.Lstat(filepath.Join(ts.spool, n)); err != nil {
				t.Errorf("%s was removed: %v", n, err)
			}
		}
		if b, err := os.ReadFile(target); err != nil || len(b) != len(big) { //nolint:gosec // test fixture
			t.Errorf("the symlink's target: %d bytes, %v", len(b), err)
		}
	})
	t.Run("heal_error_logged_and_poll_continues", func(t *testing.T) {
		// F01 (03-08e): the heal is best effort. A spool the fetcher cannot
		// remove from (read-only here) is logged, the poll still asks the
		// server, and the oversize file stays refused until a later poll
		// removes it.
		if os.Geteuid() == 0 {
			t.Skip("as root a directory's mode does not block unlink")
		}
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(emptyState)) })
		ts.seed(t, honestSpool, &enroll.Accepted{Bundle: 1})
		ts.seed(t, map[string]string{"policy-1.json": strings.Repeat("p", spool.MaxBundle+1)}, nil)
		if err := os.Chmod(ts.spool, 0o555); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ts.spool, 0o750) }) //nolint:gosec // test fixture
		var log strings.Builder
		ts.f.cfg.Log = &log
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatalf("a poll whose heal failed: %v, want it to go on", err)
		}
		if !strings.Contains(log.String(), "WARNING") || !strings.Contains(log.String(), "policy-1.json") || !strings.Contains(log.String(), "permission denied") {
			t.Errorf("log %q, want a warning naming policy-1.json and the error", log.String())
		}
		if len(ts.requests()) == 0 {
			t.Error("the poll sent no state request")
		}
		if _, _, err := spool.Read(ts.spool, spool.Floor{Bundle: 1, Policy: 1}); !errors.Is(err, spool.ErrOversize) {
			t.Fatalf("the applier's capture: %v, want spool_oversize while the file stays", err)
		}
	})
	t.Run("answer_not_following_the_request_refused", func(t *testing.T) {
		// PR #71 review F3/F7: a directory far above the requested version
		// (no chain from it) is refused before anything is spooled.
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"bundles":[],"directories":[{"version":18446744073709551615,"directory":"YQ==","sigs":"YQ=="}],"krl":null,"more":false}`))
		})
		for _, name := range []string{"directory-3.json", "directory-3.json.sigs"} {
			if err := os.WriteFile(filepath.Join(ts.spool, name), []byte("d"), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}
		if err := ts.f.Once(t.Context()); !errors.Is(err, serverclient.ErrChainOutOfOrder) {
			t.Fatalf("a directory not following version 3: %v, want chain_out_of_order", err)
		}
		if got := ts.spooled(t); len(got) != 2 {
			t.Fatalf("spooled %v", got)
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

// hostCertServer is a testServer whose host certificate route answers
// through answer, called with the 1-based count of host certificate posts.
type hostCertServer struct {
	*testServer
	posts atomic.Int32
}

func newHostCertServer(t *testing.T, answer func(n int, w http.ResponseWriter, r *http.Request)) *hostCertServer {
	t.Helper()
	hs := &hostCertServer{}
	hs.testServer = newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != serverclient.AgentHostCertPath {
			http.NotFound(w, r)
			return
		}
		answer(int(hs.posts.Add(1)), w, r)
	})
	return hs
}

// outboxRequest writes a host certificate request for a fresh Ed25519
// host key into the outbox and returns its key name and request ID.
func (s *hostCertServer) outboxRequest(t *testing.T) (string, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := hostcert.BuildRequest(signer, "0123456789abcdef0123456789abcdef", "web1", time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := trust.CanonicalJSON(hostcert.OutboxRequest{Request: body})
	if err != nil {
		t.Fatal(err)
	}
	k := hostcert.KeySHA256(signer.PublicKey())
	if err := os.WriteFile(filepath.Join(s.outbox, hostcert.RequestFileName(k)), b, 0o640); err != nil { //nolint:gosec // G306: the outbox mode
		t.Fatal(err)
	}
	return k, hexID(req.RequestID[:])
}

func hexID(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}

// answerOf reads key k's spool answer; nil when there is none.
func (s *hostCertServer) answerOf(t *testing.T, k string) *hostcert.Answer {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.spool, hostcert.AnswerFileName(k)))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	a, err := hostcert.ParseAnswer(b)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (s *hostCertServer) post(t *testing.T) {
	t.Helper()
	if err := s.f.postHostCerts(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// testHostCert stands for a certificate: the fetcher relays the bytes and
// never parses them (the applier verifies them).
func testHostCert(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func certAnswer(cert []byte) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(serverclient.AgentHostCertAnswer{Certificate: cert})
	}
}

func statusAnswer(code int, retryAfter, detail string) func(int, http.ResponseWriter, *http.Request) {
	return func(_ int, w http.ResponseWriter, _ *http.Request) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": detail})
	}
}

// TestPostHostCerts is the fetcher's half of host certificates (03-09).
func TestPostHostCerts(t *testing.T) {
	t.Run("posts_each_request_once", func(t *testing.T) {
		s := newHostCertServer(t, certAnswer(testHostCert(t)))
		s.outboxRequest(t)
		s.outboxRequest(t)
		s.post(t)
		s.post(t)
		if n := s.posts.Load(); n != 2 {
			t.Fatalf("%d posts, want one per outbox request", n)
		}
	})
	t.Run("writes_certificate_answer", func(t *testing.T) {
		cert := testHostCert(t)
		s := newHostCertServer(t, certAnswer(cert))
		k, id := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a == nil || a.RequestID != id || string(a.Certificate) != string(cert) || a.Refused != "" {
			t.Fatalf("answer %+v, want the certificate for request %s", a, id)
		}
	})
	t.Run("writes_refusal_answer", func(t *testing.T) {
		s := newHostCertServer(t, statusAnswer(http.StatusForbidden, "", "cert_revoked"))
		k, id := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a == nil || a.RequestID != id || a.Refused != "cert_revoked" {
			t.Fatalf("answer %+v, want the cert_revoked refusal", a)
		}
	})
	t.Run("rate_limited_writes_nothing", func(t *testing.T) {
		s := newHostCertServer(t, statusAnswer(http.StatusTooManyRequests, "30", "rate_limited"))
		k1, _ := s.outboxRequest(t)
		k2, _ := s.outboxRequest(t)
		s.post(t)
		if s.answerOf(t, k1) != nil || s.answerOf(t, k2) != nil || s.posts.Load() != 1 {
			t.Fatalf("after a 429: %d posts, answers %v %v; want one post and nothing written", s.posts.Load(), s.answerOf(t, k1), s.answerOf(t, k2))
		}
	})
	t.Run("rate_limited_without_retry_after_writes_nothing", func(t *testing.T) {
		for _, ra := range []string{"", "99999999999", "soon"} {
			s := newHostCertServer(t, statusAnswer(http.StatusTooManyRequests, ra, "rate_limited"))
			k, _ := s.outboxRequest(t)
			s.post(t)
			if a := s.answerOf(t, k); a != nil {
				t.Fatalf("Retry-After %q: answer %+v, want none", ra, a)
			}
		}
	})
	t.Run("old_server_404_backs_off", func(t *testing.T) {
		s := newHostCertServer(t, statusAnswer(http.StatusNotFound, "", "not_found"))
		k, _ := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a == nil || a.Refused != "http_404" {
			t.Fatalf("answer %+v, want http_404", a)
		}
	})
	t.Run("no_answer_on_503", func(t *testing.T) {
		s := newHostCertServer(t, statusAnswer(http.StatusServiceUnavailable, "", "signer_unavailable"))
		k, _ := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a != nil {
			t.Fatalf("answer %+v after a 503, want none", a)
		}
	})
	for name, code := range map[string]int{"internal_error_500_writes_nothing": 500, "bad_gateway_502_writes_nothing": 502, "gateway_timeout_504_writes_nothing": 504} {
		t.Run(name, func(t *testing.T) {
			s := newHostCertServer(t, statusAnswer(code, "", "internal"))
			k, _ := s.outboxRequest(t)
			s.post(t)
			if a := s.answerOf(t, k); a != nil {
				t.Fatalf("answer %+v after a %d, want none", a, code)
			}
		})
	}
	t.Run("forbidden_without_detail_is_http_403", func(t *testing.T) {
		for _, d := range []string{"", "Not A Detail!", "x:y:z"} {
			s := newHostCertServer(t, statusAnswer(http.StatusForbidden, "", d))
			k, _ := s.outboxRequest(t)
			s.post(t)
			if a := s.answerOf(t, k); a == nil || a.Refused != "http_403" {
				t.Fatalf("detail %q: answer %+v, want http_403", d, a)
			}
		}
	})
	t.Run("one_at_a_time", func(t *testing.T) {
		var mu sync.Mutex
		inFlight, peak := 0, 0
		cert := testHostCert(t)
		s := newHostCertServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			inFlight++
			peak = max(peak, inFlight)
			mu.Unlock()
			time.Sleep(20 * time.Millisecond) // overlap would show in peak
			certAnswer(cert)(n, w, r)
			mu.Lock()
			inFlight--
			mu.Unlock()
		})
		for range 3 {
			s.outboxRequest(t)
		}
		s.post(t)
		if peak != 1 || s.posts.Load() != 3 {
			t.Fatalf("peak %d in flight over %d posts, want one at a time", peak, s.posts.Load())
		}
	})
	t.Run("prunes_answers_without_outbox_request", func(t *testing.T) {
		s := newHostCertServer(t, certAnswer(testHostCert(t)))
		k, _ := s.outboxRequest(t)
		gone := hostcert.KeySHA256(mustSSHPub(t))
		for key, id := range map[string]string{k: "0123456789abcdef0123456789abcdef", gone: "fedcba9876543210fedcba9876543210"} {
			if err := writeHostCertAnswer(s.spool, key, hostcert.Answer{RequestID: id, Refused: "cert_revoked"}); err != nil {
				t.Fatal(err)
			}
		}
		s.post(t)
		if a := s.answerOf(t, gone); a != nil {
			t.Fatalf("an answer for a key with no outbox request survives: %+v", a)
		}
		if a := s.answerOf(t, k); a == nil || a.Refused != "" {
			t.Fatalf("the stale answer for k was not replaced by the new one: %+v", a)
		}
	})
	t.Run("oversize_answer_healed", func(t *testing.T) {
		s := newHostCertServer(t, certAnswer(testHostCert(t)))
		k, _ := s.outboxRequest(t)
		for _, n := range []int{spool.MaxHostCertAnswer, spool.MaxHostCertAnswer + 1} {
			p := filepath.Join(s.spool, hostcert.AnswerFileName(k))
			if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil { //nolint:gosec // G306: the answer mode
				t.Fatal(err)
			}
			if _, err := healSpool(s.spool); err != nil {
				t.Fatal(err)
			}
			_, err := os.Stat(p)
			if (n > spool.MaxHostCertAnswer) != os.IsNotExist(err) {
				t.Fatalf("an answer of %d bytes after the heal: %v", n, err)
			}
		}
	})
	t.Run("answer_mode_0644", func(t *testing.T) {
		s := newHostCertServer(t, certAnswer(testHostCert(t)))
		k, _ := s.outboxRequest(t)
		s.post(t)
		fi, err := os.Stat(filepath.Join(s.spool, hostcert.AnswerFileName(k)))
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("answer mode %v, %v; want 0644", fi.Mode(), err)
		}
	})
	t.Run("retry_after_lost_response_gets_certificate", func(t *testing.T) {
		cert := testHostCert(t)
		var bodies []string
		var mu sync.Mutex
		s := newHostCertServer(t, func(n int, w http.ResponseWriter, r *http.Request) {
			var req serverclient.AgentHostCertRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			bodies = append(bodies, string(req.Request))
			mu.Unlock()
			if n == 1 {
				// The server committed, then the response was lost.
				statusAnswer(http.StatusServiceUnavailable, "", "signer_unavailable")(n, w, r)
				return
			}
			certAnswer(cert)(n, w, r)
		})
		k, id := s.outboxRequest(t)
		s.post(t)
		if a := s.answerOf(t, k); a != nil {
			t.Fatalf("answer %+v after the lost response", a)
		}
		s.post(t)
		if a := s.answerOf(t, k); a == nil || a.RequestID != id || string(a.Certificate) != string(cert) {
			t.Fatalf("the retry wrote %+v, want the certificate", a)
		}
		if len(bodies) != 2 || bodies[0] != bodies[1] {
			t.Fatal("the retry did not post the same request")
		}
	})
}

func mustSSHPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
