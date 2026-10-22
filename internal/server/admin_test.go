package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/adminauth"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// uniform401 is the one body of every admin authentication failure.
const uniform401 = `{"error":"admin authentication failed"}` + "\n"

// newSigner returns a fresh Ed25519 ssh.Signer.
func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// adminPolicy returns a canonical policy whose admin is admin ("root-admin")
// and whose WebAuthn RP is testRPID with origins.
func adminPolicy(t *testing.T, admin ssh.Signer, origins ...string) []byte {
	t.Helper()
	if len(origins) == 0 {
		origins = []string{"https://" + testRPID}
	}
	p := &trust.Policy{
		Version:     1,
		Prev:        trust.GenesisPrev,
		AdminQuorum: 1,
		Admins:      []trust.AdminKey{{Name: "root-admin", Key: trust.FormatKey(admin.PublicKey())}},
		CAProfiles: []trust.CAProfile{
			{Role: trust.RoleUser, MaxTTLSeconds: 43200, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleHost, MaxTTLSeconds: 2592000, DefaultExtensions: []string{}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
			{Role: trust.RoleMachine, MaxTTLSeconds: 86400, DefaultExtensions: []string{"permit-pty"}, AllowedExtensions: []string{}, AllowedCriticalOptions: []string{}},
		},
		WebAuthn: &trust.WebAuthnRP{RPID: testRPID, Origins: origins},
	}
	data, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.ParsePolicy(data); err != nil {
		t.Fatalf("admin policy does not parse: %v", err)
	}
	return data
}

// adminEnv is a Server on a fakeSigner whose policy names one admin key.
type adminEnv struct {
	s     *Server
	fake  *fakeSigner
	clock *testClock
	log   *logBuffer
	admin ssh.Signer
}

func newAdminEnv(t *testing.T, lim Limits, origins ...string) *adminEnv {
	t.Helper()
	admin := newSigner(t)
	st := testStatus(t, "agent", 0)
	st.Policy = adminPolicy(t, admin, origins...)
	fake := newFakeSigner(st)
	s, clock, log := newTestServerLimits(t, fake, lim)
	return &adminEnv{s: s, fake: fake, clock: clock, log: log, admin: admin}
}

// testOrigin is the one webauthn origin of newAdminEnv's default policy,
// the origin of a request with Host testRPID.
const testOrigin = "https://" + testRPID

// signedReq builds an admin request for the origin-form target, signed
// with signer for testOrigin over signedPath (usually target) at at, from
// RemoteAddr 192.0.2.1 with Host testRPID.
func signedReq(t *testing.T, signer ssh.Signer, method, target, signedPath string, body []byte, at time.Time) *http.Request {
	t.Helper()
	return signedReqFor(t, signer, testOrigin, method, target, signedPath, body, at)
}

// signedReqFor is signedReq with the signed origin given.
func signedReqFor(t *testing.T, signer ssh.Signer, origin, method, target, signedPath string, body []byte, at time.Time) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.Host = testRPID
	if signer != nil {
		h, err := adminauth.Sign(signer, origin, method, signedPath, body, at)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range h {
			req.Header[k] = v
		}
	}
	return req
}

// clone returns a copy of req with the same headers and body.
func clone(t *testing.T, req *http.Request, body []byte) *http.Request {
	t.Helper()
	c := httptest.NewRequest(req.Method, req.RequestURI, bytes.NewReader(body))
	c.Host = req.Host
	c.RemoteAddr = req.RemoteAddr
	c.Header = req.Header.Clone()
	return c
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// recorder is a handler that records each call and the body it read.
type recorder struct {
	mu     sync.Mutex
	calls  int
	bodies [][]byte
	admins []string
}

func (rc *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	rc.mu.Lock()
	rc.calls++
	rc.bodies = append(rc.bodies, b)
	rc.admins = append(rc.admins, adminName(r.Context()))
	rc.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (rc *recorder) count() int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	return rc.calls
}

// countingReader is an endless body of 'a' bytes that counts what was
// read from it.
type countingReader struct{ n atomic.Int64 }

func (c *countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	c.n.Add(int64(len(p)))
	return len(p), nil
}

func (c *countingReader) read() int64 { return c.n.Load() }

// stallingReader is a body that, once read, closes started and blocks
// until release closes, the way a client that sends all but the last byte
// and then stalls holds a server's read open.
type stallingReader struct {
	n       atomic.Int64
	once    sync.Once
	started chan struct{}
	release <-chan struct{}
}

func (s *stallingReader) Read(_ []byte) (int, error) {
	s.n.Add(1)
	s.once.Do(func() { close(s.started) })
	<-s.release
	return 0, io.ErrUnexpectedEOF
}

func (s *stallingReader) read() int64 { return s.n.Load() }

const probePath = "/api/v1/admin/probe?x=1"

var probeBody = []byte(`{"probe":true}`)

func TestAdminAuth(t *testing.T) {
	t.Run("uniform_401_body", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		h := e.s.requireAdmin(rec)
		other := newSigner(t)
		wrongNS := func() *http.Request {
			req := signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)
			msg := adminauth.Message(testOrigin, "POST", probePath, sha256.Sum256(probeBody), t0.Unix(), req.Header.Get(adminauth.HeaderNonce))
			sig, err := sshsig.Sign(rand.Reader, e.admin, wire.AdminSSHSIGNamespace, msg)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set(adminauth.HeaderSignature, base64.StdEncoding.EncodeToString(sig))
			return req
		}
		badNonce := signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)
		badNonce.Header.Set(adminauth.HeaderNonce, "not-a-nonce")
		cases := []struct {
			name   string
			req    *http.Request
			reason string
		}{
			{"missing_headers", signedReq(t, nil, "POST", probePath, probePath, probeBody, t0), "missing admin headers"},
			{"stale_time", signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0.Add(-121*time.Second)), "timestamp too old"},
			{"future_time", signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0.Add(121*time.Second)), "timestamp in the future"},
			{"malformed_nonce", badNonce, "malformed nonce"},
			{"non_admin_key", signedReq(t, other, "POST", probePath, probePath, probeBody, t0), "signer is not a policy admin"},
			{"wrong_namespace", wrongNS(), "wrong signature namespace"},
			{"body_changed", func() *http.Request {
				req := signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)
				return clone(t, req, []byte(`{"probe":false}`))
			}(), "body does not match the signed digest"},
			{"digest_changed", func() *http.Request {
				// The digest header of another body, sent with that body.
				other := []byte(`{"probe":false}`)
				req := clone(t, signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0), other)
				sum := sha256.Sum256(other)
				req.Header.Set(adminauth.HeaderBodySHA256, hex.EncodeToString(sum[:]))
				return req
			}(), "signature does not match the request"},
			{"missing_digest", func() *http.Request {
				req := signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)
				req.Header.Del(adminauth.HeaderBodySHA256)
				return req
			}(), "missing admin headers"},
			{"malformed_digest", func() *http.Request {
				req := signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)
				req.Header.Set(adminauth.HeaderBodySHA256, strings.ToUpper(req.Header.Get(adminauth.HeaderBodySHA256)))
				return req
			}(), "malformed body digest"},
			{"other_deployment_origin", signedReqFor(t, e.admin, "https://staging.example", "POST", probePath, probePath, probeBody, t0),
				"signature does not match the request"},
			{"host_not_a_policy_origin", func() *http.Request {
				req := signedReqFor(t, e.admin, "https://staging.example", "POST", probePath, probePath, probeBody, t0)
				req.Host = "staging.example"
				return req
			}(), "request origin is not a policy origin"},
			{"path_changed", signedReq(t, e.admin, "POST", probePath, "/api/v1/admin/other?x=1", probeBody, t0), "signature does not match the request"},
			{"query_changed", signedReq(t, e.admin, "POST", probePath, "/api/v1/admin/probe?x=2", probeBody, t0), "signature does not match the request"},
			{"method_changed", func() *http.Request {
				req := signedReq(t, e.admin, "PUT", probePath, probePath, probeBody, t0)
				req.Method = "POST"
				return req
			}(), "signature does not match the request"},
		}
		for _, tc := range cases {
			res := serve(h, tc.req)
			if res.Code != http.StatusUnauthorized || res.Body.String() != uniform401 {
				t.Fatalf("%s: %d %q, want 401 %q", tc.name, res.Code, res.Body.String(), uniform401)
			}
			lines := e.log.Lines()
			if last := lines[len(lines)-1]; !strings.Contains(last, `"msg":"admin authentication failed"`) || !strings.Contains(last, tc.reason) {
				t.Fatalf("%s: log line %s, want the reason %q", tc.name, last, tc.reason)
			}
		}
		if rec.count() != 0 {
			t.Fatalf("the handler ran %d times for refused requests", rec.count())
		}
		probeSum := sha256.Sum256(probeBody)
		for _, l := range e.log.Lines() {
			if strings.Contains(l, "BEGIN SSH SIGNATURE") || strings.Contains(l, adminauth.HeaderSignature) ||
				strings.Contains(l, hex.EncodeToString(probeSum[:])) || strings.Contains(l, "staging.example") {
				t.Fatalf("a log line carries signature data, a digest or the Host header: %s", l)
			}
		}
	})

	t.Run("cross_deployment_replay_401_nonce_unused", func(t *testing.T) {
		// Staging and this deployment trust the same admin key. A request
		// the admin signed while talking to staging is relayed here within
		// the window, with this deployment's own Host: it does not verify,
		// and its nonce stays unused.
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		req := signedReqFor(t, e.admin, "https://staging.example", "POST", probePath, probePath, probeBody, t0)
		nonce := req.Header.Get(adminauth.HeaderNonce)
		if res := serve(e.s.requireAdmin(rec), req); res.Code != http.StatusUnauthorized || res.Body.String() != uniform401 || rec.count() != 0 {
			t.Fatalf("relayed request = %d %q (handler calls %d), want the uniform 401", res.Code, res.Body, rec.count())
		}
		if err := e.s.db.UseNonce(context.Background(), nonce, t0.Add(time.Minute), t0); err != nil {
			t.Fatalf("the relayed request consumed its nonce: %v", err)
		}
		// Control: signed for this deployment's origin, it passes.
		if res := serve(e.s.requireAdmin(rec), signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)); res.Code != http.StatusNoContent {
			t.Fatalf("signed for %s: %d, want the handler", testOrigin, res.Code)
		}
	})

	t.Run("origin_matched_exactly", func(t *testing.T) {
		// Only an exact policy origin is verified against; a ":443" suffix
		// is the default port. No other spelling, and no fallback to the
		// first policy origin as requestOrigin has.
		e := newAdminEnv(t, Limits{}, testOrigin, testOrigin+":8443")
		rec := &recorder{}
		for _, tc := range []struct {
			host, origin string
			want         int
		}{
			{testRPID + ":8443", testOrigin + ":8443", http.StatusNoContent},
			{testRPID + ":443", testOrigin, http.StatusNoContent},
			{testRPID, testOrigin, http.StatusNoContent},
			{testRPID + ":8443", testOrigin, http.StatusUnauthorized},
			{strings.ToUpper(testRPID), testOrigin, http.StatusUnauthorized},
			{testRPID + ".", testOrigin, http.StatusUnauthorized},
			{testRPID + ":9000", testOrigin, http.StatusUnauthorized},
		} {
			req := signedReqFor(t, e.admin, tc.origin, "POST", probePath, probePath, probeBody, t0)
			req.Host = tc.host
			if res := serve(e.s.requireAdmin(rec), req); res.Code != tc.want {
				t.Fatalf("Host %s signed for %s: %d, want %d", tc.host, tc.origin, res.Code, tc.want)
			}
		}
	})

	t.Run("unauthenticated_body_never_read", func(t *testing.T) {
		// Requests that do not verify, with bodies of maxAdminBody bytes:
		// no admin headers, a key that is no admin, and the real admin key
		// with a signature made for another request. The handler reads
		// none of their body bytes.
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		junk := signedReqFor(t, e.admin, "https://staging.example", "POST", probePath, probePath, probeBody, t0).Header
		for name, hdr := range map[string]http.Header{
			"no_headers":       {},
			"non_admin_key":    signedReq(t, newSigner(t), "POST", probePath, probePath, probeBody, t0).Header,
			"admin_junk_sig":   junk,
			"malformed_digest": func() http.Header { h := junk.Clone(); h.Set(adminauth.HeaderBodySHA256, "00"); return h }(),
		} {
			body := &countingReader{}
			req := httptest.NewRequest("POST", probePath, body)
			req.Host = testRPID
			req.ContentLength = maxAdminBody
			req.Header = hdr
			if res := serve(e.s.requireAdmin(rec), req); res.Code != http.StatusUnauthorized || res.Body.String() != uniform401 {
				t.Fatalf("%s: %d %q, want the uniform 401", name, res.Code, res.Body)
			}
			if n := body.read(); n != 0 {
				t.Fatalf("%s: the server read %d bytes of an unauthenticated body", name, n)
			}
		}
		if rec.count() != 0 {
			t.Fatalf("the handler ran %d times", rec.count())
		}
	})

	t.Run("body_digest_mismatch_401_nonce_unused", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		req := clone(t, signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0), []byte(`{"probe":false}`))
		nonce := req.Header.Get(adminauth.HeaderNonce)
		if res := serve(e.s.requireAdmin(rec), req); res.Code != http.StatusUnauthorized || res.Body.String() != uniform401 || rec.count() != 0 {
			t.Fatalf("= %d %q (calls %d), want the uniform 401", res.Code, res.Body, rec.count())
		}
		if err := e.s.db.UseNonce(context.Background(), nonce, t0.Add(time.Minute), t0); err != nil {
			t.Fatalf("a request whose body is not the signed one consumed its nonce: %v", err)
		}
	})

	t.Run("nonce_replay", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		h := e.s.requireAdmin(rec)
		req := signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)
		replay := clone(t, req, probeBody)
		if res := serve(h, req); res.Code != http.StatusNoContent {
			t.Fatalf("first use = %d %s", res.Code, res.Body)
		}
		if res := serve(h, replay); res.Code != http.StatusUnauthorized || res.Body.String() != uniform401 {
			t.Fatalf("replay = %d %q, want the uniform 401", res.Code, res.Body)
		}
		if rec.count() != 1 || rec.admins[0] != "root-admin" {
			t.Fatalf("handler calls %d (admins %q), want 1 by root-admin", rec.count(), rec.admins)
		}
		if !strings.Contains(e.log.String(), "nonce already used (replay)") {
			t.Fatalf("no replay log line:\n%s", e.log)
		}
	})

	t.Run("nonce_replay_parallel", func(t *testing.T) {
		for range 20 {
			e := newAdminEnv(t, Limits{})
			rec := &recorder{}
			h := e.s.requireAdmin(rec)
			req := signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)
			reqs := []*http.Request{req, clone(t, req, probeBody)}
			codes := make([]int, 2)
			var wg sync.WaitGroup
			for i := range reqs {
				wg.Add(1)
				go func() {
					defer wg.Done()
					codes[i] = serve(h, reqs[i]).Code
				}()
			}
			wg.Wait()
			non401 := 0
			for _, c := range codes {
				if c != http.StatusUnauthorized {
					non401++
				}
			}
			if non401 != 1 || rec.count() != 1 {
				t.Fatalf("two concurrent copies gave %v (handler calls %d), want exactly one non-401", codes, rec.count())
			}
		}
	})

	t.Run("nonce_replay_after_cleanup", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		h := e.s.requireAdmin(rec)
		r := signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0.Add(119*time.Second))
		replay := func(what string) {
			t.Helper()
			before := rec.count()
			res := serve(h, clone(t, r, probeBody))
			if res.Code != http.StatusUnauthorized || rec.count() != before {
				t.Fatalf("%s: replay of R = %d (handler calls %d -> %d), want 401 and no call", what, res.Code, before, rec.count())
			}
		}
		fresh := func(at time.Time) {
			t.Helper()
			if res := serve(h, signedReq(t, e.admin, "POST", probePath, probePath, probeBody, at)); res.Code != http.StatusNoContent {
				t.Fatalf("fresh request at %v = %d %s", at.Sub(t0), res.Code, res.Body)
			}
		}
		if res := serve(h, clone(t, r, probeBody)); res.Code != http.StatusNoContent || rec.count() != 1 {
			t.Fatalf("R at T = %d (calls %d), want the handler once", res.Code, rec.count())
		}
		e.clock.set(t0.Add(121 * time.Second))
		fresh(t0.Add(121 * time.Second)) // its UseNonce runs the purge
		replay("T+121s")
		if l := e.log.Lines(); !strings.Contains(l[len(l)-1], "nonce already used") {
			t.Fatalf("T+121s: the replay was not refused for its nonce: %s", l[len(l)-1])
		}
		e.clock.set(t0.Add(238 * time.Second))
		fresh(t0.Add(238 * time.Second))
		replay("T+238s")
		if l := e.log.Lines(); !strings.Contains(l[len(l)-1], "nonce already used") {
			t.Fatalf("T+238s: the replay was not refused for its nonce: %s", l[len(l)-1])
		}
		e.clock.set(t0.Add(241 * time.Second))
		replay("T+241s")
		if l := e.log.Lines(); !strings.Contains(l[len(l)-1], "timestamp too old") {
			t.Fatalf("T+241s: the replay was not refused for its timestamp: %s", l[len(l)-1])
		}
	})

	t.Run("encoded_path_variant_401", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		h := e.s.requireAdmin(rec)
		const raw = "/api/v1/admin/probe/%61lice"
		res := serve(h, signedReq(t, e.admin, "POST", raw, "/api/v1/admin/probe/alice", probeBody, t0))
		if res.Code != http.StatusUnauthorized || rec.count() != 0 {
			t.Fatalf("signed over the decoded path: %d (calls %d), want 401 and no call", res.Code, rec.count())
		}
		// Control: signed over the raw target, the same request passes.
		if res := serve(h, signedReq(t, e.admin, "POST", raw, raw, probeBody, t0)); res.Code != http.StatusNoContent || rec.count() != 1 {
			t.Fatalf("signed over the raw target: %d (calls %d), want the handler", res.Code, rec.count())
		}
	})

	t.Run("handler_sees_signed_body", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		if res := serve(e.s.requireAdmin(rec), signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0)); res.Code != http.StatusNoContent {
			t.Fatalf("= %d %s", res.Code, res.Body)
		}
		if !bytes.Equal(rec.bodies[0], probeBody) {
			t.Fatalf("handler read %q, want the signed %q", rec.bodies[0], probeBody)
		}
	})

	t.Run("body_over_limit_413_before_verify", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		h := e.s.requireAdmin(rec)
		const want413 = `{"error":"request body too large"}` + "\n"
		big := bytes.Repeat([]byte("a"), maxAdminBody+1)
		req := signedReq(t, e.admin, "POST", probePath, probePath, big, t0)
		nonce := req.Header.Get(adminauth.HeaderNonce)
		if res := serve(h, req); res.Code != http.StatusRequestEntityTooLarge || res.Body.String() != want413 {
			t.Fatalf("signed body of maxAdminBody+1 = %d %q, want 413 %q", res.Code, res.Body, want413)
		}
		if rec.count() != 0 {
			t.Fatal("the handler ran for an oversized body")
		}
		if err := e.s.db.UseNonce(context.Background(), nonce, t0.Add(time.Minute), t0); err != nil {
			t.Fatalf("the oversized request consumed its nonce: %v", err)
		}
		if res := serve(h, signedReq(t, nil, "POST", probePath, probePath, big, t0)); res.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body without admin headers = %d, want 413 (not 401)", res.Code)
		}
		exact := bytes.Repeat([]byte("a"), maxAdminBody)
		if res := serve(h, signedReq(t, e.admin, "POST", probePath, probePath, exact, t0)); res.Code != http.StatusNoContent || rec.count() != 1 {
			t.Fatalf("signed body of exactly maxAdminBody = %d, want the handler", res.Code)
		}
		small := e.s.requireAdminLimit(64, rec)
		if res := serve(small, signedReq(t, e.admin, "POST", probePath, probePath, bytes.Repeat([]byte("b"), 64), t0)); res.Code != http.StatusNoContent || rec.count() != 2 {
			t.Fatalf("limit 64, 64-byte body = %d, want the handler", res.Code)
		}
		if res := serve(small, signedReq(t, e.admin, "POST", probePath, probePath, bytes.Repeat([]byte("b"), 65), t0)); res.Code != http.StatusRequestEntityTooLarge || rec.count() != 2 {
			t.Fatalf("limit 64, 65-byte body = %d, want 413", res.Code)
		}
		if !strings.Contains(e.log.String(), `"limit":64`) {
			t.Fatalf("the 413 log line does not name the limit:\n%s", e.log)
		}
	})

	t.Run("streamed_body_over_limit_413_after_verify", func(t *testing.T) {
		// No Content-Length: the size shows only while the body is read,
		// which happens after Verify. A verified request gets 413 with its
		// nonce unused; an unverified one gets the uniform 401, its body
		// unread by the handler.
		e := newAdminEnv(t, Limits{})
		rec := &recorder{}
		h := e.s.requireAdminLimit(64, rec)
		big := bytes.Repeat([]byte("b"), 65)
		streamed := func(req *http.Request) *http.Request {
			req.Body = io.NopCloser(bytes.NewReader(big))
			req.ContentLength = -1
			return req
		}
		req := streamed(signedReq(t, e.admin, "POST", probePath, probePath, big, t0))
		nonce := req.Header.Get(adminauth.HeaderNonce)
		if res := serve(h, req); res.Code != http.StatusRequestEntityTooLarge || rec.count() != 0 {
			t.Fatalf("verified, streamed 65-byte body under limit 64 = %d (calls %d), want 413", res.Code, rec.count())
		}
		if err := e.s.db.UseNonce(context.Background(), nonce, t0.Add(time.Minute), t0); err != nil {
			t.Fatalf("the oversized request consumed its nonce: %v", err)
		}
		if res := serve(h, streamed(signedReq(t, newSigner(t), "POST", probePath, probePath, big, t0))); res.Code != http.StatusUnauthorized {
			t.Fatalf("unverified, streamed 65-byte body = %d, want the uniform 401 (verified before any read)", res.Code)
		}
	})

	t.Run("signer_unavailable_503", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		e.fake.setStatus(nil, errors.New("down"))
		rec := &recorder{}
		res := serve(e.s.requireAdmin(rec), signedReq(t, e.admin, "POST", probePath, probePath, probeBody, t0))
		if res.Code != http.StatusServiceUnavailable || rec.count() != 0 {
			t.Fatalf("= %d (calls %d), want 503: admins come only from the signer's policy", res.Code, rec.count())
		}
	})
}

// addUser sends a signed POST /api/v1/admin/users through the full
// handler and returns the response. With host set, the request goes to
// that Host and is signed for its origin, as the CLI signs the server URL
// it talks to.
func (e *adminEnv) addUser(t *testing.T, name string, reinvite bool, host string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(serverclient.AddUserRequest{Name: name, Reinvite: reinvite})
	if err != nil {
		t.Fatal(err)
	}
	origin := testOrigin
	if host != "" {
		origin = "https://" + strings.TrimSuffix(host, ":443")
	}
	req := signedReqFor(t, e.admin, origin, http.MethodPost, serverclient.AdminUsersPath, serverclient.AdminUsersPath, body, e.clock.Now())
	if host != "" {
		req.Host = host
	}
	return serve(e.s.Handler(), req)
}

// mustAdd is addUser that requires 201 and returns the decoded answer.
func (e *adminEnv) mustAdd(t *testing.T, name string, reinvite bool) serverclient.AddUserResponse {
	t.Helper()
	res := e.addUser(t, name, reinvite, "")
	if res.Code != http.StatusCreated {
		t.Fatalf("add %s (reinvite %v) = %d %s\nlog:\n%s", name, reinvite, res.Code, res.Body, e.log)
	}
	var out serverclient.AddUserResponse
	if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// getInvite GETs the path of an invite URL through the full handler.
func (e *adminEnv) getInvite(t *testing.T, inviteURL string) *httptest.ResponseRecorder {
	t.Helper()
	i := strings.Index(inviteURL, "/enroll/")
	if i < 0 {
		t.Fatalf("invite URL %q has no /enroll/", inviteURL)
	}
	return do(e.s, http.MethodGet, inviteURL[i:], nil)
}

// installDirectory makes the fake signer's installed directory the test
// vector (alice, version 1), reported by both GetDirectory and Status.
func (e *adminEnv) installDirectory(t *testing.T) []byte {
	t.Helper()
	doc, err := os.ReadFile("../../test/vectors/directory_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	e.fake.setDirectory(&wire.GetDirectoryResponse{Version: 1, Directory: doc, Sigs: []byte("sigs"), Authorized: true}, nil)
	e.fake.mu.Lock()
	st := *e.fake.status
	e.fake.mu.Unlock()
	st.DirectoryVersion, st.DirectorySHA256, st.DirectoryAuthorized = 1, sha256.Sum256(doc), true
	e.fake.setStatus(&st, nil)
	e.s.dropStatus()
	return doc
}

// pendingRows returns how many pending accounts name has: 0 or 1, since
// the name is the table's primary key.
func (e *adminEnv) pendingRows(t *testing.T, name string) int {
	t.Helper()
	_, err := e.s.db.PendingUser(context.Background(), name)
	if errors.Is(err, serverdb.ErrNotFound) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return 1
}

func TestAdminUsers(t *testing.T) {
	t.Run("add_creates_pending_account_and_invite", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		// An installed directory, so the add's directory lookup is a signer
		// read (at version 0 the mirror answers without one, 02-09).
		e.installDirectory(t)
		res := e.addUser(t, "carol", false, "")
		if res.Code != http.StatusCreated || res.Header().Get(serverclient.CustodyHeader) == "" {
			t.Fatalf("= %d (custody %q) %s", res.Code, res.Header().Get(serverclient.CustodyHeader), res.Body)
		}
		var out serverclient.AddUserResponse
		if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		token, ok := strings.CutPrefix(out.InviteURL, "https://"+testRPID+"/enroll/")
		if out.Name != "carol" || !ok || len(token) != 43 || out.ExpiresAt != t0.Add(24*time.Hour).Format(time.RFC3339) {
			t.Fatalf("answer %+v", out)
		}
		u, err := e.s.db.PendingUser(context.Background(), "carol")
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(token))
		if !bytes.Equal(u.InviteHash, sum[:]) || len(u.UserHandle) != 32 || u.CreatedBy != "root-admin" {
			t.Fatalf("pending row %+v: want the token's SHA-256, a 32-byte handle, created by root-admin", u)
		}
		if strings.Contains(e.log.String(), token) {
			t.Fatalf("the log carries the invite token:\n%s", e.log)
		}
		if e.fake.count("GetDirectory") != 1 {
			t.Fatalf("GetDirectory calls %d, want 1", e.fake.count("GetDirectory"))
		}
	})

	t.Run("invalid_names_400", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		for _, name := range []string{"Alice", "-x", strings.Repeat("a", 65), "", "a b", "../x"} {
			if res := e.addUser(t, name, false, ""); res.Code != http.StatusBadRequest {
				t.Fatalf("add %q = %d, want 400", name, res.Code)
			}
		}
		if res := e.addUser(t, strings.Repeat("a", 64), false, ""); res.Code != http.StatusCreated {
			t.Fatalf("control: a 64-character name = %d, want 201", res.Code)
		}
	})

	t.Run("unknown_field_400", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		body := []byte(`{"name":"carol","reinvite":false,"admin":true}`)
		req := signedReq(t, e.admin, http.MethodPost, serverclient.AdminUsersPath, serverclient.AdminUsersPath, body, t0)
		if res := serve(e.s.Handler(), req); res.Code != http.StatusBadRequest {
			t.Fatalf("= %d, want 400", res.Code)
		}
	})

	t.Run("name_in_directory_409", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		e.installDirectory(t)
		res := e.addUser(t, "alice", false, "")
		if res.Code != http.StatusConflict || strings.TrimSpace(res.Body.String()) != `{"error":"already in directory"}` {
			t.Fatalf("= %d %s, want 409 already in directory", res.Code, res.Body)
		}
		if e.pendingRows(t, "alice") != 0 {
			t.Fatal("a refused add left a pending row")
		}
	})

	t.Run("duplicate_pending_409", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		first := e.mustAdd(t, "carol", false)
		res := e.addUser(t, "carol", false, "")
		if res.Code != http.StatusConflict || strings.TrimSpace(res.Body.String()) != `{"error":"already pending"}` {
			t.Fatalf("= %d %s, want 409 already pending", res.Code, res.Body)
		}
		if r := e.getInvite(t, first.InviteURL); r.Code != http.StatusOK {
			t.Fatalf("the first invite stopped working after a refused add: %d", r.Code)
		}
	})

	t.Run("concurrent_add_same_name", func(t *testing.T) {
		const want409 = `{"error":"already pending"}`
		t.Run("held", func(t *testing.T) {
			e := newAdminEnv(t, Limits{})
			e.installDirectory(t) // at version 0 the mirror reads nothing (02-09)
			entered, release := e.fake.hold("GetDirectory")
			defer release()
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- e.addUser(t, "erin", false, "") }()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("the add never reached GetDirectory")
			}
			stored := serverdb.PendingUser{
				Name: "erin", UserHandle: bytes.Repeat([]byte{1}, 32), InviteHash: bytes.Repeat([]byte{2}, 32),
				InviteExpires: t0.Add(time.Hour), Created: t0, CreatedBy: "test",
			}
			if err := e.s.db.CreatePendingUser(context.Background(), stored); err != nil {
				t.Fatal(err)
			}
			release()
			res := <-done
			if res.Code != http.StatusConflict || strings.TrimSpace(res.Body.String()) != want409 {
				t.Fatalf("held add after the row appeared = %d %s, want 409 %s", res.Code, res.Body, want409)
			}
			u, err := e.s.db.PendingUser(context.Background(), "erin")
			if err != nil || !bytes.Equal(u.InviteHash, stored.InviteHash) || e.pendingRows(t, "erin") != 1 {
				t.Fatalf("erin's row %+v, %v; want exactly the stored row", u, err)
			}
		})
		t.Run("parallel", func(t *testing.T) {
			for range 10 {
				e := newAdminEnv(t, Limits{})
				codes := make([]int, 2)
				var wg sync.WaitGroup
				for i := range codes {
					wg.Add(1)
					go func() {
						defer wg.Done()
						codes[i] = e.addUser(t, "erin", false, "").Code
					}()
				}
				wg.Wait()
				if oneEach := (codes[0] == 201 && codes[1] == 409) || (codes[0] == 409 && codes[1] == 201); !oneEach || e.pendingRows(t, "erin") != 1 {
					t.Fatalf("two parallel adds = %v, rows %d; want one 201, one 409, one row", codes, e.pendingRows(t, "erin"))
				}
			}
		})
	})

	t.Run("reinvite_invalidates_old_token", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		first := e.mustAdd(t, "carol", false)
		before, err := e.s.db.PendingUser(context.Background(), "carol")
		if err != nil {
			t.Fatal(err)
		}
		second := e.mustAdd(t, "carol", true)
		if first.InviteURL == second.InviteURL {
			t.Fatal("the reinvite returned the same URL")
		}
		old := e.getInvite(t, first.InviteURL)
		if old.Code != http.StatusNotFound || !strings.Contains(old.Body.String(), "Invite not valid") {
			t.Fatalf("old invite = %d, want the uniform 404", old.Code)
		}
		if r := e.getInvite(t, second.InviteURL); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "carol") {
			t.Fatalf("new invite = %d", r.Code)
		}
		after, err := e.s.db.PendingUser(context.Background(), "carol")
		if err != nil || !bytes.Equal(after.UserHandle, before.UserHandle) || e.pendingRows(t, "carol") != 1 {
			t.Fatalf("after the reinvite %+v, %v; want one row with the same user handle", after, err)
		}
	})

	t.Run("reinvite_directory_user", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		doc := e.installDirectory(t)
		out := e.mustAdd(t, "alice", true)
		u, err := e.s.db.PendingUser(context.Background(), "alice")
		if err != nil || len(u.UserHandle) != 32 {
			t.Fatalf("pending row %+v, %v; want a 32-byte user handle", u, err)
		}
		if r := e.getInvite(t, out.InviteURL); r.Code != http.StatusOK {
			t.Fatalf("invite = %d", r.Code)
		}
		d, err := e.fake.GetDirectory(context.Background())
		if err != nil || d.Version != 1 || !bytes.Equal(d.Directory, doc) {
			t.Fatal("the signer's directory changed")
		}
		// The assertion above cannot fail in forced mode; this one can: a
		// reinvite never asks the signer to install anything (02-07 D4).
		if n := e.fake.count("InstallDirectory"); n != 0 {
			t.Fatalf("the reinvite made %d InstallDirectory calls, want 0", n)
		}
	})

	t.Run("reinvite_directory_user_with_pending_row", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		e.installDirectory(t)
		first := e.mustAdd(t, "alice", true) // extra-passkey invite: a new pending row
		before, err := e.s.db.PendingUser(context.Background(), "alice")
		if err != nil {
			t.Fatal(err)
		}
		second := e.mustAdd(t, "alice", true)
		if r := e.getInvite(t, first.InviteURL); r.Code != http.StatusNotFound {
			t.Fatalf("old invite = %d, want 404", r.Code)
		}
		if r := e.getInvite(t, second.InviteURL); r.Code != http.StatusOK {
			t.Fatalf("new invite = %d, want 200", r.Code)
		}
		after, err := e.s.db.PendingUser(context.Background(), "alice")
		if err != nil || !bytes.Equal(after.UserHandle, before.UserHandle) || e.pendingRows(t, "alice") != 1 {
			t.Fatalf("after the second reinvite %+v, %v; want one row with the same handle", after, err)
		}
		if d, _ := e.fake.GetDirectory(context.Background()); d.Version != 1 || e.fake.count("InstallDirectory") != 0 {
			t.Fatal("the signer's directory changed, or the reinvite asked the signer to install a version (02-07 D4)")
		}
		// Control: without reinvite the pending check refuses first.
		if res := e.addUser(t, "alice", false, ""); res.Code != http.StatusConflict || strings.TrimSpace(res.Body.String()) != `{"error":"already pending"}` {
			t.Fatalf("add alice without reinvite = %d %s, want 409 already pending", res.Code, res.Body)
		}
	})

	t.Run("reinvite_unknown_name_is_plain_add", func(t *testing.T) {
		// Neither pending nor in the directory: --reinvite continues as a
		// plain add, with a new row and a working invite.
		e := newAdminEnv(t, Limits{})
		e.installDirectory(t)
		out := e.mustAdd(t, "dave", true)
		u, err := e.s.db.PendingUser(context.Background(), "dave")
		if err != nil || len(u.UserHandle) != 32 || u.CreatedBy != "root-admin" {
			t.Fatalf("pending row %+v, %v; want a new row with a 32-byte handle by root-admin", u, err)
		}
		if r := e.getInvite(t, out.InviteURL); r.Code != http.StatusOK {
			t.Fatalf("invite = %d, want 200", r.Code)
		}
	})

	t.Run("invite_url_origin_matches_request_host", func(t *testing.T) {
		e := newAdminEnv(t, Limits{}, "https://"+testRPID, "https://"+testRPID+":8443")
		for i, tc := range []struct{ host, want string }{
			{testRPID + ":8443", "https://" + testRPID + ":8443/enroll/"},
			{testRPID + ":443", "https://" + testRPID + "/enroll/"},
			{testRPID, "https://" + testRPID + "/enroll/"},
		} {
			res := e.addUser(t, "user"+strconv.Itoa(i), false, tc.host)
			var out serverclient.AddUserResponse
			if res.Code != http.StatusCreated || json.Unmarshal(res.Body.Bytes(), &out) != nil || !strings.HasPrefix(out.InviteURL, tc.want) {
				t.Fatalf("Host %s: %d %s, want an invite URL starting %s", tc.host, res.Code, res.Body, tc.want)
			}
		}
		// A Host that is not a policy origin no longer reaches the handler:
		// the admin signature is bound to a policy origin (requireAdmin).
		if res := e.addUser(t, "user9", false, "other.example:9000"); res.Code != http.StatusUnauthorized || e.pendingRows(t, "user9") != 0 {
			t.Fatalf("Host other.example:9000: %d, want the uniform 401 and no row", res.Code)
		}
	})

	t.Run("directory_cache", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		e.installDirectory(t)
		e.mustAdd(t, "carol", false)
		e.mustAdd(t, "dave", false)
		if n := e.fake.count("GetDirectory"); n != 1 {
			t.Fatalf("GetDirectory calls %d for two adds at one directory version, want 1", n)
		}
	})

	t.Run("directory_cache_follows_status", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		v1 := e.installDirectory(t)
		e.mustAdd(t, "carol", false) // caches version 1
		d, err := directory.Parse(v1)
		if err != nil {
			t.Fatal(err)
		}
		d.Version, d.Prev = 2, hex.EncodeToString(func() []byte { s := sha256.Sum256(v1); return s[:] }())
		d.Users = append(d.Users, directory.User{Name: "bob", Status: directory.StatusDisabled, Credentials: []directory.Credential{}})
		d.Sort()
		v2, err := d.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := directory.Parse(v2); err != nil {
			t.Fatal(err)
		}
		e.fake.setDirectory(&wire.GetDirectoryResponse{Version: 2, Directory: v2, Sigs: []byte("sigs"), Authorized: true}, nil)
		e.fake.mu.Lock()
		st := withDirectory(e.fake.status, 2)
		e.fake.mu.Unlock()
		st.DirectorySHA256 = sha256.Sum256(v2)
		e.fake.setStatus(st, nil)
		e.s.dropStatus()
		if res := e.addUser(t, "bob", false, ""); res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "already in directory") {
			t.Fatalf("add bob after version 2 = %d %s, want 409 already in directory (no stale cache)", res.Code, res.Body)
		}
	})

	t.Run("directory_read_error_fails_closed", func(t *testing.T) {
		// alice is in the installed directory, but GetDirectory fails: the
		// add is refused 503 and writes nothing, never a plain add.
		e := newAdminEnv(t, Limits{})
		e.installDirectory(t)
		e.fake.setDirectory(nil, errors.New("signer read failed"))
		if res := e.addUser(t, "alice", false, ""); res.Code != http.StatusServiceUnavailable || e.pendingRows(t, "alice") != 0 {
			t.Fatalf("= %d %s (rows %d), want 503 and no pending row: a failed directory read is never \"no such user\"", res.Code, res.Body, e.pendingRows(t, "alice"))
		}
	})

	t.Run("unparsable_directory_fails_closed", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		bad := []byte(`{"version":1}`)
		e.fake.setDirectory(&wire.GetDirectoryResponse{Version: 1, Directory: bad, Sigs: []byte("s"), Authorized: true}, nil)
		// Status reports exactly those bytes, so the mirror reads and parses
		// them (02-09: a Status at version 0 is answered without a read).
		st := withDirectory(e.fake.statusNow(), 1)
		st.DirectorySHA256 = sha256.Sum256(bad)
		e.fake.setStatus(st, nil)
		if res := e.addUser(t, "carol", false, ""); res.Code != http.StatusServiceUnavailable {
			t.Fatalf("= %d, want 503: a directory that does not parse is never \"no such user\"", res.Code)
		}
	})
}

// TestAdminPendingRoute (pre-merge review): GET
// /api/v1/admin/users/{name}/pending is wrapped like POST
// /api/v1/admin/users, through the full handler. Every request requireAdmin
// refuses gets the uniform 401 and never reaches the handler (no "pending
// credentials listed" line, and an unknown name is not told apart), and
// the per-client admin limiter answers 429 past its burst.
func TestAdminPendingRoute(t *testing.T) {
	listed := func(e *adminEnv) int { return strings.Count(e.log.String(), `"msg":"pending credentials listed"`) }
	carol := serverclient.AdminPendingPath("carol")
	t.Run("refused_requests_uniform_401", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		e.mustAdd(t, "carol", false)
		now := e.clock.Now()
		digestOfOther := signedReq(t, e.admin, http.MethodGet, carol, carol, nil, now)
		sum := sha256.Sum256([]byte("x"))
		digestOfOther.Header.Set(adminauth.HeaderBodySHA256, hex.EncodeToString(sum[:]))
		for _, tc := range []struct {
			name string
			req  *http.Request
		}{
			{"unsigned", signedReq(t, nil, http.MethodGet, carol, carol, nil, now)},
			{"unsigned_unknown_name", signedReq(t, nil, http.MethodGet, serverclient.AdminPendingPath("nobody"), serverclient.AdminPendingPath("nobody"), nil, now)},
			{"other_deployment_origin", signedReqFor(t, e.admin, "https://staging.example", http.MethodGet, carol, carol, nil, now)},
			{"digest_mismatch", digestOfOther},
			{"non_admin_key", signedReq(t, newSigner(t), http.MethodGet, carol, carol, nil, now)},
			{"signed_for_another_name", signedReq(t, e.admin, http.MethodGet, carol, serverclient.AdminPendingPath("dave"), nil, now)},
		} {
			res := serve(e.s.Handler(), tc.req)
			if res.Code != http.StatusUnauthorized || res.Body.String() != uniform401 {
				t.Fatalf("%s: %d %q, want the uniform 401", tc.name, res.Code, res.Body)
			}
		}
		if n := listed(e); n != 0 {
			t.Fatalf("the pending handler ran %d times for refused requests", n)
		}
		// Control: the correctly signed GET is answered and logged.
		if res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodGet, carol, carol, nil, now)); res.Code != http.StatusOK || listed(e) != 1 {
			t.Fatalf("signed GET = %d %s (listed %d), want 200 and one line", res.Code, res.Body, listed(e))
		}
	})
	t.Run("admin_limiter_429", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		e.mustAdd(t, "carol", false) // one token of the burst
		for i := range defaultAdminBurst - 1 {
			if res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodGet, carol, carol, nil, e.clock.Now())); res.Code != http.StatusOK {
				t.Fatalf("GET %d = %d %s, want 200 (within the burst)", i+1, res.Code, res.Body)
			}
		}
		res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodGet, carol, carol, nil, e.clock.Now()))
		if res.Code != http.StatusTooManyRequests {
			t.Fatalf("GET burst+1 = %d %s, want 429", res.Code, res.Body)
		}
		if n := listed(e); n != defaultAdminBurst-1 {
			t.Fatalf("%d pending lists answered, want %d", n, defaultAdminBurst-1)
		}
	})
}

func TestRequestOrigin(t *testing.T) {
	// requestOrigin names the policy origin the Host reached, and otherwise
	// the first policy origin in sorted order: never anything outside the
	// list (T-02-96). 02-12's approval URL reaches the fallback on an
	// unauthenticated route. The list is deliberately unsorted.
	origins := []string{"https://b.example", "https://a.example:8443", "https://a.example"}
	for _, tc := range []struct{ host, want string }{
		{"a.example", "https://a.example"},
		{"a.example:443", "https://a.example"},
		{"a.example:8443", "https://a.example:8443"},
		{"b.example", "https://b.example"},
		{"b.example:443", "https://b.example"},
		// Not a policy origin: the first sorted origin.
		{"attacker.example", "https://a.example"},
		{"b.example:9000", "https://a.example"},
		{"a.example.attacker.example", "https://a.example"},
		{"attacker.example/https://a.example", "https://a.example"},
		{"A.EXAMPLE", "https://a.example"},
		{"a.example.", "https://a.example"},
		{"a.example:", "https://a.example"},
		{"a.example:443:443", "https://a.example"},
		{"[::1]:443", "https://a.example"},
		{"a.example\r\nX-Evil: 1", "https://a.example"},
		{"", "https://a.example"},
	} {
		r := httptest.NewRequest("GET", "/enroll/x", nil)
		r.Host = tc.host
		got := requestOrigin(r, origins)
		if got != tc.want || !slices.Contains(origins, got) {
			t.Fatalf("Host %q: requestOrigin = %q, want %q (a member of %q)", tc.host, got, tc.want, origins)
		}
	}
	for _, empty := range [][]string{nil, {}} {
		r := httptest.NewRequest("GET", "/enroll/x", nil)
		r.Host = "a.example"
		if got := requestOrigin(r, empty); got != "" {
			t.Fatalf("no policy origins %#v: requestOrigin = %q, want \"\"", empty, got)
		}
	}
}

func TestInvitePage(t *testing.T) {
	e := newAdminEnv(t, Limits{})
	out := e.mustAdd(t, "carol", false)
	token := out.InviteURL[strings.Index(out.InviteURL, "/enroll/")+len("/enroll/"):]

	t.Run("valid_invite", func(t *testing.T) {
		r := e.getInvite(t, out.InviteURL)
		if r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "Welcome, carol") || !strings.Contains(r.Body.String(), testRPID) ||
			!strings.Contains(r.Body.String(), "run it before keyroster login") {
			t.Fatalf("= %d:\n%s", r.Code, r.Body)
		}
		body := r.Body.String()
		if r.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("the invite page lacks Referrer-Policy no-referrer")
		}
		// One script, the embedded app.js, and no inline script (02-08):
		// the page's data reaches it through data- attributes only.
		if strings.Count(body, "<script") != 1 || !strings.Contains(body, `<script src="/static/app.js" defer></script>`) {
			t.Fatalf("the invite page does not carry exactly the one app.js script:\n%s", body)
		}
		for _, want := range []string{`data-begin="/api/v1/enroll/` + token + `/begin"`, `data-finish="/api/v1/enroll/` + token + `/finish"`} {
			if !strings.Contains(body, want) {
				t.Fatalf("the invite page lacks %s:\n%s", want, body)
			}
		}
		requireHeaders(t, "invite page", r)
	})
	uniform := ""
	for _, tc := range []struct{ name, path string }{
		{"unknown_token", "/enroll/" + strings.Repeat("A", 43)},
		{"malformed_token", "/enroll/short"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := do(e.s, http.MethodGet, tc.path, nil)
			if r.Code != http.StatusNotFound || !strings.Contains(r.Body.String(), "Invite not valid") {
				t.Fatalf("= %d:\n%s", r.Code, r.Body)
			}
			if uniform == "" {
				uniform = r.Body.String()
			} else if r.Body.String() != uniform {
				t.Fatal("the not-valid pages differ")
			}
		})
	}
	t.Run("expired_token_404", func(t *testing.T) {
		e.clock.set(t0.Add(24*time.Hour - time.Second))
		if r := e.getInvite(t, out.InviteURL); r.Code != http.StatusOK {
			t.Fatalf("one second before expiry = %d, want 200", r.Code)
		}
		e.clock.set(t0.Add(24 * time.Hour))
		r := e.getInvite(t, out.InviteURL)
		if r.Code != http.StatusNotFound || r.Body.String() != uniform {
			t.Fatalf("at expiry = %d, want the uniform 404:\n%s", r.Code, r.Body)
		}
	})
	t.Run("token_never_logged", func(t *testing.T) {
		if strings.Contains(e.log.String(), token) {
			t.Fatalf("the log carries the invite token:\n%s", e.log)
		}
	})
}

func TestRateLimit(t *testing.T) {
	get := func(s *Server, remote string, hdr map[string]string) int {
		req := httptest.NewRequest(http.MethodGet, "https://"+testRPID+"/enroll/"+strings.Repeat("A", 43), nil)
		req.RemoteAddr = remote
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		return serve(s.Handler(), req).Code
	}

	t.Run("rate_limited_429", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		for i := range defaultInviteBurst {
			if c := get(e.s, "192.0.2.10:1000", nil); c != http.StatusNotFound {
				t.Fatalf("invite request %d = %d, want 404 (within the burst)", i, c)
			}
		}
		req := httptest.NewRequest(http.MethodGet, "https://"+testRPID+"/enroll/x", nil)
		req.RemoteAddr = "192.0.2.10:1000"
		res := serve(e.s.Handler(), req)
		if res.Code != http.StatusTooManyRequests || res.Header().Get("Retry-After") != "2" {
			t.Fatalf("invite request burst+1 = %d (Retry-After %q), want 429 with 2", res.Code, res.Header().Get("Retry-After"))
		}
		requireHeaders(t, "429 page", res)
		for i := range defaultAdminBurst {
			if res := e.addUser(t, "u"+strconv.Itoa(i), false, ""); res.Code != http.StatusCreated {
				t.Fatalf("admin request %d = %d, want 201 (within the burst)", i, res.Code)
			}
		}
		res = e.addUser(t, "over", false, "")
		if res.Code != http.StatusTooManyRequests || res.Header().Get("Retry-After") != "1" {
			t.Fatalf("admin request burst+1 = %d (Retry-After %q), want 429 with 1", res.Code, res.Header().Get("Retry-After"))
		}
		// Refilled after the bucket's interval.
		e.clock.set(t0.Add(2 * time.Second))
		if c := get(e.s, "192.0.2.10:1000", nil); c != http.StatusNotFound {
			t.Fatalf("after 2 s = %d, want a refilled token", c)
		}
	})

	t.Run("ipv6_same_64_shares_bucket", func(t *testing.T) {
		a := &http.Request{RemoteAddr: "[2001:db8:1:2::1]:443"}
		b := &http.Request{RemoteAddr: "[2001:db8:1:2:ffff:ffff:ffff:fffe]:5000"}
		c := &http.Request{RemoteAddr: "[2001:db8:1:3::1]:443"}
		if clientKey(a) != clientKey(b) || clientKey(a) == clientKey(c) || clientKey(a) != "2001:db8:1:2::/64" {
			t.Fatalf("keys %q %q %q", clientKey(a), clientKey(b), clientKey(c))
		}
		e := newAdminEnv(t, Limits{InvitePerMinute: 1, InviteBurst: 1})
		if c := get(e.s, a.RemoteAddr, nil); c != http.StatusNotFound {
			t.Fatalf("first request from the /64 = %d", c)
		}
		if c := get(e.s, b.RemoteAddr, nil); c != http.StatusTooManyRequests {
			t.Fatalf("another address in the same /64 = %d, want 429", c)
		}
		if c := get(e.s, c.RemoteAddr, nil); c != http.StatusNotFound {
			t.Fatalf("an address in another /64 = %d, want its own bucket", c)
		}
	})

	t.Run("ipv4_and_mapped_share_bucket", func(t *testing.T) {
		if k1, k2 := clientKey(&http.Request{RemoteAddr: "192.0.2.5:1"}), clientKey(&http.Request{RemoteAddr: "[::ffff:192.0.2.5]:2"}); k1 != "192.0.2.5" || k2 != k1 {
			t.Fatalf("keys %q %q, want 192.0.2.5 for both", k1, k2)
		}
	})

	t.Run("forwarded_for_ignored", func(t *testing.T) {
		r := &http.Request{RemoteAddr: "192.0.2.20:1", Header: http.Header{"X-Forwarded-For": {"198.51.100.7"}, "Forwarded": {"for=198.51.100.8"}}}
		if k := clientKey(r); k != "192.0.2.20" {
			t.Fatalf("key %q, want the RemoteAddr host", k)
		}
		e := newAdminEnv(t, Limits{InvitePerMinute: 1, InviteBurst: 1})
		if c := get(e.s, "192.0.2.20:1", map[string]string{"X-Forwarded-For": "198.51.100.1"}); c != http.StatusNotFound {
			t.Fatalf("first = %d", c)
		}
		if c := get(e.s, "192.0.2.20:1", map[string]string{"X-Forwarded-For": "198.51.100.2"}); c != http.StatusTooManyRequests {
			t.Fatalf("a different X-Forwarded-For from the same address = %d, want 429", c)
		}
	})

	t.Run("admin_valid_request_not_refused_by_others", func(t *testing.T) {
		// Shaped like the pre-merge critic's probe: more unsigned or
		// junk-signed admin requests than the old global burst, each from
		// its own client key with a body of maxAdminBody bytes that stalls
		// once read. The handler reads none of the bodies, and a validly
		// signed request from another key succeeds meanwhile.
		e := newAdminEnv(t, Limits{})
		const n = globalFactor*defaultAdminBurst + 50
		junk := signedReqFor(t, e.admin, "https://staging.example", http.MethodPost, serverclient.AdminUsersPath, serverclient.AdminUsersPath, probeBody, t0).Header
		release := make(chan struct{})
		bodies := make([]*stallingReader, n)
		codes := make([]int, n)
		dones := make([]chan struct{}, n)
		for i := range n {
			bodies[i] = &stallingReader{started: make(chan struct{}), release: release}
			req := httptest.NewRequest(http.MethodPost, serverclient.AdminUsersPath, bodies[i])
			req.Host = testRPID
			req.ContentLength = maxAdminBody
			req.RemoteAddr = "198.51.100." + strconv.Itoa(i%250+1) + ":40000"
			if i >= 250 {
				req.RemoteAddr = "203.0.113." + strconv.Itoa(i-250+1) + ":40000"
			}
			if i%2 == 1 {
				req.Header = junk.Clone() // names the real admin key
			}
			dones[i] = make(chan struct{})
			go func() {
				defer close(dones[i])
				codes[i] = serve(e.s.Handler(), req).Code
			}()
		}
		// Every request has either been answered or is held in a body read.
		for i := range n {
			select {
			case <-dones[i]:
			case <-bodies[i].started:
			case <-time.After(10 * time.Second):
				t.Fatalf("request %d neither answered nor reading", i)
			}
		}
		res := e.addUser(t, "carol", false, "")
		close(release)
		for i := range n {
			<-dones[i]
		}
		if res.Code != http.StatusCreated {
			t.Fatalf("the valid admin request = %d %s, want 201 while %d other clients were refused", res.Code, res.Body, n)
		}
		for i := range n {
			if bodies[i].read() != 0 || codes[i] != http.StatusUnauthorized {
				t.Fatalf("request %d: %d, %d bytes of its body read; want the uniform 401 and nothing read", i, codes[i], bodies[i].read())
			}
		}
	})

	t.Run("global_backstop_429", func(t *testing.T) {
		e := newAdminEnv(t, Limits{InvitePerMinute: 1, InviteBurst: 1})
		for i := range globalFactor {
			if c := get(e.s, "198.51.100."+strconv.Itoa(i+1)+":1", nil); c != http.StatusNotFound {
				t.Fatalf("client %d = %d, want 404 within the global burst", i, c)
			}
		}
		if c := get(e.s, "198.51.100.200:1", nil); c != http.StatusTooManyRequests {
			t.Fatalf("a new client after the global burst = %d, want 429", c)
		}
	})

	t.Run("client_bucket_checked_before_global", func(t *testing.T) {
		// One client far over its own limit, and over the global burst:
		// its refused requests take no global token, so another client
		// still gets through.
		e := newAdminEnv(t, Limits{InvitePerMinute: 1, InviteBurst: 1})
		for i := range 3 * globalFactor {
			want := http.StatusTooManyRequests
			if i == 0 {
				want = http.StatusNotFound
			}
			if c := get(e.s, "198.51.100.1:1", nil); c != want {
				t.Fatalf("request %d from the hammering client = %d, want %d", i, c, want)
			}
		}
		if c := get(e.s, "198.51.100.2:1", nil); c != http.StatusNotFound {
			t.Fatalf("another client after one client's %d refused requests = %d, want 404 (the global bucket is not drained)", 3*globalFactor-1, c)
		}
	})

	t.Run("invite_token_not_logged_on_429", func(t *testing.T) {
		e := newAdminEnv(t, Limits{})
		out := e.mustAdd(t, "carol", false)
		path := out.InviteURL[strings.Index(out.InviteURL, "/enroll/"):]
		token := strings.TrimPrefix(path, "/enroll/")
		last := 0
		for range defaultInviteBurst + 1 {
			req := httptest.NewRequest(http.MethodGet, "https://"+testRPID+path, nil)
			req.RemoteAddr = "192.0.2.30:1"
			last = serve(e.s.Handler(), req).Code
		}
		if last != http.StatusTooManyRequests || !strings.Contains(e.log.String(), `"msg":"rate limited"`) {
			t.Fatalf("invite request burst+1 = %d, want 429 with its log line:\n%s", last, e.log)
		}
		if strings.Contains(e.log.String(), token) {
			t.Fatalf("the log carries the invite token after a 429:\n%s", e.log)
		}
	})

	t.Run("limiter_map_bounded", func(t *testing.T) {
		l := newLimiter(60, 20, 1<<30, 1<<30)
		for i := range 20000 {
			if !l.allow("client-"+strconv.Itoa(i), t0) {
				t.Fatalf("client %d refused", i)
			}
		}
		if n := l.size(); n > maxLimiterEntries {
			t.Fatalf("%d entries after 20000 clients, want at most %d", n, maxLimiterEntries)
		}
	})

	t.Run("idle_entries_evicted", func(t *testing.T) {
		l := newLimiter(60, 20, 1<<30, 1<<30)
		l.allow("a", t0)
		l.allow("b", t0.Add(limiterIdle))
		if n := l.size(); n != 1 {
			t.Fatalf("%d entries, want 1 after a's idle time", n)
		}
	})
}

// urlInviteHash returns the stored hash of an invite URL's token.
func urlInviteHash(t *testing.T, inviteURL string) []byte {
	t.Helper()
	i := strings.Index(inviteURL, "/enroll/")
	if i < 0 {
		t.Fatalf("invite URL %q has no /enroll/", inviteURL)
	}
	sum := sha256.Sum256([]byte(inviteURL[i+len("/enroll/"):]))
	return sum[:]
}

// TestDirectoryInstallCleanup: an accepted install deletes exactly the
// pending state its version makes obsolete, and refuses a version that
// newly binds a credential which is not pending for the user it binds it
// to (02-09-F6, cross-plan audit).
func TestDirectoryInstallCleanup(t *testing.T) {
	t.Run("install_keeps_unrelated_pending", func(t *testing.T) {
		v1 := vectorV1(t) // alice is in the directory
		e := chainEnv(t, v1)
		p1, p2 := newCredential(t), newCredential(t)
		e.storePending(t, "dave", p1)  // registered, approved by this install
		e.storePending(t, "carol", p2) // registered, not approved
		alice := e.mustAdd(t, "alice", true)
		before, err := e.s.db.PendingUser(context.Background(), "alice")
		if err != nil {
			t.Fatal(err)
		}
		if res := e.postDirectory(t, successor(t, v1, bind("dave", p1))); res.Code != http.StatusOK {
			t.Fatalf("install binding dave = %d %s", res.Code, res.Body)
		}
		if ids := e.pendingOf(t, "dave"); len(ids) != 0 || e.pendingRows(t, "dave") != 0 {
			t.Fatalf("dave after the install: pending %v, %d rows; want none", ids, e.pendingRows(t, "dave"))
		}
		if ids := e.pendingOf(t, "carol"); len(ids) != 1 || ids[0] != p2.ID || e.pendingRows(t, "carol") != 1 {
			t.Fatalf("carol after the install: pending %v, %d rows; want P2 and the row unchanged", ids, e.pendingRows(t, "carol"))
		}
		after, err := e.s.db.PendingUser(context.Background(), "alice")
		if err != nil || !bytes.Equal(after.InviteHash, before.InviteHash) {
			t.Fatalf("alice's open invite after the install: %+v, %v; want it unchanged", after, err)
		}
		if r := e.getInvite(t, alice.InviteURL); r.Code != http.StatusOK {
			t.Fatalf("alice's open invite = %d after the install, want 200", r.Code)
		}
	})

	t.Run("install_refuses_credential_no_longer_pending", func(t *testing.T) {
		e := chainEnv(t, nil)
		p1, p2, p3 := newCredential(t), newCredential(t), newCredential(t)
		first := e.mustAdd(t, "dave", false)
		e.bindPending(t, urlInviteHash(t, first.InviteURL), "dave", p1)
		withP1 := successor(t, nil, bind("dave", p1)) // built before the reinvite
		second := e.mustAdd(t, "dave", true)          // ReplaceInvite discards P1
		e.bindPending(t, urlInviteHash(t, second.InviteURL), "dave", p2)
		e.storePending(t, "carol", p3)
		requireAnswer(t, "install of the version binding the discarded P1", e.postDirectory(t, withP1), http.StatusConflict, "credential_not_pending")
		requireAnswer(t, "install binding carol's credential to dave", e.postDirectory(t, successor(t, nil, bind("dave", p3))), http.StatusConflict, "credential_not_pending")
		if n := e.fake.count("InstallDirectory"); n != 0 {
			t.Fatalf("InstallDirectory called %d times, want 0", n)
		}
		if ids := e.pendingOf(t, "dave"); len(ids) != 1 || ids[0] != p2.ID || e.pendingRows(t, "dave") != 1 {
			t.Fatalf("dave after the refusals: pending %v, %d rows; want P2 and the row", ids, e.pendingRows(t, "dave"))
		}
		// Control: the version binding P2 to dave installs.
		if res := e.postDirectory(t, successor(t, nil, bind("dave", p2))); res.Code != http.StatusOK {
			t.Fatalf("install binding P2 = %d %s", res.Code, res.Body)
		}
		if ids := e.pendingOf(t, "dave"); len(ids) != 0 {
			t.Fatalf("dave still has pending %v after P2 was bound", ids)
		}
	})

	t.Run("install_refuses_reused_id_with_other_key", func(t *testing.T) {
		// The passkey registered after the reinvite reuses the discarded
		// credential's ID with a new key: a proposal written before the
		// reinvite still must not bind the discarded key (pre-merge review,
		// 02-09).
		e := chainEnv(t, nil)
		p1, p2 := newCredential(t), newCredential(t)
		p2.ID = p1.ID // only the key differs
		first := e.mustAdd(t, "dave", false)
		e.bindPending(t, urlInviteHash(t, first.InviteURL), "dave", p1)
		withP1 := successor(t, nil, bind("dave", p1)) // built before the reinvite
		second := e.mustAdd(t, "dave", true)          // ReplaceInvite discards P1
		e.bindPending(t, urlInviteHash(t, second.InviteURL), "dave", p2)
		requireAnswer(t, "install of the version binding the discarded key under the reused ID", e.postDirectory(t, withP1), http.StatusConflict, "credential_not_pending")
		if n := e.fake.count("InstallDirectory"); n != 0 {
			t.Fatalf("InstallDirectory called %d times, want 0", n)
		}
		creds, err := e.s.db.PendingCredentials(context.Background(), "dave")
		if err != nil || len(creds) != 1 || creds[0].ID != p2.ID || base64.StdEncoding.EncodeToString(creds[0].SPKI) != p2.SPKI || e.pendingRows(t, "dave") != 1 {
			t.Fatalf("dave after the refusals: %+v, %v; want P2 with its key, and the row", creds, err)
		}
		// Control: the version binding P2 itself installs and clears it.
		if res := e.postDirectory(t, successor(t, nil, bind("dave", p2))); res.Code != http.StatusOK {
			t.Fatalf("install binding P2 = %d %s", res.Code, res.Body)
		}
		if ids := e.pendingOf(t, "dave"); len(ids) != 0 {
			t.Fatalf("dave still has pending %v after P2 was bound", ids)
		}
	})
}

// sentSigner is the fake signer whose InstallDirectory, once called, is
// not stopped by the end of ctx, as signerclient's call is not once the
// request is sent.
type sentSigner struct{ *fakeSigner }

func (s sentSigner) InstallDirectory(ctx context.Context, req *wire.InstallDirectoryRequest) (*wire.InstallDirectoryResponse, error) {
	return s.fakeSigner.InstallDirectory(context.WithoutCancel(ctx), req)
}

// TestDirectoryInstallPending: pendingMu orders an install against a
// reinvite, and the install's cleanup heals itself (02-09-R2-F1,
// 02-09-R2-F4).
func TestDirectoryInstallPending(t *testing.T) {
	t.Run("reinvite_waits_for_running_install", func(t *testing.T) {
		e := chainEnv(t, nil)
		p1 := newCredential(t)
		first := e.mustAdd(t, "dave", false)
		e.bindPending(t, urlInviteHash(t, first.InviteURL), "dave", p1)
		before, err := e.s.db.PendingUser(context.Background(), "dave")
		if err != nil {
			t.Fatal(err)
		}
		h1 := before.UserHandle
		version := successor(t, nil, bind("dave", p1))

		entered, release := e.fake.hold("InstallDirectory")
		defer release()
		installed := make(chan *httptest.ResponseRecorder, 1)
		go func() { installed <- e.postDirectory(t, version) }()
		select {
		case <-entered: // the install handler holds pendingMu
		case <-time.After(10 * time.Second):
			t.Fatal("the install never reached the signer")
		}
		gd := e.fake.count("GetDirectory")
		reinvited := make(chan *httptest.ResponseRecorder, 1)
		go func() { reinvited <- e.addUser(t, "dave", true, "") }()
		time.Sleep(200 * time.Millisecond)
		select {
		case res := <-reinvited:
			t.Fatalf("the reinvite answered %d while the install was in flight, want it to wait", res.Code)
		default:
		}
		if n := e.fake.count("GetDirectory"); n != gd {
			t.Fatalf("the reinvite made %d GetDirectory calls while waiting, want 0 (it stops before its lookups)", n-gd)
		}
		if u, err := e.s.db.PendingUser(context.Background(), "dave"); err != nil || !bytes.Equal(u.InviteHash, before.InviteHash) || !bytes.Equal(u.UserHandle, h1) {
			t.Fatalf("dave's row changed while the install held the lock: %+v, %v", u, err)
		}
		release()
		if res := <-installed; res.Code != http.StatusOK {
			t.Fatalf("install = %d %s", res.Code, res.Body)
		}
		res := <-reinvited
		if res.Code != http.StatusCreated {
			t.Fatalf("reinvite = %d %s, want 201 after the install", res.Code, res.Body)
		}
		// The end state is the install's: P1 bound, and the reinvite is an
		// invite for one more passkey under a fresh user handle.
		d, err := directory.Parse(e.fake.heldDirectory())
		if err != nil || len(d.Users) != 1 || d.Users[0].Name != "dave" || len(d.Users[0].Credentials) != 1 || d.Users[0].Credentials[0].ID != p1.ID {
			t.Fatalf("the signer holds %+v, %v; want dave with P1", d, err)
		}
		if n := e.fake.count("InstallDirectory"); n != 1 {
			t.Fatalf("InstallDirectory called %d times, want 1", n)
		}
		st, err := e.s.db.PendingState(context.Background(), "dave")
		if err != nil || len(st.Credentials) != 0 || st.InviteUsed || !st.User.InviteExpires.After(e.clock.Now()) || bytes.Equal(st.User.UserHandle, h1) {
			t.Fatalf("dave's pending state %+v, %v; want one row with an open invite, no credential and a user handle other than H1", st, err)
		}
		var out serverclient.AddUserResponse
		if err := json.Unmarshal(res.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if r := e.getInvite(t, out.InviteURL); r.Code != http.StatusOK {
			t.Fatalf("the reinvite's URL = %d, want 200", r.Code)
		}
	})

	t.Run("orphan_pending_cleaned_on_next_install", func(t *testing.T) {
		x := newCredential(t)
		base := successor(t, nil, bind("frank", x))
		e := chainEnv(t, base)
		p1, p3 := newCredential(t), newCredential(t)
		e.storePending(t, "erin", x) // the same ID as frank's bound X
		e.storePending(t, "carol", p3)
		e.storePending(t, "dave", p1)

		e.fake.setLoseAnswer(true)
		v2 := successor(t, base, bind("dave", p1))
		requireAnswer(t, "install whose answer is lost", e.postDirectory(t, v2), http.StatusServiceUnavailable, "signer unavailable")
		if !bytes.Equal(e.fake.heldDirectory(), v2) {
			t.Fatal("the fake does not hold the version whose answer was lost")
		}
		if ids := e.pendingOf(t, "dave"); len(ids) != 1 || e.pendingRows(t, "dave") != 1 {
			t.Fatalf("dave after the lost answer: pending %v, %d rows; want the orphan", ids, e.pendingRows(t, "dave"))
		}

		e.fake.setLoseAnswer(false)
		if res := e.postDirectory(t, successor(t, v2, withRole("dev"))); res.Code != http.StatusOK {
			t.Fatalf("role-only install = %d %s", res.Code, res.Body)
		}
		if ids := e.pendingOf(t, "dave"); len(ids) != 0 || e.pendingRows(t, "dave") != 0 {
			t.Fatalf("dave after the next install: pending %v, %d rows; want none", ids, e.pendingRows(t, "dave"))
		}
		if ids := e.pendingOf(t, "carol"); len(ids) != 1 || ids[0] != p3.ID {
			t.Fatalf("carol's pending %v, want P3 unchanged", ids)
		}
		if ids := e.pendingOf(t, "erin"); len(ids) != 1 || ids[0] != x.ID || e.pendingRows(t, "erin") != 1 {
			t.Fatalf("erin's pending %v, want X unchanged: X is bound to frank, not erin", ids)
		}
	})

	t.Run("cleanup_survives_client_hangup", func(t *testing.T) {
		// The client goes away while the signer installs: signerclient uses
		// ctx only for the dial and the deadline, so the signer's success
		// still arrives, and the cleanup must not run on the cancelled
		// request context (pre-merge review, 02-09).
		e := chainEnv(t, nil)
		e.s.signer = sentSigner{e.fake}
		p1 := newCredential(t)
		e.storePending(t, "dave", p1)
		version := successor(t, nil, bind("dave", p1))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		req := signedReq(t, e.admin, http.MethodPost, serverclient.AdminDirectoryPath, serverclient.AdminDirectoryPath, installBody(t, version, testSigs), e.clock.Now()).WithContext(ctx)
		entered, release := e.fake.hold("InstallDirectory")
		defer release()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- serve(e.s.Handler(), req) }()
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the install never reached the signer")
		}
		cancel() // the client hangs up
		release()
		<-done
		if !bytes.Equal(e.fake.heldDirectory(), version) {
			t.Fatal("the fake does not hold the installed version")
		}
		if ids := e.pendingOf(t, "dave"); len(ids) != 0 || e.pendingRows(t, "dave") != 0 {
			t.Fatalf("dave after an install whose client hung up: pending %v, %d rows; want none\nlog:\n%s", ids, e.pendingRows(t, "dave"), e.log)
		}
		if strings.Contains(e.log.String(), "pending_cleanup_failed") {
			t.Fatalf("the cleanup failed:\n%s", e.log)
		}
	})

	t.Run("cleanup_failure_still_reports_install", func(t *testing.T) {
		e := chainEnv(t, nil)
		p1 := newCredential(t)
		e.storePending(t, "dave", p1)
		version := successor(t, nil, bind("dave", p1))
		entered, release := e.fake.hold("InstallDirectory")
		defer release()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() { done <- e.postDirectory(t, version) }()
		select {
		case <-entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the install never reached the signer")
		}
		if err := e.s.db.Close(); err != nil { // steps 1 to 3 have used it already
			t.Fatal(err)
		}
		release()
		res := <-done
		var ans serverclient.InstallDirectoryAnswer
		if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &ans) != nil || ans.Version != 1 || ans.SHA256 != trust.SHA256Hex(version) || ans.LeafIndex != 1 {
			t.Fatalf("install with a failing cleanup = %d %s, want 200 with version 1, its SHA-256 and leaf 1", res.Code, res.Body)
		}
		if !bytes.Equal(e.fake.heldDirectory(), version) {
			t.Fatal("the fake does not hold the installed version")
		}
		if n := strings.Count(e.log.String(), `"msg":"pending_cleanup_failed"`); n != 1 {
			t.Fatalf("%d pending_cleanup_failed lines, want 1:\n%s", n, e.log)
		}
	})
}
