package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// setRevoke sets Revoke's result.
func (f *fakeSigner) setRevoke(resp *wire.RevokeResponse, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoke, f.revokeErr = resp, err
}

// lastRevokeRequest returns the last request Revoke was given.
func (f *fakeSigner) lastRevokeRequest() *wire.RevokeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRevoke
}

// setKRL sets GetKRL's result.
func (f *fakeSigner) setKRL(resp *wire.GetKRLResponse, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.krl, f.krlErr = resp, err
}

// revokeBody is a POST AdminRevokePath body carrying a revoke request.
func revokeBody(t *testing.T) ([]byte, *wire.RevokeRequest) {
	t.Helper()
	req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: 42}
	return revokeBodyFor(t, req), req
}

// revokeBodyFor is a POST AdminRevokePath body carrying req, completed
// with an installation ID, a creation time and one evidence item.
func revokeBodyFor(t *testing.T, req *wire.RevokeRequest) []byte {
	t.Helper()
	req.InstallationID, req.CreatedAt = "0123456789abcdef0123456789abcdef", 1700000000
	req.Evidence = []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("sig")}}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(serverclient.RevokeBody{Request: raw})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestRevokeRoute (03-01): POST /api/v1/admin/revoke forwards the
// admin-signed request unchanged to the signer and relays its answer;
// without the admin signature it is 401 and reaches no signer; a signer
// refusal keeps its reason code; GET /api/v1/krl is 404 no_krl before any
// publish and serves the published KRL with no-store.
func TestRevokeRoute(t *testing.T) {
	body, want := revokeBody(t)
	post := func(e *adminEnv, signed bool) int {
		t.Helper()
		signer := e.admin
		if !signed {
			signer = nil
		}
		return serve(e.s.Handler(), signedReq(t, signer, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, body, e.clock.Now())).Code
	}
	t.Run("forwards_and_answers", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setRevoke(&wire.RevokeResponse{KRLVersion: 3, RevokeLeaf: 7, PublishLeaf: 8}, nil)
		res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, body, e.clock.Now()))
		var ans serverclient.RevokeAnswer
		if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &ans) != nil || ans.KRLVersion != 3 || ans.RevokeLeaf != 7 || ans.PublishLeaf != 8 ||
			ans.SerialCount != 0 || len(ans.Serials) != 0 {
			t.Fatalf("POST revoke = %d %s", res.Code, res.Body)
		}
		got := e.fake.lastRevokeRequest()
		gotRaw, _ := got.Marshal()
		wantRaw, _ := want.Marshal()
		if !bytes.Equal(gotRaw, wantRaw) {
			t.Fatal("the server did not forward the request unchanged")
		}
	})
	t.Run("no_admin_header_401", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		if code := post(e, false); code != http.StatusUnauthorized || e.fake.count("Revoke") != 0 {
			t.Fatalf("unsigned POST revoke = %d with %d signer calls, want 401 and none", code, e.fake.count("Revoke"))
		}
	})
	t.Run("signer_refusal_keeps_its_code", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		for _, tc := range []struct {
			resp *wire.ErrorResponse
			code int
		}{
			{&wire.ErrorResponse{Code: wire.CodeRefused, Message: "evidence_not_admin"}, http.StatusForbidden},
			{&wire.ErrorResponse{Code: wire.CodeMalformed, Message: "unknown_serial"}, http.StatusBadRequest},
			{&wire.ErrorResponse{Code: wire.CodeUnavailable, Message: "krl_no_installation_id"}, http.StatusServiceUnavailable},
		} {
			e.fake.setRevoke(nil, tc.resp)
			res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, body, e.clock.Now()))
			if tc.code == http.StatusServiceUnavailable {
				requireAnswer(t, tc.resp.Message, res, tc.code, "signer unavailable")
				continue
			}
			requireAnswer(t, tc.resp.Message, res, tc.code, tc.resp.Message)
		}
	})
	t.Run("malformed_request_400", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		bad, err := json.Marshal(serverclient.RevokeBody{Request: []byte{1, 2, 3}})
		if err != nil {
			t.Fatal(err)
		}
		res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, bad, e.clock.Now()))
		if res.Code != http.StatusBadRequest || e.fake.count("Revoke") != 0 {
			t.Fatalf("a malformed request = %d with %d signer calls, want 400 and none", res.Code, e.fake.count("Revoke"))
		}
	})
	t.Run("krl_404_before_publish", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		res := serve(e.s.Handler(), signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now()))
		requireAnswer(t, "GET krl", res, http.StatusNotFound, serverclient.KRLErrNone)
	})
	t.Run("krl_served", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setKRL(&wire.GetKRLResponse{KRL: []byte("krl"), Manifest: []byte("manifest"), Sig: []byte("sig")}, nil)
		res := serve(e.s.Handler(), signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now()))
		var doc serverclient.KRLDocument
		if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &doc) != nil || string(doc.KRL) != "krl" ||
			string(doc.Manifest) != "manifest" || string(doc.Sig) != "sig" || res.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("GET krl = %d %s %v", res.Code, res.Body, res.Header())
		}
	})
}

// TestRevokeAnswerSerials (03-03b): the signer's SerialCount and Serials
// reach the JSON answer unchanged (here a truncated answer: 4096 serials
// listed of 5000), and the "revoked" log line names the target kind and
// carries the serial only for the serial target, where it is not 0.
func TestRevokeAnswerSerials(t *testing.T) {
	serials := make([]uint64, wire.MaxRevokeAnswerSerials)
	for i := range serials {
		serials[i] = uint64(2*i + 1) //nolint:gosec // G115: a small test index
	}
	revokedLine := func(t *testing.T, log *logBuffer) map[string]any {
		t.Helper()
		var found map[string]any
		for _, l := range log.Lines() {
			var m map[string]any
			if err := json.Unmarshal([]byte(l), &m); err != nil {
				t.Fatalf("log line is not JSON: %q", l)
			}
			if m["msg"] == "revoked" {
				found = m
			}
		}
		if found == nil {
			t.Fatalf("no revoked line:\n%s", log)
		}
		return found
	}
	t.Run("subject_serials_pass_through", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setRevoke(&wire.RevokeResponse{KRLVersion: 9, RevokeLeaf: 20, PublishLeaf: 21, SerialCount: 5000, Serials: serials}, nil)
		body := revokeBodyFor(t, &wire.RevokeRequest{Target: wire.TargetSubject, SubjectKind: wire.SubjectUser, Subject: "alice"})
		res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, body, e.clock.Now()))
		var ans serverclient.RevokeAnswer
		if res.Code != http.StatusOK {
			t.Fatalf("POST revoke = %d %s", res.Code, res.Body)
		}
		if err := json.Unmarshal(res.Body.Bytes(), &ans); err != nil {
			t.Fatal(err)
		}
		if ans.KRLVersion != 9 || ans.RevokeLeaf != 20 || ans.PublishLeaf != 21 || ans.SerialCount != 5000 || !slices.Equal(ans.Serials, serials) {
			t.Fatalf("answer %d/%d/%d, %d serials of %d; want the signer's 9/20/21 and its 4096 of 5000", ans.KRLVersion, ans.RevokeLeaf, ans.PublishLeaf, len(ans.Serials), ans.SerialCount)
		}
		m := revokedLine(t, e.log)
		if m["target"] != "subject" || m["subject"] != "alice" || m["serial"] != nil || m["serial_count"] != float64(5000) {
			t.Fatalf("revoked line %v, want target subject, subject alice, serial_count 5000 and no serial", m)
		}
	})
	for _, tc := range []struct {
		name   string
		req    *wire.RevokeRequest
		target string
		serial any
	}{
		{"serial_logs_serial", &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: 42}, "serial", float64(42)},
		{"key_id_logs_no_serial", &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: "kr1/x"}, "key_id", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newAdminEnv(t, highLimits)
			e.fake.setRevoke(&wire.RevokeResponse{KRLVersion: 3, RevokeLeaf: 7, PublishLeaf: 8}, nil)
			res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, revokeBodyFor(t, tc.req), e.clock.Now()))
			if res.Code != http.StatusOK {
				t.Fatalf("POST revoke = %d %s", res.Code, res.Body)
			}
			if m := revokedLine(t, e.log); m["target"] != tc.target || m["serial"] != tc.serial {
				t.Fatalf("revoked line %v, want target %s and serial %v", m, tc.target, tc.serial)
			}
		})
	}
	t.Run("refusal_names_target", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setRevoke(nil, &wire.ErrorResponse{Code: wire.CodeMalformed, Message: "key_id_not_issued"})
		res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath,
			revokeBodyFor(t, &wire.RevokeRequest{Target: wire.TargetKeyID, CARole: wire.CARoleUser, KeyID: "kr1/x"}), e.clock.Now()))
		requireAnswer(t, "key_id_not_issued", res, http.StatusBadRequest, "key_id_not_issued")
		if !strings.Contains(e.log.String(), `"target":"key_id"`) || strings.Contains(e.log.String(), `"serial":0`) {
			t.Fatalf("log %s, want the refusal with target key_id and no serial 0", e.log)
		}
	})
}

// getKRL serves one GET KRLPath and returns the KRL bytes it answered
// with, failing t unless it is 200.
func getKRL(t *testing.T, e *adminEnv) string {
	t.Helper()
	res := serve(e.s.Handler(), signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now()))
	var doc serverclient.KRLDocument
	if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &doc) != nil {
		t.Fatalf("GET krl = %d %s", res.Code, res.Body)
	}
	return string(doc.KRL)
}

// krlResp is a GetKRL answer whose bytes all name v.
func krlResp(v string) *wire.GetKRLResponse {
	return &wire.GetKRLResponse{KRL: []byte("krl " + v), Manifest: []byte("manifest " + v), Sig: []byte("sig " + v)}
}

// TestKRLCache (pre-merge review, round 2): GET /api/v1/krl is
// unauthenticated, so keyroster-server caches the signer's answer: a
// burst of concurrent requests makes one signer call, a revocation through
// this server drops the entry before it answers so the CLI's read right
// after it gets the new version, an entry older than krlTTL is read again
// (a KRL the signer changed otherwise), and a failed read is not cached.
// The bytes served are the signer's, unchanged.
func TestKRLCache(t *testing.T) {
	t.Run("burst_one_signer_call", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setKRL(krlResp("v1"), nil)
		entered, release := e.fake.hold("GetKRL")
		defer release()
		const n = 12
		reqs := make([]*http.Request, n)
		for i := range reqs {
			reqs[i] = signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now())
		}
		got := make(chan *httptest.ResponseRecorder, n)
		get := func(r *http.Request) { got <- serve(e.s.Handler(), r) }
		go get(reqs[0])
		<-entered // the first read is inside the signer call
		for _, r := range reqs[1:] {
			go get(r)
		}
		time.Sleep(100 * time.Millisecond) // let the others join the read
		release()
		for range n {
			select {
			case res := <-got:
				var doc serverclient.KRLDocument
				if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &doc) != nil ||
					string(doc.KRL) != "krl v1" || string(doc.Manifest) != "manifest v1" || string(doc.Sig) != "sig v1" ||
					res.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("GET krl = %d %s %v", res.Code, res.Body, res.Header())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("a request is still waiting after the read ended")
			}
		}
		if c := e.fake.count("GetKRL"); c != 1 {
			t.Fatalf("%d concurrent requests made %d GetKRL calls, want 1", n, c)
		}
		if getKRL(t, e); e.fake.count("GetKRL") != 1 {
			t.Fatalf("a request inside krlTTL made a signer call (%d in total)", e.fake.count("GetKRL"))
		}
	})
	t.Run("revoke_drops_cache", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setKRL(krlResp("v1"), nil)
		if got := getKRL(t, e); got != "krl v1" {
			t.Fatalf("GET krl = %q, want v1", got)
		}
		body, _ := revokeBody(t)
		e.fake.setRevoke(&wire.RevokeResponse{KRLVersion: 2, RevokeLeaf: 7, PublishLeaf: 8}, nil)
		e.fake.setKRL(krlResp("v2"), nil)
		if res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, body, e.clock.Now())); res.Code != http.StatusOK {
			t.Fatalf("POST revoke = %d %s", res.Code, res.Body)
		}
		if got := getKRL(t, e); got != "krl v2" || e.fake.count("GetKRL") != 2 {
			t.Fatalf("GET krl after the revocation = %q after %d GetKRL calls, want v2 from a new call", got, e.fake.count("GetKRL"))
		}
	})
	// A KRL read in flight when a revocation answers was asked for
	// before it: dropKRL waits for that read, so its older answer is not
	// stored after the drop and served to the CLI's read that follows.
	t.Run("drop_waits_for_read_in_flight", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setKRL(krlResp("v1"), nil)
		e.fake.setRevoke(&wire.RevokeResponse{KRLVersion: 2, RevokeLeaf: 7, PublishLeaf: 8}, nil)
		body, _ := revokeBody(t)
		getReq := signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now())
		postReq := signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, body, e.clock.Now())
		entered, release := e.fake.hold("GetKRL")
		defer release()
		got, posted := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
		go func() { got <- serve(e.s.Handler(), getReq) }()
		<-entered // the read in flight returns v1
		go func() { posted <- serve(e.s.Handler(), postReq) }()
		for deadline := time.Now().Add(5 * time.Second); e.fake.count("Revoke") == 0; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("the revocation never reached the signer")
			}
		}
		time.Sleep(100 * time.Millisecond) // let the revocation reach dropKRL
		e.fake.setKRL(krlResp("v2"), nil)
		release()
		for _, ch := range []chan *httptest.ResponseRecorder{got, posted} {
			select {
			case res := <-ch:
				if res.Code != http.StatusOK {
					t.Fatalf("request = %d %s", res.Code, res.Body)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("a request is still waiting after the read ended")
			}
		}
		if got := getKRL(t, e); got != "krl v2" || e.fake.count("GetKRL") != 2 {
			t.Fatalf("GET krl after the revocation = %q after %d GetKRL calls, want v2 from a new call", got, e.fake.count("GetKRL"))
		}
	})
	// A revocation the signer may have committed drops the entry too:
	// an unavailable or internal refusal (state_unavailable after a failed
	// COMMIT that reached the disk) and a call whose outcome is unknown.
	// A malformed or refused request publishes nothing and keeps it.
	t.Run("uncertain_outcome_drops_cache", func(t *testing.T) {
		body, _ := revokeBody(t)
		for _, tc := range []struct {
			name string
			err  error
			code int
			drop bool
		}{
			{"unavailable", &wire.ErrorResponse{Code: wire.CodeUnavailable, Message: "state_unavailable"}, http.StatusServiceUnavailable, true},
			{"internal", &wire.ErrorResponse{Code: wire.CodeInternal, Message: "internal_error"}, http.StatusServiceUnavailable, true},
			{"outcome_unknown", errors.New("connection reset"), http.StatusServiceUnavailable, true},
			{"refused", &wire.ErrorResponse{Code: wire.CodeRefused, Message: "evidence_not_admin"}, http.StatusForbidden, false},
			{"malformed", &wire.ErrorResponse{Code: wire.CodeMalformed, Message: "unknown_serial"}, http.StatusBadRequest, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e := newAdminEnv(t, highLimits)
				e.fake.setKRL(krlResp("v1"), nil)
				getKRL(t, e)
				e.fake.setRevoke(nil, tc.err)
				e.fake.setKRL(krlResp("v2"), nil)
				if res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminRevokePath, serverclient.AdminRevokePath, body, e.clock.Now())); res.Code != tc.code {
					t.Fatalf("POST revoke = %d %s, want %d", res.Code, res.Body, tc.code)
				}
				want, calls := "krl v1", 1
				if tc.drop {
					want, calls = "krl v2", 2
				}
				if got := getKRL(t, e); got != want || e.fake.count("GetKRL") != calls {
					t.Fatalf("GET krl after the answer = %q after %d GetKRL calls, want %q after %d", got, e.fake.count("GetKRL"), want, calls)
				}
			})
		}
	})
	t.Run("stale_after_ttl", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setKRL(krlResp("v1"), nil)
		getKRL(t, e)
		e.fake.setKRL(krlResp("v2"), nil)
		if got := getKRL(t, e); got != "krl v1" {
			t.Fatalf("GET krl inside krlTTL = %q, want the cached v1", got)
		}
		e.clock.set(e.clock.Now().Add(krlTTL))
		if got := getKRL(t, e); got != "krl v2" {
			t.Fatalf("GET krl after krlTTL = %q, want v2", got)
		}
	})
	t.Run("failure_not_cached", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setKRL(nil, errors.New("signer down"))
		res := serve(e.s.Handler(), signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now()))
		if res.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET krl with the signer down = %d, want 503", res.Code)
		}
		e.fake.setKRL(krlResp("v1"), nil)
		if got := getKRL(t, e); got != "krl v1" {
			t.Fatalf("GET krl after a failed read = %q, want v1", got)
		}
	})
}

// copyEnv is a Server with a durable KRL copy at file, whose signer
// status carries a real trust bundle (an ops key and installationID), and
// the ops key.
type copyEnv struct {
	s     *Server
	fake  *fakeSigner
	clock *testClock
	log   *logBuffer
	file  string
	ops   ssh.Signer
}

const copyInstallation = "0123456789abcdef0123456789abcdef"

// copyBundle is a canonical version 1 trust bundle naming ops as its ops
// key, for installation copyInstallation, with policy's hash.
func copyBundle(t *testing.T, ops ssh.Signer, policy []byte) []byte {
	t.Helper()
	key := func() string { return trust.FormatKey(newSigner(t).PublicKey()) }
	logKey := newSigner(t).PublicKey()
	b := &trust.Bundle{
		Version: 1, Prev: trust.GenesisPrev, IssuedAt: t0.Format(trust.TimeFormat),
		Root:           trust.RootSet{Keys: []trust.RootKey{{Key: key(), Custody: "software"}}, Threshold: 1},
		OpsKey:         trust.KeyEntry{Key: trust.FormatKey(ops.PublicKey()), Alg: "ssh-ed25519", Custody: "agent"},
		Log:            trust.LogEntry{Key: trust.FormatKey(logKey), Alg: "ssh-ed25519", Custody: "agent", Origin: tlog.Origin(logKey)},
		PolicySHA256:   trust.SHA256Hex(policy),
		InstallationID: copyInstallation,
	}
	for _, role := range []string{trust.RoleUser, trust.RoleHost, trust.RoleMachine} {
		b.CAs = append(b.CAs, trust.CAEntry{Role: role, Key: key(), Alg: "ssh-ed25519", Custody: "agent", State: "active", Generation: 1})
	}
	doc, err := b.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// newCopyEnv builds the Server on a fake signer with KRLFile file.
func newCopyEnv(t *testing.T, file string) *copyEnv {
	t.Helper()
	ops := newSigner(t)
	st := testStatus(t, "agent", 0)
	st.Bundle = copyBundle(t, ops, st.Policy)
	fake := newFakeSigner(st)
	clock := &testClock{now: t0}
	logger, buf := newLogger()
	s, err := newServer(Config{RPID: testRPID, Clock: clock.Now, Logger: logger, DB: openTestDB(t), KRLFile: file}, fake)
	if err != nil {
		t.Fatal(err)
	}
	return &copyEnv{s: s, fake: fake, clock: clock, log: buf, file: file, ops: ops}
}

// krlDoc is a KRL version v (the KRL bytes data, any bytes), its manifest
// for installation signed by signer under krl.Namespace.
func krlDoc(t *testing.T, signer ssh.Signer, installation string, v uint64, data string) *wire.GetKRLResponse {
	t.Helper()
	m := krl.Manifest{InstallationID: installation, KRLVersion: v, KRLSHA256: krl.SHA256Hex([]byte(data)),
		IssuedAt: t0.Format(trust.TimeFormat), BundleVersion: 1, LogIndex: 2}
	manifest, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sshsig.Sign(rand.Reader, signer, krl.Namespace, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return &wire.GetKRLResponse{KRL: []byte(data), Manifest: manifest, Sig: sig}
}

// restart replaces e.s by a new server on the same signer, clock, log and
// copy file, as a restart of keyroster-server reads the copy again.
func (e *copyEnv) restart(t *testing.T) {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(e.log, nil))
	s, err := newServer(Config{RPID: testRPID, Clock: e.clock.Now, Logger: logger, DB: openTestDB(t), KRLFile: e.file}, e.fake)
	if err != nil {
		t.Fatal(err)
	}
	e.s = s
}

// writeCopy writes doc to the copy file as keepKRL writes it.
func (e *copyEnv) writeCopy(t *testing.T, doc *wire.GetKRLResponse) []byte {
	t.Helper()
	data, err := json.Marshal(serverclient.KRLDocument{KRL: doc.KRL, Manifest: doc.Manifest, Sig: doc.Sig})
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(e.file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

// get serves GET KRLPath once the cache entry has aged out.
func (e *copyEnv) get(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	e.clock.set(e.clock.Now().Add(krlTTL + time.Second))
	return serve(e.s.Handler(), signedReq(t, nil, http.MethodGet, serverclient.KRLPath, serverclient.KRLPath, nil, e.clock.Now()))
}

// copyBytes returns the durable copy, nil when there is none.
func (e *copyEnv) copyBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(e.file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestKRLServedCopy (03-06b): keyroster-server keeps every KRL it serves
// in its state directory before it serves it, verified against the
// signer's trust bundle, and never replaces the copy by a lower or equal
// version; a KRL it cannot keep is never served (503, never cached).
func TestKRLServedCopy(t *testing.T) {
	t.Run("kept_before_served", func(t *testing.T) {
		e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 1, "krl v1"), nil)
		res := e.get(t)
		if res.Code != http.StatusOK || !bytes.Equal(e.copyBytes(t), res.Body.Bytes()) {
			t.Fatalf("GET krl = %d; the copy %q is not the served document %q", res.Code, e.copyBytes(t), res.Body.Bytes())
		}
		if fi, err := os.Stat(e.file); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
			t.Fatalf("the copy: %v, %v; want mode 0600", fi, err)
		}
	})
	t.Run("higher_version_replaces", func(t *testing.T) {
		e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 1, "krl v1"), nil)
		e.get(t)
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 2, "krl v2"), nil)
		if res := e.get(t); res.Code != http.StatusOK || !bytes.Equal(e.copyBytes(t), res.Body.Bytes()) || !strings.Contains(res.Body.String(), base64.StdEncoding.EncodeToString([]byte("krl v2"))) {
			t.Fatalf("GET krl v2 = %d; the copy does not hold v2", res.Code)
		}
	})
	t.Run("equal_identical_no_write", func(t *testing.T) {
		e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
		doc := krlDoc(t, e.ops, copyInstallation, 1, "krl v1")
		e.fake.setKRL(doc, nil)
		e.get(t)
		// A marker in the file: a write would replace it.
		if err := os.WriteFile(e.file, []byte("marker"), 0o600); err != nil {
			t.Fatal(err)
		}
		if res := e.get(t); res.Code != http.StatusOK || string(e.copyBytes(t)) != "marker" || e.fake.count("GetKRL") != 2 {
			t.Fatalf("GET of the same version = %d after %d signer calls, copy %q; want 200, 2 calls and no write", res.Code, e.fake.count("GetKRL"), e.copyBytes(t))
		}
	})
	t.Run("lower_version_not_served", func(t *testing.T) {
		e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 2, "krl v2"), nil)
		e.get(t)
		kept := e.copyBytes(t)
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 1, "krl v1"), nil)
		if res := e.get(t); res.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET of a lower version = %d, want 503", res.Code)
		}
		if !bytes.Equal(e.copyBytes(t), kept) || !strings.Contains(e.log.String(), "KRL not served: version 1 is below version 2 this server served (a signer restored without the recovery? signer-install.md)") {
			t.Fatalf("the copy changed, or the log lacks the reason:\n%s", e.log.String())
		}
	})
	t.Run("equal_version_other_bytes_not_served", func(t *testing.T) {
		e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 2, "krl v2"), nil)
		e.get(t)
		kept := e.copyBytes(t)
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 2, "another krl v2"), nil)
		if res := e.get(t); res.Code != http.StatusServiceUnavailable || !bytes.Equal(e.copyBytes(t), kept) ||
			!strings.Contains(e.log.String(), "KRL not served: version 2 has other bytes") {
			t.Fatalf("GET of the same version with other bytes = %d:\n%s", res.Code, e.log.String())
		}
	})
	t.Run("unverified_not_served", func(t *testing.T) {
		for name, doc := range map[string]func(e *copyEnv) *wire.GetKRLResponse{
			"wrong_ops_key": func(*copyEnv) *wire.GetKRLResponse { return krlDoc(t, newSigner(t), copyInstallation, 1, "krl v1") },
			"wrong_installation_id": func(e *copyEnv) *wire.GetKRLResponse {
				return krlDoc(t, e.ops, "ffffffffffffffffffffffffffffffff", 1, "krl v1")
			},
		} {
			t.Run(name, func(t *testing.T) {
				e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
				e.fake.setKRL(doc(e), nil)
				if res := e.get(t); res.Code != http.StatusServiceUnavailable || e.copyBytes(t) != nil ||
					!strings.Contains(e.log.String(), "KRL not served: it does not verify") {
					t.Fatalf("GET of an unverified KRL = %d, copy %q:\n%s", res.Code, e.copyBytes(t), e.log.String())
				}
			})
		}
	})
	t.Run("write_failure_not_served", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing")
		e := newCopyEnv(t, filepath.Join(dir, "krl-served.json"))
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 1, "krl v1"), nil)
		if res := e.get(t); res.Code != http.StatusServiceUnavailable || !strings.Contains(e.log.String(), "KRL not kept:") {
			t.Fatalf("GET with an unwritable copy = %d:\n%s", res.Code, e.log.String())
		}
		// Nothing was cached: the next request asks the signer again.
		e.clock.set(e.clock.Now().Add(-krlTTL))
		if res := e.get(t); res.Code != http.StatusServiceUnavailable || e.fake.count("GetKRL") != 2 {
			t.Fatalf("second GET = %d after %d signer calls, want 503 after 2", res.Code, e.fake.count("GetKRL"))
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if res := e.get(t); res.Code != http.StatusOK || !bytes.Equal(e.copyBytes(t), res.Body.Bytes()) {
			t.Fatalf("GET once the directory exists = %d", res.Code)
		}
	})
	// The copy read at start is the floor only once it verifies against
	// the signer's trust bundle (PR #69 review, F3): a planted copy with
	// the highest version, signed by another ops key, blocks nothing
	// silently; the route answers 503, the log names the copy, and the copy
	// is neither replaced nor removed.
	t.Run("copy_unverified_not_floor", func(t *testing.T) {
		for name, planted := range map[string]func(e *copyEnv) *wire.GetKRLResponse{
			"wrong_ops_key": func(*copyEnv) *wire.GetKRLResponse {
				return krlDoc(t, newSigner(t), copyInstallation, math.MaxUint64, "planted")
			},
			"wrong_installation_id": func(e *copyEnv) *wire.GetKRLResponse {
				return krlDoc(t, e.ops, "ffffffffffffffffffffffffffffffff", math.MaxUint64, "planted")
			},
			"digest_mismatch": func(e *copyEnv) *wire.GetKRLResponse {
				d := krlDoc(t, e.ops, copyInstallation, math.MaxUint64, "planted")
				d.KRL = []byte("other bytes")
				return d
			},
		} {
			t.Run(name, func(t *testing.T) {
				e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
				kept := e.writeCopy(t, planted(e))
				e.restart(t)
				e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 1, "krl v1"), nil)
				res := e.get(t)
				if res.Code != http.StatusServiceUnavailable || !bytes.Equal(e.copyBytes(t), kept) ||
					!strings.Contains(e.log.String(), "this server kept (version 18446744073709551615) does not verify against the signer's trust bundle v1, so it is not used as the version floor") {
					t.Fatalf("GET with a planted copy = %d, copy changed %v:\n%s", res.Code, !bytes.Equal(e.copyBytes(t), kept), e.log.String())
				}
				// Not cached: every refresh checks it again.
				if res := e.get(t); res.Code != http.StatusServiceUnavailable || e.fake.count("GetKRL") != 2 {
					t.Fatalf("second GET = %d after %d signer calls, want 503 after 2", res.Code, e.fake.count("GetKRL"))
				}
			})
		}
	})
	// The control: a copy that verifies is the floor after a restart.
	t.Run("copy_verified_is_floor", func(t *testing.T) {
		e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
		kept := e.writeCopy(t, krlDoc(t, e.ops, copyInstallation, 5, "krl v5"))
		e.restart(t)
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 3, "krl v3"), nil)
		if res := e.get(t); res.Code != http.StatusServiceUnavailable || !bytes.Equal(e.copyBytes(t), kept) ||
			!strings.Contains(e.log.String(), "KRL not served: version 3 is below version 5 this server served") {
			t.Fatalf("GET below a verified copy = %d:\n%s", res.Code, e.log.String())
		}
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 5, "krl v5"), nil)
		if res := e.get(t); res.Code != http.StatusOK || !bytes.Equal(e.copyBytes(t), kept) {
			t.Fatalf("GET of the copy's own version = %d", res.Code)
		}
	})
	// A failed directory sync after the rename still moves the floor to
	// what the disk holds (PR #69 review, F4): the answer is not served,
	// and a version between the old floor and the disk copy cannot replace
	// it.
	t.Run("dir_sync_failure_advances_floor", func(t *testing.T) {
		e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 100, "krl v100"), nil)
		if res := e.get(t); res.Code != http.StatusOK {
			t.Fatalf("GET v100 = %d", res.Code)
		}
		orig := syncDir
		syncDir = func(string) error { return errors.New("injected EIO") }
		t.Cleanup(func() { syncDir = orig })
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 200, "krl v200"), nil)
		if res := e.get(t); res.Code != http.StatusServiceUnavailable || !strings.Contains(e.log.String(), "KRL not kept: injected EIO") {
			t.Fatalf("GET v200 with a failing directory sync = %d:\n%s", res.Code, e.log.String())
		}
		kept := e.copyBytes(t)
		if !strings.Contains(string(kept), base64.StdEncoding.EncodeToString([]byte("krl v200"))) {
			t.Fatalf("the copy does not hold v200 after the rename: %q", kept)
		}
		syncDir = orig
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 150, "krl v150"), nil)
		if res := e.get(t); res.Code != http.StatusServiceUnavailable || !bytes.Equal(e.copyBytes(t), kept) ||
			!strings.Contains(e.log.String(), "KRL not served: version 150 is below version 200 this server served") {
			t.Fatalf("GET v150 after the disk copy became v200 = %d, copy replaced %v:\n%s", res.Code, !bytes.Equal(e.copyBytes(t), kept), e.log.String())
		}
	})
	// An answer without a KRL after this server served one is the
	// rollback the floor reports (PR #69 review, F6): 503, logged, never
	// cached; before it served one, 404 no_krl.
	t.Run("empty_after_served_not_served", func(t *testing.T) {
		e := newCopyEnv(t, filepath.Join(t.TempDir(), "krl-served.json"))
		if res := e.get(t); res.Code != http.StatusNotFound {
			t.Fatalf("GET before any KRL = %d, want 404 no_krl", res.Code)
		}
		e.fake.setKRL(krlDoc(t, e.ops, copyInstallation, 2, "krl v2"), nil)
		e.get(t)
		kept := e.copyBytes(t)
		e.fake.setKRL(&wire.GetKRLResponse{}, nil)
		if res := e.get(t); res.Code != http.StatusServiceUnavailable || !bytes.Equal(e.copyBytes(t), kept) ||
			!strings.Contains(e.log.String(), "KRL not served: the signer has no KRL, but this server served version 2 (a signer restored without the recovery? signer-install.md)") {
			t.Fatalf("GET of an empty answer after v2 = %d:\n%s", res.Code, e.log.String())
		}
		if res := e.get(t); res.Code != http.StatusServiceUnavailable || e.fake.count("GetKRL") != 4 {
			t.Fatalf("second GET = %d after %d signer calls, want 503 after 4 (never cached)", res.Code, e.fake.count("GetKRL"))
		}
		// After a restart the same holds from the verified copy.
		e.restart(t)
		if res := e.get(t); res.Code != http.StatusServiceUnavailable {
			t.Fatalf("GET of an empty answer after a restart = %d", res.Code)
		}
	})
	t.Run("corrupt_copy_refuses_start", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "krl-served.json")
		for name, data := range map[string]string{
			"not_json":         "not a KRL document",
			"unknown_field":    `{"krl":"AA==","manifest":"AA==","sig":"AA==","extra":1}`,
			"manifest_garbage": `{"krl":"AA==","manifest":"AA==","sig":"AA=="}`,
		} {
			t.Run(name, func(t *testing.T) {
				if err := os.WriteFile(file, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
				_, err := newServer(Config{RPID: testRPID, DB: openTestDB(t), KRLFile: file}, newFakeSigner(testStatus(t, "agent", 0)))
				if err == nil || !strings.Contains(err.Error(), "docs/runbooks/server-install.md") || !strings.Contains(err.Error(), "restore source for lost revocations") {
					t.Fatalf("newServer with a damaged copy = %v", err)
				}
			})
		}
	})
	t.Run("new_requires_krl_file", func(t *testing.T) {
		if _, err := New(Config{SignerSocket: "/run/keyroster-signer/signer.sock", RPID: testRPID, DB: openTestDB(t)}); err == nil || !strings.Contains(err.Error(), "no KRL file") {
			t.Fatalf("New without a KRL file = %v", err)
		}
	})
}
