package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
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
	req := &wire.RevokeRequest{Target: wire.TargetSerial, CARole: wire.CARoleUser, Serial: 42, CreatedAt: 1700000000,
		Evidence: []wire.Evidence{{Type: wire.EvidenceAdminSSHSIG, Blob: []byte("sig")}}}
	raw, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(serverclient.RevokeBody{Request: raw})
	if err != nil {
		t.Fatal(err)
	}
	return body, req
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
		if res.Code != http.StatusOK || json.Unmarshal(res.Body.Bytes(), &ans) != nil || ans != (serverclient.RevokeAnswer{KRLVersion: 3, RevokeLeaf: 7, PublishLeaf: 8}) {
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
