package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// machineEnv is one server on a fakeSigner whose status policy has
// pop.machines on or off (03-11b).
type machineEnv struct {
	s     *Server
	fake  *fakeSigner
	clock *testClock
	log   *logBuffer
}

func newMachineEnv(t *testing.T, popMachines bool) *machineEnv {
	t.Helper()
	st := testStatus(t, "agent", 1)
	pol, err := trust.ParsePolicy(st.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if popMachines {
		pol.PoP = &trust.PoPPolicy{Machines: true}
	} else {
		pol.PoP = &trust.PoPPolicy{Hosts: true}
	}
	if st.Policy, err = pol.Canonical(); err != nil {
		t.Fatal(err)
	}
	fake := newFakeSigner(st)
	s, clock, buf := newTestServer(t, fake)
	return &machineEnv{s: s, fake: fake, clock: clock, log: buf}
}

// machineRequest is a well-formed request for name and a fresh key; the
// route never judges the evidence.
func machineRequest(t *testing.T, name string) *wire.MachineIssueRequest {
	t.Helper()
	req := &wire.MachineIssueRequest{
		InstallationID: copyInstallation,
		MachineName:    name,
		MachineKey:     newSigner(t).PublicKey().Marshal(),
		RequestID:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		CreatedAt:      uint64(t0.Unix()), //nolint:gosec // G115: a fixed test time
		Evidence:       []wire.Evidence{{Type: wire.EvidenceMachinePoP, Blob: []byte("evidence-blob-of-the-test-request")}},
	}
	return req
}

// machineBody is the JSON body of req.
func machineBody(t *testing.T, req *wire.MachineIssueRequest) []byte {
	t.Helper()
	raw, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(serverclient.MachineRenewRequest{Request: raw})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// post sends body to the renew route from client (an IP address).
func (e *machineEnv) post(client string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://"+testRPID+serverclient.MachineRenewPath, bytes.NewReader(body))
	r.RemoteAddr = client + ":40000"
	r.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.s.Handler().ServeHTTP(rec, r)
	return rec
}

// wantAnswer fails unless rec is code with the error detail.
func wantAnswer(t *testing.T, rec *httptest.ResponseRecorder, code int, detail string) {
	t.Helper()
	var got serverclient.APIError
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != code || got.Error != detail {
		t.Fatalf("answer %d %q, want %d with detail %q", rec.Code, rec.Body.String(), code, detail)
	}
}

// warnLines returns the log records whose msg is msg, decoded.
func warnLines(t *testing.T, log *logBuffer, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range log.Lines() {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// machinePassThroughWant is the test's own copy of the 16 details the
// route passes through (03-11b, PD2), so editing the route's list alone
// fails the test.
var machinePassThroughWant = []string{
	"request_time_skew", "machine_issue_no_installation_id", "machine_issue_installation_mismatch",
	"machine_pop_not_enabled", "directory_not_installed", "directory_not_authorized", "machine_name_reserved",
	"machine_key_revoked", "cert_revoked", "machine_disabled", "machine_key_unusable",
	"machine_issue_valid_for_not_zero", "ca_not_configured", "bad_principal", "duplicate_request",
	"machine_renew_too_often",
}

// TestMachineRenewRoute pins POST MachineRenewPath (03-11b, D-15, T-03-73,
// T-03-397): its limiter, body cap, strict JSON, the pop.machines
// pre-check, the pass-through allowlist and the one generic answer for
// every other refusal, and that a failed signer call never drops the KRL.
func TestMachineRenewRoute(t *testing.T) {
	const client = "127.0.0.1"
	t.Run("issued_200_certificate", func(t *testing.T) {
		e := newMachineEnv(t, true)
		req := machineRequest(t, "ci")
		rec := e.post(client, machineBody(t, req))
		var got serverclient.MachineRenewAnswer
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK || string(got.Certificate) != "machine-certificate" {
			t.Fatalf("answer %d %q, want 200 with the fake's certificate", rec.Code, rec.Body.String())
		}
		last := e.fake.lastMachineIssue
		if last == nil || last.MachineName != "ci" || !bytes.Equal(last.MachineKey, req.MachineKey) || last.RequestID != req.RequestID ||
			len(last.Evidence) != 1 || !bytes.Equal(last.Evidence[0].Blob, req.Evidence[0].Blob) {
			t.Fatalf("the signer got %+v, want the request as parsed", last)
		}
		lines := warnLines(t, e.log, "machine certificate relayed")
		if len(lines) != 1 || lines[0]["machine"] != "ci" || lines[0]["serial"] != float64(11) || lines[0]["client"] != client {
			t.Fatalf("relayed log lines %v, want one naming machine, serial and client", lines)
		}
	})
	t.Run("pop_off_no_signer_call", func(t *testing.T) {
		e := newMachineEnv(t, false)
		wantAnswer(t, e.post(client, machineBody(t, machineRequest(t, "ci"))), http.StatusForbidden, "machine_pop_not_enabled")
		if n := e.fake.count("MachineIssue"); n != 0 {
			t.Fatalf("%d MachineIssue calls with pop.machines off, want 0", n)
		}
		if n := e.fake.count("Status"); n == 0 {
			t.Fatal("the status was never read")
		}
	})
	t.Run("pop_off_wins_over_unparsed_request", func(t *testing.T) {
		e := newMachineEnv(t, false)
		body, _ := json.Marshal(serverclient.MachineRenewRequest{Request: []byte("not a request")})
		wantAnswer(t, e.post(client, body), http.StatusForbidden, "machine_pop_not_enabled")
	})
	t.Run("status_unavailable_503_no_call", func(t *testing.T) {
		e := newMachineEnv(t, true)
		e.fake.setStatus(nil, errors.New("signer down"))
		wantAnswer(t, e.post(client, machineBody(t, machineRequest(t, "ci"))), http.StatusServiceUnavailable, "signer unavailable")
		if n := e.fake.count("MachineIssue"); n != 0 {
			t.Fatalf("%d MachineIssue calls without a status, want 0", n)
		}
	})
	t.Run("identity_details_collapsed", func(t *testing.T) {
		var bodies []string
		for _, detail := range []string{"unknown_machine", "machine_key_mismatch", "machine_pop_invalid"} {
			t.Run(detail, func(t *testing.T) {
				e := newMachineEnv(t, true)
				e.fake.machineIssueErr = &wire.ErrorResponse{Code: wire.CodeRefused, Message: detail}
				rec := e.post(client, machineBody(t, machineRequest(t, "ci")))
				wantAnswer(t, rec, http.StatusForbidden, serverclient.MachineErrNotAuthenticated)
				bodies = append(bodies, rec.Body.String())
				lines := warnLines(t, e.log, "machine renew refused by the signer")
				if len(lines) != 1 || lines[0]["machine"] != "ci" || lines[0]["reason"] != detail || lines[0]["client"] != client {
					t.Fatalf("refusal log lines %v, want one with machine, the specific reason and client", lines)
				}
			})
		}
		for _, b := range bodies {
			if b != bodies[0] {
				t.Fatalf("collapsed answers differ: %q and %q", bodies[0], b)
			}
		}
	})
	t.Run("unlisted_detail_collapsed", func(t *testing.T) {
		e := newMachineEnv(t, true)
		e.fake.machineIssueErr = &wire.ErrorResponse{Code: wire.CodeRefused, Message: "some_detail_added_later"}
		wantAnswer(t, e.post(client, machineBody(t, machineRequest(t, "ci"))), http.StatusForbidden, serverclient.MachineErrNotAuthenticated)
	})
	t.Run("pass_through", func(t *testing.T) {
		for _, detail := range machinePassThroughWant {
			t.Run(detail, func(t *testing.T) {
				e := newMachineEnv(t, true)
				e.fake.machineIssueErr = &wire.ErrorResponse{Code: wire.CodeRefused, Message: detail}
				wantAnswer(t, e.post(client, machineBody(t, machineRequest(t, "ci"))), http.StatusForbidden, detail)
			})
		}
	})
	t.Run("malformed_body_400", func(t *testing.T) {
		e := newMachineEnv(t, true)
		good := machineBody(t, machineRequest(t, "ci"))
		for _, body := range [][]byte{[]byte("not json"), append(append([]byte{}, good...), []byte(` {"request":""}`)...)} {
			wantAnswer(t, e.post(client, body), http.StatusBadRequest, "malformed_request")
		}
		if n := e.fake.count("MachineIssue"); n != 0 {
			t.Fatalf("%d MachineIssue calls for malformed bodies, want 0", n)
		}
	})
	t.Run("unknown_field_400", func(t *testing.T) {
		e := newMachineEnv(t, true)
		good := machineBody(t, machineRequest(t, "ci"))
		body := append(bytes.TrimSuffix(good, []byte("}")), []byte(`,"extra":1}`)...)
		wantAnswer(t, e.post(client, body), http.StatusBadRequest, "malformed_request")
		if n := e.fake.count("MachineIssue"); n != 0 {
			t.Fatalf("%d MachineIssue calls for an unknown field, want 0", n)
		}
	})
	t.Run("request_not_parsed_400", func(t *testing.T) {
		e := newMachineEnv(t, true)
		body, _ := json.Marshal(serverclient.MachineRenewRequest{Request: []byte("not a request")})
		wantAnswer(t, e.post(client, body), http.StatusBadRequest, "malformed_request")
		if n := e.fake.count("MachineIssue"); n != 0 {
			t.Fatalf("%d MachineIssue calls for an unparsed request, want 0", n)
		}
	})
	t.Run("oversize_413", func(t *testing.T) {
		e := newMachineEnv(t, true)
		body := []byte(`{"request":"` + strings.Repeat("A", serverclient.MaxMachineRenewBody) + `"}`)
		body = body[:serverclient.MaxMachineRenewBody+1]
		wantAnswer(t, e.post(client, body), http.StatusRequestEntityTooLarge, "request too large")
		if n := e.fake.count("MachineIssue"); n != 0 {
			t.Fatalf("%d MachineIssue calls for an oversize body, want 0", n)
		}
	})
	t.Run("limiter_429_after_burst", func(t *testing.T) {
		e := newMachineEnv(t, true)
		body := machineBody(t, machineRequest(t, "ci"))
		for i := range machineBurst {
			if rec := e.post(client, body); rec.Code != http.StatusOK {
				t.Fatalf("request %d of the burst: %d %q", i+1, rec.Code, rec.Body.String())
			}
		}
		rec := e.post(client, body)
		wantAnswer(t, rec, http.StatusTooManyRequests, "rate limited")
		if rec.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
		if rec := e.post("127.0.0.2", body); rec.Code != http.StatusOK {
			t.Fatalf("another address: %d %q, want 200", rec.Code, rec.Body.String())
		}
	})
	t.Run("signer_too_old_403", func(t *testing.T) {
		for _, tc := range []struct {
			detail string
			code   int
			want   string
		}{
			{"unknown_message_type", http.StatusForbidden, "signer_too_old"},
			{"malformed_request", http.StatusBadRequest, "malformed_request"},
			{"malformed_frame", http.StatusBadRequest, "malformed_frame"},
		} {
			e := newMachineEnv(t, true)
			e.fake.machineIssueErr = &wire.ErrorResponse{Code: wire.CodeMalformed, Message: tc.detail}
			wantAnswer(t, e.post(client, machineBody(t, machineRequest(t, "ci"))), tc.code, tc.want)
		}
	})
	t.Run("unlisted_malformed_collapsed", func(t *testing.T) {
		e := newMachineEnv(t, true)
		e.fake.machineIssueErr = &wire.ErrorResponse{Code: wire.CodeMalformed, Message: "evidence_type_unknown_to_this_route"}
		wantAnswer(t, e.post(client, machineBody(t, machineRequest(t, "ci"))), http.StatusBadRequest, "malformed_request")
		lines := warnLines(t, e.log, "machine renew refused by the signer")
		if len(lines) != 1 || lines[0]["reason"] != "evidence_type_unknown_to_this_route" {
			t.Fatalf("refusal log lines %v, want one with the specific reason", lines)
		}
	})
	t.Run("unavailable_503", func(t *testing.T) {
		for name, err := range map[string]error{
			"unavailable": &wire.ErrorResponse{Code: wire.CodeUnavailable, Message: "state_unavailable"},
			"internal":    &wire.ErrorResponse{Code: wire.CodeInternal, Message: "log_encoding"},
			"transport":   errors.New("connection reset"),
		} {
			t.Run(name, func(t *testing.T) {
				e := newMachineEnv(t, true)
				e.fake.machineIssueErr = err
				wantAnswer(t, e.post(client, machineBody(t, machineRequest(t, "ci"))), http.StatusServiceUnavailable, "signer unavailable")
			})
		}
	})
	t.Run("no_dropKRL_on_5xx", func(t *testing.T) {
		e := newMachineEnv(t, true)
		cached := &krlView{resp: &wire.GetKRLResponse{}, fetched: t0}
		e.s.mu.Lock()
		e.s.krl = cached
		e.s.mu.Unlock()
		e.fake.machineIssueErr = &wire.ErrorResponse{Code: wire.CodeUnavailable, Message: "state_unavailable"}
		wantAnswer(t, e.post(client, machineBody(t, machineRequest(t, "ci"))), http.StatusServiceUnavailable, "signer unavailable")
		e.s.mu.Lock()
		got := e.s.krl
		e.s.mu.Unlock()
		if got != cached || e.fake.count("GetKRL") != 0 {
			t.Fatalf("after a 503 the KRL cache is %p (want %p) and GetKRL ran %d times (want 0)", got, cached, e.fake.count("GetKRL"))
		}
	})
	t.Run("log_has_no_request_bytes", func(t *testing.T) {
		e := newMachineEnv(t, true)
		req := machineRequest(t, "ci")
		raw, err := req.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		body := machineBody(t, req)
		if rec := e.post(client, body); rec.Code != http.StatusOK {
			t.Fatalf("success: %d", rec.Code)
		}
		e.fake.machineIssueErr = &wire.ErrorResponse{Code: wire.CodeRefused, Message: "machine_pop_invalid"}
		if rec := e.post(client, body); rec.Code != http.StatusForbidden {
			t.Fatalf("refusal: %d", rec.Code)
		}
		logged := e.log.String()
		for name, b := range map[string][]byte{"request": raw, "key": req.MachineKey, "evidence": req.Evidence[0].Blob} {
			for _, enc := range []string{base64.StdEncoding.EncodeToString(b), hex.EncodeToString(b), string(b)} {
				if strings.Contains(logged, enc) {
					t.Fatalf("the log holds the %s bytes", name)
				}
			}
		}
	})
	t.Run("custody_header_after_status_read", func(t *testing.T) {
		e := newMachineEnv(t, true)
		body := machineBody(t, machineRequest(t, "ci"))
		ok := e.post(client, body)
		e.fake.machineIssueErr = &wire.ErrorResponse{Code: wire.CodeRefused, Message: "unknown_machine"}
		refused := e.post(client, body)
		off := newMachineEnv(t, false).post(client, body)
		for name, rec := range map[string]*httptest.ResponseRecorder{"200": ok, "collapsed 403": refused, "pop-off 403": off} {
			if rec.Header().Get(serverclient.CustodyHeader) == "" {
				t.Fatalf("the %s answer (%d) has no custody header", name, rec.Code)
			}
		}
	})
}
