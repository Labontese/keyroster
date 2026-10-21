package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/server/servertest"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
)

// enrollEnv is an adminEnv used for the registration ceremony.
type enrollEnv struct{ *adminEnv }

func newEnrollEnv(t *testing.T, lim Limits) *enrollEnv {
	t.Helper()
	return &enrollEnv{newAdminEnv(t, lim)}
}

// invite adds the pending account name through the admin API and returns
// its invite token.
func (e *enrollEnv) invite(t *testing.T, name string, reinvite bool) string {
	t.Helper()
	out := e.mustAdd(t, name, reinvite)
	return out.InviteURL[strings.Index(out.InviteURL, "/enroll/")+len("/enroll/"):]
}

// post sends a POST with body to target through the full handler, from a
// browser at testOrigin.
func (e *enrollEnv) post(target string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://"+testRPID+target, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.s.Handler().ServeHTTP(rec, req)
	return rec
}

func (e *enrollEnv) begin(token string) *httptest.ResponseRecorder {
	return e.post("/api/v1/enroll/"+token+"/begin", nil)
}

func (e *enrollEnv) finish(token string, body []byte) *httptest.ResponseRecorder {
	return e.post("/api/v1/enroll/"+token+"/finish", body)
}

// mustBegin is begin that requires 200 and returns the options.
func (e *enrollEnv) mustBegin(t *testing.T, token string) []byte {
	t.Helper()
	rec := e.begin(token)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin = %d %s\nlog:\n%s", rec.Code, rec.Body, e.log)
	}
	return rec.Body.Bytes()
}

// finishBody is servertest.Register for a, at the test RP and origin.
func finishBody(t *testing.T, a *webauthntest.Authenticator, options []byte, flags byte, opts ...servertest.Option) []byte {
	t.Helper()
	body, err := servertest.Register(a, testRPID, testOrigin, options, flags, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func newAuthenticator(t *testing.T, alg int64) *webauthntest.Authenticator {
	t.Helper()
	a, err := webauthntest.New(alg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// register runs begin, the soft registration and finish for a on token,
// and returns the finish answer.
func (e *enrollEnv) register(t *testing.T, token string, a *webauthntest.Authenticator, flags byte, opts ...servertest.Option) *httptest.ResponseRecorder {
	t.Helper()
	return e.finish(token, finishBody(t, a, e.mustBegin(t, token), flags, opts...))
}

// TestEnrollRegister: an invited user registers a passkey of each
// algorithm; the pending credential holds the SPKI the soft authenticator
// has, and the fingerprint the page gets is webauthn.Fingerprint of it.
func TestEnrollRegister(t *testing.T) {
	for _, alg := range []int64{webauthn.AlgEdDSA, webauthn.AlgES256, webauthn.AlgRS256} {
		t.Run(servertest.Algorithm(alg), func(t *testing.T) {
			e := newEnrollEnv(t, Limits{})
			token := e.invite(t, "carol", false)
			a := newAuthenticator(t, alg)
			rec := e.register(t, token, a, 0)
			if rec.Code != http.StatusOK {
				t.Fatalf("finish = %d %s\nlog:\n%s", rec.Code, rec.Body, e.log)
			}
			var got EnrollFinishResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			want := webauthn.Fingerprint(a.Credential().SPKI)
			if got.Fingerprint != want || got.Algorithm != servertest.Algorithm(alg) || got.Synced {
				t.Fatalf("finish answer %+v, want fingerprint %s, algorithm %s, not synced", got, want, servertest.Algorithm(alg))
			}
			creds, err := e.s.db.PendingCredentials(t.Context(), "carol")
			if err != nil || len(creds) != 1 || !bytes.Equal(creds[0].SPKI, a.Credential().SPKI) || creds[0].Alg != alg {
				t.Fatalf("pending credentials = %+v, %v", creds, err)
			}
			if r := do(e.s, http.MethodGet, "/enroll/"+token, nil); r.Code != http.StatusNotFound {
				t.Fatalf("invite page after registration = %d, want 404", r.Code)
			}
			list := e.pending(t, "carol")
			if len(list) != 1 || list[0].Fingerprint != want {
				t.Fatalf("pending list %+v, want the fingerprint %s", list, want)
			}
		})
	}
}

// pending lists name's pending credentials through the admin API.
func (e *enrollEnv) pending(t *testing.T, name string) []serverclient.PendingCredential {
	t.Helper()
	path := serverclient.AdminPendingPath(name)
	rec := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodGet, path, path, nil, e.clock.Now()))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d %s\nlog:\n%s", path, rec.Code, rec.Body, e.log)
	}
	var out []serverclient.PendingCredential
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
