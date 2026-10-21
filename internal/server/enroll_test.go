package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"

	"github.com/Labontese/keyroster/internal/server/servertest"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
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

// requireUnused fails unless name has no pending credential and its
// invite is still unused.
func (e *enrollEnv) requireUnused(t *testing.T, name string) {
	t.Helper()
	creds, err := e.s.db.PendingCredentials(context.Background(), name)
	if err != nil || len(creds) != 0 {
		t.Fatalf("%s has pending credentials %+v (%v), want none", name, creds, err)
	}
	used, err := e.s.db.InviteUsed(context.Background(), name)
	if err != nil || used {
		t.Fatalf("%s's invite used = %v (%v), want unused", name, used, err)
	}
}

// refusals returns the "enroll refused" lines of the log, decoded.
func refusals(t *testing.T, log *logBuffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range log.Lines() {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", l)
		}
		if m["msg"] == "enroll refused" {
			out = append(out, m)
		}
	}
	return out
}

// lastReason returns the reason of the last "enroll refused" line.
func lastReason(t *testing.T, log *logBuffer) string {
	t.Helper()
	r := refusals(t, log)
	if len(r) == 0 {
		t.Fatalf("no enroll refused line:\n%s", log)
	}
	s, _ := r[len(r)-1]["reason"].(string)
	return s
}

// beginChallenge returns the challenge of a begin answer.
func beginChallenge(t *testing.T, options []byte) string {
	t.Helper()
	var b struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(options, &b); err != nil || b.PublicKey.Challenge == "" {
		t.Fatalf("begin answer without a challenge: %s (%v)", options, err)
	}
	return b.PublicKey.Challenge
}

// rsaModulus is a random odd number of exactly bits bits. It need not be
// a usable RSA modulus: attestation none carries no signature, and the
// size checks never factor it.
func rsaModulus(t *testing.T, bits int) *big.Int {
	t.Helper()
	buf := make([]byte, (bits+7)/8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	n := new(big.Int).SetBytes(buf)
	for i := bits; i < len(buf)*8; i++ {
		n.SetBit(n, i, 0)
	}
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)
	return n
}

// rsaCOSE is an RSA COSE key under RS256 with a modulus of exactly bits
// bits and the exponent e.
func rsaCOSE(t *testing.T, bits, e int) []byte {
	t.Helper()
	cose, err := servertest.RSACOSEKey(webauthn.AlgRS256, rsaModulus(t, bits), e)
	if err != nil {
		t.Fatal(err)
	}
	return cose
}

// TestEnrollRefusals: every refusal of the registration leaves no pending
// credential and the invite unused, and logs its reason code.
func TestEnrollRefusals(t *testing.T) {
	type tc struct {
		name   string
		code   int
		reason string
		// run performs the refused finish on token (the invite of carol)
		// and returns its answer.
		run func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder
	}
	es256 := func(t *testing.T) *webauthntest.Authenticator { return newAuthenticator(t, webauthn.AlgES256) }
	cases := []tc{
		{"uv_clear_refused", http.StatusBadRequest, reasonVerifyFailed, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			return e.register(t, token, es256(t), servertest.FlagUP|servertest.FlagAT)
		}},
		{"up_clear_refused", http.StatusBadRequest, reasonVerifyFailed, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			return e.register(t, token, es256(t), servertest.FlagUV|servertest.FlagAT)
		}},
		{"wrong_rpid_hash_refused", http.StatusBadRequest, reasonVerifyFailed, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			body, err := servertest.Register(es256(t), "other.example", testOrigin, e.mustBegin(t, token), 0)
			if err != nil {
				t.Fatal(err)
			}
			return e.finish(token, body)
		}},
		{"wrong_origin_refused", http.StatusBadRequest, reasonVerifyFailed, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			body, err := servertest.Register(es256(t), testRPID, "https://evil.example", e.mustBegin(t, token), 0)
			if err != nil {
				t.Fatal(err)
			}
			return e.finish(token, body)
		}},
		{"wrong_type_refused", http.StatusBadRequest, reasonVerifyFailed, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			return e.register(t, token, es256(t), 0, servertest.WithType("webauthn.get"))
		}},
		{"challenge_from_other_session_refused", http.StatusBadRequest, reasonSessionNotFound, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			// A session begun on another invite: its challenge opens
			// nothing under this invite.
			other := e.invite(t, "dave", false)
			otherOptions := e.mustBegin(t, other)
			e.mustBegin(t, token)
			return e.finish(token, finishBody(t, es256(t), otherOptions, 0))
		}},
		{"unknown_challenge_refused", http.StatusBadRequest, reasonSessionNotFound, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			return e.register(t, token, es256(t), 0, servertest.WithChallenge(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		}},
		{"session_single_use_after_failed_finish", http.StatusBadRequest, reasonSessionNotFound, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			// A finish that fails verification has still used its
			// session: the same ceremony cannot be tried again.
			a := es256(t)
			options := e.mustBegin(t, token)
			if rec := e.finish(token, finishBody(t, a, options, servertest.FlagUP|servertest.FlagAT)); rec.Code != http.StatusBadRequest {
				t.Fatalf("first finish = %d %s, want 400", rec.Code, rec.Body)
			}
			return e.finish(token, finishBody(t, a, options, 0))
		}},
		{"session_expired_refused", http.StatusBadRequest, reasonSessionNotFound, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			options := e.mustBegin(t, token)
			e.clock.set(e.clock.Now().Add(registrationTTL))
			return e.finish(token, finishBody(t, es256(t), options, 0))
		}},
		{"es384_refused", http.StatusBadRequest, reasonVerifyFailed, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cose, err := servertest.COSEKey(-35, &k.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			return e.register(t, token, es256(t), 0, servertest.WithCOSEKey(cose))
		}},
		{"rsa1024_refused", http.StatusBadRequest, reasonUnsupportedCredential, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			return e.register(t, token, es256(t), 0, servertest.WithCOSEKey(rsaCOSE(t, 1024, 65537)))
		}},
		// go-webauthn checks only the algorithm number of a key at an
		// attestation-none registration; the conversion to SPKI is what
		// refuses an EC2 key labelled RS256.
		{"rs256_label_on_ec_key_refused", http.StatusBadRequest, reasonUnsupportedCredential, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			a := es256(t)
			pub, err := x509.ParsePKIXPublicKey(a.Credential().SPKI)
			if err != nil {
				t.Fatal(err)
			}
			cose, err := servertest.COSEKey(webauthn.AlgRS256, pub)
			if err != nil {
				t.Fatal(err)
			}
			return e.register(t, token, a, 0, servertest.WithCOSEKey(cose))
		}},
		{"bs_without_be_refused", http.StatusBadRequest, reasonVerifyFailed, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			return e.register(t, token, es256(t), servertest.DefaultFlags|servertest.FlagBS)
		}},
		{"malformed_body_refused", http.StatusBadRequest, reasonBadRequest, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			e.mustBegin(t, token)
			return e.finish(token, []byte(`{"id":"AAAA","type":"public-key"`))
		}},
		{"credential_id_pending_for_other_user_refused", http.StatusConflict, reasonDuplicateCredential, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			a := es256(t)
			dave := e.invite(t, "dave", false)
			if rec := e.register(t, dave, a, 0); rec.Code != http.StatusOK {
				t.Fatalf("dave's registration = %d %s", rec.Code, rec.Body)
			}
			return e.register(t, token, es256(t), 0, servertest.WithCredentialID(a.Credential().ID))
		}},
		{"credential_id_in_directory_refused", http.StatusConflict, reasonDuplicateCredential, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			e.installDirectory(t) // alice holds credential AQIDBAUGBwgJCgsMDQ4PEA
			id, err := base64.RawURLEncoding.DecodeString("AQIDBAUGBwgJCgsMDQ4PEA")
			if err != nil {
				t.Fatal(err)
			}
			return e.register(t, token, es256(t), 0, servertest.WithCredentialID(id))
		}},
		{"expired_invite_refused", http.StatusNotFound, reasonInviteNotValid, func(t *testing.T, e *enrollEnv, token string) *httptest.ResponseRecorder {
			options := e.mustBegin(t, token)
			e.clock.set(e.clock.Now().Add(inviteTTL))
			if rec := e.begin(token); rec.Code != http.StatusNotFound {
				t.Fatalf("begin on an expired invite = %d, want 404", rec.Code)
			}
			return e.finish(token, finishBody(t, es256(t), options, 0))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnrollEnv(t, Limits{})
			token := e.invite(t, "carol", false)
			rec := c.run(t, e, token)
			if rec.Code != c.code {
				t.Fatalf("= %d %s, want %d\nlog:\n%s", rec.Code, rec.Body, c.code, e.log)
			}
			if got := lastReason(t, e.log); got != c.reason {
				t.Fatalf("logged reason %q, want %q", got, c.reason)
			}
			e.requireUnused(t, "carol")
		})
	}

	// After a success the invite is used: a second ceremony is refused at
	// begin, and the successful finish replayed is refused too, with
	// still exactly one pending credential.
	t.Run("invite_single_use", func(t *testing.T) {
		e := newEnrollEnv(t, Limits{})
		token := e.invite(t, "carol", false)
		if rec := e.register(t, token, newAuthenticator(t, webauthn.AlgEdDSA), 0); rec.Code != http.StatusOK {
			t.Fatalf("first registration = %d %s", rec.Code, rec.Body)
		}
		if rec := e.begin(token); rec.Code != http.StatusNotFound || lastReason(t, e.log) != reasonInviteNotValid {
			t.Fatalf("begin on a used invite = %d %s, want 404 invite_not_valid", rec.Code, rec.Body)
		}
		if n := len(e.pending(t, "carol")); n != 1 {
			t.Fatalf("%d pending credentials, want 1", n)
		}
	})
	t.Run("finish_replay_refused", func(t *testing.T) {
		e := newEnrollEnv(t, Limits{})
		token := e.invite(t, "carol", false)
		body := finishBody(t, newAuthenticator(t, webauthn.AlgES256), e.mustBegin(t, token), 0)
		if rec := e.finish(token, body); rec.Code != http.StatusOK {
			t.Fatalf("finish = %d %s", rec.Code, rec.Body)
		}
		rec := e.finish(token, body)
		if rec.Code == http.StatusOK || lastReason(t, e.log) != reasonInviteNotValid {
			t.Fatalf("replayed finish = %d %s, want a refusal", rec.Code, rec.Body)
		}
		if n := len(e.pending(t, "carol")); n != 1 {
			t.Fatalf("%d pending credentials after the replay, want 1", n)
		}
	})
}

// TestEnrollRecordsCredential: BE/BS are recorded as backup_eligible and
// backed_up, and the pending id is the canonical text of the credential
// ID bytes go-webauthn verified (02-08-F10).
func TestEnrollRecordsCredential(t *testing.T) {
	t.Run("backup_flags_recorded", func(t *testing.T) {
		e := newEnrollEnv(t, Limits{})
		token := e.invite(t, "carol", false)
		rec := e.register(t, token, newAuthenticator(t, webauthn.AlgES256), servertest.DefaultFlags|servertest.FlagBE|servertest.FlagBS)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"synced":true`) {
			t.Fatalf("finish = %d %s, want 200 synced", rec.Code, rec.Body)
		}
		p := e.pending(t, "carol")
		if len(p) != 1 || !p[0].BackupEligible || !p[0].BackedUp {
			t.Fatalf("pending %+v, want backup_eligible and backed_up", p)
		}
	})
	t.Run("pending_id_is_canonical", func(t *testing.T) {
		e := newEnrollEnv(t, Limits{})
		token := e.invite(t, "carol", false)
		// 33 bytes whose unpadded base64url text is "--__" repeated: it
		// uses '-' and '_', which the standard-alphabet form a client might
		// send does not.
		raw := bytes.Repeat([]byte{0xfb, 0xef, 0xff}, 11)
		if rec := e.register(t, token, newAuthenticator(t, webauthn.AlgES256), 0, servertest.WithCredentialID(raw)); rec.Code != http.StatusOK {
			t.Fatalf("finish = %d %s", rec.Code, rec.Body)
		}
		p := e.pending(t, "carol")
		if len(p) != 1 || p[0].ID != base64.RawURLEncoding.EncodeToString(raw) {
			t.Fatalf("pending %+v, want id %s", p, base64.RawURLEncoding.EncodeToString(raw))
		}
	})
}

// TestEnrollBeginOptions pins the creation options begin offers (02-08-R2-F9).
func TestEnrollBeginOptions(t *testing.T) {
	t.Run("begin_options_exact", func(t *testing.T) {
		e := newEnrollEnv(t, Limits{})
		token := e.invite(t, "carol", false)
		var got struct {
			PublicKey struct {
				PubKeyCredParams []struct {
					Type string `json:"type"`
					Alg  int64  `json:"alg"`
				} `json:"pubKeyCredParams"`
				Attestation            *string `json:"attestation"`
				AuthenticatorSelection struct {
					UserVerification string `json:"userVerification"`
					ResidentKey      string `json:"residentKey"`
				} `json:"authenticatorSelection"`
				RP struct {
					ID string `json:"id"`
				} `json:"rp"`
			} `json:"publicKey"`
		}
		if err := json.Unmarshal(e.mustBegin(t, token), &got); err != nil {
			t.Fatal(err)
		}
		pk := got.PublicKey
		want := []int64{-8, -7, -257}
		if len(pk.PubKeyCredParams) != len(want) {
			t.Fatalf("pubKeyCredParams = %+v, want algs %v", pk.PubKeyCredParams, want)
		}
		for i, p := range pk.PubKeyCredParams {
			if p.Type != "public-key" || p.Alg != want[i] {
				t.Fatalf("pubKeyCredParams[%d] = %+v, want public-key %d", i, p, want[i])
			}
		}
		if pk.Attestation == nil || *pk.Attestation != "none" {
			t.Fatalf("attestation = %v, want present and none", pk.Attestation)
		}
		if pk.AuthenticatorSelection.UserVerification != "required" || pk.AuthenticatorSelection.ResidentKey != "preferred" {
			t.Fatalf("authenticatorSelection = %+v, want userVerification required, residentKey preferred", pk.AuthenticatorSelection)
		}
		if pk.RP.ID != testRPID {
			t.Fatalf("rp.id = %q, want %q", pk.RP.ID, testRPID)
		}
	})
	t.Run("exclude_credentials_from_directory", func(t *testing.T) {
		e := newEnrollEnv(t, Limits{})
		e.installDirectory(t) // alice, credential AQIDBAUGBwgJCgsMDQ4PEA
		token := e.invite(t, "alice", true)
		options := string(e.mustBegin(t, token))
		if !strings.Contains(options, `"excludeCredentials":[{"type":"public-key","id":"AQIDBAUGBwgJCgsMDQ4PEA"}]`) {
			t.Fatalf("begin for a directory user does not exclude its credential:\n%s", options)
		}
	})
}

// TestEnrollRefusalLog: every non-2xx answer of begin and finish writes
// exactly one "enroll refused" line with exactly route, reason, user and
// err, and nothing in the log carries a token, its hash, a challenge or
// credential material (02-08-R2-F10, T-02-140).
func TestEnrollRefusalLog(t *testing.T) {
	t.Run("refusal_logged_with_reason", func(t *testing.T) {
		// The invite limiter raised: a 429 it answers never reaches the
		// handlers and is not an enroll refusal.
		e := newEnrollEnv(t, Limits{InvitePerMinute: 1 << 20, InviteBurst: 1 << 20})
		var forbidden []string
		addToken := func(tok string) {
			sum := sha256.Sum256([]byte(tok))
			forbidden = append(forbidden, tok, hex.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:]),
				base64.RawStdEncoding.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(sum[:]))
		}
		addAuth := func(a *webauthntest.Authenticator) {
			c := a.Credential()
			forbidden = append(forbidden, base64.RawURLEncoding.EncodeToString(c.ID), base64.StdEncoding.EncodeToString(c.SPKI),
				base64.RawURLEncoding.EncodeToString(c.SPKI), base64.URLEncoding.EncodeToString(c.SPKI))
		}
		addBody := func(body []byte) {
			var b struct {
				Response struct {
					ClientDataJSON    string `json:"clientDataJSON"`
					AttestationObject string `json:"attestationObject"`
				} `json:"response"`
			}
			if err := json.Unmarshal(body, &b); err != nil {
				t.Fatal(err)
			}
			forbidden = append(forbidden, b.Response.ClientDataJSON, b.Response.AttestationObject)
		}
		beginOn := func(token string) []byte {
			o := e.mustBegin(t, token)
			forbidden = append(forbidden, beginChallenge(t, o))
			return o
		}
		type want struct{ route, reason, user, level string }
		var wants []want
		check := func(rec *httptest.ResponseRecorder, w want) {
			t.Helper()
			if rec.Code < 300 {
				t.Fatalf("%s/%s answered %d, want a refusal", w.route, w.reason, rec.Code)
			}
			wants = append(wants, w)
			got := refusals(t, e.log)
			if len(got) != len(wants) {
				t.Fatalf("after %s/%s: %d enroll refused lines, want %d:\n%s", w.route, w.reason, len(got), len(wants), e.log)
			}
			l := got[len(got)-1]
			for k := range l {
				switch k {
				case "time", "level", "msg", "route", "reason", "user", "err":
				default:
					t.Fatalf("enroll refused line has key %q: %v", k, l)
				}
			}
			if l["route"] != w.route || l["reason"] != w.reason || l["user"] != w.user || l["level"] != w.level {
				t.Fatalf("enroll refused line %v, want %+v", l, w)
			}
			if _, ok := l["err"].(string); !ok {
				t.Fatalf("enroll refused line has no string err: %v", l)
			}
		}

		// 1. begin on a token never issued.
		never := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
		addToken(never)
		check(e.begin(never), want{"begin", reasonInviteNotValid, "", "INFO"})

		// 2. finish with the UV flag clear.
		tok := e.invite(t, "carol", false)
		addToken(tok)
		a := newAuthenticator(t, webauthn.AlgES256)
		addAuth(a)
		body := finishBody(t, a, beginOn(tok), servertest.FlagUP|servertest.FlagAT)
		addBody(body)
		check(e.finish(tok, body), want{"finish", reasonVerifyFailed, "carol", "INFO"})

		// 3. finish from the wrong origin.
		body, err := servertest.Register(a, testRPID, "https://evil.example", beginOn(tok), 0)
		if err != nil {
			t.Fatal(err)
		}
		addBody(body)
		check(e.finish(tok, body), want{"finish", reasonVerifyFailed, "carol", "INFO"})

		// 4. finish with an RSA-1024 key under RS256.
		body = finishBody(t, a, beginOn(tok), 0, servertest.WithCOSEKey(rsaCOSE(t, 1024, 65537)))
		addBody(body)
		check(e.finish(tok, body), want{"finish", reasonUnsupportedCredential, "carol", "INFO"})

		// 5. begin A, begin B, finish A, finish B on a used invite.
		tok2 := e.invite(t, "dave", false)
		addToken(tok2)
		optA, optB := beginOn(tok2), beginOn(tok2)
		a2, b2 := newAuthenticator(t, webauthn.AlgEdDSA), newAuthenticator(t, webauthn.AlgEdDSA)
		addAuth(a2)
		addAuth(b2)
		bodyA, bodyB := finishBody(t, a2, optA, 0), finishBody(t, b2, optB, 0)
		addBody(bodyA)
		addBody(bodyB)
		if rec := e.finish(tok2, bodyA); rec.Code != http.StatusOK {
			t.Fatalf("finish A = %d %s", rec.Code, rec.Body)
		}
		check(e.finish(tok2, bodyB), want{"finish", reasonInviteNotValid, "", "INFO"})

		// 6. begin after the server's database handle is closed.
		tok3 := e.invite(t, "erin", false)
		addToken(tok3)
		if err := e.s.db.Close(); err != nil {
			t.Fatal(err)
		}
		rec := e.begin(tok3)
		if rec.Code < 500 {
			t.Fatalf("begin on a closed database = %d, want 5xx", rec.Code)
		}
		check(rec, want{"begin", reasonInternalError, "", "ERROR"})

		logText := e.log.String()
		for _, f := range forbidden {
			if f != "" && strings.Contains(logText, f) {
				t.Fatalf("the log carries %q:\n%s", f, logText)
			}
		}
	})
}

// TestEnrollInviteLifecycle: an invite registers exactly one credential
// however its ceremonies interleave, and a reinvite discards what the old
// invite started (02-08-F1, 02-08-F7). Run under -race.
func TestEnrollInviteLifecycle(t *testing.T) {
	noLimit := Limits{InvitePerMinute: 1 << 20, InviteBurst: 1 << 20}
	t.Run("invite_concurrent_finish", func(t *testing.T) {
		e := newEnrollEnv(t, noLimit)
		token := e.invite(t, "carol", false)
		const n = 8
		auths := make([]*webauthntest.Authenticator, n)
		for i := range auths {
			auths[i] = newAuthenticator(t, webauthn.AlgEdDSA)
		}
		codes := make([]int, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				b := e.begin(token)
				if b.Code != http.StatusOK {
					codes[i] = b.Code
					return
				}
				body, err := servertest.Register(auths[i], testRPID, testOrigin, b.Body.Bytes(), 0)
				if err != nil {
					t.Error(err)
					return
				}
				codes[i] = e.finish(token, body).Code
			}()
		}
		wg.Wait()
		ok := 0
		for i, c := range codes {
			switch c {
			case http.StatusOK:
				ok++
			case http.StatusNotFound:
			default:
				t.Fatalf("ceremony %d ended %d, want 200 or the uniform 404", i, c)
			}
		}
		if ok != 1 {
			t.Fatalf("%d ceremonies succeeded, want exactly 1 (codes %v)\nlog:\n%s", ok, codes, e.log)
		}
		if p := e.pending(t, "carol"); len(p) != 1 {
			t.Fatalf("%d pending credentials, want 1", len(p))
		}
		if used, err := e.s.db.InviteUsed(context.Background(), "carol"); err != nil || !used {
			t.Fatalf("invite used = %v (%v), want used", used, err)
		}
	})
	t.Run("finish_after_invite_used_refused", func(t *testing.T) {
		e := newEnrollEnv(t, noLimit)
		token := e.invite(t, "carol", false)
		optA, optB := e.mustBegin(t, token), e.mustBegin(t, token)
		if rec := e.finish(token, finishBody(t, newAuthenticator(t, webauthn.AlgES256), optA, 0)); rec.Code != http.StatusOK {
			t.Fatalf("finish A = %d %s", rec.Code, rec.Body)
		}
		rec := e.finish(token, finishBody(t, newAuthenticator(t, webauthn.AlgES256), optB, 0))
		if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != `{"error":"invite not valid"}` {
			t.Fatalf("finish B = %d %s, want the uniform 404", rec.Code, rec.Body)
		}
		if p := e.pending(t, "carol"); len(p) != 1 {
			t.Fatalf("%d pending credentials, want 1", len(p))
		}
	})
	t.Run("reinvite_between_begin_and_finish_refused", func(t *testing.T) {
		e := newEnrollEnv(t, noLimit)
		old := e.invite(t, "carol", false)
		options := e.mustBegin(t, old)
		fresh := e.invite(t, "carol", true)
		rec := e.finish(old, finishBody(t, newAuthenticator(t, webauthn.AlgES256), options, 0))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("finish of the replaced invite's ceremony = %d %s, want 404", rec.Code, rec.Body)
		}
		e.requireUnused(t, "carol")
		if rec := e.register(t, fresh, newAuthenticator(t, webauthn.AlgES256), 0); rec.Code != http.StatusOK {
			t.Fatalf("registration on the new invite = %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("reinvite_after_used_invite_allows_register", func(t *testing.T) {
		e := newEnrollEnv(t, noLimit)
		first := e.invite(t, "carol", false)
		if rec := e.register(t, first, newAuthenticator(t, webauthn.AlgES256), 0); rec.Code != http.StatusOK {
			t.Fatalf("first registration = %d %s", rec.Code, rec.Body)
		}
		second := e.invite(t, "carol", true)
		a := newAuthenticator(t, webauthn.AlgEdDSA)
		if rec := e.register(t, second, a, 0); rec.Code != http.StatusOK {
			t.Fatalf("registration after the reinvite = %d %s", rec.Code, rec.Body)
		}
		p := e.pending(t, "carol")
		if len(p) != 1 || p[0].Fingerprint != webauthn.Fingerprint(a.Credential().SPKI) {
			t.Fatalf("pending %+v, want only the new passkey", p)
		}
	})
	t.Run("open_sessions_capped", func(t *testing.T) {
		e := newEnrollEnv(t, noLimit)
		token := e.invite(t, "carol", false)
		for i := range serverdb.MaxOpenSessions {
			if rec := e.begin(token); rec.Code != http.StatusOK {
				t.Fatalf("begin %d = %d %s", i+1, rec.Code, rec.Body)
			}
		}
		if rec := e.begin(token); rec.Code != http.StatusTooManyRequests || lastReason(t, e.log) != reasonTooManySessions {
			t.Fatalf("begin %d = %d %s, want 429 too_many_sessions", serverdb.MaxOpenSessions+1, rec.Code, rec.Body)
		}
		// Expired sessions no longer count.
		e.clock.set(e.clock.Now().Add(registrationTTL))
		if rec := e.begin(token); rec.Code != http.StatusOK {
			t.Fatalf("begin after the sessions expired = %d %s", rec.Code, rec.Body)
		}
	})
	t.Run("used_invite_page_and_begin_404", func(t *testing.T) {
		e := newEnrollEnv(t, noLimit)
		token := e.invite(t, "carol", false)
		never := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
		page := do(e.s, http.MethodGet, "/enroll/"+token, nil)
		if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), "/api/v1/enroll/"+token+"/begin") ||
			!strings.Contains(page.Body.String(), "/api/v1/enroll/"+token+"/finish") {
			t.Fatalf("control: the page before registration = %d:\n%s", page.Code, page.Body)
		}
		if rec := e.register(t, token, newAuthenticator(t, webauthn.AlgES256), 0); rec.Code != http.StatusOK {
			t.Fatalf("registration = %d %s", rec.Code, rec.Body)
		}
		usedPage, neverPage := do(e.s, http.MethodGet, "/enroll/"+token, nil), do(e.s, http.MethodGet, "/enroll/"+never, nil)
		if usedPage.Code != http.StatusNotFound || usedPage.Body.String() != neverPage.Body.String() {
			t.Fatalf("page of a used invite = %d, want the never-issued token's 404:\n%s", usedPage.Code, usedPage.Body)
		}
		usedBegin, neverBegin := e.begin(token), e.begin(never)
		if usedBegin.Code != http.StatusNotFound || usedBegin.Body.String() != neverBegin.Body.String() {
			t.Fatalf("begin on a used invite = %d %s, want the never-issued token's 404 %s", usedBegin.Code, usedBegin.Body, neverBegin.Body)
		}
	})
}

// attestationCalls counts the calls go-webauthn makes, anywhere in this
// test binary, to the verifier of any attestation format other than
// "none". init replaces every such verifier in go-webauthn's registry by
// one that only counts and fails: the registry is a plain package map, so
// the replacement holds for the whole binary, and no test here registers
// with a format other than none except to see it refused before
// verification (owner hardening H1).
var attestationCalls atomic.Int64

func init() {
	for _, f := range []protocol.AttestationFormat{
		protocol.AttestationFormatPacked, protocol.AttestationFormatTPM, protocol.AttestationFormatAndroidKey,
		protocol.AttestationFormatAndroidSafetyNet, protocol.AttestationFormatFIDOUniversalSecondFactor,
		protocol.AttestationFormatApple, protocol.AttestationFormatCompound,
	} {
		protocol.RegisterAttestationFormat(f, func(protocol.AttestationObject, []byte, metadata.Provider, protocol.AttestationPolicy, protocol.SignaturePolicy) (string, []any, error) {
			attestationCalls.Add(1)
			return "", nil, errors.New("counting seam: an attestation verifier was reached")
		})
	}
}

// packedSelf is a packed self-attestation (no x5c) signed by a's
// credential key over authData ‖ SHA-256(clientDataJSON), as an
// authenticator without an attestation key makes it.
func packedSelf(a *webauthntest.Authenticator) servertest.AttestationFunc {
	return func(authData, cdHash []byte) (string, any, error) {
		sig, err := a.Sign(append(append([]byte(nil), authData...), cdHash...))
		if err != nil {
			return "", nil, err
		}
		return "packed", map[string]any{"alg": a.Credential().Alg, "sig": sig}, nil
	}
}

// fixedAttestation is an attestation statement of format with attStmt.
func fixedAttestation(format string, attStmt any) servertest.AttestationFunc {
	return func([]byte, []byte) (string, any, error) { return format, attStmt, nil }
}

// TestEnrollAttestationFormats (owner hardening H1, 2026-10-21): every
// attestation format other than "none" is refused right after the body is
// parsed, before the session is consumed and before go-webauthn runs any
// attestation verifier, so the packed, TPM (go-tpm), SafetyNet (JWT,
// mapstructure) and x509-chain code paths never see client input.
func TestEnrollAttestationFormats(t *testing.T) {
	x5c := [][]byte{{0x30, 0x00}}
	for _, tc := range []struct {
		name string
		alg  int64
		att  func(a *webauthntest.Authenticator) servertest.AttestationFunc
	}{
		{"packed_self_es256", webauthn.AlgES256, packedSelf},
		{"packed_self_rs256", webauthn.AlgRS256, packedSelf},
		{"tpm", webauthn.AlgRS256, func(*webauthntest.Authenticator) servertest.AttestationFunc {
			return fixedAttestation("tpm", map[string]any{"ver": "2.0", "alg": int64(-257), "x5c": x5c,
				"sig": []byte{1, 2, 3}, "certInfo": []byte{4, 5, 6}, "pubArea": []byte{7, 8, 9}})
		}},
		{"android_safetynet", webauthn.AlgES256, func(*webauthntest.Authenticator) servertest.AttestationFunc {
			return fixedAttestation("android-safetynet", map[string]any{"ver": "1", "response": []byte("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")})
		}},
		{"fido_u2f", webauthn.AlgES256, func(*webauthntest.Authenticator) servertest.AttestationFunc {
			return fixedAttestation("fido-u2f", map[string]any{"sig": []byte{1}, "x5c": x5c})
		}},
		{"apple", webauthn.AlgES256, func(*webauthntest.Authenticator) servertest.AttestationFunc {
			return fixedAttestation("apple", map[string]any{"x5c": x5c})
		}},
		{"unknown_format", webauthn.AlgES256, func(*webauthntest.Authenticator) servertest.AttestationFunc {
			return fixedAttestation("x-keyroster-test", map[string]any{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnrollEnv(t, Limits{})
			token := e.invite(t, "carol", false)
			a := newAuthenticator(t, tc.alg)
			options := e.mustBegin(t, token)
			before := attestationCalls.Load()
			rec := e.finish(token, finishBody(t, a, options, 0, servertest.WithAttestation(tc.att(a))))
			if n := attestationCalls.Load() - before; n != 0 {
				t.Fatalf("go-webauthn ran an attestation verifier %d times", n)
			}
			if rec.Code != http.StatusBadRequest || strings.TrimSpace(rec.Body.String()) != `{"error":"unsupported attestation"}` {
				t.Fatalf("= %d %s, want 400 unsupported attestation\nlog:\n%s", rec.Code, rec.Body, e.log)
			}
			if got := lastReason(t, e.log); got != reasonUnsupportedAttestation {
				t.Fatalf("logged reason %q, want %q", got, reasonUnsupportedAttestation)
			}
			e.requireUnused(t, "carol")
			// The session was not consumed: the same ceremony finishes
			// with attestation none.
			if rec := e.finish(token, finishBody(t, a, options, 0)); rec.Code != http.StatusOK {
				t.Fatalf("the none finish of the same ceremony = %d %s, want 200", rec.Code, rec.Body)
			}
		})
	}
}

// TestEnrollRSABounds (owner hardening H2, 2026-10-21): the server takes
// an RS256 credential only with a modulus of 2048 to 4096 bits and the
// exponent 65537, the rule of the verifier the signer shares
// (webauthn.ParsePublicKey). go-webauthn accepts every one of these keys
// at an attestation-none registration.
func TestEnrollRSABounds(t *testing.T) {
	for _, tc := range []struct {
		name string
		bits int
		e    int
		ok   bool
	}{
		{"rsa1024", 1024, 65537, false},
		{"rsa2048", 2048, 65537, true},
		{"rsa4096", 4096, 65537, true},
		{"rsa4097", 4097, 65537, false},
		{"rsa8192", 8192, 65537, false},
		{"rsa65536_huge", 65536, 65537, false},
		{"exponent_3", 2048, 3, false},
		{"exponent_65539", 2048, 65539, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnrollEnv(t, Limits{})
			token := e.invite(t, "carol", false)
			rec := e.register(t, token, newAuthenticator(t, webauthn.AlgES256), 0, servertest.WithCOSEKey(rsaCOSE(t, tc.bits, tc.e)))
			if tc.ok {
				if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"algorithm":"RS256"`) {
					t.Fatalf("= %d %s, want 200 RS256", rec.Code, rec.Body)
				}
				return
			}
			if rec.Code != http.StatusBadRequest || lastReason(t, e.log) != reasonUnsupportedCredential {
				t.Fatalf("= %d %s, want 400 unsupported_credential\nlog:\n%s", rec.Code, rec.Body, e.log)
			}
			e.requireUnused(t, "carol")
		})
	}
}

// streamed is a request body net/http cannot size, so the request
// carries no Content-Length.
type streamed struct{ r io.Reader }

func (s streamed) Read(p []byte) (int, error) { return s.r.Read(p) }

// postRaw sends a POST to target with body; with streamedBody it sends it
// without a Content-Length.
func (e *enrollEnv) postRaw(target string, body []byte, streamedBody bool) *httptest.ResponseRecorder {
	var rd io.Reader = bytes.NewReader(body)
	if streamedBody {
		rd = streamed{bytes.NewReader(body)}
	}
	req := httptest.NewRequest(http.MethodPost, "https://"+testRPID+target, rd)
	if streamedBody {
		req.ContentLength = -1
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestEnrollBodyLimits (owner hardening H3, 2026-10-21): begin and finish
// read at most maxEnrollBeginBody and maxEnrollFinishBody bytes, before
// any parsing, and answer a larger body 413 with nothing written and no
// session consumed, whether the size is declared or the body is streamed.
func TestEnrollBodyLimits(t *testing.T) {
	const tooLarge = `{"error":"request body too large"}`
	for _, streamedBody := range []bool{false, true} {
		mode := "declared"
		if streamedBody {
			mode = "streamed"
		}
		t.Run("begin_"+mode+"_over_limit_413", func(t *testing.T) {
			e := newEnrollEnv(t, Limits{InvitePerMinute: 1 << 20, InviteBurst: 1 << 20})
			token := e.invite(t, "carol", false)
			rec := e.postRaw("/api/v1/enroll/"+token+"/begin", bytes.Repeat([]byte(" "), maxEnrollBeginBody+1), streamedBody)
			if rec.Code != http.StatusRequestEntityTooLarge || strings.TrimSpace(rec.Body.String()) != tooLarge {
				t.Fatalf("= %d %s, want 413", rec.Code, rec.Body)
			}
			if got := lastReason(t, e.log); got != reasonBodyTooLarge {
				t.Fatalf("logged reason %q, want %q", got, reasonBodyTooLarge)
			}
			// No session was stored: all MaxOpenSessions begins still fit.
			for i := range serverdb.MaxOpenSessions {
				if rec := e.begin(token); rec.Code != http.StatusOK {
					t.Fatalf("begin %d after the refusal = %d %s", i+1, rec.Code, rec.Body)
				}
			}
			if rec := e.begin(token); rec.Code != http.StatusTooManyRequests {
				t.Fatalf("begin %d = %d, want 429", serverdb.MaxOpenSessions+1, rec.Code)
			}
		})
		if !streamedBody {
			// A declared length over the limit is refused before a byte
			// of the body is read, on both routes.
			t.Run("declared_over_limit_not_read", func(t *testing.T) {
				e := newEnrollEnv(t, Limits{})
				token := e.invite(t, "carol", false)
				for _, tc := range []struct {
					route string
					limit int64
				}{{"begin", maxEnrollBeginBody}, {"finish", maxEnrollFinishBody}} {
					body := &countingReader{}
					req := httptest.NewRequest(http.MethodPost, "https://"+testRPID+"/api/v1/enroll/"+token+"/"+tc.route, body)
					req.ContentLength = tc.limit + 1
					rec := httptest.NewRecorder()
					e.s.Handler().ServeHTTP(rec, req)
					if rec.Code != http.StatusRequestEntityTooLarge || body.read() != 0 {
						t.Fatalf("%s with a declared length over the limit = %d, %d bytes read; want 413 and none read", tc.route, rec.Code, body.read())
					}
				}
				e.requireUnused(t, "carol")
			})
		}
		t.Run("begin_"+mode+"_at_limit_accepted", func(t *testing.T) {
			e := newEnrollEnv(t, Limits{})
			token := e.invite(t, "carol", false)
			if rec := e.postRaw("/api/v1/enroll/"+token+"/begin", bytes.Repeat([]byte(" "), maxEnrollBeginBody), streamedBody); rec.Code != http.StatusOK {
				t.Fatalf("= %d %s, want 200", rec.Code, rec.Body)
			}
		})
		t.Run("finish_"+mode+"_over_limit_413", func(t *testing.T) {
			e := newEnrollEnv(t, Limits{})
			token := e.invite(t, "carol", false)
			body := finishBody(t, newAuthenticator(t, webauthn.AlgES256), e.mustBegin(t, token), 0)
			padded := append(append([]byte(nil), body...), bytes.Repeat([]byte(" "), maxEnrollFinishBody+1-len(body))...)
			rec := e.postRaw("/api/v1/enroll/"+token+"/finish", padded, streamedBody)
			if rec.Code != http.StatusRequestEntityTooLarge || strings.TrimSpace(rec.Body.String()) != tooLarge {
				t.Fatalf("= %d %s, want 413", rec.Code, rec.Body)
			}
			if got := lastReason(t, e.log); got != reasonBodyTooLarge {
				t.Fatalf("logged reason %q, want %q", got, reasonBodyTooLarge)
			}
			e.requireUnused(t, "carol")
			// The session was not consumed.
			if rec := e.finish(token, body); rec.Code != http.StatusOK {
				t.Fatalf("the same finish within the limit = %d %s, want 200", rec.Code, rec.Body)
			}
		})
		t.Run("finish_"+mode+"_at_limit_accepted", func(t *testing.T) {
			e := newEnrollEnv(t, Limits{})
			token := e.invite(t, "carol", false)
			body := finishBody(t, newAuthenticator(t, webauthn.AlgES256), e.mustBegin(t, token), 0)
			padded := append(append([]byte(nil), body...), bytes.Repeat([]byte(" "), maxEnrollFinishBody-len(body))...)
			if rec := e.postRaw("/api/v1/enroll/"+token+"/finish", padded, streamedBody); rec.Code != http.StatusOK {
				t.Fatalf("= %d %s, want 200", rec.Code, rec.Body)
			}
		})
	}
}

// TestEnrollWebAuthnConfig (owner hardening H4, 2026-10-21): the
// go-webauthn relying party has no FIDO metadata service, so nothing in
// the registration path fetches a URL (go-webauthn/x's revoke package
// fetches CRL and OCSP URLs only for metadata validation), no AAGUID
// filtering, no cross-origin use, and no go-webauthn session expiry of
// its own. The session data stays on the server: begin answers only the
// creation options.
func TestEnrollWebAuthnConfig(t *testing.T) {
	e := newEnrollEnv(t, Limits{})
	t.Run("metadata_disabled", func(t *testing.T) {
		v, err := e.s.currentStatus(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		cfg := webauthnConfig(v)
		if cfg.MDS != nil || cfg.Filtering != nil || cfg.RPAllowCrossOrigin || len(cfg.RPTopOrigins) != 0 || len(cfg.RPOpaqueOrigins) != 0 ||
			cfg.Timeouts.Registration.Enforce || cfg.Debug || cfg.AttestationPreference != protocol.PreferNoAttestation {
			t.Fatalf("webauthn config %+v: want no MDS, no filtering, no cross-origin, no top or opaque origins, no enforced session expiry, attestation none", cfg)
		}
		if cfg.RPID != testRPID || !slices.Equal(cfg.RPOrigins, []string{testOrigin}) {
			t.Fatalf("RP %s %v, want the policy's %s %v", cfg.RPID, cfg.RPOrigins, testRPID, testOrigin)
		}
	})
	t.Run("sessions_server_side_only", func(t *testing.T) {
		token := e.invite(t, "carol", false)
		var top map[string]json.RawMessage
		if err := json.Unmarshal(e.mustBegin(t, token), &top); err != nil {
			t.Fatal(err)
		}
		for k := range top {
			if k != "publicKey" && k != "mediation" {
				t.Fatalf("begin answers member %q; want only the creation options", k)
			}
		}
		var pk map[string]json.RawMessage
		if err := json.Unmarshal(top["publicKey"], &pk); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"user_id", "credParams", "expires", "allowed_credentials", "userVerification"} {
			if _, ok := pk[k]; ok {
				t.Fatalf("the creation options carry session member %q", k)
			}
		}
	})
}
