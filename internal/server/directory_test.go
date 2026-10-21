package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/adminauth"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/serverdb"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
	"github.com/Labontese/keyroster/internal/wire"
)

// highLimits keeps the admin limiter out of tests that send many requests.
var highLimits = Limits{AdminPerMinute: 100000, AdminBurst: 100000}

// testSigs stands for an install's signatures: the fake signer does not
// verify them.
var testSigs = []byte("sigs")

// vectorV1 is the test vector directory (alice, version 1).
func vectorV1(t *testing.T) []byte {
	t.Helper()
	doc, err := os.ReadFile("../../test/vectors/directory_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// successor returns the canonical successor of prev (nil: a genesis
// version 1 with no entries) after mutate.
func successor(t *testing.T, prev []byte, mutate func(d *directory.Directory)) []byte {
	t.Helper()
	d := &directory.Directory{Version: 1, Prev: trust.GenesisPrev}
	if prev != nil {
		p, err := directory.Parse(prev)
		if err != nil {
			t.Fatal(err)
		}
		d = p
		d.Version, d.Prev = p.Version+1, trust.SHA256Hex(prev)
	}
	mutate(d)
	d.Sort()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Parse(doc); err != nil {
		t.Fatalf("test successor does not parse: %v", err)
	}
	return doc
}

// withRole returns a mutation that adds the role name, granting the
// principal role:name to nobody yet.
func withRole(name string) func(d *directory.Directory) {
	return func(d *directory.Directory) {
		d.Roles = append(d.Roles, directory.Role{Name: name, Principals: []string{"role:" + name}, MaxTTLSeconds: 3600,
			Extensions: []string{}, Users: []string{}, Groups: []string{}})
	}
}

// bind returns a mutation that binds cred to user (adding the user,
// active, when it is not in the directory).
func bind(user string, cred directory.Credential) func(d *directory.Directory) {
	return func(d *directory.Directory) {
		for i := range d.Users {
			if d.Users[i].Name == user {
				d.Users[i].Credentials = append(d.Users[i].Credentials, cred)
				return
			}
		}
		d.Users = append(d.Users, directory.User{Name: user, Status: directory.StatusActive, Credentials: []directory.Credential{cred}})
	}
}

// newCredential returns a fresh EdDSA credential as a directory binds it.
func newCredential(t *testing.T) directory.Credential {
	t.Helper()
	a, err := webauthntest.New(webauthn.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	c := a.Credential()
	return directory.Credential{ID: base64.RawURLEncoding.EncodeToString(c.ID), Alg: c.Alg, SPKI: base64.StdEncoding.EncodeToString(c.SPKI)}
}

// storePending stores cred as name's pending credential under a new
// invite, written straight into the state database (as a registration
// would, without its duplicate checks), and returns the invite hash.
func (e *adminEnv) storePending(t *testing.T, name string, cred directory.Credential) []byte {
	t.Helper()
	ctx := context.Background()
	hash := sha256.Sum256([]byte("invite of " + name + " " + cred.ID))
	handle := sha256.Sum256([]byte("handle of " + name + " " + cred.ID))
	now := e.clock.Now()
	if err := e.s.db.CreatePendingUser(ctx, serverdb.PendingUser{Name: name, UserHandle: handle[:], InviteHash: hash[:],
		InviteExpires: now.Add(time.Hour), Created: now, CreatedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	e.bindPending(t, hash[:], name, cred)
	return hash[:]
}

// bindPending stores cred as the credential the invite with hash
// registered.
func (e *adminEnv) bindPending(t *testing.T, hash []byte, name string, cred directory.Credential) {
	t.Helper()
	spki, err := base64.StdEncoding.DecodeString(cred.SPKI)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.s.db.BindPendingCredential(context.Background(), hash, e.clock.Now().UnixMicro(),
		serverdb.PendingCredential{ID: cred.ID, UserName: name, Alg: cred.Alg, SPKI: spki}); err != nil {
		t.Fatal(err)
	}
}

// pendingOf returns the IDs of name's pending credentials.
func (e *adminEnv) pendingOf(t *testing.T, name string) []string {
	t.Helper()
	creds, err := e.s.db.PendingCredentials(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, c := range creds {
		ids = append(ids, c.ID)
	}
	return ids
}

// installBody is the JSON body of an install of doc with sigs.
func installBody(t *testing.T, doc, sigs []byte) []byte {
	t.Helper()
	body, err := json.Marshal(serverclient.InstallDirectoryRequest{Directory: doc, Sigs: sigs})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// postBody sends body, signed by the admin, to POST AdminDirectoryPath.
func (e *adminEnv) postBody(t *testing.T, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	return serve(e.s.Handler(), signedReq(t, e.admin, http.MethodPost, serverclient.AdminDirectoryPath, serverclient.AdminDirectoryPath, body, e.clock.Now()))
}

// postDirectory installs doc through the server.
func (e *adminEnv) postDirectory(t *testing.T, doc []byte) *httptest.ResponseRecorder {
	t.Helper()
	return e.postBody(t, installBody(t, doc, testSigs))
}

// getDirectory GETs AdminDirectoryPath, signed by the admin, and decodes
// a 200 answer.
func (e *adminEnv) getDirectory(t *testing.T) (*httptest.ResponseRecorder, serverclient.DirectoryAnswer) {
	t.Helper()
	res := serve(e.s.Handler(), signedReq(t, e.admin, http.MethodGet, serverclient.AdminDirectoryPath, serverclient.AdminDirectoryPath, nil, e.clock.Now()))
	var ans serverclient.DirectoryAnswer
	if res.Code == http.StatusOK {
		if err := json.Unmarshal(res.Body.Bytes(), &ans); err != nil {
			t.Fatal(err)
		}
	}
	return res, ans
}

// mustGetDirectory is getDirectory that requires 200 and version want with
// the bytes doc.
func (e *adminEnv) mustGetDirectory(t *testing.T, want uint64, doc []byte) {
	t.Helper()
	res, ans := e.getDirectory(t)
	if res.Code != http.StatusOK || ans.Version != want || !bytes.Equal(ans.Directory, doc) {
		t.Fatalf("GET directory = %d, version %d; want 200 and version %d with its bytes\n%s\nlog:\n%s", res.Code, ans.Version, want, res.Body, e.log)
	}
}

// chainEnv is newAdminEnv with the fake signer in chain mode holding doc
// (nil: none) and high admin limits.
func chainEnv(t *testing.T, doc []byte) *adminEnv {
	t.Helper()
	e := newAdminEnv(t, highLimits)
	e.fake.setChain(doc, testSigs)
	e.s.dropStatus()
	return e
}

// requireAnswer checks code and the exact JSON error body.
func requireAnswer(t *testing.T, what string, res *httptest.ResponseRecorder, code int, errText string) {
	t.Helper()
	want := `{"error":"` + errText + `"}`
	if res.Code != code || strings.TrimSpace(res.Body.String()) != want {
		t.Fatalf("%s = %d %s, want %d %s", what, res.Code, res.Body, code, want)
	}
}

// TestDirectoryMirror: the server's directory mirror reads signer state
// only through currentStatus, follows its SHA-256, and fails closed: a
// failed or inconsistent refresh serves nothing, never the previous
// version. An install through the server drops the status cache, so the
// very next request reads the new version (cross-plan audit, BLOCKER).
func TestDirectoryMirror(t *testing.T) {
	t.Run("install_then_immediate_edit_sees_new_base", func(t *testing.T) {
		v1 := vectorV1(t)
		e := chainEnv(t, v1)
		e.mustGetDirectory(t, 1, v1) // fills the status cache
		v2 := successor(t, v1, withRole("dev"))
		if res := e.postDirectory(t, v2); res.Code != http.StatusOK {
			t.Fatalf("POST v2 = %d %s", res.Code, res.Body)
		}
		st, gd := e.fake.count("Status"), e.fake.count("GetDirectory")
		_, ans := e.getDirectory(t) // the clock has not moved
		if ans.Version != 2 || !bytes.Equal(ans.Directory, v2) {
			t.Fatalf("GET right after the install = version %d, want 2 with v2's bytes", ans.Version)
		}
		if e.fake.count("Status") != st+1 || e.fake.count("GetDirectory") != gd+1 {
			t.Fatalf("the GET made %d Status and %d GetDirectory calls, want exactly one each",
				e.fake.count("Status")-st, e.fake.count("GetDirectory")-gd)
		}
		v3 := successor(t, ans.Directory, withRole("qa"))
		if res := e.postDirectory(t, v3); res.Code != http.StatusOK {
			t.Fatalf("POST v3 built on the answer = %d %s", res.Code, res.Body)
		}
	})

	t.Run("refused_install_drops_status", func(t *testing.T) {
		v1 := vectorV1(t)
		e := chainEnv(t, v1)
		e.mustGetDirectory(t, 1, v1)
		v2 := successor(t, v1, withRole("dev"))
		e.fake.setChain(v2, testSigs) // installed on the signer directly
		other := successor(t, v1, withRole("qa"))
		requireAnswer(t, "POST of a version built on v1", e.postDirectory(t, other), http.StatusConflict, "directory_version_chain")
		e.mustGetDirectory(t, 2, v2) // at the same instant
	})

	t.Run("out_of_band_install_converges_within_5s", func(t *testing.T) {
		v1 := vectorV1(t)
		e := chainEnv(t, v1)
		e.mustGetDirectory(t, 1, v1)
		v2 := successor(t, v1, withRole("dev"))
		e.fake.setChain(v2, testSigs)
		e.mustGetDirectory(t, 1, v1) // the status entry is still young
		e.clock.set(t0.Add(6 * time.Second))
		e.mustGetDirectory(t, 2, v2)
	})

	t.Run("mirror_refresh_failure_fails_closed", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		v1 := e.installDirectory(t)
		e.mustGetDirectory(t, 1, v1)
		v2 := successor(t, v1, withRole("dev"))
		st := withDirectory(e.fake.statusNow(), 2)
		st.DirectorySHA256 = sha256.Sum256(v2)
		e.fake.setStatus(st, nil)
		e.fake.setDirectory(nil, errors.New("signer read failed"))
		e.s.dropStatus()
		for i := range 2 {
			if v, err := e.s.currentDirectory(context.Background()); err == nil {
				t.Fatalf("call %d: currentDirectory = version %d, want an error", i, v.version)
			}
			res, _ := e.getDirectory(t)
			requireUnavailable(t, "GET directory while GetDirectory fails", res, false)
			if strings.Contains(res.Body.String(), base64.StdEncoding.EncodeToString(v1)[:40]) {
				t.Fatal("the 503 carries v1")
			}
		}
		e.fake.setDirectory(&wire.GetDirectoryResponse{Version: 2, Directory: v2, Sigs: testSigs, Authorized: true}, nil)
		e.mustGetDirectory(t, 2, v2)
	})

	t.Run("mirror_sha_mismatch_refused", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		v1 := e.installDirectory(t)
		v2 := successor(t, v1, withRole("dev"))
		st := withDirectory(e.fake.statusNow(), 2)
		st.DirectorySHA256 = sha256.Sum256(v2) // X
		e.fake.setStatus(st, nil)
		// The signer serves bytes whose SHA-256 is not X.
		e.fake.setDirectory(&wire.GetDirectoryResponse{Version: 2, Directory: successor(t, v1, withRole("qa")), Sigs: testSigs, Authorized: true}, nil)
		e.s.dropStatus()
		if _, err := e.s.currentDirectory(context.Background()); !errors.Is(err, errMirrorStale) {
			t.Fatalf("currentDirectory = %v, want errMirrorStale", err)
		}
		e.s.mirror.mu.Lock()
		held := e.s.mirror.entry
		e.s.mirror.mu.Unlock()
		if held != nil {
			t.Fatal("the mirror holds an entry after a mismatch")
		}
		st0, gd0 := e.fake.count("Status"), e.fake.count("GetDirectory")
		if _, err := e.s.currentDirectory(context.Background()); err == nil {
			t.Fatal("the second call served a directory")
		}
		if e.fake.count("Status") != st0+1 || e.fake.count("GetDirectory") != gd0+1 {
			t.Fatalf("the next call made %d Status and %d GetDirectory calls with the clock still; want one each (the mismatch dropped the status cache)",
				e.fake.count("Status")-st0, e.fake.count("GetDirectory")-gd0)
		}
	})

	t.Run("mirror_status_failure_fails_closed", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		v1 := e.installDirectory(t)
		e.mustGetDirectory(t, 1, v1)
		e.fake.setStatus(nil, errors.New("signer down"))
		e.clock.set(t0.Add(6 * time.Second))
		if v, err := e.s.currentDirectory(context.Background()); err == nil {
			t.Fatalf("currentDirectory = version %d with the status failing, want an error (the held entry is not served)", v.version)
		}
	})

	t.Run("mirror_follows_status_sha", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		v1 := e.installDirectory(t)
		e.mustGetDirectory(t, 1, v1)
		gd := e.fake.count("GetDirectory")
		e.clock.set(t0.Add(6 * time.Second)) // a new Status, same SHA-256
		e.mustGetDirectory(t, 1, v1)
		if n := e.fake.count("GetDirectory") - gd; n != 0 {
			t.Fatalf("%d GetDirectory calls for an unchanged SHA-256, want 0", n)
		}
		v2 := successor(t, v1, withRole("dev"))
		e.fake.setDirectory(&wire.GetDirectoryResponse{Version: 2, Directory: v2, Sigs: testSigs, Authorized: true}, nil)
		st := withDirectory(e.fake.statusNow(), 2)
		st.DirectorySHA256 = sha256.Sum256(v2)
		e.fake.setStatus(st, nil)
		e.clock.set(t0.Add(12 * time.Second))
		e.mustGetDirectory(t, 2, v2)
		e.mustGetDirectory(t, 2, v2)
		if n := e.fake.count("GetDirectory") - gd; n != 1 {
			t.Fatalf("%d GetDirectory calls for one changed SHA-256, want 1", n)
		}
	})

	t.Run("install_refused_when_mirror_unavailable", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		v1 := e.installDirectory(t)
		e.fake.setDirectory(nil, errors.New("signer read failed"))
		res := e.postDirectory(t, successor(t, v1, withRole("dev")))
		requireUnavailable(t, "POST with the mirror unavailable", res, false)
		if n := e.fake.count("InstallDirectory"); n != 0 {
			t.Fatalf("InstallDirectory called %d times, want 0", n)
		}
	})
}

// TestDirectoryInstallBodyLimit: the install route's one body limit,
// maxDirectoryInstallBody, lets through every install the signer's frame
// can carry and nothing larger; every other admin route keeps maxAdminBody
// (plan checker, iteration 2). requireAdminLimit applies it in its
// verify-before-body order (02-07 D2).
func TestDirectoryInstallBodyLimit(t *testing.T) {
	ok := &wire.InstallDirectoryResponse{Version: 1, LeafIndex: 7, SHA256: [32]byte{1}}
	fullDoc := bytes.Repeat([]byte{'d'}, wire.MaxDirectory)
	fullSigs := bytes.Repeat([]byte{'s'}, wire.MaxDirectorySigs)
	full := installBody(t, fullDoc, fullSigs)
	pad := func(n int) []byte {
		return append(append([]byte(nil), full...), bytes.Repeat([]byte{' '}, n-len(full))...)
	}

	t.Run("at_signer_cap_forwarded", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setInstall(ok, nil)
		if len(full) <= maxAdminBody || len(full) > maxDirectoryInstallBody {
			t.Fatalf("body of %d bytes: want above maxAdminBody (%d) and at most maxDirectoryInstallBody (%d)", len(full), maxAdminBody, maxDirectoryInstallBody)
		}
		frame, err := (&wire.InstallDirectoryRequest{Directory: fullDoc, Sigs: fullSigs}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if err := wire.WriteMessage(io.Discard, wire.TypeInstallDirectory, frame); err != nil {
			t.Fatalf("the full-size install does not fit the signer's frame: %v", err)
		}
		res := e.postBody(t, full)
		if res.Code != http.StatusOK {
			t.Fatalf("full-size install = %d %s\nlog:\n%s", res.Code, res.Body, e.log)
		}
		got := e.fake.lastInstallRequest()
		if e.fake.count("InstallDirectory") != 1 || got == nil || !bytes.Equal(got.Directory, fullDoc) || !bytes.Equal(got.Sigs, fullSigs) {
			t.Fatal("the signer was not given exactly the posted directory and signatures")
		}
	})

	t.Run("over_route_limit_413_no_signer_call", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setInstall(ok, nil)
		over := pad(maxDirectoryInstallBody + 1)
		req := signedReq(t, e.admin, http.MethodPost, serverclient.AdminDirectoryPath, serverclient.AdminDirectoryPath, over, e.clock.Now())
		nonce := req.Header.Get(adminauth.HeaderNonce)
		requireAnswer(t, "signed install one byte over the limit", serve(e.s.Handler(), req), http.StatusRequestEntityTooLarge, "request body too large")
		if n := e.fake.count("InstallDirectory"); n != 0 {
			t.Fatalf("InstallDirectory called %d times, want 0", n)
		}
		if err := e.s.db.UseNonce(context.Background(), nonce, t0.Add(time.Hour), t0); err != nil {
			t.Fatalf("the refused request's nonce is used (%v), want unused", err)
		}
		requireAnswer(t, "unsigned install one byte over the limit",
			serve(e.s.Handler(), signedReq(t, nil, http.MethodPost, serverclient.AdminDirectoryPath, serverclient.AdminDirectoryPath, over, e.clock.Now())),
			http.StatusRequestEntityTooLarge, "request body too large")
		// Control: exactly at the limit, signed, the request is not refused
		// for size and reaches the signer.
		if res := e.postBody(t, pad(maxDirectoryInstallBody)); res.Code != http.StatusOK || e.fake.count("InstallDirectory") != 1 {
			t.Fatalf("install at the limit = %d %s, InstallDirectory calls %d; want 200 and 1", res.Code, res.Body, e.fake.count("InstallDirectory"))
		}
	})

	t.Run("other_admin_routes_keep_default_limit", func(t *testing.T) {
		e := newAdminEnv(t, highLimits)
		e.fake.setInstall(ok, nil)
		users := append([]byte(`{"name":"carol","reinvite":false}`), bytes.Repeat([]byte{' '}, maxAdminBody+1-len(`{"name":"carol","reinvite":false}`))...)
		req := signedReq(t, e.admin, http.MethodPost, serverclient.AdminUsersPath, serverclient.AdminUsersPath, users, e.clock.Now())
		requireAnswer(t, "POST users of maxAdminBody+1 bytes", serve(e.s.Handler(), req), http.StatusRequestEntityTooLarge, "request body too large")
		small := installBody(t, []byte("d"), []byte("s"))
		dir := append(small, bytes.Repeat([]byte{' '}, maxAdminBody+1-len(small))...)
		if res := e.postBody(t, dir); res.Code != http.StatusOK {
			t.Fatalf("POST directory of maxAdminBody+1 bytes = %d %s, want 200", res.Code, res.Body)
		}
	})
}

// TestDirectoryInstallRefusals: the signer's refusals reach the admin as
// 409 (version chain), 403 (quorum, policy) and 400 (invalid) with the
// signer's reason code; a signer that cannot decide, or a lost answer, is
// 503. No refusal deletes a pending row.
func TestDirectoryInstallRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
		body string
	}{
		{"version_chain", &wire.ErrorResponse{Code: wire.CodeRefused, Message: "directory_version_chain"}, http.StatusConflict, "directory_version_chain"},
		{"quorum", &wire.ErrorResponse{Code: wire.CodeRefused, Message: "directory_quorum_not_met"}, http.StatusForbidden, "directory_quorum_not_met"},
		{"exceeds_policy", &wire.ErrorResponse{Code: wire.CodeRefused, Message: "directory_exceeds_policy"}, http.StatusForbidden, "directory_exceeds_policy"},
		{"invalid", &wire.ErrorResponse{Code: wire.CodeMalformed, Message: "directory_invalid"}, http.StatusBadRequest, "directory_invalid"},
		{"unavailable", &wire.ErrorResponse{Code: wire.CodeUnavailable, Message: "state_unavailable"}, http.StatusServiceUnavailable, "signer unavailable"},
		{"transport", errors.New("signerclient: connect: no such file"), http.StatusServiceUnavailable, "signer unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newAdminEnv(t, highLimits)
			p1 := newCredential(t)
			e.storePending(t, "dave", p1)
			e.fake.setInstall(nil, tc.err)
			res := e.postDirectory(t, successor(t, nil, bind("dave", p1)))
			requireAnswer(t, "refused install", res, tc.code, tc.body)
			if ids := e.pendingOf(t, "dave"); len(ids) != 1 || ids[0] != p1.ID || e.pendingRows(t, "dave") != 1 {
				t.Fatalf("dave's pending state after a refusal: %v, %d rows; want P1 and the row", ids, e.pendingRows(t, "dave"))
			}
		})
	}
}
