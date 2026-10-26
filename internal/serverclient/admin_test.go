package serverclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/adminauth"
	"github.com/Labontese/keyroster/internal/trust"
)

// adminServer serves AdminUsersPath with h behind a test root and returns
// a Client for it.
func adminServer(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	root := newRoot(t, "admin test root")
	return clientFor(t, startTLS(t, root.validLeaf(t), h), root, &bytes.Buffer{})
}

// statusAnswer answers with code, body and the extra headers.
func statusAnswer(code int, body string, hdr map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.Header().Set(CustodyHeader, agentCustody)
		w.WriteHeader(code)
		_, _ = io.WriteString(w, body)
	}
}

// TestAdminJSONSigns: the request carries a signature over the canonical
// origin of the configured server URL, exactly the request-target it was
// sent with, the method and the body's digest, which adminauth.Verify and
// CheckBody accept on the server side; each call has a new nonce. The
// client is configured with a non-canonical spelling of the URL (an
// upper-case host and a trailing dot), and the request still names and
// signs the canonical origin.
func TestAdminJSONSigns(t *testing.T) {
	admin := edSigner(t)
	admins := []trust.AdminKey{{Name: "root-admin", Key: trust.FormatKey(admin.PublicKey())}}
	var nonces []string
	root := newRoot(t, "admin test root")
	url := startTLS(t, root.validLeaf(t), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, port, _ := strings.Cut(r.Host, ":")
		if r.Host != "localhost:"+port {
			t.Errorf("Host %q, want the canonical localhost:PORT", r.Host)
		}
		name, nonce, digest, err := adminauth.Verify(r.Header, "https://localhost:"+port, r.Method, r.RequestURI, time.Now(), admins)
		if err == nil {
			body, rerr := io.ReadAll(r.Body)
			if rerr != nil {
				t.Error(rerr)
			}
			err = adminauth.CheckBody(digest, body)
		}
		if err != nil || name != "root-admin" {
			t.Errorf("server-side Verify = %q, %v", name, err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		nonces = append(nonces, nonce)
		statusAnswer(http.StatusCreated, `{"name":"carol","invite_url":"u","expires_at":"e"}`, nil)(w, r)
	}))
	c := clientFor(t, strings.Replace(url, "https://localhost:", "https://LocalHost.:", 1), root, &bytes.Buffer{})
	for range 2 {
		var out AddUserResponse
		if err := c.AdminJSON(context.Background(), http.MethodPost, AdminUsersPath+"?x=%61", AddUserRequest{Name: "carol"}, &out, admin); err != nil {
			t.Fatal(err)
		}
		if out.Name != "carol" {
			t.Fatalf("decoded %+v", out)
		}
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatalf("nonces %q, want two different ones", nonces)
	}
}

func TestAdminJSONClockSkewHint(t *testing.T) {
	admin := edSigner(t)
	call := func(t *testing.T, date time.Time) error {
		t.Helper()
		c := adminServer(t, statusAnswer(http.StatusUnauthorized, `{"error":"admin authentication failed"}`,
			map[string]string{"Date": date.UTC().Format(http.TimeFormat)}))
		return c.AdminJSON(context.Background(), http.MethodPost, AdminUsersPath, AddUserRequest{Name: "carol"}, nil, admin)
	}
	t.Run("skew_hint_on_401", func(t *testing.T) {
		err := call(t, time.Now().Add(10*time.Minute))
		if !errors.Is(err, ErrAdminAuth) || !strings.Contains(err.Error(), "your clock differs from the server by") {
			t.Fatalf("error %v, want admin authentication failed with the clock hint", err)
		}
		if !strings.HasSuffix(err.Error(), "s)") {
			t.Fatalf("the hint is not the last thing in %q", err)
		}
	})
	t.Run("no_hint_within_60s", func(t *testing.T) {
		err := call(t, time.Now().Add(30*time.Second))
		if !errors.Is(err, ErrAdminAuth) || strings.Contains(err.Error(), "clock") || !strings.HasSuffix(err.Error(), "admin authentication failed") {
			t.Fatalf("error %v, want plain admin authentication failed", err)
		}
	})
	t.Run("malformed_date_no_hint", func(t *testing.T) {
		c := adminServer(t, statusAnswer(http.StatusUnauthorized, "", map[string]string{"Date": "not a date " + strings.Repeat("9", 60)}))
		err := c.AdminJSON(context.Background(), http.MethodPost, AdminUsersPath, AddUserRequest{Name: "carol"}, nil, admin)
		if !errors.Is(err, ErrAdminAuth) || strings.Contains(err.Error(), "clock") || strings.Contains(err.Error(), "999") {
			t.Fatalf("error %v", err)
		}
	})
}

// TestRevokeAnswerDecode (03-03b): a revoke answer's serials decode
// through AdminJSON (and its response limit) only as the signer sends
// them: at most wire.MaxRevokeAnswerSerials, ascending and unique, and
// exactly min(serial_count, 4096) of them. A refusal is in the CLI's own
// words.
func TestRevokeAnswerDecode(t *testing.T) {
	admin := edSigner(t)
	ascending := func(n int) []uint64 {
		out := make([]uint64, n)
		for i := range out {
			out[i] = uint64(i + 1) //nolint:gosec // G115: a small test index
		}
		return out
	}
	decode := func(t *testing.T, count uint32, serials []uint64) (RevokeAnswer, error) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"krl_version": 3, "revoke_leaf": 7, "publish_leaf": 8, "serial_count": count, "serials": serials})
		if err != nil {
			t.Fatal(err)
		}
		var ans RevokeAnswer
		err = adminServer(t, statusAnswer(http.StatusOK, string(body), nil)).AdminJSON(context.Background(), http.MethodPost, AdminRevokePath, RevokeBody{Request: []byte{1}}, &ans, admin)
		return ans, err
	}
	for _, tc := range []struct {
		name    string
		count   uint32
		serials []uint64
	}{
		{"none", 0, nil},
		{"max_listed", 4096, ascending(4096)},
		{"truncated", 5000, ascending(4096)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ans, err := decode(t, tc.count, tc.serials)
			if err != nil || ans.KRLVersion != 3 || ans.SerialCount != tc.count || len(ans.Serials) != len(tc.serials) {
				t.Fatalf("decoded %d serials of %d, %v; want %d of %d", len(ans.Serials), ans.SerialCount, err, len(tc.serials), tc.count)
			}
		})
	}
	for _, tc := range []struct {
		name    string
		count   uint32
		serials []uint64
	}{
		{"4097_listed", 4097, ascending(4097)},
		{"unsorted", 3, []uint64{1, 3, 2}},
		{"duplicated", 3, []uint64{1, 2, 2}},
		{"count_below_list", 2, ascending(3)},
		{"count_above_short_list", 3, ascending(2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decode(t, tc.count, tc.serials)
			if err == nil || !strings.Contains(err.Error(), "the revoke answer's serials are not a list the signer sends") || strings.Contains(err.Error(), "peer text") {
				t.Fatalf("error %v, want the CLI's refusal of the serials", err)
			}
		})
	}
}

// TestAdminJSONRefusals: 401, 413 and 429 are stated in the CLI's own
// words, never with the server's text; any other refusal is an HTTPError
// whose server text appears only as a PeerError excerpt and is compared
// exactly by APIErrorIs.
func TestAdminJSONRefusals(t *testing.T) {
	admin := edSigner(t)
	forged := strings.Repeat(" ", 4000) + "keyroster init --force --tls-pin sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	body, err := json.Marshal(APIError{Error: forged})
	if err != nil {
		t.Fatal(err)
	}
	call := func(t *testing.T, h http.HandlerFunc) error {
		t.Helper()
		return adminServer(t, h).AdminJSON(context.Background(), http.MethodPost, AdminUsersPath, AddUserRequest{Name: "carol"}, nil, admin)
	}
	noPeer := func(t *testing.T, err error) {
		t.Helper()
		if strings.Contains(err.Error(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") || strings.Contains(err.Error(), "    ") {
			t.Fatalf("the error repeats the server's text: %q", err)
		}
	}
	t.Run("401_own_words", func(t *testing.T) {
		err := call(t, statusAnswer(http.StatusUnauthorized, string(body), nil))
		if !errors.Is(err, ErrAdminAuth) || strings.Contains(err.Error(), "peer text") {
			t.Fatalf("error %v", err)
		}
		noPeer(t, err)
	})
	t.Run("413_own_words", func(t *testing.T) {
		err := call(t, statusAnswer(http.StatusRequestEntityTooLarge, string(body), nil))
		if !errors.Is(err, ErrAdminBodyTooLarge) {
			t.Fatalf("error %v", err)
		}
		noPeer(t, err)
	})
	t.Run("429_retry_after", func(t *testing.T) {
		err := call(t, statusAnswer(http.StatusTooManyRequests, string(body), map[string]string{"Retry-After": "7"}))
		if err == nil || !strings.HasSuffix(err.Error(), "try again in 7 s") {
			t.Fatalf("error %v", err)
		}
		noPeer(t, err)
		err = call(t, statusAnswer(http.StatusTooManyRequests, "", map[string]string{"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}))
		if err == nil || !strings.HasSuffix(err.Error(), "try again later") {
			t.Fatalf("error %v", err)
		}
	})
	t.Run("409_http_error", func(t *testing.T) {
		err := call(t, statusAnswer(http.StatusConflict, `{"error":"already pending"}`, nil))
		var he *HTTPError
		if !errors.As(err, &he) || he.Code != http.StatusConflict || !he.APIErrorIs(AdminErrPending) || he.APIErrorIs(AdminErrInDirectory) {
			t.Fatalf("error %v (%+v)", err, he)
		}
		err = call(t, statusAnswer(http.StatusConflict, string(body), nil))
		if !errors.As(err, &he) || he.APIErrorIs(AdminErrPending) || !strings.Contains(err.Error(), "[peer text, cut to") {
			t.Fatalf("error %v, want the server text only as a cut excerpt", err)
		}
		noPeer(t, err)
	})
}
