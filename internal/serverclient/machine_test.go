package serverclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// TestClientMachineRenew pins Client.MachineRenew (03-11b): the JSON
// names of the route, a refusal as an *HTTPError with the server's detail,
// a 503 as ErrSignerUnavailable and a 429 with its Retry-After.
func TestClientMachineRenew(t *testing.T) {
	root := newRoot(t, "machine root")
	serve := func(t *testing.T, code int, body string, hdr map[string]string, seen func(r *http.Request, body map[string]any)) *Client {
		t.Helper()
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var got map[string]any
			_ = json.NewDecoder(r.Body).Decode(&got)
			if seen != nil {
				seen(r, got)
			}
			w.Header().Set(CustodyHeader, agentCustody)
			w.Header().Set("Content-Type", "application/json")
			for k, v := range hdr {
				w.Header().Set(k, v)
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body + "\n"))
		})
		return clientFor(t, startTLS(t, root.validLeaf(t), h), root, nil)
	}
	req := &MachineRenewRequest{Request: []byte("request bytes")}
	t.Run("posts_json_and_decodes_answer", func(t *testing.T) {
		var gotPath, gotMethod string
		var gotBody map[string]any
		c := serve(t, http.StatusOK, `{"certificate":"`+base64.StdEncoding.EncodeToString([]byte("cert bytes"))+`"}`, nil,
			func(r *http.Request, body map[string]any) { gotPath, gotMethod, gotBody = r.URL.Path, r.Method, body })
		a, err := c.MachineRenew(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if gotPath != MachineRenewPath || gotMethod != http.MethodPost {
			t.Fatalf("%s %s, want POST %s", gotMethod, gotPath, MachineRenewPath)
		}
		if gotBody["request"] != base64.StdEncoding.EncodeToString([]byte("request bytes")) || len(gotBody) != 1 {
			t.Fatalf("body %v, want only the request in base64", gotBody)
		}
		if string(a.Certificate) != "cert bytes" {
			t.Fatalf("certificate %q", a.Certificate)
		}
	})
	t.Run("error_body_is_httperror_with_detail", func(t *testing.T) {
		c := serve(t, http.StatusForbidden, `{"error":"machine_not_authenticated"}`, nil, nil)
		_, err := c.MachineRenew(context.Background(), req)
		var he *HTTPError
		if !errors.As(err, &he) || he.Code != http.StatusForbidden || !he.APIErrorIs(MachineErrNotAuthenticated) || he.APIErrorIs("machine_not_authenticated ") {
			t.Fatalf("a 403: %v", err)
		}
	})
	t.Run("unavailable_is_errsignerunavailable", func(t *testing.T) {
		c := serve(t, http.StatusServiceUnavailable, `{"error":"signer unavailable"}`, nil, nil)
		if _, err := c.MachineRenew(context.Background(), req); !errors.Is(err, ErrSignerUnavailable) {
			t.Fatalf("a 503: %v, want ErrSignerUnavailable", err)
		}
	})
	t.Run("rate_limited_has_retry_after", func(t *testing.T) {
		c := serve(t, http.StatusTooManyRequests, `{"error":"rate limited"}`, map[string]string{"Retry-After": "7"}, nil)
		_, err := c.MachineRenew(context.Background(), req)
		var he *HTTPError
		if !errors.As(err, &he) {
			t.Fatalf("a 429: %v", err)
		}
		if secs, ok := he.RateLimited(); !ok || secs != 7 {
			t.Fatalf("RateLimited() = %d, %v; want 7, true", secs, ok)
		}
	})
}
