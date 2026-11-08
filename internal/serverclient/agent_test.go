package serverclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// TestAgentStateCheckSince pins what a state answer must be to follow on
// from the versions the request named (PR #71 review F3/F7): with none,
// at most the current item of a kind; otherwise the next versions in a
// row; a KRL above the requested one whose manifest names its version.
func TestAgentStateCheckSince(t *testing.T) {
	dir := func(v uint64) AgentDirectory {
		return AgentDirectory{Version: v, Directory: []byte("d"), Sigs: []byte("s")}
	}
	bundle := func(v uint64) AgentBundle {
		return AgentBundle{Version: v, Bundle: []byte("b"), BundleSigs: []byte("s"), PolicyVersion: 1, Policy: []byte("p"), PolicySigs: []byte("s")}
	}
	krlItem := func(v uint64, manifest string) *AgentKRL {
		return &AgentKRL{Version: v, KRL: []byte("k"), Manifest: []byte(manifest), Sig: []byte("s")}
	}
	for _, tc := range []struct {
		name  string
		r     AgentStateResponse
		since AgentVersions
		ok    bool
	}{
		{"current_only_with_no_versions", AgentStateResponse{Bundles: []AgentBundle{bundle(7)}, Directories: []AgentDirectory{dir(9)}, KRL: krlItem(100, `{"krl_version":100}`)}, AgentVersions{}, true},
		{"next_versions_in_a_row", AgentStateResponse{Bundles: []AgentBundle{bundle(2), bundle(3)}, Directories: []AgentDirectory{dir(4), dir(5), dir(6)}, KRL: krlItem(101, `{"krl_version":101,"other":1}`)}, AgentVersions{Bundle: 1, Directory: 3, KRL: 100}, true},
		{"nothing_newer", AgentStateResponse{}, AgentVersions{Bundle: 5, Directory: 5, KRL: 5}, true},
		{"two_items_with_no_version_refused", AgentStateResponse{Directories: []AgentDirectory{dir(1), dir(2)}}, AgentVersions{}, false},
		{"directory_at_since_refused", AgentStateResponse{Directories: []AgentDirectory{dir(3)}}, AgentVersions{Directory: 3}, false},
		{"directory_gap_refused", AgentStateResponse{Directories: []AgentDirectory{dir(5)}}, AgentVersions{Directory: 3}, false},
		{"directory_far_above_refused", AgentStateResponse{Directories: []AgentDirectory{dir(18446744073709551615)}}, AgentVersions{Directory: 3}, false},
		{"bundle_gap_refused", AgentStateResponse{Bundles: []AgentBundle{bundle(2), bundle(4)}}, AgentVersions{Bundle: 1}, false},
		{"krl_at_since_refused", AgentStateResponse{KRL: krlItem(100, `{"krl_version":100}`)}, AgentVersions{KRL: 100}, false},
		{"krl_below_since_refused", AgentStateResponse{KRL: krlItem(99, `{"krl_version":99}`)}, AgentVersions{KRL: 100}, false},
		{"krl_manifest_version_differs_refused", AgentStateResponse{KRL: krlItem(18446744073709551615, `{"krl_version":101}`)}, AgentVersions{KRL: 100}, false},
		{"krl_manifest_not_json_refused", AgentStateResponse{KRL: krlItem(101, `junk`)}, AgentVersions{KRL: 100}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.r.CheckSince(tc.since)
			if tc.ok != (err == nil) || (err != nil && !errors.Is(err, ErrChainOutOfOrder)) {
				t.Fatalf("CheckSince(%+v): %v, want ok %t", tc.since, err, tc.ok)
			}
		})
	}
}

// TestAgentProbeCert (03-10b): the client posts the request bytes as
// base64 JSON to AgentProbeCertPath, returns the certificate of a 200, and
// a 403's detail through HTTPError.Detail.
func TestAgentProbeCert(t *testing.T) {
	root := newRoot(t, "probe root")
	var gotPath, gotMethod string
	var gotBody map[string]any
	refuse := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set(CustodyHeader, agentCustody)
		w.Header().Set("Content-Type", "application/json")
		if refuse {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"probe_cert_recent"}` + "\n"))
			return
		}
		_, _ = w.Write([]byte(`{"certificate":"` + base64.StdEncoding.EncodeToString([]byte("cert bytes")) + `"}` + "\n"))
	})
	c := clientFor(t, startTLS(t, root.validLeaf(t), h), root, nil)
	a, err := c.AgentProbeCert(context.Background(), &AgentProbeCertRequest{Request: []byte("request bytes")})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != AgentProbeCertPath || gotMethod != http.MethodPost {
		t.Fatalf("%s %s, want POST %s", gotMethod, gotPath, AgentProbeCertPath)
	}
	if gotBody["request"] != base64.StdEncoding.EncodeToString([]byte("request bytes")) || len(gotBody) != 1 {
		t.Fatalf("body %v", gotBody)
	}
	if string(a.Certificate) != "cert bytes" {
		t.Fatalf("certificate %q", a.Certificate)
	}
	refuse = true
	_, err = c.AgentProbeCert(context.Background(), &AgentProbeCertRequest{Request: []byte("request bytes")})
	var he *HTTPError
	if !errors.As(err, &he) || he.Code != http.StatusForbidden || he.Detail() != "probe_cert_recent" {
		t.Fatalf("a 403: %v", err)
	}
}
