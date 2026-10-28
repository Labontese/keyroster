package serverclient

import (
	"errors"
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
