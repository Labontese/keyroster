//go:build linux

package fetch

import (
	"bytes"
	"errors"
	"maps"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/trust"
)

// prunePolicy is a policy document of version v; salt tells two
// documents of one version apart.
func prunePolicy(v uint64, salt string) string {
	return `{"version":` + strconv.FormatUint(v, 10) + `,"salt":"` + salt + `"}`
}

// pruneBundle is bundle version v naming the policy pol by its SHA-256,
// the field the applier reads before any signature check (leanBundle).
func pruneBundle(v uint64, pol string) string {
	return `{"version":` + strconv.FormatUint(v, 10) + `,"policy_sha256":"` + trust.SHA256Hex([]byte(pol)) + `"}`
}

// bundleNaming is the answer's bundle version v naming pol, which it
// carries at policy version pv.
func bundleNaming(v, pv uint64, pol string) serverclient.AgentBundle {
	return serverclient.AgentBundle{Version: v, Bundle: []byte(pruneBundle(v, pol)), BundleSigs: []byte("s"), PolicyVersion: pv,
		Policy: []byte(pol), PolicySigs: []byte("s")}
}

// krlItem is a KRL item of version v whose manifest names v.
func krlItem(v uint64) *serverclient.AgentKRL {
	return &serverclient.AgentKRL{Version: v, KRL: []byte("k"), Manifest: []byte(`{"krl_version":` + strconv.FormatUint(v, 10) + `}`), Sig: []byte("s")}
}

var spoolSetRE = regexp.MustCompile(`^(bundle|policy|directory|krl)-([0-9]+)\.`)

// spoolSets is how many versions of each kind have a file in the spool.
func spoolSets(t *testing.T, dir string) map[string]int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	out := map[string]int{}
	for _, e := range entries {
		if m := spoolSetRE.FindStringSubmatch(e.Name()); m != nil && !seen[m[1]+m[2]] {
			seen[m[1]+m[2]] = true
			out[m[1]]++
		}
	}
	return out
}

// hasPolicy reports whether st offers the policy document pol.
func hasPolicy(st spool.State, pol string) bool {
	for _, d := range st.Policies {
		if string(d.Body) == pol {
			return true
		}
	}
	return false
}

// policiesNamed reports the bundles of st whose policy (by policy_sha256)
// st does not offer.
func policiesNamed(t *testing.T, st spool.State) []uint64 {
	t.Helper()
	var missing []uint64
	for v, b := range st.Bundles {
		found := false
		for _, d := range st.Policies {
			if bytes.Contains(b.Body, []byte(`"policy_sha256":"`+trust.SHA256Hex(d.Body)+`"`)) {
				found = true
			}
		}
		if !found {
			missing = append(missing, v)
		}
	}
	slices.Sort(missing)
	return missing
}

func exists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// TestSpoolPrune is F01 (03-08e) fix round 1: what the fetcher keeps in
// the spool across answers, whatever a compromised server sends.
func TestSpoolPrune(t *testing.T) {
	perPoll := MaxRounds * serverclient.MaxAgentStatePerKind
	t.Run("spool_stays_bounded_across_polls", func(t *testing.T) {
		// A compromised server answers every poll with 16 bundles, each
		// naming a policy at a new version (bundle 2 the honest policy's
		// bytes under a version they do not name), 16 directories and a
		// KRL at a new version. The spool stops growing: what one poll
		// writes goes at a later poll once nothing the applier reads names
		// it, and the versions per kind stay within the bound.
		honest := prunePolicy(1, "honest")
		var poll atomic.Uint64
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			k := poll.Add(1)
			var resp serverclient.AgentStateResponse
			for v := uint64(2); v < 2+serverclient.MaxAgentStatePerKind; v++ {
				if v == 2 {
					resp.Bundles = append(resp.Bundles, bundleNaming(v, 500+k, honest))
				} else {
					pv := 1000*k + v
					resp.Bundles = append(resp.Bundles, bundleNaming(v, pv, prunePolicy(pv, "junk")))
				}
				resp.Directories = append(resp.Directories, serverclient.AgentDirectory{Version: v, Directory: []byte("d"), Sigs: []byte("s")})
			}
			resp.KRL = krlItem(100 + k)
			_, _ = w.Write(stateBody(t, resp))
		})
		ts.seed(t, map[string]string{
			"bundle-1.json": pruneBundle(1, honest), "bundle-1.json.sigs": "s", "policy-1.json": honest, "policy-1.json.sigs": "s",
			"directory-1.json": "d", "directory-1.json.sigs": "s",
			"krl-1.krl": "k", "krl-1.manifest.json": `{"krl_version":1}`, "krl-1.manifest.sig": "s",
		}, &enroll.Accepted{Bundle: 1, Directory: 1, KRL: 1})
		// The bound: what the prune keeps (with a floor the version at or
		// below it and perPoll above it, one policy per kept bundle, the
		// newest complete KRL) plus what one poll writes.
		bound := map[string]int{"bundle": 1 + 2*perPoll, "directory": 1 + 2*perPoll, "policy": 1 + 2*perPoll, "krl": 1 + MaxRounds}
		var counts []map[string]int
		for i := range 8 {
			if err := ts.f.Once(t.Context()); err != nil {
				t.Fatalf("poll %d: %v", i+1, err)
			}
			c := spoolSets(t, ts.spool)
			for kind, n := range c {
				if n > bound[kind] {
					t.Errorf("poll %d: %d %s versions, above the bound %d", i+1, n, kind, bound[kind])
				}
			}
			counts = append(counts, c)
		}
		if !maps.Equal(counts[2], counts[7]) {
			t.Errorf("the spool grew between polls 3 and 8: %v, then %v", counts[2], counts[7])
		}
		for _, n := range []string{"policy-501.json", "policy-1003.json", "policy-6017.json", "krl-101.krl", "krl-106.krl"} {
			if exists(t, filepath.Join(ts.spool, n)) {
				t.Errorf("%s from an earlier poll is still spooled", n)
			}
		}
		for _, n := range []string{"bundle-1.json", "policy-1.json", "directory-1.json", "krl-108.krl", "policy-8017.json"} {
			if !exists(t, filepath.Join(ts.spool, n)) {
				t.Errorf("%s is gone", n)
			}
		}
	})
	t.Run("fresh_host_junk_policies_cannot_hide_the_honest_one", func(t *testing.T) {
		// A host that accepted nothing yet reads the newest
		// spool.MaxVersionsPerKind policies. Junk policies above the honest
		// one, which no bundle names, go at the next poll, and the honest
		// policy the honest bundle names is read again.
		honest := prunePolicy(3, "honest")
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{bundleNaming(5, 3, honest)}}))
		})
		files := map[string]string{"bundle-5.json": pruneBundle(5, honest), "bundle-5.json.sigs": "s", "policy-3.json": honest, "policy-3.json.sigs": "s"}
		for i := range uint64(spool.MaxVersionsPerKind) {
			v := math.MaxUint64 - i
			n := "policy-" + strconv.FormatUint(v, 10) + ".json"
			files[n], files[n+".sigs"] = prunePolicy(v, "junk"), "s"
		}
		ts.seed(t, files, &enroll.Accepted{})
		if st, _, err := spool.Read(ts.spool, spool.Floor{}); err != nil || hasPolicy(st, honest) {
			t.Fatalf("the poisoned spool's floor-0 capture offers the honest policy (%v): the test does not test", err)
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		st, _, err := spool.Read(ts.spool, spool.Floor{})
		if err != nil {
			t.Fatal(err)
		}
		if !hasPolicy(st, honest) || len(policiesNamed(t, st)) != 0 {
			t.Fatalf("the floor-0 capture after the poll offers policies %v, not the honest one", slices.Sorted(maps.Keys(st.Policies)))
		}
	})
	t.Run("fresh_host_junk_bundles_below_cannot_hide_the_honest_policy", func(t *testing.T) {
		// 64 junk bundles below the honest one, each naming a junk policy at
		// a version above the honest policy's. The fetcher keeps the newest
		// spool.MaxVersionsPerKind bundles, as the floor-0 capture reads
		// them, and only their policies, so every policy they name fits in
		// the newest MaxVersionsPerKind the capture reads.
		honest := prunePolicy(3, "honest")
		cur := uint64(spool.MaxVersionsPerKind + 1)
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{bundleNaming(cur, 3, honest)}}))
		})
		files := map[string]string{"policy-3.json": honest, "policy-3.json.sigs": "s"}
		for v := uint64(1); v <= cur; v++ {
			pol, pv := honest, uint64(3)
			if v < cur {
				pv = math.MaxUint64 - v
				pol = prunePolicy(pv, "junk")
			}
			b, p := "bundle-"+strconv.FormatUint(v, 10)+".json", "policy-"+strconv.FormatUint(pv, 10)+".json"
			files[b], files[b+".sigs"], files[p], files[p+".sigs"] = pruneBundle(v, pol), "s", pol, "s"
		}
		ts.seed(t, files, &enroll.Accepted{})
		if st, _, err := spool.Read(ts.spool, spool.Floor{}); err != nil || hasPolicy(st, honest) {
			t.Fatalf("the poisoned spool's floor-0 capture offers the honest policy (%v): the test does not test", err)
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		st, _, err := spool.Read(ts.spool, spool.Floor{})
		if err != nil {
			t.Fatal(err)
		}
		if !hasPolicy(st, honest) {
			t.Fatalf("the floor-0 capture after the poll offers policies %v, not the honest one", slices.Sorted(maps.Keys(st.Policies)))
		}
		if missing := policiesNamed(t, st); len(missing) != 0 {
			t.Fatalf("bundles %v of the capture name a policy it does not offer", missing)
		}
	})
	t.Run("fresh_host_junk_above_dropped", func(t *testing.T) {
		// A host that accepted nothing yet (accepted.json names 0, which
		// the applier writes after every apply that took the lock) asks for
		// the current state only, so the junk bundle, directory and KRL
		// above the server's current versions go at the end of that poll
		// (dropAbove). The junk policy only the junk bundle named goes at
		// the next poll.
		honest, junk := prunePolicy(3, "honest"), prunePolicy(100, "junk")
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{bundleNaming(5, 3, honest)},
				Directories: []serverclient.AgentDirectory{{Version: 5, Directory: []byte("honest"), Sigs: []byte("s")}}, KRL: krlItem(7)}))
		})
		ts.seed(t, map[string]string{
			"bundle-100.json": pruneBundle(100, junk), "bundle-100.json.sigs": "s", "policy-100.json": junk, "policy-100.json.sigs": "s",
			"directory-100.json": "junk", "directory-100.json.sigs": "s",
			"krl-100.krl": "junk", "krl-100.manifest.json": `{"krl_version":100}`, "krl-100.manifest.sig": "s",
		}, &enroll.Accepted{})
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if reqs := ts.requests(); len(reqs) != 1 || reqs[0] != "GET "+serverclient.AgentStatePath {
			t.Fatalf("requests %q, want the current state only", reqs)
		}
		for _, n := range []string{"bundle-100.json", "bundle-100.json.sigs", "directory-100.json", "directory-100.json.sigs", "krl-100.krl", "krl-100.manifest.json", "krl-100.manifest.sig"} {
			if exists(t, filepath.Join(ts.spool, n)) {
				t.Errorf("the junk %s is still spooled", n)
			}
		}
		st, _, err := spool.Read(ts.spool, spool.Floor{})
		if err != nil {
			t.Fatal(err)
		}
		if vs := slices.Sorted(maps.Keys(st.Bundles)); !slices.Equal(vs, []uint64{5}) || string(st.Directories[5].Body) != "honest" || len(st.KRLs) != 1 || st.KRLs[7].KRL == nil {
			t.Fatalf("the floor-0 capture: bundles %v, directories %v, KRLs %v", vs, slices.Sorted(maps.Keys(st.Directories)), slices.Sorted(maps.Keys(st.KRLs)))
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if exists(t, filepath.Join(ts.spool, "policy-100.json")) {
			t.Error("the junk policy no spooled bundle names is still spooled after the next poll")
		}
	})
	t.Run("prune_keeps_what_the_applier_reads", func(t *testing.T) {
		// accepted.json: bundle 3, directory 2, KRL 5. The spool also holds
		// bundles 4 and 5 and directory 3, which a pending swap reads from
		// (its floor is bundle 5, policy 3, directory 3), and the server
		// answers them again. What either capture reads stays, every policy
		// the kept bundles name stays (the accepted bundle's included), and
		// the rest goes: versions below the accepted ones, an incomplete
		// bundle, KRLs but the newest complete one (a newer one without its
		// signature included), a policy only removed bundles name, one no
		// bundle names, the accepted policy's bytes under another version,
		// and a signature file without its document.
		pOld, pAcc, pNew, pNone := prunePolicy(1, "old"), prunePolicy(2, "acc"), prunePolicy(3, "new"), prunePolicy(9, "none")
		ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != "bundle=3&directory=2&krl=5" {
				http.Error(w, "unexpected request "+r.URL.RawQuery, http.StatusBadRequest)
				return
			}
			_, _ = w.Write(stateBody(t, serverclient.AgentStateResponse{Bundles: []serverclient.AgentBundle{bundleNaming(4, 2, pAcc), bundleNaming(5, 3, pNew)},
				Directories: []serverclient.AgentDirectory{{Version: 3, Directory: []byte("d3"), Sigs: []byte("s")}}}))
		})
		ts.seed(t, map[string]string{
			"bundle-1.json": pruneBundle(1, pOld), "bundle-1.json.sigs": "s", "bundle-2.json": pruneBundle(2, pOld),
			"bundle-3.json": pruneBundle(3, pAcc), "bundle-3.json.sigs": "s", "bundle-4.json": pruneBundle(4, pAcc), "bundle-4.json.sigs": "s",
			"bundle-5.json": pruneBundle(5, pNew), "bundle-5.json.sigs": "s",
			"policy-1.json": pOld, "policy-1.json.sigs": "s", "policy-2.json": pAcc, "policy-2.json.sigs": "s", "policy-3.json": pNew, "policy-3.json.sigs": "s",
			"policy-9.json": pNone, "policy-9.json.sigs": "s", "policy-7.json": pAcc, "policy-7.json.sigs": "s", "policy-8.json.sigs": "s",
			"directory-1.json": "d1", "directory-1.json.sigs": "s", "directory-2.json": "d2", "directory-2.json.sigs": "s", "directory-3.json": "d3", "directory-3.json.sigs": "s",
			"krl-4.krl": "k", "krl-4.manifest.json": `{"krl_version":4}`, "krl-4.manifest.sig": "s",
			"krl-5.krl": "k", "krl-5.manifest.json": `{"krl_version":5}`, "krl-5.manifest.sig": "s",
			"krl-6.krl": "k", "krl-6.manifest.json": `{"krl_version":6}`,
		}, &enroll.Accepted{Bundle: 3, Directory: 2, KRL: 5})
		floors := []spool.Floor{{Bundle: 3, Policy: 2, Directory: 2}, {Bundle: 5, Policy: 3, Directory: 3}}
		var before []spool.State
		for _, fl := range floors {
			st, _, err := spool.Read(ts.spool, fl)
			if err != nil {
				t.Fatal(err)
			}
			before = append(before, st)
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"bundle-1.json", "bundle-1.json.sigs", "bundle-2.json", "directory-1.json", "directory-1.json.sigs",
			"krl-4.krl", "krl-4.manifest.json", "krl-4.manifest.sig", "krl-6.krl", "krl-6.manifest.json", "policy-1.json", "policy-1.json.sigs", "policy-9.json", "policy-9.json.sigs",
			"policy-7.json", "policy-7.json.sigs", "policy-8.json.sigs"} {
			if exists(t, filepath.Join(ts.spool, n)) {
				t.Errorf("%s is still spooled", n)
			}
		}
		for _, n := range []string{"bundle-3.json", "bundle-4.json", "bundle-5.json", "policy-2.json", "policy-3.json", "directory-2.json", "directory-3.json", "krl-5.krl"} {
			if !exists(t, filepath.Join(ts.spool, n)) {
				t.Errorf("%s is gone", n)
			}
		}
		for i, fl := range floors {
			st, _, err := spool.Read(ts.spool, fl)
			if err != nil {
				t.Fatal(err)
			}
			if !maps.EqualFunc(st.Bundles, before[i].Bundles, docEqual) || !maps.EqualFunc(st.Directories, before[i].Directories, docEqual) ||
				!maps.EqualFunc(st.KRLs, before[i].KRLs, func(a, b spool.KRLFiles) bool {
					return bytes.Equal(a.KRL, b.KRL) && bytes.Equal(a.Manifest, b.Manifest) && bytes.Equal(a.Sig, b.Sig)
				}) {
				t.Errorf("floor %+v: the capture changed: bundles %v, directories %v, KRLs %v", fl, slices.Sorted(maps.Keys(st.Bundles)),
					slices.Sorted(maps.Keys(st.Directories)), slices.Sorted(maps.Keys(st.KRLs)))
			}
			if missing := policiesNamed(t, st); len(missing) != 0 {
				t.Errorf("floor %+v: bundles %v name a policy the capture does not offer", fl, missing)
			}
		}
	})
	t.Run("prune_leaves_symlinks_unknown_names_and_non_regular_files", func(t *testing.T) {
		// The rules healSpool follows: a symlink is never followed or
		// removed, nor is a directory, and a name the applier never reads
		// is not the prune's.
		pAcc, pNone := prunePolicy(2, "acc"), prunePolicy(9, "none")
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(emptyState)) })
		ts.seed(t, map[string]string{"bundle-3.json": pruneBundle(3, pAcc), "bundle-3.json.sigs": "s", "policy-2.json": pAcc, "policy-2.json.sigs": "s",
			"bundle-1.json.sigs": "s", "policy-9.json.sigs": "s", "policy-11.json.sigs": "s", "notes.txt": "x", ".policy-4.json.tmp-0011223344556677": "x", "policy-0.json": "x"},
			&enroll.Accepted{Bundle: 3})
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte(pNone), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"bundle-1.json", "policy-9.json"} {
			if err := os.Symlink(target, filepath.Join(ts.spool, n)); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Mkdir(filepath.Join(ts.spool, "policy-11.json"), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"bundle-1.json", "policy-9.json", "policy-11.json", "notes.txt", ".policy-4.json.tmp-0011223344556677", "policy-0.json", "bundle-3.json", "policy-2.json"} {
			if !exists(t, filepath.Join(ts.spool, n)) {
				t.Errorf("%s was removed", n)
			}
		}
		if b, err := os.ReadFile(target); err != nil || string(b) != pNone { //nolint:gosec // test fixture
			t.Errorf("the symlinks' target: %q, %v", b, err)
		}
	})
	t.Run("prune_removes_no_policy_when_a_kept_bundle_cannot_be_read", func(t *testing.T) {
		// A kept bundle the fetcher cannot read (a symlink, which no answer
		// writes) might name any policy: then no policy goes.
		pAcc, pNone := prunePolicy(2, "acc"), prunePolicy(9, "none")
		ts := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(emptyState)) })
		ts.seed(t, map[string]string{"bundle-3.json.sigs": "s", "policy-2.json": pAcc, "policy-2.json.sigs": "s", "policy-9.json": pNone, "policy-9.json.sigs": "s"},
			&enroll.Accepted{Bundle: 3})
		target := filepath.Join(t.TempDir(), "bundle")
		if err := os.WriteFile(target, []byte(pruneBundle(3, pAcc)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(ts.spool, "bundle-3.json")); err != nil {
			t.Fatal(err)
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"policy-2.json", "policy-2.json.sigs", "policy-9.json", "policy-9.json.sigs"} {
			if !exists(t, filepath.Join(ts.spool, n)) {
				t.Errorf("%s was removed although a kept bundle could not be read", n)
			}
		}
	})
	t.Run("honest_catch_up_keeps_one_polls_versions", func(t *testing.T) {
		// A host far behind: one poll spools 199 bundles (13 rounds) with a
		// policy rotation every 10 versions. The applier accepts 64 of them;
		// the next poll is rate limited, after the prune. The applier still
		// reads its way to the server's current version from the spool, as
		// it did before the prune: everything one poll can write above the
		// accepted version stays.
		const cur = 200
		pol := func(v uint64) (uint64, string) { pv := 1 + (v-1)/10; return pv, prunePolicy(pv, "honest") }
		var n atomic.Int32
		ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) > 13 {
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limited"}`))
				return
			}
			since, err := strconv.ParseUint(r.URL.Query().Get("bundle"), 10, 64)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var resp serverclient.AgentStateResponse
			for v := since + 1; v <= cur && len(resp.Bundles) < serverclient.MaxAgentStatePerKind; v++ {
				pv, p := pol(v)
				resp.Bundles = append(resp.Bundles, bundleNaming(v, pv, p))
			}
			resp.More = since+uint64(len(resp.Bundles)) < cur //nolint:gosec // G115: a slice length
			_, _ = w.Write(stateBody(t, resp))
		})
		_, p1 := pol(1)
		ts.seed(t, map[string]string{"bundle-1.json": pruneBundle(1, p1), "bundle-1.json.sigs": "s", "policy-1.json": p1, "policy-1.json.sigs": "s"},
			&enroll.Accepted{Bundle: 1})
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		if v, err := spooledVersions(ts.spool); err != nil || v.Bundle != cur {
			t.Fatalf("after the first poll the spool's newest bundle is %d (%v)", v.Bundle, err)
		}
		floor := uint64(1)
		accept := func(v uint64) {
			floor = v
			ts.seed(t, nil, &enroll.Accepted{Bundle: v})
		}
		accept(1 + spool.MaxVersionsPerKind)
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		for floor < cur {
			pv, _ := pol(floor)
			st, _, err := spool.Read(ts.spool, spool.Floor{Bundle: floor, Policy: pv})
			if err != nil {
				t.Fatal(err)
			}
			if missing := policiesNamed(t, st); len(missing) != 0 {
				t.Fatalf("floor %d: bundles %v name a policy the capture does not offer", floor, missing)
			}
			vs := slices.Sorted(maps.Keys(st.Bundles))
			if len(vs) < 2 || vs[0] != floor || vs[1] != floor+1 {
				t.Fatalf("floor %d: the capture offers bundles %v, not the next version", floor, vs)
			}
			accept(vs[len(vs)-1])
		}
	})
	t.Run("superseded_pending_target_kept", func(t *testing.T) {
		// F01 (03-08e) fix round 3: a swap's widening wait reads the spool
		// from its pending target's floor, not the accepted one, and a newer
		// capture supersedes that target. Here accepted.json stays at bundle
		// 1 while the pending target moves to 65 and then to 129; a poll then
		// prunes and is rate limited. The capture at floor 129 must still
		// offer 129 and what follows it: a window of 64 above the accepted
		// version left it [65], which Verify refuses as older than the
		// pending target until a later poll succeeds.
		const cur = 200
		pol := func(v uint64) (uint64, string) {
			pv := 1 + (v-1)/10
			return pv, prunePolicy(pv, "honest")
		}
		var n atomic.Int32
		ts := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) > 13 {
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limited"}`))
				return
			}
			since, err := strconv.ParseUint(r.URL.Query().Get("bundle"), 10, 64)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var resp serverclient.AgentStateResponse
			for v := since + 1; v <= cur && len(resp.Bundles) < serverclient.MaxAgentStatePerKind; v++ {
				pv, p := pol(v)
				resp.Bundles = append(resp.Bundles, bundleNaming(v, pv, p))
			}
			resp.More = since+uint64(len(resp.Bundles)) < cur //nolint:gosec // G115: a slice length
			_, _ = w.Write(stateBody(t, resp))
		})
		_, p1 := pol(1)
		ts.seed(t, map[string]string{"bundle-1.json": pruneBundle(1, p1), "bundle-1.json.sigs": "s", "policy-1.json": p1, "policy-1.json.sigs": "s"},
			&enroll.Accepted{Bundle: 1})
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		// capture is what a pending target's capture at floor offers.
		capture := func(floor uint64) []uint64 {
			t.Helper()
			pv, _ := pol(floor)
			st, _, err := spool.Read(ts.spool, spool.Floor{Bundle: floor, Policy: pv})
			if err != nil {
				t.Fatal(err)
			}
			if missing := policiesNamed(t, st); len(missing) != 0 {
				t.Fatalf("floor %d: bundles %v name a policy the capture does not offer", floor, missing)
			}
			return slices.Sorted(maps.Keys(st.Bundles))
		}
		const p, q = 1 + spool.MaxVersionsPerKind, 1 + 2*spool.MaxVersionsPerKind
		if vs := capture(p); len(vs) == 0 || vs[0] != p || vs[len(vs)-1] != q {
			t.Fatalf("before the prune the capture at the pending floor %d offers %v", p, vs)
		}
		if err := ts.f.Once(t.Context()); err != nil {
			t.Fatal(err)
		}
		vs := capture(q)
		if len(vs) < 2 || vs[0] != q || vs[1] != q+1 {
			t.Fatalf("after the prune the capture at the superseding pending floor %d offers %v, want %d and what follows it", q, vs, q)
		}
	})
}

func docEqual(a, b spool.Doc) bool { return bytes.Equal(a.Body, b.Body) && bytes.Equal(a.Sigs, b.Sigs) }
