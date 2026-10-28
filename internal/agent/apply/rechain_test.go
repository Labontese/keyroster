//go:build linux

package apply

import (
	"errors"
	"slices"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
)

// TestKRLAlone is owner decision D-R2 (PR #71 review F5): a capture whose
// directory or bundle step is refused still installs its KRL, verified
// against the bundle in force, and only the KRL: the directory, the
// principals and the bundle stay as accepted, and the refusal is reported.
// Revocations only narrow what sshd accepts, so they never wait for a chain
// that does not verify (a signer restore that re-made a version this host
// had accepted, for example).
func TestKRLAlone(t *testing.T) {
	t.Run("directory_rechain_refused_krl_applied", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.publishKRL(5)
		h.mustApply()
		// Version 2, accepted here, is lost in a signer restore; the
		// signer re-makes a different version 2 and builds version 3 on it.
		// The spool still holds the lost version 2 the fetcher got first.
		h.publishDir(h.spec("role:ops", "role:lost"))
		h.mustApply()
		remade := h.f.directory(h.dirs[0].Body, h.spec("role:ops", "role:remade"))
		next := h.f.directory(remade.Body, h.spec("role:ops", "role:next"))
		h.state.Directories[3] = next
		h.publishKRL(5, 6)
		gen := h.current()
		r, err := h.apply()
		if !errors.Is(err, state.ErrDir) {
			t.Fatalf("a directory that does not chain to the accepted version: %v, want directory_not_verified reported", err)
		}
		if !h.krlRevokes(h.l.Current(), 6) || h.current() == gen || r.KRLVersion != h.f.krlVersion {
			t.Fatalf("the newer KRL was not applied alone: revokes 6 %t, current %d (was %d), %+v", h.krlRevokes(h.l.Current(), 6), h.current(), gen, r)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:lost", "role:ops"}) || r.DirectoryVersion != 2 {
			t.Fatalf("the refused chain changed the principals %v or the directory version %d", got, r.DirectoryVersion)
		}
		if v, err := InstalledKRLVersion(h.l); err != nil || v != h.f.krlVersion {
			t.Fatalf("installed KRL version %d (%v), want %d", v, err, h.f.krlVersion)
		}
		if len(r.Errors) == 0 {
			t.Fatal("the report does not name the directory refusal")
		}
	})
	t.Run("bundle_step_refused_krl_applied", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		// Bundle version 3 with no version 2 between: a gap.
		h.state.Bundles[3] = spool.Doc{Body: []byte(`{}`), Sigs: []byte("sigs")}
		h.publishKRL(7)
		r, err := h.apply()
		if !errors.Is(err, state.ErrBundleChainGap) {
			t.Fatalf("a bundle chain gap: %v, want bundle_chain_gap reported", err)
		}
		if !h.krlRevokes(h.l.Current(), 7) || r.BundleVersion != 1 {
			t.Fatalf("the KRL was not applied alone: revokes 7 %t, %+v", h.krlRevokes(h.l.Current(), 7), r)
		}
	})
	t.Run("krl_refused_too_changes_nothing", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		h.state.Bundles[3] = spool.Doc{Body: []byte(`{}`), Sigs: []byte("sigs")}
		v, files := h.f.krl([]uint64{8}, nil, "fedcba9876543210fedcba9876543210")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		gen := h.current()
		if _, err := h.apply(); !errors.Is(err, state.ErrBundleChainGap) || !errors.Is(err, state.ErrKRL) {
			t.Fatalf("a refused bundle and a refused KRL: %v, want both", err)
		}
		if h.current() != gen || h.krlRevokes(h.l.Current(), 8) {
			t.Fatal("a refused KRL was installed")
		}
	})
}
