//go:build linux

package apply

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Labontese/keyroster/internal/agent/enroll"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
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

// TestResetDirectory is the root-run re-bootstrap of owner decision D-R2
// (PR #71 review F5): on a host whose accepted directory a signer restore
// lost, keyroster-agent reset-directory drops it and the spool's directory
// files, so the next apply takes the re-made chain's newest version as a
// first install does, and nothing unsigned.
func TestResetDirectory(t *testing.T) {
	// diverged is a host that accepted directory version 2, which the
	// signer then lost and re-made; version 3 builds on the re-made 2.
	diverged := func(t *testing.T) (*testHost, spool.Doc) {
		t.Helper()
		h := newTestHost(t, newFixture(t))
		if err := os.Mkdir(h.l.Outbox(), 0o750); err != nil { //nolint:gosec // the outbox's mode
			t.Fatal(err)
		}
		h.installed("role:ops")
		h.publishDir(h.spec("role:ops", "role:lost"))
		h.mustApply()
		remade := h.f.directory(h.dirs[0].Body, h.spec("role:ops", "role:remade"))
		next := h.f.directory(remade.Body, h.spec("role:ops", "role:next"))
		h.state.Directories[3] = next
		if _, err := h.apply(); !errors.Is(err, state.ErrDir) {
			t.Fatalf("the re-made chain: %v, want directory_not_verified", err)
		}
		return h, next
	}
	t.Run("drops_the_lost_version_and_takes_the_remade_chain", func(t *testing.T) {
		t.Parallel()
		h, next := diverged(t)
		r, err := ResetDirectory(h.l, h.spool)
		if err != nil || r.Version != 2 || r.SHA256 != trust.SHA256Hex(h.dirs[1].Body) {
			t.Fatalf("reset-directory: %v, %+v", err, r)
		}
		for _, n := range []string{"directory-1.json", "directory-2.json", "directory-3.json", "directory-3.json.sigs"} {
			if !slices.Contains(r.SpoolRemoved, n) {
				t.Errorf("reset-directory left %s in the spool (removed %v)", n, r.SpoolRemoved)
			}
		}
		if a := readAccepted(t, h); a.Directory != 0 || a.Bundle != 1 {
			t.Fatalf("accepted.json after the reset: %+v, want directory 0", a)
		}
		// The fetcher then spools the server's current directory only.
		h.state.Directories = map[uint64]spool.Doc{3: next}
		r2, err := h.apply()
		if err != nil || r2.DirectoryVersion != 3 {
			t.Fatalf("the apply after the reset: %v, %+v", err, r2)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:next", "role:ops"}) {
			t.Fatalf("principals %v after the re-made chain", got)
		}
		if a := readAccepted(t, h); a.Directory != 3 {
			t.Fatalf("accepted.json after the apply: %+v", a)
		}
	})
	t.Run("an_unsigned_directory_is_still_refused", func(t *testing.T) {
		t.Parallel()
		h, next := diverged(t)
		if _, err := ResetDirectory(h.l, h.spool); err != nil {
			t.Fatal(err)
		}
		forged := next
		forged.Sigs = []byte("not a signature")
		h.state.Directories = map[uint64]spool.Doc{3: forged}
		if _, err := h.apply(); !errors.Is(err, state.ErrDir) {
			t.Fatalf("an unsigned directory after the reset: %v, want directory_not_verified", err)
		}
		if got := h.principals("deploy"); !slices.Equal(got, []string{"role:lost", "role:ops"}) {
			t.Fatalf("principals %v, want the last good ones kept", got)
		}
	})
	t.Run("refused_while_an_apply_is_unfinished", func(t *testing.T) {
		t.Parallel()
		h := newTestHost(t, newFixture(t))
		if err := os.Mkdir(h.l.Outbox(), 0o750); err != nil { //nolint:gosec // the outbox's mode
			t.Fatal(err)
		}
		h.installed("role:ops")
		h.publishDir(h.spec("role:ops", "role:web"))
		h.cfg.Fault = func(p string) error {
			if p == "self-test" {
				return &crash{point: p}
			}
			return nil
		}
		if _, err := h.apply(); !isCrash(err) {
			t.Fatalf("the crash: %v", err)
		}
		if _, err := ResetDirectory(h.l, h.spool); !errors.Is(err, ErrResetPending) {
			t.Fatalf("reset-directory over an unfinished apply: %v, want reset_apply_unfinished", err)
		}
	})
}

// readAccepted reads the outbox's accepted.json.
func readAccepted(t *testing.T, h *testHost) enroll.Accepted {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.l.Outbox(), enroll.AcceptedFile))
	if err != nil {
		t.Fatal(err)
	}
	var a enroll.Accepted
	if err := trust.DecodeStrict(b, &a); err != nil {
		t.Fatal(err)
	}
	return a
}
