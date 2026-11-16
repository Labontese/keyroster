//go:build linux

package apply

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// Seeds of the old CA keys of the draining cases (03-12c).
const (
	seedDrainOld  = 120
	seedDrainOld2 = 121
)

// drainAt is the end of the draining entry of the draining cases' first
// bundle: one hour after the fake clock's start (03-12c).
const drainAt = "2026-10-26T13:00:00Z"

// newDrainingHost is a test host whose first bundle is version 3 with the
// user role's generation 1 draining (old's key, until drainAt) and
// generation 2 active (03-12c).
func newDrainingHost(t *testing.T) (*testHost, ssh.Signer) {
	t.Helper()
	f := newFixture(t)
	h := newTestHost(t, f)
	old := seedKey(t, seedDrainOld)
	h.useBundle(3, f.withBundle(3, f.drainingCA(trust.RoleUser, old, drainAt)))
	return h, old
}

// caText is a user_ca_keys holding keys, one plain line each.
func caText(keys ...ssh.Signer) string {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(trust.FormatKey(k.PublicKey()) + "\n")
	}
	return b.String()
}

// setCurrentCA replaces current's user_ca_keys with text: a generation
// built by hand stands for current (03-12c).
func setCurrentCA(t *testing.T, h *testHost, text string) {
	t.Helper()
	setCurrentFile(t, h, CAFile, text)
}

// setCurrentFile replaces current's file name with text (PR #107 review).
func setCurrentFile(t *testing.T, h *testHost, name, text string) {
	t.Helper()
	p := filepath.Join(h.l.Current(), name)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// publishUnverifiedKRL offers the next KRL version with a manifest
// signature that does not verify: the ops key signed other bytes, so the
// capture is refused with krl_not_verified (PR #107 review).
func (h *testHost) publishUnverifiedKRL() {
	h.t.Helper()
	h.publishKRL()
	files := h.state.KRLs[h.f.krlVersion]
	sig, err := sshsig.Sign(rand.Reader, h.f.ops, krl.Namespace, []byte("not the manifest"))
	if err != nil {
		h.t.Fatal(err)
	}
	files.Sig = sig
	h.state.KRLs[h.f.krlVersion] = files
}

// verifiedOf is a verified state holding the bundle doc (03-12c).
func verifiedOf(t *testing.T, doc []byte) *state.Verified {
	t.Helper()
	b, err := trust.ParseBundle(doc)
	if err != nil {
		t.Fatal(err)
	}
	return &state.Verified{Bundle: b}
}

// TestDrainingDrop (03-12c): an agent trusts a draining CA until its end
// and then drops it on its own clock, with no new document, as a
// narrowing swap; a bundle without a draining entry renders as before.
func TestDrainingDrop(t *testing.T) {
	t.Run("draining_trusted_before_the_end", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		if got, want := h.file(CAFile), caText(old, h.f.user, h.f.mach); got != want {
			t.Fatalf("DRAIN: user_ca_keys before the end = %q, want %q", got, want)
		}
	})
	t.Run("draining_dropped_unchanged_capture", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		before := h.current()
		h.clock.advance(2 * time.Hour)
		r := h.mustApply()
		got := h.file(CAFile)
		if r.NoOp || r.Intermediate != 0 || r.WaitedMS != 0 || r.Reloaded || h.current() == before {
			t.Fatalf("DRAIN: the apply past the end: report %+v, current %d (before %d), user_ca_keys %q; want one narrowing swap", r, h.current(), before, got)
		}
		if strings.Contains(got, trust.FormatKey(old.PublicKey())) {
			t.Fatalf("DRAIN: user_ca_keys past the end still holds the draining key %s", ssh.FingerprintSHA256(old.PublicKey()))
		}
		if want := caText(h.f.user, h.f.mach); got != want {
			t.Fatalf("DRAIN: user_ca_keys past the end = %q, want %q", got, want)
		}
	})
	t.Run("render_plain_lines_only", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		got := h.file(CAFile)
		if want := caText(old, h.f.user, h.f.mach); got != want || !strings.HasSuffix(got, "\n") || strings.HasSuffix(got, "\n\n") {
			t.Fatalf("DRAIN: user_ca_keys = %q, want exactly %q", got, want)
		}
		for _, l := range lines([]byte(got)) {
			_, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(l))
			if err != nil || comment != "" || len(options) != 0 {
				t.Fatalf("DRAIN: line %q: comment %q, options %q, %v; want a plain key line", l, comment, options, err)
			}
		}
	})
	t.Run("no_draining_bytes_unchanged", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		if got, want := h.file(CAFile), caText(h.f.user, h.f.mach); got != want {
			t.Fatalf("DRAIN: user_ca_keys = %q, want %q", got, want)
		}
		if r := h.mustApply(); !r.NoOp {
			t.Fatalf("DRAIN: an unchanged capture without a draining entry: %+v, want a no-op", r)
		}
	})
	t.Run("drop_with_directory_unauthorized", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		// Bundle 4 carries the draining entry unchanged and policy 2,
		// whose only admin is bob, so the stored directory (alice's) is
		// unauthorized (F03 (03-08f)).
		b3, err := trust.ParseBundle(h.state.Bundles[3].Body)
		if err != nil {
			t.Fatal(err)
		}
		bob := seedKey(t, 11)
		_, d4, p2 := h.f.rotation(b3, h.state.Bundles[3].Body, h.f.policyDoc, h.f.policy, []trust.AdminKey{{Name: "bob", Key: trust.FormatKey(bob.PublicKey())}}, "2026-10-21T00:00:00Z")
		h.state.Bundles[4], h.state.Policies[2] = d4, p2
		if _, err := h.apply(); !errors.Is(err, state.ErrDirUnauthorized) {
			t.Fatalf("DRAIN: bundle 4: %v, want directory_not_authorized", err)
		}
		if got := h.file(CAFile); !strings.Contains(got, caText(old)) {
			t.Fatalf("DRAIN: user_ca_keys inside the window = %q, want the draining key's line", got)
		}
		h.clock.advance(2 * time.Hour)
		if _, err := h.apply(); err != nil && !errors.Is(err, state.ErrDirUnauthorized) {
			t.Fatalf("DRAIN: the apply past the end: %v", err)
		}
		if got := h.file(CAFile); got != caText(h.f.user, h.f.mach) {
			t.Fatalf("DRAIN: user_ca_keys past the end with the directory unauthorized = %q, want %q", got, caText(h.f.user, h.f.mach))
		}
		noPrincipals(t, h, "DRAIN: past the end")
	})
	t.Run("drop_survives_rollback", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		h.clock.advance(2 * time.Hour)
		h.sshd.setStall(true)
		if _, err := h.apply(); !errors.Is(err, ErrSelfTest) {
			t.Fatalf("DRAIN: the drop with a failing self-test: %v, want self_test_failed", err)
		}
		h.sshd.setStall(false)
		if got := h.file(CAFile); strings.Contains(got, caText(old)) {
			t.Fatalf("DRAIN: after the rollback user_ca_keys = %q; want the narrowing kept", got)
		}
		if b := latchFile(t, h); !strings.Contains(string(b), fp(old)) {
			t.Fatalf("DRAIN: after the rollback the latch = %q, want it to hold %s", b, fp(old))
		}
		stepWall(h.clock, -3*time.Hour)
		h.publishKRL(1)
		h.mustApply()
		if got := h.file(CAFile); strings.Contains(got, caText(old)) {
			t.Fatalf("DRAIN: with the clock stepped back user_ca_keys = %q; want the dropped key to stay out", got)
		}
	})
	t.Run("recover_to_last_good_then_drop_again", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		lg := h.current()
		h.clock.advance(2 * time.Hour)
		// The operator's recovery brings back last-good, which still holds
		// the draining key's line past its end.
		repoint(t, h.l.Current(), "gen/999")
		if _, err := h.apply(); !errors.Is(err, ErrPendingStateUnknown) {
			t.Fatalf("DRAIN: a dangling current: %v", err)
		}
		h.cfg.RecoverToLastGood = true
		if _, err := h.apply(); err != nil || h.current() != lg {
			t.Fatalf("DRAIN: recover to last-good: %v, current %d (want %d)", err, h.current(), lg)
		}
		h.cfg.RecoverToLastGood = false
		if got := h.file(CAFile); !strings.Contains(got, caText(old)) {
			t.Fatalf("DRAIN: the recovered generation's user_ca_keys = %q, want the drained key's line", got)
		}
		d, err := h.check()
		if err != nil || len(d.TrustExpired) != 1 || d.TrustExpired[0].Fingerprint != fp(old) {
			t.Fatalf("CHECK: after the recovery: %+v, %v; want trust_expired for %s", d, err, fp(old))
		}
		h.mustApply()
		if got := h.file(CAFile); got != caText(h.f.user, h.f.mach) {
			t.Fatalf("DRAIN: the next apply's user_ca_keys = %q, want %q", got, caText(h.f.user, h.f.mach))
		}
	})
}

// TestDrainingDropRefusedCapture (PR #107 review): a draining CA past its
// end leaves current's user_ca_keys even when the capture does not verify;
// the apply still returns the capture's refusal, the KRL in force and
// every other part of current stay as they are, nothing is added, and a
// refused capture with no drop due changes nothing.
func TestDrainingDropRefusedCapture(t *testing.T) {
	// refused is the apply of an unverified KRL past the draining CA's end:
	// it must return krl_not_verified and land the drop, latched and
	// committed.
	refused := func(t *testing.T, h *testHost, old ssh.Signer, want string) {
		t.Helper()
		h.clock.advance(2 * time.Hour)
		h.publishUnverifiedKRL()
		if _, err := h.apply(); !errors.Is(err, state.ErrKRL) {
			t.Fatalf("FALLBACK: the refused capture past the end: %v, want krl_not_verified", err)
		}
		if got := h.file(CAFile); got != want {
			t.Fatalf("FALLBACK: user_ca_keys after the refused capture = %q, want %q", got, want)
		}
		if b := latchFile(t, h); !strings.Contains(string(b), fp(old)) {
			t.Fatalf("FALLBACK: the latch = %q, want it to hold %s", b, fp(old))
		}
		if h.lastGood() != h.current() {
			t.Fatalf("FALLBACK: last-good %d, current %d; want the drop committed", h.lastGood(), h.current())
		}
	}
	t.Run("drop_lands_and_refusal_returned", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		before := h.current()
		krlBefore := h.file(KRLFile)
		refused(t, h, old, caText(h.f.user, h.f.mach))
		if h.current() == before || h.file(KRLFile) != krlBefore || !slices.Equal(h.principals("deploy"), []string{"role:ops"}) {
			t.Fatalf("FALLBACK: current %d (before %d), KRL changed %t, principals %v; want one narrowing swap of user_ca_keys only", h.current(), before, h.file(KRLFile) != krlBefore, h.principals("deploy"))
		}
	})
	t.Run("krl_above_accepted_kept", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		// A failed apply of KRL 1 (revoking 7) keeps it in current, above
		// accepted/'s none (PR #67 round 2).
		h.cfg.SelfTestTimeout = 300 * time.Millisecond
		h.sshd.setStall(true)
		h.publishKRL(7)
		if _, err := h.apply(); err == nil || !h.krlRevokes(h.l.Current(), 7) {
			t.Fatalf("FALLBACK: the failed apply of KRL 1: %v, current revokes 7: %t", err, h.krlRevokes(h.l.Current(), 7))
		}
		h.sshd.setStall(false)
		krlBefore := h.file(KRLFile)
		refused(t, h, old, caText(h.f.user, h.f.mach))
		if h.file(KRLFile) != krlBefore {
			t.Fatal("FALLBACK: the KRL in force changed; want current's, byte for byte")
		}
	})
	t.Run("krl_below_accepted_not_moved", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.publishKRL(7)
		h.installed("role:ops")
		// A hand-built current whose KRL is below accepted/'s: the fallback
		// moves no KRL, in either direction.
		setCurrentFile(t, h, KRLFile, "")
		refused(t, h, old, caText(h.f.user, h.f.mach))
		if got := h.file(KRLFile); got != "" {
			t.Fatalf("FALLBACK: the KRL in force became %d bytes; want current's empty one", len(got))
		}
	})
	t.Run("never_adds_a_line", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		// current lacks the machine CA's line, which the accepted bundle
		// renders: the fallback only removes.
		setCurrentCA(t, h, caText(old, h.f.user))
		refused(t, h, old, caText(h.f.user))
	})
	t.Run("unapplied_record_ahead_accepted_bundle_decides", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		// Directory 2 is above the generation caps: it is recorded as
		// unapplied, and the next capture is chained from the record.
		publishRun(h, 2, 2)
		h.publishKRL(6)
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("FALLBACK: directory 2 above the caps: %v, want generation_too_large", err)
		}
		mustRecord(t, h, 0, 2)
		refused(t, h, old, caText(h.f.user, h.f.mach))
		mustRecord(t, h, 0, 2)
		if a, err := h.accepted(); err != nil || a.DirectoryVersion != 1 || a.BundleVersion != 3 {
			t.Fatalf("FALLBACK: accepted/ %+v (%v), want bundle 3 and directory 1 unchanged", a, err)
		}
	})
	t.Run("never_adds_a_principal_line", func(t *testing.T) {
		// PR #108 review: current lacks a principal line that the accepted
		// state renders; the drop leaves it out.
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		p := filepath.Join(PrincipalsDir, "deploy")
		setCurrentFile(t, h, p, strings.ReplaceAll(h.file(p), "role:ops\n", ""))
		refused(t, h, old, caText(h.f.user, h.f.mach))
		if got := h.principals("deploy"); len(got) != 0 {
			t.Fatalf("FALLBACK: deploy's principals after the drop = %v, want none", got)
		}
	})
	t.Run("unreadable_latch_blocks_every_draining_entry", func(t *testing.T) {
		// PR #108 review: past a's end and inside b's window, a latch that
		// does not read blocks both, and the drop never overwrites it.
		f := newFixture(t)
		h := newTestHost(t, f)
		a, b := seedKey(t, seedDrainOld), seedKey(t, seedDrainOld2)
		h.useBundle(3, f.withBundle(3, twoDrainingCA(f, a, drainAt, b, "2026-10-26T14:00:00Z")))
		h.installed("role:ops")
		writeLatchFile(t, h, []byte("not json"), 0o600)
		h.clock.advance(90 * time.Minute)
		h.publishUnverifiedKRL()
		if _, err := h.apply(); !errors.Is(err, state.ErrKRL) {
			t.Fatalf("FALLBACK: the refused capture with the latch unreadable: %v, want krl_not_verified", err)
		}
		if got := h.file(CAFile); got != caText(f.user, f.mach) {
			t.Fatalf("FALLBACK: user_ca_keys = %q, want %q (both draining keys blocked)", got, caText(f.user, f.mach))
		}
		if got := latchFile(t, h); string(got) != "not json" {
			t.Fatalf("FALLBACK: the latch = %q, want the unreadable bytes left as they were", got)
		}
	})
	t.Run("capture_error_with_unapplied_record", func(t *testing.T) {
		// PR #108 review: the capture chained from an unapplied record does
		// not read at all; the drop lands and the record stays.
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		publishRun(h, 2, 2)
		if _, err := h.apply(); !errors.Is(err, ErrGenerationTooLarge) {
			t.Fatalf("FALLBACK: directory 2 above the caps: %v, want generation_too_large", err)
		}
		mustRecord(t, h, 0, 2)
		if err := os.RemoveAll(h.spool); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.spool, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		h.clock.advance(2 * time.Hour)
		if _, err := Apply(t.Context(), h.cfg, h.l); err == nil {
			t.Fatal("FALLBACK: the apply with a spool that does not read succeeded; want its error")
		}
		if got := h.file(CAFile); got != caText(h.f.user, h.f.mach) {
			t.Fatalf("FALLBACK: user_ca_keys = %q, want %q (%s dropped)", got, caText(h.f.user, h.f.mach), fp(old))
		}
		if h.lastGood() != h.current() {
			t.Fatalf("FALLBACK: last-good %d, current %d; want the drop committed", h.lastGood(), h.current())
		}
		mustRecord(t, h, 0, 2)
	})
	t.Run("touches_nothing_else", func(t *testing.T) {
		// PR #108 review: the drop writes no drop-in, no host certificate
		// and no takeover plan.
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		snap := func() string {
			var b strings.Builder
			dropIn, err := os.ReadFile(h.l.DropIn())
			if err != nil {
				t.Fatal(err)
			}
			b.Write(dropIn)
			ents, _ := os.ReadDir(h.l.HostCertDir())
			for _, e := range ents {
				c, _ := os.ReadFile(filepath.Join(h.l.HostCertDir(), e.Name()))
				b.WriteString("\n" + e.Name() + "\n" + string(c))
			}
			if _, err := os.Lstat(h.l.State(adoptFile)); !os.IsNotExist(err) {
				b.WriteString("\nadopt plan present")
			}
			return b.String()
		}
		before := snap()
		refused(t, h, old, caText(h.f.user, h.f.mach))
		if after := snap(); after != before {
			t.Fatalf("FALLBACK: the drop-in, the host certificates or the takeover plan changed:\nbefore %q\nafter  %q", before, after)
		}
	})
	t.Run("nothing_due_changes_nothing", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		before, gens := h.current(), h.genCount()
		h.publishUnverifiedKRL()
		if _, err := h.apply(); !errors.Is(err, state.ErrKRL) {
			t.Fatalf("FALLBACK: the refused capture inside the window: %v, want krl_not_verified", err)
		}
		if h.current() != before || h.genCount() != gens || !strings.Contains(h.file(CAFile), caText(old)) || latchFile(t, h) != nil {
			t.Fatalf("FALLBACK: inside the window: current %d (before %d), %d generations (before %d), user_ca_keys %q; want nothing changed", h.current(), before, h.genCount(), gens, h.file(CAFile))
		}
	})
}

// TestDrainingDropRefusedGeneration (PR #108 review): a draining CA past
// its end leaves current's user_ca_keys also when the capture verifies but
// the host refuses the generation it renders, by its KRL or by a CA line
// on a KRL-only change. The apply returns the refusal, the KRL in force
// stays current's byte for byte, no line is added, and the refused
// candidate's generation number is not used again.
func TestDrainingDropRefusedGeneration(t *testing.T) {
	// refused applies past old's end and checks that the drop landed from
	// the accepted state, with kind returned and the KRL in force kept.
	refused := func(t *testing.T, h *testHost, old ssh.Signer, kind error, wantCA string) {
		t.Helper()
		before, krlBefore := h.current(), h.file(KRLFile)
		h.clock.advance(2 * time.Hour)
		if _, err := h.apply(); !errors.Is(err, kind) {
			t.Fatalf("REFUSED: the apply past the end: %v, want %v", err, kind)
		}
		if got := h.file(CAFile); got != wantCA {
			t.Fatalf("REFUSED: user_ca_keys after the refused generation = %q, want %q", got, wantCA)
		}
		if h.file(KRLFile) != krlBefore {
			t.Fatal("REFUSED: the KRL in force changed; want current's, byte for byte")
		}
		if b := latchFile(t, h); !strings.Contains(string(b), fp(old)) {
			t.Fatalf("REFUSED: the latch = %q, want it to hold %s", b, fp(old))
		}
		if h.lastGood() != h.current() || h.current() != before+2 {
			t.Fatalf("REFUSED: current %d, last-good %d (before %d); want the drop committed as generation %d, after the refused candidate's", h.current(), h.lastGood(), before, before+2)
		}
	}
	t.Run("krl_rejected_by_keygen", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		if h.file(KRLFile) != "" {
			t.Fatal("REFUSED: the first install holds a KRL; want none, so the drop's own check queries none")
		}
		// current lacks the machine CA's line, which the accepted bundle
		// renders: the drop only removes.
		setCurrentCA(t, h, caText(old, h.f.user))
		h.run.queryCode = 255
		h.publishKRL(7)
		refused(t, h, old, ErrKRLRejected, caText(h.f.user))
	})
	t.Run("krl_drops_key_entry", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		v, files := h.f.krl(nil, []ssh.PublicKey{seedKey(t, 122).PublicKey()}, "")
		h.state.KRLs = map[uint64]spool.KRLFiles{v: files}
		h.mustApply()
		// The next KRL no longer lists the explicitly revoked key.
		h.publishKRL(7)
		refused(t, h, old, ErrKRLDropsKeyEntry, caText(h.f.user, h.f.mach))
	})
	t.Run("ca_line_rejected_on_krl_only_change", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		// The full render adds the machine CA's line back, and the host's
		// ssh-keygen refuses it; with the bundle and the directory
		// unchanged there is no KRL-alone pass.
		setCurrentCA(t, h, caText(old, h.f.user))
		machine := trust.FormatKey(h.f.mach.PublicKey())
		h.run.rejectCA = func(line string) bool { return line == machine }
		h.publishKRL(7)
		refused(t, h, old, ErrCALineRejected, caText(h.f.user))
	})
}

// TestDrainingDropWaitsForDropIn (PR #108 review): while the drop-in on
// disk is not the agent's, a due drop waits at every route, as it does at
// the preflight: a capture that does not verify, and a generation the host
// refuses. The apply returns the error, and user_ca_keys, last-good,
// dropin.prev, the drop-in and the latch stay as they were.
func TestDrainingDropWaitsForDropIn(t *testing.T) {
	waits := func(t *testing.T, h *testHost, kind error) {
		t.Helper()
		appendFile(t, h.l.DropIn(), "# managed by ansible\n")
		prev := []byte("# an earlier drop-in\n")
		if err := os.WriteFile(h.l.State(dropinPrevFile), prev, 0o600); err != nil {
			t.Fatal(err)
		}
		dropIn, ca, cur, lg := readFile(t, h.l.DropIn()), h.file(CAFile), h.current(), h.lastGood()
		h.clock.advance(2 * time.Hour)
		if _, err := h.apply(); !errors.Is(err, kind) {
			t.Fatalf("DROPIN: the apply past the end with an edited drop-in: %v, want %v", err, kind)
		}
		if got := h.file(CAFile); got != ca {
			t.Fatalf("DROPIN: user_ca_keys = %q, want %q unchanged until the drop-in is the agent's", got, ca)
		}
		if h.current() != cur || h.lastGood() != lg {
			t.Fatalf("DROPIN: current %d, last-good %d; want %d and %d unchanged", h.current(), h.lastGood(), cur, lg)
		}
		if got, err := os.ReadFile(h.l.State(dropinPrevFile)); err != nil || !bytes.Equal(got, prev) {
			t.Fatalf("DROPIN: dropin.prev = %q, %v; want %q unchanged", got, err, prev)
		}
		if got := readFile(t, h.l.DropIn()); got != dropIn {
			t.Fatalf("DROPIN: the drop-in = %q, want %q unchanged", got, dropIn)
		}
		if b := latchFile(t, h); b != nil {
			t.Fatalf("DROPIN: the latch = %q, want none written", b)
		}
	}
	t.Run("capture_not_verified", func(t *testing.T) {
		h, _ := newDrainingHost(t)
		h.installed("role:ops")
		h.publishUnverifiedKRL()
		waits(t, h, state.ErrKRL)
	})
	t.Run("generation_refused", func(t *testing.T) {
		h, _ := newDrainingHost(t)
		h.installed("role:ops")
		h.run.queryCode = 255
		h.publishKRL(7)
		waits(t, h, ErrKRLRejected)
	})
}

// stepWall steps the fake clock's wall time by d and leaves its
// monotonic clock alone: a step of the host's clock (03-12c).
func stepWall(c *fakeClock, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
}

// twoDrainingCA is a withBundle edit (03-12c): the user role becomes g1
// draining with a's key until endA, g2 draining with b's key until endB,
// and g3 active with the fixture's user key.
func twoDrainingCA(f *fixture, a ssh.Signer, endA string, b ssh.Signer, endB string) func(*trust.Bundle) {
	return func(bd *trust.Bundle) {
		f.drainingCA(trust.RoleUser, a, endA)(bd)
		second := bd.CAs[0]
		second.Key, second.Generation, second.TrustedUntil = trust.FormatKey(b.PublicKey()), 2, endB
		bd.CAs[1].Generation = 3
		bd.CAs = slices.Insert(bd.CAs, 1, second)
	}
}

// TestDrainingLatch (03-12c): a draining CA key that the agent dropped
// never comes back, through a clock step, a crash, a fresh first apply
// past the end or a directory reset; a dry run writes no latch, and an
// unreadable latch renders no draining key.
func TestDrainingLatch(t *testing.T) {
	t.Run("clock_step_back_keeps_drop", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		h.clock.advance(2 * time.Hour)
		h.mustApply()
		if got := h.file(CAFile); strings.Contains(got, caText(old)) {
			t.Fatalf("LATCH: user_ca_keys past the end = %q, want the drop", got)
		}
		stepWall(h.clock, -3*time.Hour)
		h.publishKRL(1)
		h.mustApply()
		if got := h.file(CAFile); strings.Contains(got, caText(old)) {
			t.Fatalf("LATCH: with the clock stepped back inside the window user_ca_keys = %q; want the dropped key to stay out", got)
		}
		if b := latchFile(t, h); !strings.Contains(string(b), fp(old)) {
			t.Fatalf("LATCH: the latch = %q, want it to hold %s", b, fp(old))
		}
	})
	t.Run("forward_jump_spares_later_rotation", func(t *testing.T) {
		f := newFixture(t)
		a, b := seedKey(t, seedDrainOld), seedKey(t, seedDrainOld2)
		start := newFakeClock().Now()
		endA := start.Add(30 * 24 * time.Hour).Format(trust.TimeFormat)
		endB := start.Add(10 * 24 * time.Hour).Format(trust.TimeFormat)
		v := verifiedOf(t, f.withBundle(3, twoDrainingCA(f, a, endA, b, endB)).Body)
		g, err := renderTrust(v, RenderAt{Now: start.Add(5 * 24 * time.Hour), Dropped: newLatch(false, latchKey{fp(a), endA}).Blocks})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(g.Files[CAFile]), caText(b, f.user, f.mach); got != want {
			t.Fatalf("LATCH: the render with a latched a = %q, want %q (b inside its window, a left out by key)", got, want)
		}
	})
	t.Run("latch_never_pruned", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		a, b := seedKey(t, seedDrainOld), seedKey(t, seedDrainOld2)
		h.useBundle(3, f.withBundle(3, twoDrainingCA(f, a, drainAt, b, "2026-10-26T14:00:00Z")))
		h.installed("role:ops")
		h.clock.advance(90 * time.Minute)
		h.mustApply()
		h.clock.advance(90 * time.Minute)
		h.mustApply()
		if got := h.file(CAFile); got != caText(f.user, f.mach) {
			t.Fatalf("LATCH: user_ca_keys after both ends = %q, want %q", got, caText(f.user, f.mach))
		}
		if got, want := latchFile(t, h), latchText(t, latchKey{fp(a), drainAt}, latchKey{fp(b), "2026-10-26T14:00:00Z"}); !bytes.Equal(got, want) {
			t.Fatalf("LATCH: the latch after both drops = %q, want %q", got, want)
		}
	})
	t.Run("latch_written_before_the_swap", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		h.clock.advance(2 * time.Hour)
		h.cfg.Fault = func(p string) error {
			if p == "marker" {
				return &crash{point: p}
			}
			return nil
		}
		if _, err := h.apply(); !isCrash(err) {
			t.Fatalf("LATCH: the apply past the end: %v, want the crash at the marker", err)
		}
		if b := latchFile(t, h); !strings.Contains(string(b), fp(old)) {
			t.Fatalf("LATCH: at the crash the latch = %q, want it to hold %s", b, fp(old))
		}
		h.cfg.Fault = nil
		stepWall(h.clock, -3*time.Hour)
		h.mustApply()
		if got := h.file(CAFile); strings.Contains(got, caText(old)) {
			t.Fatalf("LATCH: after the crash, with the clock stepped back, user_ca_keys = %q; want the drop", got)
		}
	})
	t.Run("fresh_agent_after_the_end_latches", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.clock.advance(2 * time.Hour)
		h.installed("role:ops")
		if got := h.file(CAFile); strings.Contains(got, caText(old)) {
			t.Fatalf("LATCH: a first apply past the end rendered the draining key: %q", got)
		}
		if b := latchFile(t, h); !strings.Contains(string(b), fp(old)) {
			t.Fatalf("LATCH: after a first apply past the end the latch = %q, want it to hold %s", b, fp(old))
		}
		stepWall(h.clock, -3*time.Hour)
		h.publishKRL(1)
		h.mustApply()
		if got := h.file(CAFile); strings.Contains(got, caText(old)) {
			t.Fatalf("LATCH: with the clock stepped back user_ca_keys = %q; want the key to stay out", got)
		}
	})
	t.Run("dry_run_writes_no_latch", func(t *testing.T) {
		h, _ := newDrainingHost(t)
		h.installed("role:ops")
		h.clock.advance(2 * time.Hour)
		h.cfg.DryRun = true
		if _, err := h.apply(); err != nil {
			t.Fatalf("LATCH: the dry run: %v", err)
		}
		if b := latchFile(t, h); b != nil {
			t.Fatalf("LATCH: a dry run wrote the latch %q", b)
		}
	})
	t.Run("latch_unreadable_fails_closed", func(t *testing.T) {
		h, _ := newDrainingHost(t)
		writeLatchFile(t, h, []byte("not json"), 0o600)
		var log syncLog
		h.cfg.Log = &log
		h.installed("role:ops")
		if got, want := h.file(CAFile), caText(h.f.user, h.f.mach); got != want {
			t.Fatalf("LATCH: with an unreadable latch user_ca_keys inside the window = %q, want %q", got, want)
		}
		if got := latchFile(t, h); string(got) != "not json" {
			t.Fatalf("LATCH: the unreadable latch became %q", got)
		}
		if !strings.Contains(log.String(), trustLatchFile+" does not read") {
			t.Fatalf("LATCH: the log does not name the unreadable latch:\n%s", log.String())
		}
	})
	t.Run("removed_latch_written_again_by_next_render", func(t *testing.T) {
		// The runbook's repair without a backup (PR #107 review): the file
		// removed with the clock correct reads as empty, an unchanged
		// capture renders nothing, and the next render latches every key
		// whose end has passed again.
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		h.clock.advance(2 * time.Hour)
		h.mustApply()
		if err := os.Remove(h.l.State(trustLatchFile)); err != nil {
			t.Fatal(err)
		}
		if r := h.mustApply(); !r.NoOp || latchFile(t, h) != nil {
			t.Fatalf("LATCH: an unchanged capture after the removal: %+v, latch %q; want a no-op that writes no latch", r, latchFile(t, h))
		}
		h.publishKRL(1)
		h.mustApply()
		if got, want := latchFile(t, h), latchText(t, latchKey{fp(old), drainAt}); !bytes.Equal(got, want) {
			t.Fatalf("LATCH: after the next render the latch = %q, want %q", got, want)
		}
		if got := h.file(CAFile); strings.Contains(got, caText(old)) {
			t.Fatalf("LATCH: user_ca_keys = %q, want the dropped key to stay out", got)
		}
	})
	t.Run("latch_survives_reset_directory", func(t *testing.T) {
		h, old := newDrainingHost(t)
		spoolInState(t, h)
		h.installed("role:ops")
		h.clock.advance(2 * time.Hour)
		h.mustApply()
		before := latchFile(t, h)
		if !strings.Contains(string(before), fp(old)) {
			t.Fatalf("LATCH: after the drop the latch = %q, want it to hold %s", before, fp(old))
		}
		if _, err := ResetDirectory(h.l, h.spool); err != nil {
			t.Fatal(err)
		}
		if got := latchFile(t, h); !bytes.Equal(got, before) {
			t.Fatalf("LATCH: reset-directory changed the latch from %q to %q", before, got)
		}
	})
}

// TestNarrowingPending (03-12c): an unchanged capture is rendered again
// only when current holds the line of a draining entry that the render at
// the engine's clock omits.
func TestNarrowingPending(t *testing.T) {
	t.Run("drained_line_in_current_is_pending", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		setCurrentCA(t, h, caText(old, h.f.user, h.f.mach))
		h.clock.advance(2 * time.Hour)
		if !h.engine().narrowingPending(verifiedOf(t, h.state.Bundles[3].Body)) {
			t.Fatal("current holds the drained key's line past the end: want a pending narrowing")
		}
	})
	t.Run("held_next_line_is_not_pending", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		old, next := seedKey(t, seedDrainOld), seedKey(t, seedDrainOld2)
		doc := f.withBundle(3, func(b *trust.Bundle) {
			f.drainingCA(trust.RoleUser, old, drainAt)(b)
			n := b.CAs[1]
			n.Key, n.State, n.Generation = trust.FormatKey(next.PublicKey()), "next", 3
			b.CAs = append(b.CAs[:2:2], append([]trust.CAEntry{n}, b.CAs[2:]...)...)
		})
		h.useBundle(3, doc)
		h.installed("role:ops")
		setCurrentCA(t, h, caText(old, f.user, f.mach))
		if h.engine().narrowingPending(verifiedOf(t, doc.Body)) {
			t.Fatal("a next line that current lacks is a pending narrowing; want none")
		}
	})
	t.Run("kept_state_of_an_aborted_key_is_not_pending", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		old, aborted := seedKey(t, seedDrainOld), seedKey(t, seedDrainOld2)
		doc := f.withBundle(3, func(b *trust.Bundle) {
			f.drainingCA(trust.RoleUser, old, drainAt)(b)
			r := b.CAs[1]
			r.Key, r.State, r.Generation = trust.FormatKey(aborted.PublicKey()), "retired", 3
			b.CAs = append(b.CAs[:2:2], append([]trust.CAEntry{r}, b.CAs[2:]...)...)
		})
		h.useBundle(3, doc)
		h.installed("role:ops")
		setCurrentCA(t, h, caText(old, f.user, aborted, f.mach))
		if h.engine().narrowingPending(verifiedOf(t, doc.Body)) {
			t.Fatal("current holds a retired entry's line: want no pending narrowing (the kept rollback state has its own path)")
		}
	})
	t.Run("bundle_without_draining_is_never_pending", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		h.installed("role:ops")
		setCurrentCA(t, h, caText(h.f.user, seedKey(t, seedDrainOld), h.f.mach))
		if h.engine().narrowingPending(verifiedOf(t, h.f.bundleDoc)) {
			t.Fatal("a bundle without a draining entry is a pending narrowing; want never")
		}
	})
	t.Run("latched_line_in_current_is_pending", func(t *testing.T) {
		h, old := newDrainingHost(t)
		h.installed("role:ops")
		// Inside the window, but the latch holds the key.
		writeLatchFile(t, h, latchText(t, latchKey{fp(old), drainAt}), 0o600)
		if !h.engine().narrowingPending(verifiedOf(t, h.state.Bundles[3].Body)) {
			t.Fatal("LATCH: current holds a latched key's line: want a pending narrowing")
		}
	})
}

// TestTrustDue (03-12c): the next end strictly after now, over the
// draining entries of every role.
func TestTrustDue(t *testing.T) {
	now := newFakeClock().Now()
	at := func(d time.Duration) string { return now.Add(d).UTC().Format(trust.TimeFormat) }
	f := newFixture(t)
	bundle := func(edit func(b *trust.Bundle)) *trust.Bundle {
		b, err := trust.ParseBundle(f.withBundle(3, edit).Body)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// twoDraining makes the user role g1 draining until e1, g2 draining
	// until e2 and g3 active.
	twoDraining := func(e1, e2 string) func(b *trust.Bundle) {
		return func(b *trust.Bundle) {
			f.drainingCA(trust.RoleUser, seedKey(t, seedDrainOld), e1)(b)
			second := b.CAs[0]
			second.Key, second.Generation, second.TrustedUntil = trust.FormatKey(seedKey(t, seedDrainOld2).PublicKey()), 2, e2
			b.CAs[1].Generation = 3
			b.CAs = append(b.CAs[:1:1], append([]trust.CAEntry{second}, b.CAs[1:]...)...)
		}
	}
	t.Run("earliest_end_after_now", func(t *testing.T) {
		if got, want := trustDue(bundle(twoDraining(at(time.Hour), at(3*time.Hour))), now), now.Add(time.Hour); !got.Equal(want) {
			t.Fatalf("trustDue = %v, want %v", got, want)
		}
	})
	t.Run("none_without_draining", func(t *testing.T) {
		if got := trustDue(f.bundle, now); !got.IsZero() {
			t.Fatalf("trustDue = %v, want the zero time", got)
		}
	})
	t.Run("an_end_at_now_is_not_due_again", func(t *testing.T) {
		if got, want := trustDue(bundle(twoDraining(at(0), at(3*time.Hour))), now), now.Add(3*time.Hour); !got.Equal(want) {
			t.Fatalf("trustDue = %v, want %v", got, want)
		}
	})
	t.Run("covers_every_role", func(t *testing.T) {
		b := bundle(f.drainingCA(trust.RoleHost, seedKey(t, seedDrainOld), at(time.Hour)))
		if got, want := trustDue(b, now), now.Add(time.Hour); !got.Equal(want) {
			t.Fatalf("trustDue with a draining host CA = %v, want %v", got, want)
		}
	})
	t.Run("failed_apply_reports_the_next_end", func(t *testing.T) {
		// PR #108 review: an apply that fails under the lock at the first
		// of two ends reports the second, not the zero time.
		g := newFixture(t)
		h := newTestHost(t, g)
		const endB = "2026-10-26T14:00:00Z"
		h.useBundle(3, g.withBundle(3, twoDrainingCA(g, seedKey(t, seedDrainOld), drainAt, seedKey(t, seedDrainOld2), endB)))
		h.installed("role:ops")
		h.clock.advance(90 * time.Minute)
		h.cfg.Fault = func(p string) error {
			if p == "marker" {
				return &crash{point: p}
			}
			return nil
		}
		r, err := h.apply()
		if !isCrash(err) {
			t.Fatalf("the apply at the first end: %v, want the crash at the marker", err)
		}
		want, perr := time.Parse(trust.TimeFormat, endB)
		if perr != nil {
			t.Fatal(perr)
		}
		if !r.TrustDue.Equal(want) {
			t.Fatalf("TrustDue after the failed apply = %v, want the second end %v", r.TrustDue, want)
		}
	})
}
