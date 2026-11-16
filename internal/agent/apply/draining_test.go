//go:build linux

package apply

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/state"
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
	p := filepath.Join(h.l.Current(), CAFile)
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
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
}
