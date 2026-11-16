//go:build linux

package apply

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/trust"
)

// behindHost is a test host with an outbox whose first apply accepted the
// fixture's version 1 bundle (03-12c).
func behindHost(t *testing.T) *testHost {
	t.Helper()
	h := newTestHost(t, newFixture(t))
	withOutbox(t, h)
	h.installed("role:ops")
	return h
}

// behindRecord is <state>/bundle-behind.json, nil when absent.
func behindRecord(t *testing.T, h *testHost) []byte {
	t.Helper()
	b, err := os.ReadFile(h.l.State("bundle-behind.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sawManifest offers a KRL whose manifest names bundle and applies it,
// and returns the clock before and after the apply: the first sight of
// the newer bundle lies between them.
func sawManifest(t *testing.T, h *testHost, bundle uint64) (time.Time, time.Time) {
	t.Helper()
	before := h.clock.Now()
	h.publishKRLNaming(bundle)
	h.mustApply()
	return before, h.clock.Now()
}

// TestBehind (03-12c): bundle_behind is reported once the accepted KRL
// manifest has named a newer bundle than the accepted one for 2 hours,
// keeps its first-sight time, says why, goes once the bundle is accepted,
// and check reads it without writing anything. The old key stays: this is
// detection.
func TestBehind(t *testing.T) {
	t.Run("withheld_switch_bundle_behind_reported", func(t *testing.T) {
		h := behindHost(t)
		before, after := sawManifest(t, h, 2)
		if s := outboxStatus(t, h); s.BundleBehind != nil {
			t.Fatalf("BEHIND: the status written by the apply that first saw the manifest carries %+v, want none in the grace", s.BundleBehind)
		}
		h.clock.advance(3 * time.Hour)
		s := writeStatus(t, h, StatusUpdate{})
		b := s.BundleBehind
		if b == nil || b.ManifestBundleVersion != 2 || b.AcceptedVersion != 1 || b.Reason != "not_delivered" {
			t.Fatalf("BEHIND: 3 hours after the manifest named bundle 2: %+v, want {2 1 <first sight> not_delivered}", b)
		}
		since, err := time.Parse(time.RFC3339, b.Since)
		if err != nil || since.Before(before.Truncate(time.Second)) || since.After(after) {
			t.Fatalf("BEHIND: since %q (%v), want the first sight, between %s and %s", b.Since, err, before, after)
		}
		if !strings.Contains(h.file(CAFile), trust.FormatKey(h.f.user.PublicKey())) {
			t.Fatalf("BEHIND: user_ca_keys lost the old key:\n%s", h.file(CAFile))
		}
		if fi, err := os.Stat(h.l.State("bundle-behind.json")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("BEHIND: bundle-behind.json: %v %v, want a 0600 file", fi, err)
		}
		if err := heartbeat.Validate(s); err != nil {
			t.Fatalf("BEHIND: the status does not pass the server's checks: %v", err)
		}
	})
	t.Run("behind_within_grace_quiet", func(t *testing.T) {
		// The first sight is at or after before (whole seconds), so at
		// before + 2 h - 1 s at most 1 h 59 min 59 s have passed.
		h := behindHost(t)
		before, _ := sawManifest(t, h, 2)
		at := before.Truncate(time.Second).Add(2*time.Hour - time.Second)
		if now := h.clock.Now(); now.After(at) {
			t.Fatalf("BEHIND: the apply moved the clock to %s, past %s: the case needs a quick apply", now, at)
		}
		h.clock.advance(at.Sub(h.clock.Now()))
		if s := writeStatus(t, h, StatusUpdate{}); s.BundleBehind != nil {
			t.Fatalf("BEHIND: 1 h 59 min 59 s after the first sight: %+v, want none", s.BundleBehind)
		}
	})
	t.Run("behind_since_is_kept", func(t *testing.T) {
		h := behindHost(t)
		sawManifest(t, h, 2)
		h.clock.advance(3 * time.Hour)
		first := writeStatus(t, h, StatusUpdate{}).BundleBehind
		h.clock.advance(time.Hour)
		second := writeStatus(t, h, StatusUpdate{}).BundleBehind
		if first == nil || second == nil || second.Since != first.Since {
			t.Fatalf("BEHIND: an hour later: %+v, then %+v, want the same since", first, second)
		}
		// A still newer version named later keeps the since time.
		sawManifest(t, h, 3)
		third := writeStatus(t, h, StatusUpdate{}).BundleBehind
		if third == nil || third.ManifestBundleVersion != 3 || third.Since != first.Since {
			t.Fatalf("BEHIND: after a manifest naming bundle 3: %+v, want version 3 with since %s", third, first.Since)
		}
	})
	t.Run("behind_clears_when_accepted", func(t *testing.T) {
		h := behindHost(t)
		sawManifest(t, h, 2)
		h.clock.advance(3 * time.Hour)
		if s := writeStatus(t, h, StatusUpdate{}); s.BundleBehind == nil || behindRecord(t, h) == nil {
			t.Fatalf("BEHIND: before bundle 2 arrives: %+v, record %q, want both", s.BundleBehind, behindRecord(t, h))
		}
		for v, d := range h.f.roleNextChain(trust.RoleUser, seedKey(t, 30), false) {
			h.state.Bundles[v] = d
		}
		h.mustApply()
		if a, err := h.accepted(); err != nil || a.BundleVersion != 2 {
			t.Fatalf("BEHIND: accepted/ %+v (%v), want bundle 2", a, err)
		}
		if s := outboxStatus(t, h); s.BundleBehind != nil {
			t.Fatalf("BEHIND: with bundle 2 accepted: %+v, want none", s.BundleBehind)
		}
		if b := behindRecord(t, h); b != nil {
			t.Fatalf("BEHIND: with bundle 2 accepted the record stays: %q", b)
		}
	})
	t.Run("behind_future_since_restarts_grace", func(t *testing.T) {
		// PR #107 review: a since after now (the clock was ahead at the
		// first sight and was then set right) only restarts the grace.
		h := behindHost(t)
		sawManifest(t, h, 2)
		ahead := h.clock.Now().Add(24 * time.Hour).UTC().Truncate(time.Second).Format(trust.TimeFormat)
		if err := os.WriteFile(h.l.State("bundle-behind.json"), mustCanonical(t, behindDoc{ManifestBundleVersion: 2, Since: ahead}), 0o600); err != nil {
			t.Fatal(err)
		}
		if rec, err := h.engine().readBehind(); err != nil || rec == nil || rec.Since != ahead {
			t.Fatalf("BEHIND: the record a day ahead does not read: %+v, %v", rec, err)
		}
		restart := h.clock.Now().UTC().Truncate(time.Second)
		writeStatus(t, h, StatusUpdate{})
		h.clock.advance(3 * time.Hour)
		b := writeStatus(t, h, StatusUpdate{}).BundleBehind
		if b == nil || b.Since != restart.Format(trust.TimeFormat) {
			t.Fatalf("BEHIND: 3 hours after a since a day ahead: %+v, want bundle_behind with since %s", b, restart.Format(trust.TimeFormat))
		}
		if rec := string(behindRecord(t, h)); strings.Contains(rec, ahead) {
			t.Fatalf("BEHIND: the record still holds the since a day ahead: %s", rec)
		}
	})
	t.Run("behind_reason_unapplied", func(t *testing.T) {
		// Bundle 2 verifies but a CA line ssh-keygen refuses keeps it from
		// applying, as krlsigner_test.go's ca_line_rejected cases arrange.
		h := behindHost(t)
		sawManifest(t, h, 2)
		rejected := seedKey(t, 31)
		_, d2 := h.f.successorNextUnder(h.f.bundle, h.f.bundleDoc, h.f.policyDoc, "2026-10-02T00:00:00Z", rejected)
		h.state.Bundles[2] = d2
		line := trust.FormatKey(rejected.PublicKey())
		h.run.rejectCA = func(l string) bool { return l == line }
		if _, err := h.apply(); !errors.Is(err, ErrCALineRejected) {
			t.Fatalf("BEHIND: the apply of bundle 2: %v, want ca_line_rejected", err)
		}
		mustRecord(t, h, 2, 0)
		h.clock.advance(3 * time.Hour)
		s := writeStatus(t, h, StatusUpdate{})
		if s.BundleBehind == nil || s.BundleBehind.Reason != "unapplied" || s.Unapplied == nil {
			t.Fatalf("BEHIND: bundle 2 verified and not applicable: %+v (unapplied %+v), want reason unapplied", s.BundleBehind, s.Unapplied)
		}
	})
	t.Run("behind_reason_not_accepted", func(t *testing.T) {
		// The spool holds bundle 2 and its signatures, signed by a key the
		// host does not pin: this build refuses it.
		h := behindHost(t)
		sawManifest(t, h, 2)
		_, d2 := h.f.successorNextUnder(h.f.bundle, h.f.bundleDoc, h.f.policyDoc, "2026-10-02T00:00:00Z", seedKey(t, 32))
		sig, err := sshsig.Sign(rand.Reader, seedKey(t, 33), trust.NamespaceBundle, d2.Body)
		if err != nil {
			t.Fatal(err)
		}
		h.state.Bundles[2] = spool.Doc{Body: d2.Body, Sigs: sig}
		_, _ = h.apply()
		if a, err := h.accepted(); err != nil || a.BundleVersion != 1 {
			t.Fatalf("BEHIND: accepted/ %+v (%v), want bundle 1 kept", a, err)
		}
		h.clock.advance(3 * time.Hour)
		if s := writeStatus(t, h, StatusUpdate{}); s.BundleBehind == nil || s.BundleBehind.Reason != "not_accepted" {
			t.Fatalf("BEHIND: bundle 2 in the spool and refused: %+v, want reason not_accepted", s.BundleBehind)
		}
	})
	t.Run("behind_older_manifest_quiet", func(t *testing.T) {
		// A manifest naming the accepted version, and one naming a version
		// below it (a host whose first bundle is version 3).
		h := behindHost(t)
		sawManifest(t, h, 1)
		h.clock.advance(3 * time.Hour)
		if s := writeStatus(t, h, StatusUpdate{}); s.BundleBehind != nil || behindRecord(t, h) != nil {
			t.Fatalf("BEHIND: a manifest naming the accepted bundle: %+v, record %q, want neither", s.BundleBehind, behindRecord(t, h))
		}
		g := newTestHost(t, newFixture(t))
		withOutbox(t, g)
		g.useBundle(3, g.f.withBundle(3, nil))
		g.installed("role:ops")
		sawManifest(t, g, 2)
		g.clock.advance(3 * time.Hour)
		if s := writeStatus(t, g, StatusUpdate{}); s.BundleBehind != nil || behindRecord(t, g) != nil {
			t.Fatalf("BEHIND: a manifest naming bundle 2 below the accepted 3: %+v, record %q, want neither", s.BundleBehind, behindRecord(t, g))
		}
	})
	t.Run("krl_stale_and_behind", func(t *testing.T) {
		// The fixture's manifests are issued 2026-10-01, so on the fake
		// clock the KRL is stale too: both are set in one status.
		h := behindHost(t)
		sawManifest(t, h, 2)
		h.clock.advance(3 * time.Hour)
		if s := writeStatus(t, h, StatusUpdate{}); !s.KRLStale || s.BundleBehind == nil {
			t.Fatalf("BEHIND: krl_stale %v, bundle_behind %+v, want both", s.KRLStale, s.BundleBehind)
		}
	})
	t.Run("check_reports_behind_read_only", func(t *testing.T) {
		h := behindHost(t)
		sawManifest(t, h, 2)
		h.clock.advance(3 * time.Hour)
		want := writeStatus(t, h, StatusUpdate{}).BundleBehind
		before := stateListing(t, h)
		rec := behindRecord(t, h)
		d, err := h.check()
		if err != nil {
			t.Fatalf("BEHIND: check: %v", err)
		}
		if want == nil || d.BundleBehind == nil || *d.BundleBehind != *want {
			t.Fatalf("BEHIND: check reports %+v, the status %+v, want the same object", d.BundleBehind, want)
		}
		if after := stateListing(t, h); !slices.Equal(before, after) || string(behindRecord(t, h)) != string(rec) {
			t.Fatalf("BEHIND: check changed the state directory:\nbefore %q\nafter  %q", before, after)
		}
		// With no spool configured, as the check command runs, the reason
		// is unknown.
		cfg := h.cfg
		cfg.Spool = ""
		d, err = Check(context.Background(), cfg, h.l)
		if err != nil {
			t.Fatalf("BEHIND: check without a spool: %v", err)
		}
		if d.BundleBehind == nil || d.BundleBehind.Reason != "unknown" || d.BundleBehind.Since != want.Since {
			t.Fatalf("BEHIND: check without a spool reports %+v, want reason unknown with since %s", d.BundleBehind, want.Since)
		}
	})
}
