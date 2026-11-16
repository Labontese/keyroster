//go:build linux

package apply

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/trust"
)

// fp is the SHA-256 fingerprint of s's public key.
func fp(s ssh.Signer) string { return ssh.FingerprintSHA256(s.PublicKey()) }

// latchText is the latch file holding keys, as the output contract of
// 03-12c spells it: canonical JSON, keys sorted by fingerprint.
func latchText(t *testing.T, keys ...latchKey) []byte {
	t.Helper()
	keys = slices.Clone(keys)
	slices.SortFunc(keys, func(a, b latchKey) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	b, err := trust.CanonicalJSON(struct {
		Version int        `json:"version"`
		Keys    []latchKey `json:"keys"`
	}{1, keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeLatchFile writes b as h's latch file with mode.
func writeLatchFile(t *testing.T, h *testHost, b []byte, mode os.FileMode) {
	t.Helper()
	p := h.l.State(trustLatchFile)
	if err := os.WriteFile(p, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// latchFile is h's latch file (nil: absent).
func latchFile(t *testing.T, h *testHost) []byte {
	t.Helper()
	b, err := os.ReadFile(h.l.State(trustLatchFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// syntheticLatch is a canonical latch of n keys with made-up SHA-256
// fingerprints of a real one's length, sorted (PR #107 review).
func syntheticLatch(t *testing.T, n int) []byte {
	t.Helper()
	keys := make([]latchKey, n)
	for i := range keys {
		keys[i] = latchKey{Fingerprint: fmt.Sprintf("SHA256:%043d", i), TrustedUntil: drainAt}
	}
	return latchText(t, keys...)
}

// latchUnderBound is the most synthetic keys whose latch is at most
// maxTrustLatch bytes; one more key, of any fingerprint, is above it.
func latchUnderBound(t *testing.T) int {
	t.Helper()
	one, two := len(syntheticLatch(t, 1)), len(syntheticLatch(t, 2))
	n := 1 + (maxTrustLatch-one)/(two-one)
	if len(syntheticLatch(t, n)) > maxTrustLatch || len(syntheticLatch(t, n+1)) <= maxTrustLatch {
		t.Fatalf("LATCH: %d synthetic keys are %d bytes and %d are %d; want the bound %d between them", n, len(syntheticLatch(t, n)), n+1, len(syntheticLatch(t, n+1)), maxTrustLatch)
	}
	return n
}

// TestLatch (03-12c): the drop latch trust-dropped.json, its fail-closed
// reader and its never-pruning record.
func TestLatch(t *testing.T) {
	past := newFakeClock().Now().Add(2 * time.Hour)
	drainEntry := func(s ssh.Signer, end string) trust.CAEntry {
		return trust.CAEntry{Role: trust.RoleUser, Key: trust.FormatKey(s.PublicKey()), State: "draining", Generation: 1, TrustedUntil: end}
	}
	t.Run("missing_file_is_empty", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		l := lockedEngine(h).readLatch()
		if l == nil || l.unreadable || l.Blocks(drainEntry(seedKey(t, seedDrainOld), drainAt)) {
			t.Fatalf("LATCH: a missing latch reads as %+v; want an empty latch that blocks nothing", l)
		}
		if latchFile(t, h) != nil {
			t.Fatal("LATCH: reading a missing latch created it")
		}
	})
	t.Run("round_trip_sorted", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		a, b := seedKey(t, seedDrainOld), seedKey(t, seedDrainOld2)
		doc := f.withBundle(3, twoDrainingCA(f, a, drainAt, b, "2026-10-26T13:30:00Z"))
		if err := lockedEngine(h).recordDropped(verifiedOf(t, doc.Body), past); err != nil {
			t.Fatalf("LATCH: record: %v", err)
		}
		want := latchText(t, latchKey{fp(a), drainAt}, latchKey{fp(b), "2026-10-26T13:30:00Z"})
		if got := latchFile(t, h); !bytes.Equal(got, want) {
			t.Fatalf("LATCH: the latch file = %q, want %q", got, want)
		}
		if st, err := os.Lstat(h.l.State(trustLatchFile)); err != nil || st.Mode().Perm() != 0o600 || !st.Mode().IsRegular() {
			t.Fatalf("LATCH: the latch file's mode: %v, %v; want a 0600 regular file", st, err)
		}
		l := lockedEngine(h).readLatch()
		if l.unreadable || !l.Blocks(drainEntry(a, drainAt)) || !l.Blocks(drainEntry(b, drainAt)) {
			t.Fatalf("LATCH: the latch read back blocks a %t, b %t (unreadable %t); want both", l.Blocks(drainEntry(a, drainAt)), l.Blocks(drainEntry(b, drainAt)), l.unreadable)
		}
	})
	t.Run("unreadable_blocks_every_draining_entry", func(t *testing.T) {
		// A readable latch holding another key: each row's file is
		// unreadable only for the reason its name gives.
		valid := latchText(t, latchKey{fp(seedKey(t, seedDrainOld2)), drainAt})
		for _, c := range []struct {
			name  string
			write func(t *testing.T, h *testHost)
		}{
			{"not_json", func(t *testing.T, h *testHost) { writeLatchFile(t, h, []byte("not json"), 0o600) }},
			{"wrong_mode", func(t *testing.T, h *testHost) { writeLatchFile(t, h, valid, 0o644) }},
			{"symlink", func(t *testing.T, h *testHost) {
				target := h.l.State("latch-target.json")
				if err := os.WriteFile(target, valid, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, h.l.State(trustLatchFile)); err != nil {
					t.Fatal(err)
				}
			}},
			{"oversize", func(t *testing.T, h *testHost) {
				// PR #107 review: canonical and parsable, so only the 64 KiB
				// bound refuses it.
				big := syntheticLatch(t, latchUnderBound(t)+1)
				if _, err := parseLatch(big); err != nil {
					t.Fatalf("LATCH: the oversize latch does not parse: %v", err)
				}
				writeLatchFile(t, h, big, 0o600)
			}},
			{"non_canonical", func(t *testing.T, h *testHost) {
				writeLatchFile(t, h, []byte("{\"version\": 1, \"keys\": []}\n"), 0o600)
			}},
			{"unknown_field", func(t *testing.T, h *testHost) {
				writeLatchFile(t, h, []byte(`{"version":1,"keys":[],"extra":1}`+"\n"), 0o600)
			}},
		} {
			h := newTestHost(t, newFixture(t))
			c.write(t, h)
			l := lockedEngine(h).readLatch()
			active := drainEntry(seedKey(t, seedDrainOld2), "")
			active.State = "active"
			if !l.Blocks(drainEntry(seedKey(t, seedDrainOld), drainAt)) || l.Blocks(active) {
				t.Errorf("LATCH: %s: blocks a draining entry %t, an active one %t; want true and false", c.name, l.Blocks(drainEntry(seedKey(t, seedDrainOld), drainAt)), l.Blocks(active))
			}
		}
	})
	t.Run("unreadable_is_never_overwritten", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		writeLatchFile(t, h, []byte("not json"), 0o600)
		doc := f.withBundle(3, f.drainingCA(trust.RoleUser, seedKey(t, seedDrainOld), drainAt))
		if err := lockedEngine(h).recordDropped(verifiedOf(t, doc.Body), past); err != nil {
			t.Fatalf("LATCH: record over an unreadable latch: %v, want nil", err)
		}
		if got := latchFile(t, h); string(got) != "not json" {
			t.Fatalf("LATCH: an unreadable latch became %q; want it untouched", got)
		}
	})
	t.Run("blocks_by_key_not_by_end", func(t *testing.T) {
		a, b := seedKey(t, seedDrainOld), seedKey(t, seedDrainOld2)
		l := newLatch(false, latchKey{fp(a), drainAt})
		if !l.Blocks(drainEntry(a, drainAt)) || !l.Blocks(drainEntry(a, "2026-11-26T13:00:00Z")) {
			t.Fatal("LATCH: the latch holds key a and does not block it")
		}
		if l.Blocks(drainEntry(b, drainAt)) || l.Blocks(drainEntry(b, "2026-10-26T12:30:00Z")) {
			t.Fatal("LATCH: the latch blocks key b, which it does not hold, by its end")
		}
	})
	t.Run("record_adds_and_keeps", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		a, b := seedKey(t, seedDrainOld), seedKey(t, seedDrainOld2)
		for _, k := range []ssh.Signer{a, b} {
			doc := f.withBundle(3, f.drainingCA(trust.RoleUser, k, drainAt))
			if err := lockedEngine(h).recordDropped(verifiedOf(t, doc.Body), past); err != nil {
				t.Fatalf("LATCH: record %s: %v", fp(k), err)
			}
		}
		if got, want := latchFile(t, h), latchText(t, latchKey{fp(a), drainAt}, latchKey{fp(b), drainAt}); !bytes.Equal(got, want) {
			t.Fatalf("LATCH: after two records the latch = %q, want %q", got, want)
		}
	})
	t.Run("record_skips_when_nothing_new", func(t *testing.T) {
		f := newFixture(t)
		h := newTestHost(t, f)
		a := seedKey(t, seedDrainOld)
		want := latchText(t, latchKey{fp(a), drainAt})
		writeLatchFile(t, h, want, 0o600)
		old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		if err := os.Chtimes(h.l.State(trustLatchFile), old, old); err != nil {
			t.Fatal(err)
		}
		doc := f.withBundle(3, f.drainingCA(trust.RoleUser, a, drainAt))
		if err := lockedEngine(h).recordDropped(verifiedOf(t, doc.Body), past); err != nil {
			t.Fatalf("LATCH: record: %v", err)
		}
		st, err := os.Stat(h.l.State(trustLatchFile))
		if err != nil || !st.ModTime().Equal(old) || !bytes.Equal(latchFile(t, h), want) {
			t.Fatalf("LATCH: a record with nothing new rewrote the latch: %v, %v", st, err)
		}
	})
	t.Run("record_refuses_above_the_bound", func(t *testing.T) {
		// PR #107 review: a record that would take the latch above 64 KiB
		// fails, and the latch stays as it was.
		f := newFixture(t)
		h := newTestHost(t, f)
		full := syntheticLatch(t, latchUnderBound(t))
		writeLatchFile(t, h, full, 0o600)
		doc := f.withBundle(3, f.drainingCA(trust.RoleUser, seedKey(t, seedDrainOld), drainAt))
		if err := lockedEngine(h).recordDropped(verifiedOf(t, doc.Body), past); err == nil || !strings.Contains(err.Error(), "above 65536") {
			t.Fatalf("LATCH: a record above the bound: %v, want the refusal", err)
		}
		if got := latchFile(t, h); !bytes.Equal(got, full) {
			t.Fatalf("LATCH: the refused record changed the latch to %d bytes", len(got))
		}
	})
	t.Run("path_is_allowed", func(t *testing.T) {
		h := newTestHost(t, newFixture(t))
		if err := paths.Allowed(h.l, h.l.State(trustLatchFile)); err != nil {
			t.Fatalf("LATCH: paths.Allowed refuses the latch: %v", err)
		}
	})
}
