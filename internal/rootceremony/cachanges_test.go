package rootceremony

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// seededKey is the Ed25519 public key of seed byte n repeated, with its
// SHA256 fingerprint.
func seededKey(t *testing.T, n byte) (string, string) {
	t.Helper()
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(pub), ssh.FingerprintSHA256(pub)
}

// caPairs is the genesis vector bundle and a copy of it whose CA entries
// edit changes.
func caPairs(t *testing.T, edit func(prev, next *trust.Bundle)) (*trust.Bundle, *trust.Bundle) {
	t.Helper()
	prev, err := trust.ParseBundle(readVector(t, "bundle_genesis_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	next := *prev
	next.CAs = slices.Clone(prev.CAs)
	next.Root.Keys = slices.Clone(prev.Root.Keys)
	if edit != nil {
		edit(prev, &next)
	}
	return prev, &next
}

func seededCA(t *testing.T, role string, n byte, state string, gen uint32) (trust.CAEntry, string) {
	t.Helper()
	key, fp := seededKey(t, n)
	return trust.CAEntry{Role: role, Key: key, Alg: ssh.KeyAlgoED25519, Custody: "software", State: state, Generation: gen}, fp
}

// switchIssuedAt is the issued_at of the switch successors of TestCAChanges
// (03-12e2).
const switchIssuedAt = "2026-10-07T00:00:00Z"

// switchPair is prev, the genesis vector with the user CA generation 2 (seed
// 40) added as next, and next, issued at switchIssuedAt, in which
// generation 1 is draining until until and generation 2 is active: the
// switch of the user CA (03-12e2). It returns the fingerprints of
// generations 1 and 2.
func switchPair(t *testing.T, until string) (*trust.Bundle, *trust.Bundle, string, string) {
	t.Helper()
	add, fp2 := seededCA(t, trust.RoleUser, 40, "next", 2)
	prev, next := caPairs(t, func(prev, next *trust.Bundle) {
		prev.CAs = slices.Insert(prev.CAs, 1, add)
		next.CAs = slices.Clone(prev.CAs)
		next.IssuedAt = switchIssuedAt
		next.CAs[0].State, next.CAs[0].TrustedUntil = "draining", until
		next.CAs[1].State = "active"
	})
	if prev.CAs[0].Role != trust.RoleUser || prev.CAs[0].Generation != 1 || prev.CAs[0].State != "active" {
		t.Fatalf("the vector's first CA entry is %+v, not the active user CA generation 1", prev.CAs[0])
	}
	fp1, _ := describe(prev.CAs[0].Key)
	return prev, next, fp1, fp2
}

// userPolicy is a policy whose only CA profile is the user's, with maximum
// TTL ttl (03-12e2).
func userPolicy(ttl time.Duration) *trust.Policy {
	return &trust.Policy{CAProfiles: []trust.CAProfile{{Role: trust.RoleUser, MaxTTLSeconds: uint64(ttl / time.Second)}}} //nolint:gosec // G115: a positive test TTL
}

// afterIssue is switchIssuedAt plus d, in trust.TimeFormat (03-12e2).
func afterIssue(t *testing.T, d time.Duration) string {
	t.Helper()
	at, err := time.Parse(trust.TimeFormat, switchIssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	return at.Add(d).UTC().Format(trust.TimeFormat)
}

// TestCAChanges (03-12b): the CA-change section of a successor.
func TestCAChanges(t *testing.T) {
	t.Run("unchanged", func(t *testing.T) {
		prev, next := caPairs(t, nil)
		if got := CAChanges(prev, next, nil, nil); got != "CA entries: unchanged\n" {
			t.Fatalf("CAChanges = %q", got)
		}
	})
	t.Run("added_next", func(t *testing.T) {
		add, fp := seededCA(t, trust.RoleUser, 40, "next", 2)
		prev, next := caPairs(t, func(_, next *trust.Bundle) { next.CAs = slices.Insert(next.CAs, 1, add) })
		if got, want := CAChanges(prev, next, nil, nil), "CA user gen 2 "+fp+": none -> next\n"; got != want {
			t.Fatalf("CAChanges = %q, want %q", got, want)
		}
	})
	t.Run("aborted", func(t *testing.T) {
		e, fp := seededCA(t, trust.RoleUser, 40, "next", 2)
		prev, next := caPairs(t, func(prev, next *trust.Bundle) {
			prev.CAs = slices.Insert(prev.CAs, 1, e)
			e.State = "retired"
			next.CAs = slices.Insert(next.CAs, 1, e)
		})
		if got, want := CAChanges(prev, next, nil, nil), "CA user gen 2 "+fp+": next -> retired\n"; got != want {
			t.Fatalf("CAChanges = %q, want %q", got, want)
		}
	})
	t.Run("two_roles", func(t *testing.T) {
		u, ufp := seededCA(t, trust.RoleUser, 40, "next", 2)
		h, hfp := seededCA(t, trust.RoleHost, 41, "next", 2)
		prev, next := caPairs(t, func(_, next *trust.Bundle) {
			next.CAs = slices.Insert(next.CAs, 2, h)
			next.CAs = slices.Insert(next.CAs, 1, u)
		})
		want := "CA user gen 2 " + ufp + ": none -> next\nCA host gen 2 " + hfp + ": none -> next\n"
		if got := CAChanges(prev, next, nil, nil); got != want {
			t.Fatalf("CAChanges = %q, want %q", got, want)
		}
	})
	t.Run("removed_shown", func(t *testing.T) {
		e, fp := seededCA(t, trust.RoleUser, 40, "retired", 2)
		prev, next := caPairs(t, func(prev, _ *trust.Bundle) { prev.CAs = slices.Insert(prev.CAs, 1, e) })
		if got, want := CAChanges(prev, next, nil, nil), "CA user gen 2 "+fp+": retired -> removed\n"; got != want {
			t.Fatalf("CAChanges = %q, want %q", got, want)
		}
	})
	t.Run("order_by_role_then_generation", func(t *testing.T) {
		// Listed out of order in next: the section follows role, then
		// generation, whatever order the entries come in.
		m3, mfp := seededCA(t, trust.RoleMachine, 42, "next", 3)
		u5, u5fp := seededCA(t, trust.RoleUser, 43, "next", 5)
		u2, u2fp := seededCA(t, trust.RoleUser, 44, "next", 2)
		prev, next := caPairs(t, func(_, next *trust.Bundle) { next.CAs = append([]trust.CAEntry{m3, u5}, append(next.CAs, u2)...) })
		want := "CA user gen 2 " + u2fp + ": none -> next\nCA user gen 5 " + u5fp + ": none -> next\nCA machine gen 3 " + mfp + ": none -> next\n"
		if got := CAChanges(prev, next, nil, nil); got != want {
			t.Fatalf("CAChanges = %q, want %q", got, want)
		}
	})

	// The switch (03-12e2): the old key's line names its trusted_until
	// and the advised install time, issued_at plus the allowance, where
	// the allowance is trusted_until minus the floor (issued_at plus the
	// larger maximum TTL plus 300 s).
	const margin = 300 * time.Second
	t.Run("switch_lines", func(t *testing.T) {
		prev, next, fp1, fp2 := switchPair(t, afterIssue(t, time.Hour+margin+24*time.Hour))
		want := "CA user gen 1 " + fp1 + ": active -> draining, trusted until 2026-10-08T01:05:00Z; install by 2026-10-08T00:00:00Z (advice)\n" +
			"CA user gen 2 " + fp2 + ": next -> active\n"
		if got := CAChanges(prev, next, userPolicy(time.Hour), userPolicy(time.Hour)); got != want {
			t.Fatalf("CAChanges = %q, want %q", got, want)
		}
	})
	t.Run("install_by_is_issued_at_plus_allowance", func(t *testing.T) {
		const allowance = 90 * time.Second
		for _, ttl := range []struct{ prev, next time.Duration }{
			{time.Hour, time.Hour},
			{time.Hour, 12 * time.Hour},
			{12 * time.Hour, 10 * time.Minute},
		} {
			until := afterIssue(t, max(ttl.prev, ttl.next)+margin+allowance)
			prev, next, fp1, _ := switchPair(t, until)
			want := "CA user gen 1 " + fp1 + ": active -> draining, trusted until " + until + "; install by 2026-10-07T00:01:30Z (advice)\n"
			if got := CAChanges(prev, next, userPolicy(ttl.prev), userPolicy(ttl.next)); !strings.HasPrefix(got, want) {
				t.Fatalf("CAChanges with maximum TTLs %s and %s = %q, want it to start with %q", ttl.prev, ttl.next, got, want)
			}
		}
	})
	t.Run("switch_without_policies_says_so", func(t *testing.T) {
		until := afterIssue(t, time.Hour+margin+time.Hour)
		host := &trust.Policy{CAProfiles: []trust.CAProfile{{Role: trust.RoleHost, MaxTTLSeconds: 3600}}}
		for _, tc := range []struct {
			name             string
			prevPol, nextPol *trust.Policy
		}{
			{"no policies", nil, nil},
			{"no previous policy", nil, userPolicy(time.Hour)},
			{"no successor policy", userPolicy(time.Hour), nil},
			{"no user profile", host, userPolicy(time.Hour)},
			{"trusted_until below the floor", userPolicy(3 * time.Hour), userPolicy(time.Hour)},
		} {
			prev, next, fp1, fp2 := switchPair(t, until)
			want := "CA user gen 1 " + fp1 + ": active -> draining, trusted until " + until + "; install by unknown (advice)\n" +
				"CA user gen 2 " + fp2 + ": next -> active\n"
			if got := CAChanges(prev, next, tc.prevPol, tc.nextPol); got != want {
				t.Fatalf("%s: CAChanges = %q, want %q", tc.name, got, want)
			}
		}
	})
	t.Run("allowance_above_cap_says_so", func(t *testing.T) {
		// A hand-built successor: the chain rule bounds trusted_until
		// only from below, so the section says that the signer refuses
		// it, and still refuses nothing itself.
		prev, next, fp1, _ := switchPair(t, afterIssue(t, time.Hour+margin+trust.MaxDrainAllowance+time.Second))
		want := "CA user gen 1 " + fp1 + ": active -> draining, trusted until 2026-10-14T01:05:01Z; install by unknown (advice: the allowance 168h0m1s is above the cap of 168h0m0s, so the signer refuses this switch)\n"
		if got := CAChanges(prev, next, userPolicy(time.Hour), userPolicy(time.Hour)); !strings.HasPrefix(got, want) {
			t.Fatalf("CAChanges above the cap = %q, want it to start with %q", got, want)
		}
		// At the cap the advice is the normal one.
		prev, next, fp1, _ = switchPair(t, afterIssue(t, time.Hour+margin+trust.MaxDrainAllowance))
		want = "CA user gen 1 " + fp1 + ": active -> draining, trusted until 2026-10-14T01:05:00Z; install by 2026-10-14T00:00:00Z (advice)\n"
		if got := CAChanges(prev, next, userPolicy(time.Hour), userPolicy(time.Hour)); !strings.HasPrefix(got, want) {
			t.Fatalf("CAChanges at the cap = %q, want it to start with %q", got, want)
		}
	})
}

// TestRootSetLine (03-12b): the root-set line compares root keys only, in
// any order.
func TestRootSetLine(t *testing.T) {
	key := func(n byte) trust.RootKey {
		k, _ := seededKey(t, n)
		return trust.RootKey{Key: k, Custody: "software"}
	}
	t.Run("unchanged", func(t *testing.T) {
		prev, next := caPairs(t, nil)
		if got := RootSetLine(prev, next); got != "Root set: unchanged\n" {
			t.Fatalf("RootSetLine = %q", got)
		}
		prev, next = caPairs(t, func(_, next *trust.Bundle) { slices.Reverse(next.Root.Keys) })
		if len(next.Root.Keys) < 2 {
			t.Fatal("the vector has fewer than two roots")
		}
		if got := RootSetLine(prev, next); got != "Root set: unchanged\n" {
			t.Fatalf("RootSetLine with the roots in another order = %q", got)
		}
	})
	t.Run("added_and_removed_counts", func(t *testing.T) {
		prev, next := caPairs(t, func(_, next *trust.Bundle) { next.Root.Keys = []trust.RootKey{key(50)} })
		if got := RootSetLine(prev, next); got != "Root set: CHANGED (added 1, removed 2)\n" {
			t.Fatalf("RootSetLine = %q", got)
		}
	})
	t.Run("swapped_root_changed", func(t *testing.T) {
		prev, next := caPairs(t, func(_, next *trust.Bundle) { next.Root.Keys[1] = key(51) })
		if got := RootSetLine(prev, next); got != "Root set: CHANGED (added 1, removed 1)\n" {
			t.Fatalf("RootSetLine = %q", got)
		}
	})
	t.Run("threshold_only_is_unchanged", func(t *testing.T) {
		// The threshold shows in Summary's Root keys line, not here (03-12b).
		prev, next := caPairs(t, func(_, next *trust.Bundle) { next.Root.Threshold++ })
		if got := RootSetLine(prev, next); got != "Root set: unchanged\n" {
			t.Fatalf("RootSetLine = %q", got)
		}
	})
}
