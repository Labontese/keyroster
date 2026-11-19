package rootceremony

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"testing"

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
