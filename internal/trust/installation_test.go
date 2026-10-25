package trust

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallationIDFormat (D-04, random-128): every bundle under
// test/vectors (all from before Phase 3, none with an installation ID)
// parses and re-encodes byte-identically; an explicit empty
// installation_id is refused as non-canonical; a malformed ID is refused;
// NewInstallationID draws IDs of the one valid form.
func TestInstallationIDFormat(t *testing.T) {
	t.Run("pre_phase3_bundles_unchanged", func(t *testing.T) {
		files, err := filepath.Glob(filepath.Join("..", "..", "test", "vectors", "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		bundles := 0
		for _, f := range files {
			data, err := os.ReadFile(f) //nolint:gosec // G304: a test vector
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte(`"ops_key"`)) {
				continue // not a bundle
			}
			bundles++
			b, err := ParseBundle(data)
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			again, err := b.Canonical()
			if err != nil || !bytes.Equal(again, data) || b.InstallationID != "" {
				t.Fatalf("%s re-encodes differently (or carries an installation ID %q)", f, b.InstallationID)
			}
		}
		if bundles == 0 {
			t.Fatal("no bundle under test/vectors")
		}
	})
	_, golden := goldenDocs(t)
	withID := func(t *testing.T, id string) []byte {
		t.Helper()
		return append(bytes.Clone(bytes.TrimSuffix(golden, []byte("}\n"))), []byte(`,"installation_id":"`+id+`"}`+"\n")...)
	}
	t.Run("explicit_empty_refused", func(t *testing.T) {
		if _, err := ParseBundle(withID(t, "")); !errors.Is(err, ErrNotCanonical) {
			t.Fatalf(`"installation_id":"": %v, want ErrNotCanonical`, err)
		}
	})
	t.Run("valid_id_accepted", func(t *testing.T) {
		b, err := ParseBundle(withID(t, "0123456789abcdef0123456789abcdef"))
		if err != nil || b.InstallationID != "0123456789abcdef0123456789abcdef" {
			t.Fatalf("a valid installation ID: %+v, %v", b, err)
		}
	})
	for name, id := range map[string]string{
		"uppercase":  "0123456789ABCDEF0123456789abcdef",
		"31_digits":  "0123456789abcdef0123456789abcde",
		"33_digits":  "0123456789abcdef0123456789abcdef0",
		"non_hex":    "0123456789abcdef0123456789abcdeg",
		"uuid_style": "01234567-89ab-cdef-0123-456789abcdef",
	} {
		t.Run("malformed_"+name+"_refused", func(t *testing.T) {
			if _, err := ParseBundle(withID(t, id)); !errors.Is(err, ErrInvalid) {
				t.Fatalf("installation ID %q: %v, want ErrInvalid", id, err)
			}
		})
	}
	t.Run("new_installation_id", func(t *testing.T) {
		a, err := NewInstallationID()
		if err != nil {
			t.Fatal(err)
		}
		b, err := NewInstallationID()
		if err != nil {
			t.Fatal(err)
		}
		if !IsInstallationID(a) || !IsInstallationID(b) || a == b {
			t.Fatalf("NewInstallationID = %q, %q", a, b)
		}
	})
}

// TestInstallationIDSuccessor (D-04): a successor keeps the previous
// bundle's installation ID, or adds one to an ID-less chain; changing or
// dropping it is ErrVersionChain, for the builder and the verifier alike.
func TestInstallationIDSuccessor(t *testing.T) {
	const (
		id    = "00112233445566778899aabbccddeeff"
		other = "ffeeddccbbaa99887766554433221100"
	)
	r := newRotation(t)
	prevWithID := *r.prev
	prevWithID.InstallationID = id
	prevWithIDBytes := mustCanonical(t, &prevWithID)
	for _, tc := range []struct {
		name      string
		prev      *Bundle
		prevBytes []byte
		next      string
		wantErr   bool
	}{
		{"keeps_id", &prevWithID, prevWithIDBytes, id, false},
		{"adds_id_to_idless_chain", r.prev, r.prevBytes, id, false},
		{"idless_stays_idless", r.prev, r.prevBytes, "", false},
		{"changed_id_refused", &prevWithID, prevWithIDBytes, other, true},
		{"dropped_id_refused", &prevWithID, prevWithIDBytes, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next, err := BuildSuccessor(tc.prev, tc.prevBytes, r.policy, rootKeysOf(r.c, r.d), 1, r.policy, rotationIssued, tc.next)
			if tc.wantErr {
				if !errors.Is(err, ErrVersionChain) || !strings.Contains(err.Error(), "installation_id changed from "+id) {
					t.Fatalf("BuildSuccessor: %v, want ErrVersionChain naming the change", err)
				}
				// The verifier refuses the same successor.
				bad := *tc.prev
				bad.Version, bad.Prev, bad.IssuedAt = tc.prev.Version+1, SHA256Hex(tc.prevBytes), rotationIssued
				bad.Root = RootSet{Keys: rootKeysOf(r.c, r.d), Threshold: 1}
				bad.InstallationID = tc.next
				nextBytes := mustCanonical(t, &bad)
				_, _, verr := VerifySuccessor(tc.prev, tc.prevBytes, r.policy, nextBytes, signAll(t, NamespaceBundle, nextBytes, r.a, r.c),
					r.policy, signAll(t, NamespacePolicy, r.policy, r.a, r.c))
				if !errors.Is(verr, ErrVersionChain) {
					t.Fatalf("VerifySuccessor: %v, want ErrVersionChain", verr)
				}
				return
			}
			if err != nil || next.InstallationID != tc.next {
				t.Fatalf("BuildSuccessor = %+v, %v; want installation ID %q", next, err, tc.next)
			}
			nextBytes := mustCanonical(t, next)
			if _, _, err := VerifySuccessor(tc.prev, tc.prevBytes, r.policy, nextBytes, signAll(t, NamespaceBundle, nextBytes, r.a, r.c),
				r.policy, signAll(t, NamespacePolicy, r.policy, r.a, r.c)); err != nil {
				t.Fatalf("VerifySuccessor: %v", err)
			}
		})
	}
}
