package trust

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// popPolicy is the golden genesis policy's successor (version 2, prev =
// SHA-256 of policy_genesis_v1.json) with pop set to p.
func popPolicy(t testing.TB, p *PoPPolicy) *Policy {
	t.Helper()
	pol := goldenPolicy(t)
	pol.Version, pol.Prev = 2, SHA256Hex(mustCanonical(t, goldenPolicy(t)))
	pol.PoP = p
	return pol
}

// TestPolicyPoP pins the Phase 3 policy field: an omitempty pointer and the
// last field, which leaves every earlier policy byte-identical, a null that
// is refused as non-canonical, and at least one switch on when present.
func TestPolicyPoP(t *testing.T) {
	t.Run("genesis_vector_unchanged", func(t *testing.T) {
		data, err := os.ReadFile(filepath.Join(vectorDir, "policy_genesis_v1.json")) //nolint:gosec // G304: fixed test vector path
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePolicy(data)
		if err != nil {
			t.Fatal(err)
		}
		if p.PoP != nil {
			t.Fatal("a policy without the pop field decoded with one")
		}
		if !bytes.Equal(mustCanonical(t, p), data) {
			t.Fatal("the genesis policy re-encodes differently")
		}
	})
	t.Run("pop_null_noncanonical", func(t *testing.T) {
		data := mustCanonical(t, goldenPolicy(t))
		withNull := append(bytes.TrimSuffix(data, []byte("}\n")), []byte(`,"pop":null}`+"\n")...)
		if _, err := ParsePolicy(withNull); !errors.Is(err, ErrNotCanonical) {
			t.Fatalf("ParsePolicy with \"pop\":null = %v, want ErrNotCanonical", err)
		}
	})
	t.Run("pop_both_false_refused", func(t *testing.T) {
		p := popPolicy(t, &PoPPolicy{})
		if err := p.Validate(); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "at least one of hosts and machines") {
			t.Fatalf("Validate with pop {false, false} = %v, want ErrInvalid", err)
		}
		if _, err := ParsePolicy(mustCanonical(t, p)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ParsePolicy with pop {false, false} = %v, want ErrInvalid", err)
		}
	})
	t.Run("pop_is_last_field", func(t *testing.T) {
		p := popPolicy(t, &PoPPolicy{Hosts: true})
		p.WebAuthn = &WebAuthnRP{RPID: "keyroster.example.org", Origins: []string{"https://keyroster.example.org"}}
		data := mustCanonical(t, p)
		if !bytes.HasSuffix(data, []byte(`]},"pop":{"hosts":true,"machines":false}}`+"\n")) {
			t.Fatalf("pop is not the last field, after webauthn:\n%s", data)
		}
		if _, err := ParsePolicy(data); err != nil {
			t.Fatal(err)
		}
	})
}

// TestPolicyPoPGoldenVector pins test/vectors/policy_pop_v1.json: the
// genesis policy's successor with pop {hosts true, machines true}.
func TestPolicyPoPGoldenVector(t *testing.T) {
	built := mustCanonical(t, popPolicy(t, &PoPPolicy{Hosts: true, Machines: true}))
	path := filepath.Join(vectorDir, "policy_pop_v1.json")
	if *updateVectors {
		if err := os.WriteFile(path, built, 0o644); err != nil { //nolint:gosec // G306: public test vector
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatalf("%v (create it with -update only for a deliberate format change)", err)
	}
	if !bytes.Equal(got, built) {
		t.Fatalf("%s differs from the built policy\ngot:  %s\nwant: %s", path, got, built)
	}
	p, err := ParsePolicy(got)
	if err != nil {
		t.Fatal(err)
	}
	if p.PoP == nil || !p.PoP.Hosts || !p.PoP.Machines || p.Version != 2 {
		t.Fatalf("policy_pop_v1.json decodes to version %d pop %+v", p.Version, p.PoP)
	}
	genesis, err := os.ReadFile(filepath.Join(vectorDir, "policy_genesis_v1.json")) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatal(err)
	}
	if p.Prev != SHA256Hex(genesis) {
		t.Fatal("policy_pop_v1.json does not chain to policy_genesis_v1.json")
	}
}

// TestPoPSuccessor (owner decision 2026-10-24, T-03-206): pop.hosts is
// one-way. CheckPoPSuccessor refuses true to false and true to absent with
// ErrPoPHostsRemoved, and accepts every other change; the rule holds in
// VerifySuccessor and BuildSuccessor through checkSuccessorChain.
func TestPoPSuccessor(t *testing.T) {
	on := func(h, m bool) *PoPPolicy { return &PoPPolicy{Hosts: h, Machines: m} }
	for _, tc := range []struct {
		name       string
		prev, next *PoPPolicy
		refused    bool
	}{
		{"pop_hosts_true_to_false_refused", on(true, false), on(false, true), true},
		{"pop_hosts_true_to_absent_refused", on(true, true), nil, true},
		{"pop_hosts_false_to_true_accepted", on(false, true), on(true, true), false},
		{"pop_absent_to_hosts_true_accepted", nil, on(true, false), false},
		{"pop_hosts_true_to_true_accepted", on(true, false), on(true, false), false},
		{"pop_machines_true_to_false_accepted", on(true, true), on(true, false), false},
		{"pop_machines_true_to_absent_accepted", on(false, true), nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prev, next := goldenPolicy(t), popPolicy(t, tc.next)
			prev.PoP = tc.prev
			err := CheckPoPSuccessor(prev, next)
			if tc.refused {
				if !errors.Is(err, ErrPoPHostsRemoved) || !strings.Contains(err.Error(), "pop_hosts_removed") {
					t.Fatalf("CheckPoPSuccessor = %v, want ErrPoPHostsRemoved (pop_hosts_removed)", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CheckPoPSuccessor = %v, want accepted", err)
			}
		})
	}

	t.Run("verify_successor_refuses_pop_hosts_removed", func(t *testing.T) {
		r := newRotation(t)
		prevPol := goldenPolicy(t)
		prevPol.PoP = on(true, false)
		r.policy = mustCanonical(t, prevPol)
		r.prev = goldenBundle(t, r.policy)
		r.prev.Root = RootSet{Keys: rootKeysOf(r.a), Threshold: 1}
		r.prevBytes = mustCanonical(t, r.prev)

		off := goldenPolicy(t)
		off.Version, off.Prev = 2, SHA256Hex(r.policy)
		offDoc := mustCanonical(t, off)
		if _, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, rootKeysOf(r.a), 1, offDoc, rotationIssued, ""); !errors.Is(err, ErrPoPHostsRemoved) {
			t.Fatalf("BuildSuccessor with pop.hosts cleared = %v, want ErrPoPHostsRemoved", err)
		}
		next := goldenBundle(t, offDoc)
		next.Version, next.Prev, next.IssuedAt = 2, SHA256Hex(r.prevBytes), rotationIssued
		next.Root = RootSet{Keys: rootKeysOf(r.a), Threshold: 1}
		if err := r.verify(t, r.prevBytes, r.policy, mustCanonical(t, next), offDoc, r.a); !errors.Is(err, ErrPoPHostsRemoved) {
			t.Fatalf("VerifySuccessor with pop.hosts cleared = %v, want ErrPoPHostsRemoved", err)
		}

		// Control: the same successor that keeps pop.hosts verifies.
		keep := goldenPolicy(t)
		keep.Version, keep.Prev, keep.PoP = 2, SHA256Hex(r.policy), on(true, true)
		keepDoc := mustCanonical(t, keep)
		built, err := BuildSuccessor(r.prev, r.prevBytes, r.policy, rootKeysOf(r.a), 1, keepDoc, rotationIssued, "")
		if err != nil {
			t.Fatalf("BuildSuccessor keeping pop.hosts: %v", err)
		}
		if err := r.verify(t, r.prevBytes, r.policy, mustCanonical(t, built), keepDoc, r.a); err != nil {
			t.Fatalf("VerifySuccessor keeping pop.hosts: %v", err)
		}
		// An unchanged policy is not a policy change and passes too.
		same := goldenBundle(t, r.policy)
		same.Version, same.Prev, same.IssuedAt = 2, SHA256Hex(r.prevBytes), rotationIssued
		same.Root = RootSet{Keys: rootKeysOf(r.a), Threshold: 1}
		if err := r.verify(t, r.prevBytes, r.policy, mustCanonical(t, same), r.policy, r.a); err != nil {
			t.Fatalf("VerifySuccessor with the policy unchanged: %v", err)
		}
	})
}
