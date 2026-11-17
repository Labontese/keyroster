package trust

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

// seedVector adds a golden vector to the fuzz corpus.
func seedVector(f *testing.F, name string) {
	f.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir, name)) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add(bytes.TrimSuffix(data, []byte("\n")))
	f.Add([]byte("{}\n"))
}

// FuzzParseBundle checks that ParseBundle never panics and that every
// accepted input is exactly its own canonical re-marshal.
func FuzzParseBundle(f *testing.F) {
	seedVector(f, "bundle_genesis_v1.json")
	seedVector(f, "bundle_rotation_v1.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := ParseBundle(data)
		if err != nil {
			return
		}
		re, err := b.Canonical()
		if err != nil {
			t.Fatalf("accepted bundle does not re-marshal: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("accepted a non-canonical bundle:\n%q\nre-marshals to\n%q", data, re)
		}
	})
}

// FuzzParsePolicy checks the same property for policies.
func FuzzParsePolicy(f *testing.F) {
	seedVector(f, "policy_genesis_v1.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePolicy(data)
		if err != nil {
			return
		}
		re, err := p.Canonical()
		if err != nil {
			t.Fatalf("accepted policy does not re-marshal: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("accepted a non-canonical policy:\n%q\nre-marshals to\n%q", data, re)
		}
	})
}

// caFuzzPool is the number of fixed-seed P-256 keys FuzzCATransitions draws
// CA keys from: room for the 15 entries a previous bundle can hold and the
// keys a successor adds. The roots, ops and log keys are the golden ones,
// outside the pool.
const caFuzzPool = 24

// caFuzzInput decodes FuzzCATransitions's bytes; a read past the end is 0.
type caFuzzInput struct {
	data []byte
	pos  int
}

func (in *caFuzzInput) next() byte {
	if in.pos >= len(in.data) {
		return 0
	}
	in.pos++
	return in.data[in.pos-1]
}

// caFuzzGens returns the generations the low bits of mask name, bit i being
// generation i+2 and bits naming generations 2 to last, at most limit of
// them, in increasing order.
func caFuzzGens(mask byte, last uint32, limit int) []uint32 {
	var out []uint32
	for g := uint32(2); g <= last && len(out) < limit; g++ {
		if mask&(1<<(g-2)) != 0 {
			out = append(out, g)
		}
	}
	return out
}

// caFuzzModel is the chain rule by enumeration (03-12b): for each role it
// builds every legal successor list of the previous one (unchanged; one
// next entry added for each pool key the previous bundle does not hold, at
// each generation above the role's maximum up to 8, in either custody the
// bytes can name, when the role has no next entry; one next entry aborted)
// and reports whether next's lists are among them, with the keys added
// across roles distinct.
func caFuzzModel(prev, next [3][]CAEntry, pool []string, prevHeld map[string]bool) bool {
	var added []string
	for r := range prev {
		var legal [][]CAEntry
		legal = append(legal, prev[r])
		hasNext := false
		var maxGen uint32
		for _, e := range prev[r] {
			hasNext = hasNext || e.State == "next"
			maxGen = max(maxGen, e.Generation)
		}
		if !hasNext {
			for _, k := range pool {
				if prevHeld[k] {
					continue
				}
				for g := maxGen + 1; g <= 8; g++ {
					// The rule binds no custody to an addition (the
					// signer's stored-generation check does), so both
					// custodies the bytes can name are legal.
					for _, custody := range []string{"vtpm", "software"} {
						legal = append(legal, append(slices.Clone(prev[r]), CAEntry{Role: caRoles[r], Key: k, Alg: ssh.KeyAlgoECDSA256, Custody: custody, State: "next", Generation: g}))
					}
				}
			}
		}
		for i, e := range prev[r] {
			if e.State == "next" {
				l := slices.Clone(prev[r])
				l[i].State = "retired"
				legal = append(legal, l)
			}
		}
		found := false
		for _, l := range legal {
			if slices.Equal(l, next[r]) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		if len(next[r]) == len(prev[r])+1 {
			k := next[r][len(next[r])-1].Key
			if slices.Contains(added, k) {
				return false
			}
			added = append(added, k)
		}
	}
	return true
}

// FuzzCATransitions (03-12b): checkCATransitions agrees with the rule by
// enumeration (caFuzzModel) on every pair of a previous bundle and a
// successor's CA entries, and every successor it accepts validates. The
// bytes build, per role, a previous list (generation 1 active, then up to
// four entries of generations 2 to 6, next or retired, at most one next;
// keys distinct across the bundle) and a successor list (generation 1 and
// up to five entries of generations 2 to 8, any state, either custody;
// keys drawn freely from the pool).
func FuzzCATransitions(f *testing.F) {
	pool := make([]string, caFuzzPool)
	for i := range pool {
		pool[i] = keyOf(p256Key(f, byte(100+i)))
	}
	policy := mustCanonical(f, goldenPolicy(f))
	// prevRole encodes a previous role list: the key index of generation
	// 1, then each extra entry as {generation, state, key index}.
	prevRole := func(k1 byte, extras ...[3]byte) []byte {
		var mask byte
		for _, e := range extras {
			mask |= 1 << (e[0] - 2)
		}
		out := []byte{k1, mask}
		for _, e := range extras {
			out = append(out, e[1], e[2])
		}
		return out
	}
	// nextRole encodes a successor role list: generation 1's state and key
	// index, then each extra entry as {generation, state, key index}.
	// States: 0 active, 1 next, 2 retired, plus 4 for custody software.
	nextRole := func(st1, k1 byte, extras ...[3]byte) []byte {
		var mask byte
		for _, e := range extras {
			mask |= 1 << (e[0] - 2)
		}
		out := []byte{st1, k1, mask}
		for _, e := range extras {
			out = append(out, e[1], e[2])
		}
		return out
	}
	seed := func(parts ...[]byte) []byte { return slices.Concat(parts...) }
	plain := seed(prevRole(0), prevRole(1), prevRole(2))
	f.Add(seed(plain, nextRole(0, 0), nextRole(0, 1), nextRole(0, 2)))                   // unchanged
	f.Add(seed(plain, nextRole(0, 0, [3]byte{2, 1, 3}), nextRole(0, 1), nextRole(0, 2))) // add
	f.Add(seed(prevRole(0, [3]byte{2, 1, 3}), prevRole(1), prevRole(2),
		nextRole(0, 0, [3]byte{2, 2, 3}), nextRole(0, 1), nextRole(0, 2))) // abort
	f.Add(seed(prevRole(0, [3]byte{2, 0, 3}), prevRole(1), prevRole(2),
		nextRole(0, 0), nextRole(0, 1), nextRole(0, 2))) // removal
	f.Add(seed(plain, nextRole(0, 5), nextRole(0, 1), nextRole(0, 2)))                                     // active key swap
	f.Add(seed(plain, nextRole(0, 0, [3]byte{2, 1, 7}), nextRole(0, 1, [3]byte{2, 1, 7}), nextRole(0, 2))) // two roles add one key
	f.Fuzz(func(t *testing.T, data []byte) {
		in := &caFuzzInput{data: data}
		held := map[string]bool{}
		var prevLists, nextLists [3][]CAEntry
		for r, role := range caRoles {
			pick := func() string {
				i := int(in.next()) % caFuzzPool
				for held[pool[i]] {
					i = (i + 1) % caFuzzPool
				}
				held[pool[i]] = true
				return pool[i]
			}
			prevLists[r] = []CAEntry{{Role: role, Key: pick(), Alg: ssh.KeyAlgoECDSA256, Custody: "vtpm", State: "active", Generation: 1}}
			hasNext := false
			for _, g := range caFuzzGens(in.next(), 6, 4) {
				state := "retired"
				if in.next()&1 == 1 && !hasNext {
					state, hasNext = "next", true
				}
				prevLists[r] = append(prevLists[r], CAEntry{Role: role, Key: pick(), Alg: ssh.KeyAlgoECDSA256, Custody: "vtpm", State: state, Generation: g})
			}
		}
		entry := func(role string, g uint32) CAEntry {
			st := in.next()
			e := CAEntry{Role: role, Key: pool[int(in.next())%caFuzzPool], Alg: ssh.KeyAlgoECDSA256, Custody: "vtpm",
				State: []string{"active", "next", "retired", "retired"}[st&3], Generation: g}
			if st&4 != 0 {
				e.Custody = "software"
			}
			return e
		}
		for r, role := range caRoles {
			nextLists[r] = []CAEntry{entry(role, 1)}
			for _, g := range caFuzzGens(in.next(), 8, 5) {
				nextLists[r] = append(nextLists[r], entry(role, g))
			}
		}
		prev := goldenBundle(t, policy)
		prev.CAs = slices.Concat(prevLists[0], prevLists[1], prevLists[2])
		if err := prev.Validate(); err != nil {
			t.Fatalf("the previous bundle does not validate: %v", err)
		}
		next := *prev
		next.CAs = slices.Concat(nextLists[0], nextLists[1], nextLists[2])
		err := checkCATransitions(prev, &next, goldenPolicy(t), goldenPolicy(t))
		want := caFuzzModel(prevLists, nextLists, pool, held)
		if (err == nil) != want {
			t.Fatalf("checkCATransitions = %v, the model accepts %t\nprev %+v\nnext %+v", err, want, prev.CAs, next.CAs)
		}
		if err != nil && !errors.Is(err, ErrVersionChain) {
			t.Fatalf("checkCATransitions = %v, want ErrVersionChain", err)
		}
		if err == nil {
			if verr := next.Validate(); verr != nil {
				t.Fatalf("an accepted successor does not validate: %v\n%+v", verr, next.CAs)
			}
		}
	})
}
