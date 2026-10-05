package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// refRoot is RFC 6962 section 2.1 MTH written out directly: the reference
// against which the compact-range Log is checked.
func refRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		h := sha256.Sum256(append([]byte{0}, leaves[0]...))
		return h[:]
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(refRoot(leaves[:k]))
	h.Write(refRoot(leaves[k:]))
	return h.Sum(nil)
}

func TestLogRootMatchesRFC6962(t *testing.T) {
	var leaves [][]byte
	l := NewLog()
	for n := 0; n <= 70; n++ {
		root, err := l.Root()
		if err != nil {
			t.Fatal(err)
		}
		if want := refRoot(leaves); !bytes.Equal(root, want) || l.Size() != uint64(n) {
			t.Fatalf("size %d: root %x, want %x (Size %d)", n, root, want, l.Size())
		}
		leaf := []byte(fmt.Sprintf("leaf %d", n))
		leaves = append(leaves, leaf)
		if err := l.Append(HashLeaf(leaf)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLogKnownRoots(t *testing.T) {
	// SHA-256 of the empty string (RFC 6962 empty tree) and the leaf hash
	// of an empty leaf, SHA-256(0x00).
	empty, _ := NewLog().Root()
	if got := hex.EncodeToString(empty); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty root %s", got)
	}
	if got := hex.EncodeToString(HashLeaf(nil)); got != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Fatalf("empty leaf hash %s", got)
	}
}

func TestLogCloneIsIndependent(t *testing.T) {
	l := NewLog()
	for i := range 5 {
		if err := l.Append(HashLeaf([]byte{byte(i)})); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := l.Root()
	c := l.Clone()
	for i := range 3 {
		if err := c.Append(HashLeaf([]byte{byte(10 + i)})); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := l.Root()
	if !bytes.Equal(before, after) || l.Size() != 5 || c.Size() != 8 {
		t.Fatalf("appending to the clone changed the original (sizes %d, %d)", l.Size(), c.Size())
	}
}

func TestFromHashes(t *testing.T) {
	var hashes, leaves [][]byte
	for i := range 9 {
		leaf := []byte{byte(i), 'x'}
		leaves = append(leaves, leaf)
		hashes = append(hashes, HashLeaf(leaf))
	}
	l, err := FromHashes(hashes)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := l.Root()
	if !bytes.Equal(root, refRoot(leaves)) {
		t.Fatal("FromHashes root differs from the reference")
	}
	if _, err := FromHashes([][]byte{make([]byte, 31)}); err == nil {
		t.Fatal("FromHashes accepted a 31-byte hash")
	}
}

// TestIdenticalLeavesStayDistinct: two leaves with identical bytes are two
// entries and both count toward the root (VIS-01 adjacency).
func TestIdenticalLeavesStayDistinct(t *testing.T) {
	one, two := NewLog(), NewLog()
	leaf := []byte("same refusal")
	_ = one.Append(HashLeaf(leaf))
	_ = two.Append(HashLeaf(leaf))
	_ = two.Append(HashLeaf(leaf))
	r1, _ := one.Root()
	r2, _ := two.Root()
	if bytes.Equal(r1, r2) || two.Size() != 2 {
		t.Fatal("a repeated identical leaf did not change the root")
	}
}
