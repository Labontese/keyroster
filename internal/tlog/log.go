package tlog

import (
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

// HashSize is the size of leaf and node hashes (SHA-256).
const HashSize = 32

// rangeFactory builds compact ranges with RFC 6962 interior-node hashing.
var rangeFactory = &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}

// HashLeaf returns the RFC 6962 leaf hash of the encoded leaf bytes.
func HashLeaf(leaf []byte) []byte { return rfc6962.DefaultHasher.HashLeaf(leaf) }

// Log is the Merkle tree state of the whole log as a compact range
// [0, size): enough to append and to compute the root, without storing
// interior nodes.
type Log struct {
	r *compact.Range
}

// NewLog returns an empty log.
func NewLog() *Log { return &Log{r: rangeFactory.NewEmptyRange(0)} }

// FromHashes rebuilds a log from its leaf hashes in index order.
func FromHashes(hashes [][]byte) (*Log, error) {
	l := NewLog()
	for i, h := range hashes {
		if err := l.Append(h); err != nil {
			return nil, fmt.Errorf("tlog: leaf %d: %w", i, err)
		}
	}
	return l, nil
}

// Append adds one leaf hash.
func (l *Log) Append(hash []byte) error {
	if len(hash) != HashSize {
		return errors.New("tlog: leaf hash must be 32 bytes")
	}
	return l.r.Append(append([]byte(nil), hash...), nil)
}

// Size returns the number of leaves.
func (l *Log) Size() uint64 { return l.r.End() }

// Root returns the RFC 6962 root hash; for an empty log, the hash of the
// empty string.
func (l *Log) Root() ([]byte, error) {
	if l.r.End() == 0 {
		return rfc6962.DefaultHasher.EmptyRoot(), nil
	}
	return l.r.GetRootHash(nil)
}

// Clone returns an independent copy, so the next state can be computed
// without touching this one.
func (l *Log) Clone() *Log {
	src := l.r.Hashes()
	hashes := make([][]byte, len(src))
	for i, h := range src {
		hashes[i] = append([]byte(nil), h...)
	}
	r, err := rangeFactory.NewRange(0, l.r.End(), hashes)
	if err != nil {
		// The hashes came from a valid range of the same size.
		panic("tlog: clone of a valid range failed: " + err.Error())
	}
	return &Log{r: r}
}
