// Package krl writes OpenSSH Key Revocation Lists (PROTOCOL.krl, format
// version 1) and the signed manifest every published KRL version travels
// with (D-04, REVOKE-02, REVOKE-03).
//
// The encoder is deterministic and deliberately small. It writes the
// header (magic, format version, krl_version, generated_date, flags 0, an
// empty reserved string and an empty comment) and one certificate section
// (type 1) per CA key that has revoked serials, ordered by the CA key's
// SSH wire encoding. Inside a section, the serials that are not part of a
// run go into one serial list (0x20), placed first, and every run of two
// or more consecutive serials becomes one serial range (0x21). It never
// writes a signature section (type 4: sshd ignores KRL signatures, the
// manifest's SSHSIG is the integrity check), an extension section or
// subsection, or a bitmap subsection. The same set always encodes to the
// same bytes, whatever the insertion order.
//
// The package imports only the standard library, golang.org/x/crypto and,
// for the manifest, internal/trust and internal/sshsig, none of which
// reaches the network, so the network-less signer can use it (depguard rule
// signer-no-network).
package krl

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

// Magic is the 8-byte KRL magic, written as raw bytes (the uint64
// 0x5353484b524c0a00 of PROTOCOL.krl in big-endian order).
const Magic = "SSHKRL\n\x00"

// FormatVersion is the KRL format version this package writes.
const FormatVersion uint32 = 1

// MaxKRL is the largest KRL Encode returns: 4 MiB, room for about half a
// million revoked serials that are not adjacent to one another.
const MaxKRL = 4 << 20

// Section and certificate subsection types (PROTOCOL.krl).
const (
	sectionCertificates byte = 1
	subSerialList       byte = 0x20
	subSerialRange      byte = 0x21
)

// Errors.
var (
	// ErrMalformed reports a set the encoder refuses: a nil CA key or a
	// serial 0.
	ErrMalformed = errors.New("krl: malformed revocation set")
	// ErrTooLarge reports an encoding above MaxKRL.
	ErrTooLarge = errors.New("krl: the KRL would exceed MaxKRL")
)

// Set is what a KRL revokes. This version carries certificate serials by
// CA key only; key-ID, key and SHA-256 sections arrive with 03-03.
type Set struct {
	Certs []CertSerials
}

// CertSerials is a set of revoked certificate serials under one CA key.
// Entries for the same CA key (by wire encoding) merge, and a serial listed
// twice is revoked once.
type CertSerials struct {
	CAKey   ssh.PublicKey
	Serials []uint64
}

// Encode returns the KRL for s with the given krl_version and
// generated_date (generated, in whole seconds since the epoch; 0 before
// it). It refuses a nil CA key and a serial 0 (ErrMalformed), and an
// encoding above MaxKRL (ErrTooLarge). An empty set encodes to the header
// alone, which revokes nothing.
func Encode(s Set, version uint64, generated time.Time) ([]byte, error) {
	byCA := map[string][]uint64{}
	for _, c := range s.Certs {
		if c.CAKey == nil {
			return nil, fmt.Errorf("%w: a CA key is missing", ErrMalformed)
		}
		k := string(c.CAKey.Marshal())
		for _, ser := range c.Serials {
			if ser == 0 {
				return nil, fmt.Errorf("%w: serial 0 cannot be revoked by serial", ErrMalformed)
			}
		}
		byCA[k] = append(byCA[k], c.Serials...)
	}
	cas := make([]string, 0, len(byCA))
	for k, serials := range byCA {
		if len(serials) > 0 {
			cas = append(cas, k)
		}
	}
	slices.SortFunc(cas, func(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) })

	var gen uint64
	if u := generated.Unix(); u > 0 {
		gen = uint64(u)
	}
	var b cryptobyte.Builder
	b.AddBytes([]byte(Magic))
	b.AddUint32(FormatVersion)
	b.AddUint64(version)
	b.AddUint64(gen)
	b.AddUint64(0)                                          // flags
	b.AddUint32LengthPrefixed(func(*cryptobyte.Builder) {}) // reserved
	b.AddUint32LengthPrefixed(func(*cryptobyte.Builder) {}) // comment
	for _, ca := range cas {
		single, ranges := split(byCA[ca])
		b.AddUint8(sectionCertificates)
		b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(ca)) })
			b.AddUint32LengthPrefixed(func(*cryptobyte.Builder) {}) // reserved
			if len(single) > 0 {
				b.AddUint8(subSerialList)
				b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, ser := range single {
						b.AddUint64(ser)
					}
				})
			}
			for _, r := range ranges {
				b.AddUint8(subSerialRange)
				b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint64(r[0])
					b.AddUint64(r[1])
				})
			}
		})
	}
	out, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTooLarge, err)
	}
	if len(out) > MaxKRL {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, len(out))
	}
	return out, nil
}

// split sorts and dedupes serials and returns the serials that are not
// part of a run, ascending, and every run of two or more consecutive
// serials as [min, max], ascending.
func split(serials []uint64) (single []uint64, ranges [][2]uint64) {
	s := slices.Clone(serials)
	slices.Sort(s)
	s = slices.Compact(s)
	for i := 0; i < len(s); {
		j := i
		for j+1 < len(s) && s[j+1] == s[j]+1 {
			j++
		}
		if j > i {
			ranges = append(ranges, [2]uint64{s[i], s[j]})
		} else {
			single = append(single, s[i])
		}
		i = j + 1
	}
	return single, ranges
}
