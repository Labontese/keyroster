// Package krl writes and reads OpenSSH Key Revocation Lists (PROTOCOL.krl,
// format version 1) and the signed manifest every published KRL version
// travels with (D-04, REVOKE-02, REVOKE-03).
//
// The encoder is deterministic and deliberately small. It writes the
// header (magic, format version, krl_version, generated_date, flags 0, an
// empty reserved string and an empty comment), one certificate section
// (type 1) per CA key that has revoked serials or key IDs, ordered by the
// CA key's SSH wire encoding, and one explicit-key section (type 2) after
// them when keys are revoked. Inside a certificate section, the serials
// that are not part of a run go into one serial list (0x20), placed first,
// every run of two or more consecutive serials becomes one serial range
// (0x21), and the key IDs follow in one key-ID subsection (0x23), sorted
// and unique. Explicit keys are sorted by their wire encoding and unique.
// It never writes a signature section (type 4: sshd ignores KRL
// signatures, the manifest's SSHSIG is the integrity check), a fingerprint
// section, an extension section or subsection, or a bitmap subsection. The
// same set always encodes to the same bytes, whatever the insertion order
// and however often an entry is listed.
//
// Parse (parse.go) reads every section and subsection type ssh-keygen may
// write, strictly and with memory bounded by its input.
//
// EntryLive, Prunable and PublishSet are the one liveness rule, the one
// pruning rule and the one set builder that the signer (publishing) and
// keyroster audit verify (re-deriving every published KRL from the log)
// share, so the two cannot disagree on what a KRL must list.
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
	"math"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// Magic is the 8-byte KRL magic, written as raw bytes (the uint64
// 0x5353484b524c0a00 of PROTOCOL.krl in big-endian order).
const Magic = "SSHKRL\n\x00"

// FormatVersion is the KRL format version this package writes.
const FormatVersion uint32 = 1

// MaxKRL is the largest KRL Encode returns and Parse reads: 4 MiB, room
// for about half a million revoked serials that are not adjacent to one
// another.
const MaxKRL = 4 << 20

// Section and certificate subsection types (PROTOCOL.krl).
const (
	sectionCertificates  byte = 1
	sectionExplicitKey   byte = 2
	sectionSHA1          byte = 3
	sectionSignature     byte = 4
	sectionSHA256        byte = 5
	sectionExtension     byte = 255
	subSerialList        byte = 0x20
	subSerialRange       byte = 0x21
	subSerialBitmap      byte = 0x22
	subKeyID             byte = 0x23
	subExtension         byte = 0x39
	sha1Len                   = 20
	sha256Len                 = 32
	maxBitmapMpintLength      = 16384/8 + 1 // OpenSSH's SSHBUF_MAX_BIGNUM (2048 bytes) plus a zero sign byte
)

// MaxRevokedKeys and MaxRevokedKeyBytes cap the explicit-key entries,
// which never leave a KRL (a key has no ValidBefore): at most 1000
// distinct keys, taking at most 1 MiB of the explicit-key section (4 +
// the wire length per key). The count binds for Ed25519, ECDSA,
// security-key and RSA keys up to 4096 bits; only larger RSA keys reach
// the byte cap first. So one admin cannot fill MaxKRL for good with
// explicit keys: 3 MiB stay for serial and key-ID entries, which leave the
// KRL once their certificates expire (pre-merge review of PR #61, owner
// decision 2026-10-26, T-03-211). The signer refuses a key revocation
// beyond either cap (explicit_key_cap_reached) and audit verify a log
// whose explicit keys exceed them; both call CheckExplicitKeys.
const (
	MaxRevokedKeys     = 1000
	MaxRevokedKeyBytes = 1 << 20
)

// Errors.
var (
	// ErrMalformed reports a set the encoder refuses (a nil CA key, a
	// serial 0, an empty key ID, a certificate as an explicit key) and a
	// KRL Parse refuses.
	ErrMalformed = errors.New("krl: malformed revocation set")
	// ErrTooLarge reports an encoding above MaxKRL, and an input above
	// MaxKRL or above MaxParsedEntries entries for Parse.
	ErrTooLarge = errors.New("krl: the KRL would exceed MaxKRL")
	// ErrKeyCap reports explicit keys beyond MaxRevokedKeys or
	// MaxRevokedKeyBytes (CheckExplicitKeys).
	ErrKeyCap = errors.New("krl: the explicit-key cap is reached")
)

// CheckExplicitKeys requires the distinct keys among keys (SSH wire
// format; a key listed twice counts once, as Encode lists it once) to be
// at most MaxRevokedKeys and to take at most MaxRevokedKeyBytes in the
// explicit-key section. A key already among them adds nothing, so
// revoking it again passes at the cap.
func CheckExplicitKeys(keys [][]byte) error {
	seen := make(map[string]bool, len(keys))
	size := 0
	for _, k := range keys {
		if !seen[string(k)] {
			seen[string(k)] = true
			size += 4 + len(k)
		}
	}
	if len(seen) > MaxRevokedKeys || size > MaxRevokedKeyBytes {
		return fmt.Errorf("%w: %d distinct keys in %d bytes, at most %d keys in %d bytes", ErrKeyCap, len(seen), size, MaxRevokedKeys, MaxRevokedKeyBytes)
	}
	return nil
}

// Set is what a KRL revokes: certificates by serial or key ID under a CA
// key, and explicit keys (a plain key and every certificate for it).
type Set struct {
	Certs []CertSection
	Keys  []ssh.PublicKey
}

// CertSection is a set of revoked certificate serials and key IDs under
// one CA key. Sections for the same CA key (by wire encoding) merge, and a
// serial or key ID listed twice is revoked once.
type CertSection struct {
	CAKey   ssh.PublicKey
	Serials []uint64
	KeyIDs  []string
}

// Encode returns the KRL for s with the given krl_version and
// generated_date (generated, in whole seconds since the epoch; 0 before
// it). It refuses a nil CA key, a serial 0, an empty key ID or one with a
// NUL byte, and a nil or
// certificate explicit key (ErrMalformed), and an encoding above MaxKRL
// (ErrTooLarge). An empty set encodes to the header alone, which revokes
// nothing.
func Encode(s Set, version uint64, generated time.Time) ([]byte, error) {
	type section struct {
		serials []uint64
		keyIDs  []string
	}
	byCA := map[string]*section{}
	for _, c := range s.Certs {
		if c.CAKey == nil {
			return nil, fmt.Errorf("%w: a CA key is missing", ErrMalformed)
		}
		for _, ser := range c.Serials {
			if ser == 0 {
				return nil, fmt.Errorf("%w: serial 0 cannot be revoked by serial", ErrMalformed)
			}
		}
		for _, id := range c.KeyIDs {
			if id == "" {
				return nil, fmt.Errorf("%w: an empty key ID cannot be revoked", ErrMalformed)
			}
			if strings.IndexByte(id, 0) >= 0 {
				// OpenSSH reads a key ID as a C string: it refuses the KRL
				// for a NUL inside one and ends the key ID at a final one.
				return nil, fmt.Errorf("%w: a key ID with a NUL byte cannot be revoked", ErrMalformed)
			}
		}
		k := string(c.CAKey.Marshal())
		sec := byCA[k]
		if sec == nil {
			sec = &section{}
			byCA[k] = sec
		}
		sec.serials = append(sec.serials, c.Serials...)
		sec.keyIDs = append(sec.keyIDs, c.KeyIDs...)
	}
	cas := make([]string, 0, len(byCA))
	for k, sec := range byCA {
		if len(sec.serials) > 0 || len(sec.keyIDs) > 0 {
			cas = append(cas, k)
		}
	}
	slices.SortFunc(cas, func(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) })
	keys := make([][]byte, 0, len(s.Keys))
	for _, k := range s.Keys {
		if k == nil {
			return nil, fmt.Errorf("%w: an explicit key is missing", ErrMalformed)
		}
		if _, isCert := k.(*ssh.Certificate); isCert {
			return nil, fmt.Errorf("%w: an explicit key must be a plain key, not a certificate", ErrMalformed)
		}
		keys = append(keys, k.Marshal())
	}
	slices.SortFunc(keys, bytes.Compare)
	keys = slices.CompactFunc(keys, bytes.Equal)

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
		sec := byCA[ca]
		single, ranges := split(sec.serials)
		ids := slices.Clone(sec.keyIDs)
		slices.Sort(ids)
		ids = slices.Compact(ids)
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
			if len(ids) > 0 {
				b.AddUint8(subKeyID)
				b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, id := range ids {
						b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(id)) })
					}
				})
			}
		})
	}
	if len(keys) > 0 {
		b.AddUint8(sectionExplicitKey)
		b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, k := range keys {
				b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(k) })
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

// PruneMargin is how long, in seconds, a revoked certificate stays in the
// KRL after its ValidBefore: hosts whose clocks lag the signer's by up to
// this much still refuse it.
const PruneMargin = 300

// EntryLive reports whether a revoked certificate valid before validBefore
// (whole seconds) is still live at at (whole seconds): validBefore +
// PruneMargin > at. It is the one liveness rule: subject resolution,
// publishing and keyroster audit verify all use it. It saturates, so a
// validBefore near 2^64 (ssh.CertTimeInfinity) stays live at every time.
func EntryLive(validBefore, at uint64) bool {
	if validBefore > math.MaxUint64-PruneMargin {
		return true
	}
	return validBefore+PruneMargin > at
}

// Prunable reports whether a revocation entry whose certificate is valid
// before validBefore may be left out of a KRL issued at at: its
// ValidBefore is known (not 0) and it is no longer live. An entry whose
// ValidBefore is unknown (0) is never prunable. It is the one pruning
// rule, applied through PublishSet.
func Prunable(validBefore, at uint64) bool {
	return validBefore != 0 && !EntryLive(validBefore, at)
}

// Entry kinds of an Entry.
const (
	EntrySerial uint8 = 1 // a certificate serial under a CA key
	EntryKeyID  uint8 = 2 // a certificate key ID under a CA key
	EntryKey    uint8 = 3 // an explicit public key
)

// Entry is one revocation: a revocation row in the signer, or one logged
// revoke-leaf entry in keyroster audit verify. CAKey and Key are SSH wire
// encodings; ValidBefore is the revoked certificate's valid_before in
// whole seconds, 0 when not known. An explicit key is never pruned,
// whatever its ValidBefore.
type Entry struct {
	Kind        uint8
	CAKey       []byte
	Serial      uint64
	KeyID       string
	Key         []byte
	ValidBefore uint64
}

// PublishSet builds the set a KRL issued at issuedAt (whole seconds)
// publishes from entries: every entry except the serial and key-ID entries
// for which Prunable is true at issuedAt, as they are, duplicates
// included (Encode lists each once, so an entry revoked twice stays while
// either copy is live). Both the signer and keyroster audit verify build
// every published KRL through it. It refuses an unknown kind and a CA key
// or key that does not parse (ErrMalformed).
func PublishSet(entries []Entry, issuedAt uint64) (Set, error) {
	var (
		set     Set
		section = map[string]int{} // CA key wire bytes -> index in set.Certs
		keys    = map[string]ssh.PublicKey{}
	)
	parse := func(blob []byte, what string) (ssh.PublicKey, error) {
		if k, ok := keys[string(blob)]; ok {
			return k, nil
		}
		k, err := ssh.ParsePublicKey(blob)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrMalformed, what, err)
		}
		keys[string(blob)] = k
		return k, nil
	}
	for _, e := range entries {
		switch e.Kind {
		case EntrySerial, EntryKeyID:
			if Prunable(e.ValidBefore, issuedAt) {
				continue
			}
			i, ok := section[string(e.CAKey)]
			if !ok {
				ca, err := parse(e.CAKey, "CA key")
				if err != nil {
					return Set{}, err
				}
				i = len(set.Certs)
				section[string(e.CAKey)] = i
				set.Certs = append(set.Certs, CertSection{CAKey: ca})
			}
			if e.Kind == EntrySerial {
				set.Certs[i].Serials = append(set.Certs[i].Serials, e.Serial)
			} else {
				set.Certs[i].KeyIDs = append(set.Certs[i].KeyIDs, e.KeyID)
			}
		case EntryKey:
			k, err := parse(e.Key, "explicit key")
			if err != nil {
				return Set{}, err
			}
			set.Keys = append(set.Keys, k)
		default:
			return Set{}, fmt.Errorf("%w: entry kind %d", ErrMalformed, e.Kind)
		}
	}
	return set, nil
}

// RoleCAKeys returns the SSH wire encodings of every CA key of role in b,
// in any state (active, next or retired), sorted and unique. A key-ID
// revocation under role is recorded under each of them, by the signer and
// as keyroster audit verify expects it, so a certificate of that key ID
// is refused whichever of the role's CA keys signed it.
func RoleCAKeys(b *trust.Bundle, role string) ([][]byte, error) {
	if b == nil {
		return nil, errors.New("krl: no trust bundle")
	}
	var out [][]byte
	for _, ca := range b.CAs {
		if ca.Role != role {
			continue
		}
		pub, err := trust.ParseKey(ca.Key)
		if err != nil {
			return nil, fmt.Errorf("krl: %s CA key: %w", role, err)
		}
		out = append(out, pub.Marshal())
	}
	slices.SortFunc(out, bytes.Compare)
	return slices.CompactFunc(out, bytes.Equal), nil
}

// InstallationKeys returns the SSH wire encodings of every key b names:
// each CA key in any state, the ops key, the log key and each root key.
// None of them may be revoked as an explicit key through a revoke request
// (key_is_ca_of_this_installation): an explicit-key entry on a CA key
// refuses every certificate it signed, so CA-key revocation is the
// emergency rotation path instead (03-13).
func InstallationKeys(b *trust.Bundle) (map[string]bool, error) {
	if b == nil {
		return nil, errors.New("krl: no trust bundle")
	}
	out := map[string]bool{}
	add := func(what, key string) error {
		pub, err := trust.ParseKey(key)
		if err != nil {
			return fmt.Errorf("krl: %s key: %w", what, err)
		}
		out[string(pub.Marshal())] = true
		return nil
	}
	for _, ca := range b.CAs {
		if err := add(ca.Role+" CA", ca.Key); err != nil {
			return nil, err
		}
	}
	if err := add("ops", b.OpsKey.Key); err != nil {
		return nil, err
	}
	if err := add("log", b.Log.Key); err != nil {
		return nil, err
	}
	for _, r := range b.Root.Keys {
		if err := add("root", r.Key); err != nil {
			return nil, err
		}
	}
	return out, nil
}
