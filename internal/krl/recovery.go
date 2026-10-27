package krl

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"

	"github.com/Labontese/keyroster/internal/cert"
)

// MaxRecoveryEntries bounds the entries one recovery derives (equal to
// tlog.MaxRecoveryEntries, which a test in internal/tlog asserts). It is
// tlog.MaxRecoveryBody (11 MiB) divided by 24, the size of the smallest
// entry a revocation_recovery body can hold, so the count never refuses a
// recovery that the body cap admits: the body cap binds first (PR #69
// review, D-R1). The count is still taken before anything is expanded.
const MaxRecoveryEntries = (11 << 20) / 24

// RecoveryCarrySkew is the skew bound of CarriesLost, in seconds: the
// signer's request freshness window (wire.MaxRequestSkewSeconds, which a
// test asserts), so a workstation clock ahead of the signer's never leaves
// out a certificate the signer still sees as live.
const RecoveryCarrySkew = 300

// CarriesLost is the one rule for which lost certificates a recovery
// carries (PR #69 review, D-R2): one it revokes, and one still live
// (EntryLive) at createdAt, the request's CreatedAt (the preparing
// client's clock in whole seconds), minus RecoveryCarrySkew. keyroster
// revoke recover selects the certificates with it, and the signer and
// keyroster audit verify refuse a request that carries any other
// (recovery_certificate_expired). It reads only the signed request, never
// the time the recovery is applied, so a request prepared offline and
// applied hours later is judged as it was prepared. A lost certificate it
// leaves out is expired and needs no revocation; the imported entries of
// its serial or key ID then get ValidBefore 0 and are never pruned
// (RecoveryEntries), the fail-safe outcome.
func CarriesLost(validBefore, createdAt uint64, revoke bool) bool {
	return revoke || EntryLive(validBefore, createdAt-min(createdAt, RecoveryCarrySkew))
}

// ErrRecoveryTooLarge reports a recovery that would derive more than
// MaxRecoveryEntries entries. It is returned before the entries are
// allocated, so an import revoking the serial range [1, 2^64 - 1] is
// refused, not expanded.
var ErrRecoveryTooLarge = errors.New("krl: the recovery would list more than MaxRecoveryEntries entries")

// RecoveredCert is a certificate a recovery carries (03-06b), as its
// callers read it from a verified certificate: its CA key (SSH wire
// format), serial, key ID and valid_before (whole seconds), and whether
// the recovery revokes it.
type RecoveredCert struct {
	CAKey       []byte
	Serial      uint64
	KeyID       string
	ValidBefore uint64
	Revoke      bool
}

// CertLookup returns the certificate with serial in the restored
// issuance: its CA key (SSH wire format), key ID and valid_before (whole
// seconds), or ok false when there is none. The signer looks in its
// issuance table, keyroster audit verify in the log's issue and
// login_issue entries, keyroster revoke recover in the restored export's.
type CertLookup func(serial uint64) (caKey []byte, keyID string, validBefore uint64, ok bool)

// RecoveryEntries is the one rule that derives a recovery's entries (the
// signer, which writes them, and keyroster audit verify, which re-derives
// them, both call it). It returns, in canonical order (kind, CA key bytes,
// serial, key ID, key) and without duplicates:
//
//   - every serial of every certificate section of every import, ranges
//     expanded, under the section's CA key;
//   - one serial entry for each certificate in certs with Revoke, under
//     its own CA key;
//   - every key ID of every certificate section, under the section's CA
//     key;
//   - every explicit key.
//
// A serial entry's ValidBefore is that of the certificate with the same
// serial and CA key among certs, else in lookup, else 0. A key-ID entry's
// is that of the certificate whose serial the key ID names
// (cert.ParseKeyID; D-09: a key ID names one certificate) and whose key ID
// and CA key equal the entry's, among certs, else in lookup, else 0. An
// entry with ValidBefore 0 is never pruned (Prunable), so the recovery
// never makes an entry leave a KRL early.
//
// It refuses an import with a SHA-1 or SHA-256 section (ErrMalformed: this
// installation never publishes one), a carried certificate to revoke with
// serial 0 (ErrMalformed), and a result above MaxRecoveryEntries
// (ErrRecoveryTooLarge), which it counts on the merged serial intervals
// before it expands any of them.
func RecoveryEntries(imports []*Parsed, certs []RecoveredCert, lookup CertLookup) ([]Entry, error) {
	serials := map[string][]SerialRange{} // CA key -> intervals
	keyIDs := map[string]map[string]bool{}
	keys := map[string]bool{}
	for i, p := range imports {
		if p == nil {
			return nil, fmt.Errorf("%w: import %d is missing", ErrMalformed, i)
		}
		if len(p.SHA1) > 0 || len(p.SHA256) > 0 {
			return nil, fmt.Errorf("%w: import %d has a fingerprint section, which this installation never publishes", ErrMalformed, i)
		}
		for _, sec := range p.Certs {
			ca := string(sec.CAKey)
			serials[ca] = append(serials[ca], sec.Serials...)
			for _, id := range sec.KeyIDs {
				if keyIDs[ca] == nil {
					keyIDs[ca] = map[string]bool{}
				}
				keyIDs[ca][id] = true
			}
		}
		for _, k := range p.Keys {
			keys[string(k)] = true
		}
	}
	carried := map[uint64][]RecoveredCert{}
	for _, c := range certs {
		carried[c.Serial] = append(carried[c.Serial], c)
		if !c.Revoke {
			continue
		}
		if c.Serial == 0 || len(c.CAKey) == 0 {
			return nil, fmt.Errorf("%w: a carried certificate to revoke needs a CA key and a serial above 0", ErrMalformed)
		}
		serials[string(c.CAKey)] = append(serials[string(c.CAKey)], SerialRange{c.Serial, c.Serial})
	}

	// Count the result on the merged intervals before anything is
	// expanded.
	cas := slices.Sorted(maps.Keys(serials))
	var n uint64
	add := func(k uint64) error {
		if k > MaxRecoveryEntries || n > MaxRecoveryEntries-k {
			return fmt.Errorf("%w: more than %d entries", ErrRecoveryTooLarge, MaxRecoveryEntries)
		}
		n += k
		return nil
	}
	for _, ca := range cas {
		serials[ca] = mergeRanges(slices.Clone(serials[ca]))
		for _, r := range serials[ca] {
			size := r.Hi - r.Lo
			if size == math.MaxUint64 {
				return nil, fmt.Errorf("%w: more than %d entries", ErrRecoveryTooLarge, MaxRecoveryEntries)
			}
			if err := add(size + 1); err != nil {
				return nil, err
			}
		}
	}
	for _, ids := range keyIDs {
		if err := add(uint64(len(ids))); err != nil {
			return nil, err
		}
	}
	if err := add(uint64(len(keys))); err != nil {
		return nil, err
	}

	// find returns the ValidBefore of the certificate with serial under
	// caKey, among certs, else in lookup, else 0; with matchKeyID, its key
	// ID must be keyID too.
	find := func(caKey []byte, serial uint64, keyID string, matchKeyID bool) uint64 {
		for _, c := range carried[serial] {
			if bytes.Equal(c.CAKey, caKey) && (!matchKeyID || c.KeyID == keyID) {
				return c.ValidBefore
			}
		}
		if lookup != nil {
			if ca, id, vb, ok := lookup(serial); ok && bytes.Equal(ca, caKey) && (!matchKeyID || id == keyID) {
				return vb
			}
		}
		return 0
	}
	out := make([]Entry, 0, n)
	for _, ca := range cas {
		caKey := []byte(ca)
		for _, r := range serials[ca] {
			for s := r.Lo; ; s++ {
				out = append(out, Entry{Kind: EntrySerial, CAKey: caKey, Serial: s, ValidBefore: find(caKey, s, "", false)})
				if s == r.Hi {
					break
				}
			}
		}
	}
	for _, ca := range slices.Sorted(maps.Keys(keyIDs)) {
		caKey := []byte(ca)
		for _, id := range slices.Sorted(maps.Keys(keyIDs[ca])) {
			var vb uint64
			if kid, err := cert.ParseKeyID(id); err == nil {
				vb = find(caKey, kid.Serial, id, true)
			}
			out = append(out, Entry{Kind: EntryKeyID, CAKey: caKey, KeyID: id, ValidBefore: vb})
		}
	}
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		out = append(out, Entry{Kind: EntryKey, Key: []byte(k)})
	}
	return out, nil
}
