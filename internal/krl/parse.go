package krl

import (
	"bytes"
	"cmp"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 fingerprints are a PROTOCOL.krl section type, compared, never used for security here
	"crypto/sha256"
	"fmt"
	"math"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"
)

// MaxParsedEntries bounds what Parse accepts: serial intervals (a listed
// serial, a range, or one run of a bitmap), key IDs, explicit keys and
// fingerprints together, counted before each is appended. It is above the
// most entries Encode can fit in MaxKRL (a 1-byte key ID costs 5 bytes, so
// fewer than MaxKRL / 5), so a KRL this package wrote always parses, and a
// bitmap of alternating bits, the densest encoding, is bounded too.
const MaxParsedEntries = 1 << 20

// SerialRange is an interval of revoked serials, Lo <= Hi; a single serial
// is Lo == Hi.
type SerialRange struct {
	Lo, Hi uint64
}

// Parsed is what a KRL revokes, normalised: certificate sections by CA key
// (SSH wire encoding), one per CA key, sorted by it, each with its serials
// as sorted, merged intervals and its key IDs sorted and unique, and the
// explicit keys and the SHA-1 and SHA-256 fingerprints sorted and unique.
// Ranges and bitmap runs stay intervals, never expanded per serial.
type Parsed struct {
	Version       uint64
	GeneratedDate uint64
	Certs         []ParsedSection
	Keys          [][]byte
	SHA1          [][]byte
	SHA256        [][]byte
}

// ParsedSection is one CA key's revoked serials and key IDs.
type ParsedSection struct {
	CAKey   []byte
	Serials []SerialRange
	KeyIDs  []string
}

// parseErr is a Parse refusal: what, wrapped in ErrMalformed.
func parseErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// parser is Parse's state: the entries counted so far and the sections
// read so far, before normalisation.
type parser struct {
	n      int
	certs  map[string]*ParsedSection
	keys   [][]byte
	sha1   [][]byte
	sha256 [][]byte
}

// count admits one more entry, or refuses it above MaxParsedEntries.
func (p *parser) count() error {
	if p.n == MaxParsedEntries {
		return fmt.Errorf("%w: more than %d entries", ErrTooLarge, MaxParsedEntries)
	}
	p.n++
	return nil
}

// Parse reads a KRL strictly (PROTOCOL.krl, format version 1). It refuses
// input above MaxKRL and more than MaxParsedEntries entries (ErrTooLarge),
// and, wrapping ErrMalformed: a wrong magic or format version, non-zero
// flags, a signature section (4), an extension section (255) or subsection
// (0x39), an unknown section or subsection type, a length beyond the
// remaining input, trailing bytes inside a section or subsection, an
// empty, unparsable, non-canonical or certificate CA key or explicit key,
// serial 0, a range with lo > hi, a bitmap that wraps past 2^64 - 1, is
// negative or is above OpenSSH's bignum bound, an empty key ID, a NUL
// inside a key ID or the header comment (a final NUL ends a key ID, as in
// OpenSSH), a fingerprint of the wrong length, and
// fingerprints that are not strictly ascending. It reads the serial list
// (0x20), range (0x21), bitmap (0x22) and key-ID (0x23) subsections and
// the explicit-key (2), SHA-1 (3) and SHA-256 (5) sections, which
// ssh-keygen may write; Encode never writes the bitmap or the fingerprint
// sections. Parse(Encode(s)) equals s.Normalize() for every set Encode
// accepts.
func Parse(data []byte) (*Parsed, error) {
	if len(data) > MaxKRL {
		return nil, fmt.Errorf("%w: %d bytes, above %d", ErrTooLarge, len(data), MaxKRL)
	}
	s := cryptobyte.String(data)
	var (
		out               Parsed
		magic             []byte
		format            uint32
		flags             uint64
		reserved, comment cryptobyte.String
	)
	if !s.ReadBytes(&magic, len(Magic)) || string(magic) != Magic {
		return nil, parseErr("bad magic")
	}
	if !s.ReadUint32(&format) || format != FormatVersion {
		return nil, parseErr("bad format version")
	}
	if !s.ReadUint64(&out.Version) || !s.ReadUint64(&out.GeneratedDate) || !s.ReadUint64(&flags) ||
		!readString32(&s, &reserved) || !readString32(&s, &comment) {
		return nil, parseErr("truncated header (a length beyond the input)")
	}
	if flags != 0 {
		return nil, parseErr("flags %#x (none are defined)", flags)
	}
	if _, err := cString(comment, "the header comment"); err != nil {
		return nil, err
	}
	p := &parser{certs: map[string]*ParsedSection{}}
	for !s.Empty() {
		var (
			typ  uint8
			body cryptobyte.String
		)
		if !s.ReadUint8(&typ) || !readString32(&s, &body) {
			return nil, parseErr("truncated section (a length beyond the input, or trailing bytes)")
		}
		var err error
		switch typ {
		case sectionCertificates:
			err = p.certSection(body)
		case sectionExplicitKey:
			err = p.explicitKeys(body)
		case sectionSHA1:
			err = p.fingerprints(body, sha1Len, &p.sha1)
		case sectionSHA256:
			err = p.fingerprints(body, sha256Len, &p.sha256)
		case sectionSignature:
			err = parseErr("signature section: sshd ignores KRL signatures, the manifest is the integrity check")
		case sectionExtension:
			err = parseErr("extension section")
		default:
			err = parseErr("unknown section type %d", typ)
		}
		if err != nil {
			return nil, err
		}
	}
	for _, sec := range p.certs {
		sec.Serials = mergeRanges(sec.Serials)
		slices.Sort(sec.KeyIDs)
		sec.KeyIDs = slices.Compact(sec.KeyIDs)
		if len(sec.Serials) > 0 || len(sec.KeyIDs) > 0 {
			out.Certs = append(out.Certs, *sec)
		}
	}
	slices.SortFunc(out.Certs, func(a, b ParsedSection) int { return bytes.Compare(a.CAKey, b.CAKey) })
	out.Keys = sortedUnique(p.keys)
	out.SHA1, out.SHA256 = p.sha1, p.sha256
	return &out, nil
}

// certSection reads one certificate section (type 1).
func (p *parser) certSection(body cryptobyte.String) error {
	var ca, reserved cryptobyte.String
	if !readString32(&body, &ca) || !readString32(&body, &reserved) {
		return parseErr("truncated certificate section")
	}
	if len(ca) == 0 {
		return parseErr("a certificate section with no CA key (a wildcard CA) is not accepted")
	}
	if err := checkKey(ca, "CA key"); err != nil {
		return err
	}
	sec := p.certs[string(ca)]
	if sec == nil {
		sec = &ParsedSection{CAKey: bytes.Clone(ca)}
		p.certs[string(ca)] = sec
	}
	for !body.Empty() {
		var (
			typ uint8
			sub cryptobyte.String
		)
		if !body.ReadUint8(&typ) || !readString32(&body, &sub) {
			return parseErr("truncated subsection (a length beyond the input, or trailing bytes)")
		}
		var err error
		switch typ {
		case subSerialList:
			err = p.serialList(sub, sec)
		case subSerialRange:
			err = p.serialRange(sub, sec)
		case subSerialBitmap:
			err = p.serialBitmap(sub, sec)
		case subKeyID:
			err = p.keyIDs(sub, sec)
		case subExtension:
			err = parseErr("certificate extension subsection")
		default:
			err = parseErr("unknown certificate subsection type %#x", typ)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) serialList(sub cryptobyte.String, sec *ParsedSection) error {
	if len(sub)%8 != 0 {
		return parseErr("serial list: trailing bytes")
	}
	for !sub.Empty() {
		var v uint64
		if !sub.ReadUint64(&v) {
			return parseErr("serial list: truncated")
		}
		if v == 0 {
			return parseErr("serial 0 cannot be revoked by serial")
		}
		if err := p.count(); err != nil {
			return err
		}
		sec.Serials = append(sec.Serials, SerialRange{v, v})
	}
	return nil
}

func (p *parser) serialRange(sub cryptobyte.String, sec *ParsedSection) error {
	var lo, hi uint64
	if !sub.ReadUint64(&lo) || !sub.ReadUint64(&hi) || !sub.Empty() {
		return parseErr("serial range: not exactly two serials (trailing bytes or truncated)")
	}
	switch {
	case lo == 0:
		return parseErr("serial 0 cannot be revoked by serial (a range from 0)")
	case lo > hi:
		return parseErr("serial range %d-%d: lo > hi", lo, hi)
	}
	if err := p.count(); err != nil {
		return err
	}
	sec.Serials = append(sec.Serials, SerialRange{lo, hi})
	return nil
}

// serialBitmap reads a bitmap subsection: bit i (from the least
// significant bit of the mpint) set revokes serial offset + i. Every run
// of set bits becomes one interval and counts as one entry.
func (p *parser) serialBitmap(sub cryptobyte.String, sec *ParsedSection) error {
	var (
		offset uint64
		mpint  cryptobyte.String
	)
	if !sub.ReadUint64(&offset) || !readString32(&sub, &mpint) || !sub.Empty() {
		return parseErr("serial bitmap: truncated or trailing bytes")
	}
	if len(mpint) > 0 && mpint[0]&0x80 != 0 {
		return parseErr("serial bitmap is a negative mpint")
	}
	// OpenSSH's bignum rule (sshbuf_get_bignum2_bytes_direct): at most
	// SSHBUF_MAX_BIGNUM bytes, plus one leading zero byte that keeps the
	// sign bit clear.
	if len(mpint) > maxBitmapMpintLength || (len(mpint) == maxBitmapMpintLength && mpint[0] != 0) {
		return parseErr("serial bitmap of %d bytes, above OpenSSH's %d (plus a zero sign byte)", len(mpint), maxBitmapMpintLength-1)
	}
	bits := []byte(mpint)
	for len(bits) > 0 && bits[0] == 0 {
		bits = bits[1:]
	}
	nbits := uint64(len(bits)) * 8
	bit := func(i uint64) bool { return bits[uint64(len(bits))-1-i/8]&(1<<(i%8)) != 0 }
	for i := uint64(0); i < nbits; {
		if !bit(i) {
			i++
			continue
		}
		j := i
		for j+1 < nbits && bit(j+1) {
			j++
		}
		if j > math.MaxUint64-offset {
			return parseErr("serial bitmap wraps past 2^64 - 1")
		}
		lo, hi := offset+i, offset+j
		if lo == 0 {
			return parseErr("serial 0 cannot be revoked by serial (bitmap bit 0 at offset 0)")
		}
		if err := p.count(); err != nil {
			return err
		}
		sec.Serials = append(sec.Serials, SerialRange{lo, hi})
		i = j + 1
	}
	return nil
}

// cString reads b as OpenSSH's sshbuf_get_cstring does for the header
// comment and every key ID: a NUL is allowed only as the last byte, and
// the value ends before it, so "X\x00" is the key ID "X", which sshd and
// ssh-keygen -Q revoke as "X" (they compare key IDs with strcmp). A NUL
// anywhere else is refused, as OpenSSH refuses the whole KRL.
func cString(b []byte, what string) (string, error) {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		if i != len(b)-1 {
			return "", parseErr("%s with a NUL byte inside it (OpenSSH refuses the KRL)", what)
		}
		b = b[:i]
	}
	return string(b), nil
}

func (p *parser) keyIDs(sub cryptobyte.String, sec *ParsedSection) error {
	for !sub.Empty() {
		var id cryptobyte.String
		if !readString32(&sub, &id) {
			return parseErr("key ID subsection: truncated")
		}
		kid, err := cString(id, "a key ID")
		if err != nil {
			return err
		}
		if kid == "" {
			return parseErr("an empty key ID")
		}
		if err := p.count(); err != nil {
			return err
		}
		sec.KeyIDs = append(sec.KeyIDs, kid)
	}
	return nil
}

func (p *parser) explicitKeys(body cryptobyte.String) error {
	for !body.Empty() {
		var blob cryptobyte.String
		if !readString32(&body, &blob) {
			return parseErr("explicit key section: truncated")
		}
		if err := checkKey(blob, "explicit key"); err != nil {
			return err
		}
		if err := p.count(); err != nil {
			return err
		}
		p.keys = append(p.keys, bytes.Clone(blob))
	}
	return nil
}

// fingerprints reads a fingerprint section of hashes of size n, which must
// be strictly ascending across every section of that type, as ssh-keygen
// writes them.
func (p *parser) fingerprints(body cryptobyte.String, n int, out *[][]byte) error {
	for !body.Empty() {
		var h cryptobyte.String
		if !readString32(&body, &h) {
			return parseErr("fingerprint section: truncated")
		}
		if len(h) != n {
			return parseErr("a fingerprint of %d bytes, want %d", len(h), n)
		}
		if k := len(*out); k > 0 && bytes.Compare((*out)[k-1], h) >= 0 {
			return parseErr("fingerprints not strictly ascending (unsorted or duplicated)")
		}
		if err := p.count(); err != nil {
			return err
		}
		*out = append(*out, bytes.Clone(h))
	}
	return nil
}

// checkKey requires blob to be a plain public key in canonical SSH wire
// encoding.
func checkKey(blob []byte, what string) error {
	k, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return parseErr("%s does not parse: %v", what, err)
	}
	if _, isCert := k.(*ssh.Certificate); isCert {
		return parseErr("%s is a certificate", what)
	}
	if !bytes.Equal(k.Marshal(), blob) {
		return parseErr("%s is not canonically encoded", what)
	}
	return nil
}

// readString32 reads a uint32-length-prefixed string whose length is
// checked against the remaining input before it is used.
func readString32(s *cryptobyte.String, out *cryptobyte.String) bool {
	var n uint32
	if !s.ReadUint32(&n) || uint64(n) > uint64(len(*s)) {
		return false
	}
	var b []byte
	if !s.ReadBytes(&b, int(n)) {
		return false
	}
	*out = b
	return true
}

// mergeRanges sorts rs and merges overlapping and adjacent intervals.
func mergeRanges(rs []SerialRange) []SerialRange {
	slices.SortFunc(rs, func(a, b SerialRange) int { return cmp.Or(cmp.Compare(a.Lo, b.Lo), cmp.Compare(a.Hi, b.Hi)) })
	var out []SerialRange
	for _, r := range rs {
		if k := len(out); k > 0 && (out[k-1].Hi == math.MaxUint64 || r.Lo <= out[k-1].Hi+1) {
			out[k-1].Hi = max(out[k-1].Hi, r.Hi)
			continue
		}
		out = append(out, r)
	}
	return out
}

func sortedUnique(bs [][]byte) [][]byte {
	slices.SortFunc(bs, bytes.Compare)
	return slices.CompactFunc(bs, bytes.Equal)
}

// Normalize returns what s revokes in Parse's normalised form, with
// Version and GeneratedDate 0: Parse(Encode(s)) has the same content.
func (s Set) Normalize() *Parsed {
	byCA := map[string]*ParsedSection{}
	for _, c := range s.Certs {
		if c.CAKey == nil {
			continue
		}
		k := string(c.CAKey.Marshal())
		sec := byCA[k]
		if sec == nil {
			sec = &ParsedSection{CAKey: []byte(k)}
			byCA[k] = sec
		}
		for _, v := range c.Serials {
			sec.Serials = append(sec.Serials, SerialRange{v, v})
		}
		sec.KeyIDs = append(sec.KeyIDs, c.KeyIDs...)
	}
	out := &Parsed{}
	for _, sec := range byCA {
		sec.Serials = mergeRanges(sec.Serials)
		slices.Sort(sec.KeyIDs)
		sec.KeyIDs = slices.Compact(sec.KeyIDs)
		if len(sec.Serials) > 0 || len(sec.KeyIDs) > 0 {
			out.Certs = append(out.Certs, *sec)
		}
	}
	slices.SortFunc(out.Certs, func(a, b ParsedSection) int { return bytes.Compare(a.CAKey, b.CAKey) })
	for _, k := range s.Keys {
		if k != nil {
			out.Keys = append(out.Keys, k.Marshal())
		}
	}
	out.Keys = sortedUnique(out.Keys)
	return out
}

// SameContent reports whether p and q revoke exactly the same entries,
// whatever their Version and GeneratedDate.
func (p *Parsed) SameContent(q *Parsed) bool {
	if len(p.Certs) != len(q.Certs) || !slices.EqualFunc(p.Keys, q.Keys, bytes.Equal) ||
		!slices.EqualFunc(p.SHA1, q.SHA1, bytes.Equal) || !slices.EqualFunc(p.SHA256, q.SHA256, bytes.Equal) {
		return false
	}
	for i := range p.Certs {
		a, b := p.Certs[i], q.Certs[i]
		if !bytes.Equal(a.CAKey, b.CAKey) || !slices.Equal(a.Serials, b.Serials) || !slices.Equal(a.KeyIDs, b.KeyIDs) {
			return false
		}
	}
	return true
}

// section returns the certificate section of caKey (SSH wire encoding).
func (p *Parsed) section(caKey []byte) *ParsedSection {
	i, ok := slices.BinarySearchFunc(p.Certs, caKey, func(s ParsedSection, k []byte) int { return bytes.Compare(s.CAKey, k) })
	if !ok {
		return nil
	}
	return &p.Certs[i]
}

// RevokesSerial reports whether p revokes the certificate with serial
// signed by caKey (SSH wire encoding).
func (p *Parsed) RevokesSerial(caKey []byte, serial uint64) bool {
	sec := p.section(caKey)
	if sec == nil {
		return false
	}
	i, _ := slices.BinarySearchFunc(sec.Serials, serial, func(r SerialRange, v uint64) int {
		switch {
		case r.Hi < v:
			return -1
		case r.Lo > v:
			return 1
		}
		return 0
	})
	return i < len(sec.Serials) && sec.Serials[i].Lo <= serial && serial <= sec.Serials[i].Hi
}

// RevokesKeyID reports whether p revokes the certificates with keyID
// signed by caKey (SSH wire encoding).
func (p *Parsed) RevokesKeyID(caKey []byte, keyID string) bool {
	sec := p.section(caKey)
	if sec == nil {
		return false
	}
	_, ok := slices.BinarySearch(sec.KeyIDs, keyID)
	return ok
}

// RevokesKey reports whether p revokes the plain key key (SSH wire
// encoding) explicitly or by its SHA-1 or SHA-256 fingerprint.
func (p *Parsed) RevokesKey(key []byte) bool {
	if _, ok := slices.BinarySearchFunc(p.Keys, key, bytes.Compare); ok {
		return true
	}
	h1 := sha1.Sum(key) //nolint:gosec // G401: the PROTOCOL.krl SHA-1 section is matched, not trusted
	if _, ok := slices.BinarySearchFunc(p.SHA1, h1[:], bytes.Compare); ok {
		return true
	}
	h256 := sha256.Sum256(key)
	_, ok := slices.BinarySearchFunc(p.SHA256, h256[:], bytes.Compare)
	return ok
}
