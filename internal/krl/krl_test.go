package krl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/sshsig"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

var update = flag.Bool("update", false, "rewrite the golden vectors in test/vectors")

func vectorPath(name string) string { return filepath.Join("..", "..", "test", "vectors", name) }

// seedKey returns the Ed25519 key whose seed is the 32 bytes first,
// first+1, ... (mod 256), and its SSH public key.
func seedKey(t testing.TB, first byte) (ed25519.PrivateKey, ssh.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = first + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// parsedKRL is the structure of a KRL as this test reads it back: the
// header fields and, per certificate section, the CA key, the subsection
// types in order, the listed serials and the ranges.
type parsedKRL struct {
	version, generated, flags uint64
	sections                  []parsedSection
}

type parsedSection struct {
	typ      byte
	caKey    []byte
	subtypes []byte
	list     []uint64
	ranges   [][2]uint64
}

// parseKRL reads data strictly as the subset of PROTOCOL.krl Encode
// writes; anything else fails the test.
func parseKRL(t *testing.T, data []byte) parsedKRL {
	t.Helper()
	s := cryptobyte.String(data)
	var (
		p                 parsedKRL
		magic             []byte
		format            uint32
		reserved, comment cryptobyte.String
	)
	if !s.ReadBytes(&magic, 8) || string(magic) != Magic || !s.ReadUint32(&format) || format != FormatVersion ||
		!s.ReadUint64(&p.version) || !s.ReadUint64(&p.generated) || !s.ReadUint64(&p.flags) ||
		!readString(&s, &reserved) || !readString(&s, &comment) || len(reserved) != 0 || len(comment) != 0 {
		t.Fatalf("bad KRL header: %x", data[:min(len(data), 64)])
	}
	for !s.Empty() {
		var (
			sec  parsedSection
			body cryptobyte.String
		)
		if !s.ReadUint8(&sec.typ) || !readString(&s, &body) {
			t.Fatal("bad section")
		}
		var ca, res cryptobyte.String
		if !readString(&body, &ca) || !readString(&body, &res) || len(res) != 0 {
			t.Fatal("bad certificate section header")
		}
		sec.caKey = append([]byte(nil), ca...)
		for !body.Empty() {
			var (
				st  byte
				sub cryptobyte.String
			)
			if !body.ReadUint8(&st) || !readString(&body, &sub) {
				t.Fatal("bad subsection")
			}
			sec.subtypes = append(sec.subtypes, st)
			switch st {
			case subSerialList:
				for !sub.Empty() {
					var v uint64
					if !sub.ReadUint64(&v) {
						t.Fatal("bad serial list")
					}
					sec.list = append(sec.list, v)
				}
			case subSerialRange:
				var lo, hi uint64
				if !sub.ReadUint64(&lo) || !sub.ReadUint64(&hi) || !sub.Empty() {
					t.Fatal("bad serial range")
				}
				sec.ranges = append(sec.ranges, [2]uint64{lo, hi})
			default:
				t.Fatalf("unexpected subsection type %#x", st)
			}
		}
		p.sections = append(p.sections, sec)
	}
	return p
}

func readString(s *cryptobyte.String, out *cryptobyte.String) bool {
	var n uint32
	var b []byte
	if !s.ReadUint32(&n) || !s.ReadBytes(&b, int(n)) {
		return false
	}
	*out = b
	return true
}

var testTime = time.Unix(1700000000, 0)

// TestEncode covers the REVOKE-02 edges of the encoder: adjacency,
// duplicates, insertion order, the empty set, serial 0 and section order.
func TestEncode(t *testing.T) {
	_, caA := seedKey(t, 0x00)
	_, caB := seedKey(t, 0x20)
	enc := func(t *testing.T, s Set) []byte {
		t.Helper()
		out, err := Encode(s, 7, testTime)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	one := func(ca ssh.PublicKey, serials ...uint64) Set {
		return Set{Certs: []CertSection{{CAKey: ca, Serials: serials}}}
	}

	t.Run("adjacent_serials_one_range", func(t *testing.T) {
		p := parseKRL(t, enc(t, one(caA, 5, 6)))
		if len(p.sections) != 1 || !bytes.Equal(p.sections[0].subtypes, []byte{subSerialRange}) ||
			!slices.Equal(p.sections[0].ranges, [][2]uint64{{5, 6}}) {
			t.Fatalf("{5, 6} encodes as %+v, want one 0x21 range [5, 6]", p.sections)
		}
	})
	t.Run("duplicate_serial_once", func(t *testing.T) {
		p := parseKRL(t, enc(t, Set{Certs: []CertSection{{CAKey: caA, Serials: []uint64{5, 5}}, {CAKey: caA, Serials: []uint64{5}}}}))
		if len(p.sections) != 1 || !slices.Equal(p.sections[0].list, []uint64{5}) || len(p.sections[0].ranges) != 0 {
			t.Fatalf("{5, 5} (twice, one CA) encodes as %+v, want one serial 5", p.sections)
		}
	})
	t.Run("insertion_order_identical", func(t *testing.T) {
		a := enc(t, one(caA, 9, 5, 6, 12))
		b := enc(t, one(caA, 12, 6, 9, 5))
		if !bytes.Equal(a, b) {
			t.Fatalf("{9, 5, 6, 12} and {12, 6, 9, 5} encode differently:\n%x\n%x", a, b)
		}
		p := parseKRL(t, a)
		sec := p.sections[0]
		// The single serials come first, in one list, then the ranges.
		if !bytes.Equal(sec.subtypes, []byte{subSerialList, subSerialRange}) || !slices.Equal(sec.list, []uint64{9, 12}) ||
			!slices.Equal(sec.ranges, [][2]uint64{{5, 6}}) {
			t.Fatalf("{5, 6, 9, 12} encodes as %+v", sec)
		}
		c := enc(t, Set{Certs: []CertSection{{CAKey: caB, Serials: []uint64{3}}, {CAKey: caA, Serials: []uint64{1}}}})
		d := enc(t, Set{Certs: []CertSection{{CAKey: caA, Serials: []uint64{1}}, {CAKey: caB, Serials: []uint64{3}}}})
		if !bytes.Equal(c, d) {
			t.Fatal("the CA order of the input changes the encoding")
		}
	})
	t.Run("empty_set_header_only", func(t *testing.T) {
		for _, s := range []Set{{}, one(caA)} {
			out := enc(t, s)
			p := parseKRL(t, out)
			if len(out) != 44 || len(p.sections) != 0 || p.version != 7 || p.generated != 1700000000 || p.flags != 0 {
				t.Fatalf("empty set: %d bytes, %+v; want the 44-byte header alone", len(out), p)
			}
		}
	})
	t.Run("serial_zero_refused", func(t *testing.T) {
		if _, err := Encode(one(caA, 4, 0), 1, testTime); !errors.Is(err, ErrMalformed) {
			t.Fatalf("serial 0: %v, want ErrMalformed", err)
		}
	})
	t.Run("nil_ca_refused", func(t *testing.T) {
		if _, err := Encode(Set{Certs: []CertSection{{Serials: []uint64{1}}}}, 1, testTime); !errors.Is(err, ErrMalformed) {
			t.Fatalf("nil CA key: %v, want ErrMalformed", err)
		}
	})
	t.Run("two_ca_sections_ordered", func(t *testing.T) {
		p := parseKRL(t, enc(t, Set{Certs: []CertSection{{CAKey: caB, Serials: []uint64{1}}, {CAKey: caA, Serials: []uint64{2}}}}))
		if len(p.sections) != 2 || bytes.Compare(p.sections[0].caKey, p.sections[1].caKey) >= 0 {
			t.Fatalf("two CA keys: %d sections, want 2 ordered by wire bytes", len(p.sections))
		}
		for _, sec := range p.sections {
			if sec.typ != sectionCertificates {
				t.Fatalf("section type %d: only certificate sections are written (no signature, extension or bitmap)", sec.typ)
			}
		}
	})
	t.Run("header_fields", func(t *testing.T) {
		out := enc(t, one(caA, 1))
		if !bytes.HasPrefix(out, []byte("SSHKRL\n\x00")) || hex.EncodeToString(out[:8]) != "5353484b524c0a00" ||
			binary.BigEndian.Uint32(out[8:12]) != 1 {
			t.Fatalf("header %x", out[:12])
		}
		if _, err := Encode(one(caA, 1), 1, time.Unix(-5, 0)); err != nil {
			t.Fatalf("a generated date before the epoch: %v", err)
		}
	})
}

// TestEncodeSizeBound: the largest set of non-adjacent serials under one
// Ed25519 CA key that fits MaxKRL encodes; one more serial is ErrTooLarge.
// The count comes from the sizes: the 44-byte header, the section type and
// length (5), the CA key string (4 + 51), the reserved string (4), the list
// subsection type and length (5) and 8 bytes per serial.
func TestEncodeSizeBound(t *testing.T) {
	_, ca := seedKey(t, 0x40)
	keyLen := len(ca.Marshal())
	fixed := 44 + 5 + 4 + keyLen + 4 + 5
	n := (MaxKRL - fixed) / 8
	serials := make([]uint64, n+1)
	for i := range serials {
		serials[i] = 2 * uint64(i+1) // never adjacent: one list
	}
	t.Run("encode_at_max", func(t *testing.T) {
		out, err := Encode(Set{Certs: []CertSection{{CAKey: ca, Serials: serials[:n]}}}, 1, testTime)
		if err != nil {
			t.Fatalf("%d serials: %v", n, err)
		}
		if len(out) != fixed+8*n || len(out) > MaxKRL || len(out)+8 <= MaxKRL {
			t.Fatalf("%d serials encode to %d bytes; want %d, within MaxKRL and the largest that fits", n, len(out), fixed+8*n)
		}
	})
	t.Run("encode_over_max_refused", func(t *testing.T) {
		if _, err := Encode(Set{Certs: []CertSection{{CAKey: ca, Serials: serials}}}, 1, testTime); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("%d serials: %v, want ErrTooLarge", n+1, err)
		}
	})
}

// TestKRLConstantsMatch: the size bounds that wire and tlog repeat (they
// do not import krl) equal krl's, and MaxKRLResponse is the documented
// arithmetic, above the 4 MiB cap of every other route.
func TestKRLConstantsMatch(t *testing.T) {
	if MaxKRL != wire.MaxKRLBytes || MaxManifest != tlog.MaxManifest || MaxManifestSig != tlog.MaxManifestSig {
		t.Fatalf("MaxKRL %d / wire %d, MaxManifest %d / tlog %d, MaxManifestSig %d / tlog %d",
			MaxKRL, wire.MaxKRLBytes, MaxManifest, tlog.MaxManifest, MaxManifestSig, tlog.MaxManifestSig)
	}
	if MaxKRLResponse != 5_620_744 || MaxKRLResponse <= 4<<20 {
		t.Fatalf("MaxKRLResponse = %d, want 5 620 744 (> 4 MiB)", MaxKRLResponse)
	}
	// wire's own manifest and signature caps: a GetKRLResponse of the
	// largest legal content marshals, one byte more of either is refused.
	full := &wire.GetKRLResponse{KRL: make([]byte, MaxKRL), Manifest: make([]byte, MaxManifest), Sig: make([]byte, MaxManifestSig)}
	if _, err := full.Marshal(); err != nil {
		t.Fatalf("maximum GetKRLResponse: %v", err)
	}
	for name, r := range map[string]*wire.GetKRLResponse{
		"manifest": {KRL: []byte{1}, Manifest: make([]byte, MaxManifest+1), Sig: []byte{1}},
		"sig":      {KRL: []byte{1}, Manifest: []byte{1}, Sig: make([]byte, MaxManifestSig+1)},
		"krl":      {KRL: make([]byte, MaxKRL+1), Manifest: []byte{1}, Sig: []byte{1}},
	} {
		if _, err := r.Marshal(); err == nil {
			t.Errorf("GetKRLResponse with a %s one byte above its cap marshals", name)
		}
	}
}

// goldenVector compares got with the named file in test/vectors (rewritten
// under -update).
func goldenVector(t *testing.T, name string, got []byte) []byte {
	t.Helper()
	if *update {
		if err := os.WriteFile(vectorPath(name), got, 0o644); err != nil { //nolint:gosec // G306: public test vector
			t.Fatal(err)
		}
	}
	file, err := os.ReadFile(vectorPath(name)) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		t.Fatalf("%v (create it with -update only for a deliberate format change)", err)
	}
	if !bytes.Equal(got, file) {
		t.Fatalf("%s differs from the encoding\ngot:  %q\nwant: %q", name, got, file)
	}
	return file
}

// TestKRLGoldenVector pins the KRL encoding (krl_serials_v1.hex: CA keys
// from seeds 0x00.. and 0x20.., serials {5, 6, 9} under the first and {9}
// under the second, version 1, generated 1700000000) and the manifest
// format (krl_manifest_v1.json).
func TestKRLGoldenVector(t *testing.T) {
	_, caA := seedKey(t, 0x00)
	_, caB := seedKey(t, 0x20)
	data, err := Encode(Set{Certs: []CertSection{{CAKey: caA, Serials: []uint64{5, 6, 9}}, {CAKey: caB, Serials: []uint64{9}}}}, 1, testTime)
	if err != nil {
		t.Fatal(err)
	}
	file := goldenVector(t, "krl_serials_v1.hex", []byte(hex.EncodeToString(data)+"\n"))
	if !strings.HasPrefix(string(file), "5353484b524c0a00") {
		t.Fatalf("krl_serials_v1.hex does not start with the KRL magic: %.16s", file)
	}
	m := &Manifest{
		InstallationID: "000102030405060708090a0b0c0d0e0f",
		KRLVersion:     1,
		KRLSHA256:      SHA256Hex(data),
		IssuedAt:       "2023-11-14T22:13:20Z",
		BundleVersion:  4,
		LogIndex:       42,
	}
	doc, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	goldenVector(t, "krl_manifest_v1.json", doc)
	back, err := ParseManifest(doc)
	if err != nil || *back != *m {
		t.Fatalf("ParseManifest(golden) = %+v, %v", back, err)
	}
}

// FuzzEncodeKRL: any set the fuzzer derives (at most 64 serials over two
// fixed CA keys) encodes without panic and deterministically, its
// encoding parses as written, and a set holding serial 0 is refused.
func FuzzEncodeKRL(f *testing.F) {
	f.Add([]byte{5, 0, 6, 0, 9, 1, 12, 1})
	f.Add([]byte{})
	f.Add([]byte{0, 0})
	f.Add([]byte{255, 1, 254, 1, 253, 0})
	f.Add([]byte{'a', 4, 'b', 5, 'a', 4, 1, 8, 2, 9, 1, 8}) // key IDs under both CAs, explicit keys twice
	_, caA := seedKey(f, 0x00)
	_, caB := seedKey(f, 0x20)
	var keys []ssh.PublicKey
	for i := range 4 {
		_, k := seedKey(f, byte(0x40+i))
		keys = append(keys, k)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var set Set
		set.Certs = []CertSection{{CAKey: caA}, {CAKey: caB}}
		zero, other := false, false
		for i := 0; i+1 < len(data) && i < 128; i += 2 {
			switch flags := data[i+1]; {
			case flags&8 != 0: // an explicit key
				set.Keys = append(set.Keys, keys[data[i]%4])
				other = true
			case flags&4 != 0: // a one-letter key ID
				set.Certs[flags&1].KeyIDs = append(set.Certs[flags&1].KeyIDs, string(rune('a'+data[i]%26)))
				other = true
			default:
				ser := uint64(data[i])
				if flags&2 != 0 {
					ser |= uint64(flags) << 56 // far serials too
				}
				zero = zero || ser == 0
				set.Certs[flags&1].Serials = append(set.Certs[flags&1].Serials, ser)
			}
		}
		a, errA := Encode(set, 3, testTime)
		b, errB := Encode(set, 3, testTime)
		if zero {
			if !errors.Is(errA, ErrMalformed) {
				t.Fatalf("a set with serial 0: %v, want ErrMalformed", errA)
			}
			return
		}
		if errA != nil || errB != nil {
			t.Fatalf("Encode: %v / %v", errA, errB)
		}
		if !bytes.Equal(a, b) {
			t.Fatal("Encode is not deterministic")
		}
		if !other {
			parseKRL(t, a) // the 03-01 reader of serial-only KRLs
		}
		p, err := Parse(a)
		if err != nil || !p.SameContent(set.Normalize()) {
			t.Fatalf("Parse(Encode(s)) = %+v, %v; want the content of s", p, err)
		}
	})
}

// manifestFixture is a published KRL version signed by an ops key, with
// the bundle that names that key.
type manifestFixture struct {
	ops, root, ca ssh.Signer
	bundle        *trust.Bundle
	krl           []byte
	manifest      []byte
	sig           []byte
}

const pinnedID = "00112233445566778899aabbccddeeff"

func newManifestFixture(t *testing.T) *manifestFixture {
	t.Helper()
	signer := func(first byte) ssh.Signer {
		priv, _ := seedKey(t, first)
		s, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	f := &manifestFixture{ops: signer(0x60), root: signer(0x80), ca: signer(0xa0)}
	f.bundle = &trust.Bundle{OpsKey: trust.KeyEntry{Key: trust.FormatKey(f.ops.PublicKey())}, InstallationID: pinnedID}
	var err error
	if f.krl, err = Encode(Set{Certs: []CertSection{{CAKey: f.ca.PublicKey(), Serials: []uint64{3}}}}, 2, testTime); err != nil {
		t.Fatal(err)
	}
	f.manifest = f.manifestFor(t, &Manifest{InstallationID: pinnedID, KRLVersion: 2, KRLSHA256: SHA256Hex(f.krl), IssuedAt: "2023-11-14T22:13:20Z", BundleVersion: 1, LogIndex: 7})
	f.sig = f.sign(t, f.ops, Namespace, f.manifest)
	return f
}

func (f *manifestFixture) manifestFor(t *testing.T, m *Manifest) []byte {
	t.Helper()
	doc, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func (f *manifestFixture) sign(t *testing.T, s ssh.Signer, ns string, doc []byte) []byte {
	t.Helper()
	sig, err := sshsig.Sign(rand.Reader, s, ns, doc)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// TestVerifyManifest (REVOKE-03, D-04): the ops key's signature under
// keyroster/krl/v1 over a manifest for the pinned installation, a version
// above the stored one and the KRL's SHA-256 verifies; every other key,
// namespace, installation, version and KRL byte is refused with its own
// sentinel.
func TestVerifyManifest(t *testing.T) {
	f := newManifestFixture(t)
	t.Run("ops_key_accepted", func(t *testing.T) {
		m, err := VerifyManifest(f.manifest, f.sig, f.krl, f.bundle, pinnedID, 1)
		if err != nil || m.KRLVersion != 2 || m.InstallationID != pinnedID {
			t.Fatalf("VerifyManifest = %+v, %v", m, err)
		}
	})
	flipped := bytes.Clone(f.krl)
	flipped[len(flipped)-1] ^= 1
	for _, tc := range []struct {
		name     string
		sig, krl []byte
		manifest []byte
		id       string
		stored   uint64
		wantErr  error
	}{
		{"root_key_refused", f.sign(t, f.root, Namespace, f.manifest), f.krl, f.manifest, pinnedID, 1, ErrSigner},
		{"ca_key_refused", f.sign(t, f.ca, Namespace, f.manifest), f.krl, f.manifest, pinnedID, 1, ErrSigner},
		{"other_namespace_refused", f.sign(t, f.ops, "keyroster/other/v1", f.manifest), f.krl, f.manifest, pinnedID, 1, ErrSignature},
		{"other_installation_refused", f.sig, f.krl, f.manifest, "ffeeddccbbaa99887766554433221100", 1, ErrInstallation},
		{"no_pinned_installation_refused", f.sig, f.krl, f.manifest, "", 1, ErrInstallation},
		{"version_equal_to_stored_refused", f.sig, f.krl, f.manifest, pinnedID, 2, ErrVersion},
		{"flipped_bit_refused", f.sig, flipped, f.manifest, pinnedID, 1, ErrDigest},
		{"signature_over_other_bytes_refused", f.sign(t, f.ops, Namespace, []byte("other")), f.krl, f.manifest, pinnedID, 1, ErrSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyManifest(tc.manifest, tc.sig, tc.krl, f.bundle, tc.id, tc.stored); !errors.Is(err, tc.wantErr) {
				t.Fatalf("VerifyManifest: %v, want %v", err, tc.wantErr)
			}
		})
	}
	t.Run("non_canonical_manifest_refused", func(t *testing.T) {
		spaced := append([]byte(" "), f.manifest...)
		if _, err := VerifyManifest(spaced, f.sign(t, f.ops, Namespace, spaced), f.krl, f.bundle, pinnedID, 1); !errors.Is(err, ErrManifest) {
			t.Fatalf("a non-canonical manifest: %v, want ErrManifest", err)
		}
	})
}

// TestManifestSizeBounds: ParseManifest refuses MaxManifest+1 bytes and
// VerifyManifest refuses a signature of MaxManifestSig+1 bytes, each
// before any decoding, and KRL bytes above MaxKRL.
func TestManifestSizeBounds(t *testing.T) {
	f := newManifestFixture(t)
	big := append(bytes.Clone(f.manifest), bytes.Repeat([]byte(" "), MaxManifest+1-len(f.manifest))...)
	if _, err := ParseManifest(big); !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), "above") {
		t.Fatalf("ParseManifest(MaxManifest+1 bytes): %v, want the size refusal", err)
	}
	sig := bytes.Repeat([]byte("x"), MaxManifestSig+1)
	if _, err := VerifyManifest(f.manifest, sig, f.krl, f.bundle, pinnedID, 1); !errors.Is(err, ErrSignature) || !strings.Contains(err.Error(), "above") {
		t.Fatalf("VerifyManifest(signature of MaxManifestSig+1 bytes): %v, want the size refusal", err)
	}
	if _, err := VerifyManifest(f.manifest, f.sig, make([]byte, MaxKRL+1), f.bundle, pinnedID, 1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("VerifyManifest(KRL of MaxKRL+1 bytes): %v, want ErrTooLarge", err)
	}
}

// rawKRL builds KRL bytes by hand for the Parse refusal cases: the header
// with version 1, generated 0, flags and the given comment, then each
// section as given (type byte and body, length-prefixed by sec).
type rawSection struct {
	typ  byte
	body []byte
}

func rawKRL(flags uint64, sections ...rawSection) []byte {
	var b cryptobyte.Builder
	b.AddBytes([]byte(Magic))
	b.AddUint32(FormatVersion)
	b.AddUint64(1)
	b.AddUint64(0)
	b.AddUint64(flags)
	b.AddUint32LengthPrefixed(func(*cryptobyte.Builder) {})
	b.AddUint32LengthPrefixed(func(*cryptobyte.Builder) {})
	for _, s := range sections {
		b.AddUint8(s.typ)
		b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(s.body) })
	}
	return b.BytesOrPanic()
}

// certBody is a certificate section body for ca with the given
// subsections (type, data).
func certBody(ca []byte, subs ...rawSection) []byte {
	var b cryptobyte.Builder
	b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ca) })
	b.AddUint32LengthPrefixed(func(*cryptobyte.Builder) {})
	for _, s := range subs {
		b.AddUint8(s.typ)
		b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(s.body) })
	}
	return b.BytesOrPanic()
}

func u64s(vs ...uint64) []byte {
	out := make([]byte, 0, 8*len(vs))
	for _, v := range vs {
		out = binary.BigEndian.AppendUint64(out, v)
	}
	return out
}

func strings32(vs ...[]byte) []byte {
	var b cryptobyte.Builder
	for _, v := range vs {
		b.AddUint32LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(v) })
	}
	return b.BytesOrPanic()
}

// bitmapBody is a bitmap subsection body: offset and the mpint bits.
func bitmapBody(offset uint64, mpint []byte) []byte {
	return append(u64s(offset), strings32(mpint)...)
}

// alternatingBitmap is an mpint of n bytes 0x55 (bits 0, 2, 4, 6 of every
// byte set): 4n runs, the densest bitmap.
func alternatingBitmap(n int) []byte { return bytes.Repeat([]byte{0x55}, n) }

// TestParse (REVOKE-03, T-03-15, T-03-204): Parse refuses every malformed
// or unsupported input with ErrMalformed, and too large input or too many
// entries with ErrTooLarge, each a named case; it accepts the subsections
// ssh-keygen may write that Encode never does.
func TestParse(t *testing.T) {
	_, ca := seedKey(t, 0x00)
	caKey := ca.Marshal()
	valid := rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialList, u64s(5)})})
	if _, err := Parse(valid); err != nil {
		t.Fatalf("the control KRL does not parse: %v", err)
	}
	h1, h2 := sha256.Sum256([]byte("a")), sha256.Sum256([]byte("b"))
	lo, hi := h1[:], h2[:]
	if bytes.Compare(lo, hi) > 0 {
		lo, hi = hi, lo
	}
	header := rawKRL(0)
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"too_large", append(bytes.Clone(valid), make([]byte, MaxKRL)...), ErrTooLarge},
		{"bad_magic", append([]byte("SSHKRL\n\x01"), valid[8:]...), ErrMalformed},
		{"bad_format_version", append(append(bytes.Clone(valid[:8]), 0, 0, 0, 2), valid[12:]...), ErrMalformed},
		{"bad_flags", rawKRL(1), ErrMalformed},
		{"signature_section", rawKRL(0, rawSection{sectionSignature, strings32([]byte("sig"))}), ErrMalformed},
		{"extension_section", rawKRL(0, rawSection{sectionExtension, strings32([]byte("ext"), nil)}), ErrMalformed},
		{"extension_subsection", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subExtension, strings32([]byte("ext"), nil)})}), ErrMalformed},
		{"unknown_section", rawKRL(0, rawSection{6, nil}), ErrMalformed},
		{"unknown_subsection", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{0x24, nil})}), ErrMalformed},
		{"trailing_bytes", append(bytes.Clone(valid), 0x01), ErrMalformed},
		{"trailing_bytes_in_range", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialRange, append(u64s(1, 2), 0)})}), ErrMalformed},
		{"trailing_bytes_in_list", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialList, append(u64s(1), 0)})}), ErrMalformed},
		{"serial_zero", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialList, u64s(0)})}), ErrMalformed},
		{"serial_zero_range", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialRange, u64s(0, 3)})}), ErrMalformed},
		{"serial_zero_bitmap", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialBitmap, bitmapBody(0, []byte{0x01})})}), ErrMalformed},
		{"range_lo_gt_hi", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialRange, u64s(9, 8)})}), ErrMalformed},
		{"bitmap_wraps", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialBitmap, bitmapBody(math.MaxUint64, []byte{0x03})})}), ErrMalformed},
		{"bitmap_negative", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialBitmap, bitmapBody(1, []byte{0x80})})}), ErrMalformed},
		{"unsorted_sha256", rawKRL(0, rawSection{sectionSHA256, strings32(hi, lo)}), ErrMalformed},
		{"duplicated_sha256", rawKRL(0, rawSection{sectionSHA256, strings32(lo, lo)}), ErrMalformed},
		{"sha256_wrong_length", rawKRL(0, rawSection{sectionSHA256, strings32(lo[:31])}), ErrMalformed},
		{"length_beyond_input", append(bytes.Clone(header), sectionCertificates, 0, 0, 0x10, 0, 1, 2, 3), ErrMalformed},
		{"string_length_beyond_input", rawKRL(0, rawSection{sectionCertificates, append([]byte{0, 0, 1, 0}, caKey...)}), ErrMalformed},
		{"wildcard_ca", rawKRL(0, rawSection{sectionCertificates, certBody(nil, rawSection{subKeyID, strings32([]byte("id"))})}), ErrMalformed},
		{"ca_key_unparsable", rawKRL(0, rawSection{sectionCertificates, certBody([]byte("not a key"), rawSection{subSerialList, u64s(5)})}), ErrMalformed},
		{"empty_key_id", rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subKeyID, strings32(nil)})}), ErrMalformed},
		{"explicit_key_unparsable", rawKRL(0, rawSection{sectionExplicitKey, strings32([]byte("not a key"))}), ErrMalformed},
		{"truncated_header", valid[:20], ErrMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.data)
			if p != nil || !errors.Is(err, tc.want) {
				t.Fatalf("Parse = %+v, %v; want %v", p, err, tc.want)
			}
			t.Logf("refused: %v", err)
		})
	}
	t.Run("entry_cap", func(t *testing.T) {
		// 16 bitmaps of 16384 bytes of alternating bits are 16 × 65536 =
		// MaxParsedEntries runs, at disjoint offsets: accepted. One more
		// serial is refused, before it is appended.
		var subs []rawSection
		for i := range 16 {
			subs = append(subs, rawSection{subSerialBitmap, bitmapBody(uint64(1+i)<<20, alternatingBitmap(16384))}) //nolint:gosec // G115: small test offsets
		}
		full := rawKRL(0, rawSection{sectionCertificates, certBody(caKey, subs...)})
		if len(full) > MaxKRL {
			t.Fatalf("the test KRL is %d bytes, above MaxKRL", len(full))
		}
		p, err := Parse(full)
		if err != nil {
			t.Fatalf("MaxParsedEntries entries: %v", err)
		}
		if n := len(p.Certs[0].Serials); n != MaxParsedEntries {
			t.Fatalf("%d intervals, want %d", n, MaxParsedEntries)
		}
		over := rawKRL(0, rawSection{sectionCertificates, certBody(caKey, append(subs, rawSection{subSerialList, u64s(3)})...)})
		if _, err := Parse(over); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("MaxParsedEntries + 1 entries: %v, want ErrTooLarge", err)
		}
	})
	t.Run("range_not_expanded", func(t *testing.T) {
		data := rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialRange, u64s(1, math.MaxUint64)})})
		p, err := Parse(data)
		if err != nil || len(p.Certs) != 1 || !slices.Equal(p.Certs[0].Serials, []SerialRange{{1, math.MaxUint64}}) {
			t.Fatalf("Parse = %+v, %v; want the one interval [1, 2^64 - 1]", p, err)
		}
		if !p.RevokesSerial(caKey, math.MaxUint64) || !p.RevokesSerial(caKey, 1) || p.RevokesSerial(caKey, 0) {
			t.Fatal("RevokesSerial disagrees with the interval")
		}
		if allocs := testing.AllocsPerRun(20, func() { _, _ = Parse(data) }); allocs > 30 {
			t.Fatalf("Parse of one full range allocates %.0f times, want a small constant", allocs)
		}
	})
	t.Run("bitmap_runs_are_intervals", func(t *testing.T) {
		// 0b0111_0101 at offset 100: bits 0, 2, 4, 5, 6 -> 100, 102, 104-106.
		data := rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialBitmap, bitmapBody(100, []byte{0x00, 0x75})})})
		p, err := Parse(data)
		want := []SerialRange{{100, 100}, {102, 102}, {104, 106}}
		if err != nil || !slices.Equal(p.Certs[0].Serials, want) {
			t.Fatalf("Parse = %+v, %v; want %v", p, err, want)
		}
		// A dense bitmap counts each run toward MaxParsedEntries: 4 × 16384
		// runs from one 16 KiB subsection.
		p, err = Parse(rawKRL(0, rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialBitmap, bitmapBody(1, alternatingBitmap(16384))})}))
		if err != nil || len(p.Certs[0].Serials) != 4*16384 {
			t.Fatalf("dense bitmap: %v, %d intervals", err, len(p.Certs[0].Serials))
		}
	})
	t.Run("encoder_max_under_cap", func(t *testing.T) {
		// The cheapest entry Encode writes is a 1-byte key ID: a 4-byte
		// length and the byte. Even a KRL of nothing else holds fewer than
		// MaxKRL / 5 entries.
		const cheapest = 4 + 1
		if most := MaxKRL / cheapest; most >= MaxParsedEntries {
			t.Fatalf("Encode can fit %d entries in MaxKRL, not below MaxParsedEntries %d", most, MaxParsedEntries)
		}
		// Every 1-byte printable key ID under one CA key: 5 bytes each.
		var ids []string
		for c := byte(0x21); c < 0x7f; c++ {
			ids = append(ids, string([]byte{c}))
		}
		data, err := Encode(Set{Certs: []CertSection{{CAKey: ca, KeyIDs: ids}}}, 1, testTime)
		if err != nil {
			t.Fatal(err)
		}
		empty, err := Encode(Set{Certs: []CertSection{{CAKey: ca, KeyIDs: ids[:1]}}}, 1, testTime)
		if err != nil {
			t.Fatal(err)
		}
		if per := (len(data) - len(empty)) / (len(ids) - 1); per != cheapest {
			t.Fatalf("a 1-byte key ID costs %d bytes, want %d", per, cheapest)
		}
	})
	t.Run("ssh_keygen_sections_accepted", func(t *testing.T) {
		_, key := seedKey(t, 0x60)
		h := sha256.Sum256(key.Marshal())
		data := rawKRL(0,
			rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialBitmap, bitmapBody(7, []byte{0x05})})},
			rawSection{sectionSHA256, strings32(h[:])},
			rawSection{sectionCertificates, certBody(caKey, rawSection{subSerialList, u64s(20, 8)}, rawSection{subKeyID, strings32([]byte("b"), []byte("a"), []byte("b"))})},
		)
		p, err := Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Certs) != 1 || !slices.Equal(p.Certs[0].Serials, []SerialRange{{7, 9}, {20, 20}}) || !slices.Equal(p.Certs[0].KeyIDs, []string{"a", "b"}) {
			t.Fatalf("sections of one CA key not merged and normalised: %+v", p.Certs)
		}
		if !p.RevokesKey(key.Marshal()) || !p.RevokesKeyID(caKey, "a") || p.RevokesKeyID(caKey, "c") || p.RevokesSerial(caKey, 10) {
			t.Fatal("Revokes* disagrees with the parsed sections")
		}
	})
}

// TestParseRoundTrip (REVOKE-03): Parse(Encode(s)) has exactly the content
// of s.Normalize() for random sets over two CA keys with serials (runs
// included), key IDs and explicit keys, listed in any order and with
// duplicates.
func TestParseRoundTrip(t *testing.T) {
	_, caA := seedKey(t, 0x00)
	_, caB := seedKey(t, 0x20)
	keys := make([]ssh.PublicKey, 4)
	for i := range keys {
		_, keys[i] = seedKey(t, byte(0x40+i))
	}
	for i := range 50 {
		s := randomSet(t, []ssh.PublicKey{caA, caB}, keys, 1+i*4)
		data, err := Encode(s, uint64(i+1), testTime) //nolint:gosec // G115: a small test version
		if err != nil {
			t.Fatal(err)
		}
		p, err := Parse(data)
		if err != nil {
			t.Fatalf("set %d: Parse(Encode(s)): %v", i, err)
		}
		if p.Version != uint64(i+1) || p.GeneratedDate != uint64(testTime.Unix()) || !p.SameContent(s.Normalize()) { //nolint:gosec // G115: test values
			t.Fatalf("set %d: Parse(Encode(s)) = %+v, want the content of %+v", i, p, s.Normalize())
		}
	}
}

// randomSet is a random set of up to n entries over cas and keys: serials
// below 64 (so runs and duplicates occur), key IDs of a few letters and
// explicit keys, each possibly listed twice.
func randomSet(t *testing.T, cas, keys []ssh.PublicKey, n int) Set {
	t.Helper()
	r := func(m int) int {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(m)))
		if err != nil {
			t.Fatal(err)
		}
		return int(v.Int64())
	}
	var s Set
	for range r(n) + 1 {
		ca := cas[r(len(cas))]
		switch r(3) {
		case 0:
			s.Certs = append(s.Certs, CertSection{CAKey: ca, Serials: []uint64{uint64(1 + r(63))}}) //nolint:gosec // G115: small
		case 1:
			s.Certs = append(s.Certs, CertSection{CAKey: ca, KeyIDs: []string{string([]byte{"abcdef"[r(6)]})}})
		default:
			s.Keys = append(s.Keys, keys[r(len(keys))])
		}
	}
	return s
}

// TestEncodeOrdering (REVOKE-02 edge: ordering): a set with two CA keys,
// serials, key IDs and explicit keys encodes to identical bytes in three
// insertion orders.
func TestEncodeOrdering(t *testing.T) {
	_, caA := seedKey(t, 0x00)
	_, caB := seedKey(t, 0x20)
	_, k1 := seedKey(t, 0x40)
	_, k2 := seedKey(t, 0x41)
	orders := []Set{
		{Certs: []CertSection{{CAKey: caA, Serials: []uint64{9, 5, 6}, KeyIDs: []string{"y", "x"}}, {CAKey: caB, KeyIDs: []string{"x"}}}, Keys: []ssh.PublicKey{k1, k2}},
		{Certs: []CertSection{{CAKey: caB, KeyIDs: []string{"x"}}, {CAKey: caA, KeyIDs: []string{"x"}}, {CAKey: caA, Serials: []uint64{6, 5, 9}, KeyIDs: []string{"y"}}}, Keys: []ssh.PublicKey{k2, k1}},
		{Keys: []ssh.PublicKey{k2, k1, k2}, Certs: []CertSection{{CAKey: caA, Serials: []uint64{5}}, {CAKey: caB, KeyIDs: []string{"x", "x"}}, {CAKey: caA, Serials: []uint64{9, 6}, KeyIDs: []string{"x", "y"}}}},
	}
	var first []byte
	for i, s := range orders {
		data, err := Encode(s, 4, testTime)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = data
			continue
		}
		if !bytes.Equal(data, first) {
			t.Fatalf("insertion order %d encodes differently:\n%x\n%x", i, data, first)
		}
	}
	if _, err := Encode(Set{Keys: []ssh.PublicKey{&ssh.Certificate{Key: k1}}}, 1, testTime); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a certificate as explicit key: %v, want ErrMalformed", err)
	}
	if _, err := Encode(Set{Certs: []CertSection{{CAKey: caA, KeyIDs: []string{""}}}}, 1, testTime); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an empty key ID: %v, want ErrMalformed", err)
	}
}

// TestEntryLive (F9): the one liveness rule, in whole seconds, at both
// sides of the 300 s margin and without overflow.
func TestEntryLive(t *testing.T) {
	const vb = 1_800_000_000
	for _, tc := range []struct {
		name        string
		validBefore uint64
		at          uint64
		want        bool
	}{
		{"before_margin_live", vb, vb + 299, true},
		{"at_margin_not_live", vb, vb + 300, false},
		{"after_margin_not_live", vb, vb + 301, false},
		{"before_valid_before_live", vb, vb - 1, true},
		{"infinity_live", math.MaxUint64, math.MaxUint64, true},
		{"near_infinity_live", math.MaxUint64 - 299, math.MaxUint64, true},
		{"unknown_not_live", 0, 1_800_000_000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EntryLive(tc.validBefore, tc.at); got != tc.want {
				t.Fatalf("EntryLive(%d, %d) = %v, want %v", tc.validBefore, tc.at, got, tc.want)
			}
		})
	}
}

// TestPrunable: the one pruning rule; an unknown ValidBefore (0) is never
// prunable.
func TestPrunable(t *testing.T) {
	const vb = 1_800_000_000
	for _, tc := range []struct {
		name        string
		validBefore uint64
		at          uint64
		want        bool
	}{
		{"unknown_never", 0, math.MaxUint64, false},
		{"at_margin_prunable", vb, vb + 300, true},
		{"before_margin_kept", vb, vb + 299, false},
		{"infinity_kept", math.MaxUint64, math.MaxUint64, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Prunable(tc.validBefore, tc.at); got != tc.want {
				t.Fatalf("Prunable(%d, %d) = %v, want %v", tc.validBefore, tc.at, got, tc.want)
			}
		})
	}
}

// TestPublishSetPrune: a serial entry issued at ValidBefore + 300 is left
// out (equality prunes), at ValidBefore + 299 kept; a key ID entry the
// same; an explicit key stays whatever the time and its ValidBefore.
func TestPublishSetPrune(t *testing.T) {
	_, ca := seedKey(t, 0x00)
	_, key := seedKey(t, 0x40)
	const vb = 1_800_000_000
	entries := []Entry{
		{Kind: EntrySerial, CAKey: ca.Marshal(), Serial: 5, ValidBefore: vb},
		{Kind: EntryKeyID, CAKey: ca.Marshal(), KeyID: "id", ValidBefore: vb},
		{Kind: EntryKey, Key: key.Marshal(), ValidBefore: vb},
	}
	kept, err := PublishSet(entries, vb+299)
	if err != nil {
		t.Fatal(err)
	}
	if p := kept.Normalize(); !p.RevokesSerial(ca.Marshal(), 5) || !p.RevokesKeyID(ca.Marshal(), "id") || !p.RevokesKey(key.Marshal()) {
		t.Fatalf("at ValidBefore + 299: %+v, want every entry", p)
	}
	pruned, err := PublishSet(entries, vb+300)
	if err != nil {
		t.Fatal(err)
	}
	if p := pruned.Normalize(); len(p.Certs) != 0 || !p.RevokesKey(key.Marshal()) {
		t.Fatalf("at ValidBefore + 300: %+v, want only the explicit key", p)
	}
	if _, err := PublishSet([]Entry{{Kind: 9}}, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an unknown kind: %v, want ErrMalformed", err)
	}
	if _, err := PublishSet([]Entry{{Kind: EntrySerial, CAKey: []byte("x"), Serial: 1}}, 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("an unparsable CA key: %v, want ErrMalformed", err)
	}
}

// TestPublishSetDuplicates (PR #60 review): duplicated entries (a serial
// twice under one CA key, a key ID twice with one copy prunable and one
// with ValidBefore 0, an explicit key twice) encode to the bytes of the
// deduplicated set, and the key ID stays because its ValidBefore-0 copy is
// never prunable.
func TestPublishSetDuplicates(t *testing.T) {
	_, ca := seedKey(t, 0x00)
	_, key := seedKey(t, 0x40)
	const at = 1_800_000_000
	dup, err := PublishSet([]Entry{
		{Kind: EntrySerial, CAKey: ca.Marshal(), Serial: 5, ValidBefore: at},
		{Kind: EntrySerial, CAKey: ca.Marshal(), Serial: 5, ValidBefore: at},
		{Kind: EntryKeyID, CAKey: ca.Marshal(), KeyID: "id", ValidBefore: at - 300},
		{Kind: EntryKeyID, CAKey: ca.Marshal(), KeyID: "id"},
		{Kind: EntryKey, Key: key.Marshal()},
		{Kind: EntryKey, Key: key.Marshal()},
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Encode(dup, 3, testTime)
	if err != nil {
		t.Fatal(err)
	}
	want, err := Encode(Set{Certs: []CertSection{{CAKey: ca, Serials: []uint64{5}, KeyIDs: []string{"id"}}}, Keys: []ssh.PublicKey{key}}, 3, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("duplicated entries encode differently from the deduplicated set:\n%x\n%x", got, want)
	}
	// Two CertSections of one CA key, as PublishSet's callers may pass.
	two, err := Encode(Set{Certs: []CertSection{{CAKey: ca, Serials: []uint64{5}}, {CAKey: ca, KeyIDs: []string{"id"}}}, Keys: []ssh.PublicKey{key, key}}, 3, testTime)
	if err != nil || !bytes.Equal(two, want) {
		t.Fatalf("two sections of one CA key encode differently: %v", err)
	}
}

// TestKRLFullGoldenVector pins the encoding of every section and
// subsection Encode writes: two CA keys from fixed seeds, serials
// {5, 6, 9}, key IDs and one explicit key, version 1. Rewrite it with
// -update only for a deliberate format change.
func TestKRLFullGoldenVector(t *testing.T) {
	_, caA := seedKey(t, 0x00)
	_, caB := seedKey(t, 0x20)
	_, key := seedKey(t, 0x40)
	s := Set{
		Certs: []CertSection{
			{CAKey: caA, Serials: []uint64{5, 6, 9}, KeyIDs: []string{"kr1/ca=user/sub=alice/req=000102030405060708090a0b0c0d0e0f/pol=1/ser=7"}},
			{CAKey: caB, KeyIDs: []string{"kr2/ca=user/sub=bob/req=101112131415161718191a1b1c1d1e1f/pol=1/dir=1/roles=ops/ser=8"}},
		},
		Keys: []ssh.PublicKey{key},
	}
	data, err := Encode(s, 1, testTime)
	if err != nil {
		t.Fatal(err)
	}
	file := goldenVector(t, "krl_full_v1.hex", []byte(hex.EncodeToString(data)+"\n"))
	want, err := hex.DecodeString(strings.TrimSpace(string(file)))
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("KRL differs from krl_full_v1.hex (%v)", err)
	}
	p, err := Parse(want)
	if err != nil || !p.SameContent(s.Normalize()) {
		t.Fatalf("Parse of the golden vector: %+v, %v", p, err)
	}
}
