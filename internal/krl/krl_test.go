package krl

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
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
		return Set{Certs: []CertSerials{{CAKey: ca, Serials: serials}}}
	}

	t.Run("adjacent_serials_one_range", func(t *testing.T) {
		p := parseKRL(t, enc(t, one(caA, 5, 6)))
		if len(p.sections) != 1 || !bytes.Equal(p.sections[0].subtypes, []byte{subSerialRange}) ||
			!slices.Equal(p.sections[0].ranges, [][2]uint64{{5, 6}}) {
			t.Fatalf("{5, 6} encodes as %+v, want one 0x21 range [5, 6]", p.sections)
		}
	})
	t.Run("duplicate_serial_once", func(t *testing.T) {
		p := parseKRL(t, enc(t, Set{Certs: []CertSerials{{CAKey: caA, Serials: []uint64{5, 5}}, {CAKey: caA, Serials: []uint64{5}}}}))
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
		c := enc(t, Set{Certs: []CertSerials{{CAKey: caB, Serials: []uint64{3}}, {CAKey: caA, Serials: []uint64{1}}}})
		d := enc(t, Set{Certs: []CertSerials{{CAKey: caA, Serials: []uint64{1}}, {CAKey: caB, Serials: []uint64{3}}}})
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
		if _, err := Encode(Set{Certs: []CertSerials{{Serials: []uint64{1}}}}, 1, testTime); !errors.Is(err, ErrMalformed) {
			t.Fatalf("nil CA key: %v, want ErrMalformed", err)
		}
	})
	t.Run("two_ca_sections_ordered", func(t *testing.T) {
		p := parseKRL(t, enc(t, Set{Certs: []CertSerials{{CAKey: caB, Serials: []uint64{1}}, {CAKey: caA, Serials: []uint64{2}}}}))
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
		out, err := Encode(Set{Certs: []CertSerials{{CAKey: ca, Serials: serials[:n]}}}, 1, testTime)
		if err != nil {
			t.Fatalf("%d serials: %v", n, err)
		}
		if len(out) != fixed+8*n || len(out) > MaxKRL || len(out)+8 <= MaxKRL {
			t.Fatalf("%d serials encode to %d bytes; want %d, within MaxKRL and the largest that fits", n, len(out), fixed+8*n)
		}
	})
	t.Run("encode_over_max_refused", func(t *testing.T) {
		if _, err := Encode(Set{Certs: []CertSerials{{CAKey: ca, Serials: serials}}}, 1, testTime); !errors.Is(err, ErrTooLarge) {
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
	data, err := Encode(Set{Certs: []CertSerials{{CAKey: caA, Serials: []uint64{5, 6, 9}}, {CAKey: caB, Serials: []uint64{9}}}}, 1, testTime)
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
	_, caA := seedKey(f, 0x00)
	_, caB := seedKey(f, 0x20)
	f.Fuzz(func(t *testing.T, data []byte) {
		var set Set
		set.Certs = []CertSerials{{CAKey: caA}, {CAKey: caB}}
		zero := false
		for i := 0; i+1 < len(data) && i < 128; i += 2 {
			ser := uint64(data[i])
			if data[i+1]&2 != 0 {
				ser |= uint64(data[i+1]) << 56 // far serials too
			}
			zero = zero || ser == 0
			set.Certs[data[i+1]&1].Serials = append(set.Certs[data[i+1]&1].Serials, ser)
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
		parseKRL(t, a)
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
	if f.krl, err = Encode(Set{Certs: []CertSerials{{CAKey: f.ca.PublicKey(), Serials: []uint64{3}}}}, 2, testTime); err != nil {
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
