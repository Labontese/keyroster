package tlog

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/mod/sumdb/note"
)

// Fixed test keys: the RFC 8032 section 7.1 TEST 1 Ed25519 secret key and
// the RFC 6979 appendix A.2.5 P-256 private key.
const (
	testEd25519Seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	testP256D       = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
)

func testEd25519Signer(t testing.TB) ssh.Signer {
	t.Helper()
	seed, err := hex.DecodeString(testEd25519Seed)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testP256Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	d, err := hex.DecodeString(testP256D)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testP256Signer(t testing.TB) ssh.Signer {
	t.Helper()
	s, err := ssh.NewSignerFromKey(testP256Key(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestEd25519InteropWithSumdbNote: our Ed25519 note signer and verifier
// agree with x/mod's own Ed25519 implementation in both directions.
func TestEd25519InteropWithSumdbNote(t *testing.T) {
	s := testEd25519Signer(t)
	name := Origin(s.PublicKey())
	ours, err := NewNoteSigner(name, s)
	if err != nil {
		t.Fatal(err)
	}
	vkey, err := note.NewEd25519VerifierKey(name, s.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatal(err)
	}
	if ours.KeyHash() != theirs.KeyHash() {
		t.Fatalf("key hash %08x, x/mod %08x", ours.KeyHash(), theirs.KeyHash())
	}
	msg, err := note.Sign(&note.Note{Text: "hello\n"}, ours)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(msg, note.VerifierList(theirs)); err != nil {
		t.Fatalf("x/mod rejects our signature: %v", err)
	}

	skey, vk, err := note.GenerateKey(rand.Reader, "example.com/x")
	if err != nil {
		t.Fatal(err)
	}
	xs, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(vk[strings.LastIndex(vk, "+")+1:])
	if err != nil || raw[0] != SigTypeEd25519 {
		t.Fatalf("vkey %q", vk)
	}
	pub, err := ssh.NewPublicKey(ed25519.PublicKey(raw[1:]))
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewNoteVerifier("example.com/x", pub)
	if err != nil {
		t.Fatal(err)
	}
	msg, err = note.Sign(&note.Note{Text: "from x/mod\n"}, xs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(msg, note.VerifierList(v)); err != nil {
		t.Fatalf("our verifier rejects x/mod's signature: %v", err)
	}
}

// Real ECDSA (type 0x02) checkpoints from github.com/transparency-dev/formats
// note/note_verifier_test.go (Apache-2.0): the Sigstore Rekor log key and
// the Pixel 6 transparency log key with one checkpoint each.
var ecdsaVectors = []struct {
	name, keyHash, keyMaterial, note string
}{
	{
		"rekor.sigstore.dev", "c0d23d6a",
		"AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNhtmPtrWm3U1eQXBogSMdGvXwBcK5AW5i0hrZLOC96l+smGNM7nwZ4QvFK/4sueRoVj//QP22Ni4Qt9DPfkWLc=",
		"Rekor\n798034\nf+7CoKgXKE/tNys9TTXcr/ad6U/K3xvznmzew9y6SP0=\n\n— rekor.sigstore.dev wNI9ajBEAiARInWIWyCdyG27CO6LPnPekyw20qO0YJfoaPaowGp/XgIgc+qEHS3+GKVClgqq20uDLet7MCoTURUCRdxwWBHHufk=\n",
	},
	{
		"pixel6_transparency_log", "91c16e30",
		"AjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN+4x0Jk1yTwvLFI9A4NDdGZcX0aiWVdWM5XJVy0M4VWD3AvyW5Q6Hs9A0mcDkpUoYgn+KKPNzFC0H3nN3q6JQ8=",
		"DEFAULT\n10\nbsWRucJU5xJPHb5eBdOm6+DM+VelCZBuvtI3sHERJ9Y=\n\n— pixel6_transparency_log kcFuMDBFAiEAhqMAP8P6qf6QxtUJhzMhbN+MbZ9dwfUHzGQJmffJHtoCIGD0cNe47dHWBoPwYdgBCepB06/+g5O1FmYjXl06owL4\n",
	},
}

// TestECDSAVerifierMatchesPublishedVectors checks the C2SP type 0x02 key ID
// (truncated SHA-256 of the SPKI DER) and signature (ASN.1 DER over
// SHA-256) against checkpoints signed by real logs.
func TestECDSAVerifierMatchesPublishedVectors(t *testing.T) {
	for _, vec := range ecdsaVectors {
		t.Run(vec.name, func(t *testing.T) {
			raw, err := base64.StdEncoding.DecodeString(vec.keyMaterial)
			if err != nil || raw[0] != SigTypeECDSA {
				t.Fatalf("key material: %v", err)
			}
			k, err := x509.ParsePKIXPublicKey(raw[1:])
			if err != nil {
				t.Fatal(err)
			}
			pub, err := ssh.NewPublicKey(k)
			if err != nil {
				t.Fatal(err)
			}
			v, err := NewNoteVerifier(vec.name, pub)
			if err != nil {
				t.Fatal(err)
			}
			if got := strconv.FormatUint(uint64(v.KeyHash()), 16); got != vec.keyHash {
				t.Fatalf("key hash %s, want %s", got, vec.keyHash)
			}
			if _, err := note.Open([]byte(vec.note), note.VerifierList(v)); err != nil {
				t.Fatalf("published checkpoint does not verify: %v", err)
			}
			tampered := strings.Replace(vec.note, "\n", "1\n", 2) // change the tree size
			if _, err := note.Open([]byte(tampered), note.VerifierList(v)); err == nil {
				t.Fatal("tampered checkpoint verified")
			}
		})
	}
}

// independentECDSAVerify checks a type 0x02 note signature line the way the
// C2SP spec and transparency-dev/witness define it, without our code.
func independentECDSAVerify(t *testing.T, pub *ecdsa.PublicKey, name string, msg []byte) bool {
	t.Helper()
	text, sigs, ok := bytes.Cut(msg, []byte("\n\n"))
	if !ok {
		return false
	}
	text = append(text, '\n')
	line := strings.TrimSuffix(string(sigs), "\n")
	b64, ok := strings.CutPrefix(line, "— "+name+" ")
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(sig) < 5 {
		return false
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(der)
	if binary.BigEndian.Uint32(sig[:4]) != binary.BigEndian.Uint32(h[:4]) {
		return false
	}
	digest := sha256.Sum256(text)
	return ecdsa.VerifyASN1(pub, digest[:], sig[4:])
}

func TestECDSANoteSigner(t *testing.T) {
	key := testP256Key(t)
	s := testP256Signer(t)
	name := Origin(s.PublicKey())
	ns, err := NewNoteSigner(name, s)
	if err != nil {
		t.Fatalf("NewNoteSigner(P-256): %v", err)
	}
	msg, err := note.Sign(&note.Note{Text: "a\nb\n"}, ns)
	if err != nil {
		t.Fatal(err)
	}
	if !independentECDSAVerify(t, &key.PublicKey, name, msg) {
		t.Fatalf("independent verifier rejects our ECDSA note:\n%s", msg)
	}
	v, err := NewNoteVerifier(name, s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(msg, note.VerifierList(v)); err != nil {
		t.Fatal(err)
	}
}

// TestCheckpointGolden pins one signed checkpoint per log key algorithm.
// Ed25519 signatures are deterministic, so the bytes must match; ECDSA
// signatures are randomized, so the golden note must verify (with our
// verifier and an independent one) and carry the expected text and key ID.
func TestCheckpointGolden(t *testing.T) {
	root := make([]byte, 32)
	for i := range root {
		root[i] = byte(0xa0 + i)
	}
	cases := []struct {
		file   string
		signer func(testing.TB) ssh.Signer
		exact  bool
	}{
		{"checkpoint_ed25519.golden", testEd25519Signer, true},
		{"checkpoint_ecdsa_p256.golden", testP256Signer, false},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			s := tc.signer(t)
			cp := Checkpoint{Origin: Origin(s.PublicKey()), Size: 3, Root: root}
			ns, err := NewNoteSigner(cp.Origin, s)
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := SignCheckpoint(cp, ns)
			if err != nil {
				t.Fatal(err)
			}
			if *update {
				writeGolden(t, tc.file, fresh)
			}
			golden := readGolden(t, tc.file)
			if tc.exact && !bytes.Equal(fresh, golden) {
				t.Fatalf("signed checkpoint differs from %s:\n got %q\nwant %q", tc.file, fresh, golden)
			}
			v, err := NewNoteVerifier(cp.Origin, s.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			got, err := OpenCheckpoint(golden, v)
			if err != nil {
				t.Fatalf("golden checkpoint does not verify: %v", err)
			}
			if got.Text() != cp.Text() || !strings.HasPrefix(string(golden), cp.Text()+"\n— "+cp.Origin+" ") {
				t.Fatalf("golden checkpoint text %q, want %q", golden, cp.Text())
			}
			if !tc.exact && !independentECDSAVerify(t, &testP256Key(t).PublicKey, cp.Origin, golden) {
				t.Fatal("independent verifier rejects the golden ECDSA checkpoint")
			}
		})
	}
}

func TestOpenCheckpointRejects(t *testing.T) {
	s := testEd25519Signer(t)
	origin := Origin(s.PublicKey())
	ns, err := NewNoteSigner(origin, s)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewNoteVerifier(origin, s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	root := base64.StdEncoding.EncodeToString(make([]byte, 32))
	signText := func(text string) []byte {
		msg, err := note.Sign(&note.Note{Text: text}, ns)
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}
	other := testP256Signer(t)
	otherSigner, err := NewNoteSigner(origin, other)
	if err != nil {
		t.Fatal(err)
	}
	otherMsg, err := note.Sign(&note.Note{Text: origin + "\n1\n" + root + "\n"}, otherSigner)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"other_key":        otherMsg,
		"extension_line":   signText(origin + "\n1\n" + root + "\next\n"),
		"leading_zero":     signText(origin + "\n01\n" + root + "\n"),
		"short_root":       signText(origin + "\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, 31)) + "\n"),
		"other_origin":     signText("keyroster/log/0000000000000000\n1\n" + root + "\n"),
		"two_lines":        signText(origin + "\n1\n"),
		"oversize":         append(signText(origin+"\n1\n"+root+"\n"), make([]byte, MaxCheckpoint)...),
		"unsigned_garbage": []byte("not a note"),
	}
	for name, msg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenCheckpoint(msg, v); err == nil {
				t.Fatalf("OpenCheckpoint accepted %q", msg)
			}
		})
	}
	if _, err := OpenCheckpoint(signText(origin+"\n1\n"+root+"\n"), v); err != nil {
		t.Fatalf("valid checkpoint refused: %v", err)
	}
}

// badSigner returns signatures that do not verify.
type badSigner struct{ ssh.Signer }

func (b badSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	sig, err := b.Signer.Sign(r, data)
	if err != nil {
		return nil, err
	}
	sig.Blob = append([]byte(nil), sig.Blob...)
	sig.Blob[len(sig.Blob)-1] ^= 1
	return sig, nil
}

func TestNoteSignerRefusesBadSignatures(t *testing.T) {
	for _, s := range []ssh.Signer{testEd25519Signer(t), testP256Signer(t)} {
		t.Run(s.PublicKey().Type(), func(t *testing.T) {
			ns, err := NewNoteSigner("example.com/log", badSigner{s})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ns.Sign([]byte("x\n")); err == nil {
				t.Fatal("a signature that does not verify was returned")
			}
		})
	}
}

func TestNoteKeyRestrictions(t *testing.T) {
	s := testEd25519Signer(t)
	for _, name := range []string{"", "a b", "a+b", "a\nb"} {
		if _, err := NewNoteVerifier(name, s.PublicKey()); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewNoteVerifier("example.com/log", pub); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("P-384 log key: %v, want ErrUnsupportedKey", err)
	}
}
