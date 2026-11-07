package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/directory"
)

// probeVectorKey is the SSH wire form of the Ed25519 key whose 32 bytes
// all equal fill.
func probeVectorKey(t testing.TB, fill byte) []byte {
	t.Helper()
	pub, err := ssh.NewPublicKey(ed25519.PublicKey(bytes.Repeat([]byte{fill}, ed25519.PublicKeySize)))
	if err != nil {
		t.Fatal(err)
	}
	return pub.Marshal()
}

// probeIssueVector is the fixed probe issue request of the signing vector
// (03-10): installation 0123...cdef, host web1, a host key of bytes 0x11,
// a probe key of bytes 0x22, Negative, valid_for 0, request ID 00..0f,
// created at 1700000000.
func probeIssueVector(t testing.TB) *ProbeIssueRequest {
	t.Helper()
	r := &ProbeIssueRequest{InstallationID: "0123456789abcdef0123456789abcdef", HostName: "web1",
		HostKey: probeVectorKey(t, 0x11), ProbeKey: probeVectorKey(t, 0x22), Negative: true, CreatedAt: 1_700_000_000,
		Evidence: []Evidence{{Type: EvidenceHostPoP, Blob: []byte("host pop (test vector)")},
			{Type: EvidenceProbePoP, Blob: []byte("probe pop (test vector)")}}}
	for i := range r.RequestID {
		r.RequestID[i] = byte(i)
	}
	return r
}

// handProbeSigningBytes assembles the signing bytes of probeIssueVector
// from fixed literals, length prefix by length prefix, without the
// encoder, so the vector can catch an encoding error.
func handProbeSigningBytes(t testing.TB) []byte {
	t.Helper()
	key := func(fill byte) []byte {
		// string "ssh-ed25519", then string of the 32 key bytes.
		var k []byte
		k = binary.BigEndian.AppendUint32(k, 11)
		k = append(k, "ssh-ed25519"...)
		k = binary.BigEndian.AppendUint32(k, 32)
		return append(k, bytes.Repeat([]byte{fill}, 32)...)
	}
	u16 := func(b []byte, v []byte) []byte {
		b = binary.BigEndian.AppendUint16(b, uint16(len(v))) //nolint:gosec // G115: test literals under 64 KiB
		return append(b, v...)
	}
	var b []byte
	b = append(b, "keyroster/probe-issue-request/v1"...)
	b = u16(b, []byte("0123456789abcdef0123456789abcdef"))
	b = u16(b, []byte("web1"))
	b = u16(b, key(0x11))
	b = u16(b, key(0x22))
	b = append(b, 1)                        // Negative
	b = binary.BigEndian.AppendUint32(b, 0) // ValidForSeconds
	for i := range 16 {                     // RequestID
		b = append(b, byte(i))
	}
	return binary.BigEndian.AppendUint64(b, 1_700_000_000) // CreatedAt
}

// TestProbeIssueRequest covers the signing bytes, the evidence count, the
// key rules, the name grammar, strict parsing and the signing vector
// (03-10).
func TestProbeIssueRequest(t *testing.T) {
	t.Run("every_field_bound", func(t *testing.T) {
		base := probeIssueVector(t).SigningBytes()
		for name, edit := range map[string]func(*ProbeIssueRequest){
			"installation_id": func(r *ProbeIssueRequest) { r.InstallationID = "fedcba9876543210fedcba9876543210" },
			"host_name":       func(r *ProbeIssueRequest) { r.HostName = "web2" },
			"host_key":        func(r *ProbeIssueRequest) { r.HostKey = probeVectorKey(t, 0x12) },
			"probe_key":       func(r *ProbeIssueRequest) { r.ProbeKey = probeVectorKey(t, 0x23) },
			"negative":        func(r *ProbeIssueRequest) { r.Negative = false },
			"valid_for":       func(r *ProbeIssueRequest) { r.ValidForSeconds = 1 },
			"request_id":      func(r *ProbeIssueRequest) { r.RequestID[3] ^= 1 },
			"created_at":      func(r *ProbeIssueRequest) { r.CreatedAt++ },
		} {
			r := probeIssueVector(t)
			edit(r)
			if bytes.Equal(r.SigningBytes(), base) {
				t.Errorf("changing %s does not change the signing bytes", name)
			}
		}
		r := probeIssueVector(t)
		r.Evidence[1].Blob = []byte("other")
		if !bytes.Equal(r.SigningBytes(), base) {
			t.Error("the evidence is part of the signing bytes")
		}
	})
	t.Run("two_evidence_exact", func(t *testing.T) {
		for _, n := range []int{0, 1, 3} {
			r := probeIssueVector(t)
			r.Evidence = nil
			for range n {
				r.Evidence = append(r.Evidence, Evidence{Type: EvidenceHostPoP, Blob: []byte("x")})
			}
			if err := r.Validate(); !errors.Is(err, ErrMalformed) {
				t.Errorf("%d evidence items: Validate = %v, want ErrMalformed", n, err)
			}
			if _, err := r.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("%d evidence items: Marshal = %v, want ErrMalformed", n, err)
			}
		}
		if err := probeIssueVector(t).Validate(); err != nil {
			t.Fatalf("two items refused: %v", err)
		}
	})
	t.Run("key_rules", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaPub, err := ssh.NewPublicKey(&rk.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ecPub, err := ssh.NewPublicKey(&ek.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		_, edPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		caSigner, err := ssh.NewSignerFromKey(edPriv)
		if err != nil {
			t.Fatal(err)
		}
		probePub, err := ssh.ParsePublicKey(probeVectorKey(t, 0x22))
		if err != nil {
			t.Fatal(err)
		}
		c, err := cert.Build(cert.Request{Profile: cert.Profile{CertType: ssh.UserCert, MaxTTL: time.Hour}, Subject: probePub,
			Principals: []string{"probe"}, Now: time.Now(), ValidFor: time.Minute, Serial: 1,
			KeyID: cert.KeyID{CA: "machine", Subject: "probe", Request: "000102030405060708090a0b0c0d0e0f", Policy: 1, Serial: 1}}, caSigner, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for name, probe := range map[string][]byte{
			"rsa":           rsaPub.Marshal(),
			"ecdsa":         ecPub.Marshal(),
			"certificate":   c.Marshal(),
			"non_canonical": append(probeVectorKey(t, 0x22), 0), // a trailing byte
			"garbage":       []byte("garbage"),
			"empty":         nil,
		} {
			r := probeIssueVector(t)
			r.ProbeKey = probe
			if err := r.Validate(); !errors.Is(err, ErrMalformed) {
				t.Errorf("probe key %s: Validate = %v, want ErrMalformed", name, err)
			}
		}
		for name, host := range map[string][]byte{"ed25519": probeVectorKey(t, 0x11), "ecdsa": ecPub.Marshal()} {
			r := probeIssueVector(t)
			r.HostKey = host
			if err := r.Validate(); err != nil {
				t.Errorf("host key %s refused: %v", name, err)
			}
		}
		for name, host := range map[string][]byte{"rsa": rsaPub.Marshal(), "certificate": c.Marshal()} {
			r := probeIssueVector(t)
			r.HostKey = host
			if err := r.Validate(); !errors.Is(err, ErrMalformed) {
				t.Errorf("host key %s: Validate = %v, want ErrMalformed", name, err)
			}
		}
		r := probeIssueVector(t)
		r.ValidForSeconds = 7
		if err := r.Validate(); err != nil {
			t.Fatalf("Validate puts a rule on valid_for: %v (the signer refuses it with its own detail)", err)
		}
	})
	t.Run("name_grammar_matches_directory", func(t *testing.T) {
		for _, n := range []string{"web1", "a", "a.b-c_d", "Web1", "-web", "", strings.Repeat("a", 64), strings.Repeat("a", 65), "web 1", "wéb", "web:1"} {
			r := probeIssueVector(t)
			r.HostName = n
			if got := r.Validate() == nil; got != directory.ValidUserName(n) {
				t.Errorf("%q: probe request accepts %t, directory %t", n, got, directory.ValidUserName(n))
			}
		}
	})
	t.Run("round_trip_and_signing_bytes_parse", func(t *testing.T) {
		for _, neg := range []bool{true, false} {
			r := probeIssueVector(t)
			r.Negative = neg
			body, err := r.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseProbeIssueRequest(body)
			if err != nil {
				t.Fatal(err)
			}
			if again, err := got.Marshal(); err != nil || !bytes.Equal(again, body) || got.Negative != neg {
				t.Fatalf("re-marshal differs (%v) or Negative lost", err)
			}
			sb, err := ParseProbeIssueSigningBytes(r.SigningBytes())
			if err != nil || !bytes.Equal(sb.SigningBytes(), r.SigningBytes()) || sb.Evidence != nil || sb.Negative != neg {
				t.Fatalf("ParseProbeIssueSigningBytes: %+v, %v", sb, err)
			}
			if _, err := ParseProbeIssueRequest(append(body, 0)); err == nil {
				t.Fatal("a trailing byte was accepted")
			}
			if _, err := ParseProbeIssueSigningBytes(append(r.SigningBytes(), 0)); err == nil {
				t.Fatal("a trailing byte after the signing bytes was accepted")
			}
		}
		host := hostIssueVector(t)
		if _, err := ParseProbeIssueSigningBytes(host.SigningBytes()); !errors.Is(err, ErrMalformed) {
			t.Fatalf("host issue signing bytes parse as a probe request: %v", err)
		}
	})
	t.Run("negative_byte_strict", func(t *testing.T) {
		sb := probeIssueVector(t).SigningBytes()
		// The Negative byte follows the domain and the four uint16-prefixed
		// fields; it is 1 in the vector.
		off := len(ProbeIssueRequestDomain)
		for range 4 {
			off += 2 + int(binary.BigEndian.Uint16(sb[off:]))
		}
		if sb[off] != 1 {
			t.Fatalf("the Negative byte is not where the format puts it (%#x)", sb[off])
		}
		body, err := probeIssueVector(t).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		bodyOff := off - len(ProbeIssueRequestDomain)
		for _, v := range []byte{2, 0x80, 0xff} {
			bad := bytes.Clone(sb)
			bad[off] = v
			if _, err := ParseProbeIssueSigningBytes(bad); !errors.Is(err, ErrMalformed) {
				t.Errorf("signing bytes with Negative %#x: %v", v, err)
			}
			badBody := bytes.Clone(body)
			badBody[bodyOff] = v
			if _, err := ParseProbeIssueRequest(badBody); !errors.Is(err, ErrMalformed) {
				t.Errorf("a body with Negative %#x: %v", v, err)
			}
		}
	})
	t.Run("signing_vector", func(t *testing.T) {
		want := handProbeSigningBytes(t)
		r := probeIssueVector(t)
		if got := r.SigningBytes(); !bytes.Equal(got, want) {
			t.Fatalf("SigningBytes differ from the hand-built bytes\ngot:  %x\nwant: %x", got, want)
		}
		path := filepath.Join(vectorDir, "probe_issue_request_signing_v1.hex")
		if *update {
			if err := os.WriteFile(path, []byte(hex.EncodeToString(want)+"\n"), 0o644); err != nil { //nolint:gosec // G306: public test vector
				t.Fatal(err)
			}
		}
		file, err := os.ReadFile(path) //nolint:gosec // G304: fixed test vector path
		if err != nil {
			t.Fatalf("%v (create it with -update only for a deliberate format change)", err)
		}
		fromFile, err := hex.DecodeString(strings.TrimSpace(string(file)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(fromFile, want) {
			t.Fatalf("%s differs from the hand-built bytes", path)
		}
		if ProbeIssueRequestDomain != "keyroster/probe-issue-request/v1" || ProbePoPNamespace != ProbeIssueRequestDomain ||
			EvidenceProbePoP != "probe-pop/v1" || TypeProbeIssueRequest != 0x0B {
			t.Fatal("the probe request constants changed")
		}
		if r.Digest() != sha256.Sum256(want) {
			t.Fatal("Digest is not the SHA-256 of the signing bytes")
		}
		got, err := ParseProbeIssueSigningBytes(fromFile)
		if err != nil || got.HostName != "web1" || !got.Negative || got.CreatedAt != 1_700_000_000 {
			t.Fatalf("ParseProbeIssueSigningBytes(vector) = %+v, %v", got, err)
		}
	})
}

// FuzzParseProbeIssueRequest: parse then encode is the identity (03-10).
func FuzzParseProbeIssueRequest(f *testing.F) {
	valid, err := probeIssueVector(f).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseProbeIssueRequest(data)
		if err != nil {
			return
		}
		again, err := r.Marshal()
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("parse then marshal is not the identity (%v)", err)
		}
	})
}

// FuzzParseProbeIssueSigningBytes: parse then encode is the identity
// (03-10).
func FuzzParseProbeIssueSigningBytes(f *testing.F) {
	valid := probeIssueVector(f).SigningBytes()
	f.Add(valid)
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(valid[:len(valid)-1])
	f.Add([]byte(ProbeIssueRequestDomain))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseProbeIssueSigningBytes(data)
		if err != nil {
			return
		}
		if !bytes.Equal(r.SigningBytes(), data) {
			t.Fatal("parse then encode is not the identity")
		}
	})
}
