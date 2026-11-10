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

// machineIssueVector is the fixed machine issue request of the signing
// vector (03-11): installation 0123...cdef, machine ci, an Ed25519 key of
// bytes 0x33, valid_for 0, request ID 00..0f, created at 1700000000.
func machineIssueVector(t testing.TB) *MachineIssueRequest {
	t.Helper()
	r := &MachineIssueRequest{InstallationID: "0123456789abcdef0123456789abcdef", MachineName: "ci",
		MachineKey: probeVectorKey(t, 0x33), CreatedAt: 1_700_000_000,
		Evidence: []Evidence{{Type: EvidenceMachinePoP, Blob: []byte("machine pop (test vector)")}}}
	for i := range r.RequestID {
		r.RequestID[i] = byte(i)
	}
	return r
}

// handMachineSigningBytes assembles the signing bytes of
// machineIssueVector from fixed literals, without the encoder.
func handMachineSigningBytes() []byte {
	u16 := func(b []byte, v []byte) []byte {
		b = binary.BigEndian.AppendUint16(b, uint16(len(v))) //nolint:gosec // G115: test literals under 64 KiB
		return append(b, v...)
	}
	var k []byte
	k = binary.BigEndian.AppendUint32(k, 11)
	k = append(k, "ssh-ed25519"...)
	k = binary.BigEndian.AppendUint32(k, 32)
	k = append(k, bytes.Repeat([]byte{0x33}, 32)...)
	var b []byte
	b = append(b, "keyroster/machine-issue-request/v1"...)
	b = u16(b, []byte("0123456789abcdef0123456789abcdef"))
	b = u16(b, []byte("ci"))
	b = u16(b, k)
	b = binary.BigEndian.AppendUint32(b, 0) // ValidForSeconds
	for i := range 16 {                     // RequestID
		b = append(b, byte(i))
	}
	return binary.BigEndian.AppendUint64(b, 1_700_000_000) // CreatedAt
}

// sshString is an SSH wire string: a uint32 length, then the bytes.
func sshString(b []byte, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v))) //nolint:gosec // G115: test literals
	return append(b, v...)
}

// machineTestKeys returns the SSH wire form of one key of every type a
// machine request accepts.
func machineTestKeys(t *testing.T) map[string][]byte {
	t.Helper()
	keys := map[string][]byte{"ed25519": probeVectorKey(t, 0x44)}
	for name, curve := range map[string]elliptic.Curve{"nistp256": elliptic.P256(), "nistp384": elliptic.P384(), "nistp521": elliptic.P521()} {
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		keys["ecdsa-"+name] = pub.Marshal()
	}
	var sk []byte
	sk = sshString(sk, []byte(ssh.KeyAlgoSKED25519))
	sk = sshString(sk, bytes.Repeat([]byte{0x55}, 32))
	sk = sshString(sk, []byte("ssh:"))
	keys["sk-ed25519"] = sk
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdhPub, err := ek.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	var ske []byte
	ske = sshString(ske, []byte(ssh.KeyAlgoSKECDSA256))
	ske = sshString(ske, []byte("nistp256"))
	ske = sshString(ske, ecdhPub.Bytes())
	ske = sshString(ske, []byte("ssh:"))
	keys["sk-ecdsa"] = ske
	for name, k := range keys {
		pub, err := ssh.ParsePublicKey(k)
		if err != nil || !bytes.Equal(pub.Marshal(), k) {
			t.Fatalf("test key %s does not parse canonically: %v", name, err)
		}
	}
	return keys
}

// TestMachineIssueRequest covers the machine issue request (03-11): the
// round trip, the validation rules, every key type, the signing bytes,
// the constants, the name grammar, strict parsing and the signing vector.
func TestMachineIssueRequest(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		r := machineIssueVector(t)
		body, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseMachineIssueRequest(body)
		if err != nil {
			t.Fatal(err)
		}
		if again, err := got.Marshal(); err != nil || !bytes.Equal(again, body) || got.MachineName != "ci" {
			t.Fatalf("re-marshal differs (%v)", err)
		}
		sb, err := ParseMachineIssueSigningBytes(r.SigningBytes())
		if err != nil || !bytes.Equal(sb.SigningBytes(), r.SigningBytes()) || sb.Evidence != nil {
			t.Fatalf("ParseMachineIssueSigningBytes: %+v, %v", sb, err)
		}
	})
	t.Run("validate_refuses", func(t *testing.T) {
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		rsaPub, err := ssh.NewPublicKey(&rk.PublicKey)
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
		subj, err := ssh.ParsePublicKey(probeVectorKey(t, 0x33))
		if err != nil {
			t.Fatal(err)
		}
		c, err := cert.Build(cert.Request{Profile: cert.Profile{CertType: ssh.UserCert, MaxTTL: time.Hour}, Subject: subj,
			Principals: []string{"ci"}, Now: time.Now(), ValidFor: time.Minute, Serial: 1,
			KeyID: cert.KeyID{CA: "machine", Subject: "ci", Request: "000102030405060708090a0b0c0d0e0f", Policy: 1, Serial: 1}}, caSigner, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for name, edit := range map[string]func(*MachineIssueRequest){
			"rsa_key":            func(r *MachineIssueRequest) { r.MachineKey = rsaPub.Marshal() },
			"certificate_key":    func(r *MachineIssueRequest) { r.MachineKey = c.Marshal() },
			"non_canonical_key":  func(r *MachineIssueRequest) { r.MachineKey = append(probeVectorKey(t, 0x33), 0) },
			"empty_key":          func(r *MachineIssueRequest) { r.MachineKey = nil },
			"key_too_long":       func(r *MachineIssueRequest) { r.MachineKey = make([]byte, MaxSubjectKeyLen+1) },
			"zero_request_id":    func(r *MachineIssueRequest) { r.RequestID = [16]byte{} },
			"zero_created_at":    func(r *MachineIssueRequest) { r.CreatedAt = 0 },
			"installation_upper": func(r *MachineIssueRequest) { r.InstallationID = "0123456789ABCDEF0123456789abcdef" },
			"installation_short": func(r *MachineIssueRequest) { r.InstallationID = "0123" },
			"name_grammar":       func(r *MachineIssueRequest) { r.MachineName = "-ci" },
			"name_too_long":      func(r *MachineIssueRequest) { r.MachineName = strings.Repeat("a", 65) },
			"no_evidence":        func(r *MachineIssueRequest) { r.Evidence = nil },
			"two_evidence": func(r *MachineIssueRequest) {
				r.Evidence = append(r.Evidence, Evidence{Type: EvidenceMachinePoP, Blob: []byte("x")})
			},
			"evidence_type_too_long": func(r *MachineIssueRequest) { r.Evidence[0].Type = strings.Repeat("t", MaxEvidenceType+1) },
			"evidence_type_empty":    func(r *MachineIssueRequest) { r.Evidence[0].Type = "" },
			"evidence_blob_too_long": func(r *MachineIssueRequest) { r.Evidence[0].Blob = make([]byte, MaxEvidenceBlob+1) },
		} {
			r := machineIssueVector(t)
			edit(r)
			if err := r.Validate(); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: Validate = %v, want ErrMalformed", name, err)
			}
			if _, err := r.Marshal(); !errors.Is(err, ErrMalformed) {
				t.Errorf("%s: Marshal = %v, want ErrMalformed", name, err)
			}
		}
	})
	t.Run("validate_accepts_every_key_type", func(t *testing.T) {
		keys := machineTestKeys(t)
		if len(keys) != 6 {
			t.Fatalf("%d key types, want 6", len(keys))
		}
		for name, k := range keys {
			r := machineIssueVector(t)
			r.MachineKey = k
			if err := r.Validate(); err != nil {
				t.Errorf("key %s refused: %v", name, err)
			}
			body, err := r.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseMachineIssueRequest(body); err != nil {
				t.Errorf("key %s: parse: %v", name, err)
			}
		}
		r := machineIssueVector(t)
		r.ValidForSeconds = 7
		if err := r.Validate(); err != nil {
			t.Fatalf("Validate puts a rule on valid_for: %v (the signer refuses it with its own detail)", err)
		}
	})
	t.Run("signing_bytes_bind_every_field", func(t *testing.T) {
		base := machineIssueVector(t).Digest()
		for name, edit := range map[string]func(*MachineIssueRequest){
			"installation_id": func(r *MachineIssueRequest) { r.InstallationID = "fedcba9876543210fedcba9876543210" },
			"machine_name":    func(r *MachineIssueRequest) { r.MachineName = "ci2" },
			"machine_key":     func(r *MachineIssueRequest) { r.MachineKey = probeVectorKey(t, 0x34) },
			"valid_for":       func(r *MachineIssueRequest) { r.ValidForSeconds = 1 },
			"request_id":      func(r *MachineIssueRequest) { r.RequestID[3] ^= 1 },
			"created_at":      func(r *MachineIssueRequest) { r.CreatedAt++ },
		} {
			r := machineIssueVector(t)
			edit(r)
			if r.Digest() == base {
				t.Errorf("changing %s does not change the digest", name)
			}
		}
		r := machineIssueVector(t)
		r.Evidence[0].Blob = []byte("other")
		if r.Digest() != base {
			t.Error("the evidence is part of the signing bytes")
		}
	})
	t.Run("constants_and_frame", func(t *testing.T) {
		if MachineIssueRequestDomain != "keyroster/machine-issue-request/v1" || MachinePoPNamespace != MachineIssueRequestDomain ||
			EvidenceMachinePoP != "machine-pop/v1" || TypeMachineIssueRequest != 0x0C {
			t.Fatal("the machine request constants changed")
		}
		for _, other := range []string{AdminSSHSIGNamespace, RevokeSSHSIGNamespace, RevokeSSHSIGNamespaceV1, RecoverySSHSIGNamespace,
			LoginRequestDomain, ForgetSSHSIGNamespace, HostPoPNamespace, ProbePoPNamespace} {
			if MachinePoPNamespace == other || strings.HasPrefix(other, MachinePoPNamespace) || strings.HasPrefix(MachinePoPNamespace, other) {
				t.Errorf("the machine namespace %q overlaps %q", MachinePoPNamespace, other)
			}
		}
		for _, other := range []string{EvidenceHostPoP, EvidenceProbePoP, EvidenceAdminSSHSIG} {
			if EvidenceMachinePoP == other {
				t.Errorf("the machine evidence type equals %q", other)
			}
		}
	})
	t.Run("name_grammar_matches_directory", func(t *testing.T) {
		for _, n := range []string{"ci", "a", "a.b-c_d", "probe.x", "Ci", "-ci", "", strings.Repeat("a", 64), strings.Repeat("a", 65), "c i", "cé", "c:1"} {
			r := machineIssueVector(t)
			r.MachineName = n
			if got := r.Validate() == nil; got != directory.ValidUserName(n) {
				t.Errorf("%q: machine request accepts %t, directory %t", n, got, directory.ValidUserName(n))
			}
		}
	})
	t.Run("strict_parsers", func(t *testing.T) {
		r := machineIssueVector(t)
		body, err := r.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		sb := r.SigningBytes()
		badLen := bytes.Clone(body)
		badLen[0], badLen[1] = 0xff, 0xff // the installation ID's uint16 length
		for name, b := range map[string][]byte{"trailing": append(bytes.Clone(body), 0), "truncated": body[:len(body)-1], "bad_length": badLen, "empty": nil} {
			if _, err := ParseMachineIssueRequest(b); err == nil {
				t.Errorf("body %s accepted", name)
			}
		}
		badSBLen := bytes.Clone(sb)
		off := len(MachineIssueRequestDomain)
		badSBLen[off], badSBLen[off+1] = 0, 5
		for name, b := range map[string][]byte{"trailing": append(bytes.Clone(sb), 0), "truncated": sb[:len(sb)-1], "bad_length": badSBLen,
			"domain_only": []byte(MachineIssueRequestDomain), "host_domain": hostIssueVector(t).SigningBytes()} {
			if _, err := ParseMachineIssueSigningBytes(b); err == nil {
				t.Errorf("signing bytes %s accepted", name)
			}
		}
	})
	t.Run("signing_vector", func(t *testing.T) {
		want := handMachineSigningBytes()
		r := machineIssueVector(t)
		if got := r.SigningBytes(); !bytes.Equal(got, want) {
			t.Fatalf("SigningBytes differ from the hand-built bytes\ngot:  %x\nwant: %x", got, want)
		}
		path := filepath.Join(vectorDir, "machine_issue_request_signing_v1.hex")
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
		if r.Digest() != sha256.Sum256(want) {
			t.Fatal("Digest is not the SHA-256 of the signing bytes")
		}
		got, err := ParseMachineIssueSigningBytes(fromFile)
		if err != nil || got.MachineName != "ci" || got.CreatedAt != 1_700_000_000 || got.ValidForSeconds != 0 {
			t.Fatalf("ParseMachineIssueSigningBytes(vector) = %+v, %v", got, err)
		}
	})
}

// FuzzParseMachineIssueRequest: parse then encode is the identity (03-11).
func FuzzParseMachineIssueRequest(f *testing.F) {
	valid, err := machineIssueVector(f).Marshal()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseMachineIssueRequest(data)
		if err != nil {
			return
		}
		again, err := r.Marshal()
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("parse then marshal is not the identity (%v)", err)
		}
	})
}

// FuzzParseMachineIssueSigningBytes: parse then encode is the identity
// (03-11).
func FuzzParseMachineIssueSigningBytes(f *testing.F) {
	f.Add(handMachineSigningBytes())
	valid := machineIssueVector(f).SigningBytes()
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(valid[:len(valid)-1])
	f.Add([]byte(MachineIssueRequestDomain))
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := ParseMachineIssueSigningBytes(data)
		if err != nil {
			return
		}
		if !bytes.Equal(r.SigningBytes(), data) {
			t.Fatal("parse then encode is not the identity")
		}
	})
}
