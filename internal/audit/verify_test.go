package audit

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// memLog is an in-memory LogSource.
type memLog struct {
	leaves [][]byte
	note   []byte
}

func (m *memLog) ReadLog(_ context.Context, fn func(uint64, []byte) error) ([]byte, uint64, error) {
	for i, l := range m.leaves {
		if err := fn(uint64(i), l); err != nil { //nolint:gosec // G115: test index
			return nil, 0, err
		}
	}
	return m.note, uint64(len(m.leaves)), nil
}

// fixture builds a log the way the signer does, with a log key and a user
// CA, so tests can tamper with any part of it and re-sign checkpoints as a
// log-key holder would.
type fixture struct {
	t       testing.TB
	logKey  ssh.Signer
	ca      ssh.Signer
	leaves  [][]byte
	micros  uint64
	serial  uint64
	request byte
}

func newSigner(t testing.TB, alg string) ssh.Signer {
	t.Helper()
	var (
		s   ssh.Signer
		err error
	)
	switch alg {
	case "ed25519":
		var priv ed25519.PrivateKey
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err == nil {
			s, err = ssh.NewSignerFromKey(priv)
		}
	case "p256":
		var priv *ecdsa.PrivateKey
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			s, err = ssh.NewSignerFromKey(priv)
		}
	}
	if err != nil || s == nil {
		t.Fatalf("new %s key: %v", alg, err)
	}
	return s
}

func newFixture(t testing.TB, logAlg string) *fixture {
	t.Helper()
	return &fixture{
		t: t, logKey: newSigner(t, logAlg), ca: newSigner(t, "ed25519"),
		micros: uint64(time.Now().UnixMicro()), serial: uint64(time.Now().UnixMicro()), //nolint:gosec // G115: after 1970
	}
}

// add appends a leaf of kind with body at the next index.
func (f *fixture) add(kind tlog.Kind, body []byte) {
	f.t.Helper()
	f.micros++
	raw, err := tlog.MarshalLeaf(tlog.Leaf{Index: uint64(len(f.leaves)), TimeMicros: f.micros, Kind: kind, Body: body})
	if err != nil {
		f.t.Fatal(err)
	}
	f.leaves = append(f.leaves, raw)
}

// newCert issues a real certificate through cert.Build.
func (f *fixture) newCert(serial uint64, now time.Time) *ssh.Certificate {
	f.t.Helper()
	subject := newSigner(f.t, "ed25519").PublicKey()
	f.request++
	keyID := cert.KeyID{CA: "user", Subject: "u:alice", Request: strings.Repeat(hex.EncodeToString([]byte{f.request}), 16), Serial: serial}
	c, err := cert.Build(cert.Request{
		Profile: cert.DefaultUserProfile(), Subject: subject, Principals: []string{"alice"},
		Now: now, ValidFor: time.Hour, KeyID: keyID, Serial: serial,
	}, f.ca, rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

// issueBody returns the issue leaf body for c.
func issueBody(t testing.TB, c *ssh.Certificate, serial uint64) []byte {
	t.Helper()
	b, err := (&tlog.IssueBody{CARole: uint8(wire.CARoleUser), Serial: serial, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// addIssue issues and logs one certificate with the next serial.
func (f *fixture) addIssue() {
	f.t.Helper()
	f.serial++
	f.add(tlog.KindIssue, issueBody(f.t, f.newCert(f.serial, time.Now()), f.serial))
}

func (f *fixture) addRefusal() {
	f.t.Helper()
	b, err := (&tlog.RefusalBody{PeerUID: 1000, Reason: tlog.ReasonBadPrincipal, Detail: "bad_principal"}).Encode()
	if err != nil {
		f.t.Fatal(err)
	}
	f.add(tlog.KindRefusal, b)
}

// checkpoint signs the checkpoint for the first n leaves with key.
func (f *fixture) checkpointWith(key ssh.Signer, origin string, n int) []byte {
	f.t.Helper()
	var hashes [][]byte
	for _, l := range f.leaves[:n] {
		hashes = append(hashes, tlog.HashLeaf(l))
	}
	tree, err := tlog.FromHashes(hashes)
	if err != nil {
		f.t.Fatal(err)
	}
	root, err := tree.Root()
	if err != nil {
		f.t.Fatal(err)
	}
	ns, err := tlog.NewNoteSigner(origin, key)
	if err != nil {
		f.t.Fatal(err)
	}
	msg, err := tlog.SignCheckpoint(tlog.Checkpoint{Origin: origin, Size: uint64(n), Root: root}, ns) //nolint:gosec // G115: test size
	if err != nil {
		f.t.Fatal(err)
	}
	return msg
}

func (f *fixture) checkpoint(n int) []byte {
	return f.checkpointWith(f.logKey, tlog.Origin(f.logKey.PublicKey()), n)
}

// lines exports the whole log, checkpointed by the log key, as JSONL lines.
func (f *fixture) lines() []string {
	f.t.Helper()
	var buf bytes.Buffer
	if _, err := Export(context.Background(), &buf, &memLog{leaves: f.leaves, note: f.checkpoint(len(f.leaves))}); err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
}

func join(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func (f *fixture) verify(export string, previous []byte) (*Report, error) {
	return Verify(strings.NewReader(export), Options{LogKey: f.logKey.PublicKey(), Previous: previous})
}

// standard is a log of two issuances, a refusal and an issuance.
func standard(t testing.TB, logAlg string) *fixture {
	f := newFixture(t, logAlg)
	f.addIssue()
	f.addIssue()
	f.addRefusal()
	f.addIssue()
	return f
}

func TestVerifyOK(t *testing.T) {
	for _, alg := range []string{"ed25519", "p256"} {
		t.Run(alg, func(t *testing.T) {
			f := standard(t, alg)
			rep, err := f.verify(join(f.lines()), nil)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if rep.Size != 4 || rep.Serials != 3 || rep.Counts[tlog.KindIssue] != 3 || rep.Counts[tlog.KindRefusal] != 1 {
				t.Fatalf("report %+v", rep)
			}
		})
	}
}

// leafLine re-encodes line with its leaf bytes replaced.
func leafLine(t *testing.T, line string, edit func([]byte) []byte) string {
	t.Helper()
	var l ExportLine
	if err := json.Unmarshal([]byte(line), &l); err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(l.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	l.Leaf = base64.StdEncoding.EncodeToString(edit(append([]byte(nil), raw...)))
	out, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestVerifyDetectsTampering: every modification of the export fails with a
// specific reason; editing only the informational "decoded" object does
// not.
func TestVerifyDetectsTampering(t *testing.T) {
	f := standard(t, "ed25519")
	base := f.lines() // 4 leaf lines + checkpoint
	cp := base[4]
	other := newSigner(t, "ed25519")
	// header (22 domain + 8 index + 8 time + 1 kind + 3 length) + role 1 +
	// serial 8 + policy 8 lands inside the request digest.
	const digestByte = 42 + 17 + 5
	cases := []struct {
		name  string
		lines func() []string
		want  string // "" = must verify
	}{
		{"flipped_leaf_byte", func() []string {
			l := append([]string(nil), base...)
			l[1] = leafLine(t, l[1], func(b []byte) []byte { b[digestByte] ^= 1; return b })
			return l
		}, "root mismatch"},
		{"removed_leaf_line", func() []string { return append(append([]string(nil), base[:1]...), base[2:]...) }, "missing"},
		{"truncated_tail_keeps_checkpoint", func() []string { return []string{base[0], base[1], cp} }, "checkpoint covers 4 entries"},
		{"checkpoint_other_key", func() []string {
			l := append([]string(nil), base[:4]...)
			forged := f.checkpointWith(other, tlog.Origin(f.logKey.PublicKey()), 4)
			out, _ := json.Marshal(ExportLine{Checkpoint: string(forged)})
			return append(l, string(out))
		}, "not signed by the log key"},
		{"checkpoint_not_last", func() []string { return []string{base[0], base[1], base[2], cp, base[3]} }, "not last"},
		{"two_checkpoint_lines", func() []string { return append(append([]string(nil), base...), cp) }, "more than one checkpoint"},
		{"duplicate_index", func() []string { return []string{base[0], base[1], base[1], base[2], base[3], cp} }, "repeated"},
		{"swapped_lines", func() []string { return []string{base[1], base[0], base[2], base[3], cp} }, "out of order"},
		{"empty_export", func() []string { return nil }, "empty log"},
		{"no_checkpoint", func() []string { return base[:4] }, "empty log"},
		{"checkpoint_without_entries", func() []string { return []string{cp} }, "empty log"},
		{"unknown_field", func() []string {
			l := append([]string(nil), base...)
			l[0] = strings.Replace(l[0], `{"index"`, `{"extra":1,"index"`, 1)
			return l
		}, "unknown field"},
		{"blank_line", func() []string { return []string{base[0], "", base[1], base[2], base[3], cp} }, "empty line"},
		{"decoded_only_edit_still_ok", func() []string {
			l := append([]string(nil), base...)
			var line ExportLine
			if err := json.Unmarshal([]byte(l[0]), &line); err != nil {
				t.Fatal(err)
			}
			line.Decoded = json.RawMessage(`{"kind":"issue","serial":1,"principals":["root"],"note":"edited"}`)
			out, _ := json.Marshal(line)
			l[0] = string(out)
			return l
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := f.verify(join(tc.lines()), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Verify accepted the tampered export: %+v", rep)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// forgeCert signs c with ca outside cert.Build (as a compromised CA or a
// log-key holder rewriting history could), setting the nonce, signature
// key and signature over the certificate's signed bytes.
func forgeCert(t *testing.T, c *ssh.Certificate, ca ssh.Signer, sigKey ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	c.Nonce = make([]byte, 32)
	if _, err := rand.Read(c.Nonce); err != nil {
		t.Fatal(err)
	}
	c.SignatureKey = sigKey
	c.Signature = nil
	out := c.Marshal()
	sig, err := ca.Sign(rand.Reader, out[:len(out)-4])
	if err != nil {
		t.Fatal(err)
	}
	c.Signature = sig
	return c
}

// TestVerifyChecksCertificates: a log-key holder can re-sign checkpoints,
// so audit verify also re-checks every logged certificate.
func TestVerifyChecksCertificates(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, f *fixture)
		want  string
	}{
		{"cert_bad_signature", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, time.Now())
			c.Signature.Blob = append([]byte(nil), c.Signature.Blob...)
			c.Signature.Blob[0] ^= 1
			f.add(tlog.KindIssue, issueBody(t, c, f.serial))
		}, "CA signature"},
		{"leaf_serial_differs_from_cert", func(t *testing.T, f *fixture) {
			f.serial++
			f.add(tlog.KindIssue, issueBody(t, f.newCert(f.serial, time.Now()), f.serial+1))
		}, "serial"},
		{"serial_not_increasing", func(t *testing.T, f *fixture) {
			f.addIssue()
			s := f.serial - 10
			f.add(tlog.KindIssue, issueBody(t, f.newCert(s, time.Now()), s))
		}, "serial"},
		{"serial_repeated", func(t *testing.T, f *fixture) {
			f.addIssue()
			f.add(tlog.KindIssue, issueBody(t, f.newCert(f.serial, time.Now()), f.serial))
		}, "serial"},
		{"key_id_serial_differs", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, time.Now())
			c.KeyId = strings.Replace(c.KeyId, fmt.Sprintf("/ser=%d", f.serial), fmt.Sprintf("/ser=%d", f.serial+1), 1)
			c = forgeCert(t, c, f.ca, f.ca.PublicKey())
			b, err := (&tlog.IssueBody{CARole: 1, Serial: f.serial, Cert: c.Marshal(), KeyID: c.KeyId}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			f.add(tlog.KindIssue, b)
		}, "key ID"},
		{"leaf_key_id_differs", func(t *testing.T, f *fixture) {
			f.serial++
			c := f.newCert(f.serial, time.Now())
			b, err := (&tlog.IssueBody{CARole: 1, Serial: f.serial, Cert: c.Marshal(), KeyID: c.KeyId + "x"}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			f.add(tlog.KindIssue, b)
		}, "key ID"},
		{"signature_key_is_certificate", func(t *testing.T, f *fixture) {
			f.serial++
			caCert := f.newCert(f.serial, time.Now()) // a certificate standing in as the CA key
			f.serial++
			c := f.newCert(f.serial, time.Now())
			c = forgeCert(t, c, f.ca, caCert)
			f.add(tlog.KindIssue, issueBody(t, c, f.serial))
		}, "certificate"},
		{"leaf_time_decreases", func(t *testing.T, f *fixture) {
			f.addIssue()
			f.micros -= 10
			f.addRefusal()
		}, "time"},
		{"leaf_records_wrong_index", func(t *testing.T, f *fixture) {
			f.addRefusal()
			b, err := (&tlog.RefusalBody{Reason: tlog.ReasonMalformed}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			raw, err := tlog.MarshalLeaf(tlog.Leaf{Index: 7, TimeMicros: f.micros + 1, Kind: tlog.KindRefusal, Body: b})
			if err != nil {
				t.Fatal(err)
			}
			f.leaves = append(f.leaves, raw)
		}, "records index"},
		{"expired_certificate_still_ok", func(t *testing.T, f *fixture) {
			f.serial++
			f.add(tlog.KindIssue, issueBody(t, f.newCert(f.serial, time.Now().Add(-2*365*24*time.Hour)), f.serial))
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "ed25519")
			f.addIssue()
			tc.build(t, f)
			_, err := f.verify(join(f.lines()), nil)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestIdenticalRefusalsAreDistinctEntries: two leaves with identical
// content except index and time both count (VIS-01 adjacency).
func TestIdenticalRefusalsAreDistinctEntries(t *testing.T) {
	f := newFixture(t, "ed25519")
	f.addRefusal()
	f.addRefusal()
	rep, err := f.verify(join(f.lines()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Size != 2 || rep.Counts[tlog.KindRefusal] != 2 {
		t.Fatalf("report %+v, want two refusal entries", rep)
	}
}

func TestVerifyPrevious(t *testing.T) {
	f := standard(t, "ed25519")
	export := join(f.lines())

	t.Run("previous_ok", func(t *testing.T) {
		if _, err := f.verify(export, f.checkpoint(2)); err != nil {
			t.Fatalf("Verify with an earlier checkpoint of this log: %v", err)
		}
	})
	t.Run("previous_same_size_ok", func(t *testing.T) {
		if _, err := f.verify(export, f.checkpoint(4)); err != nil {
			t.Fatalf("Verify with the current checkpoint as previous: %v", err)
		}
	})
	t.Run("previous_rewritten", func(t *testing.T) {
		g := &fixture{t: t, logKey: f.logKey, ca: f.ca, micros: f.micros, serial: f.serial}
		g.addRefusal()
		g.addRefusal()
		_, err := f.verify(export, g.checkpoint(2))
		if err == nil || !strings.Contains(err.Error(), "log rewritten") {
			t.Fatalf("Verify error = %v, want log rewritten", err)
		}
	})
	t.Run("previous_shrank", func(t *testing.T) {
		g := standard(t, "ed25519")
		g.logKey = f.logKey
		g.addRefusal()
		_, err := f.verify(export, g.checkpoint(5))
		if err == nil || !strings.Contains(err.Error(), "log shrank") {
			t.Fatalf("Verify error = %v, want log shrank", err)
		}
	})
	t.Run("previous_other_key", func(t *testing.T) {
		other := newSigner(t, "ed25519")
		_, err := f.verify(export, f.checkpointWith(other, tlog.Origin(f.logKey.PublicKey()), 2))
		if err == nil || !strings.Contains(err.Error(), "previous") {
			t.Fatalf("Verify error = %v, want a previous-checkpoint error", err)
		}
	})
}
