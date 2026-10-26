package krl

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// maxFuzzSerials bounds how many serials a parsed KRL may expand to before
// FuzzParseKRL re-encodes it (Encode takes single serials, Parse keeps
// intervals).
const maxFuzzSerials = 1 << 16

// FuzzParseKRL (T-03-15, T-03-204): Parse never panics; every error wraps
// ErrMalformed or ErrTooLarge; and whatever parses and holds only the
// types Encode writes (no fingerprint section, at most maxFuzzSerials
// serials) re-encodes to bytes that parse to the same content. Seeds: both
// golden vectors, and (from testdata/fuzz/FuzzParseKRL) the bitmap-bearing
// KRL that TestOracleReverse has ssh-keygen -k write.
func FuzzParseKRL(f *testing.F) {
	for _, name := range []string{"krl_serials_v1.hex", "krl_full_v1.hex"} {
		raw, err := os.ReadFile(vectorPath(name)) //nolint:gosec // G304: fixed test vector path
		if err != nil {
			f.Fatal(err)
		}
		data, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Add([]byte(Magic))
	f.Add([]byte{})
	_, ca := seedKey(f, 0x30)
	for _, tc := range cstringBignumKRLs(ca.Marshal()) {
		f.Add(tc.data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrMalformed) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("Parse error %v wraps neither ErrMalformed nor ErrTooLarge", err)
			}
			return
		}
		if len(p.SHA1) > 0 || len(p.SHA256) > 0 {
			return // Encode writes no fingerprint section
		}
		var (
			set Set
			n   uint64
		)
		for _, sec := range p.Certs {
			ca, err := ssh.ParsePublicKey(sec.CAKey)
			if err != nil {
				t.Fatalf("Parse accepted a CA key that does not parse: %v", err)
			}
			cs := CertSection{CAKey: ca, KeyIDs: sec.KeyIDs}
			for _, r := range sec.Serials {
				if n += r.Hi - r.Lo + 1; r.Hi-r.Lo >= maxFuzzSerials || n > maxFuzzSerials {
					return
				}
				for v := r.Lo; ; v++ {
					cs.Serials = append(cs.Serials, v)
					if v == r.Hi {
						break
					}
				}
			}
			set.Certs = append(set.Certs, cs)
		}
		for _, blob := range p.Keys {
			k, err := ssh.ParsePublicKey(blob)
			if err != nil {
				t.Fatalf("Parse accepted an explicit key that does not parse: %v", err)
			}
			set.Keys = append(set.Keys, k)
		}
		out, err := Encode(set, p.Version, time.Unix(1700000000, 0))
		if err != nil {
			if errors.Is(err, ErrTooLarge) {
				return // ranges re-encoded as lists can outgrow MaxKRL
			}
			t.Fatalf("Encode of a parsed KRL: %v", err)
		}
		q, err := Parse(out)
		if err != nil || !q.SameContent(p) {
			t.Fatalf("Parse(Encode(Parse(data))) = %+v, %v; want the content of %+v", q, err, p)
		}
	})
}
