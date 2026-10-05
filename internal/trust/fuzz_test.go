package trust

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// seedVector adds a golden vector to the fuzz corpus.
func seedVector(f *testing.F, name string) {
	f.Helper()
	data, err := os.ReadFile(filepath.Join(vectorDir, name)) //nolint:gosec // G304: fixed test vector path
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data)
	f.Add(bytes.TrimSuffix(data, []byte("\n")))
	f.Add([]byte("{}\n"))
}

// FuzzParseBundle checks that ParseBundle never panics and that every
// accepted input is exactly its own canonical re-marshal.
func FuzzParseBundle(f *testing.F) {
	seedVector(f, "bundle_genesis_v1.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := ParseBundle(data)
		if err != nil {
			return
		}
		re, err := b.Canonical()
		if err != nil {
			t.Fatalf("accepted bundle does not re-marshal: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("accepted a non-canonical bundle:\n%q\nre-marshals to\n%q", data, re)
		}
	})
}

// FuzzParsePolicy checks the same property for policies.
func FuzzParsePolicy(f *testing.F) {
	seedVector(f, "policy_genesis_v1.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePolicy(data)
		if err != nil {
			return
		}
		re, err := p.Canonical()
		if err != nil {
			t.Fatalf("accepted policy does not re-marshal: %v", err)
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("accepted a non-canonical policy:\n%q\nre-marshals to\n%q", data, re)
		}
	})
}
