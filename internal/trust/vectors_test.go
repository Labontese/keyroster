package trust

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateVectors = flag.Bool("update", false, "rewrite the golden vectors in test/vectors")

const vectorDir = "../../test/vectors"

// TestGoldenVectors pins the canonical encoding byte for byte: the genesis
// policy and bundle built from the fixed test keys must equal the files in
// test/vectors, each file must parse and re-marshal to itself, and each must
// end in exactly one newline. Any change to the encoding or field set is a
// format change that every agent pins (D-01) and shows up here.
func TestGoldenVectors(t *testing.T) {
	policy := mustCanonical(t, goldenPolicy(t))
	bundle := mustCanonical(t, goldenBundle(t, policy))
	for _, v := range []struct {
		file  string
		built []byte
		parse func([]byte) ([]byte, error)
	}{
		{"policy_genesis_v1.json", policy, func(b []byte) ([]byte, error) {
			p, err := ParsePolicy(b)
			if err != nil {
				return nil, err
			}
			return p.Canonical()
		}},
		{"bundle_genesis_v1.json", bundle, func(b []byte) ([]byte, error) {
			p, err := ParseBundle(b)
			if err != nil {
				return nil, err
			}
			return p.Canonical()
		}},
	} {
		t.Run(v.file, func(t *testing.T) {
			path := filepath.Join(vectorDir, v.file)
			if *updateVectors {
				if err := os.WriteFile(path, v.built, 0o644); err != nil { //nolint:gosec // G306: public test vector
					t.Fatal(err)
				}
			}
			got, err := os.ReadFile(path) //nolint:gosec // G304: fixed test vector path
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, v.built) {
				t.Fatalf("%s differs from the canonical encoding of the fixture (run go test -run TestGoldenVectors -update ./internal/trust/ only for a deliberate format change)\ngot:  %s\nwant: %s", v.file, got, v.built)
			}
			if !bytes.HasSuffix(got, []byte("}\n")) || bytes.HasSuffix(got, []byte("\n\n")) {
				t.Fatalf("%s must end with exactly one newline", v.file)
			}
			re, err := v.parse(got)
			if err != nil {
				t.Fatalf("parse %s: %v", v.file, err)
			}
			if !bytes.Equal(re, got) {
				t.Fatalf("%s does not re-marshal to itself", v.file)
			}
			t.Logf("%s sha256 %s", v.file, SHA256Hex(got))
		})
	}
}
