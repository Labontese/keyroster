package trust

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

var updateVectors = flag.Bool("update", false, "rewrite the golden vectors in test/vectors")

const vectorDir = "../../test/vectors"

// rotationCAFileAt is the time the rotation vector's user_ca_keys is
// rendered at (03-12c): after g2's end and before g3's.
var rotationCAFileAt = time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)

// TestGoldenVectors pins the canonical encoding byte for byte: the genesis
// policy and bundle, and the rotation bundle (03-12c), built from the fixed
// test keys must equal the files in test/vectors, each file must parse and
// re-marshal to itself, and each must end in exactly one newline. Any
// change to the encoding or field set is a format change that every agent
// pins (D-01) and shows up here. user_ca_keys_rotation_v1.txt is the
// UserCAKeysFile of the rotation bundle at rotationCAFileAt, plain key
// lines that each parse and re-format to themselves.
func TestGoldenVectors(t *testing.T) {
	policy := mustCanonical(t, goldenPolicy(t))
	bundle := mustCanonical(t, goldenBundle(t, policy))
	rotation := goldenRotationBundle(t, policy)
	caFile, err := UserCAKeysFile(rotation, rotationCAFileAt)
	if err != nil {
		t.Fatal(err)
	}
	parseBundle := func(b []byte) ([]byte, error) {
		p, err := ParseBundle(b)
		if err != nil {
			return nil, err
		}
		return p.Canonical()
	}
	for _, v := range []struct {
		file  string
		built []byte
		parse func([]byte) ([]byte, error)
		text  bool // a text vector: no JSON closing brace before the newline
	}{
		{"policy_genesis_v1.json", policy, func(b []byte) ([]byte, error) {
			p, err := ParsePolicy(b)
			if err != nil {
				return nil, err
			}
			return p.Canonical()
		}, false},
		{"bundle_genesis_v1.json", bundle, parseBundle, false},
		{"bundle_rotation_v1.json", mustCanonical(t, rotation), parseBundle, false},
		{"user_ca_keys_rotation_v1.txt", caFile, func(b []byte) ([]byte, error) {
			var out []byte
			for rest := b; len(rest) > 0; {
				line, more, _ := bytes.Cut(rest, []byte("\n"))
				pub, comment, options, tail, err := ssh.ParseAuthorizedKey(line)
				if err != nil {
					return nil, err
				}
				if comment != "" || len(options) != 0 || len(tail) != 0 {
					return nil, errNotPlain
				}
				out = append(out, FormatKey(pub)+"\n"...)
				rest = more
			}
			return out, nil
		}, true},
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
			if !bytes.HasSuffix(got, []byte("\n")) || bytes.HasSuffix(got, []byte("\n\n")) || !v.text && !bytes.HasSuffix(got, []byte("}\n")) {
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

// errNotPlain is a user_ca_keys line that carries options, a comment or
// trailing data (03-12c).
var errNotPlain = errors.New("not a plain key line")
