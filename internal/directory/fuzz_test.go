package directory

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// FuzzParseDirectory (T-02-13): Parse never panics, refuses only with
// ErrInvalid, and accepts only the canonical encoding: a parsed
// directory's Canonical() is exactly the input.
func FuzzParseDirectory(f *testing.F) {
	valid := mustCanonical(f, fixture(f))
	f.Add(valid)
	for _, name := range []string{"directory_v1.json", "directory_hosts_v1.json"} {
		if golden, err := os.ReadFile(filepath.Join(vectorDir, name)); err == nil { //nolint:gosec // G304: fixed test vector path
			f.Add(golden)
		}
	}
	hosts := mustCanonical(f, hostsFixture(f))
	f.Add(hosts)
	f.Add(bytes.Replace(hosts, []byte(`"web1.lab.example"`), []byte(`"WEB1.lab.example"`), 1))
	f.Add(bytes.Replace(hosts, []byte(`"principals":["web1",`), []byte(`"principals":["2001:db8::1",`), 1))
	f.Add(bytes.Replace(hosts, []byte(`,"machines":`), []byte(`,"machines":[],"x":`), 1))
	f.Add(append([]byte("{ "), valid[1:]...))
	f.Add(append([]byte(`{"comment":"x",`), valid[1:]...))
	f.Add(bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":0`), 1))
	f.Add(bytes.Replace(valid, []byte(`"status":"active"`), []byte(`"status":"disabled"`), 1))
	f.Add(append(append([]byte(nil), valid...), '\n'))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := Parse(data)
		if err != nil {
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse error = %v, want ErrInvalid", err)
			}
			return
		}
		c, err := d.Canonical()
		if err != nil {
			t.Fatalf("a parsed directory does not encode: %v", err)
		}
		if !bytes.Equal(c, data) {
			t.Fatalf("Parse accepted a non-canonical encoding:\n in  %q\n out %q", data, c)
		}
	})
}
