package serverclient

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

// FuzzParseCustodyHeader: the custody header comes from the server, so its
// parser must never panic, and whatever it accepts must format and parse
// back to the same keys.
func FuzzParseCustodyHeader(f *testing.F) {
	for _, s := range []string{
		"user=software, host=software, machine=software, ops=software, log=software",
		"user=agent", "", "user=a,user=b", "user", "user=Software", "=x", "user=a,,host=b",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		keys, err := ParseCustodyHeader(v)
		if err != nil {
			return
		}
		out, err := CustodyHeaderValue(keys)
		if err != nil {
			t.Fatalf("accepted %q but cannot format it: %v", v, err)
		}
		again, err := ParseCustodyHeader(out)
		if err != nil || !reflect.DeepEqual(again, keys) {
			t.Fatalf("%q -> %q -> %+v, %v; want %+v", v, out, again, err, keys)
		}
	})
}

// FuzzParseServerURL: an accepted server URL is https, has a DNS host and
// no path, and normalizes to itself.
func FuzzParseServerURL(f *testing.F) {
	for _, s := range []string{
		"https://keyroster.example", "https://keyroster.example:8443", "http://keyroster.example",
		"https://192.0.2.1", "https://[::1]", "https://keyroster.example/x", "https://u@h.example", "https://h.example:0",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseServerURL(s)
		if err != nil {
			return
		}
		if u.Scheme != "https" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
			u.Hostname() == "" || net.ParseIP(strings.Trim(u.Hostname(), "[]")) != nil {
			t.Fatalf("ParseServerURL(%q) accepted %q", s, u)
		}
		again, err := ParseServerURL(u.String())
		if err != nil || again.String() != u.String() {
			t.Fatalf("ParseServerURL(%q) = %q, which re-parses to %v, %v", s, u, again, err)
		}
	})
}
