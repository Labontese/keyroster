package serverclient

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
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

// ldhHost is a DNS name in letter-digit-hyphen form, checked here with a
// regular expression rather than the function's own loop.
var ldhHost = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// FuzzParseServerURL: an accepted server URL is https, has a DNS host in
// letter-digit-hyphen form and no path, and normalizes to itself.
func FuzzParseServerURL(f *testing.F) {
	for _, s := range []string{
		"https://keyroster.example", "https://keyroster.example:8443", "http://keyroster.example",
		"https://192.0.2.1", "https://[::1]", "https://keyroster.example/x", "https://u@h.example", "https://h.example:0",
		"https://[fe80::1%25eth0]:8443", "https://192.0.2.1.", "https://127.1", "https://a!b.example", "https://a$b.example",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := ParseServerURL(s)
		if err != nil {
			return
		}
		// Checked here with netip, not with the function's own net.ParseIP.
		h := strings.TrimSuffix(u.Hostname(), ".")
		last := h[strings.LastIndexByte(h, '.')+1:]
		_, addrErr := netip.ParseAddr(h)
		allDigits := last != "" && strings.Trim(last, "0123456789") == ""
		if u.Scheme != "https" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
			u.Hostname() == "" || strings.ContainsAny(h, ":%") || addrErr == nil || allDigits || !ldhHost.MatchString(h) {
			t.Fatalf("ParseServerURL(%q) accepted %q", s, u)
		}
		if strings.HasSuffix(u.Host, ":") {
			t.Fatalf("ParseServerURL(%q) accepted %q with an empty port", s, u)
		}
		again, err := ParseServerURL(u.String())
		if err != nil || again.String() != u.String() {
			t.Fatalf("ParseServerURL(%q) = %q, which re-parses to %v, %v", s, u, again, err)
		}
	})
}

// FuzzPeerError: whatever the peer sends, a PeerError's text is printable
// ASCII with no run of two spaces, and the excerpt between its delimiters
// is at most maxPeerExcerpt bytes.
func FuzzPeerError(f *testing.F) {
	for _, s := range []string{"", "x", strings.Repeat(" ", 4000) + "keyroster init --force", "\"]", "a\u202eb\x1b[2K\r\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := PeerError(errors.New(s)).Error()
		body, ok := strings.CutPrefix(got, `[peer text: "`)
		if !ok {
			body, ok = strings.CutPrefix(got, fmt.Sprintf(`[peer text, cut to %d bytes: "`, maxPeerExcerpt))
		}
		body, ok2 := strings.CutSuffix(body, `"]`)
		if !ok || !ok2 || len(body) > maxPeerExcerpt || strings.Contains(got, "  ") {
			t.Fatalf("PeerError(%q) = %q", s, got)
		}
		for i := range len(got) {
			if got[i] < 0x20 || got[i] > 0x7e {
				t.Fatalf("PeerError(%q) = %q carries byte %#x", s, got, got[i])
			}
		}
	})
}
