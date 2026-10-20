package main

import (
	"regexp"
	"testing"
)

// inviteURLRE is everything parseInviteURL may return: an https origin
// with a DNS-style host and an optional port, /enroll/ and a 43-character
// base64url token. No space, quote, control character or shell
// metacharacter fits it.
var inviteURLRE = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/enroll/[A-Za-z0-9_-]{43}$`)

// FuzzParseInviteURL: the invite URL comes from the server, so whatever
// parseInviteURL accepts must be a plain invite URL and parse to itself.
func FuzzParseInviteURL(f *testing.F) {
	for _, s := range []string{
		"https://keyroster.example/enroll/" + inviteToken,
		"https://keyroster.example:8443/enroll/" + inviteToken,
		"https://keyroster.example/enroll/" + inviteToken + "?x=1",
		"https://192.0.2.1/enroll/" + inviteToken,
		"https://keyroster.example/enroll/%41" + inviteToken[1:],
		"http://keyroster.example/enroll/" + inviteToken,
		"https://user@keyroster.example/enroll/" + inviteToken,
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := parseInviteURL(s)
		if err != nil {
			return
		}
		if !inviteURLRE.MatchString(out) {
			t.Fatalf("parseInviteURL(%q) = %q, not a plain invite URL", s, out)
		}
		again, err := parseInviteURL(out)
		if err != nil || again != out {
			t.Fatalf("parseInviteURL(%q) = %q, %v; want %q", out, again, err, out)
		}
	})
}
