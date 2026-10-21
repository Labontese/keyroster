package main

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/webauthn"
)

// inviteURLRE is everything parseInviteURL may return: an https origin
// with a DNS-style host and an optional port, /enroll/ and a 43-character
// base64url token. No space, quote, control character or shell
// metacharacter fits it.
var inviteURLRE = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/enroll/[A-Za-z0-9_-]{43}$`)

// FuzzParseInviteURL: the invite URL comes from the server, so whatever
// parseInviteURL accepts must be a plain invite URL under the origin it
// returns, and parse to itself.
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
		origin, out, err := parseInviteURL(s)
		if err != nil {
			return
		}
		if !inviteURLRE.MatchString(out) || !strings.HasPrefix(out, origin+"/enroll/") {
			t.Fatalf("parseInviteURL(%q) = %q, %q: not a plain invite URL under its origin", s, origin, out)
		}
		againOrigin, again, err := parseInviteURL(out)
		if err != nil || again != out || againOrigin != origin {
			t.Fatalf("parseInviteURL(%q) = %q, %q, %v; want %q, %q", out, againOrigin, again, err, origin, out)
		}
	})
}

// FuzzCheckPendingCredential: the pending list comes from the server, so
// whatever checkPendingCredential accepts must print only values the CLI
// re-derived: a fingerprint computed from the SPKI, one of three algorithm
// names and a UTC time.
func FuzzCheckPendingCredential(f *testing.F) {
	f.Add("AQIDBAUGBwgJCgsMDQ4PEA", int64(-8), "MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=",
		"SHA256:x", true, false, "2026-10-21T12:00:00Z")
	f.Add("", int64(-7), "", "", false, true, "")
	f.Fuzz(func(t *testing.T, id string, alg int64, spki, fp string, be, bs bool, at string) {
		c := serverclient.PendingCredential{ID: id, Alg: alg, SPKI: spki, Fingerprint: fp, BackupEligible: be, BackedUp: bs, RegisteredAt: at}
		got, err := checkPendingCredential(c)
		if err != nil {
			return
		}
		der, derr := base64.StdEncoding.Strict().DecodeString(spki)
		if derr != nil || got.fingerprint != webauthn.Fingerprint(der) || got.fingerprint != fp {
			t.Fatalf("accepted fingerprint %q is not the SPKI's", got.fingerprint)
		}
		switch got.alg {
		case "EdDSA", "ES256", "RS256":
		default:
			t.Fatalf("accepted algorithm name %q", got.alg)
		}
		if got.registered.Location() != time.UTC || (got.backedUp && !got.backupEligible) {
			t.Fatalf("accepted %+v", got)
		}
	})
}
