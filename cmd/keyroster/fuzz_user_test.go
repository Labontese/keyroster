package main

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/webauthn"
	"github.com/Labontese/keyroster/internal/webauthn/webauthntest"
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
// names and a UTC time. The seeds carry the real fingerprints of real
// keys of each algorithm, and every seed meant to be accepted is checked
// to be accepted, so the property checks run (pre-merge review). With
// recompute set, the fingerprint is replaced by the one of whatever the
// fuzzed SPKI decodes to: the fuzzer cannot produce a SHA-256 itself, and
// this lets mutated SPKIs, IDs, times and flags reach acceptance.
func FuzzCheckPendingCredential(f *testing.F) {
	for _, alg := range []int64{webauthn.AlgEdDSA, webauthn.AlgES256, webauthn.AlgRS256} {
		a, err := webauthntest.New(alg)
		if err != nil {
			f.Fatal(err)
		}
		cred := a.Credential()
		id, spki := base64.RawURLEncoding.EncodeToString(cred.ID), base64.StdEncoding.EncodeToString(cred.SPKI)
		fp := webauthn.Fingerprint(cred.SPKI)
		c := serverclient.PendingCredential{ID: id, Alg: alg, SPKI: spki, Fingerprint: fp, BackupEligible: true, BackedUp: true, RegisteredAt: "2026-10-21T12:00:00+02:00"}
		if _, err := checkPendingCredential(c); err != nil {
			f.Fatalf("seed for algorithm %d refused: %v", alg, err)
		}
		f.Add(id, alg, spki, fp, true, true, "2026-10-21T12:00:00+02:00", false)
		f.Add(id, alg, spki, fp, false, false, "2026-10-21T12:00:00Z", false)
		// BS without BE, with the real fingerprint: refused only by the
		// BS-implies-BE rule.
		f.Add(id, alg, spki, fp, false, true, "2026-10-21T12:00:00Z", false)
		f.Add(id, alg, spki, "SHA256:x", true, false, "2026-10-21T12:00:00Z", true)
	}
	f.Add("", int64(-7), "", "", false, true, "", false)
	f.Fuzz(func(t *testing.T, id string, alg int64, spki, fp string, be, bs bool, at string, recompute bool) {
		if recompute {
			if der, err := base64.StdEncoding.DecodeString(spki); err == nil {
				fp = webauthn.Fingerprint(der)
			}
		}
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
