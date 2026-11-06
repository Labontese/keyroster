package cert

import (
	"errors"
	"strings"
	"testing"
)

// FuzzParseKeyID (T-02-13): ParseKeyID never panics, refuses only with
// ErrKeyID, and every key ID it accepts, kr1 or kr2, formats back to
// exactly the input.
func FuzzParseKeyID(f *testing.F) {
	kr2 := KeyID{CA: "user", Subject: "alice", Request: testRequestHex, Policy: 1, Directory: 7, Roles: sixteenRoles(), Serial: 9}
	for _, s := range []string{
		validKeyIDString,
		"kr1/ca=host/sub=h:web/req=" + testRequestHex + "/pol=7/ser=18446744073709551615",
		"kr1/ca=machine/sub=m:x/req=" + testRequestHex + "/pol=0/ser=1",
		"kr2/ca=user/sub=alice/req=000102030405060708090a0b0c0d0e0f/pol=2/dir=1/roles=admin+ops/ser=1700000000000003",
		kr2.String(),
		"kr2/ca=user/sub=alice/req=" + testRequestHex + "/pol=1/dir=1/roles=ops+admin/ser=1",
		"kr2/ca=user/sub=alice/req=" + testRequestHex + "/pol=1/dir=1/roles=" + strings.Join(append(sixteenRoles(), "rq"), "+") + "/ser=1",
		"kr2/ca=user/sub=alice/req=" + testRequestHex + "/pol=1/dir=0/roles=ops/ser=1",
		"kr2/ca=user/sub=u:alice/req=" + testRequestHex + "/pol=0/ser=42",
		"kr1/ca=user/sub=u:a/b/req=" + testRequestHex + "/pol=0/ser=42",
		"kr1/ca=user/sub=/req=/pol=/ser=",
		"kr1/ca=user/sub=u:alice/req=" + testRequestHex + "/pol=01/ser=42",
		"",
		"kr1/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParseKeyID(s)
		if err != nil {
			if !errors.Is(err, ErrKeyID) {
				t.Fatalf("ParseKeyID(%q) = %v, want ErrKeyID", s, err)
			}
			return
		}
		if got := k.String(); got != s {
			t.Fatalf("accepted key ID %q formats back as %q", s, got)
		}
	})
}
