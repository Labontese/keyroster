package custodytext

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Labontese/keyroster/internal/wire"
)

// allRoles is every role of a software ca-init.
var allRoles = []string{"user", "host", "machine", "ops", "log"}

// ownerApprovedBanner is the KEY-06 warning exactly as the owner approved
// it at 02-05's Task 2 checkpoint (decision A, "edit", 2026-10-18), for all
// five roles.
const ownerApprovedBanner = `EVALUATION ONLY - SOFTWARE CA KEY: the user, host, machine, ops, log keys
of this keyroster signer are software keys (custody software). Anyone who
copies the key files and their passphrase, or controls the signer host,
can issue certificates. Do not use this instance for real access
(docs/security/custody.md).`

func TestSoftwareCABanner(t *testing.T) {
	t.Run("owner_approved_wording", func(t *testing.T) {
		if got := SoftwareCABanner(allRoles); got != ownerApprovedBanner {
			t.Fatalf("SoftwareCABanner(all roles) =\n%s\nwant the owner-approved text\n%s", got, ownerApprovedBanner)
		}
	})
	t.Run("custody_md_quotes_it_verbatim", func(t *testing.T) {
		doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "security", "custody.md"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(doc), SoftwareCABanner(allRoles)) {
			t.Fatalf("docs/security/custody.md does not quote the banner verbatim:\n%s", SoftwareCABanner(allRoles))
		}
	})
	t.Run("banner_fits_terminal", func(t *testing.T) {
		b := SoftwareCABanner(allRoles)
		if !strings.HasPrefix(b, "EVALUATION ONLY - SOFTWARE CA KEY") {
			t.Fatalf("line 1 does not start with the grep phrase: %q", b)
		}
		for i, line := range strings.Split(b, "\n") {
			if n := utf8.RuneCountInString(line); n > 76 {
				t.Errorf("line %d has %d columns, want at most 76: %q", i+1, n, line)
			}
		}
		if strings.HasSuffix(b, "\n") {
			t.Error("the banner ends with a newline; callers frame it themselves")
		}
	})
	t.Run("roles_placeholder", func(t *testing.T) {
		if got := SoftwareCABanner([]string{"user"}); !strings.HasPrefix(got, "EVALUATION ONLY - SOFTWARE CA KEY: the user keys\n") {
			t.Fatalf("one role: %q", got)
		}
	})
}

func TestSoftwareRoles(t *testing.T) {
	ks := func(pairs ...string) []wire.KeyStatus {
		var out []wire.KeyStatus
		for i := 0; i < len(pairs); i += 2 {
			out = append(out, wire.KeyStatus{Role: pairs[i], Alg: "ssh-ed25519", Custody: pairs[i+1], Fingerprint: "SHA256:x"})
		}
		return out
	}
	for _, tc := range []struct {
		name string
		keys []wire.KeyStatus
		want []string
	}{
		{"all_software_in_role_order", ks("log", "software", "ops", "software", "machine", "software", "host", "software", "user", "software"), allRoles},
		{"some_software", ks("user", "tpm", "host", "software", "machine", "tpm", "ops", "software", "log", "tpm"), []string{"host", "ops"}},
		{"none_software", ks("user", "agent", "host", "tpm", "machine", "vtpm", "ops", "piv", "log", "pkcs11-agent"), []string{}},
		{"no_keys", nil, []string{}},
		{"unknown_role_after_known", ks("zeta", "software", "user", "software"), []string{"user", "zeta"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SoftwareRoles(tc.keys)
			if got == nil || !slices.Equal(got, tc.want) {
				t.Fatalf("SoftwareRoles = %#v, want %#v", got, tc.want)
			}
		})
	}
}
