package directory

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/webauthn"
)

func vectorV1(t *testing.T) *Directory {
	t.Helper()
	data, err := os.ReadFile("../../test/vectors/directory_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// aliceFP is the fingerprint of the test vector's credential.
func aliceFP(t *testing.T, d *Directory) string {
	t.Helper()
	spki, err := base64.StdEncoding.DecodeString(d.Users[0].Credentials[0].SPKI)
	if err != nil {
		t.Fatal(err)
	}
	return webauthn.Fingerprint(spki)
}

// idDigest is the ID digest Diff prints, computed here independently.
func idDigest(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:16])
}

func TestDiff(t *testing.T) {
	t.Run("genesis", func(t *testing.T) {
		d := vectorV1(t)
		got := Diff(nil, d)
		want := []string{
			"+ user alice (active)",
			"+ credential alice " + aliceFP(t, d) + " EdDSA id-sha256=" + idDigest(d.Users[0].Credentials[0].ID) + " backup_eligible=false synced=false",
			"+ group ops-team members=[alice]",
			"+ role ops principals=[role:ops] max_ttl_seconds=3600 extensions=[] users=[alice] groups=[]",
			"+ host_group lab accounts=[zima:ops]",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("Diff(nil, v1) =\n%q\nwant\n%q", got, want)
		}
	})
	t.Run("credential_added", func(t *testing.T) {
		old := vectorV1(t)
		next := vectorV1(t)
		next.Users = append(next.Users, User{Name: "bob", Status: StatusActive, Credentials: []Credential{old.Users[0].Credentials[0]}})
		next.Users[1].Credentials[0].ID = "AAEC"
		next.Users[1].Credentials[0].BackedUp = true
		next.Sort()
		got := Diff(old, next)
		want := []string{
			"+ user bob (active)",
			"+ credential bob " + aliceFP(t, old) + " EdDSA id-sha256=" + idDigest("AAEC") + " backup_eligible=false synced=true",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("Diff =\n%q\nwant\n%q", got, want)
		}
	})
	t.Run("user_disabled", func(t *testing.T) {
		old := vectorV1(t)
		next := vectorV1(t)
		next.Users[0].Status = StatusDisabled
		if got, want := Diff(old, next), []string{"~ user alice active -> disabled"}; !slices.Equal(got, want) {
			t.Fatalf("Diff = %q, want %q", got, want)
		}
	})
	t.Run("role_added_and_changed", func(t *testing.T) {
		old := vectorV1(t)
		next := vectorV1(t)
		next.Roles[0].MaxTTLSeconds = 600
		next.Roles = append(next.Roles, Role{Name: "dev", Principals: []string{"role:dev"}, MaxTTLSeconds: 60,
			Extensions: []string{}, Users: []string{}, Groups: []string{"ops-team"}})
		next.Sort()
		got := Diff(old, next)
		want := []string{
			"+ role dev principals=[role:dev] max_ttl_seconds=60 extensions=[] users=[] groups=[ops-team]",
			"- role ops principals=[role:ops] max_ttl_seconds=3600 extensions=[] users=[alice] groups=[]",
			"+ role ops principals=[role:ops] max_ttl_seconds=600 extensions=[] users=[alice] groups=[]",
		}
		if !slices.Equal(got, want) {
			t.Fatalf("Diff =\n%q\nwant\n%q", got, want)
		}
	})
	t.Run("removed_and_unchanged", func(t *testing.T) {
		old := vectorV1(t)
		next := vectorV1(t)
		next.HostGroups = []HostGroup{}
		if got, want := Diff(old, next), []string{"- host_group lab accounts=[zima:ops]"}; !slices.Equal(got, want) {
			t.Fatalf("Diff = %q, want %q", got, want)
		}
		if got := Diff(old, vectorV1(t)); len(got) != 0 {
			t.Fatalf("Diff of equal versions = %q, want nothing", got)
		}
	})
	t.Run("credential_id_or_flag_change_visible", func(t *testing.T) {
		// A version that changes only a credential's ID (locking the user
		// out: the signer looks the credential up by ID) or only its
		// backup_eligible flag must not render as identical - and + lines,
		// which a co-signer reads as no change (pre-merge review, 02-09).
		old := vectorV1(t)
		realID := old.Users[0].Credentials[0].ID
		last := "A" // the same ID but for its last character
		if strings.HasSuffix(realID, last) {
			last = "Q"
		}
		for name, mutate := range map[string]func(c *Credential){
			"id":              func(c *Credential) { c.ID = "AAEC" },
			"id_long_prefix":  func(c *Credential) { c.ID = realID[:len(realID)-1] + last },
			"backup_eligible": func(c *Credential) { c.BackupEligible = !c.BackupEligible },
		} {
			next := vectorV1(t)
			mutate(&next.Users[0].Credentials[0])
			if next.Users[0].Credentials[0] == old.Users[0].Credentials[0] {
				t.Fatalf("%s: the mutation changed nothing", name)
			}
			got := Diff(old, next)
			if len(got) != 2 || !strings.HasPrefix(got[0], "- credential alice ") || !strings.HasPrefix(got[1], "+ credential alice ") ||
				strings.TrimPrefix(got[0], "- ") == strings.TrimPrefix(got[1], "+ ") {
				t.Fatalf("%s: Diff =\n%q\nwant a - and a + line for alice whose texts differ", name, got)
			}
		}
	})
	t.Run("extension_control_bytes_escaped", func(t *testing.T) {
		// Role extensions are the one free-text field of a directory: a
		// signed directory must not reach the admin's terminal with escape
		// sequences, in directory show or in a co-signer's diff
		// (pre-merge review, 02-09).
		old := vectorV1(t)
		next := vectorV1(t)
		next.Roles[0].Extensions = []string{"\x1b[2K\x1b[1Apermit-pty", "permit-port-forwarding", "with space", `"quoted"`}
		next.Sort()
		var all strings.Builder
		for _, line := range append(Diff(old, next), Diff(nil, next)...) {
			all.WriteString(line + "\n")
			for _, r := range line {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("Diff line %q holds the control byte %#x", line, r)
				}
			}
		}
		for _, want := range []string{`"\x1b[2K\x1b[1Apermit-pty"`, " permit-port-forwarding ", `"with space"`, `"\"quoted\""`} {
			if !strings.Contains(all.String(), want) {
				t.Fatalf("Diff output lacks %s:\n%s", want, all.String())
			}
		}
	})
	t.Run("order_is_stable", func(t *testing.T) {
		// The same change built in another order gives the same lines.
		old := vectorV1(t)
		a, b := vectorV1(t), vectorV1(t)
		for _, n := range []string{"zed", "amy", "kim"} {
			a.Groups = append(a.Groups, Group{Name: n, Members: []string{"alice"}})
		}
		for _, n := range []string{"kim", "zed", "amy"} {
			b.Groups = append(b.Groups, Group{Name: n, Members: []string{"alice"}})
		}
		a.Sort()
		b.Sort()
		if da, db := Diff(old, a), Diff(old, b); !slices.Equal(da, db) || len(da) != 3 || da[0] != "+ group amy members=[alice]" {
			t.Fatalf("Diff depends on build order:\n%q\n%q", da, db)
		}
		if a.Version != 1 || a.Prev != trust.GenesisPrev {
			t.Fatal("the vector changed")
		}
	})
}
