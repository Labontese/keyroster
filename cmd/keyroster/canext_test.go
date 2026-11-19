package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/trust"
)

// pinnedPrepareFile is the prepare file of
// cmd/keyroster-signer/rotate_test.go's prepare_file_bytes_pinned: the
// user CA generation 2 with the Ed25519 key of seed 0x00..0x1f in software
// custody. Both files pin the same bytes and change together (03-12b).
const pinnedPrepareFile = `{"role":"user","generation":2,"key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4","alg":"ssh-ed25519","custody":"software"}` + "\n"

const pinnedPrepareKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4"

// prepareFileRefusals are the prepare files parseCANextFile refuses, one
// per rule, by subtest name.
func prepareFileRefusals() map[string]string {
	pinned := strings.TrimSuffix(pinnedPrepareFile, "\n")
	return map[string]string{
		"non_canonical_refused":    `{"generation":2,"role":"user","key":"` + pinnedPrepareKey + `","alg":"ssh-ed25519","custody":"software"}` + "\n",
		"unknown_field_refused":    strings.TrimSuffix(pinned, "}") + `,"installation_id":"0123456789abcdef0123456789abcdef"}` + "\n",
		"trailing_data_refused":    pinnedPrepareFile + "{}\n",
		"role_ops_refused":         strings.Replace(pinnedPrepareFile, `"role":"user"`, `"role":"ops"`, 1),
		"role_unknown_refused":     strings.Replace(pinnedPrepareFile, `"role":"user"`, `"role":"admin"`, 1),
		"generation_1_refused":     strings.Replace(pinnedPrepareFile, `"generation":2`, `"generation":1`, 1),
		"key_with_comment_refused": strings.Replace(pinnedPrepareFile, pinnedPrepareKey, pinnedPrepareKey+" user-g2", 1),
		"alg_mismatch_refused":     strings.Replace(pinnedPrepareFile, `"alg":"ssh-ed25519"`, `"alg":"ecdsa-sha2-nistp256"`, 1),
		"oversize_refused":         pinnedPrepareFile + strings.Repeat(" ", 4097-len(pinnedPrepareFile)),
		"empty_refused":            "",
	}
}

// TestParseCANextFile (03-12b): the prepare file is read strictly, as the
// signer writes it.
func TestParseCANextFile(t *testing.T) {
	t.Run("pinned_bytes_parse", func(t *testing.T) {
		e, err := parseCANextFile([]byte(pinnedPrepareFile))
		want := trust.CAEntry{Role: "user", Key: pinnedPrepareKey, Alg: "ssh-ed25519", Custody: "software", State: "next", Generation: 2}
		if err != nil || e != want {
			t.Fatalf("parseCANextFile(pinned) = %+v, %v; want %+v", e, err, want)
		}
	})
	refusals := prepareFileRefusals()
	for _, name := range []string{"non_canonical_refused", "unknown_field_refused", "trailing_data_refused", "role_ops_refused",
		"role_unknown_refused", "generation_1_refused", "key_with_comment_refused", "alg_mismatch_refused", "oversize_refused", "empty_refused"} {
		t.Run(name, func(t *testing.T) {
			data := refusals[name]
			if name == "oversize_refused" && len(data) != 4097 {
				t.Fatalf("the oversize fixture is %d bytes, want %d", len(data), 4097)
			}
			if e, err := parseCANextFile([]byte(data)); err == nil {
				t.Fatalf("parseCANextFile accepted %q as %+v", data, e)
			}
		})
	}
}

// TestReadCANextFile (03-12b): the reader takes a regular file within the
// size bound.
func TestReadCANextFile(t *testing.T) {
	dir := t.TempDir()
	t.Run("reads_the_pinned_file", func(t *testing.T) {
		path := filepath.Join(dir, "user-g2.json")
		writeTestFile(t, path, []byte(pinnedPrepareFile))
		if e, err := readCANextFile(path); err != nil || e.Key != pinnedPrepareKey || e.State != "next" {
			t.Fatalf("readCANextFile = %+v, %v", e, err)
		}
	})
	t.Run("refuses_a_directory", func(t *testing.T) {
		if e, err := readCANextFile(dir); err == nil {
			t.Fatalf("readCANextFile accepted a directory as %+v", e)
		}
	})
	t.Run("refuses_an_oversize_file", func(t *testing.T) {
		// A file far above the bound: the size is checked before
		// anything is read.
		path := filepath.Join(dir, "big.json")
		f, err := os.Create(path) //nolint:gosec // G304: a test file
		if err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(1 << 24); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if e, err := readCANextFile(path); err == nil || !strings.Contains(err.Error(), "4096") {
			t.Fatalf("readCANextFile of a 16 MiB file = %+v, %v; want a refusal naming the bound", e, err)
		}
	})
}

// FuzzParseCANextFile (03-12b): parseCANextFile never panics, and an
// accepted entry is a next entry of user, host or machine, generation at
// least 2, a canonical key of type alg, that re-encodes to the input.
func FuzzParseCANextFile(f *testing.F) {
	f.Add([]byte(pinnedPrepareFile))
	for _, data := range prepareFileRefusals() {
		f.Add([]byte(data))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := parseCANextFile(data)
		if err != nil {
			return
		}
		if e.Role != "user" && e.Role != "host" && e.Role != "machine" {
			t.Fatalf("accepted role %q", e.Role)
		}
		if e.Generation < 2 || e.State != "next" || e.Custody == "" {
			t.Fatalf("accepted %+v", e)
		}
		pub, err := trust.ParseKey(e.Key)
		if err != nil || trust.FormatKey(pub) != e.Key || pub.Type() != e.Alg {
			t.Fatalf("accepted key %q alg %q (%v)", e.Key, e.Alg, err)
		}
		// The writer's field order (cmd/keyroster-signer/rotate.go).
		re, err := trust.CanonicalJSON(struct {
			Role       string `json:"role"`
			Generation uint32 `json:"generation"`
			Key        string `json:"key"`
			Alg        string `json:"alg"`
			Custody    string `json:"custody"`
		}{e.Role, e.Generation, e.Key, e.Alg, e.Custody})
		if err != nil || !bytes.Equal(re, data) {
			t.Fatalf("accepted %q, which re-encodes to %q (%v)", data, re, err)
		}
	})
}

// TestParseCAChangesSwitch (03-12e2): --ca-switch names a role of user,
// host and machine, and the one-change-per-role rule spans all four CA
// flags. Each refusal is a usage error, which root sign turns into exit 2.
func TestParseCAChangesSwitch(t *testing.T) {
	const once = "at most one CA change per role: user is named more than once"
	refused := func(t *testing.T, want string, next, fingerprint, retire, switchRoles []string) {
		t.Helper()
		c, err := parseCAChanges(next, fingerprint, retire, switchRoles)
		var u usageError
		if err == nil || !errors.As(err, &u) || err.Error() != want {
			t.Fatalf("parseCAChanges(%q, %q, %q, %q) = %+v, %v; want the usage refusal %q", next, fingerprint, retire, switchRoles, c, err, want)
		}
	}
	t.Run("switch_role_ok", func(t *testing.T) {
		c, err := parseCAChanges(nil, nil, nil, []string{"user", "host"})
		if err != nil || !slices.Equal(c.switchRoles, []string{"user", "host"}) {
			t.Fatalf("--ca-switch user --ca-switch host: %+v, %v; want the switch roles user and host", c, err)
		}
		// A switch of one role beside a next entry of another.
		c, err = parseCAChanges([]string{"host=host-g2.json"}, []string{"host=SHA256:x"}, nil, []string{"user"})
		if err != nil || !slices.Equal(c.switchRoles, []string{"user"}) || c.next["host"] != "host-g2.json" {
			t.Fatalf("--ca-switch user beside --ca-next host: %+v, %v", c, err)
		}
	})
	t.Run("switch_and_next_same_role_refused", func(t *testing.T) {
		refused(t, once, []string{"user=user-g2.json"}, []string{"user=SHA256:x"}, nil, []string{"user"})
	})
	t.Run("switch_and_retire_same_role_refused", func(t *testing.T) {
		refused(t, once, nil, nil, []string{"user:2"}, []string{"user"})
	})
	t.Run("switch_twice_refused", func(t *testing.T) {
		refused(t, once, nil, nil, nil, []string{"user", "user"})
	})
	t.Run("unknown_role_refused", func(t *testing.T) {
		refused(t, "--ca-switch admin: the role is not one of user, host and machine", nil, nil, nil, []string{"admin"})
	})
}
