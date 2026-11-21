package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityDocs pins two promises of the security documents. The
// hardware checklist (docs/security/needs-hardware.md) tracks the limits
// that the needs-hardware list of docs/backends/piv.md says it tracks: the
// slot that overwriting by hand does not clear, the rule of piv.md
// "Generation slots" for emptying it, the management key file that is
// shredded and not proven erased, and the location column that is not
// logged, with what retire-key and prepare still do after an edited
// location and the limit stated for generation 2 or later only, as Holds
// has it. And docs/security/custody.md states the rule for an unrecorded
// key file for both backends that write one, the tpm pair as well as the
// software file, each with the guard that no prepare is running. Each text
// is read in its own row, bullet or paragraph (the software sentence in
// its section), white-space normalised, so that a clause moved to another
// row or out of its block does not pass.
func TestSecurityDocs(t *testing.T) {
	window := func(t *testing.T, data string, e *signingSection) string {
		t.Helper()
		win, err := sectionWindow(data, e)
		if err != nil {
			t.Fatalf("%s %s: %v", e.file, e.id, err)
		}
		return win
	}
	holds := func(t *testing.T, where, win string, want []string) {
		t.Helper()
		flat := normalizeSpace(win)
		for _, w := range want {
			if !strings.Contains(flat, w) {
				t.Errorf("%s lacks %q", where, w)
			}
		}
	}
	doc := func(t *testing.T, parts ...string) string {
		t.Helper()
		return string(readTestFile(t, filepath.Join(append([]string{"..", ".."}, parts...)...)))
	}
	// locationLimit is the location sentence of piv.md's bullet and of the
	// checklist's row, from its first word to its end.
	const locationLimit = `after a database edit of a PIV generation's location, retire-key still overwrites a slot only when its key has the draining fingerprint and prepare still generates only into an empty slot, so no other key is written over, but for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held", and audit cannot show which slot a generation used.`
	t.Run("tpm_pair_after_restore", func(t *testing.T) {
		section := &signingSection{id: "tpm", file: "custody.md", section: "TPM and vTPM (KEY-04, D-07, D-08, D-09)"}
		para := window(t, doc(t, "docs", "security", "custody.md"), &signingSection{id: "tpm_pair", file: "custody.md", within: section,
			start: "A `{role}-g<N>.tpmkey` and `.auth` pair", endNext: func(l string) bool { return l == "" }})
		holds(t, `the tpm pair paragraph of custody.md "TPM and vTPM (KEY-04, D-07, D-08, D-09)"`, para, []string{
			"A `{role}-g<N>.tpmkey` and `.auth` pair that no generation row names (doctor warns `unrecorded_generation_file`) is, when no prepare is running and unless you placed it for a `--key` prepare, a key from a lost prepare, to be destroyed and not recorded again, but after a restore only once the restore section of",
			"has run to its end, because where that section stops on a lost generation the pair may hold that generation's key",
			"the rule itself is UNVERIFIED on a physical TPM and on the homelab vTPM signer",
		})
	})
	t.Run("software_file_while_no_prepare_runs", func(t *testing.T) {
		win := window(t, doc(t, "docs", "security", "custody.md"), &signingSection{id: "software_ca_keys", file: "custody.md", section: "Software CA keys (KEY-06)"})
		holds(t, `custody.md "Software CA keys (KEY-06)"`, win, []string{
			"one that no generation row names is, when no prepare is running and unless you placed it for a `--key` prepare, a key from a lost prepare, to be destroyed and not recorded again, but after a restore only once the restore section of",
		})
	})
	t.Run("piv_limits_tracked", func(t *testing.T) {
		// The checklist is read with its boxes unticked, so that a tester
		// who ticks a box ("- [x] ") moves no window and breaks no start
		// marker.
		data := strings.ReplaceAll(doc(t, "docs", "security", "needs-hardware.md"), "- [x] ", "- [ ] ")
		section := &signingSection{id: "piv", file: "needs-hardware.md", section: "2. YubiKey 5 PIV (KEY-05)"}
		// The block runs from its heading line to the section's end.
		block := &signingSection{id: "generations", file: "needs-hardware.md", within: section, start: "CA key generations (docs/backends/piv.md"}
		// A row runs to the next row or the next blank line.
		row := func(id, start string) string {
			return window(t, data, &signingSection{id: id, file: "needs-hardware.md", within: block, start: start,
				endNext: func(l string) bool { return strings.HasPrefix(l, "- [ ] ") || l == "" }})
		}
		holds(t, "needs-hardware.md, the row on the management key", row("mgmt_key", "- [ ] The management key placed for the run"), []string{
			"shredded on every exit status (shredded, not proven erased: `shred` does not reliably erase a file on an SSD or a copy-on-write filesystem)",
		})
		holds(t, "needs-hardware.md, the row on a key that no row records", row("unrecorded_key", "- [ ] A key in the next generation slot that no row records"), []string{
			"is refused `ErrSlotOccupied`, and overwriting the slot by hand does not clear it. It is emptied with `ykman piv keys delete <slot>` on 5.7 and later, only when the rule of piv.md \"Generation slots\" allows it, with the signer stopped",
		})
		holds(t, "needs-hardware.md, the row on the location column", row("location", "- [ ] The location column is not logged"), []string{
			"The location column is not logged (a later hardening item): " + locationLimit,
		})
	})
	t.Run("piv_location_limit", func(t *testing.T) {
		data := doc(t, "docs", "backends", "piv.md")
		section := &signingSection{id: "ci_and_hardware", file: "piv.md", section: "What CI verifies, and what needs hardware"}
		bullet := window(t, data, &signingSection{id: "location", file: "piv.md", within: section, start: "- the location column is not logged",
			endNext: func(l string) bool { return strings.HasPrefix(l, "- ") || l == "" }})
		holds(t, "piv.md, the bullet on the location column", bullet, []string{
			"the location column is not logged: " + locationLimit,
		})
		win := window(t, data, section)
		holds(t, `piv.md "What CI verifies, and what needs hardware"`, win, []string{"These are tracked in"})
		for _, old := range []string{"points at any slot", "is stopped by the fingerprint checks before any card write"} {
			if strings.Contains(normalizeSpace(win), old) {
				t.Errorf(`piv.md "What CI verifies, and what needs hardware" still says %q`, old)
			}
		}
	})
}
