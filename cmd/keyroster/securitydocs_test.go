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
// logged, stated for generation 2 or later only, as Holds has it. And
// docs/security/custody.md states the rule for an unrecorded key file for
// both backends that write one, the tpm pair as well as the software file,
// each with the guard that no prepare is running. Each window is the
// document's section, read white-space normalised.
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
	const narrowLocation = `for generation 2 or later an edit that points at another generation slot, one that does not hold the draining key, makes Holds answer "not held"`
	t.Run("tpm_pair_after_restore", func(t *testing.T) {
		win := window(t, doc(t, "docs", "security", "custody.md"), &signingSection{id: "tpm", file: "custody.md", section: "TPM and vTPM (KEY-04, D-07, D-08, D-09)"})
		holds(t, `custody.md "TPM and vTPM (KEY-04, D-07, D-08, D-09)"`, win, []string{
			"pair that no generation row names",
			"when no prepare is running and unless you placed it for a `--key` prepare",
			"to be destroyed and not recorded again, but after a restore only once the restore section of",
			"has run to its end, because where that section stops on a lost generation the pair may hold that generation's key",
			"the rule itself is UNVERIFIED",
		})
	})
	t.Run("software_file_while_no_prepare_runs", func(t *testing.T) {
		win := window(t, doc(t, "docs", "security", "custody.md"), &signingSection{id: "software_ca_keys", file: "custody.md", section: "Software CA keys (KEY-06)"})
		holds(t, `custody.md "Software CA keys (KEY-06)"`, win, []string{
			"when no prepare is running and unless you placed it for a `--key` prepare",
		})
	})
	t.Run("piv_limits_tracked", func(t *testing.T) {
		win := window(t, doc(t, "docs", "security", "needs-hardware.md"), &signingSection{id: "piv", file: "needs-hardware.md", section: "2. YubiKey 5 PIV (KEY-05)"})
		holds(t, `needs-hardware.md "2. YubiKey 5 PIV (KEY-05)"`, win, []string{
			"overwriting the slot by hand does not clear it",
			`only when the rule of piv.md "Generation slots" allows it`,
			"shredded, not proven erased",
			"The location column is not logged",
			narrowLocation,
		})
	})
	t.Run("piv_location_limit", func(t *testing.T) {
		win := window(t, doc(t, "docs", "backends", "piv.md"), &signingSection{id: "ci_and_hardware", file: "piv.md", section: "What CI verifies, and what needs hardware"})
		holds(t, `piv.md "What CI verifies, and what needs hardware"`, win, []string{
			narrowLocation,
			"These are tracked in",
		})
		if strings.Contains(normalizeSpace(win), "points at any slot") {
			t.Errorf(`piv.md "What CI verifies, and what needs hardware" still says an edit that "points at any slot" makes Holds answer "not held"`)
		}
	})
}
