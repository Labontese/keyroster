//go:build e2e_tpm

package e2e

import (
	"strings"
	"testing"
)

// TestTPMDoctor: with the TPM backend on swtpm (manufacturer IBM), doctor
// reads the live TPM, finds that it still maps to the recorded custody
// vtpm, and warns that the keys are only as safe as the hypervisor host
// (D-08). It never reports the vTPM keys as hardware custody.
func TestTPMDoctor(t *testing.T) {
	env := prepareSigner(t, bootstrapOpts{Backend: "tpm", BackendOpts: tpmOpts(t)})
	code, out := env.signerCmd(t, "doctor", "--state-dir", env.StateDir)
	if code != 0 {
		t.Fatalf("doctor exited %d, want 0:\n%s", code, out)
	}
	for _, want := range []string{
		"\nWARN vtpm_custody: keys user, host, machine, ops, log are in a virtual TPM",
		"\nWARN software_root: SOFTWARE ROOT:",
		"\nOK tpm: TPM manufacturer IBM maps to custody vtpm, as recorded",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output lacks %q:\n%s", strings.TrimPrefix(want, "\n"), out)
		}
	}
	for _, bad := range []string{"FAIL ", "custody_mismatch", "tpm_unavailable", "OK custody:"} {
		if strings.Contains(out, bad) {
			t.Fatalf("doctor output contains %q:\n%s", bad, out)
		}
	}
}
