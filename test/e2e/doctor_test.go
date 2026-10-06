//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// requireDoctorLine fails unless out has a line starting with prefix.
func requireDoctorLine(t *testing.T, out, prefix string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) {
			return
		}
	}
	t.Fatalf("doctor output has no line starting with %q:\n%s", prefix, out)
}

// TestDoctorReportsTestCustody: after the full bootstrap (agent backend,
// software root), keyroster-signer doctor passes and states the weaker
// custody of this setup loudly: a SOFTWARE ROOT warning and plain keys in
// ssh-agent (D-08, D-11).
func TestDoctorReportsTestCustody(t *testing.T) {
	env := prepareSigner(t, bootstrapOpts{})
	code, out := env.signerCmd(t, "doctor", "--state-dir", env.StateDir)
	if code != 0 {
		t.Fatalf("doctor exited %d, want 0:\n%s", code, out)
	}
	for _, prefix := range []string{
		"OK db_integrity:", "OK log:", "OK clock:", "OK bundle:",
		"WARN software_root: SOFTWARE ROOT: root " + env.RootFingerprints[0],
		"WARN software_key_in_agent:",
	} {
		requireDoctorLine(t, out, prefix)
	}
	if strings.Contains(out, "FAIL ") || strings.Contains(out, "OK custody:") || strings.Contains(out, "OK roots:") {
		t.Fatalf("doctor reported a FAIL or hardware custody for this software setup:\n%s", out)
	}
}
