//go:build e2e

package e2e

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // the state database, tampered with as someone with write access would
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
		"OK db_integrity:", "OK log:", "OK clock:", "OK bundle:", "OK trust:",
		"WARN software_root: SOFTWARE ROOT: root " + env.RootFingerprints[0],
		"WARN software_key_in_agent:",
	} {
		requireDoctorLine(t, out, prefix)
	}
	if strings.Contains(out, "FAIL ") || strings.Contains(out, "OK custody:") || strings.Contains(out, "OK roots:") {
		t.Fatalf("doctor reported a FAIL or hardware custody for this software setup:\n%s", out)
	}
}

// TestDoctorFailsWhenServeWouldRefuseTheBundle (C-WR-02): doctor runs the
// trust checks serve runs at start, so a trust_bundle table that no longer
// matches the log's last bundle_install entry is a FAIL trust_mismatch, not
// OK, while the log itself still reproduces its checkpoint.
func TestDoctorFailsWhenServeWouldRefuseTheBundle(t *testing.T) {
	for name, stmt := range map[string]string{
		"installed_signatures_replaced": `UPDATE trust_bundle SET policy_sigs = x'00'`,
		"installed_bundle_deleted":      `DELETE FROM trust_bundle`,
	} {
		t.Run(name, func(t *testing.T) {
			env := prepareSigner(t, bootstrapOpts{})
			db, err := sql.Open("sqlite", filepath.Join(env.StateDir, "signer.db"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			code, out := env.signerCmd(t, "doctor", "--state-dir", env.StateDir)
			if code != 1 {
				t.Fatalf("doctor exited %d, want 1:\n%s", code, out)
			}
			requireDoctorLine(t, out, "FAIL trust_mismatch:")
			requireDoctorLine(t, out, "OK log:")
			if strings.Contains(out, "OK trust:") {
				t.Fatalf("doctor reported OK trust for a tampered bundle:\n%s", out)
			}
		})
	}
}
