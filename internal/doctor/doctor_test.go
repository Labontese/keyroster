package doctor

import (
	"crypto/ed25519"
	"crypto/rand"
	"math"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

const signerUID = 998

// testKey returns a fresh Ed25519 public key in bundle format.
func testKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return trust.FormatKey(sp)
}

// hardwareKeys is a full set of online keys with hardware custody.
func hardwareKeys(custody, alg string) []CAKeyFact {
	keys := make([]CAKeyFact, 0, 5)
	for _, role := range []string{"user", "host", "machine", "ops", "log"} {
		keys = append(keys, CAKeyFact{Role: role, Alg: alg, Custody: custody})
	}
	return keys
}

// healthy returns the facts of a correctly installed signer with a
// physical TPM and a FIDO root: doctor reports no WARN or FAIL for it.
func healthy(t *testing.T) Facts {
	t.Helper()
	const hw = uint64(1_790_000_000_000_000)
	return Facts{
		UID:             signerUID,
		SignerUID:       signerUID,
		StateDirMode:    0o700,
		StateDirOwner:   signerUID,
		DBMode:          0o600,
		IntegrityOK:     true,
		LogMatches:      true,
		NowMicros:       hw + 3_600_000_000,
		HighWaterMicros: hw,
		Bundle: &trust.Bundle{
			Version: 1,
			Root:    trust.RootSet{Keys: []trust.RootKey{{Key: testKey(t), Custody: "fido"}}, Threshold: 1},
		},
		CAKeys:          hardwareKeys("tpm", ssh.KeyAlgoECDSA256),
		TPMManufacturer: "INTC",
		TPMCustody:      "tpm",
	}
}

// find returns the results with code.
func find(rs []Result, code string) []Result {
	var out []Result
	for _, r := range rs {
		if r.Code == code {
			out = append(out, r)
		}
	}
	return out
}

// requireOne fails unless rs holds exactly one result with code, at level.
func requireOne(t *testing.T, rs []Result, level Level, code string) Result {
	t.Helper()
	got := find(rs, code)
	if len(got) != 1 || got[0].Level != level {
		t.Fatalf("want exactly one %s %s, got %v in\n%s", level, code, got, format(rs))
	}
	return got[0]
}

func requireNone(t *testing.T, rs []Result, code string) {
	t.Helper()
	if got := find(rs, code); len(got) != 0 {
		t.Fatalf("want no %s, got %v in\n%s", code, got, format(rs))
	}
}

func format(rs []Result) string {
	var b strings.Builder
	for _, r := range rs {
		b.WriteString(r.String())
		b.WriteByte('\n')
	}
	return b.String()
}

func TestHealthyHasNoWarnings(t *testing.T) {
	rs := Run(healthy(t))
	if len(rs) == 0 {
		t.Fatal("Run returned no results")
	}
	for _, r := range rs {
		if r.Level >= WARN {
			t.Errorf("unexpected %s", r)
		}
	}
	if ExitCode(rs) != 0 {
		t.Fatalf("ExitCode = %d, want 0", ExitCode(rs))
	}
	requireOne(t, rs, OK, "custody")
	requireOne(t, rs, OK, "trust")
}

// TestTrustMismatchIsNotOK (C-WR-02): a trust check failure replaces the
// trust OK line, and its message names the reason and that serve refuses.
func TestTrustMismatchIsNotOK(t *testing.T) {
	f := healthy(t)
	f.TrustError = "policy admin alice uses the log key"
	rs := Run(f)
	r := requireOne(t, rs, FAIL, CodeTrustMismatch)
	if !strings.Contains(r.Message, f.TrustError) || !strings.Contains(r.Message, "serve refuses to start") {
		t.Fatalf("trust_mismatch message = %q", r.Message)
	}
	requireNone(t, rs, "trust")
}

func TestFailures(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Facts)
		code string
	}{
		{"root", func(f *Facts) { f.UID = 0 }, CodeRunningAsRoot},
		{"state dir 0755", func(f *Facts) { f.StateDirMode = 0o755 }, CodeStateDirPermissions},
		{"state dir 0750", func(f *Facts) { f.StateDirMode = 0o750 }, CodeStateDirPermissions},
		{"state dir wrong owner", func(f *Facts) { f.StateDirOwner = 0 }, CodeStateDirPermissions},
		{"state dir missing", func(f *Facts) { f.StateDirError = "lstat /var/lib/keyroster-signer: no such file or directory" }, CodeStateDirPermissions},
		{"db 0644", func(f *Facts) { f.DBMode = 0o644 }, CodeDBPermissions},
		{"db 0660", func(f *Facts) { f.DBMode = 0o660 }, CodeDBPermissions},
		{"integrity", func(f *Facts) { f.IntegrityOK, f.IntegrityDetail = false, "row 3 missing from index" }, CodeDBIntegrity},
		{"db unreadable", func(f *Facts) { f.DBError = "open signer.db: permission denied" }, CodeDBIntegrity},
		{"log mismatch", func(f *Facts) { f.LogMatches, f.LogDetail = false, "leaf 2 does not match its stored hash" }, CodeLogMismatch},
		{"trust mismatch", func(f *Facts) { f.TrustError = "the log key is SHA256:x, ca-init chose SHA256:y" }, CodeTrustMismatch},
		{"logged bundle missing", func(f *Facts) {
			f.Bundle, f.TrustError = nil, "the log records an installed trust bundle, but the state database holds none"
		}, CodeTrustMismatch},
		{"clock regression", func(f *Facts) { f.NowMicros = f.HighWaterMicros - 1 }, CodeClockRegression},
		{"clock an hour behind", func(f *Facts) { f.NowMicros = f.HighWaterMicros - 3_600_000_000 }, CodeClockRegression},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := healthy(t)
			tc.edit(&f)
			rs := Run(f)
			r := requireOne(t, rs, FAIL, tc.code)
			if r.Message == "" {
				t.Fatalf("%s has no message", tc.code)
			}
			if ExitCode(rs) != 1 {
				t.Fatalf("ExitCode = %d, want 1 with a FAIL", ExitCode(rs))
			}
		})
	}
}

func TestNoFailure(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Facts)
	}{
		{"db 0400", func(f *Facts) { f.DBMode = 0o400 }},
		{"clock equal to high-water", func(f *Facts) { f.NowMicros = f.HighWaterMicros }},
		{"clock 60 s ahead", func(f *Facts) { f.NowMicros = f.HighWaterMicros + 60_000_000 }},
		{"no serial issued yet", func(f *Facts) { f.HighWaterMicros = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := healthy(t)
			tc.edit(&f)
			rs := Run(f)
			if len(rs) == 0 {
				t.Fatal("Run returned no results")
			}
			for _, r := range rs {
				if r.Level == FAIL {
					t.Fatalf("unexpected %s", r)
				}
			}
			if ExitCode(rs) != 0 {
				t.Fatalf("ExitCode = %d, want 0", ExitCode(rs))
			}
		})
	}
}

func TestClockMessageNamesTheGap(t *testing.T) {
	f := healthy(t)
	f.NowMicros = f.HighWaterMicros - 90_000_000
	r := requireOne(t, Run(f), FAIL, CodeClockRegression)
	if !strings.Contains(r.Message, "90") {
		t.Fatalf("clock_regression message does not name the 90 s gap: %q", r.Message)
	}
}

func TestDBErrorSkipsDependentChecks(t *testing.T) {
	f := healthy(t)
	f.DBError = "open signer.db: no such file"
	f.IntegrityOK, f.LogMatches = false, false
	rs := Run(f)
	requireOne(t, rs, FAIL, CodeDBIntegrity)
	// Nothing read from an unreadable database may be reported as OK.
	for _, code := range []string{"log", "clock", "custody", "bundle", "trust"} {
		requireNone(t, rs, code)
	}
}

func TestNoBundle(t *testing.T) {
	f := healthy(t)
	f.Bundle = nil
	rs := Run(f)
	requireOne(t, rs, WARN, CodeNoBundle)
	requireNone(t, rs, "trust")
	if ExitCode(rs) != 0 {
		t.Fatal("no_bundle must not fail doctor")
	}
}

func TestSoftwareRoot(t *testing.T) {
	f := healthy(t)
	f.Bundle.Root.Keys = append(f.Bundle.Root.Keys, trust.RootKey{Key: testKey(t), Custody: "software"})
	rs := Run(f)
	r := requireOne(t, rs, WARN, CodeSoftwareRoot)
	if !strings.HasPrefix(r.Message, "SOFTWARE ROOT:") {
		t.Fatalf("software_root message must start with SOFTWARE ROOT:, got %q", r.Message)
	}
	if !strings.Contains(r.Line(), "WARN software_root: SOFTWARE ROOT:") {
		t.Fatalf("line = %q", r.Line())
	}
	// A software root is never reported as hardware custody.
	requireNone(t, rs, "roots")
	if ExitCode(rs) != 0 {
		t.Fatal("a software root warns, it does not fail")
	}
}

func TestTwoSoftwareRootsWarnTwice(t *testing.T) {
	f := healthy(t)
	f.Bundle.Root.Keys = []trust.RootKey{{Key: testKey(t), Custody: "software"}, {Key: testKey(t), Custody: "software"}}
	if got := find(Run(f), CodeSoftwareRoot); len(got) != 2 {
		t.Fatalf("want one software_root warning per root, got %d", len(got))
	}
}

func TestVTPMCustody(t *testing.T) {
	f := healthy(t)
	f.CAKeys = hardwareKeys("vtpm", ssh.KeyAlgoECDSA256)
	f.TPMManufacturer, f.TPMCustody = "IBM", "vtpm"
	rs := Run(f)
	r := requireOne(t, rs, WARN, CodeVTPMCustody)
	if !strings.Contains(r.Message, "hypervisor") {
		t.Fatalf("vtpm_custody must say the keys are only as safe as the hypervisor host: %q", r.Message)
	}
	// A vTPM-held key is never reported as hardware custody; the TPM line
	// only confirms that the live TPM matches the recorded custody.
	requireNone(t, rs, "custody")
	requireNone(t, rs, CodeCustodyMismatch)
	if tpm := requireOne(t, rs, OK, "tpm"); !strings.Contains(tpm.Message, "IBM maps to custody vtpm") {
		t.Fatalf("tpm line = %q", tpm.Message)
	}
}

func TestSoftwareKeyInAgent(t *testing.T) {
	f := healthy(t)
	f.CAKeys = hardwareKeys("agent", ssh.KeyAlgoED25519)
	f.TPMManufacturer, f.TPMCustody = "", ""
	rs := Run(f)
	requireOne(t, rs, WARN, CodeSoftwareKeyInAgent)
	requireNone(t, rs, "custody")
}

func TestSoftwareOnlineKey(t *testing.T) {
	f := healthy(t)
	f.CAKeys = hardwareKeys("software", ssh.KeyAlgoED25519)
	f.TPMManufacturer, f.TPMCustody = "", ""
	rs := Run(f)
	requireOne(t, rs, WARN, CodeSoftwareKey)
	requireNone(t, rs, "custody")
}

func TestPKCS11Ed25519NeedsAgent101(t *testing.T) {
	f := healthy(t)
	f.CAKeys = hardwareKeys("pkcs11-agent", ssh.KeyAlgoED25519)
	f.TPMManufacturer, f.TPMCustody = "", ""
	rs := Run(f)
	r := requireOne(t, rs, INFO, CodePKCS11Ed25519)
	if !strings.Contains(r.Message, "10.1") {
		t.Fatalf("pkcs11_ed25519 must name ssh-agent 10.1: %q", r.Message)
	}

	f.CAKeys = hardwareKeys("pkcs11-agent", ssh.KeyAlgoECDSA256)
	requireNone(t, Run(f), CodePKCS11Ed25519)
}

// TestPKCS11CustodyDeclared (D-WR-03, C-WR-04): custody pkcs11-agent is
// the operator's declaration (a plain ssh-add key or a SoftHSM token in
// the agent looks the same), so doctor says so and never prints the OK
// hardware-custody line for it, alone or mixed with verified custody.
func TestPKCS11CustodyDeclared(t *testing.T) {
	f := healthy(t)
	f.CAKeys = hardwareKeys("pkcs11-agent", ssh.KeyAlgoECDSA256)
	f.TPMManufacturer, f.TPMCustody = "", ""
	rs := Run(f)
	r := requireOne(t, rs, INFO, CodePKCS11CustodyDeclared)
	if !strings.Contains(r.Message, "user, host, machine, ops, log") || !strings.Contains(r.Message, "cannot verify") {
		t.Fatalf("pkcs11_custody_declared must name the keys and say it is unverified: %q", r.Message)
	}
	requireNone(t, rs, "custody")
	if ExitCode(rs) != 0 {
		t.Fatalf("declared custody alone must not fail doctor: %v", rs)
	}

	// Mixed with keys in a confirmed physical TPM: still no OK line.
	f = healthy(t)
	f.CAKeys[0].Custody = "pkcs11-agent"
	rs = Run(f)
	requireOne(t, rs, INFO, CodePKCS11CustodyDeclared)
	requireNone(t, rs, "custody")
}

// TestPIVCustodyReported (F-WR-04, D-WR-04): custody piv is what the card
// reported at ca-init, slot attestation is not checked, and doctor does
// not read the card, so it says so in an INFO line and never prints the OK
// hardware-custody line for it, alone or mixed with verified custody.
func TestPIVCustodyReported(t *testing.T) {
	f := healthy(t)
	f.CAKeys = hardwareKeys("piv", ssh.KeyAlgoED25519)
	f.TPMManufacturer, f.TPMCustody = "", ""
	rs := Run(f)
	r := requireOne(t, rs, INFO, CodePIVCustodyReported)
	if !strings.Contains(r.Message, "user, host, machine, ops, log") || !strings.Contains(r.Message, "not checked") ||
		!strings.Contains(r.Message, "did not read the card") {
		t.Fatalf("piv_custody_reported must name the keys and say the custody is not checked: %q", r.Message)
	}
	requireNone(t, rs, "custody")
	if ExitCode(rs) != 0 {
		t.Fatalf("card-reported custody alone must not fail doctor: %v", rs)
	}

	// Mixed with keys in a confirmed physical TPM: still no OK line.
	f = healthy(t)
	f.CAKeys[0].Custody = "piv"
	rs = Run(f)
	requireOne(t, rs, INFO, CodePIVCustodyReported)
	requireNone(t, rs, "custody")
}

func TestCustodyMismatch(t *testing.T) {
	f := healthy(t)
	// Recorded as a physical TPM, but the TPM now reports a virtual one.
	f.TPMManufacturer, f.TPMCustody = "IBM", "vtpm"
	rs := Run(f)
	r := requireOne(t, rs, WARN, CodeCustodyMismatch)
	if !strings.Contains(r.Message, "IBM") {
		t.Fatalf("custody_mismatch must name the manufacturer: %q", r.Message)
	}
	requireNone(t, rs, "custody")
	requireNone(t, rs, "tpm")
}

func TestTPMUnavailable(t *testing.T) {
	f := healthy(t)
	f.TPMManufacturer, f.TPMCustody, f.TPMError = "", "", "open /dev/tpmrm0: permission denied"
	rs := Run(f)
	requireOne(t, rs, WARN, CodeTPMUnavailable)
	requireNone(t, rs, "custody")
}

// TestTPMNotInspected (C-WR-03): keys recorded with TPM custody, but no TPM
// read at all (no custody, no error), never yield the hardware custody OK.
func TestTPMNotInspected(t *testing.T) {
	for _, custody := range []string{"tpm", "vtpm"} {
		t.Run(custody, func(t *testing.T) {
			f := healthy(t)
			f.CAKeys = hardwareKeys(custody, ssh.KeyAlgoECDSA256)
			f.TPMManufacturer, f.TPMCustody, f.TPMError = "", "", ""
			rs := Run(f)
			r := requireOne(t, rs, WARN, CodeTPMUnavailable)
			if !strings.Contains(r.Message, "not inspected") {
				t.Fatalf("tpm_unavailable must say the TPM was not inspected: %q", r.Message)
			}
			requireNone(t, rs, "custody")
			requireNone(t, rs, "tpm")
		})
	}
}

func TestLevelsAndLines(t *testing.T) {
	for l, want := range map[Level]string{OK: "OK", INFO: "INFO", WARN: "WARN", FAIL: "FAIL"} {
		if l.String() != want {
			t.Errorf("%d.String() = %q, want %q", l, l.String(), want)
		}
	}
	r := Result{Level: WARN, Code: "no_bundle", Message: "no trust bundle installed"}
	if r.Line() != "WARN no_bundle: no trust bundle installed" {
		t.Fatalf("Line = %q", r.Line())
	}
}

// TestDoctorRestoreMarker (03-12): a restore-recovery-pending marker in the
// state directory is a FAIL that names it; no marker, no line.
func TestDoctorRestoreMarker(t *testing.T) {
	t.Run("fails_with_path", func(t *testing.T) {
		f := healthy(t)
		f.RestoreMarker = "/var/lib/keyroster-signer/restore-recovery-pending"
		r := requireOne(t, Run(f), FAIL, CodeRestorePending)
		if !strings.Contains(r.Message, f.RestoreMarker) {
			t.Fatalf("the result does not name the marker: %s", r.Line())
		}
	})
	t.Run("absent_no_line", func(t *testing.T) {
		requireNone(t, Run(healthy(t)), "restore_recovery_pending")
	})
}

// TestDoctorInstalledIssuedAt (03-12): an installed bundle dated after the
// wall clock is a WARN; one at or before it, or an issued_at that does not
// parse (the bundle parser already refused such a value), gives nothing.
func TestDoctorInstalledIssuedAt(t *testing.T) {
	at := func(f Facts, d time.Duration) string {
		return time.UnixMicro(int64(f.NowMicros)).Add(d).UTC().Truncate(time.Second).Format(trust.TimeFormat) //nolint:gosec // G115: a test clock
	}
	t.Run("after_now_warns", func(t *testing.T) {
		f := healthy(t)
		f.Bundle.IssuedAt = at(f, 10*time.Second)
		r := requireOne(t, Run(f), WARN, "installed_issued_at_after_now")
		if !strings.Contains(r.Message, f.Bundle.IssuedAt) {
			t.Fatalf("the warning does not name the issued_at: %s", r.Line())
		}
	})
	t.Run("not_after_now_ok", func(t *testing.T) {
		f := healthy(t)
		f.Bundle.IssuedAt = at(f, -10*time.Second)
		requireNone(t, Run(f), "installed_issued_at_after_now")
	})
	t.Run("unparseable_is_skipped", func(t *testing.T) {
		f := healthy(t)
		f.Bundle.IssuedAt = "not a time"
		requireNone(t, Run(f), "installed_issued_at_after_now")
	})
}

// TestDoctorGenerations (03-12): one OK line coded generations names each
// role's active and prepared generations with their fingerprints; with no
// generation fact there is no line.
func TestDoctorGenerations(t *testing.T) {
	f := healthy(t)
	f.Generations = []GenerationFact{
		{Role: "user", Generation: 1, Fingerprint: "SHA256:aaa", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "active"},
		{Role: "user", Generation: 2, Fingerprint: "SHA256:bbb", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "prepared"},
		{Role: "host", Generation: 1, Fingerprint: "SHA256:ccc", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "active"},
	}
	r := requireOne(t, Run(f), OK, "generations")
	for _, want := range []string{"user", "active g1 SHA256:aaa", "prepared g2 SHA256:bbb", "host", "active g1 SHA256:ccc"} {
		if !strings.Contains(r.Message, want) {
			t.Fatalf("the generations line lacks %q: %s", want, r.Line())
		}
	}
	requireNone(t, Run(healthy(t)), "generations")
	// A draining generation shows its end (03-12c); no other state shows
	// one.
	t.Run("draining_shows_trusted_until", func(t *testing.T) {
		f := healthy(t)
		f.Generations = []GenerationFact{
			{Role: "user", Generation: 1, Fingerprint: "SHA256:aaa", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "draining", TrustedUntil: "2026-10-20T00:00:00Z"},
			{Role: "user", Generation: 2, Fingerprint: "SHA256:bbb", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "active"},
		}
		r := requireOne(t, Run(f), OK, "generations")
		for _, want := range []string{"draining g1 SHA256:aaa until 2026-10-20T00:00:00Z", "active g2 SHA256:bbb"} {
			if !strings.Contains(r.Message, want) {
				t.Fatalf("the generations line lacks %q: %s", want, r.Line())
			}
		}
	})
	t.Run("other_states_show_none", func(t *testing.T) {
		f := healthy(t)
		f.Generations = []GenerationFact{
			{Role: "user", Generation: 1, Fingerprint: "SHA256:aaa", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "active"},
			{Role: "user", Generation: 2, Fingerprint: "SHA256:bbb", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "next"},
			{Role: "user", Generation: 3, Fingerprint: "SHA256:ccc", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "prepared"},
		}
		if r := requireOne(t, Run(f), OK, "generations"); strings.Contains(r.Message, "until") {
			t.Fatalf("a generation that is not draining shows an end: %s", r.Line())
		}
	})
}

// TestDoctorGenerationFiles (03-12): a <role>-g<N>.age file that no
// generation row names is a WARN that names every such path, states the
// conditions under which it is a lost prepare's key, and says when it may
// be destroyed: only once the restore section of signer-install.md has run
// to its end, and never where that section stops on a lost generation.
func TestDoctorGenerationFiles(t *testing.T) {
	paths := []string{"/var/lib/keyroster-signer/software/user-g3.age", "/var/lib/keyroster-signer/software/host-g2.age"}
	t.Run("warns_for_unrecorded_file", func(t *testing.T) {
		f := healthy(t)
		f.UnrecordedGenerationFiles = paths
		r := requireOne(t, Run(f), WARN, "unrecorded_generation_file")
		for _, p := range paths {
			if !strings.Contains(r.Message, p) {
				t.Fatalf("the warning does not name %s: %s", p, r.Line())
			}
		}
	})
	t.Run("warn_text_states_the_conditions", func(t *testing.T) {
		f := healthy(t)
		f.UnrecordedGenerationFiles = paths[:1]
		r := requireOne(t, Run(f), WARN, "unrecorded_generation_file")
		for _, want := range []string{
			"no generation row names this file", "unless you placed it for a --key prepare",
			"once the restore section of docs/runbooks/signer-install.md has run to its end, destroy it",
			"where that section stops on a lost generation, keep it", "never record it again with --key",
		} {
			if !strings.Contains(r.Message, want) {
				t.Fatalf("the warning lacks %q: %s", want, r.Line())
			}
		}
	})
	t.Run("none_no_line", func(t *testing.T) {
		requireNone(t, Run(healthy(t)), "unrecorded_generation_file")
	})
}

// TestDoctorSwitch (03-12e, SR-08 and SR-09): a draining CA generation
// the backend still holds is a FAIL draining_key_still_usable; per CA role
// with an active key, an OK switch_floor line names the certificate that
// sets the earliest trusted_until a switch could carry (its ValidBefore
// plus 300 s), or says the log records none; a draining generation the
// backend no longer holds gives no FAIL and exit code 0.
func TestDoctorSwitch(t *testing.T) {
	at := func(s string) uint64 {
		t.Helper()
		v, err := time.Parse(trust.TimeFormat, s)
		if err != nil {
			t.Fatal(err)
		}
		return uint64(v.Unix()) //nolint:gosec // G115: after 1970
	}
	switched := func(t *testing.T) Facts {
		t.Helper()
		f := healthy(t)
		f.Generations = []GenerationFact{
			{Role: "user", Generation: 1, Fingerprint: "SHA256:aaa", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "draining", TrustedUntil: "2026-12-01T00:00:00Z"},
			{Role: "user", Generation: 2, Fingerprint: "SHA256:bbb", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "active"},
		}
		return f
	}
	floorLines := func(rs []Result) []string {
		var out []string
		for _, r := range find(rs, "switch_floor") {
			out = append(out, r.Line())
		}
		return out
	}
	t.Run("draining_key_held_fails", func(t *testing.T) {
		f := switched(t)
		f.DrainingHeld = []HeldFact{{Role: "user", Generation: 1, Fingerprint: "SHA256:aaa"}}
		rs := Run(f)
		r := requireOne(t, rs, FAIL, "draining_key_still_usable")
		if want := "FAIL draining_key_still_usable: user generation 1 SHA256:aaa is still held by the backend"; r.Line() != want {
			t.Fatalf("the line is\n%s\nwant\n%s", r.Line(), want)
		}
		if ExitCode(rs) != 1 {
			t.Fatalf("ExitCode = %d, want 1", ExitCode(rs))
		}
	})
	t.Run("switch_floor_shows_the_certificate", func(t *testing.T) {
		f := switched(t)
		f.SwitchFloors = []SwitchFloor{
			{Role: "user", Generation: 2, HasCertificate: true, Serial: 42, KeyID: "kr1/ca=user/ser=42", ValidBefore: at("2026-12-01T00:00:00Z")},
			{Role: "host", Generation: 1, HasCertificate: true, Serial: 7, KeyID: "kr1/ca=host/ser=7", ValidBefore: at("2027-01-01T12:00:00Z")},
		}
		got := floorLines(Run(f))
		want := []string{
			"OK switch_floor: user generation 2: the certificate that sets the earliest trusted_until a switch could carry is serial 42 (key ID kr1/ca=user/ser=42, valid until 2026-12-01T00:00:00Z); the earliest is 2026-12-01T00:05:00Z",
			"OK switch_floor: host generation 1: the certificate that sets the earliest trusted_until a switch could carry is serial 7 (key ID kr1/ca=host/ser=7, valid until 2027-01-01T12:00:00Z); the earliest is 2027-01-01T12:05:00Z",
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("the switch_floor lines are\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})
	t.Run("switch_floor_adds_the_margin", func(t *testing.T) {
		f := switched(t)
		f.SwitchFloors = []SwitchFloor{{Role: "user", Generation: 2, HasCertificate: true, Serial: 9, KeyID: "k", ValidBefore: at("2026-12-31T23:57:00Z")}}
		got := floorLines(Run(f))
		if len(got) != 1 || !strings.HasSuffix(got[0], "valid until 2026-12-31T23:57:00Z); the earliest is 2027-01-01T00:02:00Z") {
			t.Fatalf("the switch_floor lines %q do not name ValidBefore plus 300 s as the earliest", got)
		}
		f.SwitchFloors = []SwitchFloor{{Role: "user", Generation: 2, HasCertificate: true, Serial: 9, KeyID: "k", ValidBefore: math.MaxUint64, Saturated: true}}
		got = floorLines(Run(f))
		if len(got) != 1 || !strings.HasSuffix(got[0], "valid until forever); the earliest is none (that certificate never expires)") {
			t.Fatalf("the switch_floor lines %q for a certificate that never expires", got)
		}
	})
	t.Run("switch_floor_without_certificates", func(t *testing.T) {
		f := switched(t)
		f.SwitchFloors = []SwitchFloor{{Role: "machine", Generation: 1}}
		got := floorLines(Run(f))
		if want := "OK switch_floor: machine generation 1: the log records no certificate of this key; the earliest is the floor"; len(got) != 1 || got[0] != want {
			t.Fatalf("the switch_floor lines are %q, want [%q]", got, want)
		}
	})
	t.Run("no_draining_no_fact", func(t *testing.T) {
		f := healthy(t)
		f.Generations = []GenerationFact{{Role: "user", Generation: 1, Fingerprint: "SHA256:aaa", Alg: ssh.KeyAlgoED25519, Custody: "agent", State: "active"}}
		rs := Run(f)
		for _, code := range []string{"draining_key_still_usable", "draining_key_unchecked", "switch_floor"} {
			requireNone(t, rs, code)
		}
	})
	t.Run("draining_not_held_ok", func(t *testing.T) {
		f := switched(t)
		f.SwitchFloors = []SwitchFloor{{Role: "user", Generation: 2}}
		rs := Run(f)
		requireNone(t, rs, "draining_key_still_usable")
		for _, r := range rs {
			if r.Level == FAIL {
				t.Fatalf("a draining generation the backend no longer holds gives %s", r)
			}
		}
		if ExitCode(rs) != 0 {
			t.Fatalf("ExitCode = %d, want 0", ExitCode(rs))
		}
	})
}
