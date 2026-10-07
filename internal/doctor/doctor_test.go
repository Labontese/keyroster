package doctor

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

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
