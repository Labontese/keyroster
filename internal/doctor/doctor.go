// Package doctor turns facts about a keyroster-signer installation into
// OK, INFO, WARN and FAIL results (D-08, D-11). It is pure: the caller
// (keyroster-signer doctor) gathers the facts, so every check is testable on
// every OS.
//
// FAIL means the installation is unsafe or broken: running as root, a state
// directory or database readable by others, a damaged database, an audit
// log that no longer reproduces its signed checkpoint or contradicts the
// tables written with it (the log tables alone rolled back to an earlier
// signed prefix, or wiped; a rollback of the whole database is not
// detectable here, see signer.CheckLog), an installed trust bundle that
// serve would refuse at start (it does not list the recorded keys, names
// an online key or a root as a policy admin, or is not the one the log's
// last bundle_install entry records), or a clock behind the serial
// high-water mark. doctor has neither the backend's keys nor the
// operator's root pins, so a database rewritten consistently with keys and
// roots of the rewriter's choosing passes it. serve refuses such a
// database only while the rewriter cannot also place their keys in the
// backend (with the agent backend, whoever can use the agent socket can);
// the check that holds is keyroster audit verify --pin. Compare the roots
// doctor prints with your pins.
//
// WARN means weaker custody than hardware, stated loudly: a software root
// (SOFTWARE ROOT), keys in a virtual TPM, plain keys in ssh-agent, a TPM
// that no longer matches the recorded custody, or TPM custody that could
// not be confirmed. Custody pkcs11-agent is the operator's declaration,
// which doctor cannot check, and gets an INFO line saying so. doctor never
// reports a vTPM-held, agent-held, declared pkcs11-agent or software key as
// hardware custody.
package doctor

import (
	"fmt"
	"io/fs"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// Level is the severity of a result.
type Level int

// Levels, mildest first.
const (
	OK Level = iota
	INFO
	WARN
	FAIL
)

// String returns the level name: OK, INFO, WARN or FAIL.
func (l Level) String() string {
	switch l {
	case OK:
		return "OK"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case FAIL:
		return "FAIL"
	default:
		return fmt.Sprintf("LEVEL(%d)", int(l))
	}
}

// Result codes of INFO, WARN and FAIL results.
const (
	CodeRunningAsRoot         = "running_as_root"
	CodeStateDirPermissions   = "state_dir_permissions"
	CodeDBPermissions         = "db_permissions"
	CodeDBIntegrity           = "db_integrity"
	CodeLogMismatch           = "log_mismatch"
	CodeTrustMismatch         = "trust_mismatch"
	CodeClockRegression       = "clock_regression"
	CodeNoBundle              = "no_bundle"
	CodeSoftwareRoot          = "software_root"
	CodeVTPMCustody           = "vtpm_custody"
	CodeSoftwareKeyInAgent    = "software_key_in_agent"
	CodeSoftwareKey           = "software_key"
	CodePKCS11Ed25519         = "pkcs11_ed25519"
	CodeCustodyMismatch       = "custody_mismatch"
	CodeTPMUnavailable        = "tpm_unavailable"
	CodePKCS11CustodyDeclared = "pkcs11_custody_declared"
)

// Codes of OK results. Each names the check that passed.
const (
	codeUser      = "user"
	codeStateDir  = "state_dir"
	codeDBMode    = "db_permissions"
	codeIntegrity = "db_integrity"
	codeLog       = "log"
	codeTrust     = "trust"
	codeClock     = "clock"
	codeBundle    = "bundle"
	codeRoots     = "roots"
	codeCustody   = "custody"
	codeTPM       = "tpm"
)

// Result is one finding.
type Result struct {
	Level   Level
	Code    string
	Message string
}

// Line formats r as "LEVEL code: message".
func (r Result) Line() string { return r.Level.String() + " " + r.Code + ": " + r.Message }

// String is Line.
func (r Result) String() string { return r.Line() }

// CAKeyFact is one online key (user, host, machine, ops or log) as ca-init
// recorded it.
type CAKeyFact struct {
	Role, Alg, Custody string
}

// Facts describe an installation. The zero value of a field is not
// "unknown": the gatherer sets DBError when the database could not be read,
// and the database-derived fields are then ignored.
type Facts struct {
	// UID is the uid doctor runs as; SignerUID is the uid the signer runs
	// as, which must own the state directory.
	UID       int
	SignerUID int

	StateDirMode  fs.FileMode
	StateDirOwner int
	// StateDirError is set when the state directory could not be read or
	// is not a directory.
	StateDirError string
	DBMode        fs.FileMode
	// DBError is set when signer.db could not be opened or read; every
	// check of its content is then skipped (and reported as FAIL
	// db_integrity, never as OK).
	DBError string

	// IntegrityOK is PRAGMA integrity_check == "ok"; IntegrityDetail is
	// its output otherwise.
	IntegrityOK     bool
	IntegrityDetail string
	// LogMatches means the stored leaves reproduce the latest checkpoint,
	// signed by the recorded log key, and agree with the CA keys, issuance
	// rows and serial high-water mark (signer.CheckLog); LogDetail says
	// why not.
	LogMatches bool
	LogDetail  string

	// NowMicros is the wall clock and HighWaterMicros the serial
	// high-water mark, both in microseconds since the Unix epoch.
	NowMicros, HighWaterMicros uint64

	// Bundle is the installed trust bundle, nil when none is installed.
	Bundle *trust.Bundle
	// TrustError says why serve would refuse the installed trust bundle
	// (signer.CheckTrust); empty when it would load it, or when none is
	// installed and the log records none.
	TrustError string
	// CAKeys are the online keys ca-init recorded.
	CAKeys []CAKeyFact

	// TPMManufacturer is the live TPM's manufacturer ID and TPMCustody
	// the custody the TPM backend derives from it (after a recorded
	// custody=vtpm override). Both are empty unless the backend is tpm.
	// TPMError is set when the TPM could not be read.
	TPMManufacturer string
	TPMCustody      string
	TPMError        string
}

// hardwareCustody are the online custodies whose keys cannot be copied off
// a physical device and that the backend itself establishes: tpm (also
// cross-checked against the live TPM below) and piv (the card reports the
// key as generated on it). vtpm, agent and software are not among them, and
// neither is pkcs11-agent: that one is the operator's declaration, which
// nothing checks (custodyResults reports it as pkcs11_custody_declared).
var hardwareCustody = map[string]bool{"tpm": true, "piv": true}

// Run checks f and returns the results in a fixed order.
func Run(f Facts) []Result {
	var rs []Result
	add := func(l Level, code, format string, args ...any) {
		rs = append(rs, Result{Level: l, Code: code, Message: fmt.Sprintf(format, args...)})
	}

	if f.UID == 0 {
		add(FAIL, CodeRunningAsRoot, "running as root; run doctor (and the signer) as the signer's own user, e.g. runuser -u keyroster-signer -- keyroster-signer doctor")
	} else {
		add(OK, codeUser, "running as uid %d, not root", f.UID)
	}

	switch {
	case f.StateDirError != "":
		add(FAIL, CodeStateDirPermissions, "state directory: %s", f.StateDirError)
	case f.StateDirMode.Perm() != 0o700 || f.StateDirOwner != f.SignerUID:
		add(FAIL, CodeStateDirPermissions, "state directory has mode %04o and owner uid %d; want 0700 owned by uid %d", f.StateDirMode.Perm(), f.StateDirOwner, f.SignerUID)
	default:
		add(OK, codeStateDir, "state directory is 0700 and owned by uid %d", f.SignerUID)
	}

	if f.DBError != "" {
		add(FAIL, CodeDBIntegrity, "cannot read signer.db: %s; nothing in it was checked", f.DBError)
		return rs
	}
	if f.DBMode.Perm()&0o177 != 0 {
		add(FAIL, CodeDBPermissions, "signer.db has mode %04o; want 0600 or stricter", f.DBMode.Perm())
	} else {
		add(OK, codeDBMode, "signer.db has mode %04o", f.DBMode.Perm())
	}
	if !f.IntegrityOK {
		add(FAIL, CodeDBIntegrity, "PRAGMA integrity_check: %s", orUnknown(f.IntegrityDetail))
	} else {
		add(OK, codeIntegrity, "PRAGMA integrity_check: ok")
	}
	if !f.LogMatches {
		add(FAIL, CodeLogMismatch, "the stored audit log does not reproduce its latest signed checkpoint, or contradicts the CA keys, issuance rows or serial high-water mark recorded with it (%s); the database was modified outside the signer, rolled back or restored inconsistently, and serve refuses to start", orUnknown(f.LogDetail))
	} else {
		add(OK, codeLog, "the stored leaves reproduce the latest checkpoint signed by the log key and match the recorded CA keys, issuance rows and serial high-water mark")
	}
	rs = append(rs, clockResult(f.NowMicros, f.HighWaterMicros))

	if f.Bundle == nil {
		add(WARN, CodeNoBundle, "no trust bundle installed; serve refuses to start until keyroster-signer install-bundle has run")
	} else {
		add(OK, codeBundle, "trust bundle version %d installed (%d roots, threshold %d)", f.Bundle.Version, len(f.Bundle.Root.Keys), f.Bundle.Root.Threshold)
		rs = append(rs, rootResults(f.Bundle.Root.Keys)...)
	}
	switch {
	case f.TrustError != "":
		add(FAIL, CodeTrustMismatch, "the installed trust bundle is not one serve would load (%s); serve refuses to start", f.TrustError)
	case f.Bundle != nil:
		add(OK, codeTrust, "the installed trust bundle lists the recorded keys and is the one the log's last bundle_install entry records (its root signatures are checked by install-bundle and audit verify, not here)")
	}
	rs = append(rs, custodyResults(f)...)
	return rs
}

// clockResult compares the wall clock with the serial high-water mark
// (research Pitfall 9): a clock behind it means the clock stepped back or
// the VM was restored from a snapshot, and the signer refuses to issue.
func clockResult(now, highWater uint64) Result {
	if now < highWater {
		gap := time.Duration(highWater-now) * time.Microsecond //nolint:gosec // G115: a gap in microseconds fits int64 for any real clock
		return Result{Level: FAIL, Code: CodeClockRegression, Message: fmt.Sprintf(
			"the wall clock is %s (%d s) behind the serial high-water mark; issuance fails closed until the clock is correct. After a snapshot restore, fix the clock (NTP) before starting the signer",
			gap.Round(time.Second), int64(gap/time.Second))}
	}
	if highWater == 0 {
		return Result{Level: OK, Code: codeClock, Message: "no serial issued yet"}
	}
	ahead := time.Duration(now-highWater) * time.Microsecond //nolint:gosec // G115: see above
	return Result{Level: OK, Code: codeClock, Message: fmt.Sprintf("the wall clock is %s ahead of the serial high-water mark", ahead.Round(time.Second))}
}

// rootResults warns for every software root (D-11) and reports the others.
func rootResults(roots []trust.RootKey) []Result {
	var rs []Result
	var hardware []string
	for _, rk := range roots {
		fp := keyFingerprint(rk.Key)
		if rk.Custody == "software" {
			rs = append(rs, Result{Level: WARN, Code: CodeSoftwareRoot, Message: fmt.Sprintf(
				"SOFTWARE ROOT: root %s has custody software, not hardware: whoever copies the key (for example the age-encrypted file and its passphrase) can sign trust bundles (D-11, docs/security/custody.md)", fp)})
			continue
		}
		hardware = append(hardware, fp+" ("+rk.Custody+")")
	}
	if len(rs) == 0 && len(hardware) > 0 {
		rs = append(rs, Result{Level: OK, Code: codeRoots, Message: "every root has hardware custody: " + strings.Join(hardware, ", ")})
	}
	return rs
}

// custodyResults reports the custody of the online keys. Only a set of keys
// that are all in hardware custody (hardwareCustody), with a TPM (if any)
// that still matches the recorded custody, yields an OK custody line.
func custodyResults(f Facts) []Result {
	var rs []Result
	byCustody := map[string][]string{}
	var order []string
	ed25519PKCS11 := []string{}
	for _, k := range f.CAKeys {
		if _, seen := byCustody[k.Custody]; !seen {
			order = append(order, k.Custody)
		}
		byCustody[k.Custody] = append(byCustody[k.Custody], k.Role)
		if k.Custody == "pkcs11-agent" && k.Alg == ssh.KeyAlgoED25519 {
			ed25519PKCS11 = append(ed25519PKCS11, k.Role)
		}
	}
	weak, declared := false, false
	for _, c := range order {
		roles := strings.Join(byCustody[c], ", ")
		switch c {
		case "pkcs11-agent":
			// Not weak, but not confirmed either: no OK hardware line.
			declared = true
			rs = append(rs, Result{Level: INFO, Code: CodePKCS11CustodyDeclared, Message: fmt.Sprintf(
				"keys %s are declared custody pkcs11-agent (ca-init --backend-opt custody=pkcs11-agent); doctor cannot verify that these agent keys live in a hardware token, since a SoftHSM token or a plain ssh-add key in the same agent looks the same (docs/security/custody.md)", roles)})
		case "vtpm":
			weak = true
			rs = append(rs, Result{Level: WARN, Code: CodeVTPMCustody, Message: fmt.Sprintf(
				"keys %s are in a virtual TPM (custody vtpm): they are only as safe as the hypervisor host that holds the vTPM state, weaker than a physical TPM (D-08, docs/security/custody.md)", roles)})
		case "agent":
			weak = true
			rs = append(rs, Result{Level: WARN, Code: CodeSoftwareKeyInAgent, Message: fmt.Sprintf(
				"keys %s are plain private keys loaded into ssh-agent (custody agent): test and development only, the key exists as a file somewhere", roles)})
		case "software":
			weak = true
			rs = append(rs, Result{Level: WARN, Code: CodeSoftwareKey, Message: fmt.Sprintf(
				"keys %s are software keys (custody software), not hardware custody", roles)})
		default:
			if !hardwareCustody[c] {
				weak = true
				rs = append(rs, Result{Level: WARN, Code: CodeSoftwareKey, Message: fmt.Sprintf(
					"keys %s have unknown custody %q; treated as not hardware", roles, c)})
			}
		}
	}
	if len(ed25519PKCS11) > 0 {
		rs = append(rs, Result{Level: INFO, Code: CodePKCS11Ed25519, Message: fmt.Sprintf(
			"keys %s are Ed25519 keys in a PKCS#11 token: the signer's ssh-agent must be OpenSSH 10.1 or newer", strings.Join(ed25519PKCS11, ", "))})
	}

	_, tpmKeys := byCustody["tpm"]
	_, vtpmKeys := byCustody["vtpm"]
	if tpmKeys || vtpmKeys {
		switch {
		case f.TPMError != "":
			weak = true
			rs = append(rs, Result{Level: WARN, Code: CodeTPMUnavailable, Message: fmt.Sprintf(
				"cannot read the TPM to confirm the recorded custody: %s", f.TPMError)})
		case f.TPMCustody != "":
			mismatch := false
			for _, c := range []string{"tpm", "vtpm"} {
				if roles, ok := byCustody[c]; ok && c != f.TPMCustody {
					weak, mismatch = true, true
					rs = append(rs, Result{Level: WARN, Code: CodeCustodyMismatch, Message: fmt.Sprintf(
						"keys %s were recorded as custody %s, but the TPM now reports manufacturer %s, which maps to custody %s; the keys may be in another TPM than the bundle claims",
						strings.Join(roles, ", "), c, f.TPMManufacturer, f.TPMCustody)})
				}
			}
			if !mismatch {
				// A consistency check only: it does not call vtpm hardware.
				rs = append(rs, Result{Level: OK, Code: codeTPM, Message: fmt.Sprintf(
					"TPM manufacturer %s maps to custody %s, as recorded", f.TPMManufacturer, f.TPMCustody)})
			}
		default:
			// Nobody read the TPM (the recorded backend is not tpm, or
			// the read gave no custody): the recorded custody is a claim
			// only, never an OK.
			weak = true
			rs = append(rs, Result{Level: WARN, Code: CodeTPMUnavailable, Message: "keys are recorded with TPM custody, but the TPM was not inspected, so that custody is unconfirmed"})
		}
	}
	if !weak && !declared && len(f.CAKeys) > 0 {
		var parts []string
		for _, c := range order {
			parts = append(parts, strings.Join(byCustody[c], ", ")+": "+c)
		}
		rs = append(rs, Result{Level: OK, Code: codeCustody, Message: "every online key has hardware custody (" + strings.Join(parts, "; ") + ")"})
	}
	return rs
}

// keyFingerprint returns the SHA256 fingerprint of a bundle key, or the
// raw key when it does not parse.
func keyFingerprint(key string) string {
	pub, err := trust.ParseKey(key)
	if err != nil {
		return key
	}
	return ssh.FingerprintSHA256(pub)
}

func orUnknown(s string) string {
	if s == "" {
		return "no detail"
	}
	return s
}

// ExitCode is 1 when any result is a FAIL, else 0.
func ExitCode(rs []Result) int {
	for _, r := range rs {
		if r.Level == FAIL {
			return 1
		}
	}
	return 0
}
