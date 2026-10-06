// Package doctor turns facts about a keyroster-signer installation into
// OK, INFO, WARN and FAIL results (D-08, D-11). It is pure: the caller
// gathers the facts, so every check is testable on every OS.
package doctor

import (
	"io/fs"

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

// String returns the level name.
func (l Level) String() string { return "" }

// Result codes of WARN and FAIL results.
const (
	CodeRunningAsRoot       = "running_as_root"
	CodeStateDirPermissions = "state_dir_permissions"
	CodeDBPermissions       = "db_permissions"
	CodeDBIntegrity         = "db_integrity"
	CodeLogMismatch         = "log_mismatch"
	CodeClockRegression     = "clock_regression"
	CodeNoBundle            = "no_bundle"
	CodeSoftwareRoot        = "software_root"
	CodeVTPMCustody         = "vtpm_custody"
	CodeSoftwareKeyInAgent  = "software_key_in_agent"
	CodeSoftwareKey         = "software_key"
	CodePKCS11Ed25519       = "pkcs11_ed25519"
	CodeCustodyMismatch     = "custody_mismatch"
	CodeTPMUnavailable      = "tpm_unavailable"
)

// Result is one finding.
type Result struct {
	Level   Level
	Code    string
	Message string
}

// Line formats r as "LEVEL code: message".
func (r Result) Line() string { return "" }

// String is Line.
func (r Result) String() string { return r.Line() }

// CAKeyFact is one online key as ca-init recorded it.
type CAKeyFact struct {
	Role, Alg, Custody string
}

// Facts describe an installation.
type Facts struct {
	UID           int
	SignerUID     int
	StateDirMode  fs.FileMode
	StateDirOwner int
	DBMode        fs.FileMode
	DBError       string

	IntegrityOK     bool
	IntegrityDetail string
	LogMatches      bool
	LogDetail       string

	NowMicros, HighWaterMicros uint64

	Bundle *trust.Bundle
	CAKeys []CAKeyFact

	TPMManufacturer string
	TPMCustody      string
	TPMError        string
}

// Run checks f.
func Run(f Facts) []Result { return nil }

// ExitCode is 1 when any result is a FAIL, else 0.
func ExitCode(rs []Result) int { return 0 }
