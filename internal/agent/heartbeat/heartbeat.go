// Package heartbeat is the status an enrolled host reports (03-08,
// AGENT-07): the root applier writes Status into its outbox after every
// apply and every drift check, the unprivileged fetcher posts it with its
// clock offset as a Heartbeat, and keyroster-server stores the newest one
// per agent for keyroster host status. Both sides decode it strictly and
// check every field with Validate, and the CLI checks it again before it
// prints anything: a compromised host can only lie about itself, never
// place a terminal escape sequence or an oversize field in an admin's
// output (T-03-227).
//
// Status and Heartbeat are closed structs. Later plans extend both sides
// under the same rules: 03-09 adds host_certs and host_keys_skipped,
// 03-14 adds breakglass, and 03-10 reports probe outcomes through
// last_apply.detail.
//
// The package is portable (no build tag): the server and the CLI import
// it, and so do the Linux-only applier and fetcher. It imports no network
// or TLS package.
package heartbeat

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/Labontese/keyroster/internal/trust"
)

// File names and caps.
const (
	// StatusFile is the applier's status in its outbox (root:keyroster-agent,
	// 0640): canonical JSON of Status.
	StatusFile = "status.json"
	// MaxStatus bounds status.json as the fetcher reads it, and MaxBody a
	// heartbeat request body as the server reads it.
	MaxStatus = 64 << 10
	MaxBody   = 64 << 10
	// MaxFiles bounds Status.Files, MaxPath one file path and MaxText
	// every free-text field (bytes).
	MaxFiles  = 256
	MaxPath   = 128
	MaxText   = 512
	MaxDetail = 64
	// MaxClockOffset bounds Heartbeat.ClockOffsetS (about 317 years).
	MaxClockOffset = 10_000_000_000
)

// last_apply.result values (closed).
const (
	ResultOK         = "ok"
	ResultRefused    = "refused"
	ResultRolledBack = "rolled_back"
	ResultError      = "error"
)

// pending.step values (closed): 03-05's two-step swap markers.
const (
	StepIntermediate = "intermediate"
	StepFinal        = "final"
	StepCommit       = "commit"
)

// StuckPendingStateUnknown is the one stuck value: 03-05 found a layout it
// did not make and applies nothing until the operator runs
// keyroster-agent apply --once --recover-to-last-good.
const StuckPendingStateUnknown = "pending_state_unknown"

// last_apply.host_status values (closed; 03-05, owner decision 2026-10-26).
var hostStatuses = []string{"", "host_disabled", "host_removed", "host_keys_rotated", "host_keys_disagree"}

// ErrFieldInvalid is a heartbeat or status field outside its rule; the
// server answers it 400 heartbeat_field_invalid with the field's name.
var ErrFieldInvalid = errors.New("heartbeat_field_invalid")

// FieldError names the field that broke its rule.
type FieldError struct {
	Field string
}

func (e *FieldError) Error() string { return ErrFieldInvalid.Error() + ": " + e.Field }

// Unwrap makes errors.Is(err, ErrFieldInvalid) hold.
func (e *FieldError) Unwrap() error { return ErrFieldInvalid }

// Doc is one signed document the host has accepted: its version (0: none)
// and the SHA-256 of its bytes ("" when the version is 0).
type Doc struct {
	Version uint64 `json:"version"`
	SHA256  string `json:"sha256"`
}

// KRL is the KRL in force: the generation's KRL file's version and
// SHA-256, and its manifest's issued_at ("" when the applier holds no
// manifest for that version).
type KRL struct {
	Version  uint64 `json:"version"`
	SHA256   string `json:"sha256"`
	IssuedAt string `json:"issued_at"`
}

// File is one file of the generation in force, by its path in the
// generation directory, with its SHA-256.
type File struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Effective are the four trust settings sshd -T reports.
type Effective struct {
	TrustedUserCAKeys        string `json:"trustedusercakeys"`
	RevokedKeys              string `json:"revokedkeys"`
	AuthorizedPrincipalsFile string `json:"authorizedprincipalsfile"`
	HostCertificate          string `json:"hostcertificate"`
}

// LastApply is the last apply: when, its closed result, whether it rolled
// back, its first error (printable, at most MaxText bytes), the optional
// detail (03-10's probe outcomes) and the directory host status.
type LastApply struct {
	At         string `json:"at"`
	Result     string `json:"result"`
	Rollback   bool   `json:"rollback"`
	Error      string `json:"error"`
	Detail     string `json:"detail,omitempty"`
	HostStatus string `json:"host_status,omitempty"`
}

// LastCheck is the last drift check (AGENT-05).
type LastCheck struct {
	At    string `json:"at"`
	Drift bool   `json:"drift"`
}

// Pending is 03-05's pending marker while a two-step swap is in progress.
type Pending struct {
	Step         string `json:"step"`
	From         uint64 `json:"from"`
	To           uint64 `json:"to"`
	Intermediate uint64 `json:"intermediate"`
}

// Status is status.json. The versions, Generation, KRL and Files are
// those of the committed generation (current at rest; the generation a
// pending swap started from while Pending is set), never an intermediate.
// LastApply and LastCheck are nil before the first apply and check. Seq is
// max(previous + 1, now in Unix microseconds), so it only grows, even
// after the applier's state directory was reset.
type Status struct {
	AgentVersion   string     `json:"agent_version"`
	Bundle         Doc        `json:"bundle"`
	Policy         Doc        `json:"policy"`
	Directory      Doc        `json:"directory"`
	KRL            KRL        `json:"krl"`
	Generation     uint64     `json:"generation"`
	Files          []File     `json:"files"`
	FilesTruncated bool       `json:"files_truncated"`
	DropInSHA256   string     `json:"dropin_sha256"`
	SSHDVersion    string     `json:"sshd_version"`
	Effective      Effective  `json:"effective"`
	LastApply      *LastApply `json:"last_apply"`
	LastCheck      *LastCheck `json:"last_check"`
	Pending        *Pending   `json:"pending"`
	Stuck          string     `json:"stuck"`
	KRLStale       bool       `json:"krl_stale"`
	Seq            uint64     `json:"seq"`
}

// Heartbeat is the body of POST /api/v1/agent/heartbeat: the applier's
// status and the fetcher's clock offset, the server's Date header minus
// the fetcher's clock at receipt, in whole seconds (the Date header's
// resolution is one second).
type Heartbeat struct {
	Status       Status `json:"status"`
	ClockOffsetS int64  `json:"clock_offset_s"`
}

// MaxSeqAhead is how far beyond keyroster-server's clock a heartbeat's
// seq (microseconds) may be: a higher one is refused heartbeat_seq_future
// and stores nothing but its clock offset, so no seq can freeze a host's
// status (owner decision D-R2, PR #72 review C11). The applier restarts
// its seq from its clock when the previous one is this far beyond it.
const MaxSeqAhead = time.Hour

// ClockSkewS is the clock_skew threshold: an offset whose magnitude is
// above it (in whole seconds, so 300 is not flagged and 301 is) raises
// clock_skew (owner decision REVIEWS L1486).
const ClockSkewS = 300

// ClockSkew reports whether offset raises clock_skew.
func ClockSkew(offset int64) bool { return offset > ClockSkewS || offset < -ClockSkewS }

var (
	hexRE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	pathRE   = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]*(/[a-z0-9_][a-z0-9_.-]*)*$`)
	detailRE = regexp.MustCompile(`^[a-z0-9_]+(:[a-z0-9_]+)?$`)
)

// Printable reports whether s is at most max bytes of printable ASCII
// (0x20 to 0x7e).
func Printable(s string, limit int) bool {
	if len(s) > limit {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Sanitize makes s a valid free-text value: every byte outside printable
// ASCII becomes '?', and it is cut to limit bytes. The applier uses it on
// error strings and sshd's output before it writes them.
func Sanitize(s string, limit int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < limit; i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func bad(field string) error { return &FieldError{Field: field} }

func checkDoc(name string, d Doc) error {
	if (d.Version == 0) != (d.SHA256 == "") {
		return bad(name + ".sha256")
	}
	if d.SHA256 != "" && !hexRE.MatchString(d.SHA256) {
		return bad(name + ".sha256")
	}
	return nil
}

func checkTime(field, s string) error {
	if trust.CheckTimestamp(s) != nil {
		return bad(field)
	}
	return nil
}

// Validate checks every field of s (the must_haves rule of 03-08):
// versions are uint64; hashes are 64 lowercase hex digits ("" only with
// version 0, or for no drop-in); at most MaxFiles files, sorted by path
// and unique, each path matching the path grammar within MaxPath bytes;
// result, pending.step, stuck and host_status from their closed sets;
// detail, when present, ^[a-z0-9_]+(:[a-z0-9_]+)?$ within MaxDetail bytes;
// every free-text field at most MaxText bytes of printable ASCII; times in
// trust's timestamp format; seq from 1 to the largest int64. The error is
// a *FieldError naming the first field that failed.
func Validate(s *Status) error {
	if !Printable(s.AgentVersion, MaxText) {
		return bad("agent_version")
	}
	for _, d := range []struct {
		name string
		d    Doc
	}{{"bundle", s.Bundle}, {"policy", s.Policy}, {"directory", s.Directory}} {
		if err := checkDoc(d.name, d.d); err != nil {
			return err
		}
	}
	if err := checkDoc("krl", Doc{Version: s.KRL.Version, SHA256: s.KRL.SHA256}); err != nil {
		return err
	}
	if s.KRL.IssuedAt != "" && (s.KRL.Version == 0 || trust.CheckTimestamp(s.KRL.IssuedAt) != nil) {
		return bad("krl.issued_at")
	}
	if s.Files == nil {
		return bad("files")
	}
	if len(s.Files) > MaxFiles {
		return bad("files")
	}
	for i, f := range s.Files {
		if len(f.Path) > MaxPath || !pathRE.MatchString(f.Path) || (i > 0 && s.Files[i-1].Path >= f.Path) {
			return bad(fmt.Sprintf("files[%d].path", i))
		}
		if !hexRE.MatchString(f.SHA256) {
			return bad(fmt.Sprintf("files[%d].sha256", i))
		}
	}
	if s.Generation == 0 && len(s.Files) > 0 {
		return bad("files")
	}
	if s.DropInSHA256 != "" && !hexRE.MatchString(s.DropInSHA256) {
		return bad("dropin_sha256")
	}
	if !Printable(s.SSHDVersion, MaxText) {
		return bad("sshd_version")
	}
	for _, e := range []struct{ name, v string }{
		{"effective.trustedusercakeys", s.Effective.TrustedUserCAKeys}, {"effective.revokedkeys", s.Effective.RevokedKeys},
		{"effective.authorizedprincipalsfile", s.Effective.AuthorizedPrincipalsFile}, {"effective.hostcertificate", s.Effective.HostCertificate},
	} {
		if !Printable(e.v, MaxText) {
			return bad(e.name)
		}
	}
	if a := s.LastApply; a != nil {
		if err := checkTime("last_apply.at", a.At); err != nil {
			return err
		}
		switch a.Result {
		case ResultOK, ResultRefused, ResultRolledBack, ResultError:
		default:
			return bad("last_apply.result")
		}
		if !Printable(a.Error, MaxText) {
			return bad("last_apply.error")
		}
		if a.Detail != "" && (len(a.Detail) > MaxDetail || !detailRE.MatchString(a.Detail)) {
			return bad("last_apply.detail")
		}
		if !contains(hostStatuses, a.HostStatus) {
			return bad("last_apply.host_status")
		}
	}
	if c := s.LastCheck; c != nil {
		if err := checkTime("last_check.at", c.At); err != nil {
			return err
		}
	}
	if p := s.Pending; p != nil {
		switch p.Step {
		case StepIntermediate, StepFinal, StepCommit:
		default:
			return bad("pending.step")
		}
	}
	if s.Stuck != "" && s.Stuck != StuckPendingStateUnknown {
		return bad("stuck")
	}
	if s.Seq == 0 || s.Seq > math.MaxInt64 {
		return bad("seq")
	}
	return nil
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// ValidateHeartbeat is Validate for h's status and the clock offset bound.
func ValidateHeartbeat(h *Heartbeat) error {
	if h.ClockOffsetS > MaxClockOffset || h.ClockOffsetS < -MaxClockOffset {
		return bad("clock_offset_s")
	}
	return Validate(&h.Status)
}

// ParseStatus decodes status.json strictly (trust.DecodeStrict: canonical
// JSON, no unknown field) within MaxStatus bytes and validates it.
func ParseStatus(b []byte) (*Status, error) {
	if len(b) > MaxStatus {
		return nil, bad("status")
	}
	var s Status
	if err := trust.DecodeStrict(b, &s); err != nil {
		return nil, fmt.Errorf("%w: status: %w", ErrFieldInvalid, err)
	}
	if err := Validate(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ParseHeartbeat decodes a heartbeat body strictly within MaxBody bytes
// and validates it.
func ParseHeartbeat(b []byte) (*Heartbeat, error) {
	if len(b) > MaxBody {
		return nil, bad("body")
	}
	var h Heartbeat
	if err := trust.DecodeStrict(b, &h); err != nil {
		return nil, fmt.Errorf("%w: body: %w", ErrFieldInvalid, err)
	}
	if err := ValidateHeartbeat(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// Field is the field name a FieldError names ("body" for one that did
// not decode), for the server's refusal and the CLI.
func Field(err error) string {
	var fe *FieldError
	if errors.As(err, &fe) {
		return fe.Field
	}
	return "body"
}

// Committed reports whether s's committed versions are exactly bundle,
// directory and krl and no swap is pending: what keyroster host status
// and 03-12's rotation gate count as converged.
func (s *Status) Committed(bundle, directory, krl uint64) bool {
	return s.Pending == nil && s.Bundle.Version == bundle && s.Directory.Version == directory && s.KRL.Version == krl
}
