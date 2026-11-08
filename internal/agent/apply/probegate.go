//go:build linux

package apply

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/trust"
)

// The probe self-test's results (03-10b, D-06 after owner decision Q2): an
// addition held until the probes can run, and the three probe failures
// that roll back a live addition. Each error's text is its detail code.
var (
	ErrProbeHeld            = errors.New("probe_held")
	ErrProbePositiveRefused = errors.New("probe_positive_refused")
	ErrProbeKRLNotEnforced  = errors.New("probe_krl_not_enforced")
	ErrProbeInconclusive    = errors.New("probe_inconclusive")
)

// Detail codes of the probe self-test that are not an error (03-10b).
const (
	// DetailProbeSelfTestOff is reported while the switch is off, which
	// only the unit-test harness and the e2e test build can do.
	DetailProbeSelfTestOff = "probe_self_test_off"
	// DetailProbeStateReset is reported for an hour after probe-state.json
	// did not read and was rewritten as an exhausted hour.
	DetailProbeStateReset = "probe_state_reset"
	// DetailServedCertMismatch is a served-certificate check that failed.
	DetailServedCertMismatch = "served_cert_mismatch"
	// probeSkippedOff is Report.ProbePositive and ProbeNegative while the
	// switch is off.
	probeSkippedOff = "skipped:off"
)

// probeHoldReasons is the closed list of gate hold reasons (Contracts
// frozen by 03-10b; 03-10c adds the full account check's reasons).
var probeHoldReasons = []string{
	"cert_missing", "issue_unanswered", "issue_refused", "positive_in_krl", "negative_not_in_krl", "ca_mismatch",
	"account_missing", "account_unparsable", "account_uid_zero", "shell_missing", "shell_not_nologin",
	"account_is_managed", "failure_backoff", "budget",
}

// probeFailureCodes are the codes of a failed probe of an addition, and
// probeAlarmCodes those of a failed opportunistic probe.
var (
	probeFailureCodes = []string{ErrProbePositiveRefused.Error(), ErrProbeKRLNotEnforced.Error(), ErrProbeInconclusive.Error(), DetailServedCertMismatch}
	probeAlarmCodes   = []string{ErrProbePositiveRefused.Error(), ErrProbeKRLNotEnforced.Error(), ErrProbeInconclusive.Error()}
)

const (
	// probeStateFile is <state>/probe-state.json, the gate's state: the
	// budget, the failure and held records and the alarm. Only the
	// applier writes it, under apply.lock.
	probeStateFile = "probe-state.json"
	// maxProbeState bounds probe-state.json.
	maxProbeState = 16 << 10
	// maxProbeNegatives bounds the negatives kept (the last hour's).
	maxProbeNegatives = 16
	// probeResetShown is how long probe_state_reset is reported after a
	// reset.
	probeResetShown = 3600
)

var probeKeyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// probeFailure is the failure record of a rolled-back addition: its code,
// the failure key (SHA-256 over the classified content, both pair serials
// and the account's passwd line), when it last failed and how often in a
// row; the gate holds failure_backoff while the key is unchanged.
type probeFailure struct {
	Code  string `json:"code"`
	Key   string `json:"key"`
	At    uint64 `json:"at"`
	Count uint64 `json:"count"`
}

// probeHeld is the held record of an addition that waits for the probes:
// the reason and the verified versions it was held at.
type probeHeld struct {
	Reason    string `json:"reason"`
	Bundle    uint64 `json:"bundle"`
	Directory uint64 `json:"directory"`
	KRL       uint64 `json:"krl"`
	At        uint64 `json:"at"`
}

// probeState is probe-state.json (Contracts frozen by 03-10b): the Unix
// seconds of the negative probes of the last hour, when the last pair and
// the last opportunistic pair ran, the failure and held records, the
// last unresolved code of an opportunistic probe and when the file was
// last reset. Failure and Held are null when absent.
type probeState struct {
	Version           int           `json:"version"`
	Negatives         []uint64      `json:"negatives"`
	LastPair          uint64        `json:"last_pair"`
	LastOpportunistic uint64        `json:"last_opportunistic"`
	Failure           *probeFailure `json:"failure"`
	Alarm             string        `json:"alarm"`
	Held              *probeHeld    `json:"held"`
	ResetAt           uint64        `json:"reset_at"`

	// reset: the file did not read, so this is the exhausted hour, to be
	// rewritten once (loadProbeState).
	reset bool
}

// newProbeState is the state of a host with no probe-state.json.
func newProbeState() *probeState { return &probeState{Version: 1, Negatives: []uint64{}} }

// resetProbeState is what a probe-state.json that does not read counts
// as: an hour whose six negatives were all sent now, reset now
// (T-03-376: a damaged file never opens the budget).
func resetProbeState(now uint64) *probeState {
	st := newProbeState()
	for range ProbeNegativesPerHour {
		st.Negatives = append(st.Negatives, now)
	}
	st.ResetAt, st.reset = now, true
	return st
}

// validate checks st against the frozen format.
func (st *probeState) validate() error {
	switch {
	case st.Version != 1:
		return fmt.Errorf("version %d", st.Version)
	case st.Negatives == nil:
		return errors.New("negatives is null")
	case len(st.Negatives) > maxProbeNegatives:
		return fmt.Errorf("%d negatives, above %d", len(st.Negatives), maxProbeNegatives)
	case slices.Contains(st.Negatives, 0):
		return errors.New("a negative at time 0")
	case st.Alarm != "" && !slices.Contains(probeAlarmCodes, st.Alarm):
		return fmt.Errorf("alarm %q", st.Alarm)
	}
	if f := st.Failure; f != nil && (!slices.Contains(probeFailureCodes, f.Code) || !probeKeyRE.MatchString(f.Key) || f.Count == 0) {
		return fmt.Errorf("failure %+v", *f)
	}
	if h := st.Held; h != nil && !slices.Contains(probeHoldReasons, h.Reason) {
		return fmt.Errorf("held reason %q", h.Reason)
	}
	return nil
}

// encode is st's canonical form (validated first); a nil Negatives is
// the empty list.
func (st *probeState) encode() ([]byte, error) {
	if st.Negatives == nil {
		st.Negatives = []uint64{}
	}
	if err := st.validate(); err != nil {
		return nil, fmt.Errorf("probe-state.json: %w", err)
	}
	return trust.CanonicalJSON(st)
}

// parseProbeState is the strict decode of probe-state.json: canonical
// JSON of the frozen format, at most maxProbeState bytes.
func parseProbeState(b []byte) (*probeState, error) {
	if len(b) > maxProbeState {
		return nil, fmt.Errorf("probe-state.json is %d bytes, above %d", len(b), maxProbeState)
	}
	var st probeState
	if err := trust.DecodeStrict(b, &st); err != nil {
		return nil, err
	}
	if err := st.validate(); err != nil {
		return nil, fmt.Errorf("probe-state.json: %w", err)
	}
	return &st, nil
}

// decodeProbeState is the content's state at now: parsed, with every
// time after now replaced by now, or the exhausted hour when it does not
// parse.
func decodeProbeState(b []byte, now uint64) *probeState {
	st, err := parseProbeState(b)
	if err != nil {
		return resetProbeState(now)
	}
	clamp := func(t *uint64) { *t = min(*t, now) }
	for i := range st.Negatives {
		clamp(&st.Negatives[i])
	}
	clamp(&st.LastPair)
	clamp(&st.LastOpportunistic)
	clamp(&st.ResetAt)
	if st.Failure != nil {
		clamp(&st.Failure.At)
	}
	if st.Held != nil {
		clamp(&st.Held.At)
	}
	return st
}

// probeNow is the engine clock in Unix seconds.
func (e *engine) probeNow() uint64 { return uint64(max(e.clock.Now().Unix(), 0)) }

// readProbeState reads probe-state.json without following a symlink: a
// missing file is the empty state; a file that is not a regular file of
// mode 0600 owned by the effective uid, is above maxProbeState or does not
// parse is the exhausted hour (reset set). It only reads.
func (e *engine) readProbeState() *probeState {
	now := e.probeNow()
	if e.stateFd < 0 {
		return resetProbeState(now)
	}
	b, info, err := spool.ReadFileAtInfo(e.stateFd, probeStateFile, maxProbeState)
	switch {
	case errors.Is(err, unix.ENOENT):
		return newProbeState()
	case err != nil:
		e.logf("WARNING %s does not read (%v); counting an exhausted probe hour", e.l.State(probeStateFile), err)
		return resetProbeState(now)
	case info.Mode != 0o600 || int(info.UID) != os.Geteuid():
		e.logf("WARNING %s is not a 0600 file of uid %d; counting an exhausted probe hour", e.l.State(probeStateFile), os.Geteuid())
		return resetProbeState(now)
	}
	st := decodeProbeState(b, now)
	if st.reset {
		e.logf("WARNING %s does not parse; counting an exhausted probe hour", e.l.State(probeStateFile))
	}
	return st
}

// loadProbeState is readProbeState for the gate: a state that did not
// read is rewritten once, so probe_state_reset is reported for an hour and
// the next read is the exhausted hour itself.
func (e *engine) loadProbeState() (*probeState, error) {
	st := e.readProbeState()
	if st.reset {
		if err := e.writeProbeState(st); err != nil {
			return st, err
		}
		st.reset = false
	}
	return st, nil
}

// errProbeStateUnlocked: probe-state.json is written only under apply.lock.
var errProbeStateUnlocked = errors.New("probe-state.json is written only under the apply lock")

// writeProbeState writes probe-state.json, canonical and 0600, under the
// apply lock.
func (e *engine) writeProbeState(st *probeState) error {
	if !e.locked {
		return errProbeStateUnlocked
	}
	b, err := st.encode()
	if err != nil {
		return err
	}
	return e.writeState(probeStateFile, b)
}

// probeStatus fills s.ProbeDetail, by priority: an unresolved
// opportunistic alarm, a held addition (probe_held:<reason>), an unresolved
// failure, probe_state_reset within the hour after a reset,
// probe_self_test_off while the switch is off, and the issuance step's
// probe_issue:<code>. A code that is no valid detail is never sent.
func (e *engine) probeStatus(s *heartbeat.Status) {
	if e.stateFd < 0 {
		return
	}
	st := e.readProbeState()
	now := e.probeNow()
	d := ""
	switch {
	case st.Alarm != "":
		d = st.Alarm
	case st.Held != nil:
		d = ErrProbeHeld.Error() + ":" + st.Held.Reason
	case st.Failure != nil:
		d = st.Failure.Code
	case st.ResetAt != 0 && now < st.ResetAt+probeResetShown:
		d = DetailProbeStateReset
	case !e.probesOn():
		d = DetailProbeSelfTestOff
	default:
		d = e.readProbeRecord().Detail
	}
	if !heartbeat.ValidDetail(d) {
		e.logf("WARNING the probe detail %q is no valid code; it is not sent", d)
		d = ""
	}
	s.ProbeDetail = d
}
