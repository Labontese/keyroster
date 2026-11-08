//go:build linux

package apply

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/hostcert"
	probecert "github.com/Labontese/keyroster/internal/agent/probe"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	certpkg "github.com/Labontese/keyroster/internal/cert"
	"github.com/Labontese/keyroster/internal/krl"
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

// probeClass is what a change does to access, for the probe gate
// (classify, Contracts frozen by 03-10b).
type probeClass int

const (
	classFirstInstall  probeClass = iota // no last-good, or no current
	classTrustOnly                       // the generation holds no principals file
	classNarrowing                       // only removes (the KRL may change)
	classProbeFileOnly                   // adds only the probe account's generated file
	classWidening                        // anything else, a mixed change included
)

// The probes' Report values for a change the gate exempts or holds.
var probeSkipped = map[probeClass]string{
	classFirstInstall:  "skipped:exempt_first_install",
	classTrustOnly:     "skipped:exempt_trust_only",
	classProbeFileOnly: "skipped:exempt_probe_file_only",
}

const probeSkippedNotReady = "skipped:not_ready"

// classify is the class of moving current from cur to g, with lg the
// last-good link and account the probe account (Contracts frozen by
// 03-10b, owner decision Q2): first install, trust-only, narrowing,
// probe-file-only (g's file at principals/<account> is the generated probe
// file for g.Host and cur's is absent or one isCurProbeFile accepts, and
// with cur's file in its place g only removes), else widening. Any other
// content at the probe account's path, a mapped account's file included,
// is compared like any account's.
func classify(lg link, cur, g *Generation, account string) probeClass {
	switch {
	case lg.kind == linkNone || cur == nil:
		return classFirstInstall
	case len(principalAccounts(g)) == 0:
		return classTrustOnly
	case isNarrowing(cur, g):
		return classNarrowing
	}
	name := PrincipalsDir + "/" + account
	if b, ok := g.Files[name]; ok && isProbeFile(b, g.Host) {
		cb, has := cur.Files[name]
		if !has || isCurProbeFile(cb) {
			g2 := &Generation{Files: maps.Clone(g.Files)}
			if has {
				g2.Files[name] = cb
			} else {
				delete(g2.Files, name)
			}
			if isNarrowing(cur, g2) {
				return classProbeFileOnly
			}
		}
	}
	return classWidening
}

// needsGate reports whether a change of class c waits for the probes: a
// widening alone (owner decision Q2: only additions wait).
func needsGate(c probeClass) bool { return c == classWidening }

// probeWait is how long a widening swap waits after the previous swap:
// the LoginGraceTime bound in force plus graceMargin. The gate judges the
// pair and the spacing against the full wait, which the intermediate swap
// restarts (D7).
func (e *engine) probeWait() time.Duration { return time.Duration(e.grace)*time.Second + graceMargin }

// genKRL parses g's revocation list (nil when it has none or it does not
// parse: then no negative is listed).
func genKRL(g *Generation) *krl.Parsed {
	b := g.Files[KRLFile]
	if len(b) == 0 {
		return nil
	}
	p, err := krl.Parse(b)
	if err != nil {
		return nil
	}
	return p
}

// genCAKeys are the CA keys of g's user_ca_keys.
func genCAKeys(g *Generation) []ssh.PublicKey {
	var out []ssh.PublicKey
	for _, l := range lines(g.Files[CAFile]) {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err == nil {
			out = append(out, pub)
		}
	}
	return out
}

// acceptedVersions are accepted/'s bundle, policy and directory versions,
// which release a sticky refusal (hostcert.StickyReleased), as the
// issuance step reads them.
func (e *engine) acceptedVersions() (bundle, policy, dir uint64) {
	s := e.accepted
	if s == nil {
		return 0, 0, 0
	}
	if p, err := trust.ParsePolicy(s.Policy); err == nil {
		policy = p.Version
	}
	return s.BundleVersion, policy, s.DirectoryVersion
}

// probePair is the pair the probes use for the host named host (g.Host)
// at time at against the KRL k and the CA keys caKeys: Next when
// PairUsable accepts it, else Committed. A pair issued for another name
// (a renamed entry) is cert_missing (PR #91 review, F1).
// With none usable it returns the gate's reason: issue_refused while an
// attempt holds an unreleased sticky refusal, issue_unanswered while a
// request is live or the last one went unanswered, else the committed
// pair's PairUsable reason (the next pair's when there is no committed
// one), else cert_missing. The gate and the probes after a swap pick the
// pair this one way, so the failure keys they compute agree.
func (e *engine) probePair(rec *probecert.Record, host string, at time.Time, k *krl.Parsed, caKeys []ssh.PublicKey) (probecert.Pair, string) {
	for _, p := range []probecert.Pair{rec.Next, rec.Committed} {
		if probecert.PairUsable(p, host, at, k, caKeys) == "" {
			return p, ""
		}
	}
	now := e.probeNow()
	b, pol, dir := e.acceptedVersions()
	for _, pl := range probecert.Polarities {
		a := rec.Attempts.Get(pl)
		if a.Sticky != nil && !hostcert.StickyReleased(a.Sticky, now, b, pol, dir) {
			return probecert.Pair{}, "issue_refused"
		}
	}
	for _, pl := range probecert.Polarities {
		a := rec.Attempts.Get(pl)
		if a.Pending(now) != nil || a.LastCode == "no_answer" {
			return probecert.Pair{}, "issue_unanswered"
		}
	}
	switch {
	case !rec.Committed.Empty():
		return probecert.Pair{}, probecert.PairUsable(rec.Committed, host, at, k, caKeys)
	case !rec.Next.Empty():
		return probecert.Pair{}, probecert.PairUsable(rec.Next, host, at, k, caKeys)
	}
	return probecert.Pair{}, probecert.CertMissing
}

// failureKey is the key of a failed addition (D10): SHA-256 over g's
// classified content (each CA list and principals file as its sorted
// non-comment lines; no KRL, no comments), both serials of the pair and
// the probe account's passwd line, each field length-prefixed. The retry
// backs off while it is unchanged and is immediate when any input changes.
func failureKey(g *Generation, p probecert.Pair, line string) string {
	h := sha256.New()
	field := func(s string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	for _, name := range fileNames(g) {
		class, ok := ClassOf(name)
		if !ok || class == FileKRL {
			continue
		}
		field(name)
		set := lineSet(g.Files[name], keyFunc(class))
		field(strconv.Itoa(len(set)))
		for _, k := range slices.Sorted(maps.Keys(set)) {
			field(k)
		}
	}
	pos, neg := p.Serials()
	field(strconv.FormatUint(pos, 10))
	field(strconv.FormatUint(neg, 10))
	field(line)
	return hex.EncodeToString(h.Sum(nil))
}

// probeBackoff is the failure back-off after count failures in a row:
// ProbeBackoffMin doubling, at most ProbeBackoffMax.
func probeBackoff(count uint64) time.Duration {
	if count == 0 {
		return 0
	}
	if count-1 >= 6 {
		return ProbeBackoffMax
	}
	return min(ProbeBackoffMin<<(count-1), ProbeBackoffMax)
}

// recentNegatives counts the negatives sent in the hour before now.
func recentNegatives(st *probeState, now uint64) int {
	n := 0
	for _, t := range st.Negatives {
		if t+3600 > now {
			n++
		}
	}
	return n
}

// unixTime is a probe-state time in Unix seconds as a time.Time.
func unixTime(s uint64) time.Time { return time.Unix(int64(min(s, math.MaxInt64>>1)), 0) } //nolint:gosec // G115: bounded above

// probeGate decides whether an addition may go live (03-10b, Task 3): ""
// when it may, else the first failing reason of the closed list, in this
// order: the probe account (checkProbeAccount); the probe principal in g
// (account_is_managed when the host group renders that account's file);
// a usable pair at now + the full widening wait + two self-test timeouts
// against g's KRL and CA keys (probePair); the failure back-off while the
// failure key is unchanged; and the budget (six negatives in the sliding
// hour, or the last pair less than ProbePairSpacing before the probes
// would run, D7). Nothing in the gate writes a file.
func (e *engine) probeGate(_ context.Context, _, g *Generation, _ *state.Verified) string {
	account := e.probeAccount()
	reason, line := checkProbeAccount(e.l.Root, account)
	if reason != "" {
		return reason
	}
	if g.Host == "" || !lineSet(g.Files[PrincipalsDir+"/"+account], principalLine)[certpkg.ReservedPrincipalPrefix+g.Host] {
		return "account_is_managed"
	}
	now := e.clock.Now()
	wait := e.probeWait()
	pair, reason := e.probePair(e.readProbeRecord(), g.Host, now.Add(wait+2*e.cfg.SelfTestTimeout), genKRL(g), genCAKeys(g))
	if reason != "" {
		return reason
	}
	st := e.readProbeState()
	if f := st.Failure; f != nil && f.Key == failureKey(g, pair, line) && now.Before(unixTime(f.At).Add(probeBackoff(f.Count))) {
		return "failure_backoff"
	}
	if recentNegatives(st, e.probeNow()) >= ProbeNegativesPerHour {
		return "budget"
	}
	if st.LastPair != 0 && unixTime(st.LastPair).Add(ProbePairSpacing).After(now.Add(wait)) {
		return "budget"
	}
	return ""
}

// heldPresent reports whether probe-state.json has a held record, or does
// not read (then, outside a dry run, it is rewritten once as the exhausted
// hour, so the next read is that hour itself). It is read before the
// no-op test: a held addition makes every round render again until it
// lands, is reverted or disappears.
func (e *engine) heldPresent() bool {
	st := e.readProbeState()
	held := st.reset || st.Held != nil
	if st.reset && !e.cfg.DryRun {
		if _, err := e.loadProbeState(); err != nil {
			e.logf("WARNING rewriting %s: %v", e.l.State(probeStateFile), err)
		}
	}
	return held
}

// writeHeld records the held addition (reason, the verified versions,
// now) before the commit that lands its narrowing part; an unchanged hold
// (the same reason and versions) keeps its record and its first time, so
// a retry writes nothing.
func (e *engine) writeHeld(reason string, v *state.Verified) error {
	if e.cfg.DryRun {
		return nil
	}
	st := e.readProbeState()
	h := &probeHeld{Reason: reason, Bundle: v.Next.BundleVersion, Directory: v.Next.DirectoryVersion, KRL: v.Next.KRLVersion, At: e.probeNow()}
	if o := st.Held; o != nil && o.Reason == h.Reason && o.Bundle == h.Bundle && o.Directory == h.Directory && o.KRL == h.KRL {
		return nil
	}
	st.Held = h
	return e.writeProbeState(st)
}

// clearHeld removes the held record, writing only when one exists. A
// failure is only logged: a record left behind makes the next round render
// again and clear it then.
func (e *engine) clearHeld() {
	if e.cfg.DryRun {
		return
	}
	st := e.readProbeState()
	if st.Held == nil || st.reset {
		return
	}
	st.Held = nil
	if err := e.writeProbeState(st); err != nil {
		e.logf("WARNING clearing the held record in %s: %v", e.l.State(probeStateFile), err)
	}
}

// hold records that the gate held the addition for reason: the held
// record first, then the report.
func (e *engine) hold(reason string, v *state.Verified) error {
	if err := e.writeHeld(reason, v); err != nil {
		return err
	}
	e.report.Detail = ErrProbeHeld.Error() + ":" + reason
	e.report.ProbePositive, e.report.ProbeNegative = probeSkippedNotReady, probeSkippedNotReady
	return nil
}

// gateSuperseded classifies and gates a target that superseded a widening
// wait, against from, the generation current names now (03-10b, Task 3
// step 6). A widening that fails the gate is held: the held record is
// written and the target becomes Intermediate(from, t), installed and
// validated (the superseding generation, never current, is discarded);
// when that collapses, the target is from itself and done is set, so the
// caller commits it without another swap. reason is the hold's ("" for
// none).
//
// class is the superseding target's and gated reports a widening that
// passed the gate, so its probes run after the final swap (03-10b, Task 4,
// Fix round 3 r2-6: the flag belongs to the final target alone).
func (e *engine) gateSuperseded(ctx context.Context, lg link, from, t *Generation, tv *state.Verified) (target *Generation, reason string, class probeClass, gated, done bool, err error) {
	class = classify(lg, from, t, e.probeAccount())
	e.labelExempt(class)
	if !e.probesOn() || !needsGate(class) {
		return t, "", class, false, false, nil
	}
	if reason = e.probeGate(ctx, from, t, tv); reason == "" {
		return t, "", class, true, false, nil
	}
	m, collapsed := Intermediate(from, t)
	if err := e.hold(reason, tv); err != nil {
		return nil, "", class, false, false, err
	}
	e.discard(t.N)
	if collapsed {
		from.Host, from.HostStatus = t.Host, t.HostStatus
		if err := e.setHostStatus(from.N, t.HostStatus); err != nil {
			return nil, "", class, false, false, err
		}
		return from, reason, class, false, true, nil
	}
	m.Host, m.HostStatus = t.Host, t.HostStatus
	m.N = e.allocGeneration()
	if err := e.installGeneration(m); err != nil {
		return nil, "", class, false, false, err
	}
	if err := e.validate(ctx, m, e.l.Gen(m.N), nil); err != nil {
		e.discard(m.N)
		return nil, "", class, false, false, err
	}
	return m, reason, class, false, false, nil
}

// labelExempt sets the probes' Report values for an exempt class while the
// probes are on (never over skipped:off).
func (e *engine) labelExempt(c probeClass) {
	if s, ok := probeSkipped[c]; ok && e.probesOn() {
		e.report.ProbePositive, e.report.ProbeNegative = s, s
	}
}

// heldOutcome is a commit's result with the addition held for reason:
// ErrProbeHeld with the reason, joined to an earlier error.
func heldOutcome(err error, reason string) error {
	if reason == "" {
		return err
	}
	h := fmt.Errorf("%w: %s", ErrProbeHeld, reason)
	if err == nil {
		return h
	}
	return errors.Join(err, h)
}

// The probes' Report values (03-10b, 'Contracts frozen by this plan').
const (
	probePass          = "pass"
	probeFail          = "fail"
	probeInconclusive  = "inconclusive"
	probeSkippedBudget = "skipped:budget"
)

// errProbeBudget: the sliding hour holds ProbeNegativesPerHour negatives.
var errProbeBudget = errors.New("the probe budget of the hour is spent")

// reserveProbe reserves a negative probe under apply.lock before the first
// byte is sent (T-03-67): negatives older than an hour are pruned, a full
// hour refuses, and now is appended and becomes last_pair. A crash or an
// abort after it still counts.
func (e *engine) reserveProbe() error {
	st, err := e.loadProbeState()
	if err != nil {
		return err
	}
	now := e.probeNow()
	keep := make([]uint64, 0, len(st.Negatives)+1)
	for _, t := range st.Negatives {
		if t+3600 > now {
			keep = append(keep, t)
		}
	}
	if len(keep) >= ProbeNegativesPerHour {
		return errProbeBudget
	}
	st.Negatives, st.LastPair = append(keep, now), now
	return e.writeProbeState(st)
}

// runProbes runs the probe pair against the generation g current names
// (03-10b, D-06). The pair is picked as the gate picks it (probePair) and
// judged again at now + SelfTestTimeout (no longer usable: inconclusive, no
// query sent); the 60 s spacing since the last pair is waited out on the
// engine clock; the negative is reserved; then the positive goes out from
// the probes' own source and, only when it was accepted, the negative. A
// refused positive is probe_positive_refused, an accepted negative
// probe_krl_not_enforced, anything inconclusive probe_inconclusive. For a
// gated addition (required) a failure writes the failure record and
// returns the error; for the opportunistic pair it sets the alarm and
// Report.Detail and returns nil. A pass clears the failure and the alarm.
func (e *engine) runProbes(ctx context.Context, g *Generation, required bool) error {
	account := e.probeAccount()
	_, line := checkProbeAccount(e.l.Root, account)
	pair, reason := e.probePair(e.readProbeRecord(), g.Host, e.clock.Now().Add(e.cfg.SelfTestTimeout), genKRL(g), genCAKeys(g))
	key := failureKey(g, pair, line)
	if reason != "" {
		e.logf("probe: no usable probe pair at probe time (%s)", reason)
		return e.probeResult(ErrProbeInconclusive, key, required, probeInconclusive, probeSkippedNotReady)
	}
	if st := e.readProbeState(); st.LastPair != 0 {
		if d := unixTime(st.LastPair).Add(ProbePairSpacing).Sub(e.clock.Now()); d > 0 {
			if err := e.clock.Sleep(ctx, min(d, ProbePairSpacing)); err != nil {
				return err
			}
		}
	}
	if err := e.reserveProbe(); err != nil {
		e.logf("probe: %v", err)
		if !required {
			e.report.ProbePositive, e.report.ProbeNegative = probeSkippedBudget, probeSkippedBudget
			return nil
		}
		return e.probeResult(ErrProbeInconclusive, key, required, probeInconclusive, probeSkippedBudget)
	}
	if err := e.fault("probe-send"); err != nil {
		return err
	}
	q := e.probeQueryFunc()
	addr, err := e.probeAddr(ctx, time.Now().Add(e.cfg.SelfTestTimeout))
	if err != nil {
		e.logf("probe: %v", err)
		return e.probeResult(ErrProbeInconclusive, key, required, probeInconclusive, probeSkippedNotReady)
	}
	src, shared, note := probeSource(e.dump, addr)
	if shared {
		e.logf("probe: note: %s", note)
	}
	t := ProbeTarget{Addr: addr, Source: src, Account: account, HostKeys: e.keys}
	out, err := q(ctx, t, pair.Positive.Parse(), time.Now().Add(e.cfg.SelfTestTimeout))
	switch out {
	case ProbeAccepted:
	case ProbeRefused:
		return e.probeResult(ErrProbePositiveRefused, key, required, probeFail, probeSkippedNotReady)
	default:
		e.logf("probe: the positive probe is inconclusive: %v", err)
		return e.probeResult(ErrProbeInconclusive, key, required, probeInconclusive, probeSkippedNotReady)
	}
	out, err = q(ctx, t, pair.Negative.Parse(), time.Now().Add(e.cfg.SelfTestTimeout))
	switch out {
	case ProbeRefused:
	case ProbeAccepted:
		return e.probeResult(ErrProbeKRLNotEnforced, key, required, probePass, probeFail)
	default:
		e.logf("probe: the negative probe is inconclusive: %v", err)
		return e.probeResult(ErrProbeInconclusive, key, required, probePass, probeInconclusive)
	}
	e.report.ProbePositive, e.report.ProbeNegative = probePass, probePass
	// A pass stands: a state that cannot be updated is only logged (the
	// next pass clears it).
	st, err := e.loadProbeState()
	if err != nil || (st.Failure == nil && st.Alarm == "") {
		return nil
	}
	st.Failure, st.Alarm = nil, ""
	if err := e.writeProbeState(st); err != nil {
		e.logf("WARNING clearing the probe failure and alarm: %v", err)
	}
	return nil
}

// probeResult records a failed probe pair with the Report values pos and
// neg: for a gated addition the failure record and the error, for the
// opportunistic pair the alarm and Report.Detail, and nil. A gated
// addition whose negative sshd accepted (probe_krl_not_enforced) also sets
// the alarm, which outranks the failure_backoff hold in probe_detail, so
// a KRL that sshd does not enforce stays visible while the addition is
// held; a pass clears it (PR #91 review, F2).
func (e *engine) probeResult(cause error, key string, required bool, pos, neg string) error {
	e.report.ProbePositive, e.report.ProbeNegative = pos, neg
	code := cause.Error()
	st, err := e.loadProbeState()
	if err != nil {
		return errors.Join(cause, err)
	}
	if !required {
		e.report.Detail = code
		if st.Alarm != code {
			st.Alarm = code
			if err := e.writeProbeState(st); err != nil {
				e.logf("WARNING recording the probe alarm: %v", err)
			}
		}
		return nil
	}
	if errors.Is(cause, ErrProbeKRLNotEnforced) {
		st.Alarm = code
	}
	if err := e.recordFailure(st, code, key); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

// probeFailureCode is the detail code of a probe failure err wraps, "" for
// none.
func probeFailureCode(err error) string {
	for _, c := range []error{ErrProbePositiveRefused, ErrProbeKRLNotEnforced, ErrProbeInconclusive} {
		if errors.Is(err, c) {
			return c.Error()
		}
	}
	return ""
}

// recordFailure writes the failure record of a gated addition into st:
// {code, key, now, count}, count growing while the key is unchanged, which
// doubles the gate's back-off (D10).
func (e *engine) recordFailure(st *probeState, code, key string) error {
	count := uint64(1)
	if f := st.Failure; f != nil && f.Key == key {
		count = f.Count + 1
	}
	st.Failure = &probeFailure{Code: code, Key: key, At: e.probeNow(), Count: count}
	return e.writeProbeState(st)
}

// servedCertCheck runs the served-certificate self-test on the committed
// host certificates after forward changed the drop-in (03-10b, Task 4
// step 3; a gap 03-09 left): Report.ServedCerts is pass,
// skipped:no_certificates or fail:served_cert_mismatch, and the error is
// the mismatch. It runs once, in the run that changed the drop-in.
func (e *engine) servedCertCheck(ctx context.Context) error {
	rec, _, err := e.readHostCertRecord()
	if err != nil {
		return err
	}
	var certs []*ssh.Certificate
	if rec != nil {
		for _, en := range rec.Committed {
			if c := e.readCertFile(en.File, en.CertSHA256); c != nil {
				certs = append(certs, c)
			}
		}
	}
	if len(certs) == 0 {
		e.report.ServedCerts = "skipped:no_certificates"
		return nil
	}
	if _, err := e.hostCertSelfTest(ctx, e.dump, certs); err != nil {
		e.report.ServedCerts = "fail:" + DetailServedCertMismatch
		e.report.Detail = DetailServedCertMismatch
		return err
	}
	e.report.ServedCerts = probePass
	return nil
}

// opportunistic tries the pair after a narrowing or probe-file-only commit
// whose generation g holds the probe principal (03-10b, D8): only when the
// account check passes, a pair is usable at now + SelfTestTimeout, the last
// opportunistic pair is ProbeOpportunisticEvery ago, fewer than
// ProbeOpportunisticNegatives negatives went out in the last hour and the
// spacing is met; otherwise the probes report skipped:budget or
// skipped:not_ready. A failure is an alarm and never rolls anything back.
func (e *engine) opportunistic(ctx context.Context, g *Generation) {
	account := e.probeAccount()
	skip := func(v string) {
		// An exempt label (a probe-file-only change) says more than the skip.
		if e.report.ProbePositive == "" {
			e.report.ProbePositive, e.report.ProbeNegative = v, v
		}
	}
	if r, _ := checkProbeAccount(e.l.Root, account); r != "" || g.Host == "" ||
		!lineSet(g.Files[PrincipalsDir+"/"+account], principalLine)[certpkg.ReservedPrincipalPrefix+g.Host] {
		skip(probeSkippedNotReady)
		return
	}
	now := e.clock.Now()
	if _, r := e.probePair(e.readProbeRecord(), g.Host, now.Add(e.cfg.SelfTestTimeout), genKRL(g), genCAKeys(g)); r != "" {
		skip(probeSkippedNotReady)
		return
	}
	st := e.readProbeState()
	if (st.LastOpportunistic != 0 && unixTime(st.LastOpportunistic).Add(ProbeOpportunisticEvery).After(now)) ||
		recentNegatives(st, e.probeNow()) >= ProbeOpportunisticNegatives ||
		(st.LastPair != 0 && unixTime(st.LastPair).Add(ProbePairSpacing).After(now)) {
		skip(probeSkippedBudget)
		return
	}
	st.LastOpportunistic = e.probeNow()
	if err := e.writeProbeState(st); err != nil {
		e.logf("WARNING recording the opportunistic probe: %v", err)
		return
	}
	if err := e.runProbes(ctx, g, false); err != nil {
		e.logf("WARNING the opportunistic probe: %v", err)
	}
}

// settleFailedAddition ends a gated addition whose probes or served
// certificates failed after it went live (03-10b, D13): it rolls back the
// addition only. The settled content is Intermediate(last-good, target),
// every line both grant, with the target's (newest) KRL. When the target
// removes nothing last-good grants, that is 03-05's plain rollback, which
// then re-grants nothing. Otherwise current moves to a generation M of that
// content: the one live just before the widening swap (preN) when its
// content is that, the target itself when the target only removes from
// last-good, else one installed afresh. The held record failure_backoff is
// written after the failure record and before M is committed as last-good,
// with accepted/ advanced, so the removal stays in force and the next round
// holds. A listener-test failure after the move falls back to 03-05's
// rollback (the named residual: it can re-grant the removal until a
// listener test passes). It returns cause.
func (e *engine) settleFailedAddition(ctx context.Context, cause error, lg link, target *Generation, tv *state.Verified, preN uint64) error {
	if isCrash(cause) {
		return cause
	}
	lgGen, err := readGeneration(lg.dir)
	if err != nil {
		return e.rollback(ctx, cause, lg)
	}
	lgGen.N = lg.n
	m, collapsed := Intermediate(lgGen, target)
	if collapsed && isNarrowing(target, lgGen) {
		// Intermediate collapsed to last-good's content: the target removes
		// nothing last-good grants, so the plain rollback re-grants nothing.
		return e.rollback(ctx, cause, lg)
	}
	// Otherwise a collapsed Intermediate is the target itself, which then
	// only removes from last-good.
	pre, perr := readGeneration(e.l.Gen(preN))
	switch {
	case preN != 0 && perr == nil && sameContent(pre, m):
		pre.N = preN
		m = pre
	case m == target:
	default:
		m.N = e.allocGeneration()
		if err := e.installGeneration(m); err != nil {
			return e.rollback(ctx, errors.Join(cause, err), lg)
		}
		if err := e.validate(ctx, m, e.l.Gen(m.N), nil); err != nil {
			e.discard(m.N)
			return e.rollback(ctx, errors.Join(cause, err), lg)
		}
	}
	m.Host, m.HostStatus = target.Host, target.HostStatus
	e.report.Rollback = true
	e.poll = nil
	if err := e.writeHeld("failure_backoff", tv); err != nil {
		return e.rollback(ctx, errors.Join(cause, err), lg)
	}
	if m.N != target.N {
		if _, err := e.Transition(ctx, target, m, swapChecked); err != nil {
			return e.rollback(ctx, errors.Join(cause, err), lg)
		}
	}
	if err := e.selfTest(ctx, e.dump, e.keys); err != nil {
		e.report.RollbackSelfTest = "fail: " + err.Error()
		return e.rollback(ctx, errors.Join(cause, err), lg)
	}
	e.report.RollbackSelfTest = "pass"
	if err := e.setHostStatus(m.N, m.HostStatus); err != nil {
		return errors.Join(cause, err)
	}
	e.setVersions(tv, m)
	e.report.Generation = m.N
	if err := e.commit(m.N, tv); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}
