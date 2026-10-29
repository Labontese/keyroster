//go:build linux

package apply

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/heartbeat"
	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// heartbeatStateFile is the applier's own copy of the last status it
// wrote to the outbox (<state>/heartbeat.json, 0600): the previous seq,
// last apply and last check come from here, never from the outbox, which
// the applier only writes (F2, Codex 03-08 MEDIUM).
const heartbeatStateFile = "heartbeat.json"

// KRLStaleAfter is D-10's KRL age alert: an installed KRL whose
// manifest's issued_at is this old or older raises krl_stale. Staleness
// only alerts: the KRL stays installed and no login is refused because
// of its age.
const KRLStaleAfter = 24 * time.Hour

// StatusUpdate is what one status write records: the apply that just ran
// (Applied, its report and error), the drift check that just ran
// (Checked and its report), or neither (the status at start, before any
// apply). What it does not carry is kept from the previous status.
type StatusUpdate struct {
	Applied  bool
	Report   *Report
	ApplyErr error
	Checked  bool
	Drift    *DriftReport
	// CheckErr is the error of a check that failed (Checked set, Drift
	// nil): the status says so in last_check.error (PR #72 review C16).
	CheckErr error
	// Swapping is the status a two-step swap writes at its pending marker
	// (publishPending): nothing is run, sshd's version and settings are
	// the previous status's (PR #72 review C17).
	Swapping bool
}

// WriteStatus builds the host's status and writes it, under the apply
// lock, to the state directory's heartbeat.json (0600) and to the outbox's
// status.json (heartbeat.StatusFile, spool.WriteFileAt, 0640, so the
// fetcher reads it through the outbox's group; a symlink planted at its
// temporary name is never followed). The status is validated as the
// server will validate it before anything is written. When the KRL in
// force is KRLStaleAfter old or older, an error line is logged (journald
// priority 3 when JOURNAL_STREAM is set), krl_stale is set, and nothing
// else changes. Without an outbox (a host applied by hand, never
// enrolled) it writes nothing and returns nil.
func WriteStatus(ctx context.Context, cfg Config, l Layout, u StatusUpdate) (*heartbeat.Status, error) {
	if cfg.Exec == nil {
		cfg.Exec = execsite.ExecRunner{}
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if err := CheckStateDirs(l); err != nil {
		return nil, err
	}
	// No outbox, no fetcher to send it: a host applied by hand without
	// enrollment keeps no status.
	if _, err := os.Lstat(l.Outbox()); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	fd, err := spool.OpenDir(l.StateDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	defer func() { _ = unix.Close(fd) }()
	e := &engine{cfg: cfg, l: l, clock: cfg.Clock, report: &Report{Errors: []string{}}, stateFd: fd}
	unlock, err := e.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return e.publishStatus(ctx, u)
}

// publishStatus builds the status and writes it to heartbeat.json and the
// outbox; the caller holds the apply lock and has checked the outbox.
func (e *engine) publishStatus(ctx context.Context, u StatusUpdate) (*heartbeat.Status, error) {
	l := e.l
	s, err := e.buildStatus(ctx, u)
	if err != nil {
		return nil, err
	}
	if err := heartbeat.Validate(s); err != nil {
		return nil, fmt.Errorf("the status would not pass the server's checks: %w", err)
	}
	b, err := trust.CanonicalJSON(s)
	if err != nil {
		return nil, err
	}
	if len(b) > heartbeat.MaxStatus {
		return nil, fmt.Errorf("the status is %d bytes, above %d", len(b), heartbeat.MaxStatus)
	}
	if err := e.writeState(heartbeatStateFile, b); err != nil {
		return nil, err
	}
	if err := writeOutbox(l, heartbeat.StatusFile, b); err != nil {
		return nil, err
	}
	return s, nil
}

// publishPending writes the status while a two-step swap is in progress,
// each time its pending marker is written (PR #72 review C17): the
// widening wait can last LoginGraceTime, and the host must not look idle
// or converged meanwhile. The versions stay the committed generation's
// and the KRL the one current names, as for any status. It runs inside
// Apply, under the apply lock Apply holds, and runs no program: sshd's
// version and settings are carried from the previous status. A status
// that cannot be written only delays what the host reports.
func (e *engine) publishPending(ctx context.Context) {
	if !e.locked || e.cfg.DryRun || e.stateFd < 0 {
		return
	}
	if _, err := os.Lstat(e.l.Outbox()); err != nil {
		return
	}
	if _, err := e.publishStatus(ctx, StatusUpdate{Swapping: true}); err != nil {
		e.logf("WARNING writing %s during a swap: %v", filepath.Join(e.l.Outbox(), heartbeat.StatusFile), err)
	}
}

// writeOutbox writes name in the outbox (spool.WriteFileAt, 0640).
func writeOutbox(l Layout, name string, b []byte) error {
	if err := paths.Allowed(l, filepath.Join(l.Outbox(), name)); err != nil {
		return err
	}
	fd, err := spool.OpenDir(l.Outbox())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	defer func() { _ = unix.Close(fd) }()
	return spool.WriteFileAt(fd, name, b, 0o640)
}

// agentVersion is the binary's module version, as keyroster-agent version
// prints it.
func agentVersion() string {
	v := "(devel)"
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		v = info.Main.Version
	}
	return heartbeat.Sanitize("keyroster-agent "+v, heartbeat.MaxText)
}

// stampFormat is the status's time format (trust's timestamp format).
func stamp(t time.Time) string { return t.UTC().Format(trust.TimeFormat) }

// buildStatus assembles the status. The generation and its files are the
// committed generation's: current at rest, or the generation a pending
// swap started from (its marker's from), never the intermediate; bundle,
// policy and directory come from accepted/, which changes only at a
// commit. The KRL is the one in force, in the generation current names.
func (e *engine) buildStatus(ctx context.Context, u StatusUpdate) (*heartbeat.Status, error) {
	now := e.clock.Now()
	var prev *heartbeat.Status
	if b, err := e.readState(heartbeatStateFile, heartbeat.MaxStatus); err == nil && b != nil {
		prev, _ = heartbeat.ParseStatus(b) // an unreadable copy only restarts seq from the clock
	}
	s := &heartbeat.Status{AgentVersion: agentVersion(), Files: []heartbeat.File{}}

	m, err := e.loadMarker()
	if err != nil {
		return nil, err
	}
	var gen uint64
	if m != nil {
		s.Pending = &heartbeat.Pending{Step: m.Step, From: m.From, To: m.To, Intermediate: m.Intermediate}
		gen = m.From
	} else if cur, err := e.resolveLink(e.l.Current()); err == nil && cur.kind == linkAgent {
		gen = cur.n
	}
	if gen != 0 {
		rec, err := e.readRecord(gen)
		if err != nil {
			return nil, fmt.Errorf("generation %d: %w", gen, err)
		}
		s.Generation = gen
		names := make([]string, 0, len(rec.Files))
		for n := range rec.Files {
			names = append(names, n)
		}
		slices.Sort(names)
		if len(names) > heartbeat.MaxFiles {
			names, s.FilesTruncated = names[:heartbeat.MaxFiles], true
		}
		for _, n := range names {
			s.Files = append(s.Files, heartbeat.File{Path: n, SHA256: rec.Files[n]})
		}
	}
	// The KRL is the one in force: the generation current names, also
	// while a swap is pending (03-05's inherited rule; a KRL never rolls
	// back, so an intermediate's KRL is already the target's).
	krlGen := gen
	if cur, err := e.resolveLink(e.l.Current()); err == nil && cur.kind == linkAgent {
		krlGen = cur.n
	}
	if krlGen != 0 {
		g, err := readGeneration(e.l.Gen(krlGen))
		if err != nil {
			return nil, fmt.Errorf("generation %d: %w", krlGen, err)
		}
		if k := g.Files[KRLFile]; len(k) > 0 {
			if v := krlVersion(g); v != 0 {
				s.KRL = heartbeat.KRL{Version: v, SHA256: trust.SHA256Hex(k)}
			}
		}
	}

	var staleFrom string // the issued_at the KRL's age is measured from
	afd, err := spool.OpenDir(e.l.State(state.AcceptedDir))
	switch {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return nil, err
	default:
		st, err := state.LoadStored(afd)
		_ = unix.Close(afd)
		if err != nil {
			return nil, err
		}
		if st != nil {
			if st.BundleVersion != 0 {
				s.Bundle = heartbeat.Doc{Version: st.BundleVersion, SHA256: trust.SHA256Hex(st.Bundle)}
			}
			if p, err := trust.ParsePolicy(st.Policy); err == nil && p.Version != 0 {
				s.Policy = heartbeat.Doc{Version: p.Version, SHA256: trust.SHA256Hex(st.Policy)}
			}
			if st.DirectoryVersion != 0 {
				s.Directory = heartbeat.Doc{Version: st.DirectoryVersion, SHA256: trust.SHA256Hex(st.Directory)}
			}
			if mf, err := krl.ParseManifest(st.KRLManifest); err == nil && len(st.KRLManifest) > 0 {
				// The manifest accepted/ holds is the in-force KRL's when
				// the versions agree. A KRL a rollback kept in current is
				// newer than it, so its age is at most this one's (an
				// alert can come early, never late).
				staleFrom = mf.IssuedAt
				if mf.KRLVersion == s.KRL.Version {
					s.KRL.IssuedAt = mf.IssuedAt
				}
			}
		}
	}
	if staleFrom != "" && s.KRL.Version != 0 {
		if t, err := time.Parse(time.RFC3339, staleFrom); err == nil && now.Sub(t) >= KRLStaleAfter {
			s.KRLStale = true
		}
	}

	if b, err := e.readDropIn(); err == nil && b != nil {
		s.DropInSHA256 = trust.SHA256Hex(b)
	}
	switch {
	case u.Swapping:
		if prev != nil {
			s.SSHDVersion, s.Effective = prev.SSHDVersion, prev.Effective
		}
	default:
		s.SSHDVersion = heartbeat.Sanitize(e.sshdVersion(ctx), heartbeat.MaxText)
	}
	if d, err := e.sshdDump(ctx, ""); err == nil && !u.Swapping {
		s.Effective = heartbeat.Effective{
			TrustedUserCAKeys:        heartbeat.Sanitize(d.One("trustedusercakeys"), heartbeat.MaxText),
			RevokedKeys:              heartbeat.Sanitize(d.One("revokedkeys"), heartbeat.MaxText),
			AuthorizedPrincipalsFile: heartbeat.Sanitize(d.One("authorizedprincipalsfile"), heartbeat.MaxText),
			HostCertificate:          heartbeat.Sanitize(d.One("hostcertificate"), heartbeat.MaxText),
		}
	}

	if prev != nil {
		s.LastApply, s.LastCheck, s.Stuck = prev.LastApply, prev.LastCheck, prev.Stuck
	}
	if u.Applied && u.Report != nil {
		a := &heartbeat.LastApply{At: stamp(now), Result: applyResult(u.Report, u.ApplyErr), Rollback: u.Report.Rollback}
		if len(u.Report.Errors) > 0 {
			a.Error = heartbeat.Sanitize(u.Report.Errors[0], heartbeat.MaxText)
		}
		switch u.Report.HostStatus {
		case "", "host_disabled", "host_removed", "host_keys_rotated", "host_keys_disagree":
			a.HostStatus = u.Report.HostStatus
		}
		s.LastApply = a
		s.Stuck = ""
		if u.Report.Stuck == heartbeat.StuckPendingStateUnknown {
			s.Stuck = u.Report.Stuck
		}
	}
	switch {
	case u.Checked && u.CheckErr != nil:
		s.LastCheck = &heartbeat.LastCheck{At: stamp(now), Error: heartbeat.Sanitize(u.CheckErr.Error(), heartbeat.MaxText)}
	case u.Checked && u.Drift != nil:
		s.LastCheck = &heartbeat.LastCheck{At: stamp(now), Drift: u.Drift.Drift()}
	}
	// seq = max(previous + 1, now in microseconds), except that a previous
	// seq more than heartbeat.MaxSeqAhead beyond this clock (it ran ahead
	// and was corrected) restarts from the clock: the server refuses a seq
	// that far beyond its own clock (heartbeat_seq_future, owner decision
	// D-R2), so counting on from it would freeze the host's status.
	s.Seq = uint64(max(now.UnixMicro(), 1)) //nolint:gosec // G115: positive
	if prev != nil && prev.Seq >= s.Seq && prev.Seq-s.Seq <= uint64(heartbeat.MaxSeqAhead.Microseconds()) {
		s.Seq = prev.Seq + 1
	}
	return s, nil
}

// refusals are the apply errors that are a refusal by design (the signed
// state, the host's sshd layout or its clock bound refused, nothing
// changed), as opposed to a tool failure: last_apply.result refused.
var refusals = []error{
	state.ErrPins, state.ErrBundleOlder, state.ErrBundleChainGap, state.ErrBundle, state.ErrBundleInstall,
	state.ErrPolicyMissing, state.ErrNoBundle, state.ErrDirOlder, state.ErrDirChainGap, state.ErrDir,
	state.ErrDirInstall, state.ErrKRLOlder, state.ErrKRL, state.ErrKRLHeader,
	ErrPhase2Pending, ErrPhase2Differs, ErrHostNotInDirectory, ErrHostKeysDisagree, ErrKRLRollback,
	ErrForeignTrust, ErrRHEL8, ErrFIPS, ErrHostPoPNotEnabled, ErrConfigUnsafe, ErrSSHKeygenMissing,
	ErrCALineRejected, ErrKRLInvalid, ErrKRLRejected, ErrKRLDropsKeyEntry, ErrPendingStateUnknown,
	ErrLoginGraceUnbounded, ErrLoginGraceUnknown, ErrStateDirUnsafe,
}

// applyResult is last_apply.result: rolled_back after a rollback, ok
// without an error, refused for a refusal, error otherwise.
func applyResult(r *Report, err error) string {
	switch {
	case r.Rollback:
		return heartbeat.ResultRolledBack
	case err == nil:
		return heartbeat.ResultOK
	}
	for _, x := range refusals {
		if errors.Is(err, x) {
			return heartbeat.ResultRefused
		}
	}
	return heartbeat.ResultError
}

// LogKRLAge logs D-10's alert when s says the KRL in force is stale: one
// error line per call (each drift check), with the journald priority
// prefix <3> when the process logs to the journal (JOURNAL_STREAM set).
func LogKRLAge(cfg Config, s *heartbeat.Status) {
	if cfg.Log == nil || s == nil || !s.KRLStale {
		return
	}
	prefix := ""
	if os.Getenv("JOURNAL_STREAM") != "" {
		prefix = "<3>"
	}
	_, _ = fmt.Fprintf(cfg.Log, "%skeyroster-agent run: ERROR krl_stale: the installed KRL version %d was issued at %s, %s or more ago; it stays installed and refuses no login, but newer revocations may not be reaching this host (check the server and keyroster host status)\n",
		prefix, s.KRL.Version, krlIssuedAt(s), KRLStaleAfter)
}

func krlIssuedAt(s *heartbeat.Status) string {
	if s.KRL.IssuedAt == "" {
		return "an unknown time (no manifest for this version; an older accepted one is 24 h old or more)"
	}
	return s.KRL.IssuedAt
}
