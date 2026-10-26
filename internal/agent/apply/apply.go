//go:build linux

// Package apply is the keyroster agent's apply engine, the place where a
// lockout would happen (AGENT-04, AUTHZ-02, REVOKE-03): signed state from
// the spool is verified against the applier's own pins, rendered into a
// generation of trust files, checked with the host's own ssh-keygen,
// swapped in through an intermediate generation when a change both adds
// and removes (F1), reloaded only when the drop-in changes, self-tested
// against sshd over loopback (the owner's D-05 answer, loopback-only) and
// rolled back to last-good when the self-test fails.
package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/trust"
)

// Apply refusals not tied to one helper.
var (
	ErrPendingStateUnknown = errors.New("pending_state_unknown")
	ErrLastGoodInvalid     = errors.New("last_good_invalid")
	ErrFirstInstallFailed  = errors.New("first_install_failed")
	ErrDropInNotEffective  = errors.New("dropin_not_effective")
	ErrConfig              = errors.New("config_invalid")
	ErrNoDropInDir         = errors.New("no_dropin_dir")
)

// Clock is the time the engine runs on: CLOCK_MONOTONIC and the boot ID
// for the swap timing rule (they survive a restart of the agent and
// ignore wall-clock steps), wall time for the marker's deadline, and a
// sleep. Tests inject a fake.
//
// The swap timing rule measures on CLOCK_MONOTONIC (owner decision
// 2026-10-26, PR #67), the clock sshd's LoginGraceTime timer runs on:
// setitimer(ITIMER_REAL) is a CLOCK_MONOTONIC timer on Linux, and
// neither advances while the host is suspended, so a suspend cannot make
// the agent's wait end before sshd's timer does. CLOCK_BOOTTIME, used
// before, counts suspended time and could. Go's own timers (Sleep) run
// on CLOCK_MONOTONIC too (runtime nanotime).
type Clock interface {
	Monotonic() time.Duration
	BootID() string
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration) error
}

// SystemClock is the real clock.
type SystemClock struct{}

// Monotonic is CLOCK_MONOTONIC.
func (SystemClock) Monotonic() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}

// BootID is /proc/sys/kernel/random/boot_id, or "" when it cannot be read
// (then every record counts as this boot's, the cautious answer).
func (SystemClock) BootID() string {
	f, err := os.Open("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(io.LimitReader(f, 64))
	return strings.TrimSpace(string(b))
}

// Now is the wall clock.
func (SystemClock) Now() time.Time { return time.Now() }

// Sleep waits d or until ctx ends.
func (SystemClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Config is one apply run.
type Config struct {
	// Spool is the spool directory the fetcher writes.
	Spool string
	// SSHD, SSHDConfig and SSHKeygen are absolute paths: the service's
	// sshd binary and configuration, and ssh-keygen.
	SSHD, SSHDConfig, SSHKeygen string
	// Reload is the reload strategy: signal, systemd:<unit> or openrc.
	Reload string
	// DryRun verifies and renders and reports the difference against
	// current, writing nothing.
	DryRun bool
	// RecoverToLastGood is the operator's way out of
	// stuck: pending_state_unknown.
	RecoverToLastGood bool
	// AllowAdoption lets this run take over a host set up with the Phase 2
	// runbook's exact layout (D-08), removing that layout's files in
	// /etc/ssh. keyroster-agent apply --once sets it; the applier unit's
	// run loop (03-07) does not, because its sandbox cannot remove files
	// there: it reports phase2_adoption_pending and writes nothing.
	AllowAdoption bool
	// SelfTestTimeout bounds the whole self-test (default 10 s).
	SelfTestTimeout time.Duration
	// Clock, Exec and Log default to SystemClock, ExecRunner and nowhere.
	Clock Clock
	Exec  Runner
	Log   io.Writer
	// Fault is a test hook called before every durable step; an error
	// from it stops the run there, as a crash would.
	Fault func(point string) error
}

// Report is what one run did, printed as JSON and kept in status.json.
type Report struct {
	BundleVersion    uint64 `json:"bundle_version"`
	DirectoryVersion uint64 `json:"directory_version"`
	KRLVersion       uint64 `json:"krl_version"`
	Generation       uint64 `json:"generation"`
	Intermediate     uint64 `json:"intermediate"`
	LoginGraceS      int    `json:"login_grace_s"`
	// WaitedMS is, for every widening swap that had to wait, the interval
	// the timing rule enforced: from the previous swap of current to the
	// widening swap (at least LoginGraceTime + 30 s).
	WaitedMS         int64  `json:"waited_ms"`
	Reloaded         bool   `json:"reloaded"`
	SelfTest         string `json:"self_test"`
	Rollback         bool   `json:"rollback"`
	RollbackSelfTest string `json:"rollback_self_test,omitempty"`
	Recovered        bool   `json:"recovered"`
	NoOp             bool   `json:"no_op"`
	// BundleHeld: a newer bundle in the spool waits for the next run,
	// because the newest directory verifies only under an earlier policy
	// (state.Verified.BundleHeld).
	BundleHeld bool   `json:"bundle_held,omitempty"`
	Stuck      string `json:"stuck,omitempty"`
	// HostStatus is set when the directory does not give this host its
	// own principals (owner decision 2026-10-26, PR #67): host_disabled
	// and host_removed install no principals, host_keys_rotated and
	// host_keys_disagree keep last-good's; the CA keys and the KRL apply
	// in every case.
	HostStatus string `json:"host_status,omitempty"`
	// KRLKept is set when the verified state's KRL is older than the one
	// in force in current, which a rollback or crash recovery kept there
	// (the KRL never rolls back): the generation keeps the KRL in force,
	// and this names both versions instead of substituting silently (PR #67
	// round-2 carry-over).
	KRLKept *KRLKept `json:"krl_kept,omitempty"`
	// Phase2Removed are the Phase 2 layout's paths this run removed after
	// taking the host over (D-08).
	Phase2Removed     []string `json:"phase2_removed,omitempty"`
	UnmatchedHostKeys []string `json:"unmatched_host_keys,omitempty"`
	SpoolIgnored      []string `json:"spool_ignored,omitempty"`
	Diff              []string `json:"diff,omitempty"`
	Errors            []string `json:"errors"`
}

// KRLKept is Report.KRLKept: the KRL version in force in current (and the
// generation that holds it), kept over the older version the verified
// state renders.
type KRLKept struct {
	InForce    uint64 `json:"in_force"`
	Verified   uint64 `json:"verified"`
	Generation uint64 `json:"generation"`
}

// engine is one run's working state.
type engine struct {
	cfg     Config
	l       Layout
	clock   Clock
	report  *Report
	stateFd int
	locked  bool // past the apply lock: status.json may be written

	pins *state.Pins
	dump Dump
	keys []ssh.PublicKey

	grace         int // the LoginGraceTime bound in force (ObserveLoginGrace)
	rawGrace      int // sshd -T's logingracetime at start
	last          swapRecord
	lastKnown     bool
	maxGen        uint64
	pending       *marker
	dropinChanged bool
	staged        uint64     // the accepted/ snapshot a commit marker names
	adopt         *AdoptPlan // a Phase 2 takeover this first install makes (D-08)
	poll          func(ctx context.Context) (*Generation, *state.Verified, error)

	// dial and ipv6Off are the self-test's dialer and IPv6 check; nil is
	// net.Dialer and /proc (tests substitute both).
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	ipv6Off func() bool
}

func (e *engine) fault(point string) error {
	if e.cfg.Fault != nil {
		return e.cfg.Fault(point)
	}
	return nil
}

func (e *engine) logf(format string, args ...any) {
	if e.cfg.Log != nil {
		_, _ = fmt.Fprintf(e.cfg.Log, "keyroster-agent: "+format+"\n", args...)
	}
}

// Apply runs one apply under the flock on <state>/apply.lock, which it
// holds through every wait:
//
//  1. The state directory must be the applier's own (state_dir_unsafe),
//     pins.json valid, and sshd -T must report a bounded LoginGraceTime
//     (login_grace_unbounded, login_grace_unknown) before anything is
//     written.
//  2. Crash recovery: a pending marker means the last run stopped
//     mid-move; current goes back to last-good through Transition (the
//     first-install path when there is no last-good). A layout the agent
//     did not make is stuck: pending_state_unknown, no swap, until the
//     operator runs --recover-to-last-good.
//  3. One spool capture is verified (state.Verify); equal versions are a
//     no-op that writes nothing and repairs no drift.
//  4. The newest verified state is rendered once (Render), keeping a newer
//     KRL current holds (keepKRL: the KRL never rolls back), written as a
//     new generation and checked (validate).
//  5. First install: current points at it directly and the drop-in is
//     written. Otherwise Transition moves current to it, through the
//     intermediate generation and the swap timing rule; a newer spool
//     state during a widening wait supersedes the target.
//  6. Only when the drop-in changed: sshd -t, the sshd -T values, reload.
//  7. Self-test; on failure, rollback to last-good (Transition) and the
//     previous drop-in, reload when needed, self-test again, report.
//  8. Commit: last-good, accepted/, the marker cleared, old generations
//     cleaned up.
func Apply(ctx context.Context, cfg Config, l Layout) (*Report, error) {
	if cfg.SelfTestTimeout <= 0 {
		cfg.SelfTestTimeout = 10 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.Exec == nil {
		cfg.Exec = execsite.ExecRunner{}
	}
	r := &Report{Errors: []string{}}
	e := &engine{cfg: cfg, l: l, clock: cfg.Clock, report: r, stateFd: -1}
	err := e.apply(ctx)
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
		if errors.Is(err, ErrPendingStateUnknown) {
			e.logf("ERROR stuck: %v. Inspect %s and run keyroster-agent apply --once --recover-to-last-good", err, l.Current())
		}
	}
	if e.stateFd >= 0 {
		if e.locked && !cfg.DryRun && !r.NoOp {
			if serr := e.writeStatus(); serr != nil && err == nil {
				err = serr
			}
		}
		_ = unix.Close(e.stateFd)
	}
	return r, err
}

func (e *engine) apply(ctx context.Context) error {
	for _, p := range []string{e.cfg.SSHD, e.cfg.SSHDConfig, e.cfg.SSHKeygen, e.l.Root, e.l.StateDir} {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%w: %q is not an absolute path", ErrConfig, p)
		}
	}
	if err := CheckReload(e.cfg.Reload); err != nil {
		return err
	}
	if err := checkOwnDir(e.l.StateDir); err != nil {
		return err
	}
	fd, err := spool.OpenDir(e.l.StateDir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	e.stateFd = fd
	// Everything up to the lock only reads: a refusal here (bad pins, an
	// unbounded LoginGraceTime) leaves the host exactly as it was.
	if e.pins, err = state.LoadPins(e.stateFd); err != nil {
		return err
	}
	if e.dump, err = e.sshdDump(ctx, ""); err != nil {
		return err
	}
	grace, err := e.dump.LoginGrace()
	if err != nil {
		return err
	}
	if e.keys, err = hostKeys(e.dump); err != nil {
		return err
	}
	unlock, err := e.lock()
	if err != nil {
		return err
	}
	defer unlock()
	e.locked = true
	for _, d := range []string{state.AcceptedDir, generationsDir} {
		if !e.cfg.DryRun {
			if err := e.mkdir(e.l.State(d), 0o700); err != nil {
				return err
			}
		}
		if err := checkOwnDir(e.l.State(d)); err != nil && (!e.cfg.DryRun || !errors.Is(err, unix.ENOENT)) {
			return err
		}
	}
	e.grace, e.rawGrace = grace, grace
	if !e.cfg.DryRun {
		if e.grace, err = e.observeLoginGrace(grace, false); err != nil {
			return err
		}
	}
	e.report.LoginGraceS = e.grace

	m, err := e.loadMarker()
	if err != nil {
		return err
	}
	cur, err := e.resolveLink(e.l.Current())
	if err != nil {
		return err
	}
	lg, err := e.resolveLink(e.l.LastGood())
	if err != nil {
		return err
	}
	e.loadLastSwap(m != nil, cur.kind != linkNone)
	if e.cfg.RecoverToLastGood {
		if e.cfg.DryRun {
			return fmt.Errorf("%w: --recover-to-last-good does not combine with --dry-run", ErrConfig)
		}
		return e.recoverToLastGood(ctx, m, cur, lg)
	}
	if err := stuck(m, cur, lg); err != nil {
		e.report.Stuck = ErrPendingStateUnknown.Error()
		return err
	}
	if (m != nil || (cur.kind == linkAgent && lg.kind == linkAgent && cur.n != lg.n && !atRollbackTarget(cur, lg))) && !e.cfg.DryRun {
		if err := e.recover(ctx, m, cur, lg); err != nil {
			return err
		}
	}
	if !e.cfg.DryRun {
		// A Phase 2 takeover whose removal a crash or a failure cut short
		// resumes once the agent's generation is last-good (D-08).
		if lg, err := e.resolveLink(e.l.LastGood()); err != nil {
			return err
		} else if lg.kind == linkAgent && e.cfg.AllowAdoption {
			if err := e.finishAdoption(ctx); err != nil {
				return err
			}
		} else if p, _ := e.readAdopt(); lg.kind == linkAgent && p != nil {
			e.logf("WARNING %s: the agent's files are in force, and the Phase 2 layout's removal is unfinished; run %s", CodePhase2Pending, adoptCommand)
		}
	}
	return e.forward(ctx)
}

// atRollbackTarget reports whether current already holds
// RollbackTarget(current, last-good): last-good's CA keys and principals
// with a newer KRL, where a rollback left it. Then there is nothing to
// recover.
func atRollbackTarget(cur, lg link) bool {
	c, err := readGeneration(cur.dir)
	if err != nil {
		return false
	}
	l, err := readGeneration(lg.dir)
	if err != nil {
		return false
	}
	return sameBytes(c, RollbackTarget(c, l))
}

// lock takes the exclusive flock on <state>/apply.lock, waiting for a
// run that holds it. The lock is released when the returned function
// runs or the process ends.
func (e *engine) lock() (func(), error) {
	if err := paths.Allowed(e.l, e.l.State(lockFile)); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(e.stateFd, lockFile, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrStateDirUnsafe, lockFile, err)
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("lock %s: %w", lockFile, err)
	}
	return func() { _ = unix.Close(fd) }, nil
}

// stuck reports a layout the agent did not make: current or last-good
// not a link to gen/<N> with its record (outside gen/, dangling, or not a
// link), or one of them missing while the other exists and no pending
// marker explains it.
func stuck(m *marker, cur, lg link) error {
	for _, x := range []struct {
		name string
		l    link
	}{{"current", cur}, {"last-good", lg}} {
		switch x.l.kind {
		case linkForeign:
			return fmt.Errorf("%w: %s names %q, which is not a generation of this agent", ErrPendingStateUnknown, x.name, x.l.target)
		case linkDangling:
			return fmt.Errorf("%w: %s names %q, which does not exist", ErrPendingStateUnknown, x.name, x.l.target)
		}
	}
	switch {
	case cur.kind == linkNone && lg.kind != linkNone:
		return fmt.Errorf("%w: current is missing while last-good exists", ErrPendingStateUnknown)
	case cur.kind != linkNone && lg.kind == linkNone && m == nil:
		return fmt.Errorf("%w: current exists without last-good and without a pending marker", ErrPendingStateUnknown)
	}
	return nil
}

// loadLastSwap reads last_swap.json. A process that starts with a pending
// marker, or with a current but an unreadable or missing record, treats
// the last swap as just made.
func (e *engine) loadLastSwap(pending, haveCurrent bool) {
	b, _ := e.readState(lastSwapFile, 4<<10)
	var r swapRecord
	// Strict: a record of another shape (an older boottime_ns record)
	// counts as unreadable, so the last swap is taken as just made.
	ok := b != nil && trust.DecodeStrict(b, &r) == nil
	switch {
	case pending || (haveCurrent && !ok):
		e.last = swapRecord{BootID: e.clock.BootID(), MonotonicNS: int64(e.clock.Monotonic()), LoginGrace: e.grace}
		e.lastKnown = true
	case ok:
		e.last, e.lastKnown = r, true
	}
}

// capture is the one spool capture helper: the transition and every
// superseding check during a widening wait read the spool only here, and
// the bytes it returns are the bytes verified and installed (F2). floor is
// the accepted state the capture is verified against (spool.Floor).
func (e *engine) capture(floor spool.Floor) (spool.State, error) {
	st, ignored, err := spool.Read(e.cfg.Spool, floor)
	for _, n := range ignored {
		if len(e.report.SpoolIgnored) < 64 && !slices.Contains(e.report.SpoolIgnored, n) {
			e.report.SpoolIgnored = append(e.report.SpoolIgnored, n)
		}
	}
	return st, err
}

func (e *engine) acceptedFd() (int, error) {
	return spool.OpenDir(e.l.State(state.AcceptedDir))
}

func (e *engine) loadStored() (*state.Stored, error) {
	fd, err := e.acceptedFd()
	if errors.Is(err, unix.ENOENT) && e.cfg.DryRun {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	return state.LoadStored(fd)
}

// forward verifies one capture and moves current to the generation it
// renders.
func (e *engine) forward(ctx context.Context) error {
	stored, err := e.loadStored()
	if err != nil {
		return err
	}
	st, err := e.capture(stored.Floor())
	if err != nil {
		return err
	}
	v, err := state.Verify(e.pins, stored, st)
	if err != nil {
		return err
	}
	e.report.BundleHeld = v.BundleHeld
	if !v.Changed() {
		e.report.NoOp = true
		// The KRL in force is current's, which a rollback or crash recovery
		// may have kept above accepted/'s (PR #67 round-2 carry-over).
		cur, curLink, err := e.readCurrent()
		if err != nil || curLink.kind != linkAgent {
			cur = nil
		}
		e.setVersions(v, cur)
		return nil
	}
	g, err := e.render(v)
	if err != nil {
		return err
	}
	cur, curLink, err := e.readCurrent()
	if err != nil {
		return err
	}
	e.keepKRL(g, cur, curLink)
	if err := e.preflightApply(ctx, v, g); err != nil {
		return err
	}
	if e.cfg.DryRun {
		e.setVersions(v, g)
		e.report.Diff = diff(cur, g)
		return nil
	}
	if cur != nil && sameBytes(cur, g) {
		// The new versions change nothing on disk: store them.
		e.setVersions(v, g)
		e.report.Generation = curLink.n
		return e.commit(curLink.n, v)
	}
	g.N = e.allocGeneration()
	if err := e.installGeneration(g); err != nil {
		return err
	}
	if err := e.validate(ctx, g, e.l.Gen(g.N), cur); err != nil {
		e.discard(g.N)
		return err
	}
	lg, err := e.resolveLink(e.l.LastGood())
	if err != nil {
		return err
	}
	if lg.kind == linkNone {
		e.setVersions(v, g)
		return e.firstInstall(ctx, g, v)
	}
	target, tv := g, v
	e.poll = func(ctx context.Context) (*Generation, *state.Verified, error) {
		return e.pollSpool(ctx, tv, target)
	}
	defer func() { e.poll = nil }()
	for {
		from, _, err := e.readCurrent()
		if err != nil {
			return e.rollback(ctx, err, lg)
		}
		mid, err := e.Transition(ctx, from, target, swapPolled)
		e.report.Intermediate = mid
		var s *superseded
		if errors.As(err, &s) {
			e.logf("a newer state arrived during the wait; moving to generation %d", s.gen.N)
			target, tv = s.gen, s.verified
			continue
		}
		if err != nil {
			return e.rollback(ctx, err, lg)
		}
		break
	}
	e.setVersions(tv, target)
	e.report.Generation = target.N
	changed, err := e.writeDropIn()
	if err != nil {
		return e.rollback(ctx, err, lg)
	}
	if changed {
		if err := e.activateDropIn(ctx); err != nil {
			return e.rollback(ctx, err, lg)
		}
	}
	if err := e.fault("self-test"); err != nil {
		return err
	}
	if err := e.selfTest(ctx, e.dump, e.keys); err != nil {
		e.report.SelfTest = "fail: " + err.Error()
		return e.rollback(ctx, err, lg)
	}
	e.report.SelfTest = "pass"
	return e.commit(target.N, tv)
}

// setVersions reports v's versions; the KRL version is g's when g (the
// generation moved to) keeps a newer KRL in force than v accepts
// (keepKRL), so the report names the KRL actually in force.
func (e *engine) setVersions(v *state.Verified, g *Generation) {
	e.report.BundleVersion, e.report.DirectoryVersion, e.report.KRLVersion = v.Next.BundleVersion, v.Next.DirectoryVersion, v.Next.KRLVersion
	if g != nil {
		e.report.KRLVersion = max(e.report.KRLVersion, krlVersion(g))
	}
}

// keepKRL is keepKRLInForce against the generation current names, when it
// is the agent's (owner decision 2026-10-26, PR #67: the KRL never rolls
// back; PR #67 fix round 2). A rollback or crash recovery can leave a
// newer KRL in current than accepted/ holds, and a capture that no longer
// offers it must not render the older one.
func (e *engine) keepKRL(g, cur *Generation, curLink link) {
	if cur == nil || curLink.kind != linkAgent {
		return
	}
	verified := krlVersion(g)
	if !keepKRLInForce(g, cur) {
		e.report.KRLKept = nil // a superseding capture may bring a newer KRL
		return
	}
	e.report.KRLKept = &KRLKept{InForce: krlVersion(cur), Verified: verified, Generation: curLink.n}
	e.logf("WARNING krl_kept: the verified state's KRL version %d is older than version %d in force in generation %d; keeping version %d", verified, krlVersion(cur), curLink.n, krlVersion(cur))
}

// render is Render for this host. When Render refuses because of the
// host's entry and the host already has trust files (a last-good of the
// agent's), the apply goes on with RenderFallback (owner decision
// 2026-10-26, PR #67): the KRL and CA keys apply, principals are emptied
// or kept as last-good's, and the report names the host status. Before
// the first install the refusal stands and nothing is installed.
func (e *engine) render(v *state.Verified) (*Generation, error) {
	g, err := Render(v, e.keys)
	if err == nil {
		return g, nil
	}
	var he *HostError
	if errors.As(err, &he) {
		e.report.UnmatchedHostKeys = he.Unmatched
	}
	lg, lerr := e.resolveLink(e.l.LastGood())
	if lerr != nil || lg.kind != linkAgent {
		return nil, err
	}
	lgGen, rerr := readGeneration(lg.dir)
	if rerr != nil {
		return nil, errors.Join(err, rerr)
	}
	lastHost := ""
	if rec, rerr := e.readRecord(lg.n); rerr == nil {
		lastHost = rec.Host
	}
	g, status, ferr := RenderFallback(v, e.keys, lastHost, lgGen, err)
	if ferr != nil {
		return nil, ferr
	}
	e.report.HostStatus = status
	e.logf("WARNING %s: %v; the KRL and CA keys apply, principals are %s", status, err, map[bool]string{true: "kept as last-good's", false: "emptied"}[status == HostKeysRotated || status == HostKeysDisagree])
	return g, nil
}

// discard removes a generation that never became current.
func (e *engine) discard(n uint64) {
	if err := e.removeAll(e.l.Gen(n)); err == nil {
		_ = e.remove(e.l.State(generationsDir, recordName(n)))
	}
}

// pollSpool is the check during a widening wait: a capture newer than
// the pending target pending, verified against it, rendered, written and
// checked, is returned as the superseding generation.
func (e *engine) pollSpool(ctx context.Context, pending *state.Verified, target *Generation) (*Generation, *state.Verified, error) {
	prev := pending.AsStored()
	st, err := e.capture(prev.Floor())
	if err != nil {
		return nil, nil, err
	}
	v, err := state.Verify(e.pins, prev, st)
	if err != nil || !v.Changed() {
		return nil, nil, err
	}
	g, err := e.render(v)
	if err != nil {
		return nil, nil, err
	}
	cur, curLink, err := e.readCurrent()
	if err != nil {
		return nil, nil, err
	}
	e.keepKRL(g, cur, curLink)
	if sameBytes(g, target) {
		return nil, nil, nil
	}
	g.N = e.allocGeneration()
	if err := e.installGeneration(g); err != nil {
		return nil, nil, err
	}
	if err := e.validate(ctx, g, e.l.Gen(g.N), cur); err != nil {
		e.discard(g.N)
		return nil, nil, err
	}
	return g, v, nil
}

// isCrash reports an error injected by the Fault hook: the run stops
// there, as a killed process would, and does nothing more.
func isCrash(err error) bool {
	var c interface{ InjectedCrash() bool }
	return errors.As(err, &c) && c.InjectedCrash()
}

// rollback moves current back after cause failed the apply:
// Transition(current, RollbackTarget(current, last-good)) through the
// intermediate (last-good's CA keys and principals, the newest KRL; owner
// decision 2026-10-26, PR #67), the previous drop-in restored and sshd
// reloaded when the drop-in had changed, the self-test run again, the
// marker cleared. It returns cause.
func (e *engine) rollback(ctx context.Context, cause error, lg link) error {
	if isCrash(cause) {
		return cause
	}
	e.report.Rollback = true
	e.poll = nil
	if err := e.backToLastGood(ctx, lg); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

// backToLastGood is the common end of rollback and crash recovery: it
// moves current to RollbackTarget(current, last-good), installing that
// generation when it is neither last-good nor what current names already.
func (e *engine) backToLastGood(ctx context.Context, lg link) error {
	lgGen, err := readGeneration(lg.dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLastGoodInvalid, err)
	}
	lgGen.N = lg.n
	from, cur, err := e.readCurrent()
	if err != nil {
		return err
	}
	if rec, err := e.readRecord(lg.n); err == nil {
		lgGen.Host = rec.Host
	}
	to, err := e.rollbackTarget(ctx, from, cur, lgGen)
	if err != nil {
		return err
	}
	if from != nil && (cur.kind != linkAgent || cur.n != to.N) {
		if _, err := e.Transition(ctx, from, to, swapChecked); err != nil {
			return err
		}
	}
	if e.dropinChanged {
		if err := e.restoreDropIn(ctx); err != nil {
			return err
		}
	}
	if err := e.selfTest(ctx, e.dump, e.keys); err != nil {
		e.report.RollbackSelfTest = "fail: " + err.Error()
	} else {
		e.report.RollbackSelfTest = "pass"
	}
	if err := e.clearMarker(); err != nil {
		return err
	}
	return e.remove(e.l.State(dropinPrevFile))
}

// rollbackTarget is RollbackTarget(from, lgGen) on disk: last-good itself
// when that is its content, current (cur, which names from) when it holds
// it already (a revocation-only change), else a new generation, installed
// and validated.
func (e *engine) rollbackTarget(ctx context.Context, from *Generation, cur link, lgGen *Generation) (*Generation, error) {
	to := RollbackTarget(from, lgGen)
	if to.N != 0 {
		return to, nil
	}
	if from != nil && cur.kind == linkAgent && sameBytes(from, to) {
		to.N = cur.n
		return to, nil
	}
	to.N = e.allocGeneration()
	if err := e.installGeneration(to); err != nil {
		return nil, err
	}
	if err := e.validate(ctx, to, e.l.Gen(to.N), from); err != nil {
		e.discard(to.N)
		return nil, err
	}
	return to, nil
}

// recover finishes a move a previous run left (pending marker): a commit
// whose generation is current is finished; otherwise back to last-good,
// or the first-install failure path when there is none.
func (e *engine) recover(ctx context.Context, m *marker, cur, lg link) error {
	e.report.Recovered = true
	if m != nil {
		e.dropinChanged = m.DropInChanged
		e.pending = m
	}
	if m != nil && m.Step == stepCommit && cur.kind == linkAgent && cur.n == m.To {
		// The generation passed its self-test: finish its commit; the
		// drop-in it was tested with stays.
		return e.finishCommit(m.To, m.Accepted)
	}
	if lg.kind == linkNone {
		return e.undoFirstInstall(ctx, cur)
	}
	if cur.kind == linkAgent && cur.n == lg.n && (m == nil || !m.DropInChanged) {
		return e.clearMarker()
	}
	e.report.Rollback = true
	return e.backToLastGood(ctx, lg)
}

// firstInstall installs generation g where no last-good exists yet
// (Codex 03-05 suggestion): sshd reads none of its files before the
// drop-in exists, so current points at g directly, then the drop-in is
// written, checked with sshd -t and the sshd -T values, sshd reloaded and
// the self-test run. A failure undoes all of it (undoFirstInstall).
func (e *engine) firstInstall(ctx context.Context, g *Generation, v *state.Verified) error {
	e.report.Generation = g.N
	if e.adopt != nil {
		// A Phase 2 takeover (D-08): its plan is durable before current or
		// the drop-in change. A crash resumes the removal once last-good is
		// set (resumeAdoption), or is undone with the first install
		// (undoFirstInstall).
		if err := e.writeAdopt(e.adopt); err != nil {
			return err
		}
	}
	if err := e.writeMarker(0, g.N, 0, "final"); err != nil {
		return err
	}
	if err := e.swapCurrent(ctx, g, swapChecked); err != nil {
		return e.failFirstInstall(ctx, err)
	}
	changed, err := e.writeDropIn()
	if err != nil {
		return e.failFirstInstall(ctx, err)
	}
	if changed {
		if err := e.activateDropIn(ctx); err != nil {
			return e.failFirstInstall(ctx, err)
		}
	}
	if err := e.selfTest(ctx, e.dump, e.keys); err != nil {
		e.report.SelfTest = "fail: " + err.Error()
		return e.failFirstInstall(ctx, err)
	}
	e.report.SelfTest = "pass"
	if err := e.commit(g.N, v); err != nil {
		return err
	}
	// Only now, with the agent's generation last-good, do the Phase 2
	// paths go (D-08).
	return e.finishAdoption(ctx)
}

func (e *engine) failFirstInstall(ctx context.Context, cause error) error {
	if isCrash(cause) {
		return cause
	}
	e.report.Rollback = true
	cur, err := e.resolveLink(e.l.Current())
	if err != nil {
		return errors.Join(cause, err)
	}
	if err := e.undoFirstInstall(ctx, cur); err != nil {
		return errors.Join(fmt.Errorf("%w: %w", ErrFirstInstallFailed, cause), err)
	}
	return fmt.Errorf("%w: %w", ErrFirstInstallFailed, cause)
}

// undoFirstInstall removes what a first install wrote: the drop-in
// (restoring a previous one), a reload so sshd forgets it, the listener
// check against the restored configuration, current, and the marker.
func (e *engine) undoFirstInstall(ctx context.Context, cur link) error {
	e.report.Rollback = true
	if e.dropinChanged {
		if err := e.restoreDropIn(ctx); err != nil {
			return err
		}
	}
	if err := e.selfTest(ctx, e.dump, e.keys); err != nil {
		e.report.RollbackSelfTest = "fail: " + err.Error()
	} else {
		e.report.RollbackSelfTest = "pass"
	}
	if cur.kind != linkNone {
		if err := e.removeCurrent(); err != nil {
			return err
		}
	}
	// A Phase 2 takeover this first install began is undone with it: its
	// paths were never touched (they go only after the commit).
	if err := e.remove(e.l.State(adoptFile)); err != nil {
		return err
	}
	if err := e.clearMarker(); err != nil {
		return err
	}
	return e.remove(e.l.State(dropinPrevFile))
}

// recoverToLastGood is --recover-to-last-good, the operator's way out of
// stuck: pending_state_unknown, run by hand after inspection. last-good
// must be a valid generation of the agent's (last_good_invalid). For
// current X: a missing X, or one without revoked.krl, gets one direct
// swap (sshd reads the KRL first, so every authentication that mixes X
// and last-good reads X's missing KRL and is refused); a readable X is
// read through ReadFileAt with its caps and left through
// Transition(X, last-good): a narrowing swap at once to the intermediate
// built from X's bytes, then last-good after the LoginGraceTime bound.
// When X is a generation of the agent's, the target is RollbackTarget(X,
// last-good): a newer KRL in X stays in force.
func (e *engine) recoverToLastGood(ctx context.Context, m *marker, cur, lg link) error {
	e.report.Recovered = true
	if lg.kind != linkAgent {
		return fmt.Errorf("%w: last-good is not a generation of this agent", ErrLastGoodInvalid)
	}
	to, err := readGeneration(lg.dir)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLastGoodInvalid, err)
	}
	if _, ok := to.Files[KRLFile]; !ok {
		return fmt.Errorf("%w: last-good has no %s", ErrLastGoodInvalid, KRLFile)
	}
	if _, ok := to.Files[CAFile]; !ok {
		return fmt.Errorf("%w: last-good has no %s", ErrLastGoodInvalid, CAFile)
	}
	to.N = lg.n
	if m != nil {
		e.dropinChanged = m.DropInChanged
	}
	var x *Generation
	if cur.kind == linkForeign || cur.kind == linkAgent {
		if cur.target == "" && cur.kind == linkForeign {
			return fmt.Errorf("%w: %s is not a symlink; move it away by hand, then run --recover-to-last-good again", ErrPendingStateUnknown, e.l.Current())
		}
		if x, err = readGeneration(cur.dir); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	switch {
	case cur.kind == linkAgent && cur.n == lg.n:
	case x == nil || x.Files[KRLFile] == nil:
		if err := e.writeMarker(0, lg.n, 0, "final"); err != nil {
			return err
		}
		if err := e.swapCurrent(ctx, to, swapDirect); err != nil {
			return err
		}
	default:
		x.N = cur.n
		if cur.kind == linkAgent {
			// The KRL never rolls back (owner decision 2026-10-26, PR #67):
			// from a generation of the agent's, recovery moves to
			// RollbackTarget, as a rollback does. A foreign current's KRL
			// was never verified, so it sets no floor.
			if rec, err := e.readRecord(lg.n); err == nil {
				to.Host = rec.Host
			}
			if to, err = e.rollbackTarget(ctx, x, cur, to); err != nil {
				return err
			}
		}
		if cur.kind != linkAgent || cur.n != to.N {
			if _, err := e.Transition(ctx, x, to, swapChecked); err != nil {
				return err
			}
		}
	}
	if e.dropinChanged {
		if err := e.restoreDropIn(ctx); err != nil {
			return err
		}
	}
	if err := e.selfTest(ctx, e.dump, e.keys); err != nil {
		e.report.RollbackSelfTest = "fail: " + err.Error()
	} else {
		e.report.RollbackSelfTest = "pass"
	}
	if err := e.clearMarker(); err != nil {
		return err
	}
	e.report.Stuck = ""
	return e.remove(e.l.State(dropinPrevFile))
}

// stepCommit is the marker step of a commit: generation to passed its
// self-test (or changes nothing on disk) and is becoming last-good.
const stepCommit = "commit"

// commit makes generation n last-good and stores the verified state, in
// an order a crash at any point can finish (PR #67 review): the verified
// state is staged as a new accepted/ snapshot, the marker is rewritten
// with step "commit" naming that snapshot (keeping dropin_changed and
// dropin.prev), the snapshot is activated and last-good set, and only
// then is the marker cleared and dropin.prev removed. A start that finds
// a commit marker whose to is current finishes the commit
// (finishCommit): accepted/ and last-good move together, and the drop-in
// is never restored once its generation passed the self-test.
func (e *engine) commit(n uint64, v *state.Verified) error {
	from := n
	if e.pending != nil {
		from = e.pending.From
	}
	fd, err := e.acceptedFd()
	if err != nil {
		return err
	}
	snap, err := v.Next.Stage(e.l, fd, e.cfg.Fault)
	_ = unix.Close(fd)
	if err != nil {
		return err
	}
	e.staged = snap
	if err := e.writeMarker(from, n, 0, stepCommit); err != nil {
		return err
	}
	return e.finishCommit(n, snap)
}

// finishCommit is the end of a commit, and what recovery runs for a
// commit marker: accepted/ snapshot snap activated (0: none staged),
// last-good to n, the marker cleared, dropin.prev removed, old
// generations removed.
func (e *engine) finishCommit(n, snap uint64) error {
	if snap != 0 {
		if err := e.fault("save-state"); err != nil {
			return err
		}
		fd, err := e.acceptedFd()
		if err != nil {
			return err
		}
		err = state.Activate(e.l, fd, snap)
		_ = unix.Close(fd)
		if err != nil {
			return err
		}
	}
	if err := e.setLastGood(n); err != nil {
		return err
	}
	if err := e.clearMarker(); err != nil {
		return err
	}
	e.dropinChanged = false
	if err := e.remove(e.l.State(dropinPrevFile)); err != nil {
		return err
	}
	e.cleanup()
	return nil
}

// DropIn is the agent's sshd drop-in for layout l: a header comment and
// three lines naming only current/... paths. The agent never writes
// /etc/ssh/sshd_config (D-07).
func DropIn(l Layout) []byte {
	cur := l.Current()
	return []byte(dropInHeader +
		"TrustedUserCAKeys " + filepath.Join(cur, CAFile) + "\n" +
		"RevokedKeys " + filepath.Join(cur, KRLFile) + "\n" +
		"AuthorizedPrincipalsFile " + filepath.Join(cur, PrincipalsDir, "%u") + "\n")
}

// readDropIn reads the drop-in now on disk, nil when there is none.
func (e *engine) readDropIn() ([]byte, error) {
	fd, err := spool.OpenDir(e.l.DropInDir())
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, paths.DropInName, 64<<10)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	return b, err
}

// writeDropIn writes the drop-in when it is missing or differs, and sshd
// listens on a loopback address the self-test can reach (else
// no_loopback_listener, before anything is written): the previous one is
// kept as dropin.prev (none when there was none), the marker records
// dropin_changed, then the file is written. It reports whether it wrote.
func (e *engine) writeDropIn() (bool, error) {
	want := DropIn(e.l)
	old, err := e.readDropIn()
	if err != nil {
		return false, err
	}
	if bytes.Equal(old, trialDropIn(e.l)) {
		old = nil // a preflight's trial, never in force: not a previous drop-in
	}
	if bytes.Equal(old, want) {
		return false, nil
	}
	// A drop-in sshd would load but the self-test cannot reach is never
	// written: no reload for a host with no loopback listener (PR #67
	// review; 03-06's preflight reports the same code before enrollment).
	if _, err := loopbackTargets(e.dump); err != nil {
		return false, err
	}
	if old != nil {
		if err := e.writeState(dropinPrevFile, old); err != nil {
			return false, err
		}
	} else if err := e.remove(e.l.State(dropinPrevFile)); err != nil {
		return false, err
	}
	e.dropinChanged = true
	if e.pending != nil {
		if err := e.writeMarker(e.pending.From, e.pending.To, e.pending.Intermediate, e.pending.Step); err != nil {
			return false, err
		}
	}
	if st, err := os.Lstat(e.l.DropInDir()); err != nil || !st.IsDir() {
		return false, fmt.Errorf("%w: %s is not a directory; the agent writes only its drop-in there and creates no sshd configuration directory", ErrNoDropInDir, e.l.DropInDir())
	}
	if err := e.fault("dropin"); err != nil {
		return false, err
	}
	return true, e.writeFile(e.l.DropInDir(), paths.DropInName, want, 0o644)
}

// trustKeywords are the sshd settings the drop-in sets, in sshd -T's
// lowercase spelling.
var trustKeywords = []string{"trustedusercakeys", "revokedkeys", "authorizedprincipalsfile"}

// ourValues are the values sshd -T must report for trustKeywords once the
// agent's drop-in is in force: its three current/ paths.
func ourValues(l Layout) map[string]string {
	cur := l.Current()
	return map[string]string{
		"trustedusercakeys":        filepath.Join(cur, CAFile),
		"revokedkeys":              filepath.Join(cur, KRLFile),
		"authorizedprincipalsfile": filepath.Join(cur, PrincipalsDir, "%u"),
	}
}

// accountSpec is the sshd -T -C connection specification for account on
// a loopback connection to laddr port lport (03-06: Match blocks are
// evaluated per managed account; a Match Address for remote client ranges
// is not, see host-setup.md "Drift").
func accountSpec(account, laddr, lport string) string {
	return "user=" + account + ",host=127.0.0.1,addr=127.0.0.1,laddr=" + laddr + ",lport=" + lport
}

// firstLoopback is the address and port of the first loopback target
// sshd -T names, for the -C specifications.
func firstLoopback(d Dump) (string, string, error) {
	targets, err := loopbackTargets(d)
	if err != nil {
		return "", "", err
	}
	host, port, err := net.SplitHostPort(targets[0])
	return host, port, err
}

// principalAccounts is the accounts g holds a principals file for.
func principalAccounts(g *Generation) []string {
	var out []string
	if g == nil {
		return nil
	}
	for _, name := range fileNames(g) {
		if a, ok := strings.CutPrefix(name, PrincipalsDir+"/"); ok {
			out = append(out, a)
		}
	}
	return out
}

// checkDropInEffective checks that sshd -T reports the drop-in's three
// paths, and so does sshd -T -C for every account current holds a
// principals file for (03-06, T-03-34: a Match block that overrides a
// trust setting for a managed account makes the drop-in not effective
// for that account).
func (e *engine) checkDropInEffective(ctx context.Context, dump Dump) error {
	want := ourValues(e.l)
	for _, k := range trustKeywords {
		if got := dump.One(k); got != want[k] {
			return fmt.Errorf("%w: sshd -T reports %s %q, want %q; another configuration file sets it first", ErrDropInNotEffective, k, got, want[k])
		}
	}
	cur, _, err := e.readCurrent()
	if err != nil {
		return err
	}
	accounts := principalAccounts(cur)
	if len(accounts) == 0 {
		return nil
	}
	laddr, lport, err := firstLoopback(dump)
	if err != nil {
		return err
	}
	for _, a := range accounts {
		d, err := e.sshdDump(ctx, accountSpec(a, laddr, lport))
		if err != nil {
			return err
		}
		for _, k := range trustKeywords {
			if got := d.One(k); got != want[k] {
				return fmt.Errorf("%w: sshd -T -C user=%s reports %s %q, want %q; a Match block overrides it for that account", ErrDropInNotEffective, a, k, got, want[k])
			}
		}
	}
	return nil
}

// activateDropIn checks a changed drop-in with sshd -t, checks that
// sshd -T now reports its three paths, globally and for every managed
// account (a drop-in read after another file that sets them, or a Match
// block that overrides them, is not effective), and reloads sshd.
func (e *engine) activateDropIn(ctx context.Context) error {
	if err := e.sshdTest(ctx); err != nil {
		return err
	}
	dump, err := e.sshdDump(ctx, "")
	if err != nil {
		return err
	}
	if err := e.checkDropInEffective(ctx, dump); err != nil {
		return err
	}
	if err := e.fault("reload"); err != nil {
		return err
	}
	reloaded, err := e.reload(ctx, e.dump)
	if err != nil {
		return err
	}
	e.report.Reloaded = e.report.Reloaded || reloaded
	g, err := dump.LoginGrace()
	if err != nil {
		return err
	}
	e.grace, err = e.observeLoginGrace(g, true)
	return err
}

// restoreDropIn puts the previous drop-in back (or removes the drop-in
// when there was none), checks the result with sshd -t and reloads.
func (e *engine) restoreDropIn(ctx context.Context) error {
	prev, err := e.readState(dropinPrevFile, 64<<10)
	if err != nil {
		return err
	}
	if prev != nil {
		err = e.writeFile(e.l.DropInDir(), paths.DropInName, prev, 0o644)
	} else {
		err = e.remove(e.l.DropIn())
	}
	if err != nil {
		return err
	}
	e.dropinChanged = false
	if err := e.sshdTest(ctx); err != nil {
		return err
	}
	reloaded, err := e.reload(ctx, e.dump)
	if err != nil {
		return err
	}
	e.report.Reloaded = e.report.Reloaded || reloaded
	e.grace, err = e.observeLoginGrace(e.rawGrace, true)
	return err
}

// statusDoc is status.json.
type statusDoc struct {
	Stuck     string  `json:"stuck,omitempty"`
	LastApply *Report `json:"last_apply"`
}

func (e *engine) writeStatus() error {
	b, err := json.Marshal(statusDoc{Stuck: e.report.Stuck, LastApply: e.report})
	if err != nil {
		return err
	}
	if old, _ := e.readState(statusFile, 1<<20); bytes.Equal(old, b) {
		return nil
	}
	return e.writeState(statusFile, b)
}

// diff describes what moving current from cur to g would change, for
// --dry-run.
func diff(cur, g *Generation) []string {
	if cur == nil {
		cur = &Generation{Files: map[string][]byte{}}
	}
	var out []string
	for _, name := range fileNames(cur, g) {
		a, okA := cur.Files[name]
		b, okB := g.Files[name]
		switch {
		case !okA:
			out = append(out, "+ "+name)
		case !okB:
			out = append(out, "- "+name)
		case bytes.Equal(a, b):
			continue
		default:
			out = append(out, "~ "+name)
		}
		class, _ := ClassOf(name)
		if class == FileKRL {
			out = append(out, fmt.Sprintf("    %d bytes -> %d bytes", len(a), len(b)))
			continue
		}
		have := map[string]bool{}
		for _, l := range lines(a) {
			have[l] = true
		}
		want := map[string]bool{}
		for _, l := range lines(b) {
			want[l] = true
			if !have[l] {
				out = append(out, "    + "+l)
			}
		}
		for _, l := range lines(a) {
			if !want[l] {
				out = append(out, "    - "+l)
			}
		}
	}
	return out
}
