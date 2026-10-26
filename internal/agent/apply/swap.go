//go:build linux

package apply

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/trust"
)

// ErrSwapNotMonotone is a swap of current that is neither narrowing
// (the target's CA keys and principal lines all in the generation current
// names) nor widening (all of current's in the target, and every
// revocation list byte for byte the same). swapCurrent refuses it before
// any rename.
var ErrSwapNotMonotone = errors.New("swap_not_monotone")

// keepGenerations is how many of the newest generations cleanup keeps,
// besides those current, last-good and the pending marker name.
const keepGenerations = 5

// Generation file caps for reading a generation back.
const (
	maxCAFile         = 1 << 20
	maxPrincipalsFile = 64 << 10
	maxAccounts       = 4096
)

// genRecord is <state>/generations/<N>.json: the SHA-256 of each file of
// generation N, written before the directory is renamed into place. Only
// a generation with a record is the agent's (03-06's drift check and
// 03-08's heartbeat read them too).
type genRecord struct {
	Generation uint64            `json:"generation"`
	Files      map[string]string `json:"files"`
}

func recordName(n uint64) string { return strconv.FormatUint(n, 10) + ".json" }

// installGeneration writes g as generation g.N: a temporary directory in
// gen/ (0755, files 0644), the record, then rename to gen/<N> and an
// fsync of gen/. The keyroster tree and gen/ are set to 0755 whatever the
// umask (mkdirMode).
func (e *engine) installGeneration(g *Generation) error {
	for _, d := range []string{e.l.KeyrosterDir(), e.l.GenDir()} {
		if err := e.mkdirMode(d, 0o755); err != nil {
			return err
		}
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(e.l.GenDir(), ".tmp-"+strconv.FormatUint(g.N, 10)+"-"+hex.EncodeToString(rnd[:]))
	if err := e.mkdir(tmp, 0o755); err != nil {
		return err
	}
	rec := genRecord{Generation: g.N, Files: map[string]string{}}
	for _, name := range fileNames(g) {
		dir, base := filepath.Split(name)
		target := filepath.Join(tmp, dir)
		if dir != "" {
			if err := e.mkdir(target, 0o755); err != nil {
				return err
			}
		}
		if err := e.writeFile(filepath.Clean(target), base, g.Files[name], 0o644); err != nil {
			return err
		}
		rec.Files[name] = trust.SHA256Hex(g.Files[name])
	}
	if err := e.chmodDirs(tmp); err != nil {
		return err
	}
	b, err := trust.CanonicalJSON(rec)
	if err != nil {
		return err
	}
	if err := e.mkdir(e.l.State(generationsDir), 0o700); err != nil {
		return err
	}
	if err := e.writeFile(e.l.State(generationsDir), recordName(g.N), b, 0o600); err != nil {
		return err
	}
	if err := e.renameDir(tmp, e.l.Gen(g.N)); err != nil {
		return err
	}
	return fsyncDir(e.l.GenDir())
}

// chmodDirs sets 0755 on a new generation's directories, whatever the
// umask made of them: sshd reads the CA file and the KRL as root but opens
// AuthorizedPrincipalsFile as the target user, so every user must be able
// to traverse them; only root writes them.
func (e *engine) chmodDirs(root string) error {
	for _, d := range []string{root, filepath.Join(root, PrincipalsDir)} {
		if err := paths.Allowed(e.l, d); err != nil {
			return err
		}
		if err := os.Chmod(d, 0o755); err != nil && !errors.Is(err, os.ErrNotExist) { //nolint:gosec // G302: sshd reads generation directories; only root writes them
			return err
		}
	}
	return nil
}

// readGeneration reads the trust files of the generation directory dir
// through spool.ReadFileAt, each with its cap: user_ca_keys,
// revoked.krl and principals/*. A file that is missing is absent from
// the result; a missing dir is an error wrapping unix.ENOENT.
func readGeneration(dir string) (*Generation, error) {
	fd, err := spool.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	g := &Generation{Files: map[string][]byte{}}
	for _, f := range []struct {
		name string
		max  int64
	}{{CAFile, maxCAFile}, {KRLFile, krl.MaxKRL}} {
		b, err := spool.ReadFileAt(fd, f.name, f.max)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		g.Files[f.name] = b
	}
	pfd, err := unix.Openat(fd, PrincipalsDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return g, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open %s/%s: %w", dir, PrincipalsDir, err)
	}
	defer func() { _ = unix.Close(pfd) }()
	names, err := spool.ListDir(pfd)
	if err != nil {
		return nil, err
	}
	if len(names) > maxAccounts {
		return nil, fmt.Errorf("%s/%s holds %d files, above %d", dir, PrincipalsDir, len(names), maxAccounts)
	}
	for _, n := range names {
		b, err := spool.ReadFileAt(pfd, n, maxPrincipalsFile)
		if err != nil {
			return nil, err
		}
		g.Files[PrincipalsDir+"/"+n] = b
	}
	return g, nil
}

// linkKind is what a current or last-good link is.
type linkKind int

const (
	linkNone     linkKind = iota // no link at that path
	linkAgent                    // gen/<N> with its record and directory
	linkForeign                  // not a link, or a link outside gen/, or gen/<N> without its record
	linkDangling                 // a link whose target is missing
)

// link is one resolved link.
type link struct {
	kind   linkKind
	n      uint64 // for linkAgent
	target string // the link's text
	dir    string // the directory it names (absolute), when it exists
}

// resolveLink reads the link at path without following it further than
// once.
func (e *engine) resolveLink(path string) (link, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return link{kind: linkNone}, nil
		}
		return link{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return link{kind: linkForeign, dir: path}, nil
	}
	target, err := os.Readlink(path)
	if err != nil {
		return link{}, err
	}
	abs := target
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(filepath.Dir(path), target)
	}
	var tst unix.Stat_t
	if err := unix.Stat(abs, &tst); err != nil || tst.Mode&unix.S_IFMT != unix.S_IFDIR {
		return link{kind: linkDangling, target: target}, nil
	}
	n, ok := paths.ParseGenLink(target)
	if !ok {
		return link{kind: linkForeign, target: target, dir: abs}, nil
	}
	if b, err := e.readRecord(n); err != nil || b == nil {
		return link{kind: linkForeign, target: target, dir: abs}, nil
	}
	return link{kind: linkAgent, n: n, target: target, dir: abs}, nil
}

func (e *engine) readRecord(n uint64) (*genRecord, error) {
	fd, err := spool.OpenDir(e.l.State(generationsDir))
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	b, err := spool.ReadFileAt(fd, recordName(n), 1<<20)
	if err != nil {
		return nil, err
	}
	var r genRecord
	if err := trust.DecodeStrict(b, &r); err != nil || r.Generation != n {
		return nil, fmt.Errorf("record %d does not decode", n)
	}
	return &r, nil
}

// replaceLink points the link at path to target atomically: a temporary
// symlink beside it, rename(2) over path, and an fsync of the directory
// and its parent. Only swapCurrent passes the current link, and only
// setLastGood the last-good one (TestPaths pins the first).
func (e *engine) replaceLink(path, target string) error {
	if err := paths.Allowed(e.l, path); err != nil {
		return err
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(rnd[:]))
	if err := paths.Allowed(e.l, tmp); err != nil {
		return err
	}
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := fsyncDir(filepath.Dir(path)); err != nil {
		return err
	}
	return fsyncDir(filepath.Dir(filepath.Dir(path)))
}

// setLastGood points last-good at generation n.
func (e *engine) setLastGood(n uint64) error {
	if err := e.fault("last-good"); err != nil {
		return err
	}
	return e.replaceLink(e.l.LastGood(), paths.GenLink(n))
}

// removeCurrent deletes the current link (a failed first install leaves
// no generation in force).
func (e *engine) removeCurrent() error {
	if err := e.fault("remove-current"); err != nil {
		return err
	}
	if err := e.remove(e.l.Current()); err != nil {
		return err
	}
	return fsyncDir(e.l.KeyrosterDir())
}

// swapRecord is <state>/last_swap.json: when current last changed, on
// which boot (boot_id) and at which CLOCK_BOOTTIME, to which generation,
// and the LoginGraceTime bound in force then.
type swapRecord struct {
	BootID     string `json:"boot_id"`
	BoottimeNS int64  `json:"boottime_ns"`
	Generation uint64 `json:"generation"`
	LoginGrace int    `json:"login_grace_s"`
}

// swapMode is how swapCurrent may move current.
type swapMode int

const (
	swapChecked swapMode = iota // classify, wait before a widening swap
	swapPolled                  // swapChecked, and check the spool during the wait
	swapDirect                  // no classification: the operator's recovery from a missing current or KRL
)

// superseded ends a widening wait: a newer verified state arrived and
// was rendered and written as gen.
type superseded struct {
	gen      *Generation
	verified *state.Verified
}

func (s *superseded) Error() string {
	return "superseded by generation " + strconv.FormatUint(s.gen.N, 10)
}

// readCurrent reads the generation current names, or nil when there is no
// current link.
func (e *engine) readCurrent() (*Generation, link, error) {
	l, err := e.resolveLink(e.l.Current())
	if err != nil {
		return nil, l, err
	}
	switch l.kind {
	case linkNone:
		return nil, l, nil
	case linkDangling:
		return nil, l, fmt.Errorf("current names %q, which does not exist", l.target)
	}
	g, err := readGeneration(l.dir)
	if err != nil {
		return nil, l, err
	}
	g.N = l.n
	return g, l, nil
}

// swapCurrent is the one function that moves current (F1). It classifies
// the move against the generation current names, read from disk: a
// narrowing swap happens at once; a widening swap first waits until the
// LoginGraceTime bound + 5 s have passed since the previous swap of
// current (last_swap.json, by boot ID and CLOCK_BOOTTIME), checking the
// spool every 5 s when mode is swapPolled; anything else is
// swap_not_monotone, refused before any rename. swapDirect skips the
// classification (the operator's --recover-to-last-good from a missing
// current or revocation list, where every mixed read is refused).
func (e *engine) swapCurrent(ctx context.Context, target *Generation, mode swapMode) error {
	if mode != swapDirect {
		cur, _, err := e.readCurrent()
		if err != nil {
			return err
		}
		if cur != nil && !isNarrowing(cur, target) {
			if !isWidening(cur, target) {
				return fmt.Errorf("%w: generation %d both adds and removes, or adds while changing the KRL, relative to current", ErrSwapNotMonotone, target.N)
			}
			if err := e.waitWidening(ctx, mode == swapPolled); err != nil {
				return err
			}
		}
	}
	if err := e.fault("swap"); err != nil {
		return err
	}
	if err := e.replaceLink(e.l.Current(), paths.GenLink(target.N)); err != nil {
		return err
	}
	return e.recordSwap(target.N)
}

// recordSwap writes last_swap.json for a swap just made.
func (e *engine) recordSwap(n uint64) error {
	e.last = swapRecord{BootID: e.clock.BootID(), BoottimeNS: int64(e.clock.Boottime()), Generation: n, LoginGrace: e.grace}
	e.lastKnown = true
	b, err := trust.CanonicalJSON(e.last)
	if err != nil {
		return err
	}
	return e.writeState(lastSwapFile, b)
}

// widenDue is the CLOCK_BOOTTIME from which a widening swap may happen:
// the previous swap plus the larger of the bound recorded with it and the
// bound in force now, plus 5 s. Another boot owes nothing (sshd started
// again with it).
func (e *engine) widenDue() time.Duration {
	if !e.lastKnown || e.last.BootID != e.clock.BootID() {
		return 0
	}
	g := max(e.last.LoginGrace, e.grace)
	return time.Duration(e.last.BoottimeNS) + time.Duration(g+5)*time.Second
}

// spoolPoll is how often a widening wait checks the spool.
const spoolPoll = 5 * time.Second

// waitWidening waits until widenDue. With poll set it checks the spool
// every spoolPoll and returns *superseded when a newer state was
// rendered (PR #57 review: a revocation never waits behind a widening
// wait). A swap that had to wait adds to Report.WaitedMS the interval it
// enforced: from the previous swap of current to the end of the wait.
func (e *engine) waitWidening(ctx context.Context, poll bool) error {
	due := e.widenDue()
	waited := false
	for {
		now := e.clock.Boottime()
		if now >= due {
			if waited {
				e.report.WaitedMS += (now - time.Duration(e.last.BoottimeNS)).Milliseconds()
			}
			return nil
		}
		waited = true
		step := min(due-now, spoolPoll)
		if err := e.clock.Sleep(ctx, step); err != nil {
			return err
		}
		if poll && e.poll != nil {
			g, res, err := e.poll(ctx)
			if err != nil {
				e.logf("spool check during the wait: %v", err)
				continue
			}
			if g != nil {
				return &superseded{gen: g, verified: res}
			}
		}
	}
}

// marker is <state>/pending.json, canonical JSON: the move in progress
// (from, to, the intermediate, 0 when it collapsed), the step the next
// swap makes ("intermediate" or "final"), whether the drop-in was changed
// (so reaching last-good restores dropin.prev) and the wall-clock time by
// which the move should be done. Transition rewrites it before every
// swap, so at every crash point current names from, the intermediate or
// to.
type marker struct {
	From          uint64 `json:"from"`
	To            uint64 `json:"to"`
	Intermediate  uint64 `json:"intermediate"`
	Step          string `json:"step"`
	DropInChanged bool   `json:"dropin_changed"`
	Deadline      string `json:"deadline"`
}

func (e *engine) writeMarker(from, to, mid uint64, step string) error {
	if err := e.fault("marker"); err != nil {
		return err
	}
	m := marker{From: from, To: to, Intermediate: mid, Step: step, DropInChanged: e.dropinChanged,
		Deadline: e.clock.Now().Add(time.Duration(e.grace+5)*time.Second + 2*e.cfg.SelfTestTimeout).UTC().Format(trust.TimeFormat)}
	b, err := trust.CanonicalJSON(m)
	if err != nil {
		return err
	}
	e.pending = &m
	return e.writeState(pendingFile, b)
}

func (e *engine) clearMarker() error {
	if err := e.fault("clear-marker"); err != nil {
		return err
	}
	e.pending = nil
	if err := e.remove(e.l.State(pendingFile)); err != nil {
		return err
	}
	return fsyncDir(e.l.StateDir)
}

func (e *engine) loadMarker() (*marker, error) {
	b, err := e.readState(pendingFile, 4<<10)
	if err != nil || b == nil {
		return nil, err
	}
	var m marker
	if err := trust.DecodeStrict(b, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", pendingFile, err)
	}
	return &m, nil
}

// Transition moves current from the generation from (what current names
// now) to the generation to, which is already written (F1, owner decision
// 2026-10-24). It is the only way between two installed generations,
// rollback and crash recovery included: when Intermediate collapses, one
// swap to to after the marker {from, to, 0, final}; otherwise the
// intermediate M is written and checked, the marker {from, to, M,
// intermediate} written, the narrowing swap to M made at once, the marker
// rewritten with step final, and the widening swap to to made by
// swapCurrent's timing rule.
func (e *engine) Transition(ctx context.Context, from, to *Generation, mode swapMode) (uint64, error) {
	m, collapsed := Intermediate(from, to)
	if collapsed {
		if err := e.writeMarker(from.N, to.N, 0, "final"); err != nil {
			return 0, err
		}
		return 0, e.swapCurrent(ctx, to, mode)
	}
	m.N = e.allocGeneration()
	if err := e.installGeneration(m); err != nil {
		return 0, err
	}
	if err := e.validate(ctx, m, e.l.Gen(m.N), nil); err != nil {
		return 0, err
	}
	if err := e.writeMarker(from.N, to.N, m.N, "intermediate"); err != nil {
		return m.N, err
	}
	if err := e.swapCurrent(ctx, m, swapChecked); err != nil {
		return m.N, err
	}
	if err := e.writeMarker(from.N, to.N, m.N, "final"); err != nil {
		return m.N, err
	}
	return m.N, e.swapCurrent(ctx, to, mode)
}

// allocGeneration returns a generation number above every one on disk or
// recorded.
func (e *engine) allocGeneration() uint64 {
	n := e.maxGen
	for _, dir := range []string{e.l.GenDir(), e.l.State(generationsDir)} {
		names, _ := os.ReadDir(dir)
		for _, d := range names {
			s := strings.TrimSuffix(d.Name(), ".json")
			if v, err := strconv.ParseUint(s, 10, 64); err == nil && v > n {
				n = v
			}
		}
	}
	e.maxGen = n + 1
	return e.maxGen
}

// cleanup removes generations beyond the newest keepGenerations, never
// one that current, last-good or the pending marker names, and stray
// temporary directories in gen/.
func (e *engine) cleanup() {
	keep := map[uint64]bool{}
	for _, p := range []string{e.l.Current(), e.l.LastGood()} {
		if l, err := e.resolveLink(p); err == nil && l.kind == linkAgent {
			keep[l.n] = true
		}
	}
	if m, err := e.loadMarker(); err == nil && m != nil {
		keep[m.From], keep[m.To], keep[m.Intermediate] = true, true, true
	}
	entries, err := os.ReadDir(e.l.GenDir())
	if err != nil {
		return
	}
	var gens []uint64
	for _, d := range entries {
		if strings.HasPrefix(d.Name(), ".tmp-") {
			_ = e.removeAll(filepath.Join(e.l.GenDir(), d.Name()))
			continue
		}
		if v, err := strconv.ParseUint(d.Name(), 10, 64); err == nil {
			gens = append(gens, v)
		}
	}
	slices.Sort(gens)
	for i, n := range gens {
		if keep[n] || i >= len(gens)-keepGenerations {
			continue
		}
		if err := e.removeAll(e.l.Gen(n)); err == nil {
			_ = e.remove(e.l.State(generationsDir, recordName(n)))
		}
	}
}

// loginGraceState is <state>/login_grace.json.
type loginGraceState struct {
	BootID            string `json:"boot_id"`
	MaxS              int    `json:"max_s"`
	PrevMaxS          int    `json:"prev_max_s"`
	OwnReloadBoottime int64  `json:"own_reload_boottime_ns"`
}

// ObserveLoginGrace records one sshd -T observation of LoginGraceTime
// (cur seconds) in <state>/login_grace.json and returns the bound the
// swap timing uses: the largest of cur, every value observed since the
// agent's own last reload of sshd (max_s), and, until that reload plus
// prev_max_s + 5 s has passed, the maximum observed before it
// (prev_max_s). A value lowered on disk without a reload, and children
// forked before a reload, so keep their longer window. Another boot
// starts afresh. It is called at start, at every apply and by 03-06's
// drift check.
func ObserveLoginGrace(l Layout, clock Clock, stateFd int, cur int) (int, error) {
	e := &engine{l: l, clock: clock, stateFd: stateFd}
	return e.observeLoginGrace(cur, false)
}

func (e *engine) observeLoginGrace(cur int, ownReload bool) (int, error) {
	var st loginGraceState
	if b, err := e.readState(loginGraceFile, 4<<10); err == nil && b != nil {
		if trust.DecodeStrict(b, &st) != nil {
			st = loginGraceState{}
		}
	}
	now := e.clock.Boottime()
	if st.BootID != e.clock.BootID() {
		st = loginGraceState{BootID: e.clock.BootID()}
	}
	prevInForce := st.PrevMaxS > 0 && now < time.Duration(st.OwnReloadBoottime)+time.Duration(st.PrevMaxS+5)*time.Second
	if !prevInForce {
		st.PrevMaxS, st.OwnReloadBoottime = 0, 0
	}
	if ownReload {
		st.PrevMaxS = max(st.PrevMaxS, st.MaxS, cur)
		st.OwnReloadBoottime = int64(now)
		st.MaxS = cur
	}
	st.MaxS = max(st.MaxS, cur)
	bound := max(cur, st.MaxS, st.PrevMaxS)
	b, err := trust.CanonicalJSON(st)
	if err != nil {
		return 0, err
	}
	if old, _ := e.readState(loginGraceFile, 4<<10); string(old) != string(b) {
		if err := e.writeState(loginGraceFile, b); err != nil {
			return 0, err
		}
	}
	return bound, nil
}
