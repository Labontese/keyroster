//go:build linux

package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/spool"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

// Preflight codes (03-06, D-07). Each Finding carries one; Refusal is set
// for every code but the report-only ones (ReportOnly). The set is open:
// 03-10 adds its probe-account codes.
const (
	CodeSSHKeygenMissing    = "ssh_keygen_missing"
	CodeNoDropInDir         = "no_dropin_dir"
	CodeForeignTrust        = "foreign_trust_setting"
	CodeNoLoopbackListener  = "no_loopback_listener"
	CodeAccountExcluded     = "account_excluded"
	CodeRHEL8               = "rhel8_unsupported"
	CodeFIPS                = "fips_unsupported"
	CodeHostPoPNotEnabled   = "host_pop_not_enabled"
	CodeLoginGraceUnbounded = "login_grace_unbounded"
	CodeLoginGraceUnknown   = "login_grace_unknown"
)

// Preflight refusals as errors, for errors.Is on an apply refused by its
// preflight (PreflightError). ErrNoDropInDir, ErrNoLoopbackListener and
// the login-grace errors are 03-05's.
var (
	ErrSSHKeygenMissing  = errors.New(CodeSSHKeygenMissing)
	ErrForeignTrust      = errors.New(CodeForeignTrust)
	ErrRHEL8             = errors.New(CodeRHEL8)
	ErrFIPS              = errors.New(CodeFIPS)
	ErrHostPoPNotEnabled = errors.New(CodeHostPoPNotEnabled)
)

// codeErrors maps each refusal code to its error.
var codeErrors = map[string]error{
	CodeSSHKeygenMissing:    ErrSSHKeygenMissing,
	CodeNoDropInDir:         ErrNoDropInDir,
	CodeForeignTrust:        ErrForeignTrust,
	CodeNoLoopbackListener:  ErrNoLoopbackListener,
	CodeRHEL8:               ErrRHEL8,
	CodeFIPS:                ErrFIPS,
	CodeHostPoPNotEnabled:   ErrHostPoPNotEnabled,
	CodeLoginGraceUnbounded: ErrLoginGraceUnbounded,
	CodeLoginGraceUnknown:   ErrLoginGraceUnknown,
	CodePhase2Pending:       ErrPhase2Pending,
	CodePhase2Differs:       ErrPhase2Differs,
}

// ReportOnly are the codes that never refuse: keyroster-agent preflight
// exits 0 with only these (03-16's enrollment gate relies on it).
var ReportOnly = []string{CodeAccountExcluded, CodePhase2Adoptable}

// Finding is one preflight result: a stable code, what was found and how
// to fix it, and where (a file and line, or an account) when known.
type Finding struct {
	Code    string `json:"code"`
	Refusal bool   `json:"refusal"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Account string `json:"account,omitempty"`
}

// PreflightReport is keyroster-agent preflight's output.
type PreflightReport struct {
	SSHD       string    `json:"sshd"`
	SSHDConfig string    `json:"sshd_config"`
	Findings   []Finding `json:"findings"`
	// Notes are facts that are not findings: no verified state yet, so
	// the policy and account checks did not run.
	Notes []string `json:"notes,omitempty"`
}

// Refused reports whether any finding refuses the host.
func (r *PreflightReport) Refused() bool {
	return slices.ContainsFunc(r.Findings, func(f Finding) bool { return f.Refusal })
}

func (r *PreflightReport) add(f Finding) {
	f.Refusal = !slices.Contains(ReportOnly, f.Code)
	r.Findings = append(r.Findings, f)
}

// PreflightError is an apply refused by its preflight: every refusal
// finding, each matched by errors.Is through its code's error.
type PreflightError struct {
	Findings []Finding
}

func (p *PreflightError) Error() string {
	var parts []string
	for _, f := range p.Findings {
		s := f.Code + ": " + f.Message
		if f.Fix != "" {
			s += " Fix: " + f.Fix
		}
		parts = append(parts, s)
	}
	return "preflight refused: " + strings.Join(parts, "; ")
}

// Unwrap returns the error of each refusal code.
func (p *PreflightError) Unwrap() []error {
	var out []error
	for _, f := range p.Findings {
		if err, ok := codeErrors[f.Code]; ok {
			out = append(out, err)
		}
	}
	return out
}

// dropInHeader heads the agent's drop-in; trialHeader heads the trial
// copy the preflight writes and removes, so a trial left by a crash never
// passes for the agent's drop-in (writeDropIn then writes and activates
// the real one; Preflight and every apply remove a leftover trial).
const (
	dropInHeader = "# keyroster: managed by keyroster-agent; do not edit\n"
	trialHeader  = "# keyroster: preflight trial by keyroster-agent; removed when the preflight ends\n"
)

// trialDropIn is the trial drop-in: DropIn's TrustedUserCAKeys and
// AuthorizedPrincipalsFile lines under trialHeader. It sets no
// RevokedKeys: sshd treats every public key as revoked while its
// RevokedKeys file is missing, so an sshd reloaded by something else in
// the moment the trial exists would refuse every key until its next
// reload; without that line such a reload refuses only certificate logins
// (Threat Flags, 03-06 SUMMARY). The two keywords show the drop-in's
// precedence as well as three would: sshd keeps the first value of each.
func trialDropIn(l Layout) []byte {
	cur := l.Current()
	return []byte(trialHeader +
		"TrustedUserCAKeys " + filepath.Join(cur, CAFile) + "\n" +
		"AuthorizedPrincipalsFile " + filepath.Join(cur, PrincipalsDir, "%u") + "\n")
}

// trialKeywords are the keywords the trial drop-in sets.
var trialKeywords = []string{"trustedusercakeys", "authorizedprincipalsfile"}

// isDefault reports whether an sshd -T value of a trust keyword is unset:
// "none", or no line at all (OpenSSH 10.3 and later print no revokedkeys
// line when it is unset; seen on Alpine and Arch).
func isDefault(v string) bool { return v == "" || v == "none" }

// settingHit is one line of an sshd configuration file that sets a trust
// keyword.
type settingHit struct {
	File    string
	Line    int
	Keyword string
	Text    string
}

// trustSettingHits greps the sshd configuration files for lines that set
// TrustedUserCAKeys, RevokedKeys or AuthorizedPrincipalsFile, in any case
// and inside Match blocks too: config (the service's sshd_config) and
// every <root>/etc/ssh/sshd_config.d/*.conf but the agent's own drop-in.
// It only reads. A file it cannot read is skipped (sshd -T still shows
// its effect).
func trustSettingHits(l Layout, config string) []settingHit {
	files := []string{config}
	if m, err := filepath.Glob(filepath.Join(l.DropInDir(), "*.conf")); err == nil {
		sort.Strings(m)
		for _, f := range m {
			if f != l.DropIn() {
				files = append(files, f)
			}
		}
	}
	var hits []settingHit
	for _, f := range files {
		b, err := readSmall(f, 1<<20)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			words := strings.FieldsFunc(t, func(r rune) bool { return r == ' ' || r == '\t' || r == '=' })
			if len(words) == 0 {
				continue
			}
			if k := strings.ToLower(words[0]); slices.Contains(trustKeywords, k) {
				hits = append(hits, settingHit{File: f, Line: i + 1, Keyword: k, Text: t})
			}
		}
	}
	return hits
}

// readSmall reads at most limit bytes of a file, following symlinks (a
// configuration file sshd itself reads that way).
func readSmall(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: an sshd configuration file or a system file, read-only
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit))
}

// rhel8RE is /etc/redhat-release of a RHEL 8 compatible release.
var rhel8RE = regexp.MustCompile(`release 8(\.|\s|$)`)

// platformFindings are D-18's exclusions: RHEL 8 (no sshd_config.d in
// its OpenSSH 8.0) and FIPS mode (FIPS rejects Ed25519 CAs).
func platformFindings(l Layout, r *PreflightReport) {
	if b, err := readSmall(filepath.Join(l.Root, "etc", "redhat-release"), 4<<10); err == nil && rhel8RE.Match(b) {
		r.add(Finding{Code: CodeRHEL8, Message: "this host runs a RHEL 8 compatible release (" + strings.TrimSpace(string(b)) + "): its OpenSSH has no sshd_config.d, so the agent's settings cannot take effect without editing sshd_config.",
			Fix: "move the host to RHEL 9 or later (or Alma or Rocky 9 or later); see host-setup.md \"Not supported\"", File: filepath.Join(l.Root, "etc", "redhat-release")})
	}
	if b, err := readSmall(filepath.Join(l.Root, "proc", "sys", "crypto", "fips_enabled"), 64); err == nil && strings.TrimSpace(string(b)) == "1" {
		r.add(Finding{Code: CodeFIPS, Message: "the kernel runs in FIPS mode, whose OpenSSH rejects the Ed25519 CA keys keyroster signs with.",
			Fix: "run the host without FIPS mode; see host-setup.md \"Not supported\"", File: filepath.Join(l.Root, "proc", "sys", "crypto", "fips_enabled")})
	}
}

// dumpFindings are the checks of one sshd -T dump: LoginGraceTime and a
// loopback listener.
func dumpFindings(d Dump, r *PreflightReport) {
	// login_grace_unbounded and login_grace_unknown: 03-05's one check,
	// d.LoginGrace() (Dump.LoginGrace in sshd.go), never a second parser.
	if _, err := d.LoginGrace(); err != nil {
		code := CodeLoginGraceUnknown
		if errors.Is(err, ErrLoginGraceUnbounded) {
			code = CodeLoginGraceUnbounded
		}
		r.add(Finding{Code: code, Message: err.Error(),
			Fix: "set LoginGraceTime to a bounded value in sshd_config, for example the default 120; the agent never edits sshd_config, and its two-step swap waits that long plus 30 s before additions take effect"})
	}
	if _, err := loopbackTargets(d); err != nil {
		r.add(Finding{Code: CodeNoLoopbackListener, Message: err.Error(),
			Fix: "add ListenAddress 127.0.0.1 to sshd_config beside the existing ListenAddress lines (the agent self-tests sshd over loopback only, the owner's D-05 answer, and never edits sshd_config)"})
	}
}

// foreignFindings reports trust settings the agent does not own: every
// configuration line that sets one of its keywords outside its drop-in,
// and, with base the sshd -T dump, every keyword whose effective value is
// neither unset nor the agent's. hits are trustSettingHits.
func foreignFindings(l Layout, base Dump, hits []settingHit, r *PreflightReport) {
	named := map[string]bool{}
	for _, h := range hits {
		named[h.Keyword] = true
		r.add(Finding{Code: CodeForeignTrust, File: h.File, Line: h.Line,
			Message: fmt.Sprintf("%s:%d sets %q; the agent never merges with or overrides another trust setting", h.File, h.Line, h.Text),
			Fix:     "remove or comment out that line (the agent never edits sshd configuration files it does not own); a host set up with the Phase 2 runbook's exact layout is taken over instead, see host-setup.md"})
	}
	want := ourValues(l)
	for _, k := range trustKeywords {
		if v := base.One(k); !isDefault(v) && v != want[k] && !named[k] {
			r.add(Finding{Code: CodeForeignTrust,
				Message: fmt.Sprintf("sshd -T reports %s %q, set outside sshd_config and sshd_config.d (an Include elsewhere)", k, v),
				Fix:     "find and remove that setting: sudo grep -rniE '^\\s*" + k + "' /etc/ssh"})
		}
	}
}

// Preflight checks whether this host can be managed safely (03-06,
// D-07), before enrollment and on every run of keyroster-agent
// preflight. It changes nothing on the host but a trial copy of the
// drop-in, written only while no drop-in exists and removed before it
// returns, with no reload: sshd -T with the trial shows whether
// sshd_config.d is read before every other trust setting. With a state
// directory it takes the apply lock without waiting (an apply in progress
// is a tool error: run again), and the verified policy and directory, when
// there are any, add host_pop_not_enabled and account_excluded.
//
// An error is a usage or tool error (exit 2): an sshd that cannot run,
// sshd -T failing. Refusals are findings.
func Preflight(ctx context.Context, cfg Config, l Layout) (*PreflightReport, error) {
	if cfg.Exec == nil {
		cfg.Exec = execsite.ExecRunner{}
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	r := &PreflightReport{SSHD: cfg.SSHD, SSHDConfig: cfg.SSHDConfig, Findings: []Finding{}}
	e := &engine{cfg: cfg, l: l, clock: cfg.Clock, report: &Report{Errors: []string{}}, stateFd: -1}
	defer func() {
		if e.stateFd >= 0 {
			_ = unix.Close(e.stateFd)
		}
	}()
	for _, p := range []string{cfg.SSHD, cfg.SSHDConfig, cfg.SSHKeygen, l.Root, l.StateDir} {
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("%w: %q is not an absolute path", ErrConfig, p)
		}
	}
	if st, err := os.Stat(cfg.SSHD); err != nil {
		return nil, fmt.Errorf("%w: sshd %s: %w", ErrConfig, cfg.SSHD, err)
	} else if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: sshd %s is not a regular file", ErrConfig, cfg.SSHD)
	}
	if st, err := os.Stat(cfg.SSHKeygen); err != nil || !st.Mode().IsRegular() {
		r.add(Finding{Code: CodeSSHKeygenMissing, File: cfg.SSHKeygen, Message: "there is no ssh-keygen at " + cfg.SSHKeygen + "; the agent checks every CA line and KRL with the host's own ssh-keygen before installing it",
			Fix: "install the distribution's ssh-keygen (openssh-client, openssh-clients or openssh-keygen), or pass --ssh-keygen"})
	}
	platformFindings(l, r)
	unlock, err := e.preflightLock(l)
	if err != nil {
		return nil, err
	}
	defer unlock()
	base, err := e.sshdDump(ctx, "")
	if err != nil {
		return nil, err
	}
	dumpFindings(base, r)
	existing, err := e.readDropIn()
	if err != nil {
		return nil, err
	}
	if existing != nil && bytes.Equal(existing, trialDropIn(l)) {
		// A trial a crashed preflight left: never in force (no reload), and
		// pointing at files that may not exist, so it goes now.
		if err := e.removeTrial(); err != nil {
			return nil, err
		}
		existing = nil
		r.Notes = append(r.Notes, "removed a trial drop-in an earlier preflight left behind")
		if base, err = e.sshdDump(ctx, ""); err != nil {
			return nil, err
		}
	}
	hits := trustSettingHits(l, cfg.SSHDConfig)
	switch {
	case existing != nil && !bytes.Equal(existing, DropIn(l)):
		r.add(Finding{Code: CodeForeignTrust, File: l.DropIn(), Message: l.DropIn() + " exists and is not the agent's drop-in",
			Fix: "move it away; the agent owns that file name"})
	case existing != nil:
		// The agent's own drop-in: its values must be in force. The Phase 2
		// runbook's own two lines in 50-keyroster.conf, left by a takeover
		// whose removal is unfinished, are shadowed by it (00- is read
		// first, and sshd -T shows the agent's values).
		var rest []settingHit
		for _, h := range hits {
			if h.File == l.Phase2DropIn() && (h.Text == phase2CALine || h.Text == phase2PrincipalsLine) {
				continue
			}
			rest = append(rest, h)
		}
		if len(rest) < len(hits) {
			r.Notes = append(r.Notes, "the Phase 2 layout is still present beside the agent's drop-in; "+adoptCommand+" removes it")
		}
		foreignFindings(l, base, rest, r)
	default:
		if !phase2Findings(l, base, hits, r) {
			foreignFindings(l, base, hits, r)
		}
		if err := e.trialFindings(ctx, base, r); err != nil {
			return nil, err
		}
	}
	v, note := e.preflightState()
	if note != "" {
		r.Notes = append(r.Notes, note)
	}
	if v != nil {
		policyFindings(v.Policy, r)
		keys, err := hostKeys(base)
		if err != nil {
			return nil, err
		}
		if err := e.accountFindings(ctx, base, accountsForHost(v.Directory, keys), r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// preflightApply is the preflight of an apply (03-06 key link: the first
// apply, and every drop-in change, runs it before any write or reload):
// the same checks as Preflight but the trial write, because the apply's
// own drop-in write is followed by sshd -t and the sshd -T checks of
// activateDropIn. It runs only when there is no last-good yet or the
// drop-in would change, removes a trial drop-in a crashed preflight left,
// and refuses with a PreflightError on any refusal code. 03-05's own
// login_grace_unbounded check at the start of every apply stays.
//
// On a first install it also decides a Phase 2 takeover (D-08,
// adoptDecision): the exact layout, matching the signed state g was
// rendered from, sets e.adopt when Config.AllowAdoption is set and is
// phase2_adoption_pending otherwise; any other Phase 2 style layout is
// phase2_layout_differs.
func (e *engine) preflightApply(ctx context.Context, v *state.Verified, g *Generation) error {
	lg, err := e.resolveLink(e.l.LastGood())
	if err != nil {
		return err
	}
	old, err := e.readDropIn()
	if err != nil {
		return err
	}
	if lg.kind != linkNone && bytes.Equal(old, DropIn(e.l)) {
		return nil
	}
	if old != nil && bytes.Equal(old, trialDropIn(e.l)) {
		if !e.cfg.DryRun {
			if err := e.removeTrial(); err != nil {
				return err
			}
			// The start-of-run sshd -T saw the trial: read it again.
			if e.dump, err = e.sshdDump(ctx, ""); err != nil {
				return err
			}
		}
		old = nil
	}
	r := &PreflightReport{}
	if st, err := os.Stat(e.cfg.SSHKeygen); err != nil || !st.Mode().IsRegular() {
		r.add(Finding{Code: CodeSSHKeygenMissing, File: e.cfg.SSHKeygen, Message: "there is no ssh-keygen at " + e.cfg.SSHKeygen})
	}
	platformFindings(e.l, r)
	dumpFindings(e.dump, r)
	hits := trustSettingHits(e.l, e.cfg.SSHDConfig)
	switch {
	case old == nil && lg.kind == linkNone:
		plan, f := e.adoptDecision(v, g, hits)
		switch {
		case f != nil:
			r.add(*f)
		case plan != nil:
			e.adopt = plan
		default:
			foreignFindings(e.l, e.dump, hits, r)
		}
	case old == nil || bytes.Equal(old, DropIn(e.l)):
		foreignFindings(e.l, e.dump, hits, r)
	default:
		r.add(Finding{Code: CodeForeignTrust, File: e.l.DropIn(), Message: e.l.DropIn() + " exists and is not the agent's drop-in", Fix: "move it away; the agent owns that file name"})
	}
	policyFindings(v.Policy, r)
	var refusals []Finding
	for _, f := range r.Findings {
		if f.Refusal {
			refusals = append(refusals, f)
		}
	}
	if len(refusals) > 0 {
		return &PreflightError{Findings: refusals}
	}
	return nil
}

// preflightLock takes the apply lock without waiting when a state
// directory exists, so the trial drop-in never races an apply's real one.
// No state directory means no applier can run yet.
func (e *engine) preflightLock(l Layout) (func(), error) {
	if _, err := os.Lstat(l.StateDir); errors.Is(err, os.ErrNotExist) {
		return func() {}, nil
	}
	if err := checkOwnDir(l.StateDir); err != nil {
		return nil, err
	}
	fd, err := spool.OpenDir(l.StateDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateDirUnsafe, err)
	}
	e.stateFd = fd
	unlock, held, err := e.tryLock()
	if err != nil {
		return nil, err
	}
	if held {
		return nil, fmt.Errorf("an apply holds %s; run the preflight again when it has finished", l.State(lockFile))
	}
	return unlock, nil
}

// tryLock takes the apply lock without waiting; held reports that another
// run holds it.
func (e *engine) tryLock() (unlock func(), held bool, err error) {
	if err := paths.Allowed(e.l, e.l.State(lockFile)); err != nil {
		return nil, false, err
	}
	fd, err := unix.Openat(e.stateFd, lockFile, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %s: %w", ErrStateDirUnsafe, lockFile, err)
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if errors.Is(err, unix.EWOULDBLOCK) {
		_ = unix.Close(fd)
		return nil, true, nil
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, false, fmt.Errorf("lock %s: %w", lockFile, err)
	}
	return func() { _ = unix.Close(fd) }, false, nil
}

// writeTrial writes the trial drop-in (no reload follows).
func (e *engine) writeTrial() error {
	if st, err := os.Lstat(e.l.DropInDir()); err != nil || !st.IsDir() {
		return ErrNoDropInDir
	}
	if err := paths.Allowed(e.l, e.l.DropIn()); err != nil {
		return err
	}
	return e.writeFile(e.l.DropInDir(), paths.DropInName, trialDropIn(e.l), 0o644)
}

// removeTrial removes the drop-in file only while it holds exactly the
// trial bytes.
func (e *engine) removeTrial() error {
	b, err := e.readDropIn()
	if err != nil || !bytes.Equal(b, trialDropIn(e.l)) {
		return err
	}
	if err := paths.Allowed(e.l, e.l.DropIn()); err != nil {
		return err
	}
	if err := os.Remove(e.l.DropIn()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fsyncDir(e.l.DropInDir())
}

// trialFindings writes the trial drop-in, reads sshd -T, and removes it:
// a keyword the trial does not set although nothing else did (base
// reports it unset) means sshd does not read sshd_config.d/00-keyroster.conf
// before its other settings (no Include, or one after them):
// no_dropin_dir. A keyword another file sets first is foreignFindings'.
func (e *engine) trialFindings(ctx context.Context, base Dump, r *PreflightReport) error {
	if st, err := os.Lstat(e.l.DropInDir()); err != nil || !st.IsDir() {
		r.add(Finding{Code: CodeNoDropInDir, File: e.l.DropInDir(), Message: e.l.DropInDir() + " is not a directory; the agent writes only its own drop-in there and never creates sshd configuration directories or edits sshd_config",
			Fix: "use a distribution whose sshd reads sshd_config.d (see host-setup.md \"Supported platforms\"), or create the directory and add Include /etc/ssh/sshd_config.d/*.conf as the first line of sshd_config"})
		return nil
	}
	if err := e.writeTrial(); err != nil {
		return err
	}
	trial, derr := e.sshdDump(ctx, "")
	if err := e.removeTrial(); err != nil {
		return errors.Join(derr, err)
	}
	if derr != nil {
		return derr
	}
	want := ourValues(e.l)
	var unread []string
	for _, k := range trialKeywords {
		if trial.One(k) != want[k] && isDefault(base.One(k)) {
			unread = append(unread, k)
		}
	}
	if len(unread) > 0 {
		r.add(Finding{Code: CodeNoDropInDir, File: e.cfg.SSHDConfig,
			Message: fmt.Sprintf("with a trial %s, sshd -T still reports %s unset: sshd does not read sshd_config.d/*.conf before its other settings", e.l.DropIn(), strings.Join(unread, ", ")),
			Fix:     "add Include /etc/ssh/sshd_config.d/*.conf as the first line of sshd_config (Debian and Ubuntu ship it there); the agent never edits sshd_config"})
	}
	return nil
}

// policyFindings: host_pop_not_enabled when the verified, pinned policy
// has no pop.hosts (owner decision REVIEWS L1488@af84cd5).
func policyFindings(p *trust.Policy, r *PreflightReport) {
	if p == nil {
		return
	}
	if p.PoP == nil || !p.PoP.Hosts {
		r.add(Finding{Code: CodeHostPoPNotEnabled, Message: fmt.Sprintf("the verified policy version %d does not set pop.hosts; host agents require it", p.Version),
			Fix: "sign a successor policy with pop.hosts in a root ceremony (keyroster root successor-policy --pop-hosts, then keyroster root sign --prev); pop.hosts can never be turned off again"})
	}
}

// preflightState is the verified state the preflight can see without
// changing it: the pins, accepted/ and the spool, verified as an apply
// would. No pins, or nothing verifiable yet, is a note, not a finding (a
// host before enrollment).
func (e *engine) preflightState() (*state.Verified, string) {
	if e.stateFd < 0 {
		return nil, "no state directory: the policy and account checks run once the host is enrolled"
	}
	pins, err := state.LoadPins(e.stateFd)
	if errors.Is(err, unix.ENOENT) {
		return nil, "no pins.json yet: the policy and account checks run once the host is enrolled"
	}
	if err != nil {
		return nil, "pins.json: " + err.Error()
	}
	var stored *state.Stored
	if fd, err := spool.OpenDir(e.l.State(state.AcceptedDir)); err == nil {
		stored, err = state.LoadStored(fd)
		_ = unix.Close(fd)
		if err != nil {
			return nil, "accepted state: " + err.Error()
		}
	}
	capture := spool.State{}
	if e.cfg.Spool != "" {
		if st, _, err := spool.Read(e.cfg.Spool, stored.Floor()); err == nil {
			capture = st
		} else if !errors.Is(err, unix.ENOENT) {
			return nil, "spool: " + err.Error()
		}
	}
	v, err := state.Verify(pins, stored, capture)
	if errors.Is(err, state.ErrNoBundle) {
		return nil, "no trust bundle received yet: the policy and account checks run once one is"
	}
	if err != nil {
		return nil, "the signed state does not verify yet: " + err.Error()
	}
	return v, ""
}

// accountsForHost is the accounts of the host group of the one active
// host entry the host keys name, sorted; none when the directory names no
// such entry.
func accountsForHost(d *directory.Directory, keys []ssh.PublicKey) []string {
	if d == nil {
		return nil
	}
	hosts := hostsForKeys(d, keys)
	if len(hosts) != 1 || hosts[0].Status != directory.StatusActive {
		return nil
	}
	var out []string
	for _, g := range d.HostGroups {
		if g.Name == hosts[0].HostGroup {
			for _, a := range g.Accounts {
				out = append(out, a.Account)
			}
		}
	}
	sort.Strings(out)
	return out
}

// accountFindings evaluates AllowUsers, AllowGroups, DenyUsers and
// DenyGroups for each managed account with sshd -T -C (so a Match block
// that sets them applies) and sshd's pattern rules (exclusion.go):
// account_excluded, report only. The agent never edits them.
func (e *engine) accountFindings(ctx context.Context, base Dump, accounts []string, r *PreflightReport) error {
	if len(accounts) == 0 {
		return nil
	}
	laddr, lport, err := firstLoopback(base)
	if err != nil {
		return nil // no_loopback_listener is reported already
	}
	for _, a := range accounts {
		d, err := e.sshdDump(ctx, accountSpec(a, laddr, lport))
		if err != nil {
			return err
		}
		if why := Excluded(d, a, e.l.Root); why != "" {
			r.add(Finding{Code: CodeAccountExcluded, Account: a, Message: "account " + a + ": " + why,
				Fix: "change AllowUsers, AllowGroups, DenyUsers or DenyGroups by hand if " + a + " should log in with certificates; the agent never edits them"})
		}
	}
	return nil
}
