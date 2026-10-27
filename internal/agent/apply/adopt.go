//go:build linux

package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/paths"
	"github.com/Labontese/keyroster/internal/agent/state"
	"github.com/Labontese/keyroster/internal/directory"
	"github.com/Labontese/keyroster/internal/trust"
)

// D-08: a host set up by hand with the Phase 2 runbook (host-setup.md)
// is taken over only when its layout is exactly the runbook's.
const (
	// CodePhase2Adoptable is report only: the preflight sees the exact
	// Phase 2 layout, structurally; apply --once compares it with the
	// signed content and takes it over (PR #57 review).
	CodePhase2Adoptable = "phase2_adoptable"
	// CodePhase2Pending refuses an apply that recognises the layout but
	// may not take it over (Config.AllowAdoption unset: the hardened
	// applier unit cannot remove files in /etc/ssh).
	CodePhase2Pending = "phase2_adoption_pending"
	// CodePhase2Differs refuses a Phase 2 layout that is not exactly the
	// runbook's, or does not match the signed content, listing every
	// difference.
	CodePhase2Differs = "phase2_layout_differs"
)

// Errors of the Phase 2 codes.
var (
	ErrPhase2Pending = errors.New(CodePhase2Pending)
	ErrPhase2Differs = errors.New(CodePhase2Differs)
)

// The runbook's two drop-in lines, and the values sshd -T reports for
// them. They name the real paths: the runbook writes them on the host.
const (
	phase2CALine         = "TrustedUserCAKeys /etc/ssh/keyroster_user_ca.pub"
	phase2PrincipalsLine = "AuthorizedPrincipalsFile /etc/ssh/principals/%u"
	phase2CAValue        = "/etc/ssh/keyroster_user_ca.pub"
	phase2PrincipalsVal  = "/etc/ssh/principals/%u"
)

// adoptCommand is what the operator runs to take a recognised host over.
const adoptCommand = "sudo keyroster-agent apply --once"

// StructuralPhase2 is the structural Phase 2 check (PR #57 review): it
// changes nothing and needs no signed state. present is whether
// 50-keyroster.conf exists; diffs lists every way the host differs from
// the runbook's exact layout, none when it holds it:
//
//   - sshd_config.d/50-keyroster.conf, a regular file, holds exactly the
//     two runbook lines (in either order, nothing else but blank lines);
//   - /etc/ssh/keyroster_user_ca.pub, a regular file, holds one
//     parseable public-key line;
//   - /etc/ssh/principals is a directory owned by the applier's uid
//     (root) and writable by no one else;
//   - no other configuration line sets a trust keyword (hits are
//     trustSettingHits), sshd_config itself included;
//   - sshd -T (base, before the agent's drop-in exists) reports exactly
//     those two values and no revokedkeys.
func StructuralPhase2(l Layout, base Dump, hits []settingHit) (present bool, diffs []string) {
	dropIn := l.Phase2DropIn()
	st, err := os.Lstat(dropIn)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !st.Mode().IsRegular() {
		return true, []string{dropIn + " is not a regular file"}
	}
	b, err := readSmall(dropIn, 64<<10)
	if err != nil {
		return true, []string{dropIn + ": " + err.Error()}
	}
	var got []string
	for _, line := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			got = append(got, t)
		}
	}
	for _, want := range []string{phase2CALine, phase2PrincipalsLine} {
		if !slices.Contains(got, want) {
			diffs = append(diffs, fmt.Sprintf("%s lacks the runbook line %q", dropIn, want))
		}
	}
	for i, t := range got {
		if t != phase2CALine && t != phase2PrincipalsLine {
			diffs = append(diffs, fmt.Sprintf("%s holds %q, which is not one of the runbook's two lines; remove it", dropIn, t))
		} else if slices.Index(got, t) != i {
			diffs = append(diffs, fmt.Sprintf("%s holds %q twice", dropIn, t))
		}
	}
	diffs = append(diffs, structuralCA(l)...)
	diffs = append(diffs, structuralPrincipalsDir(l)...)
	for _, h := range hits {
		if h.File == dropIn && (h.Text == phase2CALine || h.Text == phase2PrincipalsLine) {
			continue
		}
		diffs = append(diffs, fmt.Sprintf("%s:%d sets %q; remove that line (the runbook's layout sets these only in %s)", h.File, h.Line, h.Text, dropIn))
	}
	for k, want := range map[string]string{"trustedusercakeys": phase2CAValue, "authorizedprincipalsfile": phase2PrincipalsVal, "revokedkeys": ""} {
		got := base.One(k)
		if isDefault(want) && isDefault(got) || got == want {
			continue
		}
		diffs = append(diffs, fmt.Sprintf("sshd -T reports %s %q, the runbook's layout gives %q", k, got, map[bool]string{true: "none", false: want}[want == ""]))
	}
	slices.Sort(diffs)
	return true, diffs
}

func structuralCA(l Layout) []string {
	ca := l.Phase2CAFile()
	st, err := os.Lstat(ca)
	if err != nil || !st.Mode().IsRegular() {
		return []string{ca + " is missing or not a regular file"}
	}
	b, err := readSmall(ca, 64<<10)
	if err != nil {
		return []string{ca + ": " + err.Error()}
	}
	var keys []string
	for _, line := range strings.Split(string(b), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			keys = append(keys, t)
		}
	}
	if len(keys) != 1 {
		return []string{fmt.Sprintf("%s holds %d lines; the runbook's file holds one key line", ca, len(keys))}
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(keys[0])); err != nil {
		return []string{ca + " does not hold a parseable public key line"}
	}
	return nil
}

func structuralPrincipalsDir(l Layout) []string {
	dir := l.Phase2PrincipalsDir()
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return []string{dir + " is missing or not a directory"}
	}
	switch {
	case int(st.Uid) != os.Geteuid():
		return []string{fmt.Sprintf("%s is owned by uid %d, not root", dir, st.Uid)}
	case st.Mode&0o022 != 0:
		return []string{fmt.Sprintf("%s is writable by group or others (mode %04o)", dir, st.Mode&0o7777)}
	}
	return nil
}

// AdoptPlan is a recognised Phase 2 layout to take over: the paths to
// remove once the agent's own generation passed its self-test.
type AdoptPlan struct {
	Remove []string `json:"remove"`
}

// headerVersionRE reads the directory version from a principals file's
// second header line (directory.RenderPrincipalsFile).
var headerVersionRE = regexp.MustCompile(`directory version ([0-9]+) sha256`)

// Adopt compares a structurally exact Phase 2 layout with the verified
// signed content (D-08): keyroster_user_ca.pub must hold the bundle's
// active user CA key (its comment is ignored), and every
// /etc/ssh/principals/<account> must be byte-equal to
// directory.RenderPrincipalsFile for this host's host group in the
// verified directory. A file whose principal lines match but whose header
// names another directory version is reported "only the header differs"
// (the host's approval installs a new version, so files rendered before
// it carry the older one). It returns the plan, or every difference.
func Adopt(l Layout, v *state.Verified, hostGroup string) (*AdoptPlan, []string) {
	var diffs []string
	ca := l.Phase2CAFile()
	if b, err := readSmall(ca, 64<<10); err != nil {
		diffs = append(diffs, ca+": "+err.Error())
	} else if pub, _, _, _, err := ssh.ParseAuthorizedKey(bytes.TrimSpace(b)); err != nil {
		diffs = append(diffs, ca+" does not hold a parseable public key line")
	} else if !isActiveUserCA(v.Bundle, pub) {
		diffs = append(diffs, fmt.Sprintf("%s holds %s, which is not the active user CA key of trust bundle version %d; re-run keyroster host ca-key, or let the agent install it fresh (remove the Phase 2 layout by hand)", ca, ssh.FingerprintSHA256(pub), v.Bundle.Version))
	}
	dir := l.Phase2PrincipalsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, append(diffs, dir+": "+err.Error())
	}
	plan := &AdoptPlan{Remove: []string{l.Phase2DropIn(), ca}}
	for _, en := range entries {
		name := en.Name()
		p := filepath.Join(dir, name)
		if !en.Type().IsRegular() {
			diffs = append(diffs, p+" is not a regular file")
			continue
		}
		want, err := directory.RenderPrincipalsFile(v.Directory, hostGroup, name)
		if err != nil {
			diffs = append(diffs, fmt.Sprintf("%s: %v", p, err))
			continue
		}
		got, err := readSmall(p, maxPrincipalsFile+1)
		if err != nil {
			diffs = append(diffs, p+": "+err.Error())
			continue
		}
		if !bytes.Equal(got, want) {
			diffs = append(diffs, principalsDiff(p, hostGroup, name, got, want, v.Directory.Version))
			continue
		}
		plan.Remove = append(plan.Remove, p)
	}
	if len(diffs) > 0 {
		return nil, diffs
	}
	plan.Remove = append(plan.Remove, dir)
	return plan, nil
}

// principalsDiff says how a hand-rendered principals file differs from
// what the verified directory renders.
func principalsDiff(path, group, account string, got, want []byte, version uint64) string {
	rerender := fmt.Sprintf("re-render it with keyroster host principals %s %s", group, account)
	if slices.Equal(principalSet(got), principalSet(want)) {
		fileVersion := "an unknown version"
		if m := headerVersionRE.FindSubmatch(got); m != nil {
			fileVersion = "directory version " + string(m[1])
		}
		return fmt.Sprintf("%s: only the header differs (the file names %s, the agent's verified directory is version %d); %s", path, fileVersion, version, rerender)
	}
	return fmt.Sprintf("%s: its principal lines (%s) differ from directory version %d's (%s); %s, or run keyroster-agent apply --dry-run to see what the agent would install",
		path, strings.Join(principalSet(got), " "), version, strings.Join(principalSet(want), " "), rerender)
}

// principalSet is a principals file's non-comment lines, sorted.
func principalSet(b []byte) []string {
	var out []string
	for _, l := range lines(b) {
		if k, ok := principalLine(l); ok {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// isActiveUserCA reports whether pub is the bundle's active user CA key.
func isActiveUserCA(b *trust.Bundle, pub ssh.PublicKey) bool {
	for _, c := range b.CAs {
		if c.Role != trust.RoleUser || c.State != "active" {
			continue
		}
		if k, err := trust.ParseKey(c.Key); err == nil && bytes.Equal(k.Marshal(), pub.Marshal()) {
			return true
		}
	}
	return false
}

// phase2Findings is the Phase 2 part of a preflight: with the layout
// present and structurally exact, phase2_adoptable (report only);
// present otherwise, one foreign_trust_setting per difference. It
// reports whether the layout is present, so foreignFindings does not
// report the runbook's own lines twice.
func phase2Findings(l Layout, base Dump, hits []settingHit, r *PreflightReport) bool {
	present, diffs := StructuralPhase2(l, base, hits)
	if !present {
		return false
	}
	if len(diffs) == 0 {
		r.add(Finding{Code: CodePhase2Adoptable, File: l.Phase2DropIn(),
			Message: "this host holds the Phase 2 runbook's exact layout; the agent takes it over once the host is approved and its principals files are re-rendered",
			Fix:     "after enrollment: approve the host, re-render every principals file with keyroster host principals <group> <account>, then run " + adoptCommand + " (host-setup.md \"Moving a Phase 2 host to the agent\")"})
		return true
	}
	for _, d := range diffs {
		r.add(Finding{Code: CodeForeignTrust, File: l.Phase2DropIn(), Message: "a Phase 2 style layout that is not the runbook's exact one: " + d,
			Fix: "make the layout exactly the runbook's (host-setup.md \"Moving a Phase 2 host to the agent\"), or remove it; the agent takes over only the exact layout"})
	}
	return true
}

// adoptDecision is the Phase 2 part of an apply's preflight on a first
// install: nil with no Phase 2 layout; phase2_layout_differs for a layout
// that is not exact or not the signed content; phase2_adoption_pending
// when it is but adoption is not allowed; the plan otherwise.
func (e *engine) adoptDecision(v *state.Verified, g *Generation, hits []settingHit) (*AdoptPlan, *Finding) {
	present, diffs := StructuralPhase2(e.l, e.dump, hits)
	if !present {
		return nil, nil
	}
	if len(diffs) == 0 {
		group := ""
		if h, ok := v.Directory.HostByName(g.Host); ok {
			group = h.HostGroup
		}
		var plan *AdoptPlan
		if plan, diffs = Adopt(e.l, v, group); len(diffs) == 0 {
			if !e.cfg.AllowAdoption {
				return nil, &Finding{Code: CodePhase2Pending, File: e.l.Phase2DropIn(),
					Message: "this host holds the Phase 2 runbook's exact layout, and it matches the signed state; this applier may not take it over (its unit cannot remove files in /etc/ssh); nothing was written or removed",
					Fix:     "run " + adoptCommand + " once from a root shell"}
			}
			return plan, nil
		}
	}
	return nil, &Finding{Code: CodePhase2Differs, File: e.l.Phase2DropIn(),
		Message: "the Phase 2 layout is not the runbook's exact one, or does not match the signed state: " + strings.Join(diffs, "; "),
		Fix:     "fix each difference listed (host-setup.md \"Moving a Phase 2 host to the agent\"); the agent takes over only the exact layout"}
}

// adoptFile is <state>/phase2-adopt.json: the plan of a takeover in
// progress, written before the first install and removed once every path
// is gone, so a crash at any point resumes the removal (or, before the
// first install committed, is undone with it).
const (
	adoptFile = "phase2-adopt.json"
	adoptBak  = "phase2"
)

func (e *engine) writeAdopt(p *AdoptPlan) error {
	b, err := trust.CanonicalJSON(p)
	if err != nil {
		return err
	}
	return e.writeState(adoptFile, b)
}

func (e *engine) readAdopt() (*AdoptPlan, error) {
	b, err := e.readState(adoptFile, 1<<20)
	if err != nil || b == nil {
		return nil, err
	}
	var p AdoptPlan
	if err := trust.DecodeStrict(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", adoptFile, err)
	}
	return &p, nil
}

// finishAdoption removes the Phase 2 paths of a takeover in progress, once
// the agent's generation is last-good (its self-test passed and the
// commit is durable): each file is first copied to <state>/phase2/,
// removed, and the principals directory removed last, which fails if
// anything was added to it. Then sshd -t, and sshd -T and -C must still
// report the agent's values, and the copies and the plan go. A failure
// leaves the plan and the copies for the next run and the operator; the
// paths are never written back.
func (e *engine) finishAdoption(ctx context.Context) error {
	p, err := e.readAdopt()
	if err != nil || p == nil {
		return err
	}
	if err := e.mkdir(e.l.State(adoptBak), 0o700); err != nil {
		return err
	}
	for _, path := range p.Remove {
		if err := e.backupPhase2(path); err != nil {
			return err
		}
	}
	for _, path := range p.Remove {
		if err := e.fault("phase2-remove"); err != nil {
			return err
		}
		if err := e.removePhase2(path); err != nil {
			return fmt.Errorf("removing the Phase 2 layout: %w (copies are in %s)", err, e.l.State(adoptBak))
		}
		e.report.Phase2Removed = append(e.report.Phase2Removed, path)
	}
	if err := e.fault("phase2-removed"); err != nil {
		return err
	}
	if err := e.sshdTest(ctx); err != nil {
		return fmt.Errorf("%w (after removing the Phase 2 layout; copies are in %s)", err, e.l.State(adoptBak))
	}
	dump, err := e.sshdDump(ctx, "")
	if err != nil {
		return err
	}
	if err := e.checkDropInEffective(ctx, dump); err != nil {
		return err
	}
	if err := e.removeAll(e.l.State(adoptBak)); err != nil {
		return err
	}
	return e.remove(e.l.State(adoptFile))
}

// backupPhase2 copies a Phase 2 file into <state>/phase2/ (a directory is
// not copied; a path already gone is skipped).
func (e *engine) backupPhase2(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) || err == nil && st.IsDir() {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	b, err := readSmall(path, 1<<20)
	if err != nil {
		return err
	}
	name := strings.ReplaceAll(strings.TrimPrefix(path, e.l.Root), "/", "_")
	return e.writeFile(e.l.State(adoptBak), name, b, 0o600)
}

// removePhase2 removes one path of the Phase 2 layout, a file or the empty
// principals directory, through the removal-only allowlist, and fsyncs the
// directory that held it. A resumed removal finds paths an earlier run
// removed already, and their directory too when that run got as far as
// the principals directory (PR #68 review, F14): the fsync then goes to
// the nearest directory that still exists, up to <root>/etc/ssh, so the
// earlier run's removals are durable before the plan goes.
func (e *engine) removePhase2(path string) error {
	if err := paths.AllowedRemoval(e.l, path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stop := filepath.Join(e.l.Root, "etc", "ssh")
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		err := fsyncDir(dir)
		if !errors.Is(err, unix.ENOENT) || dir == stop || dir == filepath.Dir(dir) {
			return err
		}
	}
}
