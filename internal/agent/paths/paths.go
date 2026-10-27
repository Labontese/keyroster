// Package paths is the keyroster agent's on-disk layout and the allowlist
// of everything the root applier may write (D-07): the keyroster tree
// under <root>/etc/ssh/keyroster/, the one sshd drop-in
// <root>/etc/ssh/sshd_config.d/00-keyroster.conf and the applier's own
// state directory. Every write in internal/agent goes through Allowed
// first, and TestPaths checks that statically. ExecSites lists the only
// programs the applier runs, with their fixed argument shapes.
package paths

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrNotAllowed is a write outside the applier's allowlist.
var ErrNotAllowed = errors.New("path_not_allowed")

// DropInName is the file name of the agent's sshd drop-in.
const DropInName = "00-keyroster.conf"

// Layout is where one agent keeps its files. Root is "/" in production
// (tests use a temporary directory); StateDir is the applier's state
// directory, /var/lib/keyroster-agent in production.
type Layout struct {
	Root     string
	StateDir string
}

// KeyrosterDir is <root>/etc/ssh/keyroster, the tree that holds every
// generation and the current and last-good links.
func (l Layout) KeyrosterDir() string { return filepath.Join(l.Root, "etc", "ssh", "keyroster") }

// GenDir is <root>/etc/ssh/keyroster/gen.
func (l Layout) GenDir() string { return filepath.Join(l.KeyrosterDir(), "gen") }

// Gen is the directory of generation n.
func (l Layout) Gen(n uint64) string { return filepath.Join(l.GenDir(), strconv.FormatUint(n, 10)) }

// GenLink is the relative symlink target that names generation n, as
// current and last-good hold it.
func GenLink(n uint64) string { return "gen/" + strconv.FormatUint(n, 10) }

// ParseGenLink returns the generation a link target names: exactly
// "gen/<N>" with N a decimal number from 1 without leading zeros.
func ParseGenLink(target string) (uint64, bool) {
	s, ok := strings.CutPrefix(target, "gen/")
	if !ok || s == "" || s[0] == '0' || len(s) > 19 {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	return n, true
}

// Current is the link sshd reads through (the drop-in names
// current/user_ca_keys, current/revoked.krl and current/principals/%u).
func (l Layout) Current() string { return filepath.Join(l.KeyrosterDir(), "current") }

// LastGood is the link to the last generation that passed its self-test.
func (l Layout) LastGood() string { return filepath.Join(l.KeyrosterDir(), "last-good") }

// DropInDir is <root>/etc/ssh/sshd_config.d.
func (l Layout) DropInDir() string { return filepath.Join(l.Root, "etc", "ssh", "sshd_config.d") }

// DropIn is the agent's sshd drop-in.
func (l Layout) DropIn() string { return filepath.Join(l.DropInDir(), DropInName) }

// State is a file or directory in the state directory.
func (l Layout) State(name ...string) string {
	return filepath.Join(append([]string{l.StateDir}, name...)...)
}

// within reports whether p is dir or below it; both are clean absolute
// paths.
func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

// Allowed returns nil when the applier may write path: the keyroster tree
// itself or anything below it, the drop-in file exactly, or the state
// directory or anything below it. The path must be absolute and clean
// (no "..", no doubled separators); anything else is ErrNotAllowed. It
// never touches the file system: the applier opens every path it checked
// with O_NOFOLLOW relative to a directory it opened the same way.
func Allowed(l Layout, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: %q is not a clean absolute path", ErrNotAllowed, path)
	}
	if !filepath.IsAbs(l.Root) || !filepath.IsAbs(l.StateDir) {
		return fmt.Errorf("%w: the layout's root and state directory must be absolute", ErrNotAllowed)
	}
	switch {
	case within(path, filepath.Clean(l.KeyrosterDir())):
		return nil
	case path == filepath.Clean(l.DropIn()):
		return nil
	case within(path, filepath.Clean(l.StateDir)):
		return nil
	}
	return fmt.Errorf("%w: %s is outside the agent's paths (%s, %s and %s)", ErrNotAllowed, path, l.KeyrosterDir(), l.DropIn(), l.StateDir)
}

// Phase2DropIn is the Phase 2 runbook's drop-in,
// <root>/etc/ssh/sshd_config.d/50-keyroster.conf. With Phase2CAFile
// (<root>/etc/ssh/keyroster_user_ca.pub) and Phase2PrincipalsDir
// (<root>/etc/ssh/principals) it is the hand-set layout of host-setup.md.
// The agent takes such a host over once (D-08) and then removes them; it
// never writes them (AllowedRemoval).
func (l Layout) Phase2DropIn() string {
	return filepath.Join(l.DropInDir(), "50-keyroster.conf")
}

// Phase2CAFile is the Phase 2 runbook's TrustedUserCAKeys file.
func (l Layout) Phase2CAFile() string {
	return filepath.Join(l.Root, "etc", "ssh", "keyroster_user_ca.pub")
}

// Phase2PrincipalsDir is the Phase 2 runbook's AuthorizedPrincipalsFile
// directory.
func (l Layout) Phase2PrincipalsDir() string {
	return filepath.Join(l.Root, "etc", "ssh", "principals")
}

// AllowedRemoval returns nil when the applier may remove path: anything
// Allowed, and the three one-time entries of the Phase 2 layout (D-08):
// Phase2DropIn and Phase2CAFile exactly, Phase2PrincipalsDir itself and
// the files directly in it. Only removals may use it; every write goes
// through Allowed, which these paths never pass (TestPaths, TestAllowed).
func AllowedRemoval(l Layout, path string) error {
	if err := Allowed(l, path); err == nil {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(l.Root) {
		return fmt.Errorf("%w: %q is not a clean absolute path", ErrNotAllowed, path)
	}
	pdir := filepath.Clean(l.Phase2PrincipalsDir())
	switch {
	case path == filepath.Clean(l.Phase2DropIn()), path == filepath.Clean(l.Phase2CAFile()), path == pdir:
		return nil
	case filepath.Dir(path) == pdir && filepath.Base(path) != "." && filepath.Base(path) != "..":
		return nil
	}
	return fmt.Errorf("%w: %s is neither the agent's nor one of the Phase 2 layout's paths (%s, %s, %s)", ErrNotAllowed, path, l.Phase2DropIn(), l.Phase2CAFile(), l.Phase2PrincipalsDir())
}

// ExecSite is one program the applier runs (PR #67 review: every exec
// site goes through internal/agent/execsite, the only package that
// imports os/exec). Func is the function in internal/agent/apply/sshd.go
// that runs it; Ctor the execsite constructor it calls; Call the
// arguments it passes, as written there; Args the constructor's argv
// after the binary, where an upper-case word is a parameter of the
// constructor and everything else a literal flag.
type ExecSite struct {
	Func string
	Ctor string
	Call string
	Args string
}

// ExecSites are every exec site of the applier. TestPaths fails for a
// call of an execsite constructor that is not in this list, from another
// function or with other arguments; for a constructor whose argv differs
// from Args or that is not listed; for a constructor used other than as
// the callee of such a call, or execsite imported by any package of the
// module but internal/agent/apply; and for any use of os/exec, or of
// os.StartProcess, syscall.Exec, ForkExec or StartProcess or unix.Exec,
// outside execsite's ExecRunner.Run.
var ExecSites = []ExecSite{
	{Func: "sshdTest", Ctor: "SSHDTest", Call: "e.cfg.SSHD e.cfg.SSHDConfig", Args: "-t -f CONFIG"},
	{Func: "sshdDump", Ctor: "SSHDDump", Call: "e.cfg.SSHD e.cfg.SSHDConfig", Args: "-T -f CONFIG"},
	{Func: "sshdDump", Ctor: "SSHDDumpFor", Call: "e.cfg.SSHD e.cfg.SSHDConfig spec", Args: "-T -f CONFIG -C SPEC"},
	{Func: "keygenFingerprint", Ctor: "KeygenFingerprint", Call: "e.cfg.SSHKeygen file", Args: "-l -f FILE"},
	{Func: "keygenQuery", Ctor: "KeygenQuery", Call: "e.cfg.SSHKeygen krlFile pub", Args: "-Q -f KRL PUB"},
	{Func: "reloadSystemd", Ctor: "SystemctlReload", Call: "systemctl unit", Args: "reload UNIT"},
	{Func: "reloadOpenRC", Ctor: "RCServiceReload", Call: "paths.RCService", Args: "sshd reload"},
	{Func: "systemctlShow", Ctor: "SystemctlShow", Call: "systemctl", Args: "show -p Id -p LoadState -p ActiveState -p ExecStart -p EnvironmentFiles -p Environment ssh.socket ssh.service sshd.service"},
}

// Systemctl are the absolute paths reloadSystemd may run, in the order
// it tries them; RCService is reloadOpenRC's.
var (
	Systemctl = []string{"/usr/bin/systemctl", "/bin/systemctl"}
	RCService = "/sbin/rc-service"
)
