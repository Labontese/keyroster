//go:build linux

package apply

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The minimal probe account check (03-10b; 03-10c extends it here with the
// shadow file, sshd -T -C and the Allow and Deny rules, and 03-14 mirrors
// this file). Its reasons are gate hold reasons (Contracts frozen by
// 03-10b).
const (
	accountMissing    = "account_missing"
	accountUnparsable = "account_unparsable"
	accountUIDZero    = "account_uid_zero"
	shellMissing      = "shell_missing"
	shellNotNologin   = "shell_not_nologin"
)

// maxPasswd bounds <root>/etc/passwd: a larger file is account_unparsable.
const maxPasswd = 1 << 20

// parsePasswdLine splits one passwd(5) line into its seven fields and
// requires a decimal uid; ok is false for anything else.
func parsePasswdLine(line string) ([]string, bool) {
	f := strings.Split(line, ":")
	if len(f) != 7 || f[0] == "" {
		return nil, false
	}
	if _, err := strconv.ParseUint(f[2], 10, 32); err != nil {
		return nil, false
	}
	return f, true
}

// checkProbeAccount is the minimal check of the probe account on the host
// at root: <root>/etc/passwd has exactly one line for account, which
// parses (seven fields, a decimal uid), whose uid is not 0 and whose shell
// is an absolute path naming an existing executable regular file under
// root (links followed) called nologin. It returns "" or the first failing
// reason, and the account's passwd line (for the failure key). Lines of
// other accounts are ignored, malformed or not: a NIS entry must not hold
// every addition.
func checkProbeAccount(root, account string) (reason, line string) {
	f, err := os.Open(filepath.Join(root, "etc", "passwd")) //nolint:gosec // the host's own passwd file under the layout root
	if errors.Is(err, fs.ErrNotExist) {
		return accountMissing, ""
	}
	if err != nil {
		return accountUnparsable, ""
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, maxPasswd+1))
	if err != nil || len(b) > maxPasswd {
		return accountUnparsable, ""
	}
	var own []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 4096), maxPasswd+1)
	for sc.Scan() {
		l := sc.Text()
		if name, _, _ := strings.Cut(l, ":"); name == account {
			own = append(own, l)
		}
	}
	if sc.Err() != nil {
		return accountUnparsable, ""
	}
	switch len(own) {
	case 0:
		return accountMissing, ""
	case 1:
	default:
		return accountUnparsable, own[0]
	}
	line = own[0]
	fields, ok := parsePasswdLine(line)
	if !ok {
		return accountUnparsable, line
	}
	if uid, _ := strconv.ParseUint(fields[2], 10, 32); uid == 0 {
		return accountUIDZero, line
	}
	shell := fields[6]
	if !path.IsAbs(shell) {
		return accountUnparsable, line
	}
	st, err := os.Stat(filepath.Join(root, filepath.FromSlash(shell)))
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o111 == 0 {
		return shellMissing, line
	}
	if path.Base(shell) != "nologin" {
		return shellNotNologin, line
	}
	return "", line
}

// The full probe account check (03-10c, owner decision Q3, 2026-11-07):
// the minimal check above, then the password class of passwd field 2 and
// <root>/etc/shadow, then sshd -T -C for the account from the probe's own
// source address. Its reasons are gate hold reasons too (Contracts frozen
// by 03-10c), in this order after the minimal check's.
const (
	passwordEmpty   = "password_empty"
	passwordSet     = "password_set"
	sshdOverride    = "sshd_override"
	accountExcluded = "account_excluded"
)

// Password classes (03-10c, 'Password classes'): the only form in which a
// password field is kept. ParseShadowLine returns one of empty, star,
// locked, hash or malformed; passwordClass adds absent, unreadable and
// unparsable.
const (
	pwAbsent     = "absent"
	pwUnreadable = "unreadable"
	pwEmpty      = "empty"
	pwStar       = "star"
	pwLocked     = "locked"
	pwHash       = "hash"
	pwUnparsable = "unparsable"
	pwMalformed  = "malformed"
)

// pwRank orders the classes, worst last: the two sources are combined and
// the worst wins (03-10c). unparsable ranks above hash, so a shadow file
// the agent cannot read safely always fails closed.
var pwRank = map[string]int{pwAbsent: 0, pwUnreadable: 1, pwStar: 2, pwLocked: 3, pwEmpty: 4, pwHash: 5, pwUnparsable: 6}

// worse is the worse of two classes.
func worse(a, b string) string {
	if pwRank[b] > pwRank[a] {
		return b
	}
	return a
}

// maxShadow bounds <root>/etc/shadow: a larger file is unparsable.
const maxShadow = 1 << 20

// ParseShadowLine classifies the password field (field 2) of one
// shadow(5) line: empty, star (exactly "*"), locked (starts with "!"),
// hash (anything else), or malformed for a line with fewer than two
// colon-separated fields. Only the class leaves this function: the field
// is never stored, formatted or returned (T-03-385).
func ParseShadowLine(line string) string {
	_, rest, ok := strings.Cut(line, ":")
	if !ok {
		return pwMalformed
	}
	field, _, _ := strings.Cut(rest, ":")
	switch {
	case field == "":
		return pwEmpty
	case field == "*":
		return pwStar
	case strings.HasPrefix(field, "!"):
		return pwLocked
	}
	return pwHash
}

// passwordResult is the effective password class of the probe account and
// whether <root>/etc/shadow did not open for a permission reason.
type passwordResult struct {
	Class            string
	ShadowUnreadable bool
}

// openShadowFile opens path read-only, without following a symlink and
// without blocking, so a FIFO cannot stall the gate (T-03-385).
func openShadowFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// passwordClass is the worst class of passwd field 2 of line (when it is
// not "x") and of every <root>/etc/shadow line for account; shadow is read
// whenever it opens. The open errors map in a closed way: ENOENT and
// ENOTDIR are absent; EACCES, EPERM and ELOOP (a symlink) unreadable; any
// other error unparsable. A file over maxShadow, one that is not a regular
// file, or a malformed line for account is unparsable. open nil is
// openShadowFile.
func passwordClass(open func(string) (*os.File, error), root, account, line string) passwordResult {
	res := passwordResult{Class: pwAbsent}
	if _, rest, ok := strings.Cut(line, ":"); ok {
		if f2, _, _ := strings.Cut(rest, ":"); f2 != "x" {
			res.Class = worse(res.Class, ParseShadowLine(account+":"+f2))
		}
	}
	if open == nil {
		open = openShadowFile
	}
	f, err := open(filepath.Join(root, "etc", "shadow"))
	switch {
	case errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR):
		return res
	case errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.ELOOP):
		res.ShadowUnreadable = true
		res.Class = worse(res.Class, pwUnreadable)
		return res
	case err != nil:
		res.Class = pwUnparsable
		return res
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		res.Class = pwUnparsable
		return res
	}
	b, err := io.ReadAll(io.LimitReader(f, maxShadow+1))
	if err != nil || len(b) > maxShadow {
		res.Class = pwUnparsable
		return res
	}
	for _, l := range strings.Split(string(b), "\n") {
		if name, _, _ := strings.Cut(l, ":"); name != account {
			continue
		}
		c := ParseShadowLine(l)
		if c == pwMalformed {
			c = pwUnparsable
		}
		res.Class = worse(res.Class, c)
	}
	return res
}

// keyLine is a passwd line with field 2 replaced by its class (unless it
// is "x"), so that no password field enters a failure key (T-03-385).
func keyLine(line string) string {
	f := strings.Split(line, ":")
	if len(f) >= 2 && f[1] != "x" {
		f[1] = ParseShadowLine(f[0] + ":" + f[1])
	}
	return strings.Join(f, ":")
}

// accountKeyInput is the probe account's part of the failure key (03-10c,
// D2): the passwd line of the minimal check with field 2 as its class, a
// NUL byte and the effective password class. It runs no command. The
// gate, runProbes, opportunistic and the served-certificate site all use
// it, so a failure recorded by one is found by the others.
func (e *engine) accountKeyInput(account string) string {
	_, line := checkProbeAccount(e.l.Root, account)
	return keyLine(line) + "\x00" + passwordClass(e.cfg.openShadow, e.l.Root, account, line).Class
}

// accountResult is the full check's result: the first failing reason (""
// when none), the passwd line as accountKeyInput writes it, the password
// class and the notes (probe_shadow_unreadable).
type accountResult struct {
	Reason string
	Line   string
	Shadow string
	Notes  []string
}

// noteShadowUnreadable is the note of a shadow file that did not open for
// a permission reason: never a hold by itself (owner decision Q3).
const noteShadowUnreadable = "probe_shadow_unreadable"

// probeAccountSpec is the sshd -T -C connection specification for the
// probe account from the probe's own source address src to laddr port
// lport (03-10c; accountSpec stays 127.0.0.1 for its own callers).
func probeAccountSpec(account, src, laddr, lport string) string {
	return "user=" + account + ",host=" + src + ",addr=" + src + ",laddr=" + laddr + ",lport=" + lport
}

// probeSpecTarget is the first loopback target of dump that certTarget's
// non-dialing skip rule keeps (an IPv6 target is skipped while IPv6 is off
// on lo), the rule probeAddr applies.
func (e *engine) probeSpecTarget(dump Dump) (string, error) {
	targets, err := loopbackTargets(dump)
	if err != nil {
		return "", err
	}
	ipv6Off := e.ipv6Off
	if ipv6Off == nil {
		ipv6Off = ipv6Disabled
	}
	for _, t := range targets {
		if strings.HasPrefix(t, "[") && ipv6Off() {
			continue
		}
		return t, nil
	}
	return "", fmt.Errorf("%w: every loopback address sshd listens on is IPv6, which is off on lo", ErrNoLoopbackListener)
}

// publickeyFirst reports whether sshd -T's authenticationmethods value v
// lets a client authenticate with publickey first: absent, any, or an
// alternative (space separated) whose first method (comma separated,
// compared before any ':' option) is publickey.
func publickeyFirst(v string) bool {
	if v == "" || v == "any" {
		return true
	}
	for _, alt := range strings.Fields(v) {
		first, _, _ := strings.Cut(alt, ",")
		if m, _, _ := strings.Cut(first, ":"); m == "publickey" {
			return true
		}
	}
	return false
}

// checkProbeAccountFull is the full probe account check (03-10c, owner
// decision Q3), stopping at the first failure in the order of the closed
// list: the minimal passwd check; the password class (empty is
// password_empty, hash password_set, unparsable account_unparsable); then
// sshd -T -C for the account from the probe source to the first loopback
// target of dump, where pubkeyauthentication other than yes,
// authenticationmethods that never offer publickey first, with compareTrust
// a trust keyword or a principals command that is not the agent's,
// permitemptypasswords yes while shadow did not open, and a locked class
// while sshd -T does not report usepam yes (an absent usepam is read as a
// build without PAM, fail-safe) are sshd_override, as are a failing
// sshd -T -C and no loopback target to run it for; then a definite
// AllowUsers, DenyUsers, AllowGroups or DenyGroups exclusion is
// account_excluded. An absent keyword is sshd's default. It writes no
// file.
func (e *engine) checkProbeAccountFull(ctx context.Context, account string, dump Dump, compareTrust bool) accountResult {
	reason, line := checkProbeAccount(e.l.Root, account)
	res := accountResult{Reason: reason, Line: keyLine(line)}
	if reason != "" {
		return res
	}
	pw := passwordClass(e.cfg.openShadow, e.l.Root, account, line)
	res.Shadow = pw.Class
	if pw.ShadowUnreadable {
		res.Notes = append(res.Notes, noteShadowUnreadable)
	}
	switch pw.Class {
	case pwUnparsable:
		res.Reason = accountUnparsable
		return res
	case pwEmpty:
		res.Reason = passwordEmpty
		return res
	case pwHash:
		res.Reason = passwordSet
		return res
	}
	override := func(format string, args ...any) accountResult {
		e.logf("probe account %s: %s: %s", account, sshdOverride, fmt.Sprintf(format, args...))
		res.Reason = sshdOverride
		return res
	}
	target, err := e.probeSpecTarget(dump)
	if err != nil {
		return override("no loopback target to evaluate sshd -T -C for: %v", err)
	}
	src, _, _ := probeSource(dump, target)
	laddr, lport, err := net.SplitHostPort(target)
	if err != nil {
		return override("%v", err)
	}
	d, err := e.sshdDump(ctx, probeAccountSpec(account, src, laddr, lport))
	if err != nil {
		return override("%v", err)
	}
	if v := d.One("pubkeyauthentication"); v != "" && v != "yes" {
		return override("sshd -T -C reports pubkeyauthentication %q", v)
	}
	if v := d.One("authenticationmethods"); !publickeyFirst(v) {
		return override("sshd -T -C reports authenticationmethods %q, which never offers publickey first", v)
	}
	if compareTrust {
		want := ourValues(e.l)
		for _, k := range trustKeywords {
			if got := d.One(k); got != want[k] {
				return override("sshd -T -C reports %s %q, want %q", k, got, want[k])
			}
		}
		if got := d.One(principalsCommand); !isDefault(got) {
			return override("sshd -T -C reports %s %q, want none", principalsCommand, got)
		}
	}
	if pw.ShadowUnreadable && d.One("permitemptypasswords") == "yes" {
		return override("sshd -T -C reports permitemptypasswords yes and %s could not be read", filepath.Join(e.l.Root, "etc", "shadow"))
	}
	if pw.Class == pwLocked && d.One("usepam") != "yes" {
		return override("the password field is locked (!) and sshd -T -C reports usepam %q, so sshd may refuse the account", d.One("usepam"))
	}
	if why, definite := ExcludedDefinite(d, account, e.l.Root); definite {
		e.logf("probe account %s: %s: %s", account, accountExcluded, why)
		res.Reason = accountExcluded
	}
	return res
}
