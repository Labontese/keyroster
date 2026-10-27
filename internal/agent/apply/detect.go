//go:build linux

package apply

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/Labontese/keyroster/internal/agent/execsite"
	"github.com/Labontese/keyroster/internal/agent/paths"
)

// ErrNotDetected is a host whose sshd service Detect cannot find: no
// systemd unit ssh.service or sshd.service, and no OpenRC
// /etc/init.d/sshd. The operator passes --sshd, --sshd-config and
// --reload instead.
var ErrNotDetected = errors.New("sshd_not_detected")

// Service is how this host runs sshd (Detect): the binary and the
// configuration the running service uses, and how the agent makes it
// re-read that configuration.
type Service struct {
	// Manager is "systemd" or "openrc".
	Manager string `json:"manager"`
	// Unit is the systemd unit's Id (ssh.service, sshd.service).
	Unit string `json:"unit,omitempty"`
	// SSHD and Config are the absolute paths of the service's sshd and
	// its configuration file.
	SSHD   string `json:"sshd"`
	Config string `json:"sshd_config"`
	// Reload is the reload strategy (CheckReload): systemd:<unit>,
	// openrc, or none for a socket-activated sshd whose service is not
	// running.
	Reload string `json:"reload"`
	// Socket is set when ssh.socket is active and the service is not: the
	// next connection starts sshd, which reads its configuration fresh.
	Socket bool `json:"socket_activated,omitempty"`
}

// defaultSSHD and defaultSSHDConfig are what an sshd service runs when
// its definition names no other.
const (
	defaultSSHD       = "/usr/sbin/sshd"
	defaultSSHDConfig = "/etc/ssh/sshd_config"
)

// Detect finds the sshd binary, its configuration and the reload strategy
// from the service that runs it, never assuming /usr/sbin/sshd (03-06):
//
//   - systemd (root/run/systemd/system is a directory): systemctl show for
//     ssh.socket, ssh.service and sshd.service. The loaded service (the
//     active one when both are loaded) gives the binary (ExecStart's path)
//     and the configuration (ExecStart's -f argument, a $VAR in it
//     resolved from the unit's Environment and EnvironmentFiles, else
//     /etc/ssh/sshd_config); any other argument is ErrSSHDCommand
//     (parseExecStart). The strategy is systemd:<its Id>. When
//     ssh.socket is active and the service is not, Socket is set and the
//     strategy is none (Ubuntu's socket activation).
//   - OpenRC (root/etc/init.d/sshd exists): the binary, configuration and
//     arguments from root/etc/conf.d/sshd (detectOpenRC), else the
//     defaults; the strategy is openrc.
//
// r runs systemctl (nil: the real runner). root is "/" in production;
// tests pass a temporary directory holding the files Detect reads. Every
// strategy is checked by sshd -t of that binary before any reload: the
// agent never relies on the service's own reload check (Arch's
// notify-reload and RHEL's plain HUP have none).
func Detect(ctx context.Context, r Runner, root string) (Service, error) {
	if r == nil {
		r = execsite.ExecRunner{}
	}
	if st, err := os.Stat(filepath.Join(root, "run", "systemd", "system")); err == nil && st.IsDir() {
		return detectSystemd(ctx, r, root)
	}
	if st, err := os.Stat(filepath.Join(root, "etc", "init.d", "sshd")); err == nil && st.Mode().IsRegular() {
		return detectOpenRC(root)
	}
	return Service{}, fmt.Errorf("%w: neither systemd (no %s) nor OpenRC (no %s) runs sshd here; pass --sshd, --sshd-config and --reload",
		ErrNotDetected, filepath.Join(root, "run", "systemd", "system"), filepath.Join(root, "etc", "init.d", "sshd"))
}

// unitProps is one unit's block of systemctl show output.
type unitProps map[string]string

// parseShow splits systemctl show output into its per-unit blocks of
// KEY=VALUE lines (a blank line between units), in order. A key printed
// more than once in a block (one EnvironmentFiles= line per file) keeps
// every value, joined by newlines.
func parseShow(out []byte) []unitProps {
	var blocks []unitProps
	cur := unitProps{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			if len(cur) > 0 {
				blocks = append(blocks, cur)
				cur = unitProps{}
			}
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			if prev, seen := cur[k]; seen {
				v = prev + "\n" + v
			}
			cur[k] = v
		}
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	return blocks
}

func detectSystemd(ctx context.Context, r Runner, root string) (Service, error) {
	systemctl := ""
	for _, p := range paths.Systemctl {
		if _, err := os.Stat(filepath.Join(root, p)); err == nil {
			systemctl = p
			break
		}
	}
	if systemctl == "" {
		return Service{}, fmt.Errorf("%w: systemd runs, but there is no systemctl at %s", ErrNotDetected, strings.Join(paths.Systemctl, " or "))
	}
	res, err := systemctlShow(ctx, r, systemctl)
	if err != nil {
		return Service{}, fmt.Errorf("%w: systemctl show: %w", ErrNotDetected, err)
	}
	if res.Code != 0 {
		return Service{}, fmt.Errorf("%w: systemctl show exited %d: %s", ErrNotDetected, res.Code, firstLine(res.Stderr))
	}
	socketActive := false
	var service unitProps
	for _, u := range parseShow(res.Stdout) {
		switch {
		case u["Id"] == "ssh.socket":
			socketActive = u["ActiveState"] == "active"
		case u["LoadState"] != "loaded" || !strings.HasSuffix(u["Id"], ".service"):
		case service == nil, service["ActiveState"] != "active" && u["ActiveState"] == "active":
			service = u
		}
	}
	if service == nil {
		return Service{}, fmt.Errorf("%w: systemd has no loaded ssh.service or sshd.service", ErrNotDetected)
	}
	unit := service["Id"]
	if !unitRE.MatchString(unit) {
		return Service{}, fmt.Errorf("%w: systemd unit %q is not a service name the agent accepts", ErrNotDetected, unit)
	}
	if strings.Contains(service["ExecStart"], "\n") {
		return Service{}, fmt.Errorf("%w: %w: %s has more than one ExecStart; the agent reads one sshd command line", ErrNotDetected, ErrSSHDCommand, unit)
	}
	sshd, config, err := parseExecStart(service["ExecStart"], func() (envVars, error) { return unitEnv(root, service) })
	if err != nil {
		return Service{}, fmt.Errorf("%w: %s: %w", ErrNotDetected, unit, err)
	}
	s := Service{Manager: "systemd", Unit: unit, SSHD: sshd, Config: config, Reload: "systemd:" + unit}
	if socketActive && service["ActiveState"] != "active" {
		s.Socket, s.Reload = true, ReloadNone
	}
	return s, nil
}

// parseExecStart reads the binary and the configuration of a systemd
// ExecStart property: "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D
// $SSHD_OPTS ; ignore_errors=no ; ... }". The agent runs sshd -t and
// sshd -T with -f <config> only, so a command line that sets anything
// else (-o RevokedKeys=none, -p, a combined -De) would change what sshd
// does behind every check: it is refused (sshd_command_unknown, PR #68
// review D-R4, the owner's "refuse unknown arguments"). sshdArgs accepts
// -D, -e and one -f <file> or -f<file>, all the stock units use (Debian
// and Ubuntu "-D $SSHD_OPTS", EL9 "-D $OPTIONS", Arch "-D"). systemctl
// show does not expand environment variables: a word that is exactly
// $NAME (split on whitespace, as systemd does) or ${NAME} (one word) is
// resolved from the unit's Environment and EnvironmentFiles (env), so a
// -f there sets the configuration; any other $, quote, backslash,
// backtick or % is refused.
func parseExecStart(v string, env func() (envVars, error)) (string, string, error) {
	field := func(name string) string {
		i := strings.Index(v, name+"=")
		if i < 0 {
			return ""
		}
		rest := v[i+len(name)+1:]
		if j := strings.Index(rest, " ;"); j >= 0 {
			rest = rest[:j]
		}
		return strings.TrimSpace(rest)
	}
	bin := field("path")
	if bin == "" || !filepath.IsAbs(bin) || filepath.Clean(bin) != bin {
		return "", "", fmt.Errorf("ExecStart names no absolute sshd path (%q)", v)
	}
	argv := strings.Fields(field("argv[]"))
	var words []string
	var vars *envVars
	for _, tok := range argv[min(1, len(argv)):] {
		name, braced, ok := varRef(tok)
		if !ok {
			if strings.ContainsAny(tok, unparsedChars) {
				return "", "", fmt.Errorf("%w: ExecStart's argument %q is not one the agent reads (only $NAME and ${NAME} are resolved)", ErrSSHDCommand, tok)
			}
			words = append(words, tok)
			continue
		}
		if vars == nil {
			ev, err := env()
			if err != nil {
				return "", "", fmt.Errorf("%w: resolving %s in ExecStart: %w", ErrSSHDCommand, tok, err)
			}
			vars = &ev
		}
		val, err := vars.get(name)
		if err != nil {
			return "", "", fmt.Errorf("%w: resolving %s in ExecStart: %w", ErrSSHDCommand, tok, err)
		}
		switch {
		case strings.ContainsAny(val, unparsedChars):
			return "", "", fmt.Errorf("%w: %s is %q, which the agent does not read", ErrSSHDCommand, tok, val)
		case braced && strings.ContainsAny(val, " \t"):
			return "", "", fmt.Errorf("%w: %s is %q, one argument with whitespace in it", ErrSSHDCommand, tok, val)
		}
		words = append(words, strings.Fields(val)...)
	}
	config, err := sshdArgs(words, true)
	if err != nil {
		return "", "", err
	}
	if config == "" {
		config = defaultSSHDConfig
	}
	if !filepath.IsAbs(config) || filepath.Clean(config) != config {
		return "", "", fmt.Errorf("%w: sshd's -f argument %q is not a clean absolute path", ErrSSHDCommand, config)
	}
	return bin, config, nil
}

// ErrSSHDCommand is a service whose sshd command line the agent cannot
// account for (sshd_command_unknown): an argument other than -D, -e and
// -f <file>, a variable it cannot resolve, or settings it cannot read
// safely. keyroster-agent preflight reports it as a refusal (exit 3).
var ErrSSHDCommand = errors.New(CodeSSHDCommand)

// unparsedChars are the characters a command-line word or a resolved
// value may not hold: the agent does not expand or unquote them.
const unparsedChars = "$%\"'\\`"

// sshdArgs checks sshd's arguments after the binary: -D, -e and, when
// withF is set, one -f <file> or -f<file>, whose file it returns ("" for
// none). Anything else is ErrSSHDCommand.
func sshdArgs(words []string, withF bool) (string, error) {
	config := ""
	for i := 0; i < len(words); i++ {
		w, file := words[i], ""
		switch {
		case w == "-D" || w == "-e":
			continue
		case withF && w == "-f" && i+1 < len(words):
			file = words[i+1]
			i++
		case withF && strings.HasPrefix(w, "-f") && len(w) > 2:
			file = w[2:]
		default:
			return "", fmt.Errorf("%w: sshd is started with the argument %q: the agent checks sshd -t and sshd -T with -f <config> only, so an argument such as -o can change a trust setting behind every check; only -D, -e and one -f <file> are accepted", ErrSSHDCommand, w)
		}
		if config != "" {
			return "", fmt.Errorf("%w: sshd is started with -f twice", ErrSSHDCommand)
		}
		config = file
	}
	return config, nil
}

// varRef reports whether tok is exactly $NAME or ${NAME}, and which.
func varRef(tok string) (name string, braced, ok bool) {
	if n, found := strings.CutPrefix(tok, "${"); found && strings.HasSuffix(n, "}") {
		name, braced = strings.TrimSuffix(n, "}"), true
	} else if n, found := strings.CutPrefix(tok, "$"); found {
		name = n
	}
	return name, braced, envNameRE.MatchString(name)
}

// envNameRE is an environment variable name.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// envVars are a unit's environment variables: their values, and why
// each one the agent could not read is unreadable.
type envVars struct {
	vals, bad map[string]string
}

func (v envVars) get(name string) (string, error) {
	if why, ok := v.bad[name]; ok {
		return "", errors.New(why)
	}
	return v.vals[name], nil
}

func (v envVars) set(name, val, bad string) {
	delete(v.vals, name)
	delete(v.bad, name)
	if bad != "" {
		v.bad[name] = bad
	} else {
		v.vals[name] = val
	}
}

// unitEnv is a unit's environment as systemd builds it for ExecStart:
// Environment, then each EnvironmentFiles entry in order, a later
// setting overriding an earlier one (systemd.exec(5)). An optional file
// (systemctl show's "(ignore_errors=yes)", EnvironmentFile=-...) that is
// missing sets nothing; every file is read below root through
// readTrusted, and one that is unsafe, or not optional and missing, is
// an error.
func unitEnv(root string, u unitProps) (envVars, error) {
	vars := envVars{vals: map[string]string{}, bad: map[string]string{}}
	for _, line := range splitProp(u["Environment"]) {
		if strings.ContainsAny(line, "\"'\\") {
			return envVars{}, fmt.Errorf("systemctl show reports Environment=%s, quoted or escaped, which the agent does not parse", line)
		}
		for _, kv := range strings.Fields(line) {
			k, val, ok := strings.Cut(kv, "=")
			if !ok || !envNameRE.MatchString(k) {
				return envVars{}, fmt.Errorf("systemctl show reports Environment=%s, which the agent does not parse", line)
			}
			vars.set(k, val, "")
		}
	}
	for _, ef := range splitProp(u["EnvironmentFiles"]) {
		path, opt, ok := strings.Cut(ef, " (ignore_errors=")
		if !ok || !filepath.IsAbs(path) || filepath.Clean(path) != path || (opt != "yes)" && opt != "no)") {
			return envVars{}, fmt.Errorf("systemctl show reports EnvironmentFiles=%s, which the agent does not parse", ef)
		}
		b, err := readTrusted(root, filepath.Join(root, path), 64<<10)
		if errors.Is(err, unix.ENOENT) && opt == "yes)" {
			continue
		}
		if err != nil {
			return envVars{}, fmt.Errorf("EnvironmentFile %s: %w", path, err)
		}
		if err := parseEnvFile(path, b, vars); err != nil {
			return envVars{}, err
		}
	}
	return vars, nil
}

// splitProp is the values of a systemctl show property parseShow joined.
func splitProp(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, "\n")
}

// parseEnvFile reads the NAME=VALUE lines of a systemd EnvironmentFile
// into vars, conservatively: blank lines and # or ; comments are
// skipped, one pair of matching quotes around a value is removed, and a
// value with another quote, a backslash, a backtick, a % or a $ is
// recorded as unreadable (refused only if ExecStart uses it). A line that
// is not NAME=VALUE, or continues on the next line, is an error: it may
// hide any assignment.
func parseEnvFile(path string, b []byte, vars envVars) error {
	for i, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || t[0] == '#' || t[0] == ';' {
			continue
		}
		k, val, ok := strings.Cut(t, "=")
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		if !ok || !envNameRE.MatchString(k) || strings.HasSuffix(t, "\\") {
			return fmt.Errorf("%s:%d is not a NAME=VALUE line the agent reads", path, i+1)
		}
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		bad := ""
		if strings.ContainsAny(val, unparsedChars) {
			bad = fmt.Sprintf("%s:%d sets %s to %q, which the agent does not expand or unquote", path, i+1, k, val)
		}
		vars.set(k, val, bad)
	}
	return nil
}

// detectOpenRC reads <root>/etc/conf.d/sshd (through readTrusted) the
// way Alpine's /etc/init.d/sshd uses it: cfgfile, else SSHD_CONFIG, else
// $SSHD_CONFDIR/sshd_config (default /etc/ssh) is the configuration;
// SSHD_BINARY the binary; command_args, else SSHD_OPTS, the arguments,
// which sshdArgs checks without -f (the init script adds its own -f
// <cfgfile>) (PR #68 review D-R4). A value with a $, a backtick, a % or
// quotes inside is refused. The init script's own command line is not
// read (UNVERIFIED for a modified script, host-setup.md).
func detectOpenRC(root string) (Service, error) {
	s := Service{Manager: "openrc", SSHD: defaultSSHD, Config: defaultSSHDConfig, Reload: "openrc"}
	b, err := readTrusted(root, filepath.Join(root, "etc", "conf.d", "sshd"), 64<<10)
	if errors.Is(err, unix.ENOENT) {
		return s, nil
	}
	if err != nil {
		return Service{}, fmt.Errorf("%w: %w: %w", ErrNotDetected, ErrSSHDCommand, err)
	}
	set := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		switch k {
		case "SSHD_BINARY", "SSHD_CONFIG", "cfgfile", "SSHD_CONFDIR":
			if v != "" && (!filepath.IsAbs(v) || strings.ContainsAny(v, unparsedChars) || filepath.Clean(v) != v) {
				return Service{}, fmt.Errorf("%w: %w: /etc/conf.d/sshd sets %s=%q, which is not a plain absolute path; pass --sshd and --sshd-config", ErrNotDetected, ErrSSHDCommand, k, v)
			}
		case "SSHD_OPTS", "command_args":
			if strings.ContainsAny(v, unparsedChars) {
				return Service{}, fmt.Errorf("%w: %w: /etc/conf.d/sshd sets %s=%q, which the agent does not expand or unquote", ErrNotDetected, ErrSSHDCommand, k, v)
			}
		default:
			continue
		}
		set[k] = v
	}
	if set["SSHD_BINARY"] != "" {
		s.SSHD = set["SSHD_BINARY"]
	}
	switch {
	case set["cfgfile"] != "":
		s.Config = set["cfgfile"]
	case set["SSHD_CONFIG"] != "":
		s.Config = set["SSHD_CONFIG"]
	case set["SSHD_CONFDIR"] != "":
		s.Config = filepath.Join(set["SSHD_CONFDIR"], "sshd_config")
	}
	args := set["command_args"]
	if args == "" {
		args = set["SSHD_OPTS"]
	}
	if _, err := sshdArgs(strings.Fields(args), false); err != nil {
		return Service{}, fmt.Errorf("%w: /etc/conf.d/sshd: %w", ErrNotDetected, err)
	}
	return s, nil
}
