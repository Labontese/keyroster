//go:build linux

package apply

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
//     and the configuration (ExecStart's -f argument, else
//     /etc/ssh/sshd_config); the strategy is systemd:<its Id>. When
//     ssh.socket is active and the service is not, Socket is set and the
//     strategy is none (Ubuntu's socket activation).
//   - OpenRC (root/etc/init.d/sshd exists): SSHD_BINARY and SSHD_CONFIG
//     from root/etc/conf.d/sshd (Alpine may name /usr/sbin/sshd.pam), else
//     the defaults; the strategy is openrc.
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
// KEY=VALUE lines (a blank line between units), in order.
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
	sshd, config, err := parseExecStart(service["ExecStart"])
	if err != nil {
		return Service{}, fmt.Errorf("%w: %s: %w", ErrNotDetected, unit, err)
	}
	s := Service{Manager: "systemd", Unit: unit, SSHD: sshd, Config: config, Reload: "systemd:" + unit}
	if socketActive && service["ActiveState"] != "active" {
		s.Socket, s.Reload = true, ReloadNone
	}
	return s, nil
}

// parseExecStart reads the binary and the -f configuration of a systemd
// ExecStart property: "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D
// $SSHD_OPTS ; ignore_errors=no ; ... }". An environment variable in argv
// is not expanded (systemctl show does not either), so a -f inside one is
// not seen: the configuration is then the default, and the operator
// passes --sshd-config.
func parseExecStart(v string) (string, string, error) {
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
	config := defaultSSHDConfig
	args := strings.Fields(field("argv[]"))
	for i := 1; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-f" && i+1 < len(args):
			config = args[i+1]
			i++
		case strings.HasPrefix(a, "-f") && len(a) > 2:
			config = a[2:]
		}
	}
	if !filepath.IsAbs(config) || strings.Contains(config, "$") {
		return "", "", fmt.Errorf("ExecStart's -f argument %q is not an absolute path", config)
	}
	return bin, filepath.Clean(config), nil
}

func detectOpenRC(root string) (Service, error) {
	s := Service{Manager: "openrc", SSHD: defaultSSHD, Config: defaultSSHDConfig, Reload: "openrc"}
	f, err := os.Open(filepath.Join(root, "etc", "conf.d", "sshd")) //nolint:gosec // G304: OpenRC's own sshd settings, read-only
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return Service{}, fmt.Errorf("%w: %w", ErrNotDetected, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return Service{}, fmt.Errorf("%w: %w", ErrNotDetected, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "SSHD_BINARY", "SSHD_CONFIG":
			if !filepath.IsAbs(v) || strings.ContainsAny(v, "$`") || filepath.Clean(v) != v {
				return Service{}, fmt.Errorf("%w: /etc/conf.d/sshd sets %s=%q, which is not a plain absolute path; pass --sshd and --sshd-config", ErrNotDetected, k, v)
			}
			if k == "SSHD_BINARY" {
				s.SSHD = v
			} else {
				s.Config = v
			}
		}
	}
	return s, nil
}
