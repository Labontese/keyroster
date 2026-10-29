//go:build linux

package apply

import (
	"fmt"
	"path/filepath"
	"strings"
)

// The agent's two services (03-08, D-05), as keyroster-agent install
// writes them: systemd units on a systemd host, OpenRC scripts on an
// OpenRC host.
const (
	ApplierUnit = "keyroster-agent.service"
	FetcherUnit = "keyroster-agent-fetch.service"
	// ApplierScript and FetcherScript are the OpenRC service names.
	ApplierScript = "keyroster-agent"
	FetcherScript = "keyroster-agent-fetch"
	// FetchUser is the fetcher's system user and group.
	FetchUser = "keyroster-agent"
	// DefaultBinDir is where the binaries are installed.
	DefaultBinDir = "/usr/local/bin"
)

// The paths the applier's unit may write, and the fetcher's (Codex 03-08
// LOW, REVIEWS L215): exactly these, so /etc/ssh itself stays read-only
// for the applier (D-08 adoption is a hand-run apply --once) and systemd
// refuses to start a unit whose ReadWritePaths path is missing, which is
// why install creates /etc/ssh/keyroster first.
const (
	applierKeyrosterDir = "/etc/ssh/keyroster"
	applierDropInDir    = "/etc/ssh/sshd_config.d"
	fetchDir            = "/var/lib/keyroster-agent-fetch"
	fetchConfig         = "/etc/keyroster-agent/fetch.json"
)

// UnitConfig is what the units name: the binaries' directory and the
// applier's state directory, both as the host sees them (absolute).
type UnitConfig struct {
	BinDir   string
	StateDir string
}

func (c UnitConfig) spool() string  { return filepath.Join(c.StateDir, "spool") }
func (c UnitConfig) outbox() string { return filepath.Join(c.StateDir, "outbox") }

// check refuses a path with a character a unit or an OpenRC script would
// read as syntax (white space, quotes, $, %, \, ;).
func (c UnitConfig) check() error {
	for _, p := range []string{c.BinDir, c.StateDir} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, " \t\n\"'$%\\;`") {
			return fmt.Errorf("%w: %q is not a clean absolute path without white space or quotes", ErrConfig, p)
		}
	}
	return nil
}

// ApplierSystemdUnit is keyroster-agent.service: the root applier's loop,
// sandboxed. NoNewPrivileges, ProtectSystem=strict with exactly three
// writable paths, no IP traffic but loopback (the self-test dials sshd
// there; the owner's D-05 network answer loopback-only, 03-05), no
// capabilities: it writes only files root owns and reloads sshd through
// systemd, which authorizes uid 0.
func ApplierSystemdUnit(c UnitConfig) (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	return `# keyroster-agent: the agent's root applier (03-08, D-05). Written by
# keyroster-agent install; see docs/runbooks/host-setup.md "Running the agent".
# It verifies the signed state the fetcher spooled and applies it to sshd's
# trust files. It opens no listening socket and sends IP traffic only to
# loopback (its self-test); /etc/ssh stays read-only to it, so taking over a
# Phase 2 host is a hand-run "sudo keyroster-agent apply --once".
[Unit]
Description=keyroster agent applier (applies signed state to sshd)
Documentation=https://github.com/Labontese/keyroster/blob/main/docs/runbooks/host-setup.md
After=network.target ssh.service sshd.service

[Service]
Type=exec
# sshd -t and -T refuse to run without sshd's privilege separation
# directory, which a socket-activated ssh.service (Ubuntu 24.04's default)
# creates only once a connection started it: until then, after every boot,
# the applier could neither apply nor check, and sshd would start on the
# first connection with the trust files of before the boot. systemd creates
# it here, outside this sandbox ("+"), root:root 0755 as sshd requires.
ExecStartPre=+/usr/bin/install -d -m 0755 -o root -g root /run/sshd
ExecStart=` + filepath.Join(c.BinDir, "keyroster-agent") + ` run --state-dir ` + c.StateDir + `
Restart=on-failure
RestartSec=5s
UMask=0022

# File system: everything read-only but exactly these three paths.
ProtectSystem=strict
ReadWritePaths=` + applierKeyrosterDir + ` ` + applierDropInDir + ` ` + c.StateDir + `
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes

# Network: loopback only (the self-test), D-05 loopback-only.
IPAddressDeny=any
IPAddressAllow=localhost
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# Privileges: uid 0 without capabilities; files it writes are its own.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
KeyringMode=private

# Kernel and process.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
LimitCORE=0

[Install]
WantedBy=multi-user.target
`, nil
}

// FetcherSystemdUnit is keyroster-agent-fetch.service: the unprivileged
// fetcher as user keyroster-agent with no capabilities, writing only its
// own directory and the spool; it reads fetch.json and the outbox.
func FetcherSystemdUnit(c UnitConfig) (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	return `# keyroster-agent-fetch: the agent's unprivileged fetcher (03-08, D-05).
# Written by keyroster-agent install; see docs/runbooks/host-setup.md
# "Running the agent". It does all of the agent's network I/O (to the
# server fetch.json names), writes only its own directory and the spool,
# and runs no program.
[Unit]
Description=keyroster agent fetcher (pulls signed state over pinned mTLS)
Documentation=https://github.com/Labontese/keyroster/blob/main/docs/runbooks/host-setup.md
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
ExecStart=` + filepath.Join(c.BinDir, "keyroster-agent-fetch") + ` --config ` + fetchConfig + ` --dir ` + fetchDir + ` --spool ` + c.spool() + ` --outbox ` + c.outbox() + `
Restart=on-failure
RestartSec=10s
User=` + FetchUser + `
Group=` + FetchUser + `
UMask=0022

# File system: read-only but its own directory and the spool.
ProtectSystem=strict
ReadWritePaths=` + fetchDir + ` ` + c.spool() + `
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed

# Network: IPv4 and IPv6 sockets only; destinations are not restricted (the server's address is not known when install writes this unit).
RestrictAddressFamilies=AF_INET AF_INET6

# Privileges: none.
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=yes
RemoveIPC=yes
KeyringMode=private

# Kernel and process.
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
LimitCORE=0

[Install]
WantedBy=multi-user.target
`, nil
}

// ApplierOpenRCScript is /etc/init.d/keyroster-agent. OpenRC has no
// sandbox of its own: the applier runs as root, and the fetcher's user is
// its only separation. UNVERIFIED until 03-16 (PLAT-01).
func ApplierOpenRCScript(c UnitConfig) (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	return `#!/sbin/openrc-run
# keyroster-agent: the agent's root applier (03-08). Written by keyroster-agent
# install; see docs/runbooks/host-setup.md "Running the agent". UNVERIFIED
# until 03-16.
description="keyroster agent applier"
command="` + filepath.Join(c.BinDir, "keyroster-agent") + `"
command_args="run --state-dir ` + c.StateDir + `"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/${RC_SVCNAME}.log"
error_log="/var/log/${RC_SVCNAME}.log"

depend() {
	need net
	after sshd
}
`, nil
}

// FetcherOpenRCScript is /etc/init.d/keyroster-agent-fetch, run as
// keyroster-agent (command_user). start-stop-daemon opens output_log only
// after it dropped to that user, so start_pre creates the log as the
// user's first (checkpath; PR #72 review C7). UNVERIFIED until 03-16.
func FetcherOpenRCScript(c UnitConfig) (string, error) {
	if err := c.check(); err != nil {
		return "", err
	}
	return `#!/sbin/openrc-run
# keyroster-agent-fetch: the agent's unprivileged fetcher (03-08). Written by
# keyroster-agent install; see docs/runbooks/host-setup.md "Running the agent".
# UNVERIFIED until 03-16.
description="keyroster agent fetcher"
command="` + filepath.Join(c.BinDir, "keyroster-agent-fetch") + `"
command_args="--config ` + fetchConfig + ` --dir ` + fetchDir + ` --spool ` + c.spool() + ` --outbox ` + c.outbox() + `"
command_user="` + FetchUser + `"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/${RC_SVCNAME}.log"
error_log="/var/log/${RC_SVCNAME}.log"

start_pre() {
	checkpath -f -o ` + FetchUser + `:` + FetchUser + ` -m 0640 "/var/log/${RC_SVCNAME}.log"
}

depend() {
	need net
}
`, nil
}
