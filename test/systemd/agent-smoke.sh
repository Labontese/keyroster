#!/usr/bin/env bash
# Smoke test of the agent's two units on a real systemd host (03-08,
# PLAT-01, D-05).
#
#   sudo env "PATH=$PATH" bash test/systemd/agent-smoke.sh
#
# Runs as root and changes the host: it installs openssh-server when it is
# missing, creates the system user keyroster-agent and the login account
# krsmoke, installs keyroster-agent and keyroster-agent-fetch in
# /usr/local/bin, and lets keyroster-agent install write the two units and
# /var/lib/keyroster-agent. Run it only on a throwaway host; CI runs it in
# the systemd-sandbox job (.github/workflows/systemd.yml).
#
# TestAgentSystemdSmoke (test/e2e/agent_systemd_test.go, build tags e2e and
# systemdsmoke) bootstraps a signer and a server with a policy that sets
# pop.hosts, mints a join file, runs keyroster-agent install, starts both
# units, approves the host, waits for the first apply (through systemctl
# reload, or try-reload-or-restart under socket activation; the log says
# which), logs in to the runner's own ssh.service on 127.0.0.1 with a
# certificate, and waits for keyroster host status to show the heartbeat
# on the current KRL. This script then checks, as the real keyroster-agent
# user, that it cannot create anything in the state directory (where
# pending.json lives), accepted/ or the outbox, nor overwrite pins.json,
# outbox/status.json or outbox/accepted.json, while it can write in the
# spool (F2 with real users, REVIEWS L1417), and gates
# `systemd-analyze security` on both units:
#   - FETCH_THRESHOLD (exposure x10) for keyroster-agent-fetch.service,
#   - APPLY_THRESHOLD for keyroster-agent.service.
set -euo pipefail

FETCH_THRESHOLD=${KEYROSTER_AGENT_FETCH_SECURITY_THRESHOLD:-15}
APPLY_THRESHOLD=${KEYROSTER_AGENT_APPLY_SECURITY_THRESHOLD:-20}
STATE=/var/lib/keyroster-agent
ACCOUNT=krsmoke

step() { printf '\n=== %s\n' "$*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || {
	echo "agent-smoke.sh: run as root" >&2
	exit 2
}
[ -d /run/systemd/system ] || {
	echo "agent-smoke.sh: not a systemd host" >&2
	exit 2
}

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/keyroster-agent-smoke.XXXXXX)
chmod 0755 "$work"
cleanup() {
	systemctl stop keyroster-agent.service keyroster-agent-fetch.service 2>/dev/null || true
}
trap cleanup EXIT

step "openssh-server"
if [ ! -x /usr/sbin/sshd ]; then
	DEBIAN_FRONTEND=noninteractive apt-get update -qq
	DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server
fi
systemctl start ssh.socket 2>/dev/null || systemctl start ssh.service
/usr/sbin/sshd -V 2>&1 | head -n 1 || true
systemctl is-active ssh.socket ssh.service || true

step "Users: keyroster-agent (system) and $ACCOUNT (login)"
getent passwd keyroster-agent >/dev/null || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin keyroster-agent
getent passwd "$ACCOUNT" >/dev/null || useradd --create-home --shell /bin/sh "$ACCOUNT"
id keyroster-agent
id "$ACCOUNT"

step "Build (CGO_ENABLED=0) as ${SUDO_USER:-root}"
bin=$work/bin
mkdir "$bin"
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
	chown "$SUDO_USER" "$bin"
	home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
	build=(runuser -u "$SUDO_USER" -- env HOME="$home" PATH="$PATH")
else
	build=(env)
fi
for cmd in keyroster-agent keyroster-agent-fetch; do
	"${build[@]}" CGO_ENABLED=0 go -C "$repo" build -trimpath -o "$bin/$cmd" "./cmd/$cmd"
done
"${build[@]}" CGO_ENABLED=0 go -C "$repo" test -c -tags "e2e systemdsmoke" -o "$bin/agentsmoke.test" ./test/e2e/
install -m 0755 -o root -g root "$bin/keyroster-agent" "$bin/keyroster-agent-fetch" /usr/local/bin/
modcache=$("${build[@]}" go env GOMODCACHE)

step "TestAgentSystemdSmoke (install, both units, enrollment, apply, login, heartbeat)"
(cd "$repo/test/e2e" && env GOMODCACHE="$modcache" GOFLAGS=-mod=readonly KEYROSTER_OPENSSH_PREFIX=/usr KEYROSTER_SMOKE_ACCOUNT="$ACCOUNT" \
	"$bin/agentsmoke.test" -test.run '^TestAgentSystemdSmoke$' -test.v -test.count=1 -test.timeout 15m)

step "The units systemd loaded"
systemctl show -p User -p NoNewPrivileges -p ProtectSystem -p ReadWritePaths -p CapabilityBoundingSet keyroster-agent-fetch.service
systemctl show -p User -p NoNewPrivileges -p ProtectSystem -p ReadWritePaths -p IPAddressDeny -p IPAddressAllow keyroster-agent.service
[ "$(systemctl show -p User --value keyroster-agent-fetch.service)" = keyroster-agent ] || fail "the fetcher does not run as keyroster-agent"
[ "$(systemctl show -p ReadWritePaths --value keyroster-agent-fetch.service)" = "/var/lib/keyroster-agent-fetch /var/lib/keyroster-agent/spool" ] ||
	fail "the fetcher's ReadWritePaths"
[ "$(systemctl show -p ReadWritePaths --value keyroster-agent.service)" = "/etc/ssh/keyroster /etc/ssh/sshd_config.d /var/lib/keyroster-agent" ] ||
	fail "the applier's ReadWritePaths"
fetch_pid=$(systemctl show -p MainPID --value keyroster-agent-fetch.service)
[ "$fetch_pid" -gt 0 ] || fail "the fetcher is not running"
grep -E '^(Uid|CapEff|NoNewPrivs|Seccomp):' "/proc/$fetch_pid/status"
grep -qE '^CapEff:[[:space:]]+0+$' "/proc/$fetch_pid/status" || fail "the fetcher has capabilities"
grep -qE '^NoNewPrivs:[[:space:]]+1$' "/proc/$fetch_pid/status" || fail "the fetcher lacks no_new_privs"

step "Cross-user writes as the real keyroster-agent user (F2)"
as_fetch() { setpriv --reuid=keyroster-agent --regid=keyroster-agent --init-groups -- "$@"; }
# deny DESCRIPTION COMMAND...: the command must fail with Permission denied.
deny() {
	local what=$1 out
	shift
	if out=$(as_fetch "$@" 2>&1); then
		fail "keyroster-agent could $what"
	fi
	case $out in
	*"Permission denied"*) echo "refused as keyroster-agent: $what ($out)" ;;
	*) fail "$what: failed, but not with Permission denied: $out" ;;
	esac
}
ls -la "$STATE" "$STATE/outbox"
for f in pins.json outbox/status.json outbox/accepted.json; do
	[ -f "$STATE/$f" ] || fail "$STATE/$f is missing"
done
deny "create a file in the state directory (where pending.json lives)" touch "$STATE/x"
deny "create a file in accepted/" touch "$STATE/accepted/x"
deny "create a file in the outbox" touch "$STATE/outbox/x"
deny "overwrite pins.json" sh -c "printf x > $STATE/pins.json"
deny "overwrite outbox/status.json" sh -c "printf x > $STATE/outbox/status.json"
deny "overwrite outbox/accepted.json" sh -c "printf x > $STATE/outbox/accepted.json"
deny "replace outbox/status.json by a rename" sh -c "printf x > $STATE/spool/.s && mv -f $STATE/spool/.s $STATE/outbox/status.json"
as_fetch rm -f "$STATE/spool/.s"
as_fetch cat "$STATE/outbox/status.json" >/dev/null || fail "keyroster-agent cannot read outbox/status.json"
echo "read as keyroster-agent: outbox/status.json"
as_fetch touch "$STATE/spool/.smoke-write" || fail "keyroster-agent cannot write in the spool"
as_fetch rm "$STATE/spool/.smoke-write"
echo "allowed as keyroster-agent: create and remove a file in the spool"
stat -c '%U:%G %a %n' "$STATE" "$STATE/accepted" "$STATE/outbox" "$STATE/spool" "$STATE/pins.json" "$STATE/outbox/status.json" "$STATE/outbox/accepted.json"

step "systemd-analyze security, fetcher unit (threshold $FETCH_THRESHOLD = exposure $((FETCH_THRESHOLD / 10)).$((FETCH_THRESHOLD % 10)))"
systemd-analyze security --no-pager --threshold="$FETCH_THRESHOLD" keyroster-agent-fetch.service
step "systemd-analyze security, applier unit (threshold $APPLY_THRESHOLD = exposure $((APPLY_THRESHOLD / 10)).$((APPLY_THRESHOLD % 10)))"
systemd-analyze security --no-pager --threshold="$APPLY_THRESHOLD" keyroster-agent.service

step "agent smoke test passed"
