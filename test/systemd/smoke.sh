#!/usr/bin/env bash
# Smoke test of the sandboxed signer on a real systemd host (KEY-01, D-08).
#
#   sudo env "PATH=$PATH" bash test/systemd/smoke.sh
#
# Runs as root and changes the host: it installs both binaries in
# /usr/local/bin, the sysusers file and both units, creates the users
# keyroster-signer, kradmin and outsider, and starts the units. Run it only on
# a throwaway host; CI runs it in the systemd-sandbox job
# (.github/workflows/systemd.yml).
#
# It replays the e2e bootstrap (test/e2e/bootstrap_test.go) against the
# installed units: the signer's own ssh-agent unit holds five generated role
# keys (agent backend), ca-init and install-bundle run as keyroster-signer,
# a software root in a temporary agent signs the genesis bundle, and then
# keyroster-signer.service starts. It checks that
#   - kradmin (member of keyroster-admin) issues a certificate over the socket,
#     signed by the user CA, and outsider (not a member) cannot connect;
#   - the running signer's network namespace contains only lo;
#   - systemd reports the core sandbox settings and the process runs as
#     keyroster-signer with no capabilities, no_new_privs and seccomp;
#   - systemd-analyze security rates the unit at or below THRESHOLD
#     (exposure x10; 20 = 2.0).
#
# The TPM drop-in is not installed here: the runner has no TPM, and its
# SupplementaryGroups=tss needs the tss group. The TPM path under systemd is
# first exercised by the homelab VM in plan 01-14.
set -euo pipefail

THRESHOLD=${KEYROSTER_SECURITY_THRESHOLD:-20}

SIGNER_SOCK=/run/keyroster-signer/signer.sock
AGENT_SOCK=/run/keyroster-signer-agent/agent.sock
STATE=/var/lib/keyroster-signer

step() { printf '\n=== %s\n' "$*"; }
fail() {
	echo "FAIL: $*" >&2
	exit 1
}

[ "$(id -u)" = 0 ] || {
	echo "smoke.sh: run as root" >&2
	exit 2
}
[ -d /run/systemd/system ] || {
	echo "smoke.sh: not a systemd host" >&2
	exit 2
}

repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d /tmp/keyroster-smoke.XXXXXX)
chmod 0711 "$work"
agent_pids=()
cleanup() {
	for pid in "${agent_pids[@]}"; do
		kill "$pid" 2>/dev/null || true
	done
}
trap cleanup EXIT

as_signer() { runuser -u keyroster-signer -- env -i PATH=/usr/local/bin:/usr/bin:/bin "$@"; }
as_user() {
	local u=$1
	shift
	runuser -u "$u" -- env -i HOME="/home/$u" PATH=/usr/local/bin:/usr/bin:/bin "$@"
}
fp_of() { ssh-keygen -lf "$1" | awk '{print $2}'; }
wait_socket() {
	local path=$1
	for _ in $(seq 1 100); do
		[ -S "$path" ] && return 0
		sleep 0.1
	done
	fail "socket $path did not appear"
}
# start_agent USER SOCKET: start an ssh-agent as USER on SOCKET and record
# its pid for cleanup.
start_agent() {
	local u=$1 sock=$2 out
	out=$(as_user "$u" ssh-agent -s -a "$sock")
	agent_pids+=("$(sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p' <<<"$out")")
	wait_socket "$sock"
}

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
for cmd in keyroster keyroster-signer; do
	"${build[@]}" CGO_ENABLED=0 go -C "$repo" build -trimpath -o "$bin/$cmd" "./cmd/$cmd"
done
install -m 0755 -o root -g root "$bin/keyroster" "$bin/keyroster-signer" /usr/local/bin/
keyroster-signer version

step "Install sysusers and units"
install -D -m 0644 "$repo/deploy/sysusers.d/keyroster.conf" /etc/sysusers.d/keyroster.conf
systemd-sysusers /etc/sysusers.d/keyroster.conf
getent passwd keyroster-signer
getent group keyroster-admin
install -m 0644 "$repo/deploy/systemd/keyroster-signer.service" "$repo/deploy/systemd/keyroster-signer-agent.service" /etc/systemd/system/
systemctl daemon-reload
useradd --create-home --shell /bin/bash --groups keyroster-admin kradmin
useradd --create-home --shell /bin/bash outsider
id kradmin
id outsider
# ca-init and install-bundle run before the unit first starts, so the state
# directory is created here with the mode and owner StateDirectory= keeps.
install -d -o keyroster-signer -g keyroster-signer -m 0700 "$STATE"

step "Start the signer's ssh-agent unit and load five role keys"
systemctl start keyroster-signer-agent.service
wait_socket "$AGENT_SOCK"
keys=$work/role-keys
install -d -o keyroster-signer -g keyroster-signer -m 0700 "$keys"
keyargs=()
for role in user host machine ops log; do
	as_signer ssh-keygen -q -t ed25519 -N '' -C "$role-key" -f "$keys/$role"
	as_signer env SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -q "$keys/$role"
	keyargs+=(--key "$role=$(fp_of "$keys/$role.pub")")
done
as_signer env SSH_AUTH_SOCK="$AGENT_SOCK" ssh-add -l

step "ca-init as keyroster-signer (agent backend)"
as_signer keyroster-signer ca-init --state-dir "$STATE" --backend agent \
	--backend-opt "socket=$AGENT_SOCK" "${keyargs[@]}"

step "Root ceremony: genesis policy with kradmin's admin key, software root in a temporary agent"
as_user kradmin ssh-keygen -q -t ed25519 -N '' -C kradmin-admin -f /home/kradmin/admin
admin_fp=$(fp_of /home/kradmin/admin.pub)
cer=$work/ceremony
install -d -m 0700 "$cer"
keyroster root genesis-policy --admin "kradmin=/home/kradmin/admin.pub" --out "$cer/genesis-policy.json"
ssh-keygen -q -t ed25519 -N '' -C root -f "$cer/root"
root_fp=$(fp_of "$cer/root.pub")
printf '%s custody=software\n' "$(cut -d' ' -f1,2 "$cer/root.pub")" >"$cer/roots.pub"
root_out=$(ssh-agent -s -a "$cer/root-agent.sock")
root_agent_pid=$(sed -n 's/^SSH_AGENT_PID=\([0-9]*\);.*/\1/p' <<<"$root_out")
agent_pids+=("$root_agent_pid")
wait_socket "$cer/root-agent.sock"
SSH_AUTH_SOCK="$cer/root-agent.sock" ssh-add -q "$cer/root"
sign=(keyroster root sign --ca-pubkeys "$STATE/ca-pubkeys.json" --policy "$cer/genesis-policy.json"
	--roots "$cer/roots.pub" --threshold 1 --out-dir "$cer/bundle" --agent-key "$root_fp")
# A wrong confirmation writes bundle.json and signs nothing; the second run
# confirms the real hash prefix.
if SSH_AUTH_SOCK="$cer/root-agent.sock" "${sign[@]}" --confirm 00000000 >"$work/sign0.log" 2>&1; then
	cat "$work/sign0.log"
	fail "root sign accepted a wrong confirmation"
fi
grep -q 'nothing was signed' "$work/sign0.log" || {
	cat "$work/sign0.log"
	fail "root sign failed for another reason than the confirmation"
}
SSH_AUTH_SOCK="$cer/root-agent.sock" "${sign[@]}" --confirm "$(sha256sum "$cer/bundle/bundle.json" | cut -c1-8)"
kill "$root_agent_pid"

step "install-bundle as keyroster-signer"
in=$work/bundle-in
install -d -o keyroster-signer -g keyroster-signer -m 0700 "$in"
install -o keyroster-signer -g keyroster-signer -m 0600 "$cer"/bundle/* "$in/"
as_signer keyroster-signer install-bundle --state-dir "$STATE" --threshold 1 --pin "$root_fp" \
	--bundle "$in/bundle.json" --policy "$in/policy.json"

step "Start keyroster-signer.service"
systemctl start keyroster-signer.service
wait_socket "$SIGNER_SOCK"
systemctl --no-pager status keyroster-signer.service || true
ls -l "$SIGNER_SOCK"
[ "$(stat -c '%a %G' "$SIGNER_SOCK")" = "660 keyroster-admin" ] || fail "socket mode/group is $(stat -c '%a %G' "$SIGNER_SOCK"), want 660 keyroster-admin"

step "kradmin (keyroster-admin) issues a user certificate over the socket"
start_agent kradmin /home/kradmin/agent.sock
as_user kradmin env SSH_AUTH_SOCK=/home/kradmin/agent.sock ssh-add -q /home/kradmin/admin
as_user kradmin ssh-keygen -q -t ed25519 -N '' -C alice -f /home/kradmin/alice
as_user kradmin env SSH_AUTH_SOCK=/home/kradmin/agent.sock keyroster ca issue \
	--socket "$SIGNER_SOCK" --admin-key "$admin_fp" \
	--pubkey /home/kradmin/alice.pub --principal alice --subject u:alice --ttl 10m
cert=/home/kradmin/alice-cert.pub
[ -s "$cert" ] || fail "no certificate written to $cert"
ssh-keygen -L -f "$cert"
user_ca_fp=$(fp_of "$keys/user.pub")
ssh-keygen -L -f "$cert" | grep -q "Signing CA: ED25519 $user_ca_fp" || fail "certificate not signed by the user CA $user_ca_fp"
echo "certificate issued by kradmin, signed by user CA $user_ca_fp"

step "outsider (not in keyroster-admin) cannot reach the signer, even holding the admin key"
# outsider gets a copy of kradmin's admin key, so the request carries valid
# admin evidence; only the socket's group permission stops it.
install -o outsider -g outsider -m 0600 /home/kradmin/admin /home/outsider/admin
start_agent outsider /home/outsider/agent.sock
as_user outsider env SSH_AUTH_SOCK=/home/outsider/agent.sock ssh-add -q /home/outsider/admin
as_user outsider ssh-keygen -q -t ed25519 -N '' -C bob -f /home/outsider/bob
if as_user outsider env SSH_AUTH_SOCK=/home/outsider/agent.sock keyroster ca issue --socket "$SIGNER_SOCK" --admin-key "$admin_fp" \
	--pubkey /home/outsider/bob.pub --principal bob --subject u:bob --ttl 10m >"$work/outsider.log" 2>&1; then
	cat "$work/outsider.log"
	fail "outsider issued a certificate"
fi
cat "$work/outsider.log"
grep -qi 'permission denied' "$work/outsider.log" || fail "outsider was refused for another reason than socket permissions"
[ ! -e /home/outsider/bob-cert.pub ] || fail "outsider got a certificate file"

step "The signer's network namespace contains only lo"
pid=$(systemctl show -p MainPID --value keyroster-signer.service)
[ -n "$pid" ] && [ "$pid" != 0 ] || fail "keyroster-signer has no main pid"
nsenter -t "$pid" -n ip -br link
links=$(nsenter -t "$pid" -n ip -br link | awk '{print $1}' | sort | tr '\n' ' ')
[ "$links" = "lo " ] || fail "signer network namespace has links: $links"
nsenter -t "$pid" -n ip -br addr

step "Sandbox properties of the running unit"
props=$(systemctl show -p PrivateNetwork,NoNewPrivileges,RestrictAddressFamilies,User,UMask,LimitCORE keyroster-signer.service)
echo "$props"
for want in PrivateNetwork=yes NoNewPrivileges=yes RestrictAddressFamilies=AF_UNIX User=keyroster-signer UMask=0077 LimitCORE=0; do
	grep -qx "$want" <<<"$props" || fail "systemctl show: want $want"
done
ps -o user=,group=,supgrp=,cmd= -p "$pid"
[ "$(ps -o user= -p "$pid" | tr -d ' ')" = keyroster-signer ] || fail "signer does not run as keyroster-signer"
grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' "/proc/$pid/status"
grep -qx $'CapEff:\t0000000000000000' "/proc/$pid/status" || fail "signer has effective capabilities"
grep -qx $'CapBnd:\t0000000000000000' "/proc/$pid/status" || fail "signer has a non-empty bounding set"
grep -qx $'NoNewPrivs:\t1' "/proc/$pid/status" || fail "no_new_privs not set"
grep -qx $'Seccomp:\t2' "/proc/$pid/status" || fail "no seccomp filter"

step "systemd-analyze security (threshold $THRESHOLD = exposure $((THRESHOLD / 10)).$((THRESHOLD % 10)))"
systemd-analyze security --no-pager keyroster-signer-agent.service | tail -n 1
systemd-analyze security --no-pager --threshold="$THRESHOLD" keyroster-signer.service

step "PASS"
