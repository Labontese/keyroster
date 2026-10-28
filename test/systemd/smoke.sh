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
#   - keyroster-signer doctor passes as keyroster-signer and states the
#     weaker custody of this test setup (SOFTWARE ROOT, plain keys in
#     ssh-agent), and fails when run as root;
#   - systemd parsed the signer's restart policy: no restart on exit 78,
#     restarts spaced and capped;
#   - the signer's ssh-agent unit, which holds the CA keys, runs as
#     keyroster-signer with no capabilities, no_new_privs and seccomp, and
#     systemd reports its sandbox settings (MemoryDenyWriteExecute,
#     localhost-only IP, address families);
#   - systemd-analyze security rates the signer unit at or below THRESHOLD
#     and the agent unit at or below AGENT_THRESHOLD (exposure x10; 20 = 2.0);
#   - signer-install.md's restore hold refuses every start of the signer and
#     server units, its file restore refuses while signer.lock is held, puts
#     signer.db and the backup's -wal back as keyroster-signer 0600 and
#     removes a stale -shm the backup does not have, and after its release
#     the signer starts and doctor passes, also
#     when it had crash-looped into its start limit before the hold;
#   - signer-install.md's step 3 copy of the replay proposal to an admin
#     refuses a link the admin planted, changes nothing it points at, and
#     otherwise writes the files as the admin;
#   - signer-install.md's capture of keyroster-server's KRL copy, under the
#     hold, stops without the server's state directory, prints "no server
#     KRL copy" without the file, refuses an existing /root/recovery, stops
#     on a state directory it cannot list and on a krl-served.json that is
#     a dangling link, a link to /dev/zero, a FIFO, a mode-000 file or one
#     byte too large (writing at most that many bytes), and keeps a copy
#     equal to the server's file byte for byte; step 2b's copy block
#     refuses a link the admin planted at ~/recovery-in and otherwise
#     writes the inputs as the admin, with the server copy and without it;
#     its read-back block stops on a request planted as a FIFO, a link to
#     /dev/zero or a dangling link, and reads the admin's request as the
#     admin; its recovery line refuses a request that does not parse
#     (recovery_malformed) and leaves signer.db as it was; after that
#     refusal the read-back stops with its reason, the move block moves the
#     refused request aside inside /root/recovery, and a new request is read
#     back and refused the same way; and the release check passes on
#     fixture exports whose restored log already holds a recovery, and
#     stops on a kept copy whose version was not imported and on a
#     recovered log that adds nothing (03-06c, PR #70 review).
#
# The TPM drop-in is not installed here: the runner has no TPM, and its
# SupplementaryGroups=tss needs the tss group. The TPM path under systemd is
# first exercised by the homelab VM in plan 01-14.
set -euo pipefail

THRESHOLD=${KEYROSTER_SECURITY_THRESHOLD:-20}
AGENT_THRESHOLD=${KEYROSTER_AGENT_SECURITY_THRESHOLD:-14}

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
# On the ubuntu-24.04 runner this key came out mode 0644 (observed on PR
# #15; the cause was not investigated), and ssh-add refuses such a key.
chmod 0600 /home/kradmin/admin
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

step "Restart policy of keyroster-signer.service"
# D-CR-01: exit status 78 (a refused PIV PIN or TPM auth value) must not be
# restarted, and restarts are spaced and capped, so a wrong secret cannot
# spend the device's limited attempts in a loop. This checks that systemd
# parsed the unit as intended (StartLimit* is ignored outside [Unit]); a run
# that really exits 78 needs a PIV card or a TPM and is not part of CI.
props=$(systemctl show -p Restart,RestartUSec,RestartPreventExitStatus,StartLimitBurst,StartLimitIntervalUSec keyroster-signer.service)
echo "$props"
for want in Restart=on-failure RestartUSec=5s RestartPreventExitStatus=78 StartLimitBurst=5 StartLimitIntervalUSec=10min; do
	grep -qx "$want" <<<"$props" || fail "systemctl show: want $want"
done

step "Sandbox properties of the running ssh-agent unit (holds the CA keys)"
# E-WR-05: the agent keeps the host network namespace and loads PKCS#11
# modules, so a weakened agent unit must fail CI as the signer's would.
# systemd-analyze below misses some regressions (MemoryDenyWriteExecute
# removed, IPAddressAllow widened), so they are asserted here.
agent_pid=$(systemctl show -p MainPID --value keyroster-signer-agent.service)
[ -n "$agent_pid" ] && [ "$agent_pid" != 0 ] || fail "keyroster-signer-agent has no main pid"
props=$(systemctl show -p NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,MemoryDenyWriteExecute,User,UMask,LimitCORE keyroster-signer-agent.service)
echo "$props"
for want in NoNewPrivileges=yes ProtectSystem=strict ProtectHome=yes PrivateTmp=yes MemoryDenyWriteExecute=yes User=keyroster-signer UMask=0077 LimitCORE=0; do
	grep -qx "$want" <<<"$props" || fail "agent unit, systemctl show: want $want"
done
# List properties are compared as sorted word sets, independent of the order
# systemd prints them in. localhost is 127.0.0.0/8 and ::1/128; any is
# 0.0.0.0/0 and ::/0.
words() { systemctl show -p "$2" --value "$1" | tr ' ' '\n' | sed '/^$/d' | LC_ALL=C sort | paste -sd' ' -; }
for want in "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" "IPAddressAllow=127.0.0.0/8 ::1/128" "IPAddressDeny=0.0.0.0/0 ::/0"; do
	got=$(words keyroster-signer-agent.service "${want%%=*}")
	echo "${want%%=*}=$got"
	[ "$got" = "${want#*=}" ] || fail "agent unit, systemctl show: want $want"
done
ps -o user=,group=,cmd= -p "$agent_pid"
[ "$(ps -o user= -p "$agent_pid" | tr -d ' ')" = keyroster-signer ] || fail "agent does not run as keyroster-signer"
grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' "/proc/$agent_pid/status"
grep -qx $'CapEff:\t0000000000000000' "/proc/$agent_pid/status" || fail "agent has effective capabilities"
grep -qx $'CapBnd:\t0000000000000000' "/proc/$agent_pid/status" || fail "agent has a non-empty bounding set"
grep -qx $'NoNewPrivs:\t1' "/proc/$agent_pid/status" || fail "agent: no_new_privs not set"
grep -qx $'Seccomp:\t2' "/proc/$agent_pid/status" || fail "agent: no seccomp filter"

step "keyroster-signer doctor on the live state (expects WARNs for this test custody)"
if as_signer keyroster-signer doctor --state-dir "$STATE" >"$work/doctor.log" 2>&1; then
	doctor_rc=0
else
	doctor_rc=$?
fi
cat "$work/doctor.log"
[ "$doctor_rc" = 0 ] || fail "doctor exited $doctor_rc"
grep -q "^WARN software_root: SOFTWARE ROOT: root $root_fp" "$work/doctor.log" || fail "doctor did not flag the software root"
grep -q '^WARN software_key_in_agent:' "$work/doctor.log" || fail "doctor did not flag plain keys in ssh-agent"
if grep -q '^OK custody:' "$work/doctor.log"; then
	fail "doctor reported hardware custody for agent-held keys"
fi
# Run as root, doctor fails: the signer's state belongs to keyroster-signer.
if keyroster-signer doctor --state-dir "$STATE" >"$work/doctor-root.log" 2>&1; then
	cat "$work/doctor-root.log"
	fail "doctor passed when run as root"
fi
grep -q '^FAIL running_as_root:' "$work/doctor-root.log" || {
	cat "$work/doctor-root.log"
	fail "doctor as root did not report running_as_root"
}

step "systemd-analyze security, agent unit (threshold $AGENT_THRESHOLD = exposure $((AGENT_THRESHOLD / 10)).$((AGENT_THRESHOLD % 10)))"
systemd-analyze security --no-pager --threshold="$AGENT_THRESHOLD" keyroster-signer-agent.service

step "systemd-analyze security, signer unit (threshold $THRESHOLD = exposure $((THRESHOLD / 10)).$((THRESHOLD % 10)))"
systemd-analyze security --no-pager --threshold="$THRESHOLD" keyroster-signer.service

step "Restore hold, file restore and release (docs/runbooks/signer-install.md, verbatim)"
# The three blocks below are the runbook's, as TestRestoreRunbookChecks
# (test/e2e/restore_test.go) requires. keyroster-server's unit is installed
# only to be held: no server runs here.
install -m 0644 "$repo/deploy/systemd/keyroster-server.service" /etc/systemd/system/
systemctl daemon-reload
# The signer to be restored crash-looped (a damaged database, say) until its
# start limit stopped it. A temporary drop-in makes it fail at once and
# restart quickly; it is removed before the hold. The release must reset
# the unit, or the start after it is refused.
crash=/etc/systemd/system/keyroster-signer.service.d/smoke-crash.conf
install -d -m 0755 /etc/systemd/system/keyroster-signer.service.d
printf '[Service]\nExecStart=\nExecStart=/bin/false\nRestartSec=100ms\n' >"$crash"
systemctl daemon-reload
systemctl restart keyroster-signer.service || true
for _ in $(seq 1 100); do
	[ "$(systemctl show -p ActiveState --value keyroster-signer.service)" = failed ] && break
	sleep 0.1
done
systemctl show -p ActiveState,Result,NRestarts keyroster-signer.service
[ "$(systemctl show -p ActiveState --value keyroster-signer.service)" = failed ] || fail "the crash-looping signer did not stop at its start limit"
rm "$crash"
systemctl daemon-reload
bash -eu -s keyroster-server keyroster-signer <<'EOF'
test "$#" -gt 0
for u in "$@"; do
  install -d -m 0755 "/etc/systemd/system/$u.service.d"
  printf '[Unit]\nAssertPathExists=/nonexistent-restore-hold\n' >"/etc/systemd/system/$u.service.d/restore-hold.conf"
done
systemctl daemon-reload
for u in "$@"; do
  systemctl stop "$u.service"
done
for u in "$@"; do
  test "$(systemctl show -p LoadState --value "$u.service")" = loaded
  systemctl show -p DropInPaths --value "$u.service" | grep -q "/$u.service.d/restore-hold.conf"
  if systemctl start "$u.service"; then
    systemctl stop "$u.service"
    echo "$u.service started: the hold is NOT in force" >&2
    exit 1
  fi
done
echo "held: $*"
EOF
# The refusal is the assertion, not another failure.
for u in keyroster-server keyroster-signer; do
	if systemctl start "$u.service" 2>"$work/hold-$u.log"; then
		fail "$u.service started under the hold"
	fi
	cat "$work/hold-$u.log"
	grep -q "Assertion failed on job for $u.service" "$work/hold-$u.log" || fail "$u.service was refused for another reason than the hold"
done
systemctl is-active --quiet keyroster-signer.service && fail "keyroster-signer.service is active under the hold"

step "Restore: keep keyroster-server's KRL copy, right after the hold (docs/runbooks/signer-install.md, verbatim)"
# The capture block reads the server's file as keyroster-server and prints
# exactly one of its two lines; without the server's state directory it
# claims neither.
capture() {
	bash -eu <<'EOF'
runuser -u keyroster-server -- test -d /var/lib/keyroster-server -a -x /var/lib/keyroster-server
test ! -e /root/recovery
install -d -m 0700 /root/recovery
listed=$(runuser -u keyroster-server -- find -H /var/lib/keyroster-server -maxdepth 1 -name krl-served.json -print)
if [ -n "$listed" ]; then
  runuser -u keyroster-server -- test -f /var/lib/keyroster-server/krl-served.json
  runuser -u keyroster-server -- head -c 5620745 /var/lib/keyroster-server/krl-served.json > /root/recovery/server-krl.json
  test -s /root/recovery/server-krl.json
  test "$(stat -c %s /root/recovery/server-krl.json)" -le 5620744
  echo "kept: /root/recovery/server-krl.json"
else
  echo "no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist"
fi
EOF
}
# capture_stops NAME: the capture block, under a timeout so that a block
# that waits fails the test, must stop without claiming either outcome and
# write at most 5 620 745 bytes; /root/recovery is cleared for the next case.
export -f capture
capture_stops() {
	local log=$work/capture-$1.log
	if timeout 60 bash -c capture >"$log" 2>&1; then
		cat "$log"
		fail "the capture block passed: $1"
	fi
	cat "$log"
	if grep -q 'kept:\|no server KRL copy' "$log"; then
		fail "the capture block claimed an outcome: $1"
	fi
	if [ -e /root/recovery/server-krl.json ] && [ "$(stat -c %s /root/recovery/server-krl.json)" -gt 5620745 ]; then
		fail "the capture block copied more than 5 620 745 bytes: $1"
	fi
	rm -rf /root/recovery
}
srv_state=/var/lib/keyroster-server
[ ! -e "$srv_state" ] || fail "$srv_state exists on this host"
[ ! -e /root/recovery ] || fail "/root/recovery exists on this host"
if capture >"$work/capture-nodir.log" 2>&1; then
	cat "$work/capture-nodir.log"
	fail "the capture block passed without keyroster-server's state directory"
fi
cat "$work/capture-nodir.log"
if grep -q 'kept:\|no server KRL copy' "$work/capture-nodir.log"; then
	fail "the capture block claimed an outcome without keyroster-server's state directory"
fi
[ ! -e /root/recovery ] || fail "the capture block created /root/recovery without keyroster-server's state directory"
# The state directory with the owner and mode the unit's StateDirectory=
# keyroster-server and StateDirectoryMode=0700 give it; no copy yet.
install -d -o keyroster-server -g keyroster-server -m 0700 "$srv_state"
capture | tee "$work/capture-none.log"
grep -qx 'no server KRL copy: /var/lib/keyroster-server/krl-served.json does not exist' "$work/capture-none.log" || fail "the capture block did not report the missing copy"
[ "$(stat -c '%a %U' /root/recovery)" = "700 root" ] || fail "/root/recovery is $(stat -c '%a %U' /root/recovery)"
[ -z "$(ls -A /root/recovery)" ] || fail "the capture block left a copy of a file that does not exist: $(ls -A /root/recovery)"
if capture >"$work/capture-again.log" 2>&1; then
	cat "$work/capture-again.log"
	fail "the capture block ran over an existing /root/recovery"
fi
cat "$work/capture-again.log"
rm -r /root/recovery
# A listing that fails (here a state directory the server account can
# search but not read) is not "no server KRL copy" (PR #70 review, F5).
chmod 0300 "$srv_state"
capture_stops unreadable-dir
chmod 0700 "$srv_state"
# A krl-served.json the server account cannot copy as a regular file of at
# most 5 620 744 bytes (PR #70 review, F8 and F15): a link that leads
# nowhere, a link to /dev/zero, a FIFO, a file of mode 000 and a file one
# byte too large.
srv_file=$srv_state/krl-served.json
as_user keyroster-server ln -s "$srv_state/nowhere" "$srv_file"
capture_stops dangling-link
as_user keyroster-server ln -sf /dev/zero "$srv_file"
capture_stops dev-zero-link
rm "$srv_file"
as_user keyroster-server mkfifo -m 0600 "$srv_file"
capture_stops fifo
rm "$srv_file"
as_user keyroster-server sh -c ': >"$1" && chmod 000 "$1"' sh "$srv_file"
capture_stops mode-000
rm "$srv_file"
as_user keyroster-server sh -c 'umask 077 && head -c 5620745 /dev/zero >"$1"' sh "$srv_file"
capture_stops too-large
rm "$srv_file"
krl_fixture=$work/krl-served.fixture
printf '{"krl":"Zml4dHVyZQ==","manifest":"Zml4dHVyZQ==","sig":"Zml4dHVyZQ=="}\n' >"$krl_fixture"
# A state directory that is a link to a directory elsewhere (state kept on
# another disk, say): the listing follows the link, so the copy behind it
# is kept, and a listing of an unreadable directory behind it fails (PR #70
# review round 2). find without -H lists nothing behind a linked start
# point and exits 0, which claimed "no server KRL copy" for both.
srv_real=/var/lib/keyroster-server-data
[ ! -e "$srv_real" ] || fail "$srv_real exists on this host"
mv "$srv_state" "$srv_real"
ln -s "$srv_real" "$srv_state"
runuser -u keyroster-server -- sh -c 'umask 077 && cat >"$1"' sh "$srv_file" <"$krl_fixture"
capture | tee "$work/capture-linked.log"
grep -qx 'kept: /root/recovery/server-krl.json' "$work/capture-linked.log" || fail "the capture block did not keep the copy behind a linked state directory"
cmp "$krl_fixture" /root/recovery/server-krl.json || fail "the copy kept behind a linked state directory differs from the server's file"
rm -r /root/recovery
chmod 0300 "$srv_real"
capture_stops linked-unreadable-dir
chmod 0700 "$srv_real"
rm "$srv_file" "$srv_state"
mv "$srv_real" "$srv_state"
if [ -L "$srv_state" ] || [ ! -d "$srv_state" ]; then
	fail "$srv_state is not a directory again"
fi
# A copy written as keyroster-server (a fixture: no server runs here).
runuser -u keyroster-server -- sh -c 'umask 077 && cat >"$1"' sh "$srv_file" <"$krl_fixture"
capture | tee "$work/capture-kept.log"
grep -qx 'kept: /root/recovery/server-krl.json' "$work/capture-kept.log" || fail "the capture block did not keep the server's copy"
cmp "$krl_fixture" /root/recovery/server-krl.json || fail "the kept copy differs from the server's file"
cmp "$krl_fixture" "$srv_state/krl-served.json" || fail "the capture block changed the server's file"
backup=$work/signer-backup
install -d -m 0700 "$backup"
for f in signer.db signer.db-wal signer.db-shm; do
	[ ! -e "$STATE/$f" ] || cp -p "$STATE/$f" "$backup/$f"
done
# The backup set has a -wal (empty: a WAL without frames) and no -shm, and
# the live state directory has stale -wal and -shm files: the restore must
# replace the -wal with the backup's and remove the -shm. A real WAL with
# frames is not built here.
[ -e "$backup/signer.db-wal" ] || : >"$backup/signer.db-wal"
rm -f "$backup/signer.db-shm"
for f in signer.db-wal signer.db-shm; do
	printf 'stale %s\n' "$f" >"$STATE/$f"
	chown keyroster-signer:keyroster-signer "$STATE/$f"
	chmod 0600 "$STATE/$f"
done
ls -l "$backup" "$STATE"
file_restore() {
	bash -eu -s "$1" <<'EOF'
S=/var/lib/keyroster-signer
test -e /etc/systemd/system/keyroster-signer.service.d/restore-hold.conf
st=$(systemctl show -p ActiveState --value keyroster-signer.service)
if [ "$st" != inactive ] && [ "$st" != failed ]; then
  echo "keyroster-signer.service is $st: hold it first" >&2
  exit 1
fi
exec 9<"$S/signer.lock"
if ! flock -n 9; then
  echo "$S is in use by another keyroster-signer process" >&2
  exit 1
fi
test -s "$1/signer.db"
rm -f "$S/signer.db" "$S/signer.db-wal" "$S/signer.db-shm"
for f in signer.db signer.db-wal signer.db-shm; do
  if [ -e "$1/$f" ]; then
    install -o keyroster-signer -g keyroster-signer -m 0600 "$1/$f" "$S/$f"
  fi
done
echo "restored signer.db from $1"
EOF
}
# Another keyroster-signer process (here a stand-in that holds the lock, as
# serve, ca-init and install-bundle do) makes the file restore refuse before
# it removes anything.
flock -o "$STATE/signer.lock" sleep 300 &
locker=$!
agent_pids+=("$locker")
for _ in $(seq 1 50); do
	flock -n "$STATE/signer.lock" true || break
	sleep 0.1
done
db_before=$(sha256sum "$STATE/signer.db")
if file_restore "$backup" >"$work/restore-locked.log" 2>&1; then
	cat "$work/restore-locked.log"
	fail "the file restore ran while the signer's lock was held"
fi
cat "$work/restore-locked.log"
grep -q 'is in use by another keyroster-signer process' "$work/restore-locked.log" || fail "the file restore refused for another reason than the lock"
[ "$(sha256sum "$STATE/signer.db")" = "$db_before" ] || fail "the refused file restore changed signer.db"
grep -qx 'stale signer.db-shm' "$STATE/signer.db-shm" || fail "the refused file restore changed signer.db-shm"
pkill -P "$locker" sleep || true
wait "$locker" || true
file_restore "$backup"
ls -l "$STATE"
for f in signer.db signer.db-wal; do
	[ "$(stat -c '%a %U %G' "$STATE/$f")" = "600 keyroster-signer keyroster-signer" ] || fail "restored $f is $(stat -c '%a %U %G' "$STATE/$f")"
	cmp "$backup/$f" "$STATE/$f" || fail "restored $f differs from the backup's"
done
[ ! -e "$STATE/signer.db-shm" ] || fail "the stale signer.db-shm, which the backup does not have, is still there"

step "Restore step 2b: copy, read-back and recovery line, under the hold (docs/runbooks/signer-install.md, verbatim)"
# The runbook's runuser -G tss needs the group, which the TPM packages
# create on a signer host and this runner may lack.
getent group tss >/dev/null || groupadd --system tss
# Stand-ins for the two exports of step 2 (the copy block reads them as
# root and does not parse them).
[ ! -e /tmp/restored.jsonl ] || fail "/tmp/restored.jsonl exists on this host"
[ ! -e /root/latest-saved.jsonl ] || fail "/root/latest-saved.jsonl exists on this host"
printf '{"fixture":"restored"}\n' >/tmp/restored.jsonl
printf '{"fixture":"saved"}\n' >/root/latest-saved.jsonl
copy_in_block() {
	bash -eu -s kradmin <<'EOF'
A=$1
H=$(getent passwd "$A" | cut -d: -f6)
test -n "$H"
test -d /root/recovery
runuser -u "$A" -- sh -c 'umask 077 && mkdir -m 0700 "$1"' sh "$H/recovery-in"
copy_in() {
  runuser -u "$A" -- sh -c 'umask 077 && set -C && cat >"$1" && chmod 0600 "$1"' sh "$H/recovery-in/$1" <"$2"
}
copy_in restored.jsonl /tmp/restored.jsonl
copy_in latest-saved.jsonl /root/latest-saved.jsonl
files="restored.jsonl latest-saved.jsonl"
if [ -e /root/recovery/server-krl.json ]; then
  copy_in server-krl.json /root/recovery/server-krl.json
  files="$files server-krl.json"
fi
echo "copied $files to $H/recovery-in for $A"
EOF
}
# A link the admin planted at ~/recovery-in: refused, and the directory it
# points at keeps its owner, mode and contents.
rec_canary=$work/recovery-canary
install -d -m 0755 "$rec_canary"
echo keep >"$rec_canary/keep"
rec_canary_state() {
	stat -c '%U %G %a' "$rec_canary"
	ls -A "$rec_canary"
}
rec_canary_before=$(rec_canary_state)
as_user kradmin ln -s "$rec_canary" /home/kradmin/recovery-in
if copy_in_block >"$work/copy-in-link.log" 2>&1; then
	cat "$work/copy-in-link.log"
	fail "the recovery copy block wrote through a link the admin planted"
fi
cat "$work/copy-in-link.log"
[ "$(rec_canary_state)" = "$rec_canary_before" ] || fail "the recovery copy block changed the directory a planted link points at: $(rec_canary_state)"
as_user kradmin rm /home/kradmin/recovery-in
check_copied() {
	[ "$(stat -c '%a %U %G' /home/kradmin/recovery-in)" = "700 kradmin kradmin" ] || fail "recovery-in is $(stat -c '%a %U %G' /home/kradmin/recovery-in)"
	for f in "$@"; do
		[ "$(stat -c '%a %U %G' "/home/kradmin/recovery-in/$f")" = "600 kradmin kradmin" ] || fail "recovery-in/$f is $(stat -c '%a %U %G' "/home/kradmin/recovery-in/$f")"
	done
	cmp /tmp/restored.jsonl /home/kradmin/recovery-in/restored.jsonl || fail "recovery-in/restored.jsonl differs from root's"
	cmp /root/latest-saved.jsonl /home/kradmin/recovery-in/latest-saved.jsonl || fail "recovery-in/latest-saved.jsonl differs from root's"
}
# With the server copy the capture block kept.
copy_in_block | tee "$work/copy-in-kept.log"
grep -qx 'copied restored.jsonl latest-saved.jsonl server-krl.json to /home/kradmin/recovery-in for kradmin' "$work/copy-in-kept.log" || fail "the recovery copy block did not report the three files"
check_copied restored.jsonl latest-saved.jsonl server-krl.json
cmp /root/recovery/server-krl.json /home/kradmin/recovery-in/server-krl.json || fail "recovery-in/server-krl.json differs from root's"
# Without it (the capture block printed no server KRL copy).
as_user kradmin rm -r /home/kradmin/recovery-in
mv /root/recovery/server-krl.json "$work/server-krl.kept"
copy_in_block | tee "$work/copy-in-none.log"
grep -qx 'copied restored.jsonl latest-saved.jsonl to /home/kradmin/recovery-in for kradmin' "$work/copy-in-none.log" || fail "the recovery copy block did not report the two files"
check_copied restored.jsonl latest-saved.jsonl
[ ! -e /home/kradmin/recovery-in/server-krl.json ] || fail "the recovery copy block copied a server copy that was not kept"
[ "$(rec_canary_state)" = "$rec_canary_before" ] || fail "the recovery copy block changed $rec_canary"
read_back() {
	bash -eu -s kradmin <<'EOF'
H=$(getent passwd "$1" | cut -d: -f6)
test -n "$H"
if [ -e /root/recovery/recovery.bin ]; then
  echo "/root/recovery/recovery.bin exists: move the refused request aside first (step 2b)" >&2
  exit 1
fi
runuser -u "$1" -- test -f "$H/recovery-in/recovery.bin"
runuser -u "$1" -- head -c 9470227 "$H/recovery-in/recovery.bin" > /root/recovery/recovery.bin
test -s /root/recovery/recovery.bin
test "$(stat -c %s /root/recovery/recovery.bin)" -le 9470226
echo "read the recovery request back to /root/recovery/recovery.bin"
EOF
}
export -f read_back
# A request the admin planted as a FIFO, a link to /dev/zero or a link
# that leads nowhere: the read-back, under a timeout so that a block that
# waits fails the test, stops without its line and copies nothing (PR #70
# review, F15).
for planted in fifo dev-zero dangling; do
	case $planted in
	fifo) as_user kradmin mkfifo -m 0600 /home/kradmin/recovery-in/recovery.bin ;;
	dev-zero) as_user kradmin ln -s /dev/zero /home/kradmin/recovery-in/recovery.bin ;;
	dangling) as_user kradmin ln -s /home/kradmin/nowhere /home/kradmin/recovery-in/recovery.bin ;;
	esac
	if timeout 60 bash -c read_back >"$work/read-back-$planted.log" 2>&1; then
		cat "$work/read-back-$planted.log"
		fail "the read-back block copied a request planted as $planted"
	fi
	cat "$work/read-back-$planted.log"
	! grep -q 'read the recovery request back' "$work/read-back-$planted.log" || fail "the read-back block claimed a copy of $planted"
	[ ! -e /root/recovery/recovery.bin ] || fail "the read-back block wrote /root/recovery/recovery.bin from $planted"
	as_user kradmin rm /home/kradmin/recovery-in/recovery.bin
done
# The admin's request: here bytes that do not parse, written as the admin.
as_user kradmin sh -c 'umask 077 && printf "not a recovery request\n" >/home/kradmin/recovery-in/recovery.bin'
read_back | tee "$work/read-back.log"
grep -qx 'read the recovery request back to /root/recovery/recovery.bin' "$work/read-back.log" || fail "the read-back block did not report the copy"
cmp /home/kradmin/recovery-in/recovery.bin /root/recovery/recovery.bin || fail "the read-back copy differs from the admin's file"
recover_line() {
	runuser -u keyroster-signer -g keyroster-signer -G tss -- \
	  keyroster-signer recover-revocations --state-dir /var/lib/keyroster-signer < /root/recovery/recovery.bin
}
# recover_refused LOG: the recovery line refuses recovery_malformed and
# leaves signer.db as it was.
recover_refused() {
	local before
	before=$(sha256sum "$STATE/signer.db")
	if recover_line >"$1" 2>&1; then
		cat "$1"
		fail "recover-revocations accepted a request that does not parse"
	fi
	cat "$1"
	grep -q 'recovery_malformed' "$1" || fail "recover-revocations refused for another reason than recovery_malformed"
	[ "$(sha256sum "$STATE/signer.db")" = "$before" ] || fail "the refused recovery changed signer.db"
}
recover_refused "$work/recover.log"
systemctl is-active --quiet keyroster-signer.service && fail "keyroster-signer.service is active under the hold"
# After the refusal, a new request (PR #70 review, F6): the read-back
# stops over the refused one and says why; the refused request is moved
# aside inside /root/recovery, the admin moves theirs aside and writes a
# new one, and the read-back and the recovery line run again.
if read_back >"$work/read-back-again.log" 2>&1; then
	cat "$work/read-back-again.log"
	fail "the read-back block ran over an earlier request"
fi
cat "$work/read-back-again.log"
grep -qx '/root/recovery/recovery.bin exists: move the refused request aside first (step 2b)' "$work/read-back-again.log" || fail "the read-back block did not say why it stopped"
refused_before=$(sha256sum </root/recovery/recovery.bin)
move_refused() {
	bash -eu <<'EOF'
test -f /root/recovery/recovery.bin
d=/root/recovery/refused-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -m 0700 "$d"
mv /root/recovery/recovery.bin "$d/recovery.bin"
echo "moved the refused request to $d/recovery.bin"
EOF
}
move_refused | tee "$work/move-refused.log"
moved=$(sed -n 's|^moved the refused request to \(/root/recovery/refused-[0-9TZ]*/recovery\.bin\)$|\1|p' "$work/move-refused.log")
[ -n "$moved" ] || fail "the move block did not report where it moved the request"
[ "$(sha256sum <"$moved")" = "$refused_before" ] || fail "the moved request differs from the refused one"
[ "$(stat -c '%a %U' "$(dirname "$moved")")" = "700 root" ] || fail "$(dirname "$moved") is $(stat -c '%a %U' "$(dirname "$moved")")"
[ ! -e /root/recovery/recovery.bin ] || fail "the move block left /root/recovery/recovery.bin"
as_user kradmin mv /home/kradmin/recovery-in/recovery.bin /home/kradmin/recovery-in/recovery.bin.refused
as_user kradmin sh -c 'umask 077 && printf "another request that does not parse\n" >/home/kradmin/recovery-in/recovery.bin'
read_back | tee "$work/read-back-new.log"
grep -qx 'read the recovery request back to /root/recovery/recovery.bin' "$work/read-back-new.log" || fail "the read-back block did not read the new request back"
cmp /home/kradmin/recovery-in/recovery.bin /root/recovery/recovery.bin || fail "the read-back copy differs from the admin's new file"
recover_refused "$work/recover-new.log"

step "Restore step 2b: the release check, on fixture exports (docs/runbooks/signer-install.md, verbatim)"
# The block reads only lines and keys that audit verify binds, so it runs
# here on fixture lines (no recovery is applied in this job; CI e2e runs it
# on real exports). The restored fixture already holds a recovery, as a
# backup taken after an earlier restore does (PR #70 review, F2).
release_check() {
	bash -eu <<'EOF'
RESTORED=/tmp/restored.jsonl
RECOVERED=/tmp/recovered.jsonl
KEPT=/root/recovery/server-krl.json
set -o pipefail
stop() { echo "release check: $*" >&2; exit 1; }
test -s "$RESTORED"
test -s "$RECOVERED"
n=$(($(wc -l <"$RESTORED") - 1))
[ "$(wc -l <"$RECOVERED")" -eq $((n + 3)) ] || stop "$RECOVERED does not hold exactly two entries after the $n of $RESTORED"
[ "$(sed -n "$((n + 1))p" "$RECOVERED" | grep -c "^{\"index\":$n,.*\"kind\":\"revocation_recovery\"")" = 1 ] || stop "entry $n is not a revocation_recovery"
[ "$(sed -n "$((n + 2))p" "$RECOVERED" | grep -c "^{\"index\":$((n + 1)),.*\"kind\":\"krl_publish\"")" = 1 ] || stop "entry $((n + 1)) is not a krl_publish"
imported=$(sed -n "$((n + 1))p" "$RECOVERED" | grep -o '"import_krl_versions":\[[0-9,]*\]' | tr -dc '0-9,') || stop "entry $n names no imported KRL versions"
if [ -e "$KEPT" ]; then
  [ "$(wc -l <"$KEPT")" -eq 1 ] || stop "$KEPT is not one line"
  grep -Eqx '\{"krl":"[A-Za-z0-9+/=]+","manifest":"[A-Za-z0-9+/=]+","sig":"[A-Za-z0-9+/=]+"\}' "$KEPT" || stop "$KEPT is not a KRL document as keyroster-server writes it"
  v=$(cut -d'"' -f8 "$KEPT" | base64 -d | grep -o '"krl_version":[0-9]*' | cut -d: -f2) || stop "$KEPT has no KRL version"
  case "$v" in '' | *[!0-9]*) stop "$KEPT has no single KRL version" ;; esac
  printf '%s\n' "$imported" | tr , '\n' | grep -x "$v" >/dev/null || stop "the recovery did not import the kept server copy, KRL v$v (it imported KRL versions [$imported])"
  echo "release check passed: entries $n (revocation_recovery) and $((n + 1)) (krl_publish), imported KRL versions [$imported], the kept server copy's v$v among them"
else
  echo "release check passed: entries $n (revocation_recovery) and $((n + 1)) (krl_publish), imported KRL versions [$imported], no server KRL copy kept"
fi
EOF
}
[ ! -e /tmp/recovered.jsonl ] || fail "/tmp/recovered.jsonl exists on this host"
fixture_line() { printf '{"index":%d,"leaf":"Zml4dHVyZQ==","decoded":{%s}}\n' "$1" "$2"; }
fixture_kept() {
	printf '{"krl":"Zml4dHVyZQ==","manifest":"%s","sig":"Zml4dHVyZQ=="}\n' "$(printf '{"krl_version":%d}' "$1" | base64 -w0)" >/root/recovery/server-krl.json
}
{
	fixture_line 0 '"kind":"bundle_install"'
	fixture_line 1 '"import_krl_versions":[5],"kind":"revocation_recovery"'
	fixture_line 2 '"kind":"krl_publish"'
	echo '{"checkpoint":"fixture"}'
} >/tmp/restored.jsonl
{
	head -n 3 /tmp/restored.jsonl
	fixture_line 3 '"import_krl_versions":[7,19],"kind":"revocation_recovery"'
	fixture_line 4 '"kind":"krl_publish"'
	echo '{"checkpoint":"fixture"}'
} >/tmp/recovered.jsonl
# release_check_stops NAME WANT: the check stops with the reason WANT and
# never prints its passed line.
release_check_stops() {
	if release_check >"$work/release-check-$1.log" 2>&1; then
		cat "$work/release-check-$1.log"
		fail "the release check passed: $1"
	fi
	cat "$work/release-check-$1.log"
	grep -q "$2" "$work/release-check-$1.log" || fail "the release check stopped for another reason: $1"
	! grep -q 'release check passed' "$work/release-check-$1.log" || fail "the release check printed its passed line: $1"
}
fixture_kept 19
release_check | tee "$work/release-check-kept.log"
grep -qx "release check passed: entries 3 (revocation_recovery) and 4 (krl_publish), imported KRL versions \[7,19\], the kept server copy's v19 among them" "$work/release-check-kept.log" ||
	fail "the release check did not pass with the kept copy's version imported"
fixture_kept 9
release_check_stops not-imported 'the recovery did not import the kept server copy, KRL v9'
fixture_kept 1
release_check_stops not-imported-prefix 'the recovery did not import the kept server copy, KRL v1 '
rm /root/recovery/server-krl.json
release_check | tee "$work/release-check-none.log"
grep -qx 'release check passed: entries 3 (revocation_recovery) and 4 (krl_publish), imported KRL versions \[7,19\], no server KRL copy kept' "$work/release-check-none.log" ||
	fail "the release check did not pass without a kept copy"
# One entry more after the recovery's two: something else was logged.
{
	head -n 5 /tmp/recovered.jsonl
	fixture_line 5 '"kind":"revoke"'
	echo '{"checkpoint":"fixture"}'
} >"$work/recovered-extra.jsonl"
mv "$work/recovered-extra.jsonl" /tmp/recovered.jsonl
release_check_stops extra-entry 'does not hold exactly two entries after the 3 of /tmp/restored.jsonl'
cp /tmp/restored.jsonl /tmp/recovered.jsonl
release_check_stops not-applied 'does not hold exactly two entries after the 3 of /tmp/restored.jsonl'
rm -r /root/recovery /home/kradmin/recovery-in /tmp/restored.jsonl /tmp/recovered.jsonl /root/latest-saved.jsonl
bash -eu -s keyroster-server keyroster-signer <<'EOF'
test "$#" -gt 0
for u in "$@"; do
  rm "/etc/systemd/system/$u.service.d/restore-hold.conf"
done
systemctl daemon-reload
for u in "$@"; do
  if systemctl is-failed --quiet "$u.service"; then systemctl reset-failed "$u.service"; fi
done
echo "released: $*"
EOF
systemctl start keyroster-signer.service
wait_socket "$SIGNER_SOCK"
systemctl is-active keyroster-signer.service
as_signer keyroster-signer doctor --state-dir "$STATE" >"$work/doctor-restore.log" 2>&1 || {
	cat "$work/doctor-restore.log"
	fail "doctor failed after the restore"
}
cat "$work/doctor-restore.log"

step "Restore step 3: copy the replay proposal to an admin (docs/runbooks/signer-install.md, verbatim)"
# The block writes as the admin (runuser), and root only reads /root/replay:
# a link the admin planted at ~/replay-v2 is refused, and the directory of
# root's that it points at keeps its owner, mode and contents.
[ ! -e /root/replay ] || fail "/root/replay exists on this host"
install -d -m 0700 /root/replay /root/replay/v2
printf '{"version":2}\n' >/root/replay/v2/directory.json
printf 'sigs\n' >/root/replay/v2/directory.json.sigs
canary=$work/replay-canary
install -d -m 0755 "$canary"
echo keep >"$canary/keep"
canary_state() {
	stat -c '%U %G %a' "$canary"
	ls -A "$canary"
}
canary_before=$(canary_state)
# The modes are set explicitly: on the runner, /home/kradmin has a default
# ACL (default:user:runner:rwx, default:mask::rwx), under which a directory
# made with umask 077 alone came out 775 (run 40208370162).
ls -ld /home/kradmin
! command -v getfacl >/dev/null || getfacl -p /home/kradmin
copy_proposal() {
	bash -eu -s kradmin <<'EOF'
V=2                                   # the lost directory version
H=$(getent passwd "$1" | cut -d: -f6)
test -n "$H"
runuser -u "$1" -- sh -c 'umask 077 && mkdir -m 0700 "$1"' sh "$H/replay-v$V"
for f in directory.json directory.json.sigs; do
  runuser -u "$1" -- sh -c 'umask 077 && set -C && cat >"$1" && chmod 0600 "$1"' sh "$H/replay-v$V/$f" <"/root/replay/v$V/$f"
done
echo "copied the proposal of directory version $V to $H/replay-v$V for $1"
EOF
}
as_user kradmin ln -s "$canary" /home/kradmin/replay-v2
if copy_proposal >"$work/copy-link.log" 2>&1; then
	cat "$work/copy-link.log"
	fail "the copy block wrote through a link the admin planted"
fi
cat "$work/copy-link.log"
[ "$(canary_state)" = "$canary_before" ] || fail "the copy block changed the directory a planted link points at: $(canary_state)"
as_user kradmin rm /home/kradmin/replay-v2
copy_proposal | tee "$work/copy.log"
grep -qx 'copied the proposal of directory version 2 to /home/kradmin/replay-v2 for kradmin' "$work/copy.log" || fail "the copy block did not report the copy"
[ "$(stat -c '%a %U %G' /home/kradmin/replay-v2)" = "700 kradmin kradmin" ] || fail "replay-v2 is $(stat -c '%a %U %G' /home/kradmin/replay-v2)"
for f in directory.json directory.json.sigs; do
	[ "$(stat -c '%a %U %G' "/home/kradmin/replay-v2/$f")" = "600 kradmin kradmin" ] || fail "replay-v2/$f is $(stat -c '%a %U %G' "/home/kradmin/replay-v2/$f")"
	cmp "/root/replay/v2/$f" "/home/kradmin/replay-v2/$f" || fail "replay-v2/$f differs from root's copy"
done
[ "$(canary_state)" = "$canary_before" ] || fail "the copy block changed $canary"
rm -r /root/replay

step "PASS"
