#!/usr/bin/env bash
# Start a software TPM 2.0 (swtpm) for the TPM keystore tests (KEY-04). swtpm
# is a test and development stand-in only: production uses the kernel's
# resource manager, /dev/tpmrm0.
#
#   bash scripts/swtpm-setup.sh DIR
#
# swtpm listens on a Unix socket carrying raw TPM commands (unixio), which
# the backend reaches with its test-only swtpm-socket option. No root is
# needed. This is the only transport CI exercises; the production device
# path (/dev/tpmrm0) is not covered here (see docs/security/custody.md).
#
# DIR must be new or empty; the TPM state, pid file and log go there. The
# swtpm daemon keeps running until killed (kill "$(cat DIR/swtpm.pid)").
# The last line on stdout is the backend option for the tests:
#
#   KEYROSTER_TPM_OPTS=swtpm-socket=DIR/swtpm.sock
#
# Set SWTPM to use another swtpm binary (for example one extracted without
# root for a local run); the default is swtpm on PATH.
set -euo pipefail
umask 077

die() {
	echo "swtpm-setup: $*" >&2
	exit 1
}

[ "$#" -eq 1 ] || die "usage: $0 DIR"
dir=$1
swtpm=${SWTPM:-$(command -v swtpm || true)}
[ -n "$swtpm" ] && [ -x "$swtpm" ] || die "swtpm not found (install swtpm or set SWTPM)"

mkdir -p "$dir"
[ -z "$(ls -A "$dir")" ] || die "$dir is not empty"
dir=$(cd "$dir" && pwd -P)
mkdir -m 0700 "$dir/state"

wait_for() { # wait_for TEST-ARGS... : up to 10 s
	for _ in $(seq 100); do
		if test "$@"; then return 0; fi
		sleep 0.1
	done
	return 1
}

"$swtpm" socket --tpm2 \
	--server "type=unixio,path=$dir/swtpm.sock" \
	--ctrl "type=unixio,path=$dir/swtpm.ctrl" \
	--tpmstate "dir=$dir/state" \
	--flags not-need-init,startup-clear \
	--pid "file=$dir/swtpm.pid" --log "file=$dir/swtpm.log" --daemon
wait_for -S "$dir/swtpm.sock" || die "swtpm socket did not appear (log: $(cat "$dir/swtpm.log" 2>/dev/null))"
echo "swtpm-setup: unixio socket $dir/swtpm.sock" >&2
echo "KEYROSTER_TPM_OPTS=swtpm-socket=$dir/swtpm.sock"
