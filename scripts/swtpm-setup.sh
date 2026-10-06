#!/usr/bin/env bash
# Start a software TPM 2.0 (swtpm) for the TPM keystore tests (KEY-04). swtpm
# is a test and development stand-in only: production uses the kernel's
# resource manager, /dev/tpmrm0.
#
#   bash scripts/swtpm-setup.sh MODE DIR
#
# MODE is one of:
#
#   vtpm-proxy  swtpm behind the kernel's vTPM proxy (needs sudo and the
#               tpm_vtpm_proxy module): the kernel creates a new
#               /dev/tpmrmN, so the backend uses its production transport.
#               The device is handed to the current user.
#   unixio      swtpm on a Unix socket carrying raw TPM commands, reached
#               with the backend's test-only swtpm-socket option. No root
#               needed (local WSL runs; WSL2 kernels lack tpm_vtpm_proxy).
#
# DIR must be new or empty; the TPM state, pid file and log go there. The
# swtpm daemon keeps running until killed (kill "$(cat DIR/swtpm.pid)").
# The last line on stdout is the backend option for the tests:
#
#   KEYROSTER_TPM_OPTS=device=/dev/tpmrmN        (vtpm-proxy)
#   KEYROSTER_TPM_OPTS=swtpm-socket=DIR/swtpm.sock  (unixio)
#
# Set SWTPM to use another swtpm binary (for example one extracted without
# root for a local run); the default is swtpm on PATH.
set -euo pipefail
umask 077

die() {
	echo "swtpm-setup: $*" >&2
	exit 1
}

[ "$#" -eq 2 ] || die "usage: $0 vtpm-proxy|unixio DIR"
mode=$1
dir=$2
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

case "$mode" in
vtpm-proxy)
	sudo modprobe tpm_vtpm_proxy || die "cannot load tpm_vtpm_proxy"
	before=$(ls /dev/tpmrm* 2>/dev/null || true)
	sudo "$swtpm" chardev --vtpm-proxy --tpm2 --tpmstate "dir=$dir/state" \
		--flags not-need-init,startup-clear \
		--pid "file=$dir/swtpm.pid" --log "file=$dir/swtpm.log" --daemon
	dev=""
	for _ in $(seq 100); do
		for d in /dev/tpmrm*; do
			[ -e "$d" ] || continue
			if ! grep -qxF "$d" <<<"$before"; then dev=$d; fi
		done
		[ -n "$dev" ] && break
		sleep 0.1
	done
	[ -n "$dev" ] || die "no new /dev/tpmrm* appeared (log: $(sudo cat "$dir/swtpm.log" 2>/dev/null))"
	sudo chown "$(id -u)" "$dev"
	sudo chmod 0600 "$dev"
	sudo chown "$(id -u)" "$dir/swtpm.pid" "$dir/swtpm.log"
	echo "swtpm-setup: vtpm-proxy device $dev" >&2
	echo "KEYROSTER_TPM_OPTS=device=$dev"
	;;
unixio)
	"$swtpm" socket --tpm2 \
		--server "type=unixio,path=$dir/swtpm.sock" \
		--ctrl "type=unixio,path=$dir/swtpm.ctrl" \
		--tpmstate "dir=$dir/state" \
		--flags not-need-init,startup-clear \
		--pid "file=$dir/swtpm.pid" --log "file=$dir/swtpm.log" --daemon
	wait_for -S "$dir/swtpm.sock" || die "swtpm socket did not appear (log: $(cat "$dir/swtpm.log" 2>/dev/null))"
	echo "swtpm-setup: unixio socket $dir/swtpm.sock" >&2
	echo "KEYROSTER_TPM_OPTS=swtpm-socket=$dir/swtpm.sock"
	;;
*)
	die "unknown mode '$mode' (want vtpm-proxy or unixio)"
	;;
esac
