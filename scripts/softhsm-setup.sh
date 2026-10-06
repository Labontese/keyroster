#!/usr/bin/env bash
# Create the SoftHSM2 test tokens for the PKCS#11 e2e suite (KEY-03, D-12).
# SoftHSM2 is the CI stand-in for a YubiHSM 2 or another PKCS#11 HSM. The
# keyroster processes never load it: OpenSSH's ssh-agent reaches it through
# ssh-pkcs11-helper.
#
#   bash scripts/softhsm-setup.sh DIR KEYTYPE
#
# KEYTYPE is p256 (EC prime256v1) or ed25519 (EC edwards25519; ssh-agent
# 10.1 or newer is needed to use these keys). DIR must be new or empty. The
# script writes:
#
#   DIR/ca/softhsm2.conf    SoftHSM2 config whose token directory holds only
#                           the token keyroster-ca, with key pairs user-ca,
#                           host-ca, machine-ca, ops and log (CKA_ID 01-05)
#   DIR/root/softhsm2.conf  SoftHSM2 config whose token directory holds only
#                           the token keyroster-root, with key pair root
#                           (the stand-in for a PIV root, D-11)
#   DIR/pin                 the random user PIN of both tokens (mode 0600)
#   DIR/askpass.sh          SSH_ASKPASS helper that prints DIR/pin (0700)
#
# and prints the PKCS#11 module path (symlinks resolved, as ssh-agent -P
# matches it) on stdout. Every process that loads the module (ssh-agent,
# ssh-keygen -D) must get SOFTHSM2_CONF set to one of the two configs. The
# two separate configs keep the CA and root keys out of each other's agent:
# an agent that loads the module sees every token in its token directory.
#
# The PINs are never echoed and never passed as command-line arguments
# (which every local user can read in ps): pkcs11-tool reads them from
# environment variables through its env:NAME syntax, which only this user
# and root can read, and ssh-add gets the user PIN through askpass.sh. The
# security officer PIN is random and discarded.
#
# The module is /usr/lib/softhsm/libsofthsm2.so or the first
# /usr/lib/*/softhsm/libsofthsm2.so. Set SOFTHSM2_MODULE to use another
# install (for example packages extracted without root for a local run).
set -euo pipefail
umask 077

die() {
	echo "softhsm-setup: $*" >&2
	exit 1
}

if [ "$#" -ne 2 ]; then
	echo "usage: $0 DIR p256|ed25519" >&2
	exit 2
fi
dir=$1
case "$2" in
p256) keytype=EC:prime256v1 ;;
ed25519) keytype=EC:edwards25519 ;;
*) die "KEYTYPE must be p256 or ed25519, got '$2'" ;;
esac

command -v pkcs11-tool >/dev/null || die "pkcs11-tool not found (install opensc)"

module=${SOFTHSM2_MODULE:-}
if [ -z "$module" ]; then
	for m in /usr/lib/softhsm/libsofthsm2.so /usr/lib/*/softhsm/libsofthsm2.so; do
		if [ -f "$m" ]; then
			module=$m
			break
		fi
	done
fi
[ -n "$module" ] && [ -f "$module" ] || die "libsofthsm2.so not found (install softhsm2 or set SOFTHSM2_MODULE)"
# ssh-agent matches its -P allowlist against the resolved path.
module=$(readlink -f "$module")

mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
[ -z "$(ls -A "$dir")" ] || die "$dir is not empty"

# 128-bit random PINs as hex. Only the user PIN is kept.
randhex() { od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; }
randhex >"$dir/pin"
chmod 0600 "$dir/pin"
KEYROSTER_SO_PIN=$(randhex)
KEYROSTER_USER_PIN=$(cat "$dir/pin")
export KEYROSTER_SO_PIN KEYROSTER_USER_PIN

p11() { pkcs11-tool --module "$module" "$@" >/dev/null; }

# new_token NAME LABEL: create DIR/NAME/softhsm2.conf with its own token
# directory, initialise its free slot as LABEL and set the user PIN. Later
# pkcs11-tool calls use this config.
new_token() {
	local slot
	mkdir -p "$dir/$1/tokens"
	printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
		"$dir/$1/tokens" >"$dir/$1/softhsm2.conf"
	export SOFTHSM2_CONF="$dir/$1/softhsm2.conf"
	slot=$(pkcs11-tool --module "$module" --list-slots |
		awk '/^Slot [0-9]+ /{i=$2} /token state: *uninitialized/{print i; exit}')
	[ -n "$slot" ] || die "no uninitialised SoftHSM2 slot for $2"
	p11 --init-token --slot-index "$slot" --label "$2" --so-pin env:KEYROSTER_SO_PIN
	p11 --token-label "$2" --init-pin --login --login-type so \
		--so-pin env:KEYROSTER_SO_PIN --new-pin env:KEYROSTER_USER_PIN
}

# keypair TOKEN ID LABEL
keypair() {
	p11 --token-label "$1" --login --pin env:KEYROSTER_USER_PIN \
		--keypairgen --key-type "$keytype" --id "$2" --label "$3"
}

new_token ca keyroster-ca
id=1
for label in user-ca host-ca machine-ca ops log; do
	keypair keyroster-ca "$(printf '%02x' "$id")" "$label"
	id=$((id + 1))
done
new_token root keyroster-root
keypair keyroster-root 01 root
unset KEYROSTER_SO_PIN KEYROSTER_USER_PIN

cat >"$dir/askpass.sh" <<EOF
#!/bin/sh
# SSH_ASKPASS helper: prints the SoftHSM2 user PIN for ssh-add.
exec cat '$dir/pin'
EOF
chmod 0700 "$dir/askpass.sh"

echo "$module"
