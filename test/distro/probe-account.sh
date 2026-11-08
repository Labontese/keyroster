#!/bin/sh
# Create the probe account (03-10c, owner answer Q3, 2026-11-07) exactly
# as docs/runbooks/host-setup.md 'The probe account' says: one arm per
# distribution family, each arm the runbook's block for that family, line
# for line (TestProbeAccountRunbook compares them). The distro matrix and
# the systemd smoke run it:
#
#   sh test/distro/probe-account.sh debian|rhel|alpine|arch
#
# Each arm creates a system account with no home and the family's nologin
# shell, then sets its shadow field to exactly "*" (no usable password,
# not locked) with usermod; no command edits /etc/shadow by hand.
# KEYROSTER_PROBE_NAME names another account (default keyroster-probe).
# POSIX sh: Alpine has no bash.
set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: $0 debian|rhel|alpine|arch" >&2
	exit 2
fi
case "$1" in
debian)
	name=${KEYROSTER_PROBE_NAME:-keyroster-probe}
	test -x /usr/sbin/nologin
	useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$name"
	usermod --password '*' "$name"
	;;
rhel)
	name=${KEYROSTER_PROBE_NAME:-keyroster-probe}
	test -x /sbin/nologin
	useradd --system --no-create-home --home-dir /nonexistent --shell /sbin/nologin "$name"
	usermod --password '*' "$name"
	;;
alpine)
	name=${KEYROSTER_PROBE_NAME:-keyroster-probe}
	test -x /sbin/nologin
	command -v usermod >/dev/null 2>&1 || apk add -q shadow
	adduser -S -D -H -h /nonexistent -s /sbin/nologin "$name"
	usermod --password '*' "$name"
	;;
arch)
	name=${KEYROSTER_PROBE_NAME:-keyroster-probe}
	test -x /usr/bin/nologin
	useradd --system --no-create-home --home-dir /nonexistent --shell /usr/bin/nologin "$name"
	usermod --password '*' "$name"
	;;
*)
	echo "probe-account.sh: unknown family $1 (debian, rhel, alpine or arch)" >&2
	exit 2
	;;
esac

# For the log: the account's passwd line and the class of its shadow
# field, never the field itself.
grep "^$name:" /etc/passwd
awk -F: -v n="$name" '$1 == n {
	c = "hash"
	if ($2 == "") c = "empty"
	else if ($2 == "*") c = "star"
	else if (substr($2, 1, 1) == "!") c = "locked"
	print n ": shadow field class " c
}' /etc/shadow
