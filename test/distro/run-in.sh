#!/bin/sh
# Inside the distribution container (test/distro/run.sh): install the
# distribution's own OpenSSH server and ssh-keygen with its package
# manager, then run the distro tests as root. POSIX sh: Alpine has no bash.
set -eu

keygen_package=none
if command -v apt-get >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends openssh-server >/dev/null
elif command -v dnf >/dev/null 2>&1; then
	dnf install -y -q openssh-server >/dev/null
elif command -v apk >/dev/null 2>&1; then
	apk add -q openssh openssh-keygen
	keygen_package=openssh-keygen
elif command -v pacman >/dev/null 2>&1; then
	# Arch rolls, and the image is frozen by its digest: pacman -Sy of the
	# live repositories followed by installing only openssh is a partial
	# upgrade (Arch does not support one), and breaks once the live
	# openssh needs newer libraries than the image holds. Instead pacman
	# reads the Arch Linux Archive's snapshot of the day the image was
	# built (the day its build wrote the mirrorlist), and -Syyu upgrades
	# the whole system to that snapshot before installing openssh: the
	# same package set on every run, with pacman's signature checks left
	# on (the image's own archlinux-keyring verifies them).
	snapshot=$(date -u -r /etc/pacman.d/mirrorlist +%Y/%m/%d)
	# shellcheck disable=SC2016 # $repo and $arch are pacman's own variables
	printf 'Server = https://archive.archlinux.org/repos/%s/$repo/os/$arch\n' "$snapshot" >/etc/pacman.d/mirrorlist
	echo "run-in.sh: pacman from the Arch Linux Archive snapshot $snapshot"
	pacman -Syyu --noconfirm --needed openssh >/dev/null
else
	echo "run-in.sh: no supported package manager in this image" >&2
	exit 1
fi

export KEYROSTER_AGENT=/k/keyroster-agent KEYROSTER_KEYGEN_PACKAGE="$keygen_package"
exec /k/distro.test -test.v -test.count=1 -test.timeout=20m
