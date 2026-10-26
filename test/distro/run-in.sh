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
	pacman -Sy --noconfirm --needed openssh >/dev/null
else
	echo "run-in.sh: no supported package manager in this image" >&2
	exit 1
fi

export KEYROSTER_AGENT=/k/keyroster-agent KEYROSTER_KEYGEN_PACKAGE="$keygen_package"
exec /k/distro.test -test.v -test.count=1 -test.timeout=20m
