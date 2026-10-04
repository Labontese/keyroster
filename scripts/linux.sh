#!/usr/bin/env bash
# Run a command string in Linux: directly on Linux, through WSL on Windows
# (Git Bash / MSYS). The exit status is the inner command's.
#
#   bash scripts/linux.sh 'go test ./...'
#
# On Windows the command runs in a login shell (so ~/.profile puts Go on PATH)
# in the WSL path of the current directory. Set KEYROSTER_WSL_DISTRO to pick a
# distribution other than the WSL default.
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 'command string'" >&2
	exit 2
fi

case "$(uname -s)" in
MINGW* | MSYS* | CYGWIN*)
	MSYS_NO_PATHCONV=1 exec wsl.exe ${KEYROSTER_WSL_DISTRO:+-d "$KEYROSTER_WSL_DISTRO"} \
		--cd "$(pwd -W)" -- bash -lc "$1"
	;;
*)
	exec bash -c "$1"
	;;
esac
