#!/usr/bin/env bash
# capslock capability baseline for keyroster-signer (REPO-02, T-01-61).
#
#   bash scripts/capslock-check.sh            # compare with the baseline
#   bash scripts/capslock-check.sh --update   # rewrite the baseline
#
# Runs capslock (pinned in tools/go.mod) on ./cmd/keyroster-signer for
# GOOS=linux GOARCH=amd64 with CGO_ENABLED=0, in package mode: for every
# package in the signer's dependency graph, the capabilities (FILES,
# NETWORK, EXEC, ...) that capslock finds reachable from it. The check fails
# when any (package, capability) pair is not in the committed baseline
# test/capslock/keyroster-signer.json, so a dependency bump or a code change
# that gives any package a new capability fails CI until a reviewed PR
# updates the baseline. This is finer than comparing capability names only:
# the signer as a whole already reaches nearly every capability (through
# net.ListenUnix, os, reflect and the SQLite stack), so a name-only diff
# would miss almost everything.
#
# Pairs that disappeared are reported but do not fail; tighten the baseline
# with --update in a reviewed PR.
#
# A further target (for example the PIV build: -buildtags piv with
# CGO_ENABLED=1, which needs the pcsclite headers) is one more check_target
# call with its own baseline file.
#
# Exit 0 when nothing is new, 1 when a pair is new, 2 on usage or tool
# errors.
set -euo pipefail

cd "$(dirname "$0")/.."

update=0
case "${1:-}" in
"") ;;
--update) update=1 ;;
*)
	echo "usage: $0 [--update]" >&2
	exit 2
	;;
esac

# pairs FILE: the sorted "package CAPABILITY_X" pairs of a capslock
# -output package JSON file (a map from package path to capability list).
pairs() {
	awk '
		/^  "[^"]+": \[/ { match($0, /"[^"]+"/); pkg = substr($0, RSTART + 1, RLENGTH - 2); next }
		/^    "CAPABILITY_[A-Z_]+"/ { match($0, /CAPABILITY_[A-Z_]+/); print pkg, substr($0, RSTART, RLENGTH) }
	' "$1" | LC_ALL=C sort -u
}

# check_target NAME TAGS CGO BASELINE
check_target() {
	local name=$1 tags=$2 cgo=$3 baseline=$4 out cur base new gone
	out=$(mktemp)
	trap 'rm -f "$out"' RETURN
	echo "== capslock $(go tool -modfile=tools/go.mod capslock -version 2>&1 | head -n 1): $name (GOOS=linux GOARCH=amd64 CGO_ENABLED=$cgo tags=${tags:-none})"
	if ! CGO_ENABLED=$cgo go tool -modfile=tools/go.mod capslock \
		-packages ./cmd/keyroster-signer -goos linux -goarch amd64 \
		-buildtags "$tags" -force_local_module -output package >"$out"; then
		echo "capslock-check: capslock failed" >&2
		exit 2
	fi
	cur=$(pairs "$out")
	if [ -z "$cur" ]; then
		echo "capslock-check: no capabilities parsed from the capslock output; did its format change?" >&2
		exit 2
	fi
	if [ "$update" = 1 ]; then
		mkdir -p "$(dirname "$baseline")"
		cp "$out" "$baseline"
		echo "   wrote $baseline: $(wc -l <<<"$cur") (package, capability) pairs"
		return 0
	fi
	if [ ! -f "$baseline" ]; then
		echo "capslock-check: no baseline $baseline; create it with --update in a reviewed PR" >&2
		exit 2
	fi
	base=$(pairs "$baseline")
	new=$(LC_ALL=C comm -13 <(echo "$base") <(echo "$cur"))
	gone=$(LC_ALL=C comm -23 <(echo "$base") <(echo "$cur"))
	echo "   $(wc -l <<<"$cur") (package, capability) pairs; baseline has $(wc -l <<<"$base")"
	echo "   capabilities: $(awk '{print $2}' <<<"$cur" | LC_ALL=C sort -u | sed 's/^CAPABILITY_//' | tr '\n' ' ')"
	if [ -n "$gone" ]; then
		echo "   no longer reported (tighten the baseline with --update in a reviewed PR):"
		sed 's/^/     - /' <<<"$gone"
	fi
	if [ -n "$new" ]; then
		echo "   NEW capabilities not in $baseline:"
		sed 's/^/     + /' <<<"$new"
		status=1
	fi
}

status=0
check_target "keyroster-signer" "" 0 test/capslock/keyroster-signer.json
if [ "$status" != 0 ]; then
	echo "capslock-check: keyroster-signer gained capabilities; review them, then update the baseline in a reviewed PR (bash scripts/capslock-check.sh --update)" >&2
fi
exit "$status"
