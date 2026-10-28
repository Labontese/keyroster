#!/usr/bin/env bash
# capslock capability baselines per binary (REPO-02, T-01-61): keyroster-signer,
# keyroster-agent since 03-05, and keyroster-agent-fetch since 03-07.
#
#   bash scripts/capslock-check.sh            # compare with the baseline
#   bash scripts/capslock-check.sh --update   # rewrite the baseline
#
# Runs capslock (pinned in tools/go.mod) on each target (./cmd/keyroster-signer,
# ./cmd/keyroster-agent) for GOOS=linux GOARCH=amd64 with CGO_ENABLED=0, in
# package mode: for every package in the binary's dependency graph, the
# capabilities (FILES, NETWORK, EXEC, ...) that capslock finds reachable
# from it. The check fails when any (package, capability) pair is not in
# the target's committed baseline (test/capslock/keyroster-signer.json,
# test/capslock/keyroster-agent.json), so a dependency bump or a code change
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
# The package pairs cannot say where a capability enters the code: they
# list the packages on one example path per capability, so a second exec
# site in a package that already reaches EXEC adds no pair. For
# keyroster-agent the check therefore also reads capslock's EXEC call
# graph (-output graph -capabilities EXEC) and fails when any edge from a
# function of this module to a function outside it starts outside
# internal/agent/execsite (PR #67 review): every program the agent runs
# leaves the module through execsite's ExecRunner.Run, and nowhere else.
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

# check_target NAME PACKAGE TAGS CGO BASELINE
check_target() {
	local name=$1 pkg=$2 tags=$3 cgo=$4 baseline=$5 out cur base new gone
	out=$(mktemp)
	trap 'rm -f "$out"' RETURN
	# stderr carries "go: downloading ..." on a cold module cache.
	echo "== $(go tool -modfile=tools/go.mod capslock -version 2>/dev/null | head -n 1): $name (GOOS=linux GOARCH=amd64 CGO_ENABLED=$cgo tags=${tags:-none})"
	if ! CGO_ENABLED=$cgo go tool -modfile=tools/go.mod capslock \
		-packages "$pkg" -goos linux -goarch amd64 \
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

# check_exec_confined NAME PACKAGE ALLOWED: every edge of capslock's EXEC
# graph from a function of this module to one outside it must start in the
# package ALLOWED (a full import path).
check_exec_confined() {
	local name=$1 pkg=$2 allowed=$3 out edges bad
	out=$(mktemp)
	trap 'rm -f "$out"' RETURN
	if ! CGO_ENABLED=0 go tool -modfile=tools/go.mod capslock \
		-packages "$pkg" -goos linux -goarch amd64 \
		-force_local_module -output graph -capabilities EXEC >"$out"; then
		echo "capslock-check: capslock -output graph failed" >&2
		exit 2
	fi
	# Lines of the DOT graph: "caller" -> "callee". Print each edge from
	# the module to outside it, marked ok when its caller is in ALLOWED.
	edges=$(awk -F'" -> "' -v mod="github.com/Labontese/keyroster/" -v allowed="$allowed." '
		/ -> / {
			a = $1; b = $2
			sub(/^[ \t]*"/, "", a); sub(/"[ \t]*$/, "", b)
			if (index(a, mod) && !index(b, mod)) print (index(a, allowed) ? "ok " : "bad ") a " -> " b
		}' "$out" | LC_ALL=C sort -u)
	if [ -z "$edges" ]; then
		echo "capslock-check: $name: no EXEC edge leaves the module; did the graph format change?" >&2
		exit 2
	fi
	bad=$(sed -n 's/^bad //p' <<<"$edges")
	echo "== $name: EXEC leaves the module only through $allowed ($(wc -l <<<"$edges") edges)"
	if [ -n "$bad" ]; then
		echo "   EXEC edges outside $allowed:"
		sed 's/^/     + /' <<<"$bad"
		status=1
	fi
}

# check_no_exec NAME BASELINE: the fetcher runs no program (03-07, T-03-43),
# so its baseline holds no EXEC pair at all. (ARBITRARY_EXECUTION is
# capslock's over-approximation of interface calls such as
# ssh.PublicKey.Verify, reviewed per pair like every other capability.)
check_no_exec() {
	local name=$1 baseline=$2 found
	found=$(pairs "$baseline" | awk '$2 == "CAPABILITY_EXEC"')
	if [ -n "$found" ]; then
		echo "   $name: EXEC capability in $baseline:"
		sed 's/^/     + /' <<<"$found"
		status=1
	fi
}

status=0
check_target "keyroster-signer" ./cmd/keyroster-signer "" 0 test/capslock/keyroster-signer.json
check_target "keyroster-agent" ./cmd/keyroster-agent "" 0 test/capslock/keyroster-agent.json
check_target "keyroster-agent-fetch" ./cmd/keyroster-agent-fetch "" 0 test/capslock/keyroster-agent-fetch.json
if [ "$update" = 0 ]; then
	check_no_exec "keyroster-agent-fetch" test/capslock/keyroster-agent-fetch.json
	check_exec_confined "keyroster-agent" ./cmd/keyroster-agent github.com/Labontese/keyroster/internal/agent/execsite
fi
if [ "$status" != 0 ]; then
	echo "capslock-check: a binary gained capabilities; review them, then update the baseline in a reviewed PR (bash scripts/capslock-check.sh --update)" >&2
fi
exit "$status"
