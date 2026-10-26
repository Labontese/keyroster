#!/usr/bin/env bash
# Dependency firewall per binary (KEY-01, REPO-02, D-05). Each target has
# its own banned list:
#
#   keyroster-signer: no network, template, exec or plugin packages, no
#   TPM simulator, no WebAuthn attestation stack (BANNED, EXCEPTIONS).
#   keyroster-agent (the root applier, 03-05): no HTTP, RPC, TLS, SMTP,
#   templates, plugins or WebAuthn stack (AGENT_BANNED). os/exec is allowed
#   for this target only, imported only by internal/agent/execsite, whose
#   constructors internal/agent/paths' TestPaths pins and to which
#   capslock-check confines EXEC. Its only network use is the loopback self-test (the
#   owner's D-05 answer, loopback-only), through net and x/crypto/ssh.
#
# depguard (lint) catches direct imports; this catches what dependencies
# pull in.
#
#   bash scripts/dep-firewall.sh
#
# It runs `go list -deps` for GOOS=linux: for the signer twice, with no
# build tags (CGO_ENABLED=0, the default binary) and with -tags piv
# (CGO_ENABLED=1, the PIV build); for the agent once, with no tags. For
# every banned package it prints the packages that import it. A banned
# package passes only when every importer is listed for it in the target's
# exceptions; each exception names the locked dependency that imports it
# and why that is acceptable, and is reviewed in the PR that adds it.
#
# Exit 0 when clean, 1 when a banned package is found without a matching
# exception, 2 on usage or tool errors.
set -euo pipefail

cd "$(dirname "$0")/.."

BANNED=(
	net/http
	net/rpc
	crypto/tls
	html/template
	text/template
	os/exec
	net/smtp
	plugin
	github.com/google/go-tpm-tools
	github.com/google/go-tpm/tpm2/transport/simulator
	# D-17: WebAuthn attestation, CBOR and JWT parsing stays in
	# keyroster-server (02-08). The signer verifies assertions with
	# internal/webauthn only, over SPKI DER, and never parses CBOR.
	github.com/go-webauthn
	github.com/fxamacker/cbor
	github.com/golang-jwt
)

# EXCEPTIONS: "BANNED_PACKAGE IMPORTER" pairs.
EXCEPTIONS=(
	# os/exec <- modernc.org/libc (locked SQLite stack, CLAUDE.md; found in
	# 01-02). In the linux build, libc uses os/exec only in Xsystem (C
	# system(3): exec.Command("sh", "-c", ...)). The SQLite translation in
	# modernc.org/sqlite v1.60.1 never references Xsystem or Xpopen, so the
	# code is linked but never called. capslock still reports EXEC for
	# internal/signerdb through an interface-call over-approximation; that
	# entry is in test/capslock/keyroster-signer.json for the same reason.
	# The systemd unit (NoNewPrivileges, empty capability set, read-only
	# file system, no network) bounds what a spawned process could do.
	"os/exec modernc.org/libc"
)

# AGENT_BANNED is keyroster-agent's banned list (03-05 Task 4). 03-07 adds
# the fetcher as its own target.
AGENT_BANNED=(
	net/http
	net/rpc
	crypto/tls
	html/template
	text/template
	net/smtp
	plugin
	github.com/go-webauthn
	github.com/fxamacker/cbor
	github.com/golang-jwt
)
AGENT_EXCEPTIONS=()

# A package matches a banned entry when it is the entry or below it.
# $1 names the banned array.
banned_match() {
	local -n list=$1
	local pkg=$2 b
	for b in "${list[@]}"; do
		if [ "$pkg" = "$b" ] || [[ $pkg == "$b"/* ]]; then
			return 0
		fi
	done
	return 1
}

# $1 names the exceptions array.
excepted() {
	local -n list=$1
	local pkg=$2 importer=$3 e
	for e in "${list[@]}"; do
		[ "$e" = "$pkg $importer" ] && return 0
	done
	return 1
}

status=0

# check_target NAME PKG TAGS BANNED_ARRAY EXCEPTIONS_ARRAY
check_target() {
	local name=$1 pkg=$2 tags=$3 banned=$4 exceptions=$5 cgo=0 label deps graph found p importers importer
	[ -n "$tags" ] && cgo=1
	label=${tags:-default}
	if ! deps=$(CGO_ENABLED=$cgo GOOS=linux go list -deps -tags "$tags" "$pkg"); then
		echo "dep-firewall: go list failed for $name, tags '$label'" >&2
		exit 2
	fi
	if ! graph=$(CGO_ENABLED=$cgo GOOS=linux go list -deps -tags "$tags" -f '{{.ImportPath}}: {{join .Imports " "}}' "$pkg"); then
		echo "dep-firewall: go list failed for $name, tags '$label'" >&2
		exit 2
	fi
	echo "== $name, GOOS=linux, tags=$label, CGO_ENABLED=$cgo: $(wc -l <<<"$deps") packages"
	found=0
	while IFS= read -r p; do
		banned_match "$banned" "$p" || continue
		found=1
		importers=$(awk -v p="$p" '{for (i = 2; i <= NF; i++) if ($i == p) {sub(/:$/, "", $1); print $1}}' <<<"$graph")
		for importer in $importers; do
			if excepted "$exceptions" "$p" "$importer"; then
				echo "   allowed: $p <- $importer (documented exception)"
			else
				echo "   BANNED:  $p <- $importer"
				status=1
			fi
		done
	done <<<"$deps"
	[ "$found" = 0 ] && echo "   no banned packages"
	return 0
}

for tags in "" piv; do
	check_target keyroster-signer ./cmd/keyroster-signer "$tags" BANNED EXCEPTIONS
done
check_target keyroster-agent ./cmd/keyroster-agent "" AGENT_BANNED AGENT_EXCEPTIONS

if [ "$status" != 0 ]; then
	echo "dep-firewall: banned packages in a binary's dependency graph (see above)" >&2
fi
exit "$status"
