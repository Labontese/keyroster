#!/usr/bin/env bash
# Dependency firewall for keyroster-signer (KEY-01, REPO-02): the signer's
# transitive dependency graph must not contain network, template, exec or
# plugin packages, nor a TPM simulator. depguard (lint) catches direct
# imports in signer packages; this catches what dependencies pull in.
#
#   bash scripts/dep-firewall.sh
#
# It runs `go list -deps` for GOOS=linux twice: with no build tags
# (CGO_ENABLED=0, the default binary) and with -tags piv (CGO_ENABLED=1, the
# PIV build). For every banned package it prints the packages that import it.
# A banned package passes only when every importer is listed for it in
# EXCEPTIONS below; each exception names the locked dependency that imports
# it and why that is acceptable, and is reviewed in the PR that adds it.
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

# A package matches a banned entry when it is the entry or below it.
banned_match() {
	local pkg=$1 b
	for b in "${BANNED[@]}"; do
		if [ "$pkg" = "$b" ] || [[ $pkg == "$b"/* ]]; then
			return 0
		fi
	done
	return 1
}

excepted() {
	local pkg=$1 importer=$2 e
	for e in "${EXCEPTIONS[@]}"; do
		[ "$e" = "$pkg $importer" ] && return 0
	done
	return 1
}

status=0
for tags in "" piv; do
	cgo=0
	[ -n "$tags" ] && cgo=1
	label=${tags:-default}
	if ! deps=$(CGO_ENABLED=$cgo GOOS=linux go list -deps -tags "$tags" ./cmd/keyroster-signer); then
		echo "dep-firewall: go list failed for tags '$label'" >&2
		exit 2
	fi
	if ! graph=$(CGO_ENABLED=$cgo GOOS=linux go list -deps -tags "$tags" -f '{{.ImportPath}}: {{join .Imports " "}}' ./cmd/keyroster-signer); then
		echo "dep-firewall: go list failed for tags '$label'" >&2
		exit 2
	fi
	echo "== keyroster-signer, GOOS=linux, tags=$label, CGO_ENABLED=$cgo: $(wc -l <<<"$deps") packages"
	found=0
	while IFS= read -r pkg; do
		banned_match "$pkg" || continue
		found=1
		importers=$(awk -v p="$pkg" '{for (i = 2; i <= NF; i++) if ($i == p) {sub(/:$/, "", $1); print $1}}' <<<"$graph")
		for importer in $importers; do
			if excepted "$pkg" "$importer"; then
				echo "   allowed: $pkg <- $importer (documented exception)"
			else
				echo "   BANNED:  $pkg <- $importer"
				status=1
			fi
		done
	done <<<"$deps"
	[ "$found" = 0 ] && echo "   no banned packages"
done

if [ "$status" != 0 ]; then
	echo "dep-firewall: banned packages in the keyroster-signer dependency graph (see above)" >&2
fi
exit "$status"
