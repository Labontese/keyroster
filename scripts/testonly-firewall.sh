#!/usr/bin/env bash
# Test-only helper firewall (T-02-75, review finding 02-01-F19): no release
# binary may link a package that exists only for tests, such as the soft
# WebAuthn authenticator. Linking one would create no bypass (the signer
# verifies every assertion itself), but a test helper in a release binary is
# attack surface and a sign that test code leaked into production code.
#
#   bash scripts/testonly-firewall.sh
#
# It runs `go list -deps ./cmd/...` for GOOS linux, windows and darwin, each
# with no build tags (CGO_ENABLED=0, the default binaries) and with -tags piv
# (CGO_ENABLED=1, the PIV build), and compares every listed package with
# each TESTONLY entry: the entry itself or any package below it is a hit.
# go list needs no C toolchain or headers, so the piv pass installs nothing.
# scripts/dep-firewall.sh (the signer's banned-package list) stays separate
# and unchanged.
#
# Exit 0 when clean, 1 when a binary links a test-only helper, 2 when go list
# fails (a combination that cannot be listed is never skipped).
set -euo pipefail

cd "$(dirname "$0")/.."

TESTONLY=(
	# Soft WebAuthn authenticator (02-01).
	github.com/Labontese/keyroster/internal/webauthn/webauthntest
	# Soft registration helper of keyroster-server (02-08); listed before it
	# exists so the gate holds from the moment it does.
	github.com/Labontese/keyroster/internal/server/servertest
)

# testonly_match prints the TESTONLY entry pkg matches, if any.
testonly_match() {
	local pkg=$1 e
	for e in "${TESTONLY[@]}"; do
		if [ "$pkg" = "$e" ] || [[ $pkg == "$e"/* ]]; then
			printf '%s\n' "$e"
			return 0
		fi
	done
	return 1
}

status=0
combos=0
for goos in linux windows darwin; do
	for tags in "" piv; do
		cgo=0
		[ -n "$tags" ] && cgo=1
		label=${tags:-default}
		if ! deps=$(CGO_ENABLED=$cgo GOOS=$goos GOARCH=amd64 go list -deps -tags "$tags" ./cmd/...); then
			echo "testonly-firewall: go list failed for GOOS=$goos tags=$label" >&2
			exit 2
		fi
		combos=$((combos + 1))
		hits=0
		while IFS= read -r pkg; do
			if testonly_match "$pkg" >/dev/null; then
				echo "   TEST-ONLY: $pkg linked into ./cmd/... (GOOS=$goos, tags=$label)"
				hits=$((hits + 1))
				status=1
			fi
		done <<<"$deps"
		if [ "$hits" = 0 ]; then
			echo "== test-only helpers, ./cmd/..., GOOS=$goos, tags=$label: none"
		fi
	done
done

if [ "$status" != 0 ]; then
	echo "testonly-firewall: a release binary links a test-only helper (see above)" >&2
	exit "$status"
fi
echo "testonly-firewall: clean ($combos GOOS/tag combinations)"
