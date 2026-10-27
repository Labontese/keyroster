#!/usr/bin/env bash
# Run the distro tests (03-06, D-17) in one distribution image:
#
#   bash test/distro/run.sh debian:12
#   bash test/distro/run.sh debian@sha256:<digest>    # CI pins images by digest
#
# Builds keyroster-agent and the e2edistro test binary on this host (both
# static, CGO_ENABLED=0, so they run on glibc and musl alike), then runs
# them as root in a fresh container of the image: run-in.sh installs the
# distribution's own OpenSSH server with its package manager and runs the
# tests. The container gets no secrets and no token. It runs on Docker's
# default bridge network for the whole run, the package install and the
# tests alike, so the image, the packages it installs and the test binary
# keep outbound network access; the tests themselves connect only to
# loopback addresses. Needs Docker and Go.
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: $0 IMAGE" >&2
	exit 2
fi
image=$1
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

(
	cd "$repo"
	CGO_ENABLED=0 GOOS=linux go build -trimpath -o "$work/keyroster-agent" ./cmd/keyroster-agent
	CGO_ENABLED=0 GOOS=linux go test -c -tags e2edistro -o "$work/distro.test" ./test/distro
)
cp "$repo/test/distro/run-in.sh" "$work/run-in.sh"
chmod 0755 "$work/run-in.sh" "$work/keyroster-agent" "$work/distro.test"

echo "== $image"
docker run --rm -e KEYROSTER_DISTRO="$image" -v "$work:/k:ro" "$image" /bin/sh /k/run-in.sh
