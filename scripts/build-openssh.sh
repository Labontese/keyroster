#!/usr/bin/env bash
# Build portable OpenSSH from a SHA-256-pinned, GPG-verified release tarball
# into a private prefix, as a non-root user. The e2e tests run the resulting
# sshd, ssh, ssh-agent and ssh-keygen (ssh-keygen as a test oracle only).
#
#   bash scripts/build-openssh.sh VERSION [PREFIX]
#
# VERSION must be in the pinned table below (9.5p1, 10.5p1). There is no
# upstream 9.5p2: "OpenSSH_for_Windows_9.5p2" is Microsoft's own build, which
# plan 01-15 checks manually on Windows.
#
# PREFIX defaults to $HOME/.cache/keyroster/openssh-VERSION. A stamp file
# ($PREFIX/.keyroster-build) records version, SHA-256 and the build layout;
# when it matches, the cached build is reused.
#
# Besides the install, the build puts OpenSSH's test-only FIDO security-key
# provider regress/misc/sk-dummy/sk-dummy.so into $PREFIX/libexec/. It is a
# software stand-in for a FIDO token (no touch, no PIN) that the e2e suite
# uses as a hardware-root stand-in (D-11). It is never part of a release.
set -euo pipefail

BASE_URL=https://cdn.openbsd.org/pub/OpenBSD/OpenSSH
# Primary fingerprint of the OpenSSH release signing key (RELEASE_KEY.asc).
RELEASE_KEY_FPR=7168B983815A5EEF59A4ADFD2A3F414E736060BA

pinned_sha256() {
	case "$1" in
	9.5p1) echo f026e7b79ba7fb540f75182af96dc8a8f1db395f922bbc9f6ca603672686086b ;;
	10.5p1) echo d44d28a839ea9daf969cc69150fde59910b2b39361dad81a3bd6cbd19218db11 ;;
	*) return 1 ;;
	esac
}

die() {
	echo "build-openssh: $*" >&2
	exit 1
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	echo "usage: $0 VERSION [PREFIX]" >&2
	exit 2
fi
VERSION=$1
if ! SHA256=$(pinned_sha256 "$VERSION"); then
	die "version $VERSION is not pinned (pinned: 9.5p1, 10.5p1). OpenSSH 9.5p2 has no upstream release; the Windows OpenSSH 9.5p2 check is the manual step in plan 01-15."
fi
PREFIX=${2:-$HOME/.cache/keyroster/openssh-$VERSION}
STAMP="$PREFIX/.keyroster-build"
# The "+sk-dummy" layout tag makes prefixes cached before sk-dummy.so was
# installed rebuild.
STAMP_LINE="$VERSION $SHA256 +sk-dummy"

[ "$(id -u)" -ne 0 ] || die "refusing to build as root"
for tool in curl gpg sha256sum make cc; do
	command -v "$tool" >/dev/null 2>&1 || die "missing tool: $tool"
done

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$STAMP_LINE" ] && [ -x "$PREFIX/sbin/sshd" ] && [ -f "$PREFIX/libexec/sk-dummy.so" ]; then
	echo "build-openssh: using cached OpenSSH $VERSION in $PREFIX"
	exit 0
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

TARBALL="openssh-$VERSION.tar.gz"
fetch() {
	curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
}
fetch "$BASE_URL/portable/$TARBALL" "$TARBALL"
fetch "$BASE_URL/portable/$TARBALL.asc" "$TARBALL.asc"
fetch "$BASE_URL/RELEASE_KEY.asc" RELEASE_KEY.asc

# 1. SHA-256 pin.
echo "$SHA256  $TARBALL" | sha256sum -c --quiet - || die "SHA-256 mismatch for $TARBALL"

# 2. GPG signature by the pinned release key, in a throwaway keyring.
export GNUPGHOME="$WORK/gnupg"
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --quiet --import RELEASE_KEY.asc 2>/dev/null
gpg --batch --with-colons --fingerprint "$RELEASE_KEY_FPR" 2>/dev/null |
	awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; exit }' |
	grep -qx "$RELEASE_KEY_FPR" || die "RELEASE_KEY.asc does not contain the pinned primary key $RELEASE_KEY_FPR"
STATUS=$(gpg --batch --status-fd 1 --verify "$TARBALL.asc" "$TARBALL" 2>/dev/null) || die "GPG verification of $TARBALL failed"
# VALIDSIG <signing key fpr> ... <primary key fpr>: accept the pinned key as
# the signing key or as the primary key of the signing subkey.
echo "$STATUS" | awk -v fpr="$RELEASE_KEY_FPR" '
	$1 == "[GNUPG:]" && $2 == "VALIDSIG" && ($3 == fpr || $NF == fpr) { ok = 1 }
	END { exit ok ? 0 : 1 }' || die "no VALIDSIG for $RELEASE_KEY_FPR on $TARBALL"
echo "build-openssh: $TARBALL verified (SHA-256 pin and GPG signature by $RELEASE_KEY_FPR)"

# 3. Build and install the whole prefix (sshd 10.x execs sshd-session and
#    sshd-auth from libexec, so a partial copy fails at login).
tar -xzf "$TARBALL"
cd "openssh-$VERSION"
rm -rf "$PREFIX"
./configure --prefix="$PREFIX" --with-privsep-path="$PREFIX/var/empty" --without-pam >"$WORK/configure.log" 2>&1 ||
	{ tail -n 40 "$WORK/configure.log" >&2; die "configure failed"; }
make -j"$(nproc 2>/dev/null || echo 2)" >"$WORK/make.log" 2>&1 ||
	{ tail -n 40 "$WORK/make.log" >&2; die "make failed"; }
make install-nokeys >"$WORK/install.log" 2>&1 ||
	{ tail -n 40 "$WORK/install.log" >&2; die "make install-nokeys failed"; }
[ -x "$PREFIX/sbin/sshd" ] || die "sshd missing after install"

# 4. The test-only FIDO provider (same verified source tree, Makefile.in
#    target regress/misc/sk-dummy/sk-dummy.so, built -fPIC).
make regress/misc/sk-dummy/sk-dummy.so >"$WORK/sk-dummy.log" 2>&1 ||
	{ tail -n 40 "$WORK/sk-dummy.log" >&2; die "building sk-dummy.so failed"; }
install -m 0755 regress/misc/sk-dummy/sk-dummy.so "$PREFIX/libexec/sk-dummy.so"
echo "$STAMP_LINE" >"$STAMP"
"$PREFIX/bin/ssh" -V
echo "build-openssh: installed OpenSSH $VERSION in $PREFIX"
