#!/bin/sh
# Build a static ARM64 qemu-x86_64 (user mode) with the rtnetlink pass-through
# patch, for running the x86-64 Barracuda VPN client on the Flint 2.
#
# Why: stock qemu-user translates rtnetlink messages per type and rejects any
# it doesn't know (EOPNOTSUPP). The Barracuda 5.3 daemon sends policy-rule
# messages (RTM_*RULE) at startup and aborts. x86-64 and ARM64 share byte
# order and LP64 layout, so unknown types can pass through unchanged.
#
# Source: Debian trixie's qemu 10.0.13 orig tarball, hash-checked against the
# signed Debian Sources index. Output: runtime/qemu-x86_64-flint (+ .sha256).
# Needs Docker. Usage: tools/qemu/build.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT="$REPO/runtime"
VER=10.0.13
TARBALL="qemu_${VER}+ds.orig.tar.xz"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"

SHA=$(curl -fsSL https://deb.debian.org/debian/dists/trixie/main/source/Sources.xz | xz -dc \
  | awk -v f="$TARBALL" '/^Package: qemu$/{p=1} p&&/^Checksums-Sha256:/{c=1;next} c&&$3==f{print $1; exit}')
[ -n "$SHA" ] || { echo "could not find $TARBALL in the Debian index" >&2; exit 1; }
curl -fsSL -o "$WORK/$TARBALL" "https://deb.debian.org/debian/pool/main/q/qemu/$TARBALL"
echo "$SHA  $WORK/$TARBALL" | sha256sum -c -
tar xJf "$WORK/$TARBALL" -C "$WORK"
patch -d "$WORK/qemu-$VER" -p1 < "$HERE/rtnetlink-passthrough.patch"

docker run --rm -v "$WORK:/src" -e VER="$VER" -e UIDGID="$(id -u):$(id -g)" debian:trixie sh -euc '
  dpkg --add-architecture arm64
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    gcc libc6-dev gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross pkgconf \
    libglib2.0-dev:arm64 libpcre2-dev:arm64 zlib1g-dev:arm64 libffi-dev:arm64 \
    meson ninja-build python3 python3-venv python3-setuptools python3-pycotap xz-utils make >/dev/null
  cd /src/qemu-$VER && mkdir build && cd build
  PKG_CONFIG=aarch64-linux-gnu-pkg-config ../configure --static --disable-system --enable-linux-user \
    --target-list=x86_64-linux-user --cross-prefix=aarch64-linux-gnu- \
    --disable-tools --disable-docs --disable-capstone --disable-werror \
    --disable-download --disable-install-blobs >/dev/null
  ninja qemu-x86_64 >/dev/null
  aarch64-linux-gnu-strip -o /src/qemu-x86_64-flint qemu-x86_64
  chown "$UIDGID" /src/qemu-x86_64-flint'

install -m 755 "$WORK/qemu-x86_64-flint" "$OUT/qemu-x86_64-flint"
(cd "$OUT" && sha256sum qemu-x86_64-flint > qemu-x86_64-flint.sha256)
file "$OUT/qemu-x86_64-flint"
cat "$OUT/qemu-x86_64-flint.sha256"
