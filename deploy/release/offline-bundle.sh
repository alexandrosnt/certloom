#!/bin/sh
# Builds the offline bundle (.tar.gz) of a release for one architecture (ADR-0032):
#
#   deploy/release/offline-bundle.sh <version> <arch> <dist dir> <out dir>
#
# The bundle holds the Linux archives and packages of that architecture, the
# release SHA256SUMS and its Sigstore bundle, the packaging key, the images
# (certloom, certloom-agent, PostgreSQL) as docker-archive tarballs, the
# Compose files and CONTENTS.sha256 over everything in it.
#
# Environment:
#   IMAGE_SOURCE  skopeo source prefix for the certloom images
#                 (default docker://ghcr.io/alexandrosnt)
#   IMAGE_TAG     tag of the certloom images (default <version>)
#   POSTGRES_IMAGE PostgreSQL image the Compose file uses
#                 (default docker://docker.io/library/postgres:18-alpine)
#
# Needs skopeo, sha256sum and tar.
set -eu

version=${1#v}
arch=$2
dist=$(cd "$3" && pwd)
out=$(mkdir -p "$4" && cd "$4" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)

src=${IMAGE_SOURCE:-docker://ghcr.io/alexandrosnt}
tag=${IMAGE_TAG:-$version}
pg=${POSTGRES_IMAGE:-docker://docker.io/library/postgres:18-alpine}

name=certloom-offline_${version}_linux_${arch}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
b=$work/$name
mkdir -p "$b/archives" "$b/packages" "$b/images" "$b/compose" "$b/docs"

case $arch in
    amd64) rpmarch=x86_64 ;;
    arm64) rpmarch=aarch64 ;;
    *) echo "unknown arch $arch" >&2; exit 1 ;;
esac

cp "$dist"/*_linux_"$arch".tar.gz "$b/archives/"
cp "$dist"/*_"$arch".deb "$dist"/*."$rpmarch".rpm "$b/packages/"
cp "$dist/SHA256SUMS" "$b/"
if [ -f "$dist/SHA256SUMS.sigstore.json" ]; then
    cp "$dist/SHA256SUMS.sigstore.json" "$b/"
fi
if [ -f "$dist/gpg.key" ]; then
    cp "$dist/gpg.key" "$b/"
fi

copy() {
    skopeo copy --quiet --override-os linux --override-arch "$arch" "$1" "docker-archive:$b/images/$2.tar:$3"
}
copy "$src/certloom:$tag" certloom "certloom:$version"
copy "$src/certloom-agent:$tag" certloom-agent "certloom-agent:$version"
copy "$pg" postgres "postgres:18-alpine"

cp "$root/deploy/compose/compose.yaml" "$root/deploy/compose/.env.example" "$root/deploy/compose/README.md" "$b/compose/"
cp "$root/docs/runbooks/airgap.md" "$root/docs/runbooks/install-packages.md" "$root/docs/verify-release.md" "$b/docs/"
sed "s|^# certloom offline|# certloom $version offline|" "$root/deploy/release/offline-README.txt" > "$b/README.txt"

(cd "$b" && find . -type f | LC_ALL=C sort | xargs sha256sum) > "$work/CONTENTS.sha256"
mv "$work/CONTENTS.sha256" "$b/"

# Fixed order, owners and times, so the tar depends only on its content.
mtime=@${SOURCE_DATE_EPOCH:-0}
tar -C "$work" --sort=name --owner=0 --group=0 --numeric-owner --mtime="$mtime" \
    -cf - "$name" | gzip -9n > "$out/$name.tar.gz"
echo "$out/$name.tar.gz"
