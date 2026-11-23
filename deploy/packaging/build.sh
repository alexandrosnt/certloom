#!/bin/sh
# Builds every release artifact (archives, deb and rpm packages) into dist/ as
# an unsigned snapshot, from .goreleaser.yaml, the same file releases use.
#
#   deploy/packaging/build.sh                 # version 0.0.0-dev+<commit>
#   VERSION=1.2.3-rc1 deploy/packaging/build.sh
#   IMAGES=1 deploy/packaging/build.sh        # also build the container images
#
# Needs Docker only: GoReleaser, Go and syft run from the GoReleaser image.
set -eu

GORELEASER_IMAGE=goreleaser/goreleaser:v2.20.0

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

skip=sign,publish,sbom
if [ -z "${IMAGES:-}" ]; then
    skip=$skip,docker
fi

# Docker Desktop on Windows (Git Bash) needs a native path and no path rewriting.
src=$(pwd -W 2>/dev/null || pwd)

MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$src:/src" -w /src \
    -v certloom-gomod:/go/pkg/mod \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/src \
    -e GORELEASER_CURRENT_TAG=v0.0.0 \
    -e CERTLOOM_SNAPSHOT_VERSION="${VERSION:-}" \
    -e SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
    "$GORELEASER_IMAGE" release --snapshot --clean --skip="$skip"

# The container runs as root; hand dist/ back to the caller on Linux.
if [ "$(uname -s)" = Linux ]; then
    MSYS_NO_PATHCONV=1 docker run --rm -v "$src:/src" --entrypoint chown \
        "$GORELEASER_IMAGE" -R "$(id -u):$(id -g)" /src/dist
fi
ls dist/*.deb dist/*.rpm
