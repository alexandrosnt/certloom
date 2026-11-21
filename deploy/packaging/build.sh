#!/bin/sh
# Builds certloom-agent deb and rpm packages into dist/.
#
#   deploy/packaging/build.sh                    # version 0.0.0-dev, host arch
#   VERSION=1.2.3 GOARCH=arm64 deploy/packaging/build.sh
#
# Needs Go and Docker. nfpm runs from its container image; it is not a Go
# module dependency.
set -eu

NFPM_IMAGE=goreleaser/nfpm:v2.44.0

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

VERSION=${VERSION:-0.0.0-dev}
GOARCH=${GOARCH:-$(go env GOARCH)}
COMMIT=${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}
bin=dist/linux/certloom-agent

CGO_ENABLED=0 GOOS=linux GOARCH=$GOARCH go build -trimpath \
    -ldflags "-s -w -X github.com/alexandrosnt/certloom/internal/version.Version=${VERSION} -X github.com/alexandrosnt/certloom/internal/version.Commit=${COMMIT}" \
    -o "$bin" ./cmd/certloom-agent

# Docker Desktop on Windows (Git Bash) needs a native path and no path rewriting.
src=$(pwd -W 2>/dev/null || pwd)
user=""
if [ "$(uname -s)" = Linux ]; then
    user="--user $(id -u):$(id -g)"
fi

for packager in deb rpm; do
    # shellcheck disable=SC2086
    MSYS_NO_PATHCONV=1 docker run --rm $user -v "$src:/src" -w /src \
        -e VERSION="$VERSION" -e GOARCH="$GOARCH" \
        "$NFPM_IMAGE" pkg --config deploy/packaging/nfpm.yaml --packager "$packager" --target dist/
done
ls -l dist/*.deb dist/*.rpm
