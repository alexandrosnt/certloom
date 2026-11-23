#!/bin/sh
# Prints the CHANGELOG.md section of a release, for the GitHub release notes.
#   deploy/release/notes.sh v1.2.3
# Fails if the section ("## 1.2.3" or "## 1.2.3 - date") is missing, so a
# release cannot go out before its changelog is written.
set -eu

version=${1#v}
awk -v v="$version" '
    /^## / { if (found) exit; split($0, h, " "); if (h[2] == v) { found = 1; next } }
    found { print }
    END { if (!found) exit 1 }
' "$(dirname "$0")/../../CHANGELOG.md" || {
    echo "CHANGELOG.md has no section for $version" >&2
    exit 1
}
