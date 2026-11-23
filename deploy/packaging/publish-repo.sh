#!/bin/sh
# Adds release packages to the apt and yum repositories served from the
# certloom-packages repo (GitHub Pages) and re-signs their metadata.
#
#   deploy/packaging/publish-repo.sh <dir with .deb/.rpm> <certloom-packages checkout>
#
# Environment:
#   PACKAGE_GPG_KEY_FILE   armored secret packaging key (required)
#   PACKAGE_GPG_PASSPHRASE its passphrase (optional)
#   KEEP                   versions kept per package and architecture (default 5)
#
# Needs gpg, apt-ftparchive (apt-utils) and createrepo_c.
set -eu

pkgs=$(cd "$1" && pwd)
repo=$(cd "$2" && pwd)
keep=${KEEP:-5}

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
gpg --batch --quiet --import "$PACKAGE_GPG_KEY_FILE"
fpr=$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^fpr:/ { print $10; exit }')
printf '%s' "${PACKAGE_GPG_PASSPHRASE:-}" > "$GNUPGHOME/pass"
sign() {
    gpg --batch --yes --pinentry-mode loopback --passphrase-file "$GNUPGHOME/pass" \
        --local-user "$fpr" "$@"
}

# prune DIR GLOB: keep the newest $keep files matching GLOB in DIR.
prune() {
    # $2 is a glob, so it stays unquoted.
    # shellcheck disable=SC2012,SC2086
    ls "$1"/$2 2>/dev/null | sort -V | head -n "-$keep" | while read -r old; do
        rm -f "$old"
    done
}

# apt: one suite "stable", component "main", flat pool per package.
for deb in "$pkgs"/*.deb; do
    name=$(dpkg-deb -f "$deb" Package)
    mkdir -p "$repo/deb/pool/main/$name"
    cp "$deb" "$repo/deb/pool/main/$name/"
done
for dir in "$repo"/deb/pool/main/*; do
    for arch in amd64 arm64; do
        prune "$dir" "*_$arch.deb"
    done
done
cd "$repo/deb"
for arch in amd64 arm64; do
    out=dists/stable/main/binary-$arch
    mkdir -p "$out"
    apt-ftparchive --arch "$arch" packages pool > "$out/Packages"
    gzip -9nkf "$out/Packages"
done
apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=certloom \
    -o APT::FTPArchive::Release::Label=certloom \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
    -o APT::FTPArchive::Release::Components=main \
    release dists/stable > dists/stable/Release
sign --clearsign -o dists/stable/InRelease dists/stable/Release
sign --detach-sign --armor -o dists/stable/Release.gpg dists/stable/Release

# yum/dnf: one repository per architecture.
for rpm in "$pkgs"/*.rpm; do
    arch=$(basename "$rpm" .rpm)
    arch=${arch##*.}
    mkdir -p "$repo/rpm/$arch"
    cp "$rpm" "$repo/rpm/$arch/"
done
for dir in "$repo"/rpm/*/; do
    for name in certloom-agent certloomd; do
        prune "$dir" "$name-[0-9]*.rpm"
    done
    createrepo_c --quiet --update "$dir"
    sign --detach-sign --armor -o "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml"
done

gpg --batch --armor --export "$fpr" > "$repo/gpg.key"
cat > "$repo/certloom.repo" <<EOF
[certloom]
name=certloom
baseurl=https://alexandrosnt.github.io/certloom-packages/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://alexandrosnt.github.io/certloom-packages/gpg.key
EOF
echo "signed with $fpr"
