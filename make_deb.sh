#!/bin/sh

# depends on `fpm`, install via `gem`

VERSION="0.16.0"
BUILD="slack1"
CONTACT="Jane Doe <janed@example.com>"
PACKAGE_NAME="go-audit"

DIRNAME="$(cd "$(dirname "$0")" && pwd)"
OLDESTPWD="$PWD"

go build
rm -f "$PWD/rootfs"
mkdir -p "$PWD/rootfs/usr/local/bin"
mv "$PWD/go-audit" "$PWD/rootfs/usr/local/bin/"

fakeroot fpm -C "$PWD/rootfs" \
    --license "MIT" \
    --url "https://github.com/slackhq/go-audit" \
    --vendor "" \
    --description "go-audit is an alternative to the auditd daemon that ships with many distros." \
    -d "auditd" \
    -m "${CONTACT}" \
    -n "${PACKAGE_NAME}" -v "$VERSION-$BUILD" \
    -p "$OLDESTPWD/${PACKAGE_NAME}_${VERSION}-${BUILD}_amd64.deb" \
    -s "dir" -t "deb" \
    "usr"
