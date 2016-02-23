#!/bin/sh

#depends on `fpm`

VERSION="0.14.0"
BUILD="yourcompany"
CONTACT="Jane Doe <janed@example.com>"
PACKAGE_NAME="go-audit"

DIRNAME="$(cd "$(dirname "$0")" && pwd)"
OLDESTPWD="$PWD"

mkdir -p "$PWD/rootfs/usr/local/bin"
mv "$PWD/go-audit" "$PWD/rootfs/usr/local/bin/"

fakeroot fpm -C "$PWD/rootfs" \
    -m "${CONTACT}" \
    -n "${PACKAGE_NAME}" -v "$VERSION-$BUILD" \
    -p "$OLDESTPWD/${PACKAGE_NAME}_${VERSION}-${BUILD}_amd64.deb" \
    -s "dir" -t "deb" \
    "usr"
