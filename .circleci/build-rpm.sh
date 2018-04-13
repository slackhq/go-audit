#!/bin/sh
name='go-audit'
version=$(cat VERSION.txt)
iteration="$(date +%Y%m%d%H%M).git$(git rev-parse --short HEAD)"  # datecode + git sha-ref: "201503020102.gitef8e0fb"
arch='x86_64'
url="https://github.com/pantheon-systems/${name}"
vendor='Pantheon'
description='a kernel auditing shipper built in go'
install_prefix="/opt/${name}"

filepath=$name
if [ -d "$CIRCLE_ARTIFACTS" ] ; then
  filepath="$CIRCLE_ARTIFACTS/$name"
fi

fpm -s dir -t rpm \
    --name "${name}" \
    --version "${version}" \
    --iteration "${iteration}" \
    --architecture "${arch}" \
    --url "${url}" \
    --vendor "${vendor}" \
    --description "${description}" \
    --prefix "$install_prefix" \
    README.md \
    VERSION.txt \
    $filepath

if [ -d "$CIRCLE_ARTIFACTS" ] ; then
  cp ./*.rpm "$CIRCLE_ARTIFACTS"
fi
