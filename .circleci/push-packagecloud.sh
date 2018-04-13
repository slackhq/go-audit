#!/bin/bash
#
#  wrapper for pushing rpm's up to both repos
#
repo_versions=(22)

if [ -z "$(which package_cloud)" ]; then
  echo "Error no 'package_cloud' found in PATH"
  exit 1
fi

if [ -z "$1" ] ; then
  echo "Need to specify target repo: internal, internal-staging"
  exit 1
fi

for i in ${repo_versions[@]} ; do
  package_cloud push "pantheon/$1/fedora/$i" ~/go-audit/artifacts/*.rpm
done
