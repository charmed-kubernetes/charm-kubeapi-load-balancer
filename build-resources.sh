#!/bin/bash
set -eux

VERSION="0.11.0"


# This script will generate nginx-prometheus-exporter
function fetch() {
  # fetch a binary and make sure it's what we expect (executable > 3MB)
  location="${1-}"

  # remove everything up until the last slash to get the filename
  filename=$(echo "${location##*/}")
  fetch_cmd="wget ${location} -O ./${filename}"
  ${fetch_cmd}
  echo $filename
}

function fetch_and_validate() {
  local filename=$(fetch "${1-}")
  local sha_file="${2}"
  local arch="${3}"
  local sum=$(sha256sum $filename)
  grep -Fxq "${sum}" "${2}"
  mv nginx-prometheus-exporter{_${VERSION},}_linux_${arch}.tar.gz
}

fetch https://github.com/nginxinc/nginx-prometheus-exporter/releases/download/v${VERSION}/sha256sums.txt
ARCH=${ARCH:-"amd64 arm64 s390x"}
for arch in ${ARCH}; do
  fetch_and_validate \
    https://github.com/nginxinc/nginx-prometheus-exporter/releases/download/v${VERSION}/nginx-prometheus-exporter_${VERSION}_linux_${arch}.tar.gz \
    ${PWD}/sha256sums.txt \
    $arch
done